use super::*;

#[test]
fn pointer_write_failure_rolls_back_its_prefix() {
    let first = AtomicUsize::new(10);
    let second = AtomicUsize::new(99);
    let plan = HookPlan {
        previous: 10,
        slots: NonZeroUsize::new(2).unwrap(),
        writes: vec![
            pointer_write(&first, 10, 11),
            pointer_write(&second, 20, 21),
        ],
    };

    // SAFETY: both stack atomics remain live, writable, naturally aligned,
    // and exclusively owned for the complete write and rollback sequence.
    let result = unsafe { write_chunk(&plan.writes) };
    assert!(matches!(result, Err(Error::Conflict)));
    assert_eq!(first.load(Ordering::SeqCst), 10);
    assert_eq!(second.load(Ordering::SeqCst), 99);
}

#[test]
fn atomic_commit_conflict_rolls_back_closed_ranges() {
    let first = AtomicUsize::new(10);
    let second = AtomicUsize::new(99);
    let mut mutation = MutationPlan {
        ranges: vec![range_work(0x1000, 0, 0..1), range_work(0x3000, 1, 1..2)],
        initially_writable_chunks: 0..0,
        chunks: vec![range_chunk(0, 0..1), range_chunk(1, 1..2)],
        writes: vec![
            pointer_write(&first, 10, 11),
            pointer_write(&second, 20, 21),
        ],
        images: 1,
        slots: 2,
        pages: 2,
    };
    let mut state = CommitState::new(2);
    let mut open = None;
    let mut events = Vec::new();

    // SAFETY: the stack atomics remain live, writable, aligned, and
    // exclusively owned; the protection closure models the planned ranges.
    let failure = unsafe {
        commit_mutation_with(
            &mut mutation,
            &mut state,
            CommitPolicy::Atomic,
            |start, length, protection| {
                match events.len() {
                    0 => assert_eq!(first.load(Ordering::SeqCst), 10),
                    1..=4 => assert_eq!(first.load(Ordering::SeqCst), 11),
                    5 => assert_eq!(first.load(Ordering::SeqCst), 10),
                    _ => unreachable!(),
                }
                assert_eq!(second.load(Ordering::SeqCst), 99);
                events.push((start, length, protection));
                if protection & libc::PROT_WRITE != 0 {
                    assert!(open.replace(start).is_none());
                } else {
                    assert_eq!(open.take(), Some(start));
                }
                Ok(())
            },
        )
    }
    .unwrap_err();
    assert_eq!(failure.hook, Some(1));
    assert!(matches!(failure.source, Error::Conflict));
    assert_eq!(
        events,
        [
            (0x1000, 0x1000, libc::PROT_READ | libc::PROT_WRITE),
            (0x1000, 0x1000, libc::PROT_READ),
            (0x3000, 0x1000, libc::PROT_READ | libc::PROT_WRITE),
            (0x3000, 0x1000, libc::PROT_READ),
            (0x1000, 0x1000, libc::PROT_READ | libc::PROT_WRITE),
            (0x1000, 0x1000, libc::PROT_READ),
        ]
    );
    assert!(open.is_none());
    assert_eq!(first.load(Ordering::SeqCst), 10);
    assert_eq!(second.load(Ordering::SeqCst), 99);
}

#[test]
fn flat_conflict_rolls_back_only_failed_hook_across_ranges() {
    let writable = AtomicUsize::new(10);
    let first = AtomicUsize::new(20);
    let failed_early = AtomicUsize::new(30);
    let conflict = AtomicUsize::new(99);
    let later = AtomicUsize::new(50);
    let skipped = AtomicUsize::new(60);
    let mut mutation = MutationPlan {
        ranges: vec![
            range_work(0x1000, 0, 1..3),
            range_work(0x3000, 1, 3..5),
            range_work(0x5000, 2, 5..6),
        ],
        initially_writable_chunks: 0..1,
        chunks: vec![
            range_chunk(1, 0..1),
            range_chunk(0, 1..2),
            range_chunk(1, 2..3),
            range_chunk(1, 3..4),
            range_chunk(2, 4..5),
            range_chunk(1, 5..6),
        ],
        writes: vec![
            pointer_write(&writable, 10, 11),
            pointer_write(&first, 20, 21),
            pointer_write(&failed_early, 30, 31),
            pointer_write(&conflict, 40, 41),
            pointer_write(&later, 50, 51),
            pointer_write(&skipped, 60, 61),
        ],
        images: 1,
        slots: 6,
        pages: 4,
    };
    let mut state = CommitState::new(3);
    let mut open = None;
    let mut events = Vec::new();

    // SAFETY: the stack atomics remain live, writable, aligned, and
    // exclusively owned; the protection closure models the planned ranges.
    unsafe {
        commit_mutation_with(
            &mut mutation,
            &mut state,
            CommitPolicy::Independent,
            |start, _, protection| {
                events.push((start, protection));
                if protection & libc::PROT_WRITE != 0 {
                    assert!(open.replace(start).is_none());
                } else {
                    assert_eq!(open.take(), Some(start));
                }
                Ok(())
            },
        )
    }
    .unwrap();
    assert!(matches!(state.hook_errors[1], Some(Error::Conflict)));
    assert_eq!(
        events.iter().map(|event| event.0).collect::<Vec<_>>(),
        [0x1000, 0x1000, 0x3000, 0x3000, 0x1000, 0x1000]
    );
    assert!(open.is_none());
    assert_eq!(writable.load(Ordering::SeqCst), 10);
    assert_eq!(first.load(Ordering::SeqCst), 21);
    assert_eq!(failed_early.load(Ordering::SeqCst), 30);
    assert_eq!(conflict.load(Ordering::SeqCst), 99);
    assert_eq!(later.load(Ordering::SeqCst), 51);
    assert_eq!(skipped.load(Ordering::SeqCst), 60);
}

#[test]
fn initial_writable_conflict_rolls_back_failed_hook_prefix() {
    let failed_prefix = AtomicUsize::new(10);
    let failed_conflict = AtomicUsize::new(99);
    let independent = AtomicUsize::new(30);
    let mut mutation = MutationPlan {
        ranges: Vec::new(),
        initially_writable_chunks: 0..3,
        chunks: vec![
            range_chunk(0, 0..1),
            range_chunk(0, 1..2),
            range_chunk(1, 2..3),
        ],
        writes: vec![
            pointer_write(&failed_prefix, 10, 11),
            pointer_write(&failed_conflict, 20, 21),
            pointer_write(&independent, 30, 31),
        ],
        images: 1,
        slots: 3,
        pages: 1,
    };
    let mut state = CommitState::new(2);

    // SAFETY: the stack atomics remain live, writable, aligned, and
    // exclusively owned; no protected range is involved in this plan.
    unsafe {
        commit_mutation_with(
            &mut mutation,
            &mut state,
            CommitPolicy::Independent,
            |_, _, _| panic!("initially-writable chunks must not change protection"),
        )
    }
    .unwrap();

    assert!(matches!(state.hook_errors[0], Some(Error::Conflict)));
    assert!(state.failed_hooks[0]);
    assert!(!state.failed_hooks[1]);
    assert!(state.hook_errors[1].is_none());
    assert_eq!(failed_prefix.load(Ordering::SeqCst), 10);
    assert_eq!(failed_conflict.load(Ordering::SeqCst), 99);
    assert_eq!(independent.load(Ordering::SeqCst), 31);
    assert!(!mutation.chunks[0].committed);
    assert!(!mutation.chunks[1].committed);
    assert!(mutation.chunks[2].committed);
}

#[test]
fn late_range_open_failure_rolls_back_committed_prefix() {
    let writable = AtomicUsize::new(10);
    let first = AtomicUsize::new(20);
    let untouched = AtomicUsize::new(30);
    let mut mutation = MutationPlan {
        ranges: vec![range_work(0x1000, 0, 1..2), range_work(0x3000, 1, 2..3)],
        initially_writable_chunks: 0..1,
        chunks: vec![
            range_chunk(0, 0..1),
            range_chunk(1, 1..2),
            range_chunk(2, 2..3),
        ],
        writes: vec![
            pointer_write(&writable, 10, 11),
            pointer_write(&first, 20, 21),
            pointer_write(&untouched, 30, 31),
        ],
        images: 1,
        slots: 3,
        pages: 3,
    };
    let mut state = CommitState::new(3);
    let mut failed = false;
    let mut open = None;
    let mut events = Vec::new();

    // SAFETY: the stack atomics remain live, writable, aligned, and
    // exclusively owned; the closure models an unsuccessful range open.
    let failure = unsafe {
        commit_mutation_with(
            &mut mutation,
            &mut state,
            CommitPolicy::Independent,
            |start, _, protection| {
                events.push((start, protection));
                if protection & libc::PROT_WRITE != 0 {
                    if start == 0x3000 && !failed {
                        failed = true;
                        return Err(Error::SystemCall {
                            operation: "mprotect",
                            source: std::io::Error::from_raw_os_error(libc::EACCES),
                        });
                    }
                    assert!(open.replace(start).is_none());
                } else {
                    assert_eq!(open.take(), Some(start));
                }
                Ok(())
            },
        )
    }
    .unwrap_err();
    assert_eq!(failure.hook, None);
    assert!(matches!(failure.source, Error::SystemCall { .. }));
    assert_eq!(
        events.iter().map(|event| event.0).collect::<Vec<_>>(),
        [0x1000, 0x1000, 0x3000, 0x1000, 0x1000]
    );
    assert!(open.is_none());
    assert_eq!(writable.load(Ordering::SeqCst), 10);
    assert_eq!(first.load(Ordering::SeqCst), 20);
    assert_eq!(untouched.load(Ordering::SeqCst), 30);
}

#[test]
fn restore_failure_recovers_current_before_earlier_ranges() {
    let first = AtomicUsize::new(10);
    let second = AtomicUsize::new(20);
    let mut mutation = MutationPlan {
        ranges: vec![range_work(0x1000, 0, 0..1), range_work(0x3000, 1, 1..2)],
        initially_writable_chunks: 0..0,
        chunks: vec![range_chunk(0, 0..1), range_chunk(1, 1..2)],
        writes: vec![
            pointer_write(&first, 10, 11),
            pointer_write(&second, 20, 21),
        ],
        images: 1,
        slots: 2,
        pages: 2,
    };
    let mut state = CommitState::new(2);
    let mut failed = false;
    let mut open = None;
    let mut events = Vec::new();

    // SAFETY: the stack atomics remain live, writable, aligned, and
    // exclusively owned; the closure models a partial restore failure.
    let failure = unsafe {
        commit_mutation_with(
            &mut mutation,
            &mut state,
            CommitPolicy::Independent,
            |start, _, protection| {
                events.push((start, protection));
                if protection & libc::PROT_WRITE != 0 {
                    assert!(open.is_none() || open == Some(start));
                    open = Some(start);
                } else if start == 0x3000 && !failed {
                    assert_eq!(open, Some(start));
                    failed = true;
                    return Err(Error::SystemCall {
                        operation: "mprotect",
                        source: std::io::Error::from_raw_os_error(libc::EACCES),
                    });
                } else {
                    assert_eq!(open.take(), Some(start));
                }
                Ok(())
            },
        )
    }
    .unwrap_err();
    assert_eq!(failure.hook, None);
    assert!(matches!(failure.source, Error::SystemCall { .. }));
    assert_eq!(
        events.iter().map(|event| event.0).collect::<Vec<_>>(),
        [
            0x1000, 0x1000, 0x3000, 0x3000, 0x3000, 0x3000, 0x1000, 0x1000
        ]
    );
    assert!(open.is_none());
    assert_eq!(first.load(Ordering::SeqCst), 10);
    assert_eq!(second.load(Ordering::SeqCst), 20);
}

#[test]
fn page_planning_validates_every_page_before_mutation() {
    let page_size = crate::sys::page_size().unwrap();
    let first = page_size.checked_mul(2).unwrap();
    let second = first.checked_add(page_size).unwrap();
    let maps = [
        MapInfo {
            start: first,
            end: second,
            perms: MapPerms::READ,
            is_private: true,
            offset: 0,
            device: DeviceId::new(1, 2),
            inode: 3,
            path: None,
        },
        MapInfo {
            start: second,
            end: second + page_size,
            perms: MapPerms::READ,
            is_private: false,
            offset: page_size as u64,
            device: DeviceId::new(1, 2),
            inode: 3,
            path: None,
        },
    ];
    let plan = HookPlan {
        previous: 1,
        slots: NonZeroUsize::new(2).unwrap(),
        writes: vec![
            PointerWrite {
                image: test_image(first),
                address: first,
                expected: 1,
                replacement: 2,
            },
            PointerWrite {
                image: test_image(first),
                address: second,
                expected: 1,
                replacement: 2,
            },
        ],
    };
    assert!(matches!(
        mutation_scope(&maps, &[Some(plan)], None),
        Err(Error::UnsupportedFeature("shared relocation page"))
    ));
}

#[test]
fn mutation_budget_counts_unique_selected_images_slots_and_writable_pages() {
    let page_size = crate::sys::page_size().unwrap();
    let start = page_size.checked_mul(8).unwrap();
    let maps = [MapInfo {
        start,
        end: start + page_size * 3,
        perms: MapPerms::READ | MapPerms::WRITE,
        is_private: true,
        offset: 0,
        device: DeviceId::new(1, 2),
        inode: 3,
        path: None,
    }];
    let plan = HookPlan {
        previous: 1,
        slots: NonZeroUsize::new(3).unwrap(),
        writes: vec![
            PointerWrite {
                image: test_image(0x1000),
                address: start + 8,
                expected: 1,
                replacement: 2,
            },
            PointerWrite {
                image: test_image(0x1000),
                address: start + 16,
                expected: 1,
                replacement: 2,
            },
            PointerWrite {
                image: test_image(0x2000),
                address: start + page_size + 8,
                expected: 1,
                replacement: 2,
            },
        ],
    };
    let plans = [Some(plan)];
    let scope = mutation_scope(&maps, &plans, None).unwrap();
    let mutation = mutation_plan(&maps, &plans, scope).unwrap();
    assert_eq!((mutation.images, mutation.slots, mutation.pages), (2, 3, 2));
    assert!(mutation.ranges.is_empty());
    mutation
        .enforce(MutationBudget {
            max_images: 2,
            max_slots: 3,
            max_pages: 2,
        })
        .unwrap();
    assert!(matches!(
        mutation.enforce(MutationBudget {
            max_images: 1,
            max_slots: 3,
            max_pages: 2,
        }),
        Err(Error::MutationBudgetExceeded {
            images: 2,
            slots: 3,
            pages: 2,
            ..
        })
    ));

    let executable = [MapInfo {
        perms: MapPerms::READ | MapPerms::WRITE | MapPerms::EXEC,
        ..maps[0].clone()
    }];
    assert!(matches!(
        mutation_scope(&executable, &plans, None),
        Err(Error::UnsupportedFeature("executable relocation page"))
    ));
}

#[test]
fn mutation_plan_preserves_range_hook_and_intra_hook_order() {
    let page_size = crate::sys::page_size().unwrap();
    let writable = page_size.checked_mul(16).unwrap();
    let first = writable + page_size * 2;
    let second = writable + page_size * 4;
    let maps = [
        MapInfo {
            start: writable,
            end: writable + page_size,
            perms: MapPerms::READ | MapPerms::WRITE,
            is_private: true,
            offset: 0,
            device: DeviceId::new(1, 2),
            inode: 3,
            path: None,
        },
        MapInfo {
            start: first,
            end: first + page_size,
            perms: MapPerms::READ,
            is_private: true,
            offset: page_size as u64,
            device: DeviceId::new(1, 2),
            inode: 3,
            path: None,
        },
        MapInfo {
            start: second,
            end: second + page_size,
            perms: MapPerms::READ,
            is_private: true,
            offset: (page_size * 2) as u64,
            device: DeviceId::new(1, 2),
            inode: 3,
            path: None,
        },
    ];
    let write = |address| PointerWrite {
        image: test_image(writable),
        address,
        expected: 1,
        replacement: 2,
    };
    let plans = [
        Some(HookPlan {
            previous: 1,
            slots: NonZeroUsize::new(4).unwrap(),
            writes: vec![
                write(first + 24),
                write(writable + 24),
                write(first + 8),
                write(second + 16),
            ],
        }),
        Some(HookPlan {
            previous: 1,
            slots: NonZeroUsize::new(3).unwrap(),
            writes: vec![write(second + 8), write(first + 16), write(writable + 8)],
        }),
    ];

    let scope = mutation_scope(&maps, &plans, None).unwrap();
    let mutation = mutation_plan(&maps, &plans, scope).unwrap();

    assert_eq!(mutation.initially_writable_chunks, 0..2);
    assert_eq!(
        mutation
            .ranges
            .iter()
            .map(|range| (range.range.start, range.chunks.clone()))
            .collect::<Vec<_>>(),
        [(first, 2..4), (second, 4..6)]
    );
    assert_eq!(
        mutation
            .chunks
            .iter()
            .map(|chunk| (chunk.hook, chunk.writes.clone()))
            .collect::<Vec<_>>(),
        [
            (0, 0..1),
            (1, 1..2),
            (0, 2..4),
            (1, 4..5),
            (0, 5..6),
            (1, 6..7),
        ]
    );
    assert_eq!(
        mutation
            .writes
            .iter()
            .map(|write| write.address)
            .collect::<Vec<_>>(),
        [
            writable + 24,
            writable + 8,
            first + 24,
            first + 8,
            first + 16,
            second + 16,
            second + 8,
        ]
    );
}

#[test]
fn writable_ranges_merge_only_adjacent_pages_in_the_same_vma_and_protection() {
    let page_size = 4096;
    let pages = [
        WritablePage {
            start: page_size,
            map_index: 0,
            original_protection: libc::PROT_READ,
        },
        WritablePage {
            start: page_size * 2,
            map_index: 0,
            original_protection: libc::PROT_READ,
        },
        WritablePage {
            start: page_size * 4,
            map_index: 0,
            original_protection: libc::PROT_READ,
        },
        WritablePage {
            start: page_size * 5,
            map_index: 1,
            original_protection: libc::PROT_READ,
        },
        WritablePage {
            start: page_size * 6,
            map_index: 1,
            original_protection: libc::PROT_READ | libc::PROT_EXEC,
        },
    ];
    assert_eq!(
        coalesce_writable_pages(&pages, page_size).unwrap(),
        [
            WritableRange {
                start: page_size,
                length: page_size * 2,
                map_index: 0,
                original_protection: libc::PROT_READ,
            },
            WritableRange {
                start: page_size * 4,
                length: page_size,
                map_index: 0,
                original_protection: libc::PROT_READ,
            },
            WritableRange {
                start: page_size * 5,
                length: page_size,
                map_index: 1,
                original_protection: libc::PROT_READ,
            },
            WritableRange {
                start: page_size * 6,
                length: page_size,
                map_index: 1,
                original_protection: libc::PROT_READ | libc::PROT_EXEC,
            },
        ]
    );
}

use super::*;

unsafe extern "C" {
    fn sysconf(name: libc::c_int) -> libc::c_long;
}

static ORIGINAL_SYSCONF: OriginalSlot = OriginalSlot::new();

/// Reports a page size the engine must reject, while every other query keeps
/// working so the test harness itself stays usable.
extern "C" fn wedging_sysconf(name: libc::c_int) -> libc::c_long {
    if name == libc::_SC_PAGESIZE {
        return 0;
    }
    let Some(original) = ORIGINAL_SYSCONF.get() else {
        return -1;
    };
    // SAFETY: strict publication proved this is the sysconf entry the slot
    // held before installation, so it keeps sysconf's exact ABI.
    let original = unsafe {
        std::mem::transmute::<*const (), unsafe extern "C" fn(libc::c_int) -> libc::c_long>(
            original,
        )
    };
    // SAFETY: name is forwarded unchanged and sysconf has no other
    // caller-side preconditions.
    unsafe { original(name) }
}

/// Hooking a symbol the engine itself calls must not make the hook permanent.
///
/// `sysconf(_SC_PAGESIZE)` is resolved once per process and cached, so removal
/// no longer depends on a symbol the caller is allowed to replace. Without the
/// cache every operation after this installation — removal included — fails
/// with `UnsupportedFeature`, and the hook can never be taken back out.
#[test]
fn hooking_sysconf_still_allows_removal() {
    if std::env::var_os(SYSCONF_CHILD).is_some() {
        // Resolve the real PLT entry before scanning it on lazy-binding
        // GNU/Linux. Android resolves it eagerly.
        // SAFETY: _SC_PAGESIZE is a documented sysconf query.
        let expected_page_size = unsafe { sysconf(libc::_SC_PAGESIZE) };
        assert!(expected_page_size > 0);

        let target = Target::current_executable().unwrap();
        let hook = Hook::new(&target, c"sysconf", wedging_sysconf as *const ())
            .unwrap()
            .require_non_null_previous()
            .with_original_slot(&ORIGINAL_SYSCONF);

        // SAFETY: this single-threaded child keeps its executable stable,
        // excludes competing writers, and the replacement stays live and
        // ABI-compatible for the complete installation.
        let mut applied = unsafe { install_hook(hook) }.unwrap();
        assert!(applied.is_installed());

        // The replacement is live for callers...
        // SAFETY: _SC_PAGESIZE is a documented sysconf query.
        assert_eq!(unsafe { sysconf(libc::_SC_PAGESIZE) }, 0);
        // ...but the engine keeps the value it resolved before installation.
        assert_eq!(
            crate::sys::page_size().unwrap(),
            usize::try_from(expected_page_size).unwrap()
        );

        // SAFETY: this child has drained every sysconf call and the
        // installation guarantees still hold during removal.
        unsafe { applied.unhook() }.unwrap();
        assert!(!applied.is_installed());
        // SAFETY: _SC_PAGESIZE is a documented sysconf query.
        assert_eq!(unsafe { sysconf(libc::_SC_PAGESIZE) }, expected_page_size);
        return;
    }

    run_child(
        "plt::tests::install::hooking_sysconf_still_allows_removal",
        SYSCONF_CHILD,
    );
}

#[test]
fn budget_precedes_publication_and_publication_precedes_mutation() {
    if std::env::var_os(PUBLICATION_CHILD).is_some() {
        // Resolve the real PLT entry before scanning it on lazy-binding
        // GNU/Linux. Android resolves it eagerly.
        // SAFETY: getpid takes no arguments.
        let _ = unsafe { getpid() };
        let maps = read_self_maps().unwrap();
        let marker = (executable_marker as *const ()).expose_provenance();
        let executable = find_map_containing(&maps, marker, 1).unwrap();
        let target = Target::new(executable.device, executable.inode).unwrap();
        let original = OriginalSlot::new();
        let hook = Hook::new(&target, c"getpid", passthrough_getpid as *const ())
            .unwrap()
            .with_original_slot(&original);

        // SAFETY: this child keeps its executable stable and only reads
        // the relocation state during inspection.
        let inspection = unsafe { inspect_hooks(&[hook]) }.unwrap();
        assert!(inspection[0].error.is_none(), "{inspection:?}");
        let eligible = inspection[0]
            .images
            .iter()
            .flat_map(|image| &image.slots)
            .filter(|slot| slot.status == InspectionStatus::Eligible)
            .collect::<Vec<_>>();
        assert!(!eligible.is_empty());
        assert!(
            eligible
                .iter()
                .all(|slot| !slot.permissions.contains(MapPerms::WRITE))
        );

        crate::sys::tests::install_test_seccomp_errno(&[syscalls::Sysno::mprotect]);
        // SAFETY: the zero budget rejects the fully preflighted mutation
        // before publication or any page-protection syscall.
        let budget_error = unsafe {
            install_hooks_with_budget(
                &[hook],
                MutationBudget {
                    max_images: 0,
                    max_slots: 0,
                    max_pages: 0,
                },
            )
        }
        .unwrap_err();
        assert!(matches!(budget_error, Error::MutationBudgetExceeded { .. }));
        assert!(original.get().is_none());

        // SAFETY: the replacement is ABI-compatible and remains live. The
        // seccomp rule forces page elevation to fail before any slot change,
        // so the original publication ordering stays observable.
        let protection_error = unsafe { install_hooks(&[hook]) }.unwrap_err();
        assert!(matches!(
            protection_error,
            Error::SystemCall {
                operation: "mprotect",
                ..
            }
        ));
        assert!(original.get().is_some());
        crate::sys::tests::exit_seccomp_child();
    }

    run_child(
        "plt::tests::install::budget_precedes_publication_and_publication_precedes_mutation",
        PUBLICATION_CHILD,
    );
}

#[test]
fn duplicate_slots_report_only_the_conflicting_slots() {
    let _guard = STATEFUL_SLOT_TEST_LOCK.lock().unwrap();
    FIRST_SLOT.store(20, Ordering::SeqCst);
    SECOND_SLOT.store(21, Ordering::SeqCst);
    let conflict = FIRST_SLOT.as_ptr() as usize;
    let independent = SECOND_SLOT.as_ptr() as usize;
    let maps = read_self_maps().unwrap();
    let map = find_map_containing(&maps, conflict, std::mem::size_of::<usize>()).unwrap();
    assert!(find_map_containing(&maps, independent, std::mem::size_of::<usize>()).is_some());
    let target = Target::new(map.device, map.inode).unwrap();
    let replacement = std::ptr::without_provenance(40);
    let hooks = [
        Hook::new(&target, c"first", replacement).unwrap(),
        Hook::new(&target, c"second", replacement).unwrap(),
    ];
    let mut image_id = ImageId::for_test(map.device, map.inode, map.start);
    image_id.loader_base = Some(map.start);
    let images: Arc<[FoundImage]> = Arc::from([FoundImage {
        id: image_id,
        load_ranges: vec![(map.start, map.end)],
        build_id: None,
    }]);
    let relocation = |address| {
        FoundRelocation::for_test(
            address,
            image_id,
            RelocationKind::JumpSlot,
            0,
            JumpSlotState::Resolved,
        )
    };
    let scans = vec![
        Some(ScannedHook {
            relocations: vec![relocation(conflict), relocation(independent)],
            images: Arc::clone(&images),
        }),
        Some(ScannedHook {
            relocations: vec![relocation(conflict)],
            images: Arc::clone(&images),
        }),
    ];
    let ignored = conflicting_slots(&scans, &[false, true]).unwrap();
    assert!(ignored.iter().all(BTreeSet::is_empty));
    let conflicts = conflicting_slots(&scans, &[true, true]).unwrap();
    assert_eq!(conflicts[0], BTreeSet::from([conflict]));
    assert_eq!(conflicts[1], BTreeSet::from([conflict]));

    let prepared = PreparedBatch {
        outcomes: vec![Some(Err(Error::Conflict)), Some(Err(Error::Conflict))],
        scanned: scans,
        images: vec![Some(Arc::clone(&images)), Some(images)],
        rejected: vec![Vec::new(), Vec::new()],
        conflicting_slots: conflicts,
        plans: vec![None, None],
    };
    let report = build_inspection_report(&hooks, &maps, prepared).unwrap();
    assert!(matches!(report[0].error, Some(Error::Conflict)));
    assert!(matches!(report[1].error, Some(Error::Conflict)));
    let first = &report[0].images[0].slots;
    assert_eq!(
        first
            .iter()
            .find(|slot| slot.address.addr() == conflict)
            .unwrap()
            .status,
        InspectionStatus::Conflict
    );
    assert_eq!(
        first
            .iter()
            .find(|slot| slot.address.addr() == independent)
            .unwrap()
            .status,
        InspectionStatus::Rejected
    );
    assert_eq!(
        report[1].images[0].slots[0].status,
        InspectionStatus::Conflict
    );
}

#[test]
fn previous_pointer_must_be_unique_before_writing() {
    let _guard = STATEFUL_SLOT_TEST_LOCK.lock().unwrap();
    FIRST_SLOT.store(20, Ordering::SeqCst);
    SECOND_SLOT.store(21, Ordering::SeqCst);
    let addresses = [
        (FIRST_SLOT.as_ptr() as usize, JumpSlotState::Resolved),
        (SECOND_SLOT.as_ptr() as usize, JumpSlotState::Resolved),
    ];
    let (target, scan) = scan_for(&addresses);
    let hook = Hook::new(&target, c"symbol", std::ptr::without_provenance(40)).unwrap();

    assert!(matches!(
        build_hook_plan(&hook, &scan),
        Err(Error::AmbiguousPreviousPointer)
    ));
    assert_eq!(FIRST_SLOT.load(Ordering::SeqCst), 20);
    assert_eq!(SECOND_SLOT.load(Ordering::SeqCst), 21);
}

#[test]
fn non_null_previous_is_opt_in_and_checked_before_writing() {
    let _guard = STATEFUL_SLOT_TEST_LOCK.lock().unwrap();
    LAZY_SLOT.store(0, Ordering::SeqCst);
    let address = LAZY_SLOT.as_ptr() as usize;
    let (target, scan) = scan_for(&[(address, JumpSlotState::Resolved)]);
    let hook = Hook::new(&target, c"symbol", std::ptr::without_provenance(40)).unwrap();

    let plan = build_hook_plan(&hook, &scan).unwrap();
    assert_eq!(plan.previous, 0);
    assert!(matches!(
        build_hook_plan(&hook.require_non_null_previous(), &scan),
        Err(Error::NullPreviousPointer)
    ));
    assert_eq!(LAZY_SLOT.load(Ordering::SeqCst), 0);
}

#[test]
fn lazy_and_ambiguous_ifunc_slots_require_proof() {
    let _guard = STATEFUL_SLOT_TEST_LOCK.lock().unwrap();
    let maps = read_self_maps().unwrap();
    let address = LAZY_SLOT.as_ptr() as usize;
    let map = find_map_containing(&maps, address, std::mem::size_of::<usize>()).unwrap();
    LAZY_SLOT.store(map.start, Ordering::SeqCst);
    let (target, lazy) = scan_for(&[(address, JumpSlotState::Lazy(map.start))]);
    let hook = Hook::new(&target, c"symbol", std::ptr::without_provenance(40)).unwrap();
    assert!(matches!(
        build_hook_plan(&hook, &lazy),
        Err(Error::UnsupportedFeature("unresolved lazy PLT relocation"))
    ));

    let address = IFUNC_SLOT.as_ptr() as usize;
    let map = find_map_containing(&maps, address, std::mem::size_of::<usize>()).unwrap();
    IFUNC_SLOT.store(map.start, Ordering::SeqCst);
    let (target, ambiguous) = scan_for(&[(address, JumpSlotState::AmbiguousIfunc)]);
    let hook = Hook::new(&target, c"symbol", std::ptr::without_provenance(41)).unwrap();
    assert!(matches!(
        build_hook_plan(&hook, &ambiguous),
        Err(Error::UnsupportedFeature("ambiguous IFUNC jump-slot state"))
    ));

    let (_, proven) = scan_for(&[(address, JumpSlotState::AmbiguousIfunc)]);
    let hook = hook.with_resolved_ifunc(std::ptr::with_exposed_provenance(map.start));
    assert!(build_hook_plan(&hook, &proven).is_ok());
}

/// Our own committed replacement makes a jump slot look lazy on glibc because
/// the value points back into the same image, but the process registry knows
/// the exact pointer it installed there and must keep stacking available.
#[test]
fn a_recorded_replacement_on_a_lazy_looking_slot_allows_stacking() {
    let _guard = STATEFUL_SLOT_TEST_LOCK.lock().unwrap();
    let maps = read_self_maps().unwrap();
    let address = RECORDED_LAZY_SLOT.as_ptr() as usize;
    let map = find_map_containing(&maps, address, std::mem::size_of::<usize>()).unwrap();
    let previous = map.start;
    RECORDED_LAZY_SLOT.store(previous, Ordering::SeqCst);
    let (target, lazy) = scan_for(&[(address, JumpSlotState::Lazy(previous))]);
    let hook = Hook::new(&target, c"symbol", std::ptr::without_provenance(50)).unwrap();
    let write = PointerWrite {
        image: lazy.relocations[0].image,
        address,
        expected: 0,
        replacement: previous,
    };
    {
        let _process_guard = crate::sys::PROCESS_LOCK.write().unwrap();
        record_installed_writes(9001, std::slice::from_ref(&write));
    }

    let plan = build_hook_plan(&hook, &lazy).unwrap();
    assert_eq!(plan.previous, previous);

    {
        let _process_guard = crate::sys::PROCESS_LOCK.write().unwrap();
        complete_removal(&[(9001, address, previous)]);
    }
    assert!(matches!(
        build_hook_plan(&hook, &lazy),
        Err(Error::UnsupportedFeature("unresolved lazy PLT relocation"))
    ));
}

#[test]
fn current_replacement_is_a_conflict() {
    let _guard = STATEFUL_SLOT_TEST_LOCK.lock().unwrap();
    CURRENT_REPLACEMENT_SLOT.store(30, Ordering::SeqCst);
    let address = CURRENT_REPLACEMENT_SLOT.as_ptr() as usize;
    let (target, scan) = scan_for(&[(address, JumpSlotState::Resolved)]);
    let hook = Hook::new(&target, c"symbol", std::ptr::without_provenance(30)).unwrap();
    assert!(matches!(
        build_hook_plan(&hook, &scan),
        Err(Error::Conflict)
    ));
}

#[test]
fn serialized_revalidation_detects_slot_and_original_changes() {
    let _slot_guard = STATEFUL_SLOT_TEST_LOCK.lock().unwrap();
    FIRST_SLOT.store(20, Ordering::SeqCst);
    let address = FIRST_SLOT.as_ptr() as usize;
    let (target, scan) = scan_for(&[(address, JumpSlotState::Resolved)]);
    let original = OriginalSlot::new();
    let hook = Hook::new(&target, c"symbol", std::ptr::without_provenance(40))
        .unwrap()
        .with_original_slot(&original);
    let plans = [Some(build_hook_plan(&hook, &scan).unwrap())];
    let _process_guard = crate::sys::PROCESS_LOCK.write().unwrap();

    // SAFETY: the test owns the live slot and holds the process write lock.
    assert!(unsafe { revalidate_hook_plans(&[hook], &plans) }.unwrap()[0].is_none());
    FIRST_SLOT.store(21, Ordering::SeqCst);
    // SAFETY: the same slot and lock guarantees still hold.
    assert!(matches!(
        unsafe { revalidate_hook_plans(&[hook], &plans) }.unwrap()[0],
        Some(Error::Conflict)
    ));

    FIRST_SLOT.store(20, Ordering::SeqCst);
    original.value.set(21).unwrap();
    // SAFETY: the same slot and lock guarantees still hold.
    assert!(matches!(
        unsafe { revalidate_hook_plans(&[hook], &plans) }.unwrap()[0],
        Some(Error::OriginalSlotConflict)
    ));
}

#[test]
fn unhook_is_atomic_retryable_and_restores_multiple_slots() {
    let _guard = STATEFUL_SLOT_TEST_LOCK.lock().unwrap();
    let mut applied = installed_handle(&[&FIRST_SLOT, &SECOND_SLOT], 20, 30);
    assert_eq!(applied.slots.get(), 2);
    assert_eq!(FIRST_SLOT.load(Ordering::SeqCst), 30);
    assert_eq!(SECOND_SLOT.load(Ordering::SeqCst), 30);

    SECOND_SLOT.store(31, Ordering::SeqCst);
    // SAFETY: the test owns both stable atomic slots; the deliberate
    // conflict must be detected before either slot is restored.
    assert!(matches!(unsafe { applied.unhook() }, Err(Error::Conflict)));
    assert!(applied.is_installed());
    assert_eq!(applied.original(), Some(std::ptr::without_provenance(20)));
    assert_eq!(FIRST_SLOT.load(Ordering::SeqCst), 30);
    assert_eq!(SECOND_SLOT.load(Ordering::SeqCst), 31);

    SECOND_SLOT.store(30, Ordering::SeqCst);
    // SAFETY: both slots again contain the installed replacement and no
    // competing reader or writer exists.
    unsafe { applied.unhook() }.unwrap();
    assert!(!applied.is_installed());
    assert_eq!(FIRST_SLOT.load(Ordering::SeqCst), 20);
    assert_eq!(SECOND_SLOT.load(Ordering::SeqCst), 20);
    // SAFETY: successful removal is idempotent.
    unsafe { applied.unhook() }.unwrap();
}

#[test]
fn stacked_hook_removal_requires_the_newest_writer() {
    let _guard = STATEFUL_SLOT_TEST_LOCK.lock().unwrap();
    FIRST_SLOT.store(20, Ordering::SeqCst);
    let address = FIRST_SLOT.as_ptr() as usize;
    let maps = read_self_maps().unwrap();

    let (target, outer_scan) = scan_for(&[(address, JumpSlotState::Resolved)]);
    let outer_hook = Hook::new(&target, c"symbol", std::ptr::without_provenance(30)).unwrap();
    let outer_plans = [Some(build_hook_plan(&outer_hook, &outer_scan).unwrap())];
    FIRST_SLOT.store(30, Ordering::SeqCst);
    let (_, inner_scan) = scan_for(&[(address, JumpSlotState::Resolved)]);
    let inner_hook = Hook::new(&target, c"symbol", std::ptr::without_provenance(40)).unwrap();
    let inner_plans = [Some(build_hook_plan(&inner_hook, &inner_scan).unwrap())];
    FIRST_SLOT.store(40, Ordering::SeqCst);

    let empty_protections = Arc::new(BTreeMap::new());
    let mut outer_ledgers = prepare_plt_ledgers(
        &[outer_hook],
        &maps,
        &[Some(outer_scan)],
        &outer_plans,
        &empty_protections,
    )
    .unwrap();
    let mut inner_ledgers = prepare_plt_ledgers(
        &[inner_hook],
        &maps,
        &[Some(inner_scan)],
        &inner_plans,
        &empty_protections,
    )
    .unwrap();
    let mut outer = AppliedHook {
        previous: crate::sys::encode_usize(outer_plans[0].as_ref().unwrap().previous),
        slots: outer_plans[0].as_ref().unwrap().slots,
        concealment: Concealment::InPlace("concealment not requested"),
        ledger: outer_ledgers[0].take(),
    };
    let mut inner = AppliedHook {
        previous: crate::sys::encode_usize(inner_plans[0].as_ref().unwrap().previous),
        slots: inner_plans[0].as_ref().unwrap().slots,
        concealment: Concealment::InPlace("concealment not requested"),
        ledger: inner_ledgers[0].take(),
    };
    {
        let _process_guard = crate::sys::PROCESS_LOCK.write().unwrap();
        record_installed_writes(
            outer.ledger.as_ref().unwrap().id,
            &outer_plans[0].as_ref().unwrap().writes,
        );
        record_installed_writes(
            inner.ledger.as_ref().unwrap().id,
            &inner_plans[0].as_ref().unwrap().writes,
        );
    }

    // A slot value colliding with the older hook's replacement must not let
    // that hook bypass the newer installed writer.
    FIRST_SLOT.store(30, Ordering::SeqCst);
    assert!(matches!(unsafe { outer.unhook() }, Err(Error::Conflict)));
    assert!(outer.is_installed());

    // LIFO removal restores each writer's saved value in order.
    FIRST_SLOT.store(40, Ordering::SeqCst);
    // SAFETY: the test owns the stable slot and no competing writer exists.
    unsafe { inner.unhook() }.unwrap();
    assert_eq!(FIRST_SLOT.load(Ordering::SeqCst), 30);
    // SAFETY: the newer writer is removed and the slot again holds this hook.
    unsafe { outer.unhook() }.unwrap();
    assert_eq!(FIRST_SLOT.load(Ordering::SeqCst), 20);
}

#[test]
fn complete_stack_batch_removal_is_canonicalized_newest_first() {
    let _guard = STATEFUL_SLOT_TEST_LOCK.lock().unwrap();
    let outer = installed_handle(&[&FIRST_SLOT], 20, 30);
    let inner = installed_handle(&[&FIRST_SLOT], 30, 40);
    assert_eq!(FIRST_SLOT.load(Ordering::SeqCst), 40);

    // The caller supplies installation order; the transaction must still
    // remove the newer writer before restoring the older one.
    let mut batch = [outer, inner];
    // SAFETY: the test owns the stable slot and no competing writer exists.
    unsafe { unhook_hooks(&mut batch) }.unwrap();
    assert!(batch.iter().all(|hook| !hook.is_installed()));
    assert_eq!(FIRST_SLOT.load(Ordering::SeqCst), 20);
}

#[test]
fn complete_stack_batch_distinguishes_repeated_replacements() {
    let _guard = STATEFUL_SLOT_TEST_LOCK.lock().unwrap();
    let outer = installed_handle(&[&FIRST_SLOT], 20, 30);
    let middle = installed_handle(&[&FIRST_SLOT], 30, 40);
    let inner = installed_handle(&[&FIRST_SLOT], 40, 30);
    assert_eq!(FIRST_SLOT.load(Ordering::SeqCst), 30);

    let mut batch = [outer, middle, inner];
    // SAFETY: the test owns the stable slot and no competing writer exists.
    unsafe { unhook_hooks(&mut batch) }.unwrap();
    assert!(batch.iter().all(|hook| !hook.is_installed()));
    assert_eq!(FIRST_SLOT.load(Ordering::SeqCst), 20);
}

#[test]
fn signed_addends_do_not_wrap() {
    assert_eq!(apply_addend(100, 7).unwrap(), 107);
    assert_eq!(apply_addend(100, -7).unwrap(), 93);
    assert!(matches!(
        apply_addend(usize::MAX, 1),
        Err(Error::ArithmeticOverflow)
    ));
    assert!(matches!(
        apply_addend(0, -1),
        Err(Error::ArithmeticOverflow)
    ));
    assert!(matches!(
        apply_addend(0, i64::MIN),
        Err(Error::ArithmeticOverflow)
    ));
}

static CONCEAL_CHILD: &str = "OMHOOK_CONCEAL_CHILD";
static CONCEAL_LOCKED_CHILD: &str = "OMHOOK_CONCEAL_LOCKED_CHILD";

extern "C" fn concealed_getpid() -> i32 {
    0x7C0
}

/// Concealment must fail closed before any pointer write in this release.
#[test]
fn requested_concealment_fails_closed_before_mutation() {
    if std::env::var_os(CONCEAL_CHILD).is_some() {
        // Resolve the real PLT entry before scanning it on lazy-binding
        // GNU/Linux. Android resolves it eagerly.
        // SAFETY: getpid takes no arguments and cannot fail.
        let expected_pid = unsafe { getpid() };
        let target = Target::current_executable().unwrap();
        let plain = Hook::new(&target, c"getpid", concealed_getpid as *const ())
            .unwrap()
            .require_non_null_previous();
        let hook = Hook::new(&target, c"getpid", concealed_getpid as *const ())
            .unwrap()
            .require_non_null_previous()
            .enforce_concealed_mutations();

        let executable = std::fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
        let before = read_self_maps().unwrap();
        let file_data_ranges: Vec<(usize, usize)> = before
            .iter()
            .filter(|map| {
                map.path.as_deref() == Some(executable.as_path())
                    && !map.perms.contains(MapPerms::EXEC)
                    && map.perms.contains(MapPerms::READ)
            })
            .map(|map| (map.start, map.end))
            .collect();
        assert!(!file_data_ranges.is_empty());

        // SAFETY: this child satisfies the single-hook installation contract.
        let mut plain_applied = unsafe { install_hook(plain) }.unwrap();
        assert_eq!(
            plain_applied.concealment(),
            Concealment::InPlace("concealment not requested")
        );
        // SAFETY: the plain hook has drained before concealment is requested.
        unsafe { plain_applied.unhook() }.unwrap();

        let error = unsafe { install_hook(hook) }.unwrap_err();
        assert!(matches!(
            error,
            Error::UnsupportedFeature("concealed PLT mutations are disabled in this release")
        ));
        // SAFETY: getpid takes no arguments and cannot fail.
        assert_eq!(unsafe { getpid() }, expected_pid);
        assert_eq!(restore_concealed_mutations().unwrap(), 0);
        return;
    }

    run_child(
        "plt::tests::install::requested_concealment_fails_closed_before_mutation",
        CONCEAL_CHILD,
    );
}
/// Concealment fails before mutation even when a page is locked.
#[test]
fn requested_concealment_rejects_a_locked_relocation_page() {
    if std::env::var_os(CONCEAL_LOCKED_CHILD).is_some() {
        let _ = unsafe { getpid() };
        let target = Target::current_executable().unwrap();
        let hook = Hook::new(&target, c"getpid", concealed_getpid as *const ())
            .unwrap()
            .require_non_null_previous()
            .enforce_concealed_mutations();
        // SAFETY: this child keeps the selected image stable for inspection.
        let report = unsafe { inspect_hooks(std::slice::from_ref(&hook)) }.unwrap();
        let slot = report[0]
            .images()
            .iter()
            .flat_map(|image| image.slots.iter())
            .find(|slot| slot.status == InspectionStatus::Eligible)
            .expect("getpid relocation slot");
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
        let page = slot.address as usize & !(page_size - 1);
        assert_eq!(unsafe { libc::mlock(page as *const _, page_size) }, 0);
        // SAFETY: the image and replacement remain stable; the expected failure
        // happens before any relocation slot is changed.
        let error = unsafe { install_hook(hook) }.unwrap_err();
        assert_eq!(
            unsafe { libc::munlock(page as *const _, page_size) },
            0,
            "failed to unlock test page after {error:?}"
        );
        assert!(
            matches!(
                error,
                Error::UnsupportedFeature("concealed PLT mutations are disabled in this release")
            ),
            "unexpected locked-page error: {error:?}"
        );
        return;
    }

    run_child(
        "plt::tests::install::requested_concealment_rejects_a_locked_relocation_page",
        CONCEAL_LOCKED_CHILD,
    );
}

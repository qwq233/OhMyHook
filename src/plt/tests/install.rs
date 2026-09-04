use super::*;

unsafe extern "C" {
    fn sysconf(name: libc::c_int) -> libc::c_long;
}

#[cfg(target_arch = "aarch64")]
unsafe extern "C" {
    fn getauxval(kind: libc::c_ulong) -> libc::c_ulong;
}

static ORIGINAL_SYSCONF: OriginalPointerCell = OriginalPointerCell::new();
static ORIGINAL_MALLOC: OriginalPointerCell = OriginalPointerCell::new();
static MALLOC_CALLS: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn counted_malloc(size: usize) -> *mut libc::c_void {
    let original = ORIGINAL_MALLOC
        .get()
        .unwrap_or_else(|| crate::sys::fail_stop());
    // SAFETY: publication preserves the selected malloc import's exact ABI.
    let original = unsafe {
        std::mem::transmute::<*const (), unsafe extern "C" fn(usize) -> *mut libc::c_void>(original)
    };
    MALLOC_CALLS.fetch_add(1, Ordering::Relaxed);
    // SAFETY: the original allocator receives the unchanged size; this
    // replacement neither allocates itself nor re-enters library operations.
    unsafe { original(size) }
}

#[test]
fn allocator_hook_forwards_calls_during_install_and_can_be_removed() {
    let _guard = process_test_guard();
    // SAFETY: malloc accepts this size and free receives its returned pointer.
    unsafe { libc::free(libc::malloc(std::hint::black_box(64))) };
    let image_selector = ElfImageSelector::current_executable().unwrap();
    for budget in [
        None,
        Some(MutationBudget::new(usize::MAX, usize::MAX, usize::MAX)),
    ] {
        let request = PltHookRequest::new(&image_selector, c"malloc", counted_malloc as *const ())
            .unwrap()
            .require_non_null_previous()
            .with_original_pointer_cell(&ORIGINAL_MALLOC);
        let before = MALLOC_CALLS.load(Ordering::Relaxed);
        // SAFETY: the process lock excludes competing slot writers. The
        // allocation-free replacement and published original stay live for
        // the process lifetime, including concurrent allocator readers.
        let report = unsafe {
            match budget {
                Some(budget) => install_hooks_with_budget(&[request], budget),
                None => install_hooks(&[request]),
            }
        }
        .unwrap();
        let (mut installed, failed) = report.into_parts();
        assert!(failed.is_empty());
        let (_, mut hook) = installed.pop().unwrap();
        assert!(MALLOC_CALLS.load(Ordering::Relaxed) > before);
        let before = MALLOC_CALLS.load(Ordering::Relaxed);
        // SAFETY: the replacement forwards malloc's ABI and returns an owned
        // allocation; volatile access also keeps this call observable.
        unsafe {
            let pointer = libc::malloc(std::hint::black_box(64)).cast::<u8>();
            assert!(!pointer.is_null());
            pointer.write_volatile(0x35);
            assert_eq!(pointer.read_volatile(), 0x35);
            libc::free(pointer.cast());
        }
        assert!(MALLOC_CALLS.load(Ordering::Relaxed) > before);
        let writes = hook
            .record
            .as_ref()
            .unwrap()
            .entries()
            .map(PltRemovalEntry::decoded_write)
            .collect::<Vec<_>>();
        // SAFETY: mappings and original remain stable; any concurrent reader
        // which loaded the replacement can finish using its process-live state.
        unsafe { hook.unhook() }.unwrap();
        // SAFETY: the restored import uses the same malloc/free contract.
        unsafe { libc::free(libc::malloc(std::hint::black_box(64))) };
        for write in writes {
            // SAFETY: the captured import slot remains mapped and readable.
            let restored = unsafe { crate::sys::read_pointer(write.address) }.unwrap();
            assert_eq!(restored, write.expected);
        }
        assert!(!hook.is_installed());
    }
}

#[cfg(target_arch = "aarch64")]
extern "C" fn zero_getauxval(kind: libc::c_ulong) -> libc::c_ulong {
    let _ = kind;
    0
}

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

/// Hooking a symbol the engine itself calls must not make the request permanent.
///
/// `sysconf(_SC_PAGESIZE)` is resolved once per process and cached, so removal
/// no longer depends on a symbol the caller is allowed to replace. Without the
/// cache every operation after this installation — removal included — fails
/// with `UnsupportedFeature`, and the request can never be taken back out.
#[test]
fn hooking_sysconf_still_allows_removal() {
    let _guard = process_test_guard();
    {
        // Resolve the real PLT entry before scanning it on lazy-binding
        // GNU/Linux. Android resolves it eagerly.
        // SAFETY: _SC_PAGESIZE is a documented sysconf query.
        let expected_page_size = unsafe { sysconf(libc::_SC_PAGESIZE) };
        assert!(expected_page_size > 0);

        let image_selector = ElfImageSelector::current_executable().unwrap();
        let request =
            PltHookRequest::new(&image_selector, c"sysconf", wedging_sysconf as *const ())
                .unwrap()
                .require_non_null_previous()
                .with_original_pointer_cell(&ORIGINAL_SYSCONF);

        // SAFETY: the process test lock keeps this executable stable,
        // excludes competing writers, and the replacement stays live and
        // ABI-compatible for the complete installation.
        let mut applied = unsafe {
            // SAFETY: this test satisfies the single-request contract.
            install_hook(request)
        }
        .unwrap();
        assert!(applied.is_installed());

        // The replacement is live for callers...
        // SAFETY: _SC_PAGESIZE is a documented sysconf query.
        assert_eq!(unsafe { sysconf(libc::_SC_PAGESIZE) }, 0);
        // ...but the engine keeps the value it resolved before installation.
        assert_eq!(
            crate::sys::page_size().unwrap(),
            usize::try_from(expected_page_size).unwrap()
        );

        // SAFETY: every sysconf call above has drained and the installation
        // guarantees still hold during removal.
        unsafe {
            // SAFETY: the replacement has drained.
            applied.unhook()
        }
        .unwrap();
        assert!(!applied.is_installed());
        // SAFETY: _SC_PAGESIZE is a documented sysconf query.
        assert_eq!(unsafe { sysconf(libc::_SC_PAGESIZE) }, expected_page_size);
    }
}

#[cfg(target_arch = "aarch64")]
#[test]
fn hooking_getauxval_keeps_cached_memory_features() {
    let _guard = process_test_guard();
    {
        let before = crate::sys::aarch64_memory_protection_features();
        let image_selector = ElfImageSelector::current_executable().unwrap();
        let request =
            PltHookRequest::new(&image_selector, c"getauxval", zero_getauxval as *const ())
                .unwrap()
                .require_non_null_previous();

        // SAFETY: the process test lock keeps this executable stable and the
        // replacement is ABI-compatible for the complete installation.
        let mut applied = unsafe { install_hook(request) }.unwrap();
        // SAFETY: getauxval has no pointer arguments and retains no state.
        assert_eq!(unsafe { getauxval(libc::AT_HWCAP2) }, 0);

        let after = crate::sys::aarch64_memory_protection_features();
        assert_eq!(after.bti, before.bti);
        assert_eq!(after.mte, before.mte);

        // SAFETY: the getauxval call above has drained.
        unsafe { applied.unhook() }.unwrap();
    }
}

#[test]
fn bound_fast_path_reports_original_pointer_cell_conflicts() {
    let _guard = process_test_guard();
    let image_selector = ElfImageSelector::current_executable().unwrap();
    let original = OriginalPointerCell::from_expected(std::ptr::without_provenance(0xdead_beef));
    let request = PltHookRequest::new(
        &image_selector,
        c"getpid",
        private_file_validated_getpid as *const (),
    )
    .unwrap()
    .with_original_pointer_cell(&original);

    // SAFETY: preflight rejects the request before any slot is published or
    // written, and the process lock excludes competing writers.
    let error = match unsafe { install_hook(request) } {
        Err(error) => error,
        Ok(_) => panic!("mismatched expected original was accepted"),
    };
    assert!(
        matches!(error, Error::OriginalPointerCellConflict),
        "unexpected error: {error:?}"
    );
}

#[test]
fn budget_precedes_publication_and_publication_precedes_mutation() {
    let _guards = injection_test_guard();
    {
        // Resolve the real PLT entry before scanning it on lazy-binding
        // GNU/Linux. Android resolves it eagerly.
        // SAFETY: getpid takes no arguments.
        let _ = unsafe { getpid() };
        let maps = read_self_maps().unwrap();
        let marker = (executable_marker as *const ()).expose_provenance();
        let executable = find_map_containing(&maps, marker, 1).unwrap();
        let image_selector = ElfImageSelector::new(executable.device, executable.inode).unwrap();
        let original = OriginalPointerCell::new();
        let request =
            PltHookRequest::new(&image_selector, c"getpid", passthrough_getpid as *const ())
                .unwrap()
                .with_original_pointer_cell(&original);

        // SAFETY: the process test lock keeps this executable stable and only reads
        // the relocation state during inspection.
        let inspection = unsafe { inspect_hooks(&[request]) }.unwrap();
        assert!(inspection[0].error.is_none(), "{inspection:?}");
        let eligible = inspection[0]
            .images
            .iter()
            .flat_map(|image| &image.slots)
            .filter(|slot| slot.status == InspectionStatus::SelectionEligible)
            .collect::<Vec<_>>();
        assert!(!eligible.is_empty());
        // Bionic sometimes maps the single GOT page with RELRO merged into a
        // neighbouring writable segment in a heavily threaded process, so a
        // writable slot is legal; both budget and protection ordering below
        // must hold either way.
        let slots_need_protection = eligible
            .iter()
            .any(|slot| !slot.permissions.contains(MapPerms::WRITE));
        drop(eligible);

        crate::sys::tests::fail_next_protect();
        // SAFETY: the zero budget rejects the fully preflighted mutation
        // before publication or any page-protection syscall.
        let budget_error =
            unsafe { install_hooks_with_budget(&[request], MutationBudget::new(0, 0, 0)) }
                .unwrap_err();
        assert!(matches!(budget_error, Error::MutationBudgetExceeded { .. }));
        assert!(original.get().is_none());
        crate::sys::tests::restore_next_protect();

        if slots_need_protection && !forced_writes_supported() {
            // SAFETY: the replacement is ABI-compatible and remains live. The
            // armed one-shot failure forces page elevation to fail before any
            // slot change, so the original publication ordering stays
            // observable.
            crate::sys::tests::fail_next_protect();
            let protection_error = unsafe {
                // SAFETY: the test owns the live slot and holds the lock.
                install_hooks(&[request])
            }
            .unwrap_err();
            assert!(matches!(
                protection_error,
                Error::SystemCall {
                    operation: "mprotect",
                    ..
                }
            ));
            crate::sys::tests::restore_next_protect();
        }
        // SAFETY: whatever the initial mapping permissions were, a successful
        // install must have published the original pointer.
        let mut applied = unsafe { install_hooks(&[request]) }
            .unwrap()
            .into_parts()
            .0
            .pop()
            .unwrap()
            .1;
        assert!(original.get().is_some());
        // SAFETY: the passthrough replacement has drained.
        unsafe { applied.unhook() }.unwrap();
    }
}

#[test]
fn duplicate_slots_report_only_the_conflicting_slots() {
    let _guard = process_test_guard();
    FIRST_SLOT.store(20, Ordering::SeqCst);
    SECOND_SLOT.store(21, Ordering::SeqCst);
    let conflict = FIRST_SLOT.as_ptr() as usize;
    let independent = SECOND_SLOT.as_ptr() as usize;
    let maps = read_self_maps().unwrap();
    let map = find_map_containing(&maps, conflict, std::mem::size_of::<usize>()).unwrap();
    assert!(find_map_containing(&maps, independent, std::mem::size_of::<usize>()).is_some());
    let image_selector = ElfImageSelector::new(map.device, map.inode).unwrap();
    let replacement = std::ptr::without_provenance(40);
    let hooks = [
        PltHookRequest::new(&image_selector, c"first", replacement).unwrap(),
        PltHookRequest::new(&image_selector, c"second", replacement).unwrap(),
    ];
    let mut image_id = ImageMappingKey::for_test(map.device, map.inode, map.start);
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
        #[cfg(target_arch = "aarch64")]
        replacement_landings: None,
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
    let _guard = process_test_guard();
    FIRST_SLOT.store(20, Ordering::SeqCst);
    SECOND_SLOT.store(21, Ordering::SeqCst);
    let addresses = [
        (FIRST_SLOT.as_ptr() as usize, JumpSlotState::Resolved),
        (SECOND_SLOT.as_ptr() as usize, JumpSlotState::Resolved),
    ];
    let (image_selector, scan) = scan_for(&addresses);
    let request =
        PltHookRequest::new(&image_selector, c"symbol", std::ptr::without_provenance(40)).unwrap();

    assert!(matches!(
        build_hook_plan(&request, &scan),
        Err(Error::AmbiguousPreviousPointer)
    ));
    assert_eq!(FIRST_SLOT.load(Ordering::SeqCst), 20);
    assert_eq!(SECOND_SLOT.load(Ordering::SeqCst), 21);
}

#[test]
fn non_null_previous_is_opt_in_and_checked_before_writing() {
    let _guard = process_test_guard();
    LAZY_SLOT.store(0, Ordering::SeqCst);
    let address = LAZY_SLOT.as_ptr() as usize;
    let (image_selector, scan) = scan_for(&[(address, JumpSlotState::Resolved)]);
    let request =
        PltHookRequest::new(&image_selector, c"symbol", std::ptr::without_provenance(40)).unwrap();

    let plan = build_hook_plan(&request, &scan).unwrap();
    assert_eq!(plan.previous, 0);
    assert!(matches!(
        build_hook_plan(&request.require_non_null_previous(), &scan),
        Err(Error::NullPreviousPointer)
    ));
    assert_eq!(LAZY_SLOT.load(Ordering::SeqCst), 0);
}

#[test]
fn lazy_and_ambiguous_ifunc_slots_require_proof() {
    let _guard = process_test_guard();
    let maps = read_self_maps().unwrap();
    let address = LAZY_SLOT.as_ptr() as usize;
    let map = find_map_containing(&maps, address, std::mem::size_of::<usize>()).unwrap();
    LAZY_SLOT.store(map.start, Ordering::SeqCst);
    let (image_selector, lazy) = scan_for(&[(address, JumpSlotState::Lazy(map.start))]);
    let request =
        PltHookRequest::new(&image_selector, c"symbol", std::ptr::without_provenance(40)).unwrap();
    assert!(matches!(
        build_hook_plan(&request, &lazy),
        Err(Error::UnsupportedFeature("unresolved lazy PLT relocation"))
    ));

    let address = IFUNC_SLOT.as_ptr() as usize;
    let map = find_map_containing(&maps, address, std::mem::size_of::<usize>()).unwrap();
    IFUNC_SLOT.store(map.start, Ordering::SeqCst);
    let (image_selector, ambiguous) = scan_for(&[(address, JumpSlotState::AmbiguousIfunc)]);
    let request =
        PltHookRequest::new(&image_selector, c"symbol", std::ptr::without_provenance(41)).unwrap();
    assert!(matches!(
        build_hook_plan(&request, &ambiguous),
        Err(Error::UnsupportedFeature("ambiguous IFUNC jump-slot state"))
    ));

    let (_, proven) = scan_for(&[(address, JumpSlotState::AmbiguousIfunc)]);
    let request = request.with_resolved_ifunc(std::ptr::with_exposed_provenance(map.start));
    assert!(build_hook_plan(&request, &proven).is_ok());
}

#[test]
fn lazy_original_hint_preserves_raw_restore_and_resolved_previous() {
    let _guard = process_test_guard();
    let address = LAZY_SLOT.as_ptr() as usize;
    let resolver = 20;
    LAZY_SLOT.store(resolver, Ordering::SeqCst);
    let (image_selector, mut scan) = scan_for(&[(address, JumpSlotState::Lazy(resolver))]);
    let request =
        PltHookRequest::new(&image_selector, c"symbol", std::ptr::without_provenance(40)).unwrap();
    let resolved = request.with_resolved_original(std::ptr::without_provenance(30));
    let plan = build_hook_plan(&resolved, &scan).unwrap();
    assert_eq!(plan.previous, 30);
    assert_eq!(plan.writes[0].expected, resolver);
    assert_eq!(plan.writes[0].replacement, 40);
    let single = build_single_hook_plan(&resolved, &scan.relocations[0]).unwrap();
    assert_eq!(single.previous, 30);
    assert_eq!(single.write.expected, resolver);
    assert_eq!(LAZY_SLOT.load(Ordering::SeqCst), resolver);

    for invalid in [0, resolver, 40] {
        assert!(matches!(
            build_hook_plan(
                &request.with_resolved_original(std::ptr::without_provenance(invalid)),
                &scan,
            ),
            Err(Error::Conflict)
        ));
    }
    assert!(matches!(
        build_hook_plan(
            &request.with_resolved_ifunc(std::ptr::without_provenance(30)),
            &scan,
        ),
        Err(Error::UnsupportedFeature("unresolved lazy PLT relocation"))
    ));

    LAZY_SLOT.store(50, Ordering::SeqCst);
    assert_eq!(build_hook_plan(&resolved, &scan).unwrap().previous, 50);
    scan.relocations[0].jump_slot_state = JumpSlotState::Resolved;
    assert_eq!(build_hook_plan(&resolved, &scan).unwrap().previous, 50);

    LAZY_SLOT.store(resolver, Ordering::SeqCst);
    SECOND_SLOT.store(50, Ordering::SeqCst);
    let (_, mixed) = scan_for(&[
        (address, JumpSlotState::Lazy(resolver)),
        (SECOND_SLOT.as_ptr() as usize, JumpSlotState::Resolved),
    ]);
    assert!(matches!(
        build_hook_plan(&resolved, &mixed),
        Err(Error::AmbiguousPreviousPointer)
    ));
}

/// Our own committed replacement makes a jump slot look lazy on glibc because
/// the value points back into the same image, but the process registry knows
/// the exact pointer it installed there and must keep stacking available.
#[test]
fn a_recorded_replacement_on_a_lazy_looking_slot_allows_stacking() {
    let _guard = process_test_guard();
    let maps = read_self_maps().unwrap();
    let address = RECORDED_LAZY_SLOT.as_ptr() as usize;
    let map = find_map_containing(&maps, address, std::mem::size_of::<usize>()).unwrap();
    let previous = map.start;
    RECORDED_LAZY_SLOT.store(previous, Ordering::SeqCst);
    let (image_selector, lazy) = scan_for(&[(address, JumpSlotState::Lazy(previous))]);
    let request =
        PltHookRequest::new(&image_selector, c"symbol", std::ptr::without_provenance(50)).unwrap();
    let write = StoredPointerWrite {
        image: lazy.relocations[0].image,
        address,
        expected: 0,
        replacement: previous,
    };
    {
        let _process_guard = crate::sys::PROCESS_LOCK.write().unwrap();
        record_installed_writes(9001, std::slice::from_ref(&write));
    }

    let plan = build_hook_plan(&request, &lazy).unwrap();
    assert_eq!(plan.previous, previous);

    {
        let _process_guard = crate::sys::PROCESS_LOCK.write().unwrap();
        complete_removal(&[(9001, address, previous)]);
    }
    assert!(matches!(
        build_hook_plan(&request, &lazy),
        Err(Error::UnsupportedFeature("unresolved lazy PLT relocation"))
    ));
}

#[test]
fn current_replacement_is_a_conflict() {
    let _guard = process_test_guard();
    CURRENT_REPLACEMENT_SLOT.store(30, Ordering::SeqCst);
    let address = CURRENT_REPLACEMENT_SLOT.as_ptr() as usize;
    let (image_selector, scan) = scan_for(&[(address, JumpSlotState::Resolved)]);
    let request =
        PltHookRequest::new(&image_selector, c"symbol", std::ptr::without_provenance(30)).unwrap();
    assert!(matches!(
        build_hook_plan(&request, &scan),
        Err(Error::Conflict)
    ));
}

#[test]
fn serialized_revalidation_detects_slot_and_original_changes() {
    let _slot_guard = process_test_guard();
    FIRST_SLOT.store(20, Ordering::SeqCst);
    let address = FIRST_SLOT.as_ptr() as usize;
    let (image_selector, scan) = scan_for(&[(address, JumpSlotState::Resolved)]);
    let original = OriginalPointerCell::new();
    let request = PltHookRequest::new(&image_selector, c"symbol", std::ptr::without_provenance(40))
        .unwrap()
        .with_original_pointer_cell(&original);
    let plans = [Some(build_hook_plan(&request, &scan).unwrap())];
    let _process_guard = crate::sys::PROCESS_LOCK.write().unwrap();

    // SAFETY: the test owns the live slot and holds the process write lock.
    assert!(
        unsafe {
            // SAFETY: the test owns the live slot and process lock.
            revalidate_hook_plans(&[request], &plans)
        }
        .unwrap()[0]
            .is_none()
    );
    FIRST_SLOT.store(21, Ordering::SeqCst);
    // SAFETY: the same slot and lock guarantees still hold.
    assert!(matches!(
        unsafe {
            // SAFETY: the same slot and lock guarantees still hold.
            revalidate_hook_plans(&[request], &plans)
        }
        .unwrap()[0],
        Some(Error::Conflict)
    ));

    FIRST_SLOT.store(20, Ordering::SeqCst);
    original.value.set(21).unwrap();
    // SAFETY: the same slot and lock guarantees still hold.
    assert!(matches!(
        unsafe {
            // SAFETY: the same slot and lock guarantees still hold.
            revalidate_hook_plans(&[request], &plans)
        }
        .unwrap()[0],
        Some(Error::OriginalPointerCellConflict)
    ));
}

#[test]
fn unhook_is_atomic_retryable_and_restores_multiple_slots() {
    let _guard = process_test_guard();
    let mut applied = installed_handle(&[&FIRST_SLOT, &SECOND_SLOT], 20, 30);
    assert_eq!(applied.slots().get(), 2);
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
    let _guard = process_test_guard();
    FIRST_SLOT.store(20, Ordering::SeqCst);
    let address = FIRST_SLOT.as_ptr() as usize;
    let maps = read_self_maps().unwrap();

    let (image_selector, outer_scan) = scan_for(&[(address, JumpSlotState::Resolved)]);
    let outer_hook =
        PltHookRequest::new(&image_selector, c"symbol", std::ptr::without_provenance(30)).unwrap();
    let outer_plans = [Some(build_hook_plan(&outer_hook, &outer_scan).unwrap())];
    FIRST_SLOT.store(30, Ordering::SeqCst);
    let (_, inner_scan) = scan_for(&[(address, JumpSlotState::Resolved)]);
    let inner_hook =
        PltHookRequest::new(&image_selector, c"symbol", std::ptr::without_provenance(40)).unwrap();
    let inner_plans = [Some(build_hook_plan(&inner_hook, &inner_scan).unwrap())];
    FIRST_SLOT.store(40, Ordering::SeqCst);

    let empty_protections = Arc::new(BTreeMap::new());
    let mut outer_records = prepare_plt_records(
        &[outer_hook],
        &maps,
        &[Some(outer_scan)],
        &outer_plans,
        &empty_protections,
    )
    .unwrap();
    let mut inner_records = prepare_plt_records(
        &[inner_hook],
        &maps,
        &[Some(inner_scan)],
        &inner_plans,
        &empty_protections,
    )
    .unwrap();
    let mut outer = PltHookHandle {
        previous: crate::sys::encode_usize(outer_plans[0].as_ref().unwrap().previous),
        slots: outer_plans[0].as_ref().unwrap().slots,
        private_file_validation: PrivateFileValidation::Unvalidated,
        forced_descriptor_close_errno: None,
        record: outer_records[0].take(),
    };
    let mut inner = PltHookHandle {
        previous: crate::sys::encode_usize(inner_plans[0].as_ref().unwrap().previous),
        slots: inner_plans[0].as_ref().unwrap().slots,
        private_file_validation: PrivateFileValidation::Unvalidated,
        forced_descriptor_close_errno: None,
        record: inner_records[0].take(),
    };
    {
        let _process_guard = crate::sys::PROCESS_LOCK.write().unwrap();
        record_installed_writes(
            outer.record.as_ref().unwrap().id,
            &outer_plans[0].as_ref().unwrap().writes,
        );
        record_installed_writes(
            inner.record.as_ref().unwrap().id,
            &inner_plans[0].as_ref().unwrap().writes,
        );
    }

    // A slot value colliding with the older request's replacement must not let
    // that request bypass the newer installed writer.
    FIRST_SLOT.store(30, Ordering::SeqCst);
    assert!(matches!(
        unsafe {
            // SAFETY: the test owns the stable slot and no writer competes.
            outer.unhook()
        },
        Err(Error::Conflict)
    ));
    assert!(outer.is_installed());

    // LIFO removal restores each writer's saved value in order.
    FIRST_SLOT.store(40, Ordering::SeqCst);
    // SAFETY: the test owns the stable slot and no competing writer exists.
    unsafe { inner.unhook() }.unwrap();
    assert_eq!(FIRST_SLOT.load(Ordering::SeqCst), 30);
    // SAFETY: the newer writer is removed and the slot again holds this request.
    unsafe { outer.unhook() }.unwrap();
    assert_eq!(FIRST_SLOT.load(Ordering::SeqCst), 20);
}

#[test]
fn complete_stack_batch_removal_is_canonicalized_newest_first() {
    let _guard = process_test_guard();
    let outer = installed_handle(&[&FIRST_SLOT], 20, 30);
    let inner = installed_handle(&[&FIRST_SLOT], 30, 40);
    assert_eq!(FIRST_SLOT.load(Ordering::SeqCst), 40);

    // The caller supplies installation order; the transaction must still
    // remove the newer writer before restoring the older one.
    let mut batch = [outer, inner];
    // SAFETY: the test owns the stable slot and no competing writer exists.
    unsafe { unhook_hooks(&mut batch) }.unwrap();
    assert!(batch.iter().all(|request| !request.is_installed()));
    assert_eq!(FIRST_SLOT.load(Ordering::SeqCst), 20);
}

#[test]
fn complete_stack_batch_distinguishes_repeated_replacements() {
    let _guard = process_test_guard();
    let outer = installed_handle(&[&FIRST_SLOT], 20, 30);
    let middle = installed_handle(&[&FIRST_SLOT], 30, 40);
    let inner = installed_handle(&[&FIRST_SLOT], 40, 30);
    assert_eq!(FIRST_SLOT.load(Ordering::SeqCst), 30);

    let mut batch = [outer, middle, inner];
    // SAFETY: the test owns the stable slot and no competing writer exists.
    unsafe { unhook_hooks(&mut batch) }.unwrap();
    assert!(batch.iter().all(|request| !request.is_installed()));
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

#[unsafe(export_name = "private_file_validated_getpid")]
extern "C" fn private_file_validated_getpid() -> i32 {
    0x7C0
}

fn read_backing_slot(address: usize, map: &MapInfo) -> Option<[u8; 8]> {
    let path = map.path.as_deref()?;
    let offset = map
        .offset
        .checked_add(u64::try_from(address.checked_sub(map.start)?).ok()?)?;
    let mut file = std::fs::File::open(path).ok()?;
    use std::io::{Read, Seek, SeekFrom};
    file.seek(SeekFrom::Start(offset)).ok()?;
    let mut bytes = [0_u8; 8];
    file.read_exact(&mut bytes).ok()?;
    Some(bytes)
}

/// PrivateFileValidation keeps a GOT page inside its original private file mapping.
#[test]
fn requested_private_file_validation_keeps_the_got_page_private() {
    let _guards = injection_test_guard();
    {
        // Resolve the real PLT entry before scanning it on lazy-binding
        // GNU/Linux. Android resolves it eagerly.
        // SAFETY: getpid takes no arguments and cannot fail.
        let expected_pid = unsafe { getpid() };
        let image_selector = ElfImageSelector::current_executable().unwrap();
        let request = PltHookRequest::new(
            &image_selector,
            c"getpid",
            private_file_validated_getpid as *const (),
        )
        .unwrap()
        .require_non_null_previous()
        .require_private_file_pages()
        .require_bound_image()
        .unwrap();

        // SAFETY: inspection is read-only and the image stays loaded.
        let report = unsafe { inspect_hooks(std::slice::from_ref(&request)) }.unwrap();
        let slot = report[0]
            .images()
            .iter()
            .flat_map(|image| image.slots.iter())
            .find(|slot| slot.status == InspectionStatus::SelectionEligible)
            .expect("getpid relocation slot");
        let slot_address = slot.address as usize;
        let before = read_self_maps().unwrap();
        let original = before
            .iter()
            .find(|map| slot_address >= map.start && slot_address < map.end)
            .expect("GOT mapping");
        let original_perms = original.perms;
        let original_inode = original.inode;
        let original_device = original.device;
        let original_path = original.path.clone();
        let backing_before = read_backing_slot(slot_address, original)
            .expect("the Validated GOT slot must have a readable backing file");

        // SAFETY: this test satisfies the single-request installation contract.
        let mut applied = unsafe {
            // SAFETY: this test satisfies the single-request contract.
            install_hook(request)
        }
        .unwrap();
        assert_eq!(
            applied.private_file_validation(),
            PrivateFileValidation::Validated
        );
        assert_eq!(
            unsafe {
                // SAFETY: the replacement is ABI-compatible with getpid.
                getpid()
            },
            0x7C0
        );

        // The Validated page stays inside its original file mapping: no
        // anonymous replacement, no split, and no permission widening.
        let during = read_self_maps().unwrap();
        let live = during
            .iter()
            .find(|map| slot_address >= map.start && slot_address < map.end)
            .expect("live GOT mapping");
        assert_eq!(live.perms, original_perms);
        assert_eq!(live.inode, original_inode);
        assert_eq!(live.device, original_device);
        assert_eq!(live.path, original_path);

        // SAFETY: the replacement has drained.
        unsafe {
            // SAFETY: the replacement has drained.
            applied.unhook()
        }
        .unwrap();
        assert_eq!(
            unsafe {
                // SAFETY: the original implementation is restored.
                getpid()
            },
            expected_pid
        );
        let restored = read_self_maps().unwrap();
        let got = restored
            .iter()
            .find(|map| slot_address >= map.start && slot_address < map.end)
            .expect("restored GOT mapping");
        // Restore must return the page to its exact original protection. A
        // read-only RELRO GOT page that comes back writable is a permanent
        // hardening loss, not a cosmetic difference.
        assert_eq!(got.perms, original_perms);
        assert_eq!(got.inode, original_inode);
        assert_eq!(got.path, original_path);
        let backing_after = read_backing_slot(slot_address, got)
            .expect("the restored GOT slot must still have a readable backing file");
        assert_eq!(
            backing_before, backing_after,
            "the install or removal changed the backing file's bytes"
        );
    }
}

#[cfg(target_arch = "aarch64")]
#[test]
fn bti_plt_pages_preserve_access_and_existing_guards() {
    let features = crate::sys::aarch64_memory_protection_features();
    if !features.bti {
        return;
    }
    let _guards = injection_test_guard();
    for (bti, budgeted) in [(false, false), (true, false), (false, true), (true, true)] {
        // SAFETY: getpid takes no arguments and cannot fail.
        let expected_pid = unsafe { getpid() };
        let image_selector = ElfImageSelector::current_executable().unwrap();
        let request = PltHookRequest::new(
            &image_selector,
            c"getpid",
            private_file_validated_getpid as *const (),
        )
        .unwrap()
        .require_non_null_previous();

        // SAFETY: inspection is read-only and the image stays loaded.
        let report = unsafe { inspect_hooks(std::slice::from_ref(&request)) }.unwrap();
        let slot = report[0]
            .images()
            .iter()
            .flat_map(|image| image.slots.iter())
            .find(|slot| slot.status == InspectionStatus::SelectionEligible)
            .expect("getpid relocation slot");
        let slot_address = slot.address as usize;
        let maps = read_self_maps().unwrap();
        let slot_map = maps
            .iter()
            .find(|map| slot_address >= map.start && slot_address < map.end)
            .expect("GOT mapping");
        let original_protection = if slot_map.perms.contains(MapPerms::WRITE) {
            slot_map.perms.to_prot() & !libc::PROT_WRITE
        } else {
            slot_map.perms.to_prot()
        };
        let page_size = crate::sys::page_size().unwrap();
        let page = crate::sys::page_start(slot_address, page_size);
        let initial_smaps =
            crate::maps::read_self_smaps_for_ranges(&[(page, page + page_size)]).unwrap();
        let initial_flags = initial_smaps
            .iter()
            .find(|entry| entry.map.contains_range(page, page_size))
            .expect("initial GOT smaps")
            .vm_flags;
        let saved_protection = slot_map.perms.to_prot()
            | if initial_flags.bti { PROT_BTI } else { 0 }
            | if initial_flags.mte { PROT_MTE } else { 0 };

        // SAFETY: the process test lock keeps this page quiescent while its
        // non-executable BTI state is set for this installation path.
        unsafe {
            crate::sys::protect(
                page,
                page_size,
                original_protection | if bti { PROT_BTI } else { 0 },
            )
        }
        .expect("GOT page must accept its requested BTI state");
        // SAFETY: the image, slot and ABI stay stable for either installation path.
        let report = unsafe {
            if budgeted {
                install_hooks_with_budget(
                    &[request],
                    MutationBudget::new(usize::MAX, usize::MAX, usize::MAX),
                )
            } else {
                install_hooks(&[request])
            }
        }
        .expect("GOT page installation failed");
        let (mut installed, failed) = report.into_parts();
        assert!(failed.is_empty());
        let (_, mut applied) = installed.pop().unwrap();
        // SAFETY: getpid has no arguments and the replacement is ABI-compatible.
        let hooked_pid = unsafe { getpid() };
        // SAFETY: installation resolved the selected getpid import's exact ABI.
        let original = unsafe {
            std::mem::transmute::<*const (), unsafe extern "C" fn() -> i32>(
                applied.original().unwrap(),
            )
        };
        // SAFETY: the original implementation remains loaded and takes no arguments.
        let original_pid = unsafe { original() };
        let installed_smaps =
            crate::maps::read_self_smaps_for_ranges(&[(page, page + page_size)]).unwrap();
        let installed_flags = installed_smaps
            .iter()
            .find(|entry| entry.map.contains_range(page, page_size))
            .expect("installed GOT smaps")
            .vm_flags;

        // SAFETY: the getpid replacement has drained.
        unsafe { applied.unhook() }.expect("BTI GOT page removal failed");
        let restored_smaps =
            crate::maps::read_self_smaps_for_ranges(&[(page, page + page_size)]).unwrap();
        let restored_flags = restored_smaps
            .iter()
            .find(|entry| entry.map.contains_range(page, page_size))
            .expect("restored GOT smaps")
            .vm_flags;
        // SAFETY: no other hook is installed on this test-owned page.
        unsafe { crate::sys::protect(page, page_size, saved_protection) }
            .expect("GOT page protection must be restored");
        assert_eq!(hooked_pid, 0x7C0);
        assert_eq!(original_pid, expected_pid);
        // SAFETY: the original implementation is restored.
        assert_eq!(unsafe { getpid() }, expected_pid);
        let expected_bti = bti || !features.mte;
        assert_eq!(
            installed_flags.bti, expected_bti,
            "installed BTI state, budgeted={budgeted}"
        );
        assert_eq!(
            restored_flags.bti, expected_bti,
            "restored BTI state, budgeted={budgeted}"
        );
        assert_eq!(installed_flags.mte, initial_flags.mte);
        assert_eq!(restored_flags.mte, initial_flags.mte);
        for entries in [&installed_smaps, &restored_smaps] {
            let entry = entries
                .iter()
                .find(|entry| entry.map.contains_range(page, page_size))
                .unwrap();
            assert_eq!(entry.map.perms.to_prot(), original_protection);
        }
    }
}

/// A Validated install uses the atomic elevation path.
#[test]
fn private_file_validated_write_uses_atomic_elevation() {
    let _guards = injection_test_guard();
    {
        let selector_maps = read_self_maps().unwrap();
        let executable = find_map_containing(
            &selector_maps,
            (executable_marker as *const ()).expose_provenance(),
            1,
        )
        .unwrap();
        let image_selector = ElfImageSelector::new(executable.device, executable.inode).unwrap();
        let request = PltHookRequest::new(
            &image_selector,
            c"getpid",
            private_file_validated_getpid as *const (),
        )
        .unwrap()
        .require_non_null_previous()
        .require_private_file_pages();
        // SAFETY: this test satisfies the single-request installation contract.
        let mut applied = unsafe { install_hook(request) }
            .expect("the atomic elevation path must install the request");
        assert_eq!(
            applied.private_file_validation(),
            PrivateFileValidation::Validated
        );
        assert!(
            !crate::sys::tests::self_mem_open_failure_pending(),
            "the forced channel was never opened"
        );
        // SAFETY: all calls through the replacement have drained.
        unsafe { applied.unhook() }.expect("forced removal failed");
    }
}

/// The PLT path never opens `/proc/self/mem`, so a failed self-mem probe is
/// ignored and the atomic elevation path remains available.
#[test]
fn private_file_validated_self_mem_unavailable_is_ignored() {
    let _guards = injection_test_guard();
    {
        let image_selector = ElfImageSelector::current_executable().unwrap();
        let request = PltHookRequest::new(
            &image_selector,
            c"getpid",
            private_file_validated_getpid as *const (),
        )
        .unwrap()
        .require_non_null_previous()
        .require_private_file_pages();
        // SAFETY: this test satisfies the single-request installation contract.
        let mut applied =
            unsafe { install_hook(request) }.expect("the elevation fallback must remain available");
        crate::sys::tests::restore_next_self_mem_open();
        assert_eq!(
            applied.private_file_validation(),
            PrivateFileValidation::Validated
        );
        // SAFETY: all calls through the replacement have drained.
        unsafe { applied.unhook() }.expect("fallback removal failed");
    }
}

#[test]
fn private_file_validated_elevation_failure_is_reported() {
    let _guards = injection_test_guard();
    {
        let selector_maps = read_self_maps().unwrap();
        let executable = find_map_containing(
            &selector_maps,
            (executable_marker as *const ()).expose_provenance(),
            1,
        )
        .unwrap();
        let image_selector = ElfImageSelector::new(executable.device, executable.inode).unwrap();
        let request = PltHookRequest::new(
            &image_selector,
            c"getpid",
            private_file_validated_getpid as *const (),
        )
        .unwrap()
        .require_non_null_previous()
        .require_private_file_pages();
        // Force the selected GOT page through the elevation path so this test
        // does not depend on whether the loader left the slot writable.
        // SAFETY: the process test lock keeps this executable stable and
        // inspection read-only.
        let report = unsafe { inspect_hooks(std::slice::from_ref(&request)) }.unwrap();
        let slot = report[0]
            .images()
            .iter()
            .flat_map(|image| image.slots.iter())
            .find(|slot| slot.status == InspectionStatus::SelectionEligible)
            .expect("getpid relocation slot");
        let slot_address = slot.address as usize;
        let maps = read_self_maps().unwrap();
        let slot_map = maps
            .iter()
            .find(|map| slot_address >= map.start && slot_address < map.end)
            .expect("GOT mapping");
        let original_protection = if slot_map.perms.contains(MapPerms::WRITE) {
            slot_map.perms.to_prot() & !libc::PROT_WRITE
        } else {
            slot_map.perms.to_prot()
        };
        let page = crate::sys::page_start(slot_address, crate::sys::page_size().unwrap());
        // SAFETY: the process test lock keeps this page quiescent while the
        // installation is forced onto the elevation path.
        unsafe { crate::sys::protect(page, crate::sys::page_size().unwrap(), original_protection) }
            .expect("GOT page must be made non-writable");
        let protected = read_self_maps().unwrap();
        let protected_map = protected
            .iter()
            .find(|map| slot_address >= map.start && slot_address < map.end)
            .expect("protected GOT mapping");
        assert!(!protected_map.perms.contains(MapPerms::WRITE));
        crate::sys::tests::fail_next_protect();

        // SAFETY: the request fails before any slot is published, so the
        // replacement is never called and the complete install contract holds.
        let error = match unsafe { install_hook(request) } {
            Err(error) => error,
            Ok(_) => panic!("both mutation channels must fail"),
        };
        crate::sys::tests::restore_next_protect();
        // SAFETY: no other hook is installed and the failed installation made
        // no slot write on this page.
        unsafe {
            crate::sys::protect(
                page,
                crate::sys::page_size().unwrap(),
                slot_map.perms.to_prot(),
            )
        }
        .expect("GOT page protection must be restored");

        match error {
            Error::SystemCall {
                operation: "mprotect",
                source: syscalls::Errno::EPERM,
            } => {}
            other => panic!("unexpected dual-channel failure: {other:?}"),
        }
    }
}

/// A `/proc/self/mem` write refusal must not affect the PLT path, which no
/// longer uses that channel for atomic pointer publication.
#[test]
fn private_file_validated_self_mem_write_refusal_is_ignored() {
    let _guards = injection_test_guard();
    {
        let image_selector = ElfImageSelector::current_executable().unwrap();
        let request = PltHookRequest::new(
            &image_selector,
            c"getpid",
            private_file_validated_getpid as *const (),
        )
        .unwrap()
        .require_non_null_previous()
        .require_private_file_pages();
        crate::sys::tests::fail_next_self_mem_write();
        // SAFETY: this test satisfies the single-request installation contract.
        let mut applied = unsafe { install_hook(request) }
            .expect("a write refusal must not affect the atomic path");
        crate::sys::tests::restore_next_self_mem_write();
        assert_eq!(
            applied.private_file_validation(),
            PrivateFileValidation::Validated
        );
        // SAFETY: all calls through the replacement have drained.
        unsafe { applied.unhook() }.expect("fallback removal failed");
    }
}

extern "C" fn private_file_validated_gettid() -> i32 {
    0x7C1
}

/// Two Validated hooks in one image report their own result, unhook cleanly,
/// and leave no registered PrivateFileValidation range behind.
#[test]
fn private_file_validated_hooks_in_one_image_unhook_cleanly() {
    let _guards = injection_test_guard();
    {
        let image_selector = ElfImageSelector::current_executable().unwrap();
        let first = PltHookRequest::new(
            &image_selector,
            c"getpid",
            private_file_validated_getpid as *const (),
        )
        .unwrap()
        .require_non_null_previous()
        .require_private_file_pages();
        let second = PltHookRequest::new(
            &image_selector,
            c"gettid",
            private_file_validated_gettid as *const (),
        )
        .unwrap()
        .require_non_null_previous()
        .require_private_file_pages();

        // SAFETY: each test satisfies the single-request installation contract;
        // the process test lock serializes the two installs.
        let mut first_applied = unsafe {
            // SAFETY: this test satisfies the single-request contract.
            install_hook(first)
        }
        .unwrap();
        assert_eq!(
            first_applied.private_file_validation(),
            PrivateFileValidation::Validated
        );
        let mut second_applied = unsafe {
            // SAFETY: this test satisfies the single-request contract.
            install_hook(second)
        }
        .unwrap();
        assert_eq!(
            second_applied.private_file_validation(),
            PrivateFileValidation::Validated
        );

        // SAFETY: both replacements have drained before removal.
        unsafe {
            // SAFETY: both replacements have drained before removal.
            first_applied.unhook()
        }
        .unwrap();
        unsafe {
            // SAFETY: both replacements have drained before removal.
            second_applied.unhook()
        }
        .unwrap();

        // SAFETY: both original imports are restored and have no preconditions.
        let originals = unsafe { [getpid(), libc::gettid()] };
        let missing = PltHookRequest::new(
            &image_selector,
            c"omhook_missing_batch_candidate",
            private_file_validated_getpid as *const (),
        )
        .unwrap();
        // SAFETY: the same live ABI-compatible entries and exclusive slots
        // remain valid for the complete batch and its removal.
        let report = unsafe { install_hooks(&[first, missing, second]) }.unwrap();
        assert!(report[0].is_ok());
        assert!(matches!(report[1], Err(Error::NoMatchingRelocation)));
        assert!(report[2].is_ok());
        let (mut installed, failed) = report.into_parts();
        assert_eq!(installed.len(), 2);
        assert_eq!((installed[0].0, installed[1].0), (0, 2));
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].0, 1);
        // SAFETY: both installed replacements preserve the import ABIs.
        assert_eq!(unsafe { [getpid(), libc::gettid()] }, [0x7C0, 0x7C1]);
        for ((_, handle), expected) in installed.iter_mut().zip(originals) {
            // SAFETY: each saved original has the selected zero-argument ABI.
            let original = unsafe {
                std::mem::transmute::<*const (), unsafe extern "C" fn() -> i32>(
                    handle.original().unwrap(),
                )
            };
            // SAFETY: the original code remains loaded throughout the test.
            assert_eq!(unsafe { original() }, expected);
            // SAFETY: all calls have drained and both mappings remain stable.
            unsafe { handle.unhook() }.unwrap();
        }
        // SAFETY: removal restored both original imports and their ABIs.
        assert_eq!(unsafe { [getpid(), libc::gettid()] }, originals);
    }
}

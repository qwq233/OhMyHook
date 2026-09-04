use super::*;

#[test]
fn required_and_optional_groups_classify_only_candidate_absence() {
    let target = Target::new(DeviceId::new(u32::MAX, u32::MAX), u64::MAX).unwrap();
    let replacement = std::ptr::NonNull::<()>::dangling().as_ptr();
    let hooks = [Hook::new(&target, c"missing", replacement).unwrap()];

    // SAFETY: the selector intentionally cannot match a loaded image, so
    // no replacement can be installed or called.
    let error = unsafe { install_hook_groups(&[HookGroup::required(&hooks)]) }.unwrap_err();
    assert_eq!(error.group, Some(0));
    assert_eq!(error.hook, None);
    assert!(matches!(error.source, Error::RequiredGroupMissing));

    // SAFETY: an empty optional group has no pointer or mapping
    // requirements and remains aligned in the per-group report.
    let empty = unsafe { install_hook_groups(&[HookGroup::optional(&[])]) }.unwrap();
    assert_eq!(empty.len(), 1);
    assert!(empty[0].is_empty());

    let groups = [HookGroup::optional(&[]), HookGroup::required(&hooks)];
    // SAFETY: only the absent selector is inspected; the empty group is a
    // no-op and neither replacement can be installed or called.
    let error = unsafe { install_hook_groups(&groups) }.unwrap_err();
    assert_eq!(error.group, Some(1));
    assert_eq!(error.hook, None);
    assert!(matches!(error.source, Error::RequiredGroupMissing));

    let groups = [HookGroup::optional(&[]), HookGroup::optional(&hooks)];
    // SAFETY: both groups are read-only no-ops or absent selections.
    let report = unsafe { install_hook_groups(&groups) }.unwrap();
    assert!(report[0].is_empty());
    assert!(matches!(report[1][0], Err(Error::TargetNotLoaded)));
}

#[test]
fn original_slot_requires_global_consistency_and_survives_rollback() {
    let target = Target::new(DeviceId::new(1, 2), 3).unwrap();
    let original = OriginalSlot::new();
    let replacement = std::ptr::without_provenance(30);
    let hooks = [
        Hook::new(&target, c"first", replacement)
            .unwrap()
            .with_original_slot(&original),
        Hook::new(&target, c"second", replacement)
            .unwrap()
            .with_original_slot(&original),
    ];
    let plans = [Some(empty_plan(10)), Some(empty_plan(11))];
    assert_eq!(original_slot_conflicts(&hooks, &plans), [true, true]);

    let third_hook = Hook::new(&target, c"third", replacement)
        .unwrap()
        .with_original_slot(&original);
    let three_hooks = [hooks[0], hooks[1], third_hook];
    let three_plans = [
        Some(empty_plan(10)),
        Some(empty_plan(10)),
        Some(empty_plan(11)),
    ];
    assert_eq!(
        original_slot_conflicts(&three_hooks, &three_plans),
        [true, true, true]
    );

    let consistent = [Some(empty_plan(10)), Some(empty_plan(10))];
    assert_eq!(original_slot_conflicts(&hooks, &consistent), [false, false]);
    publish_originals(&hooks, &consistent);
    assert_eq!(original.get(), Some(std::ptr::without_provenance(10)));

    let slot = AtomicUsize::new(20);
    let writes = [pointer_write(&slot, 20, 30)];
    // SAFETY: the stack atomic remains live, writable, aligned, and
    // exclusively owned for the write/rollback sequence.
    assert!(unsafe { crate::sys::compare_exchange_pointer(writes[0].address, 20, 30) }.unwrap());
    // SAFETY: this is exactly the successful write above.
    unsafe { rollback_or_abort(&writes) };
    assert_eq!(slot.load(Ordering::SeqCst), 20);
    assert_eq!(original.get(), Some(std::ptr::without_provenance(10)));
}

#[test]
fn batch_reports_missing_success_and_missing_symbol_in_input_order() {
    if std::env::var_os(STRICT_CHILD).is_some() {
        // Resolve the real PLT slot before scanning it on lazy-binding
        // GNU/Linux. Android resolves it eagerly.
        // SAFETY: getpid has no arguments or caller-side preconditions.
        let before = unsafe { getpid() };
        let maps = read_self_maps().unwrap();
        let marker = (executable_marker as *const ()).expose_provenance();
        let executable = find_map_containing(&maps, marker, 1).unwrap();
        let source = Target::new(executable.device, executable.inode).unwrap();
        let broad = Hook::new(&source, c"getpid", passthrough_getpid as *const ()).unwrap();

        // SAFETY: this child keeps the executable and its resolved getpid
        // relocation stable for inspection and installation.
        let inspection = unsafe { inspect_hooks(&[broad]) }.unwrap();
        assert!(inspection[0].error.is_none(), "{inspection:?}");
        let expected_previous = inspection[0]
            .previous
            .expect("installable Hook has a previous pointer");
        let (target, selector, kinds) = inspection[0]
            .images
            .iter()
            .find_map(|image| {
                image
                    .slots
                    .iter()
                    .find(|slot| slot.status == InspectionStatus::Eligible)
                    .map(|slot| {
                        let kinds = match slot.kind {
                            RelocationKind::Absolute => RelocationKinds::ABSOLUTE,
                            RelocationKind::GlobalData => RelocationKinds::GLOBAL_DATA,
                            RelocationKind::JumpSlot => RelocationKinds::JUMP_SLOT,
                        };
                        (image.image.exact_target(), slot.selector(), kinds)
                    })
            })
            .expect("getpid has an eligible relocation");
        let original = OriginalSlot::new();
        let strict = Hook::new(&target, c"getpid", passthrough_getpid as *const ())
            .unwrap()
            .require_exact_image()
            .unwrap()
            .with_relocation_kinds(kinds)
            .with_slot_selector(selector)
            .unwrap()
            .require_unique_match()
            .with_original_slot(&original);
        let missing = Target::new(DeviceId::new(u32::MAX, u32::MAX), u64::MAX).unwrap();
        let hooks = [
            Hook::new(&missing, c"getpid", passthrough_getpid as *const ()).unwrap(),
            strict,
            Hook::new(
                &target,
                c"omhook_symbol_that_does_not_exist",
                passthrough_getpid as *const (),
            )
            .unwrap(),
        ];

        // SAFETY: the exact inspected slot remains stable, the live
        // replacement has getpid's ABI, and this child excludes writers.
        let mut report = unsafe {
            install_hooks_with_budget(
                &hooks,
                MutationBudget {
                    max_images: 1,
                    max_slots: 1,
                    max_pages: 1,
                },
            )
        }
        .unwrap();
        assert!(matches!(report[0], Err(Error::TargetNotLoaded)));
        {
            let applied = report[1].as_ref().unwrap();
            assert_eq!(applied.slots.get(), 1);
            assert_eq!(applied.previous(), expected_previous);
            assert!(applied.is_installed());
            assert_eq!(applied.original(), Some(expected_previous));
        }
        assert_eq!(original.get(), Some(expected_previous));
        assert!(matches!(report[2], Err(Error::SymbolNotFound)));
        // SAFETY: the installed passthrough preserves getpid's ABI and
        // behavior for the rest of this isolated child.
        assert_eq!(unsafe { getpid() }, before);
        let applied = report[1].as_mut().unwrap();
        // SAFETY: this single-threaded child drained getpid calls and
        // keeps the selected image and slot stable.
        unsafe { applied.unhook() }.unwrap();
        assert!(!applied.is_installed());
        assert!(applied.original().is_none());
        // SAFETY: the original getpid slot and ABI were restored.
        assert_eq!(unsafe { getpid() }, before);
        // SAFETY: successful removal is idempotent.
        unsafe { applied.unhook() }.unwrap();
        return;
    }

    run_child(
        "plt::tests::groups::batch_reports_missing_success_and_missing_symbol_in_input_order",
        STRICT_CHILD,
    );
}

#[test]
fn inspection_succeeds_when_seccomp_rejects_mprotect() {
    if std::env::var_os(INSPECT_CHILD).is_some() {
        // Resolve the executable's real PLT entry before scanning it.
        // SAFETY: getpid takes no arguments.
        let _ = unsafe { getpid() };
        let maps = read_self_maps().unwrap();
        let marker = (executable_marker as *const ()).expose_provenance();
        let executable = find_map_containing(&maps, marker, 1).unwrap();
        let target = Target::new(executable.device, executable.inode).unwrap();
        let hook = Hook::new(&target, c"getpid", passthrough_getpid as *const ()).unwrap();
        crate::sys::tests::install_test_seccomp_errno(&[syscalls::Sysno::mprotect]);

        // SAFETY: this child keeps its executable stable and performs only
        // read-only inspection of a live ABI-compatible replacement.
        let report = unsafe { inspect_hooks(&[hook]) }.unwrap();
        assert!(report[0].error.is_none(), "{report:?}");
        assert!(report[0].images.iter().any(|image| !image.slots.is_empty()));
        crate::sys::tests::exit_seccomp_child();
    }

    run_child(
        "plt::tests::groups::inspection_succeeds_when_seccomp_rejects_mprotect",
        INSPECT_CHILD,
    );
}

use super::*;

#[test]
fn group_private_file_validation_defaults_to_off_and_applies_to_every_hook() {
    let image_selector =
        ElfImageSelector::new(DeviceId::new(u32::MAX, u32::MAX), u64::MAX).unwrap();
    let replacement = std::ptr::NonNull::<()>::dangling().as_ptr();
    let request = PltHookRequest::new(&image_selector, c"missing", replacement).unwrap();
    let hooks = [request];
    let groups = [
        PltHookRequestGroup::optional(&hooks),
        PltHookRequestGroup::optional(&hooks).require_private_file_pages(),
    ];
    assert!(!groups[0].private_file_validation_requested());
    assert!(groups[1].private_file_validation_requested());

    // SAFETY: both selectors are absent, so no replacement is installed,
    // Validated, or called. PrivateFileValidation support is irrelevant because an
    // absent image_selector yields no page to remap.
    match unsafe { install_hook_groups(&groups) } {
        Ok(report) => {
            assert!(matches!(report[0][0], Err(Error::TargetNotLoaded)));
            assert!(matches!(report[1][0], Err(Error::TargetNotLoaded)));
        }
        Err(failure) => assert!(
            matches!(
                failure.source,
                Error::UnsupportedFeature("Validated mutations are not supported")
            ),
            "unexpected group PrivateFileValidation failure: {failure}"
        ),
    }
}

extern "C" fn private_file_validated_group_getpid() -> i32 {
    0x7C2
}

/// A Validated group install uses the atomic elevation path, which keeps the
/// complete group transaction free of torn pointer reads.
#[test]
fn private_file_validated_group_uses_atomic_elevation() {
    let _guards = injection_test_guard();
    {
        let image_selector = ElfImageSelector::current_executable().unwrap();
        let hooks = [PltHookRequest::new(
            &image_selector,
            c"getpid",
            private_file_validated_group_getpid as *const (),
        )
        .unwrap()
        .require_non_null_previous()];
        let groups = [PltHookRequestGroup::optional(&hooks).require_private_file_pages()];
        // SAFETY: this test satisfies the group installation contract and
        // drains every call before removal.
        let report = unsafe { install_hook_groups(&groups) }
            .expect("the atomic elevation path must install the Validated group");
        let report = report.into_groups().pop().unwrap();
        let (mut installed, failed) = report.into_parts();
        assert!(failed.is_empty());
        let (_, mut installed) = installed.pop().unwrap();
        assert_eq!(
            installed.private_file_validation(),
            super::PrivateFileValidation::Validated
        );
        // SAFETY: every replacement call has drained.
        unsafe { installed.unhook() }.expect("group removal failed");
    }
}

#[test]
fn required_and_optional_groups_classify_only_candidate_absence() {
    let image_selector =
        ElfImageSelector::new(DeviceId::new(u32::MAX, u32::MAX), u64::MAX).unwrap();
    let replacement = std::ptr::NonNull::<()>::dangling().as_ptr();
    let hooks = [PltHookRequest::new(&image_selector, c"missing", replacement).unwrap()];

    // SAFETY: the selector intentionally cannot match a loaded image, so
    // no replacement can be installed or called.
    let error =
        unsafe { install_hook_groups(&[PltHookRequestGroup::required(&hooks)]) }.unwrap_err();
    assert_eq!(error.group, Some(0));
    assert_eq!(error.hook_index, None);
    assert!(matches!(error.source, Error::RequiredGroupMissing));

    // SAFETY: an empty optional group has no pointer or mapping
    // requirements and remains aligned in the per-group report.
    let empty = unsafe { install_hook_groups(&[PltHookRequestGroup::optional(&[])]) }.unwrap();
    assert_eq!(empty.len(), 1);
    assert!(empty[0].is_empty());

    let groups = [
        PltHookRequestGroup::optional(&[]),
        PltHookRequestGroup::required(&hooks),
    ];
    // SAFETY: only the absent selector is inspected; the empty group is a
    // no-op and neither replacement can be installed or called.
    let error = unsafe { install_hook_groups(&groups) }.unwrap_err();
    assert_eq!(error.group, Some(1));
    assert_eq!(error.hook_index, None);
    assert!(matches!(error.source, Error::RequiredGroupMissing));

    let groups = [
        PltHookRequestGroup::optional(&[]),
        PltHookRequestGroup::optional(&hooks),
    ];
    // SAFETY: both groups are read-only no-ops or absent selections.
    let report = unsafe { install_hook_groups(&groups) }.unwrap();
    assert!(report[0].is_empty());
    assert!(matches!(report[1][0], Err(Error::TargetNotLoaded)));
}

#[test]
fn original_slot_requires_global_consistency_and_survives_rollback() {
    let image_selector = ElfImageSelector::new(DeviceId::new(1, 2), 3).unwrap();
    let original = OriginalPointerCell::new();
    let replacement = std::ptr::without_provenance(30);
    let hooks = [
        PltHookRequest::new(&image_selector, c"first", replacement)
            .unwrap()
            .with_original_pointer_cell(&original),
        PltHookRequest::new(&image_selector, c"second", replacement)
            .unwrap()
            .with_original_pointer_cell(&original),
    ];
    let plans = [Some(empty_plan(10)), Some(empty_plan(11))];
    assert_eq!(
        original_pointer_cell_conflicts(&hooks, &plans),
        [true, true]
    );

    let third_hook = PltHookRequest::new(&image_selector, c"third", replacement)
        .unwrap()
        .with_original_pointer_cell(&original);
    let three_hooks = [hooks[0], hooks[1], third_hook];
    let three_plans = [
        Some(empty_plan(10)),
        Some(empty_plan(10)),
        Some(empty_plan(11)),
    ];
    assert_eq!(
        original_pointer_cell_conflicts(&three_hooks, &three_plans),
        [true, true, true]
    );

    let consistent = [Some(empty_plan(10)), Some(empty_plan(10))];
    assert_eq!(
        original_pointer_cell_conflicts(&hooks, &consistent),
        [false, false]
    );
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
    let _guards = injection_test_guard();
    {
        // Resolve the real PLT slot before scanning it on lazy-binding
        // GNU/Linux. Android resolves it eagerly.
        // SAFETY: getpid has no arguments or caller-side preconditions.
        let before = unsafe { getpid() };
        let maps = read_self_maps().unwrap();
        let marker = (executable_marker as *const ()).expose_provenance();
        let executable = find_map_containing(&maps, marker, 1).unwrap();
        let source = ElfImageSelector::new(executable.device, executable.inode).unwrap();
        let broad =
            PltHookRequest::new(&source, c"getpid", passthrough_getpid as *const ()).unwrap();

        // SAFETY: the process test lock keeps the executable and resolved getpid
        // relocation stable for inspection and installation.
        let inspection = unsafe { inspect_hooks(&[broad]) }.unwrap();
        assert!(inspection[0].error.is_none(), "{inspection:?}");
        let expected_previous = inspection[0]
            .previous
            .expect("installable request has a previous pointer");
        let (image_selector, selector, kinds) = inspection[0]
            .images
            .iter()
            .find_map(|image| {
                image
                    .slots
                    .iter()
                    .find(|slot| slot.status == InspectionStatus::SelectionEligible)
                    .map(|slot| {
                        let kinds = match slot.kind {
                            RelocationKind::Absolute => RelocationKinds::ABSOLUTE,
                            RelocationKind::GlobalData => RelocationKinds::GLOBAL_DATA,
                            RelocationKind::JumpSlot => RelocationKinds::JUMP_SLOT,
                        };
                        (image.image.bound_selector(), slot.selector(), kinds)
                    })
            })
            .expect("getpid has an eligible relocation");
        let original = OriginalPointerCell::new();
        let strict =
            PltHookRequest::new(&image_selector, c"getpid", passthrough_getpid as *const ())
                .unwrap()
                .require_bound_image()
                .unwrap()
                .with_relocation_kinds(kinds)
                .with_slot_selector(selector)
                .unwrap()
                .require_single_image_and_slot()
                .with_original_pointer_cell(&original);
        let missing = ElfImageSelector::new(DeviceId::new(u32::MAX, u32::MAX), u64::MAX).unwrap();
        let hooks = [
            PltHookRequest::new(&missing, c"getpid", passthrough_getpid as *const ()).unwrap(),
            strict,
            PltHookRequest::new(
                &image_selector,
                c"omhook_symbol_that_does_not_exist",
                passthrough_getpid as *const (),
            )
            .unwrap(),
        ];

        // SAFETY: the exact inspected slot remains stable and the live
        // replacement has getpid's ABI.
        let report =
            unsafe { install_hooks_with_budget(&hooks, MutationBudget::new(1, 1, 1)) }.unwrap();
        assert!(matches!(report[0], Err(Error::TargetNotLoaded)));
        {
            let applied = report[1].as_ref().unwrap();
            assert_eq!(applied.slots().get(), 1);
            assert_eq!(applied.previous(), expected_previous);
            assert!(applied.is_installed());
            assert_eq!(applied.original(), Some(expected_previous));
        }
        assert_eq!(original.get(), Some(expected_previous));
        assert!(matches!(report[2], Err(Error::NoMatchingRelocation)));
        // SAFETY: the installed passthrough preserves getpid's ABI and
        // behavior for the rest of this test.
        assert_eq!(unsafe { getpid() }, before);
        let (mut installed, failed) = report.into_parts();
        assert_eq!(installed.len(), 1);
        assert_eq!(installed[0].0, 1);
        assert_eq!(failed.len(), 2);
        assert_eq!((failed[0].0, failed[1].0), (0, 2));
        let applied = &mut installed[0].1;
        // SAFETY: every getpid call above drained and the selected image and
        // slot remain stable.
        unsafe { applied.unhook() }.unwrap();
        assert!(!applied.is_installed());
        assert!(applied.original().is_none());
        // SAFETY: the original getpid slot and ABI were restored.
        assert_eq!(unsafe { getpid() }, before);
        // SAFETY: successful removal is idempotent.
        unsafe { applied.unhook() }.unwrap();
    }
}

#[test]
fn inspection_succeeds_when_mprotect_is_rejected() {
    let _guards = injection_test_guard();
    {
        // Resolve the executable's real PLT entry before scanning it.
        // SAFETY: getpid takes no arguments.
        let _ = unsafe { getpid() };
        let maps = read_self_maps().unwrap();
        let marker = (executable_marker as *const ()).expose_provenance();
        let executable = find_map_containing(&maps, marker, 1).unwrap();
        let image_selector = ElfImageSelector::new(executable.device, executable.inode).unwrap();
        let request =
            PltHookRequest::new(&image_selector, c"getpid", passthrough_getpid as *const ())
                .unwrap();
        crate::sys::tests::fail_next_protect();

        // SAFETY: the process test lock keeps its executable stable and performs only
        // read-only inspection of a live ABI-compatible replacement.
        let report = unsafe { inspect_hooks(&[request]) }.unwrap();
        crate::sys::tests::restore_next_protect();
        assert!(report[0].error.is_none(), "{report:?}");
        assert!(report[0].images.iter().any(|image| !image.slots.is_empty()));
    }
}

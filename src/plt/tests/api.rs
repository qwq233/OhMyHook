use super::*;

#[test]
fn safe_hook_construction_validates_only_descriptor_data() {
    let image_selector = ElfImageSelector::new(DeviceId::new(1, 2), 3).unwrap();
    let replacement = std::ptr::NonNull::<()>::dangling().as_ptr();

    assert!(matches!(
        PltHookRequest::new(&image_selector, c"", replacement),
        Err(Error::EmptySymbol)
    ));
    assert!(matches!(
        PltHookRequest::new(&image_selector, c"symbol", std::ptr::null()),
        Err(Error::NullReplacement)
    ));
    let request = PltHookRequest::new(&image_selector, c"symbol\xff", replacement)
        .unwrap()
        .with_resolved_ifunc(replacement);
    assert_eq!(
        request.resolved_ifunc,
        Some(replacement.expose_provenance())
    );
    assert!(matches!(
        SymbolQuery::exact_version(c"symbol", c""),
        Err(Error::EmptySymbolVersion)
    ));
    assert_eq!(
        SymbolQuery::unversioned(c"symbol").unwrap().name(),
        c"symbol"
    );
}

#[test]
fn debug_output_redacts_addresses() {
    let image_selector = ElfImageSelector::new(DeviceId::new(1, 2), 3).unwrap();
    let replacement = std::ptr::without_provenance(0x1111_1111);
    let resolved_ifunc = std::ptr::without_provenance(0x2222_2222);
    let original = OriginalPointerCell::from_expected(std::ptr::without_provenance(0x3333_3333));
    let request = PltHookRequest::new(&image_selector, c"symbol", replacement)
        .unwrap()
        .with_resolved_ifunc(resolved_ifunc)
        .with_original_pointer_cell(&original);

    let hook_debug = format!("{request:?}");
    assert!(!hook_debug.contains("286331153"));
    assert!(!hook_debug.contains("572662306"));
    assert!(!hook_debug.contains("858993459"));

    let slot_debug = format!("{original:?}");
    assert!(!slot_debug.contains("858993459"));
}

#[test]
fn strict_descriptors_reject_unbound_zero_and_wrong_selector() {
    let source = ElfImageSelector::new(DeviceId::new(1, 2), 3).unwrap();
    let replacement = std::ptr::NonNull::<()>::dangling().as_ptr();
    assert!(matches!(
        PltHookRequest::new(&source, c"symbol", replacement)
            .unwrap()
            .require_bound_image_and_single_slot(),
        Err(Error::BoundImageRequired)
    ));
    assert!(matches!(
        PltHookRequest::new(&source, c"symbol", replacement)
            .unwrap()
            .expect_slots(0),
        Err(Error::InvalidSlotCount)
    ));

    let expected = OriginalPointerCell::from_expected(std::ptr::without_provenance(17));
    assert_eq!(expected.get(), Some(std::ptr::without_provenance(17)));

    let image = LoadedImageSnapshot {
        source,
        header: 0x1000,
        loader_base: 0x1000,
        build_id: None,
    };
    let exact = image.bound_selector();
    let mut image_id = test_image(0x1000);
    image_id.loader_base = Some(0x1000);
    let selector = StoredValueSelector {
        image: image_id,
        archive_member_size: None,
        address: 0x2000,
        kind: RelocationKind::JumpSlot,
        stored_value: 17,
        addend: Some(0),
    };
    assert!(
        PltHookRequest::new(&exact, c"symbol", replacement)
            .unwrap()
            .require_bound_image()
            .unwrap()
            .with_slot_selector(selector)
            .is_ok()
    );
    let wrong_archive = StoredValueSelector {
        archive_member_size: Some(4096),
        ..selector
    };
    assert!(matches!(
        PltHookRequest::new(&exact, c"symbol", replacement)
            .unwrap()
            .with_slot_selector(wrong_archive),
        Err(Error::SlotSelectorMismatch)
    ));
}

#[test]
fn unique_eligible_inspection_is_extracted_once() {
    let source = ElfImageSelector::new(DeviceId::new(1, 2), 3).unwrap();
    let image = LoadedImageSnapshot {
        source,
        header: 0x1000,
        loader_base: 0x1000,
        build_id: None,
    };
    let mut image_id = test_image(0x1000);
    image_id.loader_base = Some(0x1000);
    let eligible = SlotSnapshot {
        address: std::ptr::without_provenance_mut(0x2000),
        kind: RelocationKind::JumpSlot,
        current: std::ptr::without_provenance(0x3000),
        addend: Some(0),
        permissions: MapPerms::READ,
        status: InspectionStatus::SelectionEligible,
        selector: StoredValueSelector {
            image: image_id,
            archive_member_size: None,
            address: 0x2000,
            kind: RelocationKind::JumpSlot,
            stored_value: 0x3000,
            addend: Some(0),
        },
    };
    let inspection = HookInspection {
        images: vec![ImageInspection {
            image: image.clone(),
            slots: vec![eligible],
        }],
        previous: Some(eligible.current),
        error: None,
    };
    assert_eq!(
        inspection.into_unique_eligible().unwrap(),
        (image, eligible)
    );

    let none = HookInspection {
        images: Vec::new(),
        previous: None,
        error: None,
    };
    assert!(matches!(
        none.into_unique_eligible(),
        Err(Error::UnexpectedSlotCount {
            expected: 1,
            actual: 0
        })
    ));

    let null = HookInspection {
        images: vec![ImageInspection {
            image: LoadedImageSnapshot {
                source: ElfImageSelector::new(DeviceId::new(1, 2), 3).unwrap(),
                header: 0x1000,
                loader_base: 0x1000,
                build_id: None,
            },
            slots: vec![SlotSnapshot {
                current: std::ptr::without_provenance(0x4000),
                ..eligible
            }],
        }],
        previous: Some(std::ptr::null()),
        error: None,
    };
    assert!(matches!(
        null.into_unique_eligible(),
        Err(Error::NullPreviousPointer)
    ));
}

#[test]
fn relocation_selection_filters_before_errors_and_slot_count() {
    let image_selector = ElfImageSelector::new(DeviceId::new(1, 2), 3).unwrap();
    let replacement = std::ptr::NonNull::<()>::dangling().as_ptr();
    let image = test_image(0x1000);
    let supported = [
        FoundRelocation::for_test(
            0x2000,
            image,
            RelocationKind::GlobalData,
            0,
            JumpSlotState::Resolved,
        ),
        FoundRelocation::for_test(
            0x3000,
            image,
            RelocationKind::JumpSlot,
            0,
            JumpSlotState::Resolved,
        ),
    ];
    let unsupported = [
        RejectedRelocation {
            address: 0x4000,
            image,
            kind: RelocationKind::Absolute,
            addend: None,
            reason: RelocationRejection::ImplicitAddend,
        },
        RejectedRelocation {
            address: 0x5000,
            image,
            kind: RelocationKind::JumpSlot,
            addend: Some(0),
            reason: RelocationRejection::PacPltVerificationFailed,
        },
    ];
    let request = PltHookRequest::new(&image_selector, c"symbol", replacement)
        .unwrap()
        .with_relocation_kinds(RelocationKinds::GLOBAL_DATA)
        .expect_slots(1)
        .unwrap();
    let mut relocations = supported.to_vec();
    let mut rejected = unsupported.to_vec();
    assert!(apply_hook_selection(&request, &mut relocations, &mut rejected).is_none());
    assert_eq!(relocations, supported[..1]);
    assert!(rejected.is_empty());

    let default_hook = PltHookRequest::new(&image_selector, c"symbol", replacement).unwrap();
    let mut relocations = supported.to_vec();
    let mut rejected = unsupported.to_vec();
    assert!(matches!(
        apply_hook_selection(&default_hook, &mut relocations, &mut rejected),
        Some(Error::Conflict)
    ));

    let mut relocations = supported.to_vec();
    let mut rejected = vec![unsupported[0]];
    assert!(matches!(
        apply_hook_selection(&default_hook, &mut relocations, &mut rejected),
        Some(Error::UnsupportedFeature(
            "implicit-addend absolute relocation"
        ))
    ));

    let count_hook = request.expect_slots(2).unwrap();
    let mut relocations = supported.to_vec();
    let mut rejected = unsupported.to_vec();
    assert!(matches!(
        apply_hook_selection(&count_hook, &mut relocations, &mut rejected),
        Some(Error::UnexpectedSlotCount {
            expected: 2,
            actual: 1
        })
    ));

    let jump_slot_hook = PltHookRequest::new(&image_selector, c"symbol", replacement)
        .unwrap()
        .with_relocation_kinds(RelocationKinds::JUMP_SLOT);
    let mut relocations = supported.to_vec();
    let mut rejected = vec![unsupported[1]];
    assert!(matches!(
        apply_hook_selection(&jump_slot_hook, &mut relocations, &mut rejected),
        Some(Error::Conflict)
    ));
}

#[test]
fn inspected_selector_revalidates_metadata_and_current_pointer() {
    static SLOT: AtomicUsize = AtomicUsize::new(21);
    SLOT.store(21, Ordering::SeqCst);
    let address = SLOT.as_ptr() as usize;
    let maps = read_self_maps().unwrap();
    let map = find_map_containing(&maps, address, std::mem::size_of::<usize>()).unwrap();
    let mut image = ImageMappingKey::for_test(map.device, map.inode, map.start);
    image.loader_base = Some(map.start);
    let mut image_selector = ElfImageSelector::new(map.device, map.inode).unwrap();
    image_selector.bound_image = Some(BoundImage {
        header: map.start,
        loader_base: map.start,
    });
    let selector = StoredValueSelector {
        image,
        archive_member_size: None,
        address,
        kind: RelocationKind::JumpSlot,
        stored_value: 20,
        addend: Some(0),
    };
    let request = PltHookRequest::new(&image_selector, c"symbol", std::ptr::without_provenance(40))
        .unwrap()
        .with_slot_selector(selector)
        .unwrap();
    let relocation = FoundRelocation::for_test(
        address,
        image,
        RelocationKind::JumpSlot,
        0,
        JumpSlotState::Resolved,
    );
    let scan = ScannedHook {
        relocations: vec![relocation],
        images: Arc::from([FoundImage {
            id: image,
            load_ranges: vec![(map.start, map.end)],
            build_id: None,
        }]),
    };
    assert!(matches!(
        build_hook_plan(&request, &scan),
        Err(Error::Conflict)
    ));

    let mut changed = vec![FoundRelocation::for_test(
        address,
        image,
        RelocationKind::JumpSlot,
        1,
        JumpSlotState::Resolved,
    )];
    assert!(matches!(
        apply_hook_selection(&request, &mut changed, &mut Vec::new()),
        Some(Error::SlotSelectorMismatch)
    ));
}

#[test]
fn loaded_image_exact_target_preserves_archive_bounds_and_raw_build_id() {
    let source = ElfImageSelector::from_archive_member(DeviceId::new(1, 2), 3, 4096, 8192).unwrap();
    let image = LoadedImageSnapshot {
        source,
        header: 0x10000,
        loader_base: 0x10000,
        build_id: Some(Arc::from([0_u8, 0xff, 7])),
    };
    let exact = image.bound_selector();
    assert_eq!(exact.archive_member_size(), Some(8192));
    assert_eq!(exact.elf_header_offset(), 4096);
    assert_eq!(
        exact.bound_image(),
        Some(BoundImage {
            header: 0x10000,
            loader_base: 0x10000,
        })
    );
    assert_eq!(image.build_id(), Some([0_u8, 0xff, 7].as_slice()));
}

#[test]
fn inspection_reports_rejected_relocations_in_address_order() {
    let _guard = process_test_guard();
    FIRST_SLOT.store(20, Ordering::SeqCst);
    SECOND_SLOT.store(21, Ordering::SeqCst);
    CURRENT_REPLACEMENT_SLOT.store(30, Ordering::SeqCst);
    let first = FIRST_SLOT.as_ptr() as usize;
    let second = SECOND_SLOT.as_ptr() as usize;
    let supported = CURRENT_REPLACEMENT_SLOT.as_ptr() as usize;
    let maps = read_self_maps().unwrap();
    let map = find_map_containing(&maps, first, std::mem::size_of::<usize>()).unwrap();
    assert!(find_map_containing(&maps, second, std::mem::size_of::<usize>()).is_some());
    assert!(find_map_containing(&maps, supported, std::mem::size_of::<usize>()).is_some());
    let image_selector = ElfImageSelector::new(map.device, map.inode).unwrap();
    let request = PltHookRequest::new(
        &image_selector,
        c"symbol",
        std::ptr::NonNull::<()>::dangling().as_ptr(),
    )
    .unwrap();
    let mut image_id = ImageMappingKey::for_test(map.device, map.inode, map.start);
    image_id.loader_base = Some(map.start);
    let images: Arc<[FoundImage]> = Arc::from([FoundImage {
        id: image_id,
        load_ranges: vec![(map.start, map.end)],
        build_id: None,
    }]);
    let prepared = PreparedBatch {
        outcomes: vec![Some(Err(Error::Conflict))],
        scanned: vec![Some(ScannedHook {
            relocations: vec![FoundRelocation::for_test(
                supported,
                image_id,
                RelocationKind::GlobalData,
                0,
                JumpSlotState::Resolved,
            )],
            images: Arc::clone(&images),
        })],
        images: vec![Some(images)],
        rejected: vec![vec![
            RejectedRelocation {
                address: second,
                image: image_id,
                kind: RelocationKind::JumpSlot,
                addend: Some(7),
                reason: RelocationRejection::PacPltVerificationFailed,
            },
            RejectedRelocation {
                address: first,
                image: image_id,
                kind: RelocationKind::Absolute,
                addend: None,
                reason: RelocationRejection::ImplicitAddend,
            },
        ]],
        conflicting_slots: vec![BTreeSet::new()],
        plans: vec![None],
        #[cfg(target_arch = "aarch64")]
        replacement_landings: None,
    };

    let report = build_inspection_report(&[request], &maps, prepared).unwrap();
    assert!(matches!(report[0].error.as_ref(), Some(Error::Conflict)));
    let slots = &report[0].images[0].slots;
    assert_eq!(slots.len(), 3);
    assert!(
        slots
            .windows(2)
            .all(|pair| pair[0].address.addr() < pair[1].address.addr())
    );
    let implicit = slots
        .iter()
        .find(|slot| slot.address.addr() == first)
        .unwrap();
    assert_eq!(implicit.current, std::ptr::without_provenance(20));
    assert_eq!(implicit.addend, None);
    assert_eq!(implicit.status, InspectionStatus::ImplicitAddend);
    let pac = slots
        .iter()
        .find(|slot| slot.address.addr() == second)
        .unwrap();
    assert_eq!(pac.current, std::ptr::without_provenance(21));
    assert_eq!(pac.addend, Some(7));
    assert_eq!(pac.status, InspectionStatus::PacPltVerificationFailed);
    let supported = slots
        .iter()
        .find(|slot| slot.address.addr() == supported)
        .unwrap();
    assert_eq!(supported.current, std::ptr::without_provenance(30));
    assert_eq!(supported.addend, Some(0));
    assert_eq!(supported.status, InspectionStatus::Rejected);
}

#[test]
fn lazy_inspection_uses_the_plan_original_and_keeps_raw_slot_selection() {
    let _guard = process_test_guard();
    LAZY_SLOT.store(20, Ordering::SeqCst);
    let address = LAZY_SLOT.as_ptr() as usize;
    let maps = read_self_maps().unwrap();
    let (image_selector, scan) = scan_for(&[(address, JumpSlotState::Lazy(20))]);
    let request =
        PltHookRequest::new(&image_selector, c"symbol", std::ptr::without_provenance(40)).unwrap();
    for (request, expected_status, expected_previous) in [
        (request, InspectionStatus::UnresolvedLazy, None),
        (
            request.with_resolved_original(std::ptr::without_provenance(30)),
            InspectionStatus::SelectionEligible,
            Some(std::ptr::without_provenance(30)),
        ),
        (
            request.with_resolved_original(std::ptr::without_provenance(20)),
            InspectionStatus::Rejected,
            None,
        ),
    ] {
        let (plan, outcome) = match build_hook_plan(&request, &scan) {
            Ok(plan) => (Some(plan), None),
            Err(error) => (None, Some(Err(error))),
        };
        let prepared = PreparedBatch {
            outcomes: vec![outcome],
            scanned: vec![Some(ScannedHook {
                relocations: scan.relocations.clone(),
                images: Arc::clone(&scan.images),
            })],
            images: vec![Some(Arc::clone(&scan.images))],
            rejected: vec![Vec::new()],
            conflicting_slots: vec![BTreeSet::new()],
            plans: vec![plan],
            #[cfg(target_arch = "aarch64")]
            replacement_landings: None,
        };
        let report = build_inspection_report(&[request], &maps, prepared).unwrap();
        assert_eq!(report[0].previous, expected_previous);
        let slot = &report[0].images[0].slots[0];
        assert_eq!(slot.status, expected_status);
        assert_eq!(slot.current, std::ptr::without_provenance(20));
        assert_eq!(slot.selector.stored_value, 20);
        assert_eq!(LAZY_SLOT.load(Ordering::SeqCst), 20);
    }
}

#[test]
fn empty_batch_and_absent_targets_preserve_input_order() {
    // SAFETY: an empty batch has no pointer or mapping requirements.
    assert!(unsafe { install_hooks(&[]) }.unwrap().is_empty());

    let image_selector =
        ElfImageSelector::new(DeviceId::new(u32::MAX, u32::MAX), u64::MAX).unwrap();
    let replacement = std::ptr::NonNull::<()>::dangling().as_ptr();
    // SAFETY: the selector intentionally matches no image, so the
    // replacement cannot be installed or called.
    assert!(matches!(
        unsafe {
            // SAFETY: the selector matches no image, so nothing is installed.
            install_hook(PltHookRequest::new(&image_selector, c"single", replacement).unwrap())
        },
        Err(Error::TargetNotLoaded)
    ));

    let hooks = [
        PltHookRequest::new(&image_selector, c"first", replacement).unwrap(),
        PltHookRequest::new(&image_selector, c"second", replacement).unwrap(),
    ];
    // SAFETY: the selector intentionally matches no image, so neither
    // replacement can be installed or called.
    let report = unsafe { install_hooks(&hooks) }.unwrap();
    assert!(matches!(report[0], Err(Error::TargetNotLoaded)));
    assert!(matches!(report[1], Err(Error::TargetNotLoaded)));
}

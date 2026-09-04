use super::*;

#[cfg(target_arch = "aarch64")]
#[test]
fn smaps_flags_restore_raw_bti_and_mte_and_detect_mapping_changes() {
    let page_size = crate::sys::page_size().unwrap();
    let start = page_size.checked_mul(16).unwrap();
    let map = MapInfo {
        start,
        end: start + page_size,
        perms: MapPerms::READ | MapPerms::EXEC,
        is_private: true,
        offset: 0,
        device: DeviceId::new(1, 2),
        inode: 3,
        path: None,
    };
    let mut pages = [WritablePage {
        start,
        map_index: 0,
        original_protection: map.perms.to_prot(),
    }];
    assert!(matches!(
        add_aarch64_protection_flags(std::slice::from_ref(&map), &[], page_size, &mut pages),
        Err(Error::InvalidSmaps("target page has no matching mapping"))
    ));
}

#[cfg(target_arch = "aarch64")]
#[test]
fn mutation_scope_reuses_saved_extension_protections() {
    let page_size = crate::sys::page_size().unwrap();
    let start = page_size.checked_mul(20).unwrap();
    let maps = [MapInfo {
        start,
        end: start + page_size,
        perms: MapPerms::READ,
        is_private: true,
        offset: 0,
        device: DeviceId::new(1, 2),
        inode: 3,
        path: None,
    }];
    let plans = [Some(HookPlan {
        previous: 1,
        slots: NonZeroUsize::new(1).unwrap(),
        writes: vec![PointerWrite {
            image: test_image(start),
            address: start,
            expected: 1,
            replacement: 2,
        }],
    })];
    let protections = BTreeMap::from([(start, libc::PROT_READ | PROT_BTI | PROT_MTE)]);

    let scope = mutation_scope(&maps, &plans, Some(&protections)).unwrap();
    assert_eq!(scope.writable.len(), 1);
    assert_eq!(
        scope.writable[0].original_protection,
        libc::PROT_READ | PROT_BTI | PROT_MTE
    );
}

#[cfg(target_arch = "aarch64")]
#[test]
fn aarch64_feature_probed_bti_and_mte_survive_write_windows() {
    const HWCAP2_BTI: libc::c_ulong = 1 << 17;
    const HWCAP2_MTE: libc::c_ulong = 1 << 18;

    // SAFETY: getauxval has no pointer arguments for AT_HWCAP2.
    let capabilities = unsafe { libc::getauxval(libc::AT_HWCAP2) };
    assert_eq!(
        crate::sys::aarch64_bti_supported(),
        capabilities & HWCAP2_BTI != 0
    );
    let page_size = crate::sys::page_size().unwrap();
    for (capability, extension) in [(HWCAP2_BTI, PROT_BTI), (HWCAP2_MTE, PROT_MTE)] {
        if capabilities & capability == 0 {
            continue;
        }
        // SAFETY: requests one private anonymous page and checks MAP_FAILED
        // before exposing its address to the protection helpers.
        let allocation = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(allocation, libc::MAP_FAILED);
        let start = allocation.expose_provenance();
        let base_protection = libc::PROT_READ | extension;
        // SAFETY: allocation is exactly one live page-aligned mapping.
        unsafe { crate::sys::protect(start, page_size, base_protection) }.unwrap();

        let maps = read_self_maps().unwrap();
        let (map_index, map) = find_page_map_index(&maps, start, page_size).unwrap();
        let smaps = read_self_smaps_for_ranges(&[(start, start + page_size)]).unwrap();
        let mut pages = [WritablePage {
            start,
            map_index,
            original_protection: map.perms.to_prot(),
        }];
        add_aarch64_protection_flags(&maps, &smaps, page_size, &mut pages).unwrap();
        assert_eq!(pages[0].original_protection, base_protection);
        let ranges = coalesce_writable_pages(&pages, page_size).unwrap();
        let range = ranges[0];
        if extension == PROT_BTI {
            // SAFETY: the exact private mapping remains stable and no other
            // thread accesses it during the temporary RW write window.
            unsafe {
                crate::sys::protect(
                    range.start,
                    range.length,
                    libc::PROT_READ | libc::PROT_WRITE,
                )
            }
            .unwrap();
            let writable = read_self_smaps_for_ranges(&[(start, start + page_size)]).unwrap();
            assert!(
                !writable
                    .iter()
                    .find(|entry| entry.map.contains_range(start, page_size))
                    .unwrap()
                    .vm_flags
                    .bti
            );
            // SAFETY: restores BTI explicitly after the write window cleared it.
            unsafe { crate::sys::protect(range.start, range.length, range.original_protection) }
                .unwrap();
        } else {
            // SAFETY: MTE is sticky for this mapping. Both transitions omit
            // PROT_MTE deliberately to match the no-BTI fast path.
            unsafe {
                crate::sys::protect(
                    range.start,
                    range.length,
                    libc::PROT_READ | libc::PROT_WRITE,
                )
            }
            .unwrap();
            // SAFETY: restores the original base access without spelling MTE.
            unsafe { crate::sys::protect(range.start, range.length, libc::PROT_READ) }.unwrap();
        }

        let restored = read_self_smaps_for_ranges(&[(start, start + page_size)]).unwrap();
        let flags = restored
            .iter()
            .find(|entry| entry.map.contains_range(start, page_size))
            .unwrap()
            .vm_flags;
        if extension == PROT_BTI {
            assert!(flags.bti);
        } else {
            assert!(flags.mte);
        }
        // SAFETY: releases the exact allocation after all borrowed mapping
        // snapshots and protection operations are complete.
        assert_eq!(unsafe { libc::munmap(allocation, page_size) }, 0);
    }
}

#[test]
fn pac_plt_plan_keeps_raw_previous_and_exact_signed_slot_words() {
    let _guard = STATEFUL_SLOT_TEST_LOCK.lock().unwrap();
    let first = FIRST_SLOT.as_ptr() as usize;
    let second = SECOND_SLOT.as_ptr() as usize;
    let plain = CURRENT_REPLACEMENT_SLOT.as_ptr() as usize;
    let raw_previous = 0x2000;
    let first_stored = crate::sys::sign_pac_plt(raw_previous, first);
    let second_stored = crate::sys::sign_pac_plt(raw_previous, second);
    FIRST_SLOT.store(first_stored, Ordering::SeqCst);
    SECOND_SLOT.store(second_stored, Ordering::SeqCst);
    CURRENT_REPLACEMENT_SLOT.store(raw_previous, Ordering::SeqCst);

    let (target, mut scan) = scan_for(&[
        (first, JumpSlotState::Resolved),
        (second, JumpSlotState::Resolved),
        (plain, JumpSlotState::Resolved),
    ]);
    scan.relocations[0].aarch64_pac_plt = true;
    scan.relocations[0].addend = 7;
    scan.relocations[1].aarch64_pac_plt = true;
    scan.relocations[1].addend = -7;
    scan.relocations[2].kind = RelocationKind::GlobalData;
    let maps = read_self_maps().unwrap();
    let map = find_map_containing(&maps, first, std::mem::size_of::<usize>()).unwrap();
    let mut image = scan.relocations[0].image;
    image.loader_base = Some(map.start);
    for relocation in &mut scan.relocations {
        relocation.image = image;
    }
    scan.images = Arc::from([FoundImage {
        id: image,
        load_ranges: vec![(map.start, map.end)],
        build_id: None,
    }]);

    let hook = Hook::new(&target, c"symbol", std::ptr::without_provenance(0x4000)).unwrap();
    let report_scan = ScannedHook {
        relocations: scan.relocations.clone(),
        images: Arc::clone(&scan.images),
    };
    let report_plan = build_hook_plan(&hook, &scan).unwrap();
    assert_eq!(report_plan.previous, raw_previous);
    let first_write = report_plan
        .writes
        .iter()
        .find(|write| write.address == first)
        .unwrap();
    assert_eq!(first_write.expected, first_stored);
    assert_eq!(
        first_write.replacement,
        crate::sys::sign_pac_plt(0x4007, first)
    );
    let second_write = report_plan
        .writes
        .iter()
        .find(|write| write.address == second)
        .unwrap();
    assert_eq!(second_write.expected, second_stored);
    assert_eq!(
        second_write.replacement,
        crate::sys::sign_pac_plt(0x3ff9, second)
    );
    let plain_write = report_plan
        .writes
        .iter()
        .find(|write| write.address == plain)
        .unwrap();
    assert_eq!(plain_write.expected, raw_previous);
    assert_eq!(plain_write.replacement, 0x4000);

    let prepared = PreparedBatch {
        outcomes: vec![None],
        scanned: vec![Some(report_scan)],
        images: vec![Some(Arc::clone(&scan.images))],
        rejected: vec![Vec::new()],
        conflicting_slots: vec![BTreeSet::new()],
        plans: vec![Some(report_plan)],
    };
    let report = build_inspection_report(&[hook], &maps, prepared).unwrap();
    assert_eq!(
        report[0].previous,
        Some(std::ptr::without_provenance(raw_previous))
    );
    for (address, stored) in [
        (first, first_stored),
        (second, second_stored),
        (plain, raw_previous),
    ] {
        let slot = report[0].images[0]
            .slots
            .iter()
            .find(|slot| slot.address.addr() == address)
            .unwrap();
        assert_eq!(slot.current, std::ptr::without_provenance(stored));
        assert_eq!(slot.selector.current, stored);
        assert_eq!(slot.status, InspectionStatus::Eligible);
    }

    let plan = build_hook_plan(&hook, &scan).unwrap();
    let plans = [Some(plan)];
    let scans = [Some(scan)];
    let mut ledgers =
        prepare_plt_ledgers(&[hook], &maps, &scans, &plans, &Arc::new(BTreeMap::new())).unwrap();
    let plan = plans[0].as_ref().unwrap();
    for write in &plan.writes {
        match write.address {
            address if address == first => FIRST_SLOT.store(write.replacement, Ordering::SeqCst),
            address if address == second => {
                SECOND_SLOT.store(write.replacement, Ordering::SeqCst);
            }
            address if address == plain => {
                CURRENT_REPLACEMENT_SLOT.store(write.replacement, Ordering::SeqCst);
            }
            _ => unreachable!(),
        }
    }
    let mut applied = AppliedHook {
        previous: crate::sys::encode_usize(plan.previous),
        slots: plan.slots,
        concealment: Concealment::InPlace("concealment not requested"),
        ledger: ledgers[0].take(),
    };
    {
        let _process_guard = crate::sys::PROCESS_LOCK.write().unwrap();
        record_installed_writes(applied.ledger.as_ref().unwrap().id, &plan.writes);
    }
    // SAFETY: the test owns all stable slots and no competing reader or
    // writer accesses them during removal.
    unsafe { applied.unhook() }.unwrap();
    assert_eq!(FIRST_SLOT.load(Ordering::SeqCst), first_stored);
    assert_eq!(SECOND_SLOT.load(Ordering::SeqCst), second_stored);
    assert_eq!(
        CURRENT_REPLACEMENT_SLOT.load(Ordering::SeqCst),
        raw_previous
    );
}

#[test]
fn pac_plt_plan_checks_verified_state_and_literal_selector_value() {
    const HWCAP_PACA: libc::c_ulong = 1 << 30;

    let _guard = STATEFUL_SLOT_TEST_LOCK.lock().unwrap();
    let address = FIRST_SLOT.as_ptr() as usize;
    let replacement = 0x4000;
    let (target, mut scan) = scan_for(&[(address, JumpSlotState::Resolved)]);
    scan.relocations[0].aarch64_pac_plt = true;
    let hook = Hook::new(
        &target,
        c"symbol",
        std::ptr::without_provenance(replacement),
    )
    .unwrap();

    FIRST_SLOT.store(0, Ordering::SeqCst);
    assert_eq!(build_hook_plan(&hook, &scan).unwrap().previous, 0);
    assert!(matches!(
        build_hook_plan(&hook.require_non_null_previous(), &scan),
        Err(Error::NullPreviousPointer)
    ));

    FIRST_SLOT.store(crate::sys::sign_pac_plt(0, address), Ordering::SeqCst);
    assert_eq!(build_hook_plan(&hook, &scan).unwrap().previous, 0);
    assert!(matches!(
        build_hook_plan(&hook.require_non_null_previous(), &scan),
        Err(Error::NullPreviousPointer)
    ));

    FIRST_SLOT.store(
        crate::sys::sign_pac_plt(replacement, address),
        Ordering::SeqCst,
    );
    assert!(matches!(
        build_hook_plan(&hook, &scan),
        Err(Error::Conflict)
    ));

    let resolver = 0x3000;
    FIRST_SLOT.store(
        crate::sys::sign_pac_plt(resolver, address),
        Ordering::SeqCst,
    );
    scan.relocations[0].jump_slot_state = JumpSlotState::Lazy(resolver);
    assert!(matches!(
        build_hook_plan(&hook, &scan),
        Err(Error::UnsupportedFeature("unresolved lazy PLT relocation"))
    ));
    scan.relocations[0].jump_slot_state = JumpSlotState::AmbiguousIfunc;
    assert!(matches!(
        build_hook_plan(&hook, &scan),
        Err(Error::UnsupportedFeature("ambiguous IFUNC jump-slot state"))
    ));
    assert!(
        build_hook_plan(
            &hook.with_resolved_ifunc(std::ptr::without_provenance(resolver)),
            &scan
        )
        .is_ok()
    );

    // SAFETY: getauxval has no pointer arguments for AT_HWCAP.
    if unsafe { libc::getauxval(libc::AT_HWCAP) } & HWCAP_PACA == 0 {
        return;
    }
    scan.relocations[0].jump_slot_state = JumpSlotState::Resolved;
    let raw = 0x2000;
    let valid = crate::sys::sign_pac_plt(raw, address);
    let wrong = (1..=1024)
        .map(|offset| {
            crate::sys::sign_pac_plt(raw, address + offset * std::mem::size_of::<usize>())
        })
        .find(|&stored| stored != valid)
        .expect("PAC did not vary across modifiers");
    FIRST_SLOT.store(valid, Ordering::SeqCst);
    let mut selected = hook;
    selected.slot_selector = Some(SlotSelector {
        image: scan.relocations[0].image,
        archive_member_size: None,
        address,
        kind: RelocationKind::JumpSlot,
        current: wrong,
        addend: Some(0),
    });
    assert!(matches!(
        build_hook_plan(&selected, &scan),
        Err(Error::Conflict)
    ));

    FIRST_SLOT.store(wrong, Ordering::SeqCst);
    assert!(matches!(
        build_hook_plan(&hook, &scan),
        Err(Error::Conflict)
    ));
}

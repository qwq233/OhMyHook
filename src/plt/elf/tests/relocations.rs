use super::*;

#[test]
fn defined_jump_slot_distinguishes_lazy_trampoline_from_self_resolution() {
    let class = native_class();
    let mut fixture = Fixture::new();
    let (strtab, strsz, symtab) = install_symbol(&mut fixture, class);
    let symbol = SYMTAB_OFFSET + class.sym_size();
    let definition_offset = 640_usize;
    let resolver_offset = 704_usize;
    let base = fixture.base();
    fixture.write_u16(symbol + class.sym_shndx_offset(), 1);
    match class {
        ElfClass::Elf32 => {
            fixture.write_u32(symbol + 4, definition_offset as u32);
            fixture.write_u32(SLOT_OFFSET, (base + resolver_offset) as u32);
        }
        ElfClass::Elf64 => {
            fixture.write_u64(symbol + 8, definition_offset as u64);
            fixture.write_u64(SLOT_OFFSET, (base + resolver_offset) as u64);
        }
    }
    let relocation_type = match arch::MACHINE {
        arch::EM_386 | arch::EM_X86_64 => 7_u32,
        arch::EM_ARM => 22,
        arch::EM_AARCH64 => 1026,
        _ => unreachable!(),
    };
    let info = match class {
        ElfClass::Elf32 => u64::from((1_u32 << 8) | relocation_type),
        ElfClass::Elf64 => (1_u64 << 32) | u64::from(relocation_type),
    };
    let image = image_for(&fixture, class, arch::MACHINE, false);
    let query = ResolvedSymbolQuery {
        output: 0,
        name: b"getpid",
        version: SymbolVersion::Any,
        strtab,
        strsz,
        symtab,
        symbol_count: Some(2),
        versions: None,
    };
    let address = base + SLOT_OFFSET;
    let resolver = base + resolver_offset;
    let definition = base + definition_offset;

    let mut scan = RelocationScan::default();
    {
        let maps = [map_for(&fixture.0)];
        image
            .consider_relocation(
                &memory(&maps),
                &query,
                SLOT_OFFSET as u64,
                info,
                None,
                &mut scan,
            )
            .unwrap();
    }
    assert_eq!(
        scan.matches[&address].jump_slot_state,
        if cfg!(target_os = "linux") {
            JumpSlotState::Lazy(resolver)
        } else {
            JumpSlotState::Resolved
        }
    );

    match class {
        ElfClass::Elf32 => fixture.write_u32(SLOT_OFFSET, definition as u32),
        ElfClass::Elf64 => fixture.write_u64(SLOT_OFFSET, definition as u64),
    }
    let maps = [map_for(&fixture.0)];
    let mut scan = RelocationScan::default();
    image
        .consider_relocation(
            &memory(&maps),
            &query,
            SLOT_OFFSET as u64,
            info,
            None,
            &mut scan,
        )
        .unwrap();
    assert_eq!(
        scan.matches[&address].jump_slot_state,
        JumpSlotState::Resolved
    );

    fixture.write(symbol + class.sym_info_offset(), &[STT_GNU_IFUNC]);
    match class {
        ElfClass::Elf32 => fixture.write_u32(SLOT_OFFSET, definition as u32),
        ElfClass::Elf64 => fixture.write_u64(SLOT_OFFSET, definition as u64),
    }
    let maps = [map_for(&fixture.0)];
    let mut scan = RelocationScan::default();
    image
        .consider_relocation(
            &memory(&maps),
            &query,
            SLOT_OFFSET as u64,
            info,
            None,
            &mut scan,
        )
        .unwrap();
    assert_eq!(
        scan.matches[&address].jump_slot_state,
        if cfg!(target_os = "linux") {
            JumpSlotState::AmbiguousIfunc
        } else {
            JumpSlotState::Resolved
        }
    );

    let absolute_resolver = base + fixture.0.len() + 0x1000;
    fixture.write_u16(symbol + class.sym_shndx_offset(), SHN_ABS);
    match class {
        ElfClass::Elf32 => {
            fixture.write_u32(symbol + 4, absolute_resolver as u32);
            fixture.write_u32(SLOT_OFFSET, absolute_resolver as u32);
        }
        ElfClass::Elf64 => {
            fixture.write_u64(symbol + 8, absolute_resolver as u64);
            fixture.write_u64(SLOT_OFFSET, absolute_resolver as u64);
        }
    }
    let maps = [map_for(&fixture.0)];
    let mut scan = RelocationScan::default();
    image
        .consider_relocation(
            &memory(&maps),
            &query,
            SLOT_OFFSET as u64,
            info,
            None,
            &mut scan,
        )
        .unwrap();
    assert_eq!(
        scan.matches[&address].jump_slot_state,
        if cfg!(target_os = "linux") {
            JumpSlotState::AmbiguousIfunc
        } else {
            JumpSlotState::Resolved
        }
    );
}

#[test]
fn decodes_grouped_and_per_entry_aps2_fields() {
    let mut fixture = Fixture::new();
    let (strtab, strsz, symtab) = install_symbol(&mut fixture, ElfClass::Elf64);
    let info = ((1_u64 << 32) | 1026) as i64;
    let mut packed = b"APS2".to_vec();
    for value in [
        3,
        (SLOT_OFFSET - 8) as i64,
        2,
        KNOWN_GROUP_FLAGS,
        8,
        info,
        -3,
        1,
        RELOCATION_GROUP_HAS_ADDEND,
        8,
        info,
        5,
    ] {
        push_sleb128(&mut packed, value);
    }
    fixture.write(TABLE_OFFSET, &packed);
    let maps = [map_for(&fixture.0)];
    let memory = memory(&maps);
    let image = image_for(&fixture, ElfClass::Elf64, arch::EM_AARCH64, false);
    let query = ResolvedSymbolQuery {
        output: 0,
        name: b"getpid",
        version: SymbolVersion::Any,
        strtab,
        strsz,
        symtab,
        symbol_count: Some(2),
        versions: None,
    };
    let mut scan = RelocationScan::default();
    image
        .scan_packed_table(
            &memory,
            std::slice::from_ref(&query),
            (fixture.base() + TABLE_OFFSET) as u64,
            packed.len() as u64,
            RelFormat::Rela,
            std::slice::from_mut(&mut scan),
        )
        .unwrap();
    assert_eq!(
        scan.matches.keys().copied().collect::<Vec<_>>(),
        [SLOT_OFFSET, SLOT_OFFSET + 8, SLOT_OFFSET + 16].map(|offset| fixture.base() + offset)
    );
    assert_eq!(
        scan.matches
            .values()
            .map(|relocation| relocation.addend)
            .collect::<Vec<_>>(),
        vec![-3, -3, 2]
    );
}

#[test]
fn rel_accepts_unused_grouped_addend_flag_but_rejects_real_addends() {
    let mut fixture = Fixture::new();
    let (strtab, strsz, symtab) = install_symbol(&mut fixture, ElfClass::Elf32);
    let info = ((1_u32 << 8) | 7) as i64;
    let mut packed = b"APS2".to_vec();
    for value in [
        1,
        (SLOT_OFFSET - 4) as i64,
        1,
        RELOCATION_GROUPED_BY_OFFSET_DELTA
            | RELOCATION_GROUPED_BY_INFO
            | RELOCATION_GROUPED_BY_ADDEND,
        4,
        info,
    ] {
        push_sleb128(&mut packed, value);
    }
    fixture.write(TABLE_OFFSET, &packed);
    let maps = [map_for(&fixture.0)];
    let memory = memory(&maps);
    let image = image_for(&fixture, ElfClass::Elf32, 3, false);
    let query = ResolvedSymbolQuery {
        output: 0,
        name: b"getpid",
        version: SymbolVersion::Any,
        strtab,
        strsz,
        symtab,
        symbol_count: Some(2),
        versions: None,
    };
    let mut scan = RelocationScan::default();
    image
        .scan_packed_table(
            &memory,
            std::slice::from_ref(&query),
            (fixture.base() + TABLE_OFFSET) as u64,
            packed.len() as u64,
            RelFormat::Rel,
            std::slice::from_mut(&mut scan),
        )
        .unwrap();
    assert_eq!(scan.matches.len(), 1);

    let mut invalid = b"APS2".to_vec();
    for value in [1, (SLOT_OFFSET - 4) as i64, 1, RELOCATION_GROUP_HAS_ADDEND] {
        push_sleb128(&mut invalid, value);
    }
    fixture.write(TABLE_OFFSET, &invalid);
    let error = image
        .scan_packed_table(
            &memory,
            std::slice::from_ref(&query),
            (fixture.base() + TABLE_OFFSET) as u64,
            invalid.len() as u64,
            RelFormat::Rel,
            std::slice::from_mut(&mut RelocationScan::default()),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        Error::InvalidElf("REL packed group contains addends")
    ));
}

#[test]
fn x86_64_data_slots_reject_non_zero_explicit_addends() {
    let mut fixture = Fixture::new();
    let (strtab, strsz, symtab) = install_symbol(&mut fixture, ElfClass::Elf64);
    let symbol = SYMTAB_OFFSET + ElfClass::Elf64.sym_size();
    let definition_offset = 640_usize;
    let base = fixture.base();
    fixture.write_u16(symbol + ElfClass::Elf64.sym_shndx_offset(), 1);
    fixture.write_u64(symbol + 8, definition_offset as u64);
    fixture.write_u64(SLOT_OFFSET, (base + definition_offset) as u64);
    let info = (1_u64 << 32) | 7;
    let image = image_for(&fixture, ElfClass::Elf64, arch::EM_X86_64, false);
    let query = ResolvedSymbolQuery {
        output: 0,
        name: b"getpid",
        version: SymbolVersion::Any,
        strtab,
        strsz,
        symtab,
        symbol_count: Some(2),
        versions: None,
    };
    let maps = [map_for(&fixture.0)];
    let memory = memory(&maps);
    let address = base + SLOT_OFFSET;

    let mut scan = RelocationScan::default();
    image
        .consider_relocation(
            &memory,
            &query,
            SLOT_OFFSET as u64,
            info,
            Some(8),
            &mut scan,
        )
        .unwrap();
    assert!(scan.matches.is_empty());
    assert_eq!(
        scan.rejected.values().copied().collect::<Vec<_>>(),
        [RejectedRelocation {
            address,
            image: image.id,
            kind: RelocationKind::JumpSlot,
            addend: Some(8),
            reason: RelocationRejection::UnsupportedAddend,
        }]
    );

    let mut zero_addend = RelocationScan::default();
    image
        .consider_relocation(
            &memory,
            &query,
            SLOT_OFFSET as u64,
            info,
            Some(0),
            &mut zero_addend,
        )
        .unwrap();
    assert_eq!(zero_addend.matches.len(), 1);
    assert!(zero_addend.rejected.is_empty());
}

#[test]
fn raw_fast_path_matches_generic_addends_and_relocation_metadata() {
    let mut fixture = Fixture::new();
    let (strtab, strsz, symtab) = install_symbol(&mut fixture, ElfClass::Elf64);
    let symbol = SYMTAB_OFFSET + ElfClass::Elf64.sym_size();
    let definition_offset = 640_usize;
    let base = fixture.base();
    fixture.write_u16(symbol + ElfClass::Elf64.sym_shndx_offset(), 1);
    fixture.write_u64(symbol + 8, definition_offset as u64);
    fixture.write_u64(SLOT_OFFSET, (base + definition_offset) as u64);
    fixture.write_u32(TABLE_OFFSET, 1);
    fixture.write_u32(TABLE_OFFSET + 4, 2);
    fixture.write_u32(TABLE_OFFSET + 8, 1);
    fixture.write_u32(TABLE_OFFSET + 16, 0);
    fixture.write_u64(768, SLOT_OFFSET as u64);
    fixture.write_u64(776, (1_u64 << 32) | 7);
    fixture.write_u64(784, 8);

    let mut image = image_for(&fixture, ElfClass::Elf64, arch::EM_X86_64, false);
    image.dynamic.hash = Some((base + TABLE_OFFSET) as u64);
    image.dynamic.strtab = Some(strtab);
    image.dynamic.strsz = Some(strsz);
    image.dynamic.symtab = Some(symtab);
    image.dynamic.syment = Some(ElfClass::Elf64.sym_size() as u64);
    image.dynamic.rela = Some((base + 768) as u64);
    image.dynamic.relasz = Some(24);
    image.dynamic.relaent = Some(24);
    image.dynamic.relacount = Some(0);
    let query = any_query(c"getpid");
    let maps = [map_for(&fixture.0)];
    let view = memory(&maps);

    assert!(
        image
            .find_exact_relocation_raw(&view, &query)
            .unwrap()
            .is_none()
    );
    fixture.write_u64(784, 0);
    assert!(
        image
            .find_exact_relocation_raw(&view, &query)
            .unwrap()
            .is_some()
    );
    for offset in [
        TABLE_OFFSET,
        TABLE_OFFSET + 8,
        TABLE_OFFSET + 16,
        symbol,
        symbol + 8,
        STRTAB_OFFSET + 1,
        768,
        SLOT_OFFSET,
    ] {
        let mut before = map_for(&fixture.0);
        before.end = base + offset;
        let mut after = map_for(&fixture.0);
        after.start = base + offset + 1;
        let split = [before, after];
        assert!(
            image
                .find_exact_relocation_raw(&memory(&split), &query)
                .is_err()
        );
    }
    image.dynamic.relasz = Some(4_000_000_000);
    assert!(
        image
            .find_exact_relocation_raw(&view, &query)
            .unwrap()
            .is_none()
    );
    image.dynamic.relasz = Some(24);
    let assert_invalid = |image: &Image, expected| {
        assert!(matches!(
            image.find_exact_relocation_raw(&view, &query),
            Err(Error::InvalidElf(message)) if message == expected
        ));
        assert!(matches!(
            image.find_exact_relocation(&view, &query),
            Err(Error::InvalidElf(message)) if message == expected
        ));
        assert!(matches!(
            image.scan_symbol_relocations(&view, &[query], &mut [RelocationScan::default()]),
            Err(Error::InvalidElf(message)) if message == expected
        ));
    };
    for present in 1..7 {
        image.dynamic.jmprel = (present & 1 != 0).then_some((base + 768) as u64);
        image.dynamic.pltrelsz = (present & 2 != 0).then_some(24);
        image.dynamic.pltrel = (present & 4 != 0).then_some(DT_RELA as u64);
        assert_invalid(&image, "incomplete or invalid PLT relocation tags");
    }
    image.dynamic.jmprel = Some((base + 768) as u64);
    image.dynamic.pltrelsz = Some(24);
    image.dynamic.pltrel = Some(DT_RELA as u64);
    for present in 1..3 {
        image.dynamic.rela = (present & 1 != 0).then_some((base + 768) as u64);
        image.dynamic.relasz = (present & 2 != 0).then_some(24);
        assert_invalid(&image, "incomplete relocation table tags");
    }
    image.dynamic.rela = Some((base + 768) as u64);
    image.dynamic.relasz = Some(24);
    image.dynamic.relacount = Some(2);
    assert_invalid(&image, "relative relocation count exceeds relocation table");
    image.dynamic.relacount = Some(0);
    image.dynamic.jmprel = None;
    image.dynamic.pltrelsz = None;
    image.dynamic.pltrel = None;
    image.dynamic.rel = Some((base + 768) as u64);
    assert_invalid(&image, "incomplete relocation table tags");
    image.dynamic.rel = None;
    image.dynamic.relsz = Some(16);
    assert_invalid(&image, "incomplete relocation table tags");
    image.dynamic.relsz = None;
    for present in 0..4 {
        image.dynamic.android_rel = (present == 0).then_some((base + 768) as u64);
        image.dynamic.android_relsz = (present == 1).then_some(24);
        image.dynamic.android_rela = (present == 2).then_some((base + 768) as u64);
        image.dynamic.android_relasz = (present == 3).then_some(24);
        assert_invalid(&image, "incomplete packed relocation tags");
    }
}

#[test]
fn dynamic_pointer_policy_rejects_ambiguity_and_limits_absolute_fallback_to_linux() {
    let fixture = Fixture::new();
    let maps = [map_for(&fixture.0)];
    let memory = memory(&maps);
    let base = fixture.base();
    let ranges = [(base, base + fixture.0.len())];
    let raw = (base + 128) as u64;

    assert!(matches!(
        resolve_dynamic_pointer_with_policy(&memory, 16, &ranges, raw, true),
        Err(Error::UnsupportedFeature(
            "ambiguous Linux dynamic pointer encoding"
        ))
    ));
    assert_eq!(
        resolve_dynamic_pointer_with_policy(&memory, 16, &ranges, raw, false).unwrap(),
        raw + 16
    );
    assert_eq!(
        resolve_dynamic_pointer_with_policy(&memory, 0, &ranges, raw, true).unwrap(),
        raw
    );

    assert_eq!(
        resolve_dynamic_pointer_with_policy(&memory, fixture.0.len(), &ranges, raw, true,).unwrap(),
        raw
    );
    assert!(matches!(
        resolve_dynamic_pointer_with_policy(&memory, fixture.0.len(), &ranges, raw, false,),
        Err(Error::UnmappedRead { .. })
    ));

    let relative = 128;
    assert_eq!(
        resolve_dynamic_pointer_with_policy(&memory, base, &ranges, relative, true).unwrap(),
        raw
    );
    assert_eq!(
        resolve_dynamic_pointer_with_policy(&memory, base, &ranges, relative, false).unwrap(),
        raw
    );

    let overflow_bias = usize::MAX - usize::try_from(raw).unwrap() + 1;
    assert_eq!(
        resolve_dynamic_pointer_with_policy(&memory, overflow_bias, &ranges, raw, true,).unwrap(),
        raw
    );
    assert!(matches!(
        resolve_dynamic_pointer_with_policy(&memory, overflow_bias, &ranges, raw, false,),
        Err(Error::ArithmeticOverflow)
    ));
}

#[test]
fn sysv_fast_paths_preserve_unhashed_same_name_imports() {
    for with_gnu_hash in [false, true] {
        let mut fixture = Fixture::new();
        let class = ElfClass::Elf64;
        let (strtab, strsz, symtab) = install_symbol(&mut fixture, class);
        let base = fixture.base();
        let defined = SYMTAB_OFFSET + 2 * class.sym_size();
        fixture.write_u32(defined, 1);
        fixture.write_u16(defined + class.sym_shndx_offset(), 1);
        fixture.write_u64(defined + 8, 640);
        fixture.write_u32(TABLE_OFFSET, 1);
        fixture.write_u32(TABLE_OFFSET + 4, 3);
        fixture.write_u32(TABLE_OFFSET + 8, 2);
        for (index, symbol) in [1_u64, 2].into_iter().enumerate() {
            let entry = 768 + index * 24;
            fixture.write_u64(entry, (SLOT_OFFSET + index * 8) as u64);
            fixture.write_u64(entry + 8, (symbol << 32) | 1025);
        }
        let mut image = image_for(&fixture, class, arch::EM_AARCH64, false);
        image.dynamic.hash = Some((base + TABLE_OFFSET) as u64);
        image.dynamic.strtab = Some(strtab);
        image.dynamic.strsz = Some(strsz);
        image.dynamic.symtab = Some(symtab);
        image.dynamic.syment = Some(class.sym_size() as u64);
        image.dynamic.rela = Some((base + 768) as u64);
        image.dynamic.relasz = Some(48);
        image.dynamic.relaent = Some(24);
        if with_gnu_hash {
            install_gnu_hash(&mut fixture, class, b"getpid", 2);
            image.dynamic.gnu_hash = Some((base + GNU_HASH_OFFSET) as u64);
        }
        let maps = [map_for(&fixture.0)];
        let view = memory(&maps);
        let query = any_query(c"getpid");
        assert!(
            image
                .find_exact_relocation_raw(&view, &query)
                .unwrap()
                .is_none()
        );
        assert!(
            image
                .find_exact_relocation(&view, &query)
                .unwrap()
                .is_none()
        );
        for query in [query, SymbolQuery::unversioned(c"getpid").unwrap()] {
            let mut scans = [RelocationScan::default()];
            image
                .scan_symbol_relocations(&view, &[query], &mut scans)
                .unwrap();
            assert_eq!(
                scans[0].matches.keys().copied().collect::<Vec<_>>(),
                [base + SLOT_OFFSET, base + SLOT_OFFSET + 8]
            );
        }
        image.dynamic.relasz = Some(24);
        let mut scans = [RelocationScan::default()];
        image
            .scan_symbol_relocations(&view, &[query], &mut scans)
            .unwrap();
        assert_eq!(
            scans[0].matches.keys().copied().collect::<Vec<_>>(),
            [base + SLOT_OFFSET]
        );

        fixture.write_u32(defined, 0);
        let maps = [map_for(&fixture.0)];
        let view = memory(&maps);
        assert_eq!(
            image
                .find_exact_relocation_raw(&view, &query)
                .unwrap()
                .unwrap()
                .address,
            base + SLOT_OFFSET
        );
        assert_eq!(
            image
                .find_exact_relocation(&view, &query)
                .unwrap()
                .unwrap()
                .address,
            base + SLOT_OFFSET
        );
        fixture.write_u32(defined, u32::try_from(strsz).unwrap());
        let maps = [map_for(&fixture.0)];
        let view = memory(&maps);
        assert!(matches!(
            image.find_exact_relocation_raw(&view, &query),
            Err(Error::InvalidElf("symbol name exceeds DT_STRSZ"))
        ));
        assert!(matches!(
            image.find_exact_relocation(&view, &query),
            Err(Error::InvalidElf("symbol name exceeds DT_STRSZ"))
        ));
    }
}

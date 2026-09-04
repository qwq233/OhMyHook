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
        symbol_count: 2,
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
        symbol_count: 2,
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
        symbol_count: 2,
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
        symbol_count: 2,
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

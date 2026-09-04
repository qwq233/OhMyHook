use super::*;

#[test]
fn scans_real_elf32_rel_and_elf64_rela_entries() {
    for (class, machine, format, info, entry_size, expected_addend) in [
        (ElfClass::Elf32, 3, RelFormat::Rel, (1_u64 << 8) | 7, 8, 0),
        (
            ElfClass::Elf32,
            40,
            RelFormat::Rela,
            (1_u64 << 8) | 22,
            12,
            -7_i64,
        ),
        (
            ElfClass::Elf64,
            arch::EM_AARCH64,
            RelFormat::Rela,
            (1_u64 << 32) | 1026,
            24,
            -7_i64,
        ),
    ] {
        let mut fixture = Fixture::new();
        let (strtab, strsz, symtab) = install_symbol(&mut fixture, class);
        match class {
            ElfClass::Elf32 => {
                fixture.write_u32(TABLE_OFFSET, SLOT_OFFSET as u32);
                fixture.write_u32(TABLE_OFFSET + 4, info as u32);
                if format == RelFormat::Rela {
                    fixture.write_u32(TABLE_OFFSET + 8, expected_addend as u32);
                }
            }
            ElfClass::Elf64 => {
                fixture.write_u64(TABLE_OFFSET, SLOT_OFFSET as u64);
                fixture.write_u64(TABLE_OFFSET + 8, info);
                fixture.write_u64(TABLE_OFFSET + 16, expected_addend as u64);
            }
        }
        let full_map = map_for(&fixture.0);
        let split = fixture.base() + TABLE_OFFSET + 3;
        let split_maps = [
            MapInfo {
                end: split,
                ..full_map.clone()
            },
            MapInfo {
                start: split,
                offset: (split - fixture.base()) as u64,
                ..full_map.clone()
            },
        ];
        let symbol_split = fixture.base() + SYMTAB_OFFSET + class.sym_size() + 2;
        let symbol_split_maps = [
            MapInfo {
                end: symbol_split,
                ..full_map.clone()
            },
            MapInfo {
                start: symbol_split,
                offset: (symbol_split - fixture.base()) as u64,
                ..full_map.clone()
            },
        ];
        let string_split = fixture.base() + STRTAB_OFFSET + 3;
        let string_split_maps = [
            MapInfo {
                end: string_split,
                ..full_map.clone()
            },
            MapInfo {
                start: string_split,
                offset: (string_split - fixture.base()) as u64,
                ..full_map.clone()
            },
        ];
        let contiguous_maps = [full_map];
        let image = image_for(&fixture, class, machine, false);
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
        for maps in [
            &contiguous_maps[..],
            &split_maps[..],
            &symbol_split_maps[..],
            &string_split_maps[..],
        ] {
            let mut scan = RelocationScan::default();
            image
                .scan_relocation_table(
                    &memory(maps),
                    std::slice::from_ref(&query),
                    RelocationTable::Plain {
                        address: (fixture.base() + TABLE_OFFSET) as u64,
                        size: entry_size,
                        entry_size,
                        format,
                        relative_prefix: 0,
                    },
                    std::slice::from_mut(&mut scan),
                )
                .unwrap();
            assert_eq!(scan.matches.len(), 1);
            assert_eq!(
                scan.matches[&(fixture.base() + SLOT_OFFSET)].kind,
                RelocationKind::JumpSlot
            );
            assert_eq!(
                scan.matches[&(fixture.base() + SLOT_OFFSET)].addend,
                expected_addend
            );
        }
    }
}

#[test]
fn empty_gnu_hash_bucket_falls_back_to_the_exact_import_scan() {
    let class = ElfClass::Elf64;
    let mut fixture = Fixture::new();
    fixture.write(STRTAB_OFFSET, b"\0getpid\0second\0");
    fixture.write_u32(SYMTAB_OFFSET + class.sym_size(), 1);
    fixture.write_u32(SYMTAB_OFFSET + 2 * class.sym_size(), 8);

    let second_hash = Hashes::for_name(b"second").gnu;
    fixture.write_u32(GNU_HASH_OFFSET, 2);
    fixture.write_u32(GNU_HASH_OFFSET + 4, 2);
    fixture.write_u32(GNU_HASH_OFFSET + 8, 1);
    fixture.write_u64(GNU_HASH_OFFSET + 16, u64::from(second_hash));
    let bucket = GNU_HASH_OFFSET + 16 + class.pointer_size();
    fixture.write_u32(bucket, 0); // getpid hashes to the first bucket.
    fixture.write_u32(bucket + 4, 2); // second lives in the second bucket.
    fixture.write_u32(bucket + 8, second_hash | 1);

    fixture.write_u64(TABLE_OFFSET, SLOT_OFFSET as u64);
    fixture.write_u64(TABLE_OFFSET + 8, (1_u64 << 32) | 1026);
    fixture.write_u64(TABLE_OFFSET + 16, 0);

    let mut image = image_for(&fixture, class, arch::EM_AARCH64, false);
    image.dynamic.strtab = Some((fixture.base() + STRTAB_OFFSET) as u64);
    image.dynamic.strsz = Some(15);
    image.dynamic.symtab = Some((fixture.base() + SYMTAB_OFFSET) as u64);
    image.dynamic.syment = Some(class.sym_size() as u64);
    image.dynamic.symtabsz = Some((3 * class.sym_size()) as u64);
    image.dynamic.gnu_hash = Some((fixture.base() + GNU_HASH_OFFSET) as u64);
    image.dynamic.rela = Some((fixture.base() + TABLE_OFFSET) as u64);
    image.dynamic.relasz = Some(class.rel_size(RelFormat::Rela) as u64);
    image.dynamic.relaent = Some(class.rel_size(RelFormat::Rela) as u64);

    let maps = [map_for(&fixture.0)];
    let mut scans = [RelocationScan::default()];
    image
        .scan_symbol_relocations(&memory(&maps), &[any_query(c"getpid")], &mut scans)
        .unwrap();

    assert_eq!(
        scans[0].matches.keys().copied().collect::<Vec<_>>(),
        [fixture.base() + SLOT_OFFSET]
    );
}

#[test]
fn rejects_readable_symbol_table_outside_image_load_ranges() {
    let class = ElfClass::Elf64;
    let mut fixture = Fixture::new();
    let (strtab, strsz, symtab) = install_symbol(&mut fixture, class);
    fixture.write_u64(TABLE_OFFSET, SLOT_OFFSET as u64);
    fixture.write_u64(TABLE_OFFSET + 8, (1_u64 << 32) | 7);
    fixture.write_u64(TABLE_OFFSET + 16, 0);

    let mut image = image_for(&fixture, class, 3, false);
    image.load_ranges = vec![(
        fixture.base() + TABLE_OFFSET,
        fixture.base() + SLOT_OFFSET + 8,
    )];
    let maps = [map_for(&fixture.0)];
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

    assert!(matches!(
        image.scan_relocation_table(
            &memory(&maps),
            std::slice::from_ref(&query),
            RelocationTable::Plain {
                address: (fixture.base() + TABLE_OFFSET) as u64,
                size: class.rel_size(RelFormat::Rela) as u64,
                entry_size: class.rel_size(RelFormat::Rela) as u64,
                format: RelFormat::Rela,
                relative_prefix: 0,
            },
            std::slice::from_mut(&mut scan),
        ),
        Err(Error::InvalidElf("symbol entry exceeds PT_LOAD"))
    ));
}

#[test]
fn one_table_routes_ordered_symbol_buckets_with_pac_slots() {
    let mut fixture = Fixture::new();
    fixture.write(STRTAB_OFFSET, b"\0first\0second\0");
    fixture.write_u32(SYMTAB_OFFSET + ElfClass::Elf64.sym_size(), 1);
    fixture.write_u32(SYMTAB_OFFSET + 2 * ElfClass::Elf64.sym_size(), 7);
    for (index, (offset, info)) in [
        (SLOT_OFFSET, (1_u64 << 32) | 1026),
        (SLOT_OFFSET + 8, (2_u64 << 32) | 1025),
    ]
    .into_iter()
    .enumerate()
    {
        let entry = TABLE_OFFSET + index * ElfClass::Elf64.rel_size(RelFormat::Rela);
        fixture.write_u64(entry, offset as u64);
        fixture.write_u64(entry + 8, info);
        fixture.write_u64(entry + 16, 0);
    }
    let maps = [map_for(&fixture.0)];
    let image = image_for(&fixture, ElfClass::Elf64, arch::EM_AARCH64, true);
    let strtab = (fixture.base() + STRTAB_OFFSET) as u64;
    let symtab = (fixture.base() + SYMTAB_OFFSET) as u64;
    let mut queries =
        [(b"second".as_slice(), 0), (b"missing", 1), (b"first", 2)].map(|(name, output)| {
            ResolvedSymbolQuery {
                output,
                name,
                version: SymbolVersion::Any,
                strtab,
                strsz: 14,
                symtab,
                symbol_count: Some(3),
                versions: None,
            }
        });
    queries.sort_unstable_by(|left, right| left.name.cmp(right.name));
    let mut scans: [RelocationScan; 3] = std::array::from_fn(|_| Default::default());

    image
        .scan_relocation_table(
            &memory(&maps),
            &queries,
            RelocationTable::Plain {
                address: (fixture.base() + TABLE_OFFSET) as u64,
                size: 2 * ElfClass::Elf64.rel_size(RelFormat::Rela) as u64,
                entry_size: ElfClass::Elf64.rel_size(RelFormat::Rela) as u64,
                format: RelFormat::Rela,
                relative_prefix: 0,
            },
            &mut scans,
        )
        .unwrap();

    assert_eq!(
        scans[0].matches.keys().copied().collect::<Vec<_>>(),
        [fixture.base() + SLOT_OFFSET + 8]
    );
    assert!(scans[1].matches.is_empty());
    assert_eq!(
        scans[2].matches.keys().copied().collect::<Vec<_>>(),
        [fixture.base() + SLOT_OFFSET]
    );
    assert!(scans[2].matches[&(fixture.base() + SLOT_OFFSET)].aarch64_pac_plt);
}

#[test]
fn preserves_unsorted_duplicate_version_query_results() {
    const LOCAL_SYMTAB_OFFSET: usize = 320;

    let class = native_class();
    let mut fixture = Fixture::new();
    let mut image = image_for(&fixture, class, arch::MACHINE, false);
    let (strtab, strsz, _) = install_version_tables(&mut fixture, &mut image);
    let symtab = (fixture.base() + LOCAL_SYMTAB_OFFSET) as u64;
    for index in 1..=2 {
        let symbol = LOCAL_SYMTAB_OFFSET + index * class.sym_size();
        fixture.write_u32(symbol, 1);
        fixture.write_u16(symbol + class.sym_shndx_offset(), 1);
    }
    fixture.write_u16(VERSYM_OFFSET + 2, 2);
    fixture.write_u16(VERSYM_OFFSET + 4, VER_NDX_GLOBAL);

    let relocation_type = match arch::MACHINE {
        arch::EM_ARM => 22,
        arch::EM_AARCH64 => 1026,
        _ => 7,
    };
    let format = match class {
        ElfClass::Elf32 => RelFormat::Rel,
        ElfClass::Elf64 => RelFormat::Rela,
    };
    let entry_size = class.rel_size(format);
    for (index, symbol) in [1_u64, 2].into_iter().enumerate() {
        let entry = TABLE_OFFSET + index * entry_size;
        match class {
            ElfClass::Elf32 => {
                fixture.write_u32(entry, (SLOT_OFFSET + index * 4) as u32);
                fixture.write_u32(entry + 4, ((symbol << 8) | relocation_type) as u32);
            }
            ElfClass::Elf64 => {
                fixture.write_u64(entry, (SLOT_OFFSET + index * 8) as u64);
                fixture.write_u64(entry + 8, (symbol << 32) | relocation_type);
                fixture.write_u64(entry + 16, 0);
            }
        }
    }
    image.dynamic.strtab = Some(strtab);
    image.dynamic.strsz = Some(strsz);
    image.dynamic.symtab = Some(symtab);
    image.dynamic.syment = Some(class.sym_size() as u64);
    image.dynamic.symtabsz = Some((3 * class.sym_size()) as u64);
    match format {
        RelFormat::Rel => {
            image.dynamic.rel = Some((fixture.base() + TABLE_OFFSET) as u64);
            image.dynamic.relsz = Some((2 * entry_size) as u64);
            image.dynamic.relent = Some(entry_size as u64);
        }
        RelFormat::Rela => {
            image.dynamic.rela = Some((fixture.base() + TABLE_OFFSET) as u64);
            image.dynamic.relasz = Some((2 * entry_size) as u64);
            image.dynamic.relaent = Some(entry_size as u64);
        }
    }

    let requested = [
        SymbolQuery::exact_version(c"foo", c"VER_DEF").unwrap(),
        any_query(c"missing"),
        any_query(c"foo"),
        SymbolQuery::unversioned(c"foo").unwrap(),
        SymbolQuery::exact_version(c"foo", c"VER_DEF").unwrap(),
    ];
    let maps = [map_for(&fixture.0)];
    let mut scans = (0..requested.len())
        .map(|_| RelocationScan::default())
        .collect::<Vec<_>>();
    image
        .scan_symbol_relocations(&memory(&maps), &requested, &mut scans)
        .unwrap();
    let first = fixture.base() + SLOT_OFFSET;
    let second = first + class.pointer_size();

    assert_eq!(
        scans[0].matches.keys().copied().collect::<Vec<_>>(),
        [first]
    );
    assert!(scans[1].matches.is_empty());
    assert_eq!(
        scans[2].matches.keys().copied().collect::<Vec<_>>(),
        [first, second]
    );
    assert_eq!(
        scans[3].matches.keys().copied().collect::<Vec<_>>(),
        [second]
    );
    assert_eq!(
        scans[4].matches.keys().copied().collect::<Vec<_>>(),
        [first]
    );
}

#[test]
fn symbol_lookup_accepts_non_utf8_names() {
    let class = ElfClass::Elf64;
    let mut fixture = Fixture::new();
    let string_table = b"\0\xffhook\0";
    fixture.write(STRTAB_OFFSET, string_table);
    fixture.write_u32(SYMTAB_OFFSET + class.sym_size(), 1);
    let maps = [map_for(&fixture.0)];
    let memory = memory(&maps);
    let image = image_for(&fixture, class, arch::EM_AARCH64, false);
    let symbol = c"\xffhook";
    let query = ResolvedSymbolQuery {
        output: 0,
        name: symbol.to_bytes(),
        version: SymbolVersion::Any,
        strtab: (fixture.base() + STRTAB_OFFSET) as u64,
        strsz: string_table.len() as u64,
        symtab: (fixture.base() + SYMTAB_OFFSET) as u64,
        symbol_count: Some(2),
        versions: None,
    };

    assert!(matches!(
        image.symbol_match(&memory, &query, 1).unwrap(),
        SymbolMatch::Match {
            undefined: true,
            definition: None,
            ifunc: false,
            ..
        }
    ));
}

#[test]
fn symbol_lookup_reports_defined_and_undefined_matches() {
    for class in [ElfClass::Elf32, ElfClass::Elf64] {
        let mut fixture = Fixture::new();
        let (strtab, strsz, symtab) = install_symbol(&mut fixture, class);
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
        let image = image_for(&fixture, class, arch::MACHINE, false);
        assert_eq!(
            image.symbol_match(&memory(&maps), &query, 1).unwrap(),
            SymbolMatch::Match {
                undefined: true,
                definition: None,
                ifunc: false,
                function: false,
            }
        );

        fixture.write_u16(
            SYMTAB_OFFSET + class.sym_size() + class.sym_shndx_offset(),
            1,
        );
        let maps = [map_for(&fixture.0)];
        assert_eq!(
            image.symbol_match(&memory(&maps), &query, 1).unwrap(),
            SymbolMatch::Match {
                undefined: false,
                definition: Some(fixture.base()),
                ifunc: false,
                function: false,
            }
        );

        fixture.write(
            SYMTAB_OFFSET + class.sym_size() + class.sym_info_offset(),
            &[STT_GNU_IFUNC],
        );
        let maps = [map_for(&fixture.0)];
        assert_eq!(
            image.symbol_match(&memory(&maps), &query, 1).unwrap(),
            SymbolMatch::Match {
                undefined: false,
                definition: Some(fixture.base()),
                ifunc: true,
                function: true,
            }
        );
        for (symbol_type, function) in [(0, false), (1, false), (2, true)] {
            fixture.write(
                SYMTAB_OFFSET + class.sym_size() + class.sym_info_offset(),
                &[symbol_type],
            );
            let maps = [map_for(&fixture.0)];
            assert_eq!(
                image.symbol_match(&memory(&maps), &query, 1).unwrap(),
                SymbolMatch::Match {
                    undefined: false,
                    definition: Some(fixture.base()),
                    ifunc: false,
                    function,
                }
            );
        }
    }
}

#[test]
fn matches_defined_and_required_gnu_symbol_versions() {
    for class in [ElfClass::Elf32, ElfClass::Elf64] {
        let mut fixture = Fixture::new();
        let mut image = image_for(&fixture, class, arch::MACHINE, false);
        let (strtab, strsz, symtab) = install_version_tables(&mut fixture, &mut image);
        let symbol = SYMTAB_OFFSET + class.sym_size();
        fixture.write_u32(symbol, 1);
        fixture.write_u16(symbol + class.sym_shndx_offset(), 1);
        fixture.write_u16(VERSYM_OFFSET + 2, 0x8002);
        let maps = [map_for(&fixture.0)];
        let view = memory(&maps);
        let versions = image
            .parse_version_metadata(&view, strtab, strsz, true)
            .unwrap();
        let defined = ResolvedSymbolQuery {
            output: 0,
            name: b"foo",
            version: SymbolVersion::Exact(c"VER_DEF"),
            strtab,
            strsz,
            symtab,
            symbol_count: Some(2),
            versions: Some(&versions),
        };
        assert!(matches!(
            image.symbol_match(&view, &defined, 1).unwrap(),
            SymbolMatch::Match {
                undefined: false,
                ..
            }
        ));
        let wrong = ResolvedSymbolQuery {
            version: SymbolVersion::Exact(c"VER_NEED"),
            ..defined
        };
        assert_eq!(
            image.symbol_match(&view, &wrong, 1).unwrap(),
            SymbolMatch::Mismatch
        );

        fixture.write_u16(symbol + class.sym_shndx_offset(), SHN_UNDEF);
        fixture.write_u16(VERSYM_OFFSET + 2, 3);
        let maps = [map_for(&fixture.0)];
        let view = memory(&maps);
        let required = ResolvedSymbolQuery {
            output: 0,
            name: b"foo",
            version: SymbolVersion::Exact(c"VER_NEED"),
            strtab,
            strsz,
            symtab,
            symbol_count: Some(2),
            versions: Some(&versions),
        };
        assert!(matches!(
            image.symbol_match(&view, &required, 1).unwrap(),
            SymbolMatch::Match {
                undefined: true,
                ..
            }
        ));
    }
}

#[test]
fn unversioned_and_any_queries_preserve_compatibility() {
    let class = native_class();
    let mut fixture = Fixture::new();
    let (strtab, strsz, symtab) = install_symbol(&mut fixture, class);
    let mut image = image_for(&fixture, class, arch::MACHINE, false);
    image.dynamic.strtab = Some(strtab);
    image.dynamic.strsz = Some(strsz);
    image.dynamic.symtab = Some(symtab);
    image.dynamic.syment = Some(class.sym_size() as u64);
    image.dynamic.symtabsz = Some((2 * class.sym_size()) as u64);
    image.dynamic.versym = Some(u64::MAX);
    image.dynamic.verdef = Some(u64::MAX);
    image.dynamic.duplicate_version_tag = true;
    let maps = [map_for(&fixture.0)];
    let memory = memory(&maps);
    let mut scans = [RelocationScan::default()];

    assert!(
        image
            .scan_symbol_relocations(&memory, &[any_query(c"getpid")], &mut scans)
            .is_ok()
    );

    let no_versions = VersionMetadata::default();
    let unversioned = ResolvedSymbolQuery {
        output: 0,
        name: b"getpid",
        version: SymbolVersion::Unversioned,
        strtab,
        strsz,
        symtab,
        symbol_count: Some(2),
        versions: Some(&no_versions),
    };
    assert!(matches!(
        image.symbol_match(&memory, &unversioned, 1).unwrap(),
        SymbolMatch::Match { .. }
    ));
    let exact = ResolvedSymbolQuery {
        version: SymbolVersion::Exact(c"VER"),
        ..unversioned
    };
    assert_eq!(
        image.symbol_match(&memory, &exact, 1).unwrap(),
        SymbolMatch::Mismatch
    );
}

#[test]
fn rejects_incomplete_and_out_of_bounds_gnu_version_metadata() {
    let class = native_class();
    let mut fixture = Fixture::new();
    let mut image = image_for(&fixture, class, arch::MACHINE, false);
    let (strtab, strsz, symtab) = install_version_tables(&mut fixture, &mut image);
    fixture.write_u32(SYMTAB_OFFSET + class.sym_size(), 1);
    let maps = [map_for(&fixture.0)];
    let memory = memory(&maps);

    image.dynamic.verdefnum = None;
    assert!(matches!(
        image.parse_version_metadata(&memory, strtab, strsz, true),
        Err(Error::InvalidElf("incomplete VERDEF dynamic tags"))
    ));
    image.dynamic.verdefnum = Some(0);
    assert!(matches!(
        image.parse_version_metadata(&memory, strtab, strsz, true),
        Err(Error::InvalidElf("invalid GNU version record count"))
    ));

    let versions = VersionMetadata {
        versym: Some(fixture.base() + fixture.0.len() - 1),
        ..VersionMetadata::default()
    };
    let query = ResolvedSymbolQuery {
        output: 0,
        name: b"foo",
        version: SymbolVersion::Unversioned,
        strtab,
        strsz,
        symtab,
        symbol_count: Some(2),
        versions: Some(&versions),
    };
    assert!(matches!(
        image.symbol_match(&memory, &query, 1),
        Err(Error::InvalidElf("VERSYM entry exceeds PT_LOAD"))
    ));
}

#[test]
fn rejects_overlapping_gnu_version_auxiliary_chains() {
    for (offset, count_offset, expected) in [
        (
            VERDEF_OFFSET + 12,
            None,
            "overlapping VERDEF auxiliary chain",
        ),
        (
            VERDEF_OFFSET + 24,
            Some(VERDEF_OFFSET + 6),
            "overlapping VERDEF auxiliary chain",
        ),
        (
            VERNEED_OFFSET + 8,
            None,
            "overlapping VERNEED auxiliary chain",
        ),
        (
            VERNEED_OFFSET + 28,
            Some(VERNEED_OFFSET + 2),
            "overlapping VERNEED auxiliary chain",
        ),
    ] {
        let class = native_class();
        let mut fixture = Fixture::new();
        let mut image = image_for(&fixture, class, arch::MACHINE, false);
        let (strtab, strsz, _) = install_version_tables(&mut fixture, &mut image);
        if let Some(count_offset) = count_offset {
            fixture.write_u16(count_offset, 2);
        }
        fixture.write_u32(offset, 4);
        let maps = [map_for(&fixture.0)];
        match image.parse_version_metadata(&memory(&maps), strtab, strsz, true) {
            Err(Error::InvalidElf(message)) => assert_eq!(message, expected),
            Err(error) => panic!("unexpected error: {error}"),
            Ok(_) => panic!("overlapping GNU version chain was accepted"),
        }
    }
}

#[test]
fn version_string_validation_reuses_overlapping_suffixes() {
    let bytes = b"overlapping-version\0";
    let maps = [map_for(bytes)];
    let memory = memory(&maps);
    let mut validated = BTreeMap::new();

    for offset in (0..bytes.len() - 1).rev() {
        validate_dynamic_string(
            &memory,
            bytes.as_ptr() as u64,
            bytes.len() as u64,
            offset as u32,
            &mut validated,
        )
        .unwrap();
    }

    assert_eq!(validated, BTreeMap::from([(0, (bytes.len() - 1) as u64)]));
}

#[test]
fn symbol_extent_does_not_infer_padding_or_drop_empty_hash_imports() {
    for class in [ElfClass::Elf32, ElfClass::Elf64] {
        for strtab_offset in [
            STRTAB_OFFSET,
            SYMTAB_OFFSET + 12 * class.sym_size(),
            SYMTAB_OFFSET + 12 * class.sym_size() + 1,
        ] {
            for (sysv, gnu) in [(false, true), (true, false), (false, false)] {
                let mut fixture = Fixture::new();
                fixture.write(strtab_offset, b"\0getpid\0");
                fixture.write_u32(SYMTAB_OFFSET + class.sym_size(), 1);
                // This is padding after the two real symbols, not a third entry.
                fixture.write_u32(SYMTAB_OFFSET + 2 * class.sym_size(), u32::MAX);
                let machine = match class {
                    ElfClass::Elf32 => {
                        fixture.write_u32(TABLE_OFFSET, SLOT_OFFSET as u32);
                        fixture.write_u32(TABLE_OFFSET + 4, (1 << 8) | 7);
                        arch::EM_386
                    }
                    ElfClass::Elf64 => {
                        fixture.write_u64(TABLE_OFFSET, SLOT_OFFSET as u64);
                        fixture.write_u64(TABLE_OFFSET + 8, (1_u64 << 32) | 7);
                        arch::EM_X86_64
                    }
                };
                let mut image = image_for(&fixture, class, machine, false);
                image.dynamic.strtab = Some((fixture.base() + strtab_offset) as u64);
                image.dynamic.strsz = Some(8);
                image.dynamic.symtab = Some((fixture.base() + SYMTAB_OFFSET) as u64);
                image.dynamic.syment = Some(class.sym_size() as u64);
                image.dynamic.rela = Some((fixture.base() + TABLE_OFFSET) as u64);
                image.dynamic.relasz = Some(class.rel_size(RelFormat::Rela) as u64);
                image.dynamic.relaent = Some(class.rel_size(RelFormat::Rela) as u64);
                if sysv {
                    fixture.write_u32(NOTE_OFFSET, 1);
                    fixture.write_u32(NOTE_OFFSET + 4, 2);
                    image.dynamic.hash = Some((fixture.base() + NOTE_OFFSET) as u64);
                }
                if gnu {
                    fixture.write_u32(GNU_HASH_OFFSET, 1);
                    fixture.write_u32(GNU_HASH_OFFSET + 4, 1);
                    fixture.write_u32(GNU_HASH_OFFSET + 8, 1);
                    image.dynamic.gnu_hash = Some((fixture.base() + GNU_HASH_OFFSET) as u64);
                }
                let maps = [map_for(&fixture.0)];
                let mut scans = [RelocationScan::default()];
                image
                    .scan_symbol_relocations(&memory(&maps), &[any_query(c"getpid")], &mut scans)
                    .unwrap();
                assert_eq!(
                    scans[0].matches.keys().copied().collect::<Vec<_>>(),
                    [fixture.base() + SLOT_OFFSET],
                    "class={} strtab={strtab_offset} sysv={sysv} gnu={gnu}",
                    class.value()
                );
            }
        }
    }
}

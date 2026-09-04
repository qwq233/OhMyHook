use super::*;

#[test]
fn c_string_matching_crosses_adjacent_readable_maps() {
    let bytes = *b"prefix\0";
    let base = bytes.as_ptr() as usize;
    let maps = [
        MapInfo {
            end: base + 3,
            ..map_for(&bytes)
        },
        MapInfo {
            start: base + 3,
            ..map_for(&bytes)
        },
    ];
    let split_memory = memory(&maps);

    assert!(
        split_memory
            .matches_c_string(base, bytes.len(), b"prefix")
            .unwrap()
    );
    assert!(
        !split_memory
            .matches_c_string(base, bytes.len(), b"prefox")
            .unwrap()
    );
    assert_eq!(
        split_memory
            .compare_c_string(base, bytes.len(), b"prefix")
            .unwrap(),
        Ordering::Equal
    );
    assert_eq!(
        split_memory
            .compare_c_string(base, bytes.len(), b"pref")
            .unwrap(),
        Ordering::Greater
    );
    assert_eq!(
        split_memory
            .compare_c_string(base, bytes.len(), b"prefox")
            .unwrap(),
        Ordering::Less
    );
    assert_eq!(
        split_memory
            .compare_c_string(base, bytes.len() - 1, b"prefix")
            .unwrap(),
        Ordering::Less
    );

    let nul_maps = [
        MapInfo {
            end: base + 6,
            ..map_for(&bytes)
        },
        MapInfo {
            start: base + 6,
            ..map_for(&bytes)
        },
    ];
    assert!(
        memory(&nul_maps)
            .matches_c_string(base, bytes.len(), b"prefix")
            .unwrap()
    );
}

#[test]
fn decodes_sleb128_boundaries_and_distinguishes_errors() {
    assert_eq!(read_sleb128(&[0x7f]).unwrap(), -1);
    assert_eq!(
        read_sleb128(&[0xff; 9].into_iter().chain([0]).collect::<Vec<_>>()).unwrap(),
        i64::MAX
    );
    assert_eq!(
        read_sleb128(&[0x80; 9].into_iter().chain([0x7f]).collect::<Vec<_>>()).unwrap(),
        i64::MIN
    );
    assert!(matches!(
        read_sleb128(&[0x80]),
        Err(Error::InvalidElf("truncated SLEB128"))
    ));
    assert!(matches!(
        read_sleb128(&[0x80; 10]),
        Err(Error::InvalidElf("SLEB128 overflow"))
    ));
    assert!(matches!(
        read_sleb128(&[0xff; 9].into_iter().chain([1]).collect::<Vec<_>>()),
        Err(Error::InvalidElf("SLEB128 overflow"))
    ));

    let packed = *b"APS2\x7f";
    let base = packed.as_ptr() as usize;
    let maps = [
        MapInfo {
            end: base + 4,
            ..map_for(&packed)
        },
        MapInfo {
            start: base + 4,
            ..map_for(&packed)
        },
    ];
    let view = memory(&maps);
    let mut reader = PackedReader::new(&view, base, packed.len()).unwrap();
    assert_eq!(reader.read_sleb128().unwrap(), -1);
}

#[test]
fn decodes_elf32_and_elf64_r_info() {
    assert_eq!(
        ElfClass::Elf32.decode_info(0x1234_5607).unwrap(),
        (0x12_3456, 7)
    );
    assert_eq!(
        ElfClass::Elf64
            .decode_info((0x1234_5678_u64 << 32) | 1026)
            .unwrap(),
        (0x1234_5678, 1026)
    );
}

#[test]
fn parses_real_elf32_and_elf64_header_layouts() {
    for (class, machine, phoff) in [(ElfClass::Elf32, 3, 52_u64), (ElfClass::Elf64, 62, 64_u64)] {
        let mut fixture = Fixture::new();
        write_header(&mut fixture, class, machine, phoff, 1);
        let maps = [map_for(&fixture.0)];
        let header = parse_header(&memory(&maps), fixture.base(), None).unwrap();
        assert!(matches!(
            (class, header.class),
            (ElfClass::Elf32, ElfClass::Elf32) | (ElfClass::Elf64, ElfClass::Elf64)
        ));
        assert_eq!(header.machine, machine);
        assert_eq!(header.phoff, phoff);
        assert_eq!(header.phnum, 1);
    }

    let class = native_class();
    let mut fixture = Fixture::new();
    write_header(
        &mut fixture,
        class,
        arch::MACHINE,
        class.ehdr_size() as u64,
        (MAX_PROGRAM_HEADERS + 1) as u16,
    );
    let maps = [map_for(&fixture.0)];
    assert!(matches!(
        parse_header(&memory(&maps), fixture.base(), None),
        Err(Error::InvalidElf("too many program headers"))
    ));
}

#[test]
fn parses_data_only_dynamic_table_from_anonymous_bss_tail() {
    let class = native_class();
    let phoff = class.ehdr_size();
    let dynamic_offset = 512;
    let mut fixture = Fixture::new();
    write_header(&mut fixture, class, arch::MACHINE, phoff as u64, 2);

    let dynamic_size = class.dyn_size();
    let fixture_size = fixture.0.len();
    match class {
        ElfClass::Elf32 => {
            fixture.write_u32(phoff, PT_LOAD);
            fixture.write_u32(phoff + 4, 0);
            fixture.write_u32(phoff + 8, 0);
            fixture.write_u32(phoff + 16, dynamic_offset as u32);
            fixture.write_u32(phoff + 20, fixture_size as u32);
            fixture.write_u32(phoff + 24, 0);

            let dynamic = phoff + class.phdr_size();
            fixture.write_u32(dynamic, PT_DYNAMIC);
            fixture.write_u32(dynamic + 4, dynamic_offset as u32);
            fixture.write_u32(dynamic + 8, dynamic_offset as u32);
            fixture.write_u32(dynamic + 16, dynamic_size as u32);
            fixture.write_u32(dynamic + 20, dynamic_size as u32);
        }
        ElfClass::Elf64 => {
            fixture.write_u32(phoff, PT_LOAD);
            fixture.write_u32(phoff + 4, 0);
            fixture.write_u64(phoff + 8, 0);
            fixture.write_u64(phoff + 16, 0);
            fixture.write_u64(phoff + 32, dynamic_offset as u64);
            fixture.write_u64(phoff + 40, fixture_size as u64);

            let dynamic = phoff + class.phdr_size();
            fixture.write_u32(dynamic, PT_DYNAMIC);
            fixture.write_u64(dynamic + 8, dynamic_offset as u64);
            fixture.write_u64(dynamic + 16, dynamic_offset as u64);
            fixture.write_u64(dynamic + 32, dynamic_size as u64);
            fixture.write_u64(dynamic + 40, dynamic_size as u64);
        }
    }

    let base = fixture.base();
    let mut file_map = map_for(&fixture.0);
    file_map.end = base + dynamic_offset;
    file_map.perms = MapPerms::READ;
    file_map.device = crate::DeviceId::new(1, 2);
    file_map.inode = 3;
    let mut bss_map = map_for(&fixture.0);
    bss_map.start = base + dynamic_offset;
    bss_map.device = crate::DeviceId::new(0, 0);
    bss_map.inode = 0;
    let header_maps = [file_map.clone()];
    let maps = [file_map, bss_map];
    let target = Target::new(crate::DeviceId::new(1, 2), 3).unwrap();

    let (_, image_maps) = parse_image(&memory(&header_maps), &maps, base, base, &target)
        .unwrap()
        .unwrap();

    assert!(
        image_maps.iter().any(|map| {
            map.inode == 0 && map.contains_range(base + dynamic_offset, dynamic_size)
        })
    );
}

#[test]
fn validates_file_backed_bss_tail_boundaries() {
    let page_size = crate::sys::page_size().unwrap();
    let base = page_size * 16;
    let raw_file_end = base + page_size + 123;
    let file_tail_end = base + page_size * 2;
    let mem_end = base + page_size * 3;
    let device = crate::DeviceId::new(1, 2);
    let target = Target::new(device, 3).unwrap();
    let load = ProgramHeader {
        kind: PT_LOAD,
        flags: 0,
        offset: 0,
        vaddr: 0,
        filesz: (raw_file_end - base) as u64,
        memsz: (mem_end - base) as u64,
    };
    let file_map = |start, end, offset| MapInfo {
        start,
        end,
        perms: MapPerms::READ,
        is_private: true,
        offset,
        device,
        inode: 3,
        path: None,
    };
    let anonymous_map = |start, end| MapInfo {
        start,
        end,
        perms: MapPerms::READ,
        is_private: true,
        offset: 0,
        device: crate::DeviceId::new(0, 0),
        inode: 0,
        path: None,
    };

    let split_tail = [
        file_map(base, raw_file_end, 0),
        file_map(raw_file_end, file_tail_end, (raw_file_end - base) as u64),
        anonymous_map(file_tail_end, mem_end),
    ];
    assert!(load_mappings_are_loader_shaped(base, base, &[load], &split_tail, &target).unwrap());

    let file_past_tail = [file_map(base, mem_end, 0)];
    assert!(
        !load_mappings_are_loader_shaped(base, base, &[load], &file_past_tail, &target).unwrap()
    );

    let aligned = ProgramHeader {
        filesz: (page_size * 2) as u64,
        ..load
    };
    let aligned_tail = [
        file_map(base, file_tail_end, 0),
        anonymous_map(file_tail_end, mem_end),
    ];
    assert!(
        load_mappings_are_loader_shaped(base, base, &[aligned], &aligned_tail, &target).unwrap()
    );

    let anonymous_base = (load_mappings_are_loader_shaped as *const ()).expose_provenance();
    let loader_base = loader_image_base(anonymous_base).unwrap();
    let mut bound = target;
    bound.bound_image = Some(crate::plt::BoundImage {
        header: anonymous_base,
        loader_base,
    });
    let empty_file = ProgramHeader {
        filesz: 0,
        memsz: 1,
        ..load
    };
    assert!(
        load_mappings_are_loader_shaped(
            anonymous_base,
            loader_base,
            &[empty_file],
            &[anonymous_map(anonymous_base, anonymous_base + 1)],
            &bound,
        )
        .unwrap()
    );
}

#[test]
fn shared_load_page_uses_the_latter_segment_permissions() {
    let base = 0x1_0000;
    let device = crate::DeviceId::new(1, 2);
    let target = Target::new(device, 3).unwrap();
    for (flags, perms) in [
        ([0, PF_X], MapPerms::READ | MapPerms::EXEC),
        ([PF_X, 0], MapPerms::READ),
    ] {
        let loads = [
            ProgramHeader {
                kind: PT_LOAD,
                flags: flags[0],
                offset: 0,
                vaddr: 0,
                filesz: 0x1000,
                memsz: 0x1000,
            },
            ProgramHeader {
                kind: PT_LOAD,
                flags: flags[1],
                offset: 0x800,
                vaddr: 0x800,
                filesz: 0x800,
                memsz: 0x800,
            },
        ];
        let maps = [MapInfo {
            start: base,
            end: base + 0x1000,
            perms,
            is_private: true,
            offset: 0,
            device,
            inode: 3,
            path: None,
        }];

        assert!(load_mappings_are_loader_shaped(base, base, &loads, &maps, &target).unwrap());
    }
}

#[test]
fn rejects_a_read_only_flat_file_view_as_a_loaded_image() {
    let class = native_class();
    let phoff = class.ehdr_size();
    let mut fixture = Fixture::new();
    write_header(&mut fixture, class, arch::MACHINE, phoff as u64, 1);
    let fixture_size = fixture.0.len();
    match class {
        ElfClass::Elf32 => {
            fixture.write_u32(phoff, PT_LOAD);
            fixture.write_u32(phoff + 8, 0);
            fixture.write_u32(phoff + 16, fixture_size as u32);
            fixture.write_u32(phoff + 20, fixture_size as u32);
            fixture.write_u32(phoff + 24, PF_X);
        }
        ElfClass::Elf64 => {
            fixture.write_u32(phoff, PT_LOAD);
            fixture.write_u32(phoff + 4, PF_X);
            fixture.write_u64(phoff + 16, 0);
            fixture.write_u64(phoff + 32, fixture_size as u64);
            fixture.write_u64(phoff + 40, fixture_size as u64);
        }
    }
    let mut map = map_for(&fixture.0);
    map.device = crate::DeviceId::new(1, 2);
    map.inode = 3;
    let maps = [map];
    let target = Target::new(crate::DeviceId::new(1, 2), 3).unwrap();

    // SAFETY: the synthetic mapping is backed by the live fixture for the
    // complete scan and is intentionally described as read-only.
    assert!(matches!(
        unsafe { find_symbol_relocations(&target, &maps, &[any_query(c"getpid")], false) },
        Ok(None)
    ));

    match class {
        ElfClass::Elf32 => fixture.write_u32(phoff + 24, 0),
        ElfClass::Elf64 => fixture.write_u32(phoff + 4, 0),
    }
    // SAFETY: matching PT_LOAD permissions still cannot turn an ordinary
    // file view into an image registered with the dynamic loader.
    assert!(matches!(
        unsafe { find_symbol_relocations(&target, &maps, &[any_query(c"getpid")], false) },
        Ok(None)
    ));
}

#[test]
fn loader_registry_distinguishes_loaded_images_from_ordinary_memory() {
    let function = find_symbol_relocations as *const ();
    let base = loader_image_base(function.expose_provenance()).unwrap();
    assert_eq!(loader_image_base(base), Some(base));

    let fixture = Fixture::new();
    assert_eq!(loader_image_base(fixture.base()), None);
}

#[test]
fn elf_magic_probe_preserves_read_errors() {
    let memory = memory(&[]);
    assert!(matches!(
        has_elf_magic(&memory, 0x1000),
        Err(Error::UnmappedRead {
            address: 0x1000,
            length: 4
        })
    ));
}

#[test]
fn filesz_may_exceed_memsz_for_non_load_program_headers() {
    let class = native_class();
    let mut fixture = Fixture::new();
    fixture.write_u32(0, PT_DYNAMIC);
    match class {
        ElfClass::Elf32 => {
            fixture.write_u32(16, 2);
            fixture.write_u32(20, 1);
        }
        ElfClass::Elf64 => {
            fixture.write_u64(32, 2);
            fixture.write_u64(40, 1);
        }
    }
    let maps = [map_for(&fixture.0)];

    assert!(parse_program_header(&memory(&maps), fixture.base(), class).is_ok());
}

#[test]
fn archive_bounds_precede_magic_and_full_header_reads() {
    let class = native_class();
    let mut fixture = Fixture::new();
    write_header(
        &mut fixture,
        class,
        arch::MACHINE,
        class.ehdr_size() as u64,
        1,
    );
    let mut map = map_for(&fixture.0);
    map.device = crate::DeviceId::new(1, 2);
    map.inode = 3;
    let device = map.device;
    let inode = map.inode;
    let maps = [map];
    let memory = memory(&maps);

    let shorter_than_magic = Target::from_archive_member(device, inode, 0, 3).unwrap();
    assert!(matches!(
        unsafe {
            find_symbol_relocations(&shorter_than_magic, &maps, &[any_query(c"getpid")], false)
        },
        Err(Error::InvalidElf("ELF magic exceeds archive member"))
    ));

    let shorter_than_ident = Target::from_archive_member(device, inode, 0, 15).unwrap();
    assert!(matches!(
        parse_image(
            &memory,
            &maps,
            fixture.base(),
            fixture.base(),
            &shorter_than_ident
        ),
        Err(Error::InvalidElf(
            "ELF identification exceeds archive member"
        ))
    ));

    let shorter_than_header =
        Target::from_archive_member(device, inode, 0, class.ehdr_size() as u64 - 1).unwrap();
    assert!(matches!(
        parse_image(
            &memory,
            &maps,
            fixture.base(),
            fixture.base(),
            &shorter_than_header
        ),
        Err(Error::InvalidElf("ELF header exceeds archive member"))
    ));
}

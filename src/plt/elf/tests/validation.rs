use super::*;

#[test]
fn implicit_addend_rejection_is_per_symbol() {
    let mut fixture = Fixture::new();
    let (strtab, strsz, symtab) = install_symbol(&mut fixture, ElfClass::Elf64);
    let maps = [map_for(&fixture.0)];
    let memory = memory(&maps);
    let image = image_for(&fixture, ElfClass::Elf64, 62, false);
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

    let missing = ResolvedSymbolQuery {
        output: 1,
        name: b"missing",
        version: SymbolVersion::Any,
        strtab,
        strsz,
        symtab,
        symbol_count: Some(2),
        versions: None,
    };
    let queries = [query, missing];
    let mut scans: [RelocationScan; 2] = std::array::from_fn(|_| Default::default());
    image
        .consider_relocations(
            &memory,
            &queries,
            SLOT_OFFSET as u64,
            (1_u64 << 32) | 1,
            None,
            &mut scans,
        )
        .unwrap();
    image
        .consider_relocations(
            &memory,
            &queries,
            (SLOT_OFFSET + 8) as u64,
            (1_u64 << 32) | 6,
            Some(0),
            &mut scans,
        )
        .unwrap();
    assert!(scans[0].unsupported_implicit_addend);
    assert!(!scans[1].unsupported_implicit_addend);
    assert_eq!(scans[0].matches.len(), 1);
    assert!(scans[1].matches.is_empty());
    assert_eq!(
        scans[0].matches[&(fixture.base() + SLOT_OFFSET + 8)].kind,
        RelocationKind::GlobalData
    );
    let rejected = scans[0].rejected.values().copied().collect::<Vec<_>>();
    assert_eq!(
        rejected,
        [RejectedRelocation {
            address: fixture.base() + SLOT_OFFSET,
            image: image.id,
            kind: RelocationKind::Absolute,
            addend: None,
            reason: RelocationRejection::ImplicitAddend,
        }]
    );
    assert!(scans[1].rejected.is_empty());
}

#[test]
fn version_mismatch_precedes_relocation_slot_validation() {
    let class = native_class();
    let mut fixture = Fixture::new();
    let (strtab, strsz, symtab) = install_symbol(&mut fixture, class);
    fixture.write_u16(VERSYM_OFFSET + 2, 2);
    let maps = [map_for(&fixture.0)];
    let view = memory(&maps);
    let image = image_for(&fixture, class, arch::MACHINE, false);
    let versions = VersionMetadata {
        versym: Some(fixture.base() + VERSYM_OFFSET),
        ..VersionMetadata::default()
    };
    let query = ResolvedSymbolQuery {
        output: 0,
        name: b"getpid",
        version: SymbolVersion::Unversioned,
        strtab,
        strsz,
        symtab,
        symbol_count: Some(2),
        versions: Some(&versions),
    };
    let relocation_type = match arch::MACHINE {
        arch::EM_ARM => 22,
        arch::EM_AARCH64 => 1026,
        _ => 7,
    };
    let info = match class {
        ElfClass::Elf32 => u64::from((1_u32 << 8) | relocation_type),
        ElfClass::Elf64 => (1_u64 << 32) | u64::from(relocation_type),
    };
    let mut scans = [RelocationScan::default()];

    image
        .consider_relocations(
            &view,
            std::slice::from_ref(&query),
            fixture.0.len() as u64,
            info,
            Some(0),
            &mut scans,
        )
        .unwrap();
    assert!(scans[0].matches.is_empty());
    assert!(scans[0].rejected.is_empty());
}

#[test]
fn records_32_bit_implicit_absolute_relocations() {
    for (machine, relocation_type) in [(arch::EM_386, 1_u32), (arch::EM_ARM, 2_u32)] {
        let mut fixture = Fixture::new();
        let (strtab, strsz, symtab) = install_symbol(&mut fixture, ElfClass::Elf32);
        let maps = [map_for(&fixture.0)];
        let memory = memory(&maps);
        let image = image_for(&fixture, ElfClass::Elf32, machine, false);
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
            .consider_relocation(
                &memory,
                &query,
                SLOT_OFFSET as u64,
                u64::from((1_u32 << 8) | relocation_type),
                None,
                &mut scan,
            )
            .unwrap();

        assert!(scan.unsupported_implicit_addend);
        assert!(scan.matches.is_empty());
        assert_eq!(
            scan.rejected.values().copied().collect::<Vec<_>>(),
            [RejectedRelocation {
                address: fixture.base() + SLOT_OFFSET,
                image: image.id,
                kind: RelocationKind::Absolute,
                addend: None,
                reason: RelocationRejection::ImplicitAddend,
            }]
        );
    }
}

#[test]
fn pac_plt_only_marks_aarch64_jump_slots() {
    let mut fixture = Fixture::new();
    let (strtab, strsz, symtab) = install_symbol(&mut fixture, ElfClass::Elf64);
    let maps = [map_for(&fixture.0)];
    let memory = memory(&maps);
    let aarch64 = image_for(&fixture, ElfClass::Elf64, arch::EM_AARCH64, true);
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
    aarch64
        .consider_relocation(
            &memory,
            &query,
            SLOT_OFFSET as u64,
            (1_u64 << 32) | 1026,
            Some(0),
            &mut scan,
        )
        .unwrap();
    assert_eq!(scan.matches.len(), 1);
    assert!(scan.matches[&(fixture.base() + SLOT_OFFSET)].aarch64_pac_plt);
    assert!(scan.rejected.is_empty());
    aarch64
        .consider_relocation(
            &memory,
            &query,
            (SLOT_OFFSET + 8) as u64,
            (1_u64 << 32) | 1025,
            Some(0),
            &mut scan,
        )
        .unwrap();
    assert_eq!(scan.matches.len(), 2);
    assert!(!scan.matches[&(fixture.base() + SLOT_OFFSET + 8)].aarch64_pac_plt);

    let x86_64 = image_for(&fixture, ElfClass::Elf64, 62, true);
    let mut x86_scan = RelocationScan::default();
    x86_64
        .consider_relocation(
            &memory,
            &query,
            (SLOT_OFFSET + 8) as u64,
            (1_u64 << 32) | 7,
            Some(7),
            &mut x86_scan,
        )
        .unwrap();
    assert_eq!(
        x86_scan.rejected.values().copied().collect::<Vec<_>>(),
        [RejectedRelocation {
            address: fixture.base() + SLOT_OFFSET + 8,
            image: x86_64.id,
            kind: RelocationKind::JumpSlot,
            addend: Some(7),
            reason: RelocationRejection::UnsupportedAddend,
        }]
    );
    assert!(x86_scan.matches.is_empty());

    let mut x86_global = RelocationScan::default();
    x86_64
        .consider_relocation(
            &memory,
            &query,
            (SLOT_OFFSET + 16) as u64,
            (1_u64 << 32) | 6,
            Some(7),
            &mut x86_global,
        )
        .unwrap();
    assert_eq!(
        x86_global.rejected.values().copied().collect::<Vec<_>>(),
        [RejectedRelocation {
            address: fixture.base() + SLOT_OFFSET + 16,
            image: x86_64.id,
            kind: RelocationKind::GlobalData,
            addend: Some(7),
            reason: RelocationRejection::UnsupportedAddend,
        }]
    );
    assert!(x86_global.matches.is_empty());

    let mut x86_absolute = RelocationScan::default();
    x86_64
        .consider_relocation(
            &memory,
            &query,
            (SLOT_OFFSET + 24) as u64,
            (1_u64 << 32) | 1,
            Some(7),
            &mut x86_absolute,
        )
        .unwrap();
    assert_eq!(
        x86_absolute.matches[&(fixture.base() + SLOT_OFFSET + 24)].addend,
        7
    );
}

#[cfg(target_arch = "aarch64")]
#[test]
fn pac_plt_rejects_a_signature_for_another_slot() {
    const HWCAP_PACA: libc::c_ulong = 1 << 30;

    let mut fixture = Fixture::new();
    let (strtab, strsz, symtab) = install_symbol(&mut fixture, ElfClass::Elf64);
    let maps = [map_for(&fixture.0)];
    let memory = memory(&maps);
    let image = image_for(&fixture, ElfClass::Elf64, arch::EM_AARCH64, true);
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
    let address = fixture.base() + SLOT_OFFSET;
    let raw = 0x1234;
    let valid = crate::sys::sign_pac_plt(raw, address);
    // SAFETY: getauxval has no pointer arguments for AT_HWCAP.
    let paca = unsafe { libc::getauxval(libc::AT_HWCAP) } & HWCAP_PACA != 0;
    if !paca {
        assert_eq!(valid, raw);
        assert_eq!(crate::sys::verify_pac_plt(valid, address), Some(raw));
        return;
    }
    let wrong = (1..=1024)
        .map(|offset| {
            crate::sys::sign_pac_plt(raw, address + offset * std::mem::size_of::<usize>())
        })
        .find(|&stored| stored != valid)
        .expect("PAC did not vary across modifiers");
    fixture.write_u64(SLOT_OFFSET, wrong as u64);

    let mut scan = RelocationScan::default();
    image
        .consider_relocation(
            &memory,
            &query,
            SLOT_OFFSET as u64,
            (1_u64 << 32) | 1026,
            Some(0),
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
            addend: Some(0),
            reason: RelocationRejection::PacPltVerificationFailed,
        }]
    );
}

#[test]
fn rejects_archive_program_headers_and_loads_outside_the_member() {
    let class = native_class();
    let phoff = class.ehdr_size() as u64;
    let mut fixture = Fixture::new();
    write_header(&mut fixture, class, arch::MACHINE, phoff, 1);
    let maps = [map_for(&fixture.0)];
    let memory = memory(&maps);
    let too_short = ElfImageSelector::from_archive_member(
        crate::DeviceId::new(1, 2),
        3,
        0,
        phoff + class.phdr_size() as u64 - 1,
    )
    .unwrap();
    assert!(matches!(
        parse_image(&memory, &maps, fixture.base(), fixture.base(), &too_short),
        Err(Error::InvalidElf("program headers exceed archive member"))
    ));

    let phdr = phoff as usize;
    fixture.write_u32(phdr, PT_LOAD);
    match class {
        ElfClass::Elf32 => {
            fixture.write_u32(phdr + 4, 0);
            fixture.write_u32(phdr + 8, 0);
            fixture.write_u32(phdr + 16, 512);
            fixture.write_u32(phdr + 20, 512);
        }
        ElfClass::Elf64 => {
            fixture.write_u64(phdr + 8, 0);
            fixture.write_u64(phdr + 16, 0);
            fixture.write_u64(phdr + 32, 512);
            fixture.write_u64(phdr + 40, 512);
        }
    }
    let bounded =
        ElfImageSelector::from_archive_member(crate::DeviceId::new(1, 2), 3, 0, 256).unwrap();
    assert!(matches!(
        parse_image(&memory, &maps, fixture.base(), fixture.base(), &bounded),
        Err(Error::InvalidElf("PT_LOAD exceeds archive member"))
    ));
}

#[test]
fn rejects_archive_metadata_beyond_the_member() {
    let class = native_class();
    let phoff = class.ehdr_size() as u64;
    let mut fixture = Fixture::new();
    write_header(&mut fixture, class, arch::MACHINE, phoff, 2);

    // The file data ends at the member boundary; memsz extends beyond it.
    let phdr = phoff as usize;
    fixture.write_u32(phdr, PT_LOAD);
    match class {
        ElfClass::Elf32 => {
            fixture.write_u32(phdr + 4, 0);
            fixture.write_u32(phdr + 8, 0);
            fixture.write_u32(phdr + 16, 256);
            fixture.write_u32(phdr + 20, 1024);
        }
        ElfClass::Elf64 => {
            fixture.write_u64(phdr + 8, 0);
            fixture.write_u64(phdr + 16, 0);
            fixture.write_u64(phdr + 32, 256);
            fixture.write_u64(phdr + 40, 1024);
        }
    }

    // PT_DYNAMIC is placed in the memory tail beyond the declared member,
    // but still inside the mapped bytes of the archive file.
    let dynamic = phdr + class.phdr_size();
    let dynamic_offset = 768;
    let dynamic_size = class.dyn_size();
    fixture.write_u32(dynamic, PT_DYNAMIC);
    match class {
        ElfClass::Elf32 => {
            fixture.write_u32(dynamic + 4, 0);
            fixture.write_u32(dynamic + 8, dynamic_offset as u32);
            fixture.write_u32(dynamic + 16, dynamic_size as u32);
            fixture.write_u32(dynamic + 20, dynamic_size as u32);
        }
        ElfClass::Elf64 => {
            fixture.write_u32(dynamic + 4, 0);
            fixture.write_u64(dynamic + 16, dynamic_offset as u64);
            fixture.write_u64(dynamic + 32, dynamic_size as u64);
            fixture.write_u64(dynamic + 40, dynamic_size as u64);
        }
    }

    let base = fixture.base();
    let page_size = crate::sys::page_size().unwrap();
    let file_tail_end =
        crate::sys::page_start(base + 256 + page_size - 1, page_size).min(base + 1024);
    let mut maps = vec![MapInfo {
        start: base,
        end: file_tail_end,
        perms: MapPerms::READ,
        is_private: true,
        offset: 0,
        device: crate::DeviceId::new(1, 2),
        inode: 3,
        path: None,
    }];
    if file_tail_end < base + 1024 {
        maps.push(MapInfo {
            start: file_tail_end,
            end: base + 1024,
            perms: MapPerms::READ,
            is_private: true,
            offset: 0,
            device: crate::DeviceId::new(0, 0),
            inode: 0,
            path: None,
        });
    }
    let maps = maps.as_slice();
    let memory = memory(maps);
    let image_selector =
        ElfImageSelector::from_archive_member(crate::DeviceId::new(1, 2), 3, 0, 256).unwrap();
    assert!(matches!(
        parse_image(&memory, maps, base, base, &image_selector),
        Err(Error::InvalidElf("PT_DYNAMIC exceeds PT_LOAD"))
    ));
}

#[test]
fn archive_file_ranges_survive_vaddr_to_offset_skew() {
    let class = native_class();
    let phoff = class.ehdr_size() as u64;
    let mut fixture = Fixture::new();
    write_header(&mut fixture, class, arch::MACHINE, phoff, 3);

    // The second PT_LOAD ends 0x200 bytes into the member but starts 0x200
    // bytes into memory. Its complete file-backed range is inside the member
    // even though it starts at the member end in the address domain.
    let first = phoff as usize;
    let second = first + class.phdr_size();
    let dynamic = second + class.phdr_size();
    fixture.write_u32(first, PT_LOAD);
    fixture.write_u32(second, PT_LOAD);
    fixture.write_u32(dynamic, PT_DYNAMIC);
    match class {
        ElfClass::Elf32 => {
            fixture.write_u32(first + 4, 0);
            fixture.write_u32(first + 8, 0x100);
            fixture.write_u32(first + 16, 0x100);
            fixture.write_u32(first + 20, 0x100);
            fixture.write_u32(second + 4, 0x100);
            fixture.write_u32(second + 8, 0x300);
            fixture.write_u32(second + 16, 0x100);
            fixture.write_u32(second + 20, 0x100);
            fixture.write_u32(dynamic + 4, 0x150);
            fixture.write_u32(dynamic + 8, 0x350);
            fixture.write_u32(dynamic + 16, class.dyn_size() as u32);
            fixture.write_u32(dynamic + 20, class.dyn_size() as u32);
        }
        ElfClass::Elf64 => {
            fixture.write_u64(first + 8, 0);
            fixture.write_u64(first + 16, 0x100);
            fixture.write_u64(first + 32, 0x100);
            fixture.write_u64(first + 40, 0x100);
            fixture.write_u64(second + 8, 0x100);
            fixture.write_u64(second + 16, 0x300);
            fixture.write_u64(second + 32, 0x100);
            fixture.write_u64(second + 40, 0x100);
            fixture.write_u64(dynamic + 8, 0x150);
            fixture.write_u64(dynamic + 16, 0x350);
            fixture.write_u64(dynamic + 32, class.dyn_size() as u64);
            fixture.write_u64(dynamic + 40, class.dyn_size() as u64);
        }
    }

    let base = fixture.base();
    let maps = [MapInfo {
        start: base,
        end: base + 0x300,
        perms: MapPerms::READ,
        is_private: true,
        offset: 0,
        device: crate::DeviceId::new(1, 2),
        inode: 3,
        path: None,
    }];
    let image_selector =
        ElfImageSelector::from_archive_member(crate::DeviceId::new(1, 2), 3, 0, 0x200).unwrap();
    assert!(matches!(
        parse_image(&memory(&maps), &maps, base, base, &image_selector),
        Ok(Some(_))
    ));
}

#[test]
fn rejects_misaligned_and_unterminated_dynamic_tables() {
    let bytes = [1_u8; 32];
    let maps = [map_for(&bytes)];
    let view = memory(&maps);
    assert!(matches!(
        parse_dynamic(&view, bytes.as_ptr() as usize, 15, ElfClass::Elf64),
        Err(Error::InvalidElf("invalid PT_DYNAMIC size"))
    ));
    assert!(matches!(
        parse_dynamic(&view, bytes.as_ptr() as usize, 16, ElfClass::Elf64),
        Err(Error::InvalidElf("unterminated PT_DYNAMIC"))
    ));
    let oversized = vec![1; MAX_DYNAMIC_ENTRIES * ElfClass::Elf64.dyn_size()];
    let oversized_maps = [map_for(&oversized)];
    assert!(matches!(
        parse_dynamic(
            &memory(&oversized_maps),
            oversized.as_ptr() as usize,
            (MAX_DYNAMIC_ENTRIES + 1) * ElfClass::Elf64.dyn_size(),
            ElfClass::Elf64,
        ),
        Err(Error::InvalidElf("too many dynamic entries"))
    ));

    let terminated = [0_u8; 16];
    let terminated_maps = [map_for(&terminated)];
    assert!(
        parse_dynamic(
            &memory(&terminated_maps),
            terminated.as_ptr() as usize,
            (MAX_DYNAMIC_ENTRIES + 1) * ElfClass::Elf64.dyn_size(),
            ElfClass::Elf64,
        )
        .is_ok()
    );
}

#[test]
fn parses_dynamic_symbol_table_size_tags() {
    let mut fixture = Fixture::new();
    for (index, (tag, value)) in [
        (DT_HASH, 128_u64),
        (DT_SYMTAB, 160),
        (DT_SYMENT, 24),
        (DT_SYMTABSZ, 48),
        (DT_GNU_HASH, 256),
    ]
    .into_iter()
    .enumerate()
    {
        let entry = index * ElfClass::Elf64.dyn_size();
        fixture.write_u64(entry, tag as u64);
        fixture.write_u64(entry + 8, value);
    }
    let maps = [map_for(&fixture.0)];
    let info = parse_dynamic(
        &memory(&maps),
        fixture.base(),
        6 * ElfClass::Elf64.dyn_size(),
        ElfClass::Elf64,
    )
    .unwrap();

    assert_eq!(info.hash, Some(128));
    assert_eq!(info.symtab, Some(160));
    assert_eq!(info.syment, Some(24));
    assert_eq!(info.symtabsz, Some(48));
    assert_eq!(info.gnu_hash, Some(256));
}

#[test]
fn dt_symtabsz_is_a_fallback_and_bounded() {
    for class in [ElfClass::Elf32, ElfClass::Elf64] {
        let mut fixture = Fixture::new();
        let (_, _, symtab) = install_symbol(&mut fixture, class);
        fixture.write_u32(TABLE_OFFSET, 1);
        fixture.write_u32(TABLE_OFFSET + 4, 2);
        let mut image = image_for(&fixture, class, arch::MACHINE, false);
        image.dynamic.hash = Some((fixture.base() + TABLE_OFFSET) as u64);
        let syment = class.sym_size() as u64;
        image.dynamic.symtabsz = Some(2 * syment);
        let maps = [map_for(&fixture.0)];
        let view = memory(&maps);

        assert_eq!(
            image.dynamic_symbol_count(&view, symtab, syment).unwrap(),
            Some(2)
        );

        image.dynamic.symtabsz = Some(3 * syment);
        assert!(matches!(
            image.dynamic_symbol_count(&view, symtab, syment),
            Err(Error::InvalidElf("inconsistent dynamic symbol table sizes"))
        ));

        image.dynamic.symtabsz = Some(2 * syment + 1);
        assert_eq!(
            image.dynamic_symbol_count(&view, symtab, syment).unwrap(),
            Some(2)
        );

        image.dynamic.hash = None;
        image.dynamic.gnu_hash = None;
        assert!(matches!(
            image.dynamic_symbol_count(&view, symtab, syment),
            Err(Error::InvalidElf("invalid DT_SYMTABSZ"))
        ));

        let available = fixture.0.len() - SYMTAB_OFFSET;
        image.dynamic.symtabsz =
            Some(((available / class.sym_size() + 1) * class.sym_size()) as u64);
        assert!(matches!(
            image.dynamic_symbol_count(&view, symtab, syment),
            Err(Error::InvalidElf("DT_SYMTAB exceeds readable PT_LOAD"))
        ));
    }
}

#[test]
fn symbol_count_falls_back_from_sysv_to_gnu_hash() {
    for class in [ElfClass::Elf32, ElfClass::Elf64] {
        let mut fixture = Fixture::new();
        let (_, _, symtab) = install_symbol(&mut fixture, class);
        let mut image = image_for(&fixture, class, arch::MACHINE, false);
        let hash = fixture.base() + TABLE_OFFSET;
        fixture.write_u32(TABLE_OFFSET, 1);
        fixture.write_u32(TABLE_OFFSET + 4, 2);
        fixture.write_u32(TABLE_OFFSET + 8, 1);
        image.dynamic.hash = Some(hash as u64);
        let maps = [map_for(&fixture.0)];
        let view = memory(&maps);

        assert_eq!(
            image
                .dynamic_symbol_count(&view, symtab, class.sym_size() as u64)
                .unwrap(),
            Some(2)
        );

        image.dynamic.hash = None;
        image.dynamic.gnu_hash = Some(hash as u64);
        fixture.write_u32(TABLE_OFFSET, 1);
        fixture.write_u32(TABLE_OFFSET + 4, 1);
        fixture.write_u32(TABLE_OFFSET + 8, 1);
        fixture.write_u32(TABLE_OFFSET + 12, 0);
        let bucket = TABLE_OFFSET + 16 + class.pointer_size();
        fixture.write_u32(bucket, 1);
        fixture.write_u32(bucket + 4, 1);
        let maps = [map_for(&fixture.0)];
        let view = memory(&maps);
        assert_eq!(
            image
                .dynamic_symbol_count(&view, symtab, class.sym_size() as u64)
                .unwrap(),
            Some(2)
        );

        fixture.write_u32(TABLE_OFFSET + 4, 2);
        fixture.write_u32(bucket, 0);
        let maps = [map_for(&fixture.0)];
        assert_eq!(
            image
                .dynamic_symbol_count(&memory(&maps), symtab, class.sym_size() as u64)
                .unwrap(),
            None
        );

        fixture.write_u32(TABLE_OFFSET + 4, 1);
        fixture.write_u32(bucket, 0);
        let syment = class.sym_size() as u64;
        image.dynamic.strtab = Some(symtab + 5 * syment);
        let maps = [map_for(&fixture.0)];
        assert_eq!(
            image
                .dynamic_symbol_count(&memory(&maps), symtab, syment)
                .unwrap(),
            None
        );
    }
}

#[test]
fn rejects_truncated_hash_tables_and_unterminated_gnu_chains() {
    for class in [ElfClass::Elf32, ElfClass::Elf64] {
        let mut fixture = Fixture::new();
        let (_, _, symtab) = install_symbol(&mut fixture, class);
        let mut image = image_for(&fixture, class, arch::MACHINE, false);
        let truncated = fixture.0.len() - 8;
        fixture.write_u32(truncated, 1);
        fixture.write_u32(truncated + 4, 2);
        image.dynamic.hash = Some((fixture.base() + truncated) as u64);
        image.dynamic.gnu_hash = Some((fixture.base() + TABLE_OFFSET) as u64);
        fixture.write_u32(TABLE_OFFSET, 1);
        fixture.write_u32(TABLE_OFFSET + 4, 1);
        fixture.write_u32(TABLE_OFFSET + 8, 1);
        let valid_gnu_bucket = TABLE_OFFSET + 16 + class.pointer_size();
        fixture.write_u32(valid_gnu_bucket, 1);
        fixture.write_u32(valid_gnu_bucket + 4, 1);
        let maps = [map_for(&fixture.0)];
        assert!(matches!(
            image.dynamic_symbol_count(&memory(&maps), symtab, class.sym_size() as u64),
            Err(Error::InvalidElf("invalid DT_HASH"))
        ));
        fixture.write_u32(truncated, 0);
        fixture.write_u32(truncated + 4, 0);

        const GNU_HASH_OFFSET: usize = 928;
        image.dynamic.hash = None;
        image.dynamic.gnu_hash = Some((fixture.base() + GNU_HASH_OFFSET) as u64);
        fixture.write_u32(GNU_HASH_OFFSET, 1);
        fixture.write_u32(GNU_HASH_OFFSET + 4, 1);
        fixture.write_u32(GNU_HASH_OFFSET + 8, 1);
        fixture.write_u32(GNU_HASH_OFFSET + 12, 0);
        let bucket = GNU_HASH_OFFSET + 16 + class.pointer_size();
        fixture.write_u32(bucket, 1);
        let maps = [map_for(&fixture.0)];
        assert!(matches!(
            image.dynamic_symbol_count(&memory(&maps), symtab, class.sym_size() as u64),
            Err(Error::InvalidElf("invalid DT_GNU_HASH"))
        ));

        let truncated = fixture.0.len() - 16;
        fixture.write_u32(truncated, 1);
        fixture.write_u32(truncated + 4, 1);
        fixture.write_u32(truncated + 8, 1);
        image.dynamic.gnu_hash = Some((fixture.base() + truncated) as u64);
        let maps = [map_for(&fixture.0)];
        assert!(matches!(
            image.dynamic_symbol_count(&memory(&maps), symtab, class.sym_size() as u64),
            Err(Error::InvalidElf("invalid DT_GNU_HASH"))
        ));
    }
}

#[test]
fn unknown_symbol_count_preserves_entry_bounds() {
    let mut fixture = Fixture::new();
    let (strtab, strsz, symtab) = install_symbol(&mut fixture, ElfClass::Elf64);
    let image = image_for(&fixture, ElfClass::Elf64, arch::MACHINE, false);
    let maps = [map_for(&fixture.0)];
    let view = memory(&maps);

    assert_eq!(
        image
            .dynamic_symbol_count(&view, symtab, ElfClass::Elf64.sym_size() as u64)
            .unwrap(),
        None
    );

    let query = ResolvedSymbolQuery {
        output: 0,
        name: b"getpid",
        version: SymbolVersion::Any,
        strtab,
        strsz,
        symtab,
        symbol_count: Some(1),
        versions: None,
    };
    assert!(matches!(
        image.symbol_name_location(&view, &query, 1),
        Err(Error::InvalidElf(
            "relocation symbol index exceeds dynamic symbol table"
        ))
    ));

    let query = ResolvedSymbolQuery {
        symbol_count: None,
        ..query
    };
    assert!(image.symbol_name_location(&view, &query, 1).is_ok());
    assert!(matches!(
        image.symbol_name_location(&view, &query, u32::MAX),
        Err(Error::InvalidElf("dynamic symbol table is too large"))
    ));
    assert!(matches!(
        image.symbol_name_location(&view, &query, 40),
        Err(Error::InvalidElf("symbol entry exceeds PT_LOAD"))
    ));
    let mut maps = maps;
    maps[0].end = fixture.base() + SYMTAB_OFFSET + ElfClass::Elf64.sym_size() + 4;
    assert!(matches!(
        image.symbol_name_location(&memory(&maps), &query, 1),
        Err(Error::InvalidElf("symbol entry exceeds PT_LOAD"))
    ));
}

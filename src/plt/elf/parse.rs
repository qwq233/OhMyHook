pub(super) fn parse_image(
    header_memory: &Memory<'_>,
    maps: &[MapInfo],
    header_address: usize,
    loader_base: usize,
    target: &Target,
) -> Result<Option<(Image, Vec<MapInfo>)>> {
    let header = parse_header(header_memory, header_address, target.archive_member_size())?;
    if header.class.value() != arch::ELF_CLASS {
        return Err(Error::UnsupportedFeature(
            "ELF class does not match the current process",
        ));
    }
    if header.machine != arch::MACHINE {
        return Err(Error::MachineMismatch {
            expected: arch::MACHINE,
            actual: header.machine,
        });
    }
    if let Some(file_size) = target.archive_member_size() {
        let table_size = u64::from(header.phentsize)
            .checked_mul(u64::from(header.phnum))
            .ok_or(Error::ArithmeticOverflow)?;
        let table_end = header
            .phoff
            .checked_add(table_size)
            .ok_or(Error::ArithmeticOverflow)?;
        if table_end > file_size {
            return Err(Error::InvalidElf("program headers exceed archive member"));
        }
    }

    let mut load = None;
    let mut loads = Vec::new();
    let mut dynamic = None;
    let mut notes = Vec::new();
    for index in 0..usize::from(header.phnum) {
        let entry_offset = index
            .checked_mul(usize::from(header.phentsize))
            .ok_or(Error::ArithmeticOverflow)?;
        let address = checked_add(checked_add_u64(header_address, header.phoff)?, entry_offset)?;
        let program = parse_program_header(header_memory, address, header.class)?;
        match program.kind {
            PT_LOAD => {
                if let Some(file_size) = target.archive_member_size() {
                    let file_end = program
                        .offset
                        .checked_add(program.filesz)
                        .ok_or(Error::ArithmeticOverflow)?;
                    if file_end > file_size {
                        return Err(Error::InvalidElf("PT_LOAD exceeds archive member"));
                    }
                }
                if program.offset == 0 {
                    load.get_or_insert(program);
                }
                loads.push(program);
            }
            PT_DYNAMIC if dynamic.replace(program).is_some() => {
                return Err(Error::InvalidElf("multiple PT_DYNAMIC segments"));
            }
            PT_DYNAMIC => {}
            PT_NOTE => notes.push(program),
            _ => {}
        }
    }

    let load = load.ok_or(Error::InvalidElf("missing PT_LOAD at file offset zero"))?;
    if load.filesz < header.class.ehdr_size() as u64 {
        return Err(Error::InvalidElf("ELF header is outside PT_LOAD"));
    }
    let load_vaddr = usize::try_from(load.vaddr).map_err(|_| Error::ArithmeticOverflow)?;
    let load_bias = header_address
        .checked_sub(load_vaddr)
        .ok_or(Error::InvalidElf("invalid load bias"))?;
    if !load_mappings_are_loader_shaped(load_bias, loader_base, &loads, maps, target)? {
        return Ok(None);
    }
    let dynamic = dynamic.ok_or(Error::InvalidElf("missing PT_DYNAMIC"))?;
    let dynamic_address = runtime_address(load_bias, dynamic.vaddr)?;
    let dynamic_size = usize::try_from(dynamic.memsz).map_err(|_| Error::ArithmeticOverflow)?;
    let mut load_ranges = Vec::with_capacity(loads.len());
    for segment in &loads {
        let start = runtime_address(load_bias, segment.vaddr)?;
        let length = usize::try_from(segment.memsz).map_err(|_| Error::ArithmeticOverflow)?;
        let end = checked_add(start, length)?;
        load_ranges.push((start, end));
    }
    // An archive member's metadata must stay inside the declared member: the
    // mapped archive page can contain the next member's bytes, which must
    // never drive this image's symbol or relocation selection. A loader-owned
    // anonymous tail beyond the member, for example BSS, remains readable.
    let load_ranges = if let Some(member_size) = target.archive_member_size() {
        let member_end = checked_add_u64(header_address, member_size)?;
        let mut bounded = Vec::with_capacity(loads.len() * 2);
        for (start, end) in load_ranges {
            if end <= member_end {
                bounded.push((start, end));
                continue;
            }
            if start < member_end {
                bounded.push((start, member_end));
            }
            let tail_start = start.max(member_end);
            if tail_start < end
                && find_map_containing(maps, tail_start, end - tail_start)
                    .is_some_and(|map| map.device != target.device() || map.inode != target.inode())
            {
                bounded.push((tail_start, end));
            }
        }
        bounded
    } else {
        load_ranges
    };
    let load_ranges = merge_ranges(load_ranges);
    if load_ranges.is_empty() {
        return Err(Error::InvalidElf("empty PT_LOAD range"));
    }
    if !range_in_ranges(dynamic_address, dynamic_size, &load_ranges) {
        return Err(Error::InvalidElf("PT_DYNAMIC exceeds PT_LOAD"));
    }
    let image_maps = maps_in_ranges(maps, &load_ranges);
    // SAFETY: every mapping is clipped to this image's exact PT_LOAD ranges;
    // the caller keeps those mappings stable for the complete scan.
    let image_memory = unsafe { Memory::new(&image_maps) };
    let mut dynamic_info =
        parse_dynamic(&image_memory, dynamic_address, dynamic_size, header.class)?;
    normalize_dynamic_pointers(&image_memory, load_bias, &load_ranges, &mut dynamic_info)?;

    Ok(Some((
        Image {
            id: ImageId {
                device: target.device(),
                inode: target.inode(),
                header: header_address,
                load_bias,
                elf_header_offset: target.elf_header_offset(),
                loader_base: Some(loader_base),
            },
            header,
            dynamic: dynamic_info,
            load_ranges,
            notes,
        },
        image_maps,
    )))
}

pub(super) fn load_mappings_are_loader_shaped(
    load_bias: usize,
    loader_base: usize,
    loads: &[ProgramHeader],
    maps: &[MapInfo],
    target: &Target,
) -> Result<bool> {
    let bound_image = target.bound_image();
    let page_size = crate::sys::page_size()?;
    let page_mask = u64::try_from(page_size - 1).map_err(|_| Error::ArithmeticOverflow)?;
    for segment in loads.iter().filter(|segment| segment.memsz != 0) {
        let executable = segment.flags & PF_X != 0;
        let segment_start = runtime_address(load_bias, segment.vaddr)?;
        let mut address = segment_start;
        let raw_file_end = checked_add_u64(address, segment.filesz)?;
        let end = checked_add_u64(address, segment.memsz)?;
        let file_tail_end = raw_file_end
            .checked_add(page_size - 1)
            .map(|address| crate::sys::page_start(address, page_size))
            .ok_or(Error::ArithmeticOverflow)?
            .min(end);
        let mut expected_offset = target
            .elf_header_offset()
            .checked_add(segment.offset)
            .ok_or(Error::ArithmeticOverflow)?;
        let mut previous_anonymous_map: Option<usize> = None;
        while address < end {
            let Some(map) = find_map_containing(maps, address, 1) else {
                return Ok(false);
            };
            if bound_image.is_none()
                && map.perms.contains(MapPerms::EXEC)
                    != load_page_is_executable(load_bias, loads, address, page_size)?
            {
                return Ok(false);
            }
            let source_file = address < file_tail_end
                && map.is_private
                && map.device == target.device()
                && map.inode == target.inode()
                && map.file_offset_at(address) == Some(expected_offset);
            let concealed = crate::plt::conceal::replaces_file_mapping(
                address,
                expected_offset,
                target.device(),
                target.inode(),
            );
            let anonymous =
                map.is_private && map.device == crate::DeviceId::new(0, 0) && map.inode == 0;
            let follows_source_file = (address == raw_file_end || address == file_tail_end)
                && address
                    .checked_sub(1)
                    .and_then(|previous| find_map_containing(maps, previous, 1))
                    .is_some_and(|previous| {
                        previous.is_private
                            && previous.device == target.device()
                            && previous.inode == target.inode()
                    });
            let loader_owned_anonymous = anonymous
                && (bound_image.is_some() || address >= raw_file_end)
                && if previous_anonymous_map == Some(map.start) {
                    true
                } else {
                    previous_anonymous_map = Some(map.start);
                    follows_source_file || loader_image_base(address) == Some(loader_base)
                };
            if !source_file && !concealed && !loader_owned_anonymous {
                return Ok(false);
            }
            if bound_image.is_none() && executable && address == segment_start {
                let expected_start = crate::sys::page_start(address, page_size);
                let expected_map_offset = target
                    .elf_header_offset()
                    .checked_add(segment.offset & !page_mask)
                    .ok_or(Error::ArithmeticOverflow)?;
                let exact_unaligned_mapping = map.start == address
                    && address != expected_start
                    && map.offset
                        == target
                            .elf_header_offset()
                            .checked_add(segment.offset)
                            .ok_or(Error::ArithmeticOverflow)?;
                if !((map.start == expected_start && map.offset == expected_map_offset)
                    || exact_unaligned_mapping)
                {
                    return Ok(false);
                }
            }
            let chunk_end = map
                .end
                .min(end)
                .min(if source_file { file_tail_end } else { end });
            let length = chunk_end
                .checked_sub(address)
                .ok_or(Error::ArithmeticOverflow)?;
            if length == 0 {
                return Ok(false);
            }
            address = chunk_end;
            expected_offset = expected_offset
                .checked_add(u64::try_from(length).map_err(|_| Error::ArithmeticOverflow)?)
                .ok_or(Error::ArithmeticOverflow)?;
        }
    }
    Ok(true)
}

fn load_page_is_executable(
    load_bias: usize,
    loads: &[ProgramHeader],
    address: usize,
    page_size: usize,
) -> Result<bool> {
    let page = crate::sys::page_start(address, page_size);
    let mut executable = None;
    for segment in loads.iter().filter(|segment| segment.memsz != 0) {
        let start = runtime_address(load_bias, segment.vaddr)?;
        let end = checked_add_u64(start, segment.memsz)?;
        let last = crate::sys::page_start(
            end.checked_sub(1).ok_or(Error::ArithmeticOverflow)?,
            page_size,
        );
        if crate::sys::page_start(start, page_size) <= page && page <= last {
            executable = Some(segment.flags & PF_X != 0);
        }
    }
    executable.ok_or(Error::InvalidElf("PT_LOAD page has no segment"))
}

pub(super) fn parse_header(
    memory: &Memory<'_>,
    address: usize,
    file_size: Option<u64>,
) -> Result<ElfHeader> {
    if file_size.is_some_and(|file_size| file_size < 16) {
        return Err(Error::InvalidElf(
            "ELF identification exceeds archive member",
        ));
    }
    let ident = memory.read_array::<16>(address)?;
    if &ident[..4] != ELF_MAGIC {
        return Err(Error::InvalidElf("bad ELF magic"));
    }
    let class = ElfClass::from_ident(ident[4])?;
    if file_size.is_some_and(|file_size| file_size < class.ehdr_size() as u64) {
        return Err(Error::InvalidElf("ELF header exceeds archive member"));
    }
    if ident[5] != ELFDATA2LSB {
        return Err(Error::UnsupportedEndian(ident[5]));
    }
    let machine = memory.read_u16(checked_add(address, 18)?)?;
    let (phoff, phentsize_offset, phnum_offset) = match class {
        ElfClass::Elf32 => (memory.read_u32(checked_add(address, 28)?)? as u64, 42, 44),
        ElfClass::Elf64 => (memory.read_u64(checked_add(address, 32)?)?, 54, 56),
    };
    let phentsize = memory.read_u16(checked_add(address, phentsize_offset)?)?;
    let phnum = memory.read_u16(checked_add(address, phnum_offset)?)?;
    if usize::from(phentsize) != class.phdr_size() || phnum == 0 {
        return Err(Error::InvalidElf("invalid program header table"));
    }
    if usize::from(phnum) > MAX_PROGRAM_HEADERS {
        return Err(Error::InvalidElf("too many program headers"));
    }
    Ok(ElfHeader {
        class,
        machine,
        phoff,
        phentsize,
        phnum,
    })
}

pub(super) fn parse_program_header(
    memory: &Memory<'_>,
    address: usize,
    class: ElfClass,
) -> Result<ProgramHeader> {
    let kind = memory.read_u32(address)?;
    let program = match class {
        ElfClass::Elf32 => ProgramHeader {
            kind,
            flags: memory.read_u32(checked_add(address, 24)?)?,
            offset: memory.read_u32(checked_add(address, 4)?)? as u64,
            vaddr: memory.read_u32(checked_add(address, 8)?)? as u64,
            filesz: memory.read_u32(checked_add(address, 16)?)? as u64,
            memsz: memory.read_u32(checked_add(address, 20)?)? as u64,
        },
        ElfClass::Elf64 => ProgramHeader {
            kind,
            flags: memory.read_u32(checked_add(address, 4)?)?,
            offset: memory.read_u64(checked_add(address, 8)?)?,
            vaddr: memory.read_u64(checked_add(address, 16)?)?,
            filesz: memory.read_u64(checked_add(address, 32)?)?,
            memsz: memory.read_u64(checked_add(address, 40)?)?,
        },
    };
    if kind == PT_LOAD && program.filesz > program.memsz {
        return Err(Error::InvalidElf("PT_LOAD filesz exceeds memsz"));
    }
    Ok(program)
}

pub(super) fn parse_dynamic(
    memory: &Memory<'_>,
    address: usize,
    size: usize,
    class: ElfClass,
) -> Result<DynamicInfo> {
    let entry_size = class.dyn_size();
    if size < entry_size || !size.is_multiple_of(entry_size) {
        return Err(Error::InvalidElf("invalid PT_DYNAMIC size"));
    }
    let entries = size / entry_size;
    let mut info = DynamicInfo::default();
    let mut terminated = false;
    for index in 0..entries.min(MAX_DYNAMIC_ENTRIES) {
        let entry = checked_add(
            address,
            index
                .checked_mul(entry_size)
                .ok_or(Error::ArithmeticOverflow)?,
        )?;
        let (tag, value) = match class {
            ElfClass::Elf32 => (
                memory.read_i32(entry)? as i64,
                memory.read_u32(entry + 4)? as u64,
            ),
            ElfClass::Elf64 => (memory.read_i64(entry)?, memory.read_u64(entry + 8)?),
        };
        if tag == DT_NULL {
            terminated = true;
            break;
        }
        match tag {
            DT_HASH => info.hash = Some(value),
            DT_STRTAB => info.strtab = Some(value),
            DT_STRSZ => info.strsz = Some(value),
            DT_SYMTAB => info.symtab = Some(value),
            DT_SYMENT => info.syment = Some(value),
            DT_SYMTABSZ => info.symtabsz = Some(value),
            DT_GNU_HASH => info.gnu_hash = Some(value),
            DT_REL => info.rel = Some(value),
            DT_RELSZ => info.relsz = Some(value),
            DT_RELENT => info.relent = Some(value),
            DT_RELA => info.rela = Some(value),
            DT_RELASZ => info.relasz = Some(value),
            DT_RELAENT => info.relaent = Some(value),
            DT_JMPREL => info.jmprel = Some(value),
            DT_PLTRELSZ => info.pltrelsz = Some(value),
            DT_PLTREL => info.pltrel = Some(value),
            DT_ANDROID_REL => info.android_rel = Some(value),
            DT_ANDROID_RELSZ => info.android_relsz = Some(value),
            DT_ANDROID_RELA => info.android_rela = Some(value),
            DT_ANDROID_RELASZ => info.android_relasz = Some(value),
            DT_VERSYM => {
                let duplicate = info.versym.replace(value).is_some();
                info.duplicate_versym |= duplicate;
                info.duplicate_version_tag |= duplicate;
            }
            DT_VERDEF => {
                info.duplicate_version_tag |= info.verdef.replace(value).is_some();
            }
            DT_VERDEFNUM => {
                info.duplicate_version_tag |= info.verdefnum.replace(value).is_some();
            }
            DT_VERNEED => {
                info.duplicate_version_tag |= info.verneed.replace(value).is_some();
            }
            DT_VERNEEDNUM => {
                info.duplicate_version_tag |= info.verneednum.replace(value).is_some();
            }
            DT_AARCH64_PAC_PLT => info.aarch64_pac_plt = true,
            _ => {}
        }
    }
    if !terminated {
        return Err(Error::InvalidElf(if entries > MAX_DYNAMIC_ENTRIES {
            "too many dynamic entries"
        } else {
            "unterminated PT_DYNAMIC"
        }));
    }
    Ok(info)
}

fn normalize_dynamic_pointers(
    memory: &Memory<'_>,
    load_bias: usize,
    load_ranges: &[(usize, usize)],
    info: &mut DynamicInfo,
) -> Result<()> {
    for value in [
        &mut info.hash,
        &mut info.strtab,
        &mut info.symtab,
        &mut info.gnu_hash,
        &mut info.rel,
        &mut info.rela,
        &mut info.jmprel,
        &mut info.android_rel,
        &mut info.android_rela,
    ]
    .into_iter()
    .flatten()
    {
        *value = resolve_dynamic_pointer(memory, load_bias, load_ranges, *value)?;
    }
    Ok(())
}

pub(super) fn resolve_dynamic_pointer(
    memory: &Memory<'_>,
    load_bias: usize,
    load_ranges: &[(usize, usize)],
    value: u64,
) -> Result<u64> {
    resolve_dynamic_pointer_with_policy(
        memory,
        load_bias,
        load_ranges,
        value,
        cfg!(target_os = "linux"),
    )
}

pub(super) fn resolve_dynamic_pointer_with_policy(
    memory: &Memory<'_>,
    load_bias: usize,
    load_ranges: &[(usize, usize)],
    value: u64,
    allow_absolute: bool,
) -> Result<u64> {
    let rebased = match runtime_address(load_bias, value) {
        Ok(rebased) => Some(rebased),
        Err(error) if !allow_absolute => return Err(error),
        Err(Error::ArithmeticOverflow) => None,
        Err(error) => return Err(error),
    };
    let valid_rebased = rebased.filter(|rebased| {
        address_in_ranges(*rebased, load_ranges) && memory.is_readable(*rebased, 1)
    });
    let valid_absolute = allow_absolute
        .then(|| usize::try_from(value).ok())
        .flatten()
        .filter(|raw| address_in_ranges(*raw, load_ranges) && memory.is_readable(*raw, 1));
    match (valid_rebased, valid_absolute) {
        (Some(rebased), Some(raw)) if rebased != raw => {
            return Err(Error::UnsupportedFeature(
                "ambiguous Linux dynamic pointer encoding",
            ));
        }
        (Some(rebased), _) => {
            return u64::try_from(rebased).map_err(|_| Error::ArithmeticOverflow);
        }
        (None, Some(_)) => return Ok(value),
        (None, None) => {}
    }
    match rebased {
        Some(rebased) => Err(Error::UnmappedRead {
            address: rebased,
            length: 1,
        }),
        None => Err(Error::ArithmeticOverflow),
    }
}

pub(super) fn address_in_ranges(address: usize, ranges: &[(usize, usize)]) -> bool {
    ranges
        .iter()
        .any(|(start, end)| *start <= address && address < *end)
}

pub(crate) fn range_in_ranges(address: usize, length: usize, ranges: &[(usize, usize)]) -> bool {
    address.checked_add(length).is_some_and(|end| {
        ranges
            .iter()
            .any(|(start, limit)| *start <= address && end <= *limit)
    })
}
use super::*;

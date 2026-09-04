pub(super) fn parse_image(
    header_memory: &Memory<'_>,
    maps: &[MapInfo],
    header_address: usize,
    loader_base: usize,
    selector: &ElfImageSelector,
) -> Result<Option<(Image, Vec<MapInfo>)>> {
    let headers = parse_image_headers(header_memory, header_address, selector)?;
    parse_image_with_headers(headers, maps, header_address, loader_base, selector)
}

pub(super) struct ParsedImageHeaders {
    pub(super) header: ElfHeader,
    pub(super) loads: Vec<ProgramHeader>,
    pub(super) load_bias: usize,
    dynamic: Option<ProgramHeader>,
    notes: Vec<ProgramHeader>,
}

pub(super) fn parse_image_headers(
    header_memory: &Memory<'_>,
    header_address: usize,
    selector: &ElfImageSelector,
) -> Result<ParsedImageHeaders> {
    let header = parse_header(
        header_memory,
        header_address,
        selector.archive_member_size(),
    )?;
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
    if let Some(file_size) = selector.archive_member_size() {
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
                if let Some(file_size) = selector.archive_member_size() {
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
    Ok(ParsedImageHeaders {
        header,
        loads,
        load_bias,
        dynamic,
        notes,
    })
}

pub(super) fn parse_image_with_headers(
    headers: ParsedImageHeaders,
    maps: &[MapInfo],
    header_address: usize,
    loader_base: usize,
    selector: &ElfImageSelector,
) -> Result<Option<(Image, Vec<MapInfo>)>> {
    let ParsedImageHeaders {
        header,
        loads,
        load_bias,
        dynamic,
        notes,
    } = headers;
    if !load_mappings_are_loader_shaped(load_bias, loader_base, &loads, maps, selector)? {
        return Ok(None);
    }
    let dynamic = dynamic.ok_or(Error::InvalidElf("missing PT_DYNAMIC"))?;
    let dynamic_address = runtime_address(load_bias, dynamic.vaddr)?;
    let dynamic_size = usize::try_from(dynamic.memsz).map_err(|_| Error::ArithmeticOverflow)?;
    // An archive member's metadata must stay inside the declared member: the
    // vaddr-to-offset skew means a member boundary cannot be applied in the
    // address domain. Split each PT_LOAD at its own file end instead: the
    // file part is already member-bounded, and only a loader-owned anonymous
    // memory tail may follow it.
    let load_ranges = if selector.archive_member_size().is_some() {
        let mut bounded = Vec::with_capacity(loads.len() * 2);
        for segment in &loads {
            let start = runtime_address(load_bias, segment.vaddr)?;
            let length = usize::try_from(segment.memsz).map_err(|_| Error::ArithmeticOverflow)?;
            let end = checked_add(start, length)?;
            let filesz = usize::try_from(segment.filesz).map_err(|_| Error::ArithmeticOverflow)?;
            let file_end = checked_add(start, filesz)?;
            if file_end > end {
                return Err(Error::ArithmeticOverflow);
            }
            if file_end > start {
                bounded.push((start, file_end));
            }
            if file_end < end
                && find_map_containing(maps, file_end, end - file_end).is_some_and(|map| {
                    map.is_private && map.device == crate::DeviceId::new(0, 0) && map.inode == 0
                })
            {
                bounded.push((file_end, end));
            }
        }
        bounded
    } else {
        let mut load_ranges = Vec::with_capacity(loads.len());
        for segment in &loads {
            let start = runtime_address(load_bias, segment.vaddr)?;
            let length = usize::try_from(segment.memsz).map_err(|_| Error::ArithmeticOverflow)?;
            let end = checked_add(start, length)?;
            load_ranges.push((start, end));
        }
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
            id: ImageMappingKey {
                device: selector.device(),
                inode: selector.inode(),
                header: header_address,
                load_bias,
                elf_header_offset: selector.elf_header_offset(),
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
    selector: &ElfImageSelector,
) -> Result<bool> {
    let bound_image = selector.bound_image();
    let page_size = crate::sys::page_size()?;
    for segment in loads.iter().filter(|segment| segment.memsz != 0) {
        let executable = segment.flags & PF_X != 0;
        let segment_start = runtime_address(load_bias, segment.vaddr)?;
        let segment_end = checked_add_u64(segment_start, segment.memsz)?;
        // Android's loader maps BOLT and 16K-aligned segments at their own
        // p_align boundaries, so pages at the segment head can fall into a
        // loader gap while the first real mapping starts later in the same
        // segment. Validation starts from that first mapped page instead.
        let mut address = match maps.iter().find(|map| {
            map.start >= crate::sys::page_start(segment_start, page_size)
                && map.start < segment_end
                && ((map.is_private
                    && map.device == selector.device()
                    && map.inode == selector.inode())
                    || (map.device == crate::DeviceId::new(0, 0) && map.inode == 0))
        }) {
            Some(map) if map.start > segment_start => map.start,
            _ => segment_start,
        };
        if address > segment_start
            && maps
                .iter()
                .any(|candidate| candidate.start < address && candidate.end > segment_start)
        {
            return Ok(false);
        }
        let raw_file_end = checked_add_u64(segment_start, segment.filesz)?;
        let end = segment_end;
        let segment_file_start = selector
            .elf_header_offset()
            .checked_add(segment.offset)
            .ok_or(Error::ArithmeticOverflow)?;
        let file_tail_end = raw_file_end
            .checked_add(page_size - 1)
            .map(|address| crate::sys::page_start(address, page_size))
            .ok_or(Error::ArithmeticOverflow)?
            .min(end);
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
            // BOLT libraries split one PT_LOAD across several file mappings
            // whose offsets need not stay linear or inside the segment's
            // declared file range; identity and permissions carry the check.
            let source_file = address < file_tail_end
                && map.is_private
                && map.device == selector.device()
                && map.inode == selector.inode();
            let anonymous =
                map.is_private && map.device == crate::DeviceId::new(0, 0) && map.inode == 0;
            let follows_source_file = (address == raw_file_end || address == file_tail_end)
                && address
                    .checked_sub(1)
                    .and_then(|previous| find_map_containing(maps, previous, 1))
                    .is_some_and(|previous| {
                        previous.is_private
                            && previous.device == selector.device()
                            && previous.inode == selector.inode()
                    });
            let loader_owned_anonymous = anonymous
                && (bound_image.is_some() || address >= raw_file_end)
                && if previous_anonymous_map == Some(map.start) {
                    true
                } else {
                    previous_anonymous_map = Some(map.start);
                    follows_source_file || loader_image_base(address) == Some(loader_base)
                };
            if !source_file && !loader_owned_anonymous {
                return Ok(false);
            }
            if bound_image.is_none() && executable && address == segment_start {
                let expected_start = crate::sys::page_start(address, page_size);
                let exact_unaligned_mapping = map.start == address
                    && address != expected_start
                    && map.offset == segment_file_start;
                let expected_map_offset = u64::try_from(crate::sys::page_start(
                    usize::try_from(segment_file_start).map_err(|_| Error::ArithmeticOverflow)?,
                    page_size,
                ))
                .map_err(|_| Error::ArithmeticOverflow)?;
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
    let (phoff, phentsize_offset) = match class {
        ElfClass::Elf32 => (memory.read_u32(checked_add(address, 28)?)? as u64, 42),
        ElfClass::Elf64 => (memory.read_u64(checked_add(address, 32)?)?, 54),
    };
    let counts = memory.read_array::<4>(checked_add(address, phentsize_offset)?)?;
    let phentsize = u16::from_le_bytes([counts[0], counts[1]]);
    let phnum = u16::from_le_bytes([counts[2], counts[3]]);
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
    // Batch adjacent fields without reading the unused p_paddr or p_align.
    let program = match class {
        ElfClass::Elf32 => {
            let prefix = memory.read_array::<12>(address)?;
            let suffix = memory.read_array::<12>(checked_add(address, 16)?)?;
            let prefix = prefix.as_chunks::<4>().0;
            let suffix = suffix.as_chunks::<4>().0;
            ProgramHeader {
                kind: u32::from_le_bytes(prefix[0]),
                flags: u32::from_le_bytes(suffix[2]),
                offset: u32::from_le_bytes(prefix[1]) as u64,
                vaddr: u32::from_le_bytes(prefix[2]) as u64,
                filesz: u32::from_le_bytes(suffix[0]) as u64,
                memsz: u32::from_le_bytes(suffix[1]) as u64,
            }
        }
        ElfClass::Elf64 => {
            let prefix = memory.read_array::<24>(address)?;
            let sizes = memory.read_array::<16>(checked_add(address, 32)?)?;
            let words = prefix.as_chunks::<8>().0;
            let sizes = sizes.as_chunks::<8>().0;
            ProgramHeader {
                kind: u32::from_le_bytes(prefix.as_chunks::<4>().0[0]),
                flags: u32::from_le_bytes(prefix.as_chunks::<4>().0[1]),
                offset: u64::from_le_bytes(words[1]),
                vaddr: u64::from_le_bytes(words[2]),
                filesz: u64::from_le_bytes(sizes[0]),
                memsz: u64::from_le_bytes(sizes[1]),
            }
        }
    };
    if program.kind == PT_LOAD && program.filesz > program.memsz {
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
    let mut apply_entry = |tag: i64, value: u64| -> bool {
        if tag == DT_NULL {
            return true;
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
            DT_RELCOUNT => info.relcount = Some(value),
            DT_RELA => info.rela = Some(value),
            DT_RELASZ => info.relasz = Some(value),
            DT_RELAENT => info.relaent = Some(value),
            DT_RELACOUNT => info.relacount = Some(value),
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
        false
    };
    if memory.is_fully_readable(address, size) {
        // SAFETY: the complete table was just checked readable and Memory's
        // caller contract keeps it live and stable for this read.
        let bytes =
            unsafe { std::slice::from_raw_parts(std::ptr::with_exposed_provenance(address), size) };
        for entry in bytes.chunks_exact(entry_size).take(MAX_DYNAMIC_ENTRIES) {
            let (tag, value) = match class {
                ElfClass::Elf32 => (
                    i32::from_le_bytes(
                        entry[0..4]
                            .try_into()
                            .unwrap_or_else(|_| crate::sys::fail_stop()),
                    ) as i64,
                    u32::from_le_bytes(
                        entry[4..8]
                            .try_into()
                            .unwrap_or_else(|_| crate::sys::fail_stop()),
                    ) as u64,
                ),
                ElfClass::Elf64 => (
                    i64::from_le_bytes(
                        entry[0..8]
                            .try_into()
                            .unwrap_or_else(|_| crate::sys::fail_stop()),
                    ),
                    u64::from_le_bytes(
                        entry[8..16]
                            .try_into()
                            .unwrap_or_else(|_| crate::sys::fail_stop()),
                    ),
                ),
            };
            terminated = apply_entry(tag, value);
            if terminated {
                break;
            }
        }
    } else {
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
            terminated = apply_entry(tag, value);
            if terminated {
                break;
            }
        }
    }
    if terminated {
        return Ok(info);
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

pub(super) fn normalize_dynamic_pointers(
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
    if allow_absolute
        && load_bias != 0
        && load_ranges.iter().all(|range| range.0 >= load_bias)
        && let Ok(raw) = usize::try_from(value)
        && raw < load_bias
    {
        // PIE link-time pointers are below the loader base, so the absolute
        // interpretation cannot overlap this image's PT_LOAD ranges.
        let rebased = load_bias
            .checked_add(raw)
            .ok_or(Error::ArithmeticOverflow)?;
        if address_in_ranges(rebased, load_ranges) && memory.is_readable(rebased, 1) {
            return u64::try_from(rebased).map_err(|_| Error::ArithmeticOverflow);
        }
        return Err(Error::UnmappedRead {
            address: rebased,
            length: 1,
        });
    }
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

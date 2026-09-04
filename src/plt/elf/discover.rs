#[cfg(not(target_pointer_width = "64"))]
pub(crate) unsafe fn bound_image_discovery(
    selector: &ElfImageSelector,
) -> Result<(DiscoveredImage, Vec<MapInfo>)> {
    let _ = selector;
    Err(Error::UnsupportedFeature(
        "bound image discovery requires a 64-bit selector",
    ))
}

pub(crate) unsafe fn find_loaded_images(
    selector: &ElfImageSelector,
    maps: &[MapInfo],
) -> Result<Vec<FoundImage>> {
    // SAFETY: forwarded from this function's mapping-stability contract.
    let discovered = unsafe { discover_images(selector, maps)? };
    let mut images = Vec::with_capacity(discovered.len());
    for discovered in discovered {
        // SAFETY: maps are clipped to the exact live PT_LOAD ranges and the
        // caller keeps them stable for this read-only operation.
        let memory = unsafe { Memory::new(&discovered.maps) };
        images.push(FoundImage {
            id: discovered.image.id,
            load_ranges: discovered.image.load_ranges.clone(),
            build_id: discovered.image.gnu_build_id(&memory)?,
        });
    }
    Ok(images)
}

pub(super) unsafe fn discover_images(
    selector: &ElfImageSelector,
    maps: &[MapInfo],
) -> Result<Vec<DiscoveredImage>> {
    let bound_image = selector.bound_image();
    if let Some(bound) = bound_image {
        if find_map_containing(maps, bound.header, ELF_MAGIC.len()).is_none() {
            return Ok(Vec::new());
        }
        // SAFETY: the caller guarantees that this exact mapping remains stable
        // for the complete scan.
        let memory = unsafe { Memory::new(maps) };
        if !has_elf_magic(&memory, bound.header)? {
            return Ok(Vec::new());
        }
        if loader_image_base(bound.header) != Some(bound.loader_base) {
            return Ok(Vec::new());
        }
        let Some((image, image_maps)) =
            parse_image(&memory, maps, bound.header, bound.loader_base, selector)?
        else {
            return Ok(Vec::new());
        };
        let image_start = crate::sys::page_start(
            image
                .load_ranges
                .first()
                .ok_or(Error::InvalidElf("empty PT_LOAD range"))?
                .0,
            crate::sys::page_size()?,
        );
        if bound.loader_base != image_start {
            return Ok(Vec::new());
        }
        return Ok(vec![DiscoveredImage {
            image,
            maps: image_maps,
        }]);
    }
    let target_maps = maps
        .iter()
        .filter(|map| {
            map.perms.contains(MapPerms::READ)
                && bound_image.map_or_else(
                    || map.device == selector.device() && map.inode == selector.inode(),
                    |_| map.is_private,
                )
        })
        .cloned()
        .collect::<Vec<_>>();
    // SAFETY: the caller guarantees that every matching selector mapping remains
    // stable for the complete scan.
    let memory = unsafe { Memory::new(&target_maps) };
    let mut images = BTreeMap::<ImageMappingKey, DiscoveredImage>::new();

    let header_addresses = if let Some(bound) = bound_image {
        find_map_containing(&target_maps, bound.header, ELF_MAGIC.len())
            .map(|_| vec![bound.header])
            .unwrap_or_default()
    } else {
        target_maps
            .iter()
            .filter(|map| map.offset == selector.elf_header_offset())
            .map(|map| map.start)
            .collect()
    };
    for header_address in header_addresses {
        if selector
            .archive_member_size()
            .is_some_and(|member_size| member_size < 4)
        {
            return Err(Error::InvalidElf("ELF magic exceeds archive member"));
        }
        if !has_elf_magic(&memory, header_address)? {
            continue;
        }
        let loader_base = match bound_image {
            Some(bound) => {
                if loader_image_base(header_address) != Some(bound.loader_base) {
                    continue;
                }
                bound.loader_base
            }
            None => {
                let Some(loader_base) = loader_image_base(header_address) else {
                    continue;
                };
                loader_base
            }
        };
        let Some((image, image_maps)) =
            parse_image(&memory, maps, header_address, loader_base, selector)?
        else {
            continue;
        };
        let image_start = crate::sys::page_start(
            image
                .load_ranges
                .first()
                .ok_or(Error::InvalidElf("empty PT_LOAD range"))?
                .0,
            crate::sys::page_size()?,
        );
        if loader_base != image_start {
            continue;
        }
        if let Some(previous) = images.get(&image.id) {
            if previous.image.load_ranges != image.load_ranges {
                return Err(Error::InvalidElf("conflicting ranges for one image"));
            }
            continue;
        }
        images.insert(
            image.id,
            DiscoveredImage {
                image,
                maps: image_maps,
            },
        );
    }
    Ok(images.into_values().collect())
}

// Both inputs are ordered; ranges have already been merged.
pub(super) fn maps_in_ranges(maps: &[MapInfo], ranges: &[(usize, usize)]) -> Vec<MapInfo> {
    let mut clipped = Vec::with_capacity(maps.len());
    let mut first_map = 0;
    for &(start, end) in ranges {
        while maps.get(first_map).is_some_and(|map| map.end <= start) {
            first_map += 1;
        }
        for map in &maps[first_map..] {
            if map.start >= end {
                break;
            }
            if !map.perms.contains(MapPerms::READ) {
                continue;
            }
            let intersection_start = map.start.max(start);
            let intersection_end = map.end.min(end);
            if intersection_start < intersection_end {
                let mut intersection = map.clone();
                intersection.start = intersection_start;
                intersection.end = intersection_end;
                clipped.push(intersection);
            }
        }
    }
    clipped
}

pub(super) fn merge_ranges(mut ranges: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    ranges.retain(|(start, end)| start < end);
    ranges.sort_unstable();
    ranges.dedup_by(|current, previous| {
        if current.0 <= previous.1 {
            previous.1 = previous.1.max(current.1);
            true
        } else {
            false
        }
    });
    ranges
}

pub(super) fn has_elf_magic(memory: &Memory<'_>, address: usize) -> Result<bool> {
    Ok(&memory.read_array::<4>(address)? == ELF_MAGIC)
}

#[cfg(target_pointer_width = "64")]
pub(crate) unsafe fn bound_image_discovery(
    selector: &ElfImageSelector,
) -> Result<(DiscoveredImage, Vec<MapInfo>)> {
    let bound = selector
        .bound_image()
        .ok_or(Error::UnsupportedFeature("selector is not bound"))?;
    let base = loader_image_base(bound.header)
        .ok_or(Error::UnsupportedFeature("bound ELF is not loaded"))?;
    if base != bound.loader_base || selector.archive_member_size().is_some() {
        return Err(Error::MappingChanged);
    }
    let mut parsed_headers = None;
    let maps = crate::maps::read_self_maps_for_image(bound.header, |first| {
        // SAFETY: only this real, live VMA is exposed to the bootstrap parser.
        let memory = unsafe { Memory::new(std::slice::from_ref(first)) };
        let headers = super::parse::parse_image_headers(&memory, bound.header, selector)?;
        let header = headers.header;
        let phdr = checked_add_u64(bound.header, header.phoff)?;
        let phdr_size = usize::from(header.phentsize)
            .checked_mul(usize::from(header.phnum))
            .ok_or(Error::ArithmeticOverflow)?;
        // Unusual layouts use the complete scanner, without speculative reads.
        if !memory.is_readable(phdr, phdr_size) {
            return Err(Error::UnmappedRead {
                address: phdr,
                length: phdr_size,
            });
        }
        let mut low_vaddr = u64::MAX;
        let mut high_vaddr = 0;
        for program in &headers.loads {
            low_vaddr = low_vaddr.min(program.vaddr);
            high_vaddr = high_vaddr.max(
                program
                    .vaddr
                    .checked_add(program.memsz)
                    .ok_or(Error::ArithmeticOverflow)?,
            );
        }
        let load_bias = headers.load_bias;
        if runtime_address(load_bias, low_vaddr)? < first.start {
            return Err(Error::UnsupportedFeature("PT_LOAD precedes header mapping"));
        }
        let end = checked_add(phdr, phdr_size)?.max(runtime_address(load_bias, high_vaddr)?);
        parsed_headers = Some(headers);
        Ok(end)
    })?;
    let headers = parsed_headers.ok_or(Error::UnmappedRead {
        address: bound.header,
        length: 1,
    })?;
    let (image, image_maps) =
        super::parse::parse_image_with_headers(headers, &maps, bound.header, base, selector)?
            .ok_or(Error::MappingChanged)?;
    let image_start = crate::sys::page_start(
        image
            .load_ranges
            .first()
            .ok_or(Error::InvalidElf("empty PT_LOAD range"))?
            .0,
        crate::sys::page_size()?,
    );
    if image_start != base {
        return Err(Error::MappingChanged);
    }
    Ok((
        DiscoveredImage {
            image,
            maps: image_maps,
        },
        maps,
    ))
}
use super::*;

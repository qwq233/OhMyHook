pub(crate) unsafe fn find_loaded_images(
    target: &Target,
    maps: &[MapInfo],
) -> Result<Vec<FoundImage>> {
    // SAFETY: forwarded from this function's mapping-stability contract.
    let discovered = unsafe { discover_images(target, maps)? };
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
    target: &Target,
    maps: &[MapInfo],
) -> Result<Vec<DiscoveredImage>> {
    let bound_image = target.bound_image();
    let target_maps = maps
        .iter()
        .filter(|map| {
            map.perms.contains(MapPerms::READ)
                && bound_image.map_or_else(
                    || map.device == target.device() && map.inode == target.inode(),
                    |_| map.is_private,
                )
        })
        .cloned()
        .collect::<Vec<_>>();
    // SAFETY: the caller guarantees that every matching target mapping remains
    // stable for the complete scan.
    let memory = unsafe { Memory::new(&target_maps) };
    let mut images = BTreeMap::<ImageId, DiscoveredImage>::new();

    let header_addresses = if let Some(bound) = bound_image {
        find_map_containing(&target_maps, bound.header, ELF_MAGIC.len())
            .map(|_| vec![bound.header])
            .unwrap_or_default()
    } else {
        target_maps
            .iter()
            .filter(|map| map.offset == target.elf_header_offset())
            .map(|map| map.start)
            .collect()
    };
    for header_address in header_addresses {
        if target
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
            parse_image(&memory, maps, header_address, loader_base, target)?
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

pub(super) fn maps_in_ranges(maps: &[MapInfo], ranges: &[(usize, usize)]) -> Vec<MapInfo> {
    let mut clipped = Vec::new();
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
    clipped.sort_unstable_by_key(|map| (map.start, map.end));
    clipped
}

pub(super) fn merge_ranges(mut ranges: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    ranges.retain(|(start, end)| start < end);
    ranges.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        if let Some((_, previous_end)) = merged.last_mut()
            && start <= *previous_end
        {
            *previous_end = (*previous_end).max(end);
            continue;
        }
        merged.push((start, end));
    }
    merged
}

pub(super) fn has_elf_magic(memory: &Memory<'_>, address: usize) -> Result<bool> {
    Ok(&memory.read_array::<4>(address)? == ELF_MAGIC)
}
use super::*;

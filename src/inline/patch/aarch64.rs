use super::{CodePage, PageFlags};
use crate::maps::{
    MapInfo, MapPerms, MappingSnapshot, extend_self_smaps_for_ranges, find_map_containing,
};
use crate::{Error, Result};

const PROT_BTI: i32 = 0x10;
const PROT_MTE: i32 = 0x20;

pub(super) fn capture_flags(
    pages: &mut [CodePage],
    maps: &[MapInfo],
    page_flags: &PageFlags,
    replacement: usize,
) -> Result<bool> {
    let Some(smaps) = page_flags else {
        return Ok(replacement_has_bti_hint(maps, replacement));
    };
    if smaps.is_empty() {
        // An empty snapshot proves nothing about guard state: adding
        // PROT_BTI could turn an ordinary landing into SIGILL, so every page
        // stays unguarded until a snapshot actually reports the bit.
        return Ok(replacement_has_bti_hint(maps, replacement));
    }
    for page in &mut *pages {
        let entry = smaps
            .iter()
            .find(|entry| entry.map.contains_range(page.start, page.length))
            .filter(|entry| page.mapping.matches(&entry.map));
        if let Some(entry) = entry {
            if entry.vm_flags.bti {
                page.original_protection |= PROT_BTI;
            }
            if entry.vm_flags.mte {
                page.original_protection |= PROT_MTE;
            }
        }
    }
    let map = find_map_containing(maps, replacement, 4)
        .filter(|map| map.perms.contains(MapPerms::EXEC))
        .ok_or(Error::MappingChanged)?;
    let identity = MappingSnapshot::from_map(map);
    Ok(smaps
        .iter()
        .find(|entry| entry.map.contains_range(replacement, 4) && identity.matches(&entry.map))
        .map(|entry| entry.vm_flags.bti)
        .unwrap_or_else(|| replacement_has_bti_hint(maps, replacement)))
}

pub(super) fn apply_protection_flags(
    pages: &mut [impl AsMut<[CodePage]>],
    snapshot: Option<&[crate::maps::SmapInfo]>,
) -> Result<()> {
    let features = crate::sys::aarch64_memory_protection_features();
    if !features.bti && !features.mte {
        return Ok(());
    }
    let mut ranges = Vec::new();
    for page in pages.iter_mut().flat_map(|group| group.as_mut().iter_mut()) {
        ranges.push((
            page.start,
            page.start
                .checked_add(page.length)
                .ok_or(Error::ArithmeticOverflow)?,
        ));
    }
    ranges.sort_unstable();
    ranges.dedup();
    let mut smaps = Vec::new();
    let mut missing = Vec::new();
    for &(start, end) in &ranges {
        let covered = snapshot.is_some_and(|snapshot| {
            snapshot
                .iter()
                .any(|entry| entry.map.start <= start && end <= entry.map.end)
        });
        if !covered {
            missing.push((start, end));
        }
    }
    if let Some(snapshot) = snapshot {
        let covered: Vec<_> = snapshot
            .iter()
            .filter(|entry| {
                ranges
                    .iter()
                    .any(|&(start, end)| entry.map.start <= start && end <= entry.map.end)
            })
            .cloned()
            .collect();
        smaps.extend(covered);
    }
    if !missing.is_empty() {
        extend_self_smaps_for_ranges(&mut smaps, &missing)?;
    }
    for page in pages.iter_mut().flat_map(|group| group.as_mut().iter_mut()) {
        let Some(entry) = smaps
            .iter()
            .find(|entry| entry.map.contains_range(page.start, page.length))
            .filter(|entry| {
                page.mapping
                    .matches_at_ignoring_write(&entry.map, page.start)
            })
        else {
            return Err(Error::MappingChanged);
        };
        page.original_protection &= !(PROT_BTI | PROT_MTE);
        if entry.vm_flags.bti {
            page.original_protection |= PROT_BTI;
        }
        if entry.vm_flags.mte {
            page.original_protection |= PROT_MTE;
        }
    }
    Ok(())
}

fn replacement_has_bti_hint(maps: &[MapInfo], replacement: usize) -> bool {
    if super::validate_executable_entry(maps, replacement, 4).is_err() {
        // Indirect relays still query the live VMA's guard state before use.
        return false;
    }
    // SAFETY: validation covers one readable instruction and the installer
    // contract keeps this mapping and its contents stable.
    let instruction = unsafe {
        u32::from_le(std::ptr::read_unaligned(std::ptr::with_exposed_provenance(
            replacement,
        )))
    };
    matches!(
        instruction,
        0xd503_241f | 0xd503_245f | 0xd503_249f | 0xd503_24df
    )
}

pub(super) const fn arena_protection(_: &[CodePage]) -> i32 {
    libc::PROT_READ | libc::PROT_EXEC
}

pub(super) fn is_guarded(pages: &[CodePage]) -> bool {
    pages
        .iter()
        .any(|page| page.original_protection & PROT_BTI != 0)
}

pub(super) fn writable_protection(page: &CodePage) -> i32 {
    libc::PROT_READ | libc::PROT_WRITE | (page.original_protection & PROT_MTE)
}

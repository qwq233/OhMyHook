use super::{CodePage, PageFlags, executable_code_map};
use crate::maps::{MapInfo, MappingIdentity, find_map_containing, read_self_smaps_for_ranges};
use crate::{Error, Result};

const PROT_BTI: i32 = 0x10;
const PROT_MTE: i32 = 0x20;

pub(super) fn read_flags(ranges: &[(usize, usize)]) -> Result<PageFlags> {
    if !crate::sys::aarch64_bti_supported() {
        return Ok(None);
    }
    read_self_smaps_for_ranges(ranges).map(Some)
}

pub(super) fn capture_flags(
    pages: &mut [CodePage],
    maps: &[MapInfo],
    page_flags: &PageFlags,
    replacement: usize,
) -> Result<bool> {
    let Some(smaps) = page_flags else {
        return Ok(false);
    };
    for page in &mut *pages {
        let entry = smaps
            .iter()
            .find(|entry| entry.map.contains_range(page.start, page.length))
            .filter(|entry| page.mapping.matches(&entry.map))
            .ok_or(Error::MappingChanged)?;
        if entry.vm_flags.bti {
            page.original_protection |= PROT_BTI;
        }
        if entry.vm_flags.mte {
            page.original_protection |= PROT_MTE;
        }
    }
    let map = find_map_containing(maps, replacement, 1)
        .filter(|map| executable_code_map(map))
        .ok_or(Error::MappingChanged)?;
    let identity = MappingIdentity::from_map(map);
    smaps
        .iter()
        .find(|entry| entry.map.contains(replacement) && identity.matches(&entry.map))
        .map(|entry| entry.vm_flags.bti)
        .ok_or(Error::MappingChanged)
}

pub(super) fn arena_protection(pages: &[CodePage]) -> i32 {
    libc::PROT_READ | libc::PROT_EXEC | if is_guarded(pages) { PROT_BTI } else { 0 }
}

pub(super) fn is_guarded(pages: &[CodePage]) -> bool {
    pages
        .iter()
        .any(|page| page.original_protection & PROT_BTI != 0)
}

pub(super) fn writable_protection(page: &CodePage) -> i32 {
    libc::PROT_READ | libc::PROT_WRITE | (page.original_protection & PROT_MTE)
}

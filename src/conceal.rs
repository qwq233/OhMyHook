//! Private-file-page validation for file-backed targets.
//!
//! PrivateFileValidation is a validation contract, not a page swap: a selected page
//! must be a readable private file mapping, and every write channel this
//! crate uses (`/proc/self/mem` forced writes and the mprotect elevation
//! window) copy-on-writes such a page, so the backing file page is never
//! written and the mapping keeps its file identity and path. Successful
//! restoration preserves RWX access. AArch64 PLT mutation with BTI but without
//! MTE can retain an added BTI bit and changed VMA boundaries after removal.
//! The page that reaches instruction fetch after an install is the
//! process's own private copy, which is also what the kernel produces for
//! any ordinary relocation write.
//!
//! Engines that request PrivateFileValidation fail closed when a selected page is not
//! a private-file mapping instead of silently degrading to a shared write.

use crate::maps::{DeviceId, MapInfo, MapPerms, MappingSnapshot, SmapInfo};
use crate::{Error, Result};

/// Whether an installed hook proved its target pages satisfy the private-file
/// mapping contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrivateFileValidation {
    /// Every selected file-backed target page is a private mapping whose
    /// contents stay a private copy: no write reaches the backing file.
    Validated,
    /// The selected pages were not checked against the private-file mapping
    /// contract.
    Unvalidated,
}

/// One engine's selection of pages to validate.
pub(crate) struct PageSelection<'a> {
    /// Input `(address, containing map)` pairs; the address is page-aligned.
    pub(crate) pages: &'a [(usize, MapInfo)],
    /// Targeted `smaps` entries for the selected pages.
    pub(crate) smaps: &'a [SmapInfo],
    /// Runtime page size.
    pub(crate) page_size: usize,
    /// Reject executable pages instead of validating them (PLT/GOT rule).
    pub(crate) reject_executable: bool,
}

/// Validates every selected page and returns the page starts that can carry
/// a Validated mutation, deduplicated, in input order.
///
/// The caller holds `PROCESS_LOCK` for writing and verified the selected
/// mappings against a fresh snapshot.
pub(crate) fn validate_selection(selection: &PageSelection<'_>) -> Result<Vec<usize>> {
    let mut validated = Vec::with_capacity(selection.pages.len());
    for (page, map) in selection.pages {
        if selection.reject_executable && map.perms.contains(MapPerms::EXEC) {
            return Err(Error::UnsupportedFeature("executable relocation page"));
        }
        if !map.is_private || map.inode == 0 || map.device == DeviceId::new(0, 0) {
            return Err(Error::UnsupportedFeature(
                "page is not a private-file mapping",
            ));
        }
        if !map.perms.contains(MapPerms::READ) {
            return Err(Error::UnsupportedFeature("page is not readable"));
        }
        let identity = MappingSnapshot::from_map(map);
        let smap = selection
            .smaps
            .iter()
            .find(|entry| entry.map.contains_range(*page, selection.page_size))
            .filter(|entry| identity.matches(&entry.map))
            .ok_or(Error::UnsupportedFeature(
                "page has no matching smaps entry",
            ))?;
        let flags = smap.vm_flags;
        if flags.mixed_map
            || flags.io_map
            || flags.sync
            || flags.hugepage
            || flags.dont_fork
            || flags.wipe_on_fork
            || flags.lock_on_fault
            || flags.unknown
            || smap.protection_key != 0
        {
            return Err(Error::UnsupportedFeature(
                "page has special mapping semantics",
            ));
        }
        if !validated.contains(page) {
            validated.push(*page);
        }
    }
    Ok(validated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maps::SmapVmFlags;

    fn page_map(perms: MapPerms, is_private: bool, inode: u64, device: DeviceId) -> MapInfo {
        MapInfo {
            start: 0x1000,
            end: 0x2000,
            perms,
            is_private,
            offset: 0,
            device,
            inode,
            path: None,
        }
    }

    fn page_smap(map: &MapInfo) -> SmapInfo {
        SmapInfo {
            map: map.clone(),
            vm_flags: Default::default(),
            protection_key: 0,
        }
    }

    #[test]
    fn selection_rejects_pages_that_cannot_be_private_file_validated() {
        let device = DeviceId::new(8, 2);
        let file = page_map(MapPerms::READ | MapPerms::WRITE, true, 42, device);
        for (map, reject_executable, expected) in [
            (
                page_map(MapPerms::READ | MapPerms::WRITE, false, 42, device),
                false,
                "page is not a private-file mapping",
            ),
            (
                page_map(MapPerms::READ | MapPerms::WRITE, true, 0, device),
                false,
                "page is not a private-file mapping",
            ),
            (
                page_map(
                    MapPerms::READ | MapPerms::WRITE,
                    true,
                    42,
                    DeviceId::new(0, 0),
                ),
                false,
                "page is not a private-file mapping",
            ),
            (
                page_map(MapPerms::WRITE, true, 42, device),
                false,
                "page is not readable",
            ),
            (
                page_map(MapPerms::READ | MapPerms::EXEC, true, 42, device),
                true,
                "executable relocation page",
            ),
        ] {
            let pages = [(0x1000, map.clone())];
            let smaps = [page_smap(&map)];
            let selection = PageSelection {
                pages: &pages,
                smaps: &smaps,
                page_size: 0x1000,
                reject_executable,
            };
            assert!(
                matches!(
                    validate_selection(&selection),
                    Err(Error::UnsupportedFeature(reason)) if reason == expected
                ),
                "unexpected selection result for {expected}"
            );
        }

        let pages = [(0x1000, file.clone())];
        for (locked, dont_dump) in [(false, false), (true, false), (false, true), (true, true)] {
            let mut smap = page_smap(&file);
            smap.vm_flags.locked = locked;
            smap.vm_flags.dont_dump = dont_dump;
            let selection = PageSelection {
                pages: &pages,
                smaps: &[smap],
                page_size: 0x1000,
                reject_executable: true,
            };
            assert_eq!(validate_selection(&selection).unwrap(), vec![0x1000]);
        }
    }

    #[test]
    fn selection_rejects_special_smaps_semantics() {
        let device = DeviceId::new(8, 2);
        let map = page_map(MapPerms::READ | MapPerms::WRITE, true, 42, device);
        let special = |flags: SmapVmFlags, key: u64| SmapInfo {
            map: map.clone(),
            vm_flags: flags,
            protection_key: key,
        };
        let mut cases: Vec<SmapInfo> = [
            SmapVmFlags {
                mixed_map: true,
                ..Default::default()
            },
            SmapVmFlags {
                io_map: true,
                ..Default::default()
            },
            SmapVmFlags {
                sync: true,
                ..Default::default()
            },
            SmapVmFlags {
                hugepage: true,
                ..Default::default()
            },
            SmapVmFlags {
                dont_fork: true,
                ..Default::default()
            },
            SmapVmFlags {
                wipe_on_fork: true,
                ..Default::default()
            },
            SmapVmFlags {
                lock_on_fault: true,
                ..Default::default()
            },
            SmapVmFlags {
                unknown: true,
                ..Default::default()
            },
        ]
        .into_iter()
        .map(|flags| special(flags, 0))
        .collect();
        cases.push(special(SmapVmFlags::default(), 1));
        for smaps in cases {
            let pages = [(0x1000, map.clone())];
            let selection = PageSelection {
                pages: &pages,
                smaps: &[smaps],
                page_size: 0x1000,
                reject_executable: false,
            };
            assert!(
                matches!(
                    validate_selection(&selection),
                    Err(Error::UnsupportedFeature(reason))
                        if reason == "page has special mapping semantics"
                ),
                "special semantics were accepted"
            );
        }
    }
}

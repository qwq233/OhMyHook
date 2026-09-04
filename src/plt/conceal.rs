//! validated PLT mutations validate that each selected GOT page is a private
//! file mapping, so the relocation write stays a private copy and cannot
//! reach the backing file.
//!
//! Requests are opt-in: the default install path performs no page selection
//! and no validation. This module selects the relocation pages and publishes
//! the per-request PrivateFileValidation result.

use super::{HookPlan, PltHookRequest};
use crate::conceal::{self as shared, PageSelection};
use crate::maps::{MapInfo, find_map_containing, page_ranges};
use crate::{Error, Result};

pub(super) struct PrivateFileValidationResults {
    kinds: Vec<super::PrivateFileValidation>,
    pub(super) smaps: Vec<crate::maps::SmapInfo>,
}

impl PrivateFileValidationResults {
    pub(super) fn not_requested() -> Self {
        Self {
            kinds: Vec::new(),
            smaps: Vec::new(),
        }
    }

    pub(super) fn get(&self, index: usize) -> super::PrivateFileValidation {
        self.kinds
            .get(index)
            .copied()
            .unwrap_or(super::PrivateFileValidation::Unvalidated)
    }
}

pub(super) fn apply(
    hooks: &[PltHookRequest<'_>],
    plans: &[Option<HookPlan>],
    install_maps: &[MapInfo],
) -> Result<PrivateFileValidationResults> {
    if hooks.len() != plans.len() {
        return Err(Error::InvalidElf(
            "PrivateFileValidation plan count mismatch",
        ));
    }
    if !requested(hooks) {
        return Ok(PrivateFileValidationResults::not_requested());
    }

    let page_size = crate::sys::page_size()?;
    // The installer already holds a complete pathless snapshot captured under
    // the same process write lock; selecting GOT pages from it keeps this
    // operation's view atomic without a second procfs read.
    let maps = install_maps;
    let mut pages: Vec<(usize, MapInfo)> = Vec::new();
    for (request, plan) in hooks.iter().zip(plans) {
        if !request.require_private_file_pages {
            continue;
        }
        let Some(plan) = plan else {
            continue;
        };
        for write in &plan.writes {
            let map = find_map_containing(maps, write.address, std::mem::size_of::<usize>())
                .ok_or(Error::MappingChanged)?;
            let page = crate::sys::page_start(write.address, page_size);
            if !pages.iter().any(|(existing, _)| *existing == page) {
                pages.push((page, map.clone()));
            }
        }
    }
    pages.sort_by_key(|(page, _)| *page);
    let ranges = page_ranges(pages.iter().map(|(page, _)| *page))?;
    let mut smaps = Vec::new();
    crate::maps::extend_self_smaps_for_ranges(&mut smaps, &ranges)?;
    let selection = PageSelection {
        pages: &pages,
        smaps: &smaps,
        page_size,
        reject_executable: true,
    };
    let validated_page_starts = shared::validate_selection(&selection)?;

    let mut kinds = Vec::with_capacity(hooks.len());
    for (request, plan) in hooks.iter().zip(plans) {
        if !request.require_private_file_pages {
            kinds.push(super::PrivateFileValidation::Unvalidated);
            continue;
        }
        let Some(plan) = plan else {
            kinds.push(super::PrivateFileValidation::Unvalidated);
            continue;
        };
        let validated = plan.writes.iter().all(|write| {
            validated_page_starts.contains(&crate::sys::page_start(write.address, page_size))
        });
        kinds.push(if validated {
            super::PrivateFileValidation::Validated
        } else {
            super::PrivateFileValidation::Unvalidated
        });
    }
    Ok(PrivateFileValidationResults { kinds, smaps })
}

pub(super) fn requested(hooks: &[PltHookRequest<'_>]) -> bool {
    hooks
        .iter()
        .any(|request| request.require_private_file_pages)
}

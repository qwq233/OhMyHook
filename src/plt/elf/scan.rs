/// Finds supported relocations for `symbols` in every loaded matching image.
///
/// # Safety
///
/// Every readable mapping for `ElfImageSelector` must remain loaded, readable, at the same
/// address, and free of concurrent content mutation until this function
/// returns.
pub(crate) unsafe fn find_symbol_relocations(
    selector: &ElfImageSelector,
    maps: &[MapInfo],
    queries: &[SymbolQuery<'_>],
    include_build_id: bool,
) -> Result<Option<FoundRelocations>> {
    // SAFETY: forwarded from this function's mapping-stability contract.
    let discovered = unsafe { discover_images(selector, maps)? };
    if discovered.is_empty() {
        return Ok(None);
    }
    let mut found = (0..queries.len())
        .map(|_| RelocationScan::default())
        .collect::<Vec<_>>();
    let mut images = Vec::with_capacity(discovered.len());
    for discovered in discovered {
        // SAFETY: every map is clipped to this image's exact PT_LOAD ranges and
        // inherits the caller's mapping-lifetime guarantee.
        let image_memory = unsafe { Memory::new(&discovered.maps) };
        discovered
            .image
            .scan_symbol_relocations(&image_memory, queries, &mut found)?;
        // Inspection metadata must not make an otherwise installable
        // relocation batch fail. Strict build-id discovery remains available
        // through find_loaded_images.
        let build_id = if include_build_id {
            discovered
                .image
                .gnu_build_id(&image_memory)
                .unwrap_or_default()
        } else {
            None
        };
        images.push(FoundImage {
            id: discovered.image.id,
            load_ranges: discovered.image.load_ranges.clone(),
            build_id,
        });
    }

    let mut by_symbol = Vec::with_capacity(found.len());
    for scan in found {
        by_symbol.push(FoundSymbolRelocations {
            relocations: scan.matches.into_values().collect(),
            rejected: scan.rejected.into_values().collect(),
        });
    }
    Ok(Some(FoundRelocations { by_symbol, images }))
}

/// Finds one exact relocation for a bound image without the generic batch
/// containers. Unsupported or ambiguous inputs return `None` so the caller can
/// use the complete scanner.
///
/// # Safety
///
/// Every readable mapping for `ElfImageSelector` must remain loaded, readable, at the same
/// address, and free of concurrent content mutation until this function
/// returns.
pub(crate) unsafe fn find_bound_symbol_relocation(
    selector: &ElfImageSelector,
    query: &SymbolQuery<'_>,
) -> Result<Option<BoundSymbolRelocation>> {
    // SAFETY: forwarded to the bound-image discovery contract.
    let (discovered, maps) = unsafe { super::discover::bound_image_discovery(selector)? };
    let image = discovered.image;
    // SAFETY: the snapshot is clipped to this image's PT_LOAD ranges and the
    // caller keeps its readable mappings stable.
    let memory = unsafe { Memory::new(&discovered.maps) };
    let raw = if image.dynamic.hash.is_some() {
        image.find_exact_relocation_raw(&memory, query)?
    } else {
        None
    };
    let relocation = match raw {
        Some(relocation) => Some(relocation),
        None => image.find_exact_relocation(&memory, query)?,
    };
    let image = FoundImage {
        id: image.id,
        load_ranges: image.load_ranges,
        build_id: None,
    };
    Ok(relocation.map(|relocation| BoundSymbolRelocation {
        relocation,
        image,
        maps,
    }))
}

pub(crate) struct BoundSymbolRelocation {
    pub(crate) relocation: FoundRelocation,
    pub(crate) image: FoundImage,
    pub(crate) maps: Vec<MapInfo>,
}
use super::*;

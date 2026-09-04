/// Finds supported relocations for `symbols` in every loaded matching image.
///
/// # Safety
///
/// Every readable mapping for `target` must remain loaded, readable, at the same
/// address, and free of concurrent content mutation until this function
/// returns.
pub(crate) unsafe fn find_symbol_relocations(
    target: &Target,
    maps: &[MapInfo],
    queries: &[SymbolQuery<'_>],
    include_build_id: bool,
) -> Result<Option<FoundRelocations>> {
    // SAFETY: forwarded from this function's mapping-stability contract.
    let discovered = unsafe { discover_images(target, maps)? };
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
use super::*;

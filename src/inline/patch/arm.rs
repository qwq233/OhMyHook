use super::range_end;
use crate::maps::{MapInfo, MapPerms, find_map_containing};
use crate::{Error, Result};
use std::ops::Range;

pub(in crate::inline) fn copy_literal(
    maps: &[MapInfo],
    address: usize,
    length: usize,
    overwritten: Range<usize>,
) -> Result<Vec<u8>> {
    if ranges_overlap(address..range_end(address, length)?, overwritten) {
        return Err(Error::UnsupportedFeature(
            "PC-relative data overlaps stolen instructions",
        ));
    }
    let map = find_map_containing(maps, address, length).ok_or(Error::MappingChanged)?;
    if !map.is_private || !map.perms.contains(MapPerms::READ) || map.perms.contains(MapPerms::WRITE)
    {
        return Err(Error::UnsupportedFeature(
            "mutable or shared PC-relative literal",
        ));
    }
    // SAFETY: the fresh readable mapping covers the complete literal and the
    // caller keeps it stable for generation.
    Ok(unsafe {
        std::slice::from_raw_parts(std::ptr::with_exposed_provenance(address), length).to_vec()
    })
}

fn ranges_overlap(left: Range<usize>, right: Range<usize>) -> bool {
    left.start < right.end && right.start < left.end
}

use crate::maps::{DeviceId, MapInfo, MapPerms};
use crate::{Error, Result};
use std::collections::BTreeMap;
use std::sync::Mutex;

const MAP_FIXED_NOREPLACE: i32 = 0x100000;

#[derive(Clone, Copy)]
pub(super) struct ArenaPlacement {
    pub(super) direct: Option<(i32, usize)>,
    pub(super) allowed: Option<(usize, usize)>,
}

#[derive(Clone, Copy)]
pub(super) struct Arena {
    address: usize,
    length: usize,
    /// Writes use the forced-access channel with final protection already set.
    direct: bool,
    /// Final protection of the page, including architecture-specific bits.
    protection: i32,
    /// Owned by the process-wide reservation registry rather than one hook.
    reserved: bool,
}

static RESERVED_POOL: Mutex<BTreeMap<usize, usize>> = Mutex::new(BTreeMap::new());
const POOL_SIZE: usize = 2 * 1024 * 1024;
const POOL_DISTANCE: usize = (128 * 1024 * 1024) - 4;

impl Arena {
    pub(super) unsafe fn allocate_near<T>(
        maps: &[MapInfo],
        target: usize,
        max_distance: usize,
        page_size: usize,
        length: usize,
        placement: ArenaPlacement,
        mut generate: impl FnMut(usize) -> Result<T>,
    ) -> Result<(Self, T)> {
        let ArenaPlacement { direct, allowed } = placement;
        if length == 0 || !length.is_multiple_of(page_size) {
            return Err(Error::ArithmeticOverflow);
        }
        if allowed.is_some_and(|(low, high)| low > high) {
            return Err(Error::NoNearbyMemory);
        }
        let search_distance = max_distance.min(POOL_DISTANCE);
        let mut excluded_pool_addresses = Vec::new();
        let mut pool_arena = take_pool_arena(
            target,
            search_distance,
            length,
            allowed,
            page_size,
            &excluded_pool_addresses,
        );
        if pool_arena.is_none() {
            let pool_length = length.max(POOL_SIZE);
            if let Ok(pool) =
                map_fixed_pool_near(target, pool_length, page_size, search_distance, allowed)
            {
                insert_pool_range(pool.address, pool.length);
                pool_arena = take_pool_arena(
                    target,
                    search_distance,
                    length,
                    allowed,
                    page_size,
                    &excluded_pool_addresses,
                );
            }
        }
        while let Some(mut arena) = pool_arena {
            if let Some((protection, _)) = direct {
                // SAFETY: the reservation owns the complete page range and no
                // code has been generated into it yet.
                let protected =
                    unsafe { crate::sys::protect(arena.address, arena.length, protection) };
                match protected {
                    Ok(()) => {
                        arena.direct = true;
                        arena.protection = protection;
                    }
                    Err(_) => {
                        // The failed protection change leaves the pool page
                        // writable. Return it to the registry and continue with
                        // the direct executable mapping below.
                        insert_pool_range(arena.address, arena.length);
                        break;
                    }
                }
            }
            match generate(arena.address) {
                Ok(generated) => return Ok((arena, generated)),
                Err(Error::NoNearbyMemory) => {
                    let failed_address = arena.address;
                    release_pool_arena(arena).map_err(super::cleanup_pending)?;
                    excluded_pool_addresses.push(failed_address);
                    pool_arena = take_pool_arena(
                        target,
                        search_distance,
                        length,
                        allowed,
                        page_size,
                        &excluded_pool_addresses,
                    );
                }
                Err(error) => {
                    release_pool_arena(arena).map_err(super::cleanup_pending)?;
                    return Err(error);
                }
            }
        }
        let requested_protection = direct.map_or(libc::PROT_READ | libc::PROT_WRITE, |(p, _)| p);
        if max_distance == usize::MAX && allowed.is_none() {
            let address = match direct {
                // SAFETY: a zero hint asks the kernel for any free anonymous
                // range; this path is only used when the trampoline has no
                // PC-relative back-edge to the stolen window.
                Some((protection, _)) => unsafe {
                    crate::sys::map_exec_anonymous(0, length, protection, 0)
                },
                None => {
                    // SAFETY: a zero hint asks the kernel for a free anonymous
                    // range; this caller owns the returned mapping.
                    unsafe { crate::sys::map_rw_anonymous(0, length, 0) }
                }
            };
            let address = address?;
            let arena = Self::anonymous(address, length, direct.is_some(), requested_protection);
            match generate(address) {
                Ok(generated) => return Ok((arena, generated)),
                Err(error) => {
                    // SAFETY: generation has not published an entry into this
                    // private mapping.
                    if let Err(unmap_error) = unsafe { arena.release() } {
                        return Err(super::cleanup_pending(unmap_error));
                    }
                    return Err(error);
                }
            }
        }
        if maps.is_empty() {
            return Err(Error::NoNearbyMemory);
        }
        let mut candidates = merge_candidates(maps, target, max_distance, page_size, length)?;
        candidates.extend(gap_candidates(
            maps,
            target,
            max_distance,
            page_size,
            length,
            allowed,
        )?);
        restrict_candidates(&mut candidates, allowed);
        let nearest_candidate = candidates
            .iter()
            .map(|candidate| candidate.abs_diff(target))
            .min();
        let candidate_count = candidates.len();
        let mut unique_candidates = Vec::with_capacity(candidates.len());
        for candidate in candidates.drain(..) {
            if !unique_candidates.contains(&candidate) {
                unique_candidates.push(candidate);
            }
        }
        candidates = unique_candidates;
        let mut mapped_candidate_count = 0;
        let mut map_error = None;
        let mut generation_failures = 0;
        let mut first_generation_error = None;
        let mut exact_supported = true;
        // The exact pass runs first: an occupied candidate then fails with
        // EEXIST and costs nothing, whereas the hint pass has to map and unmap
        // every candidate the kernel decides to place somewhere unusable. Old
        // kernels reject MAP_FIXED_NOREPLACE with EINVAL; the fallback pass
        // then retries the remaining candidates with a plain address hint; the
        // address check below discards any mapping the kernel misplaced.
        for exact in [true, false] {
            if exact && !exact_supported {
                continue;
            }
            'candidates: for &candidate in &candidates {
                let flags = if exact { MAP_FIXED_NOREPLACE } else { 0 };
                let address = match direct {
                    // SAFETY: fixed candidates name complete captured ranges;
                    // ordinary mmap treats the same address only as a hint.
                    Some((protection, _)) => {
                        let mapped = unsafe {
                            // SAFETY: fixed candidates name complete captured
                            // ranges; ordinary mmap treats the address as a hint.
                            crate::sys::map_exec_anonymous(candidate, length, protection, flags)
                        };
                        match mapped {
                            Ok(address) => address,
                            Err(error) => {
                                if exact && unsupported_fixed_mapping(&error) {
                                    exact_supported = false;
                                    break 'candidates;
                                } else if !exact || !fixed_collision(&error) {
                                    map_error.get_or_insert(error);
                                }
                                continue;
                            }
                        }
                    }
                    _ => {
                        // SAFETY: the candidate is a captured or hinted
                        // anonymous mapping request owned by this allocation.
                        let mapped =
                            unsafe { crate::sys::map_rw_anonymous(candidate, length, flags) };
                        match mapped {
                            Ok(address) => address,
                            Err(error) => {
                                if exact && unsupported_fixed_mapping(&error) {
                                    exact_supported = false;
                                    break 'candidates;
                                } else if !exact || !fixed_collision(&error) {
                                    map_error.get_or_insert(error);
                                }
                                continue;
                            }
                        }
                    }
                };
                mapped_candidate_count += 1;
                if address != candidate || address.abs_diff(target) > max_distance {
                    // SAFETY: this call owns the unsuitable mapping. There is no
                    // handle through which a failed cleanup could be retried, so
                    // the mapping leaks; no target byte has been written, so the
                    // caller decides what a leaked mapping is worth.
                    if let Err(error) = unsafe { crate::sys::unmap(address, length) } {
                        return Err(super::cleanup_pending(error));
                    }
                    continue;
                }

                let arena =
                    Self::anonymous(address, length, direct.is_some(), requested_protection);
                match generate(address) {
                    Ok(generated) => return Ok((arena, generated)),
                    Err(error) => {
                        // SAFETY: generation has not published an entry into
                        // this private mapping. There is no handle through
                        // which a failed cleanup could be retried, so the
                        // mapping leaks. Report the leak rather than the
                        // generation error: the caller can retry a generation
                        // failure, but only it can decide what to do about an
                        // executable mapping this process can no longer free.
                        if let Err(unmap_error) = unsafe { arena.release() } {
                            return Err(super::cleanup_pending(unmap_error));
                        }
                        if !matches!(error, Error::NoNearbyMemory) {
                            return Err(error);
                        }
                        generation_failures += 1;
                        first_generation_error.get_or_insert_with(|| format!("{error}"));
                    }
                }
            }
        }
        if mapped_candidate_count == 0
            && let Some(error) = map_error
        {
            return Err(error);
        }
        log::warn!(
            "inline arena placement failed: required_distance={}, allowed_window_present={}, candidate_count={}, nearest_candidate_distance={:?}, mapped_candidates={}, map_error={:?}, generation_failures={}, first_generation_error={:?}",
            max_distance,
            allowed.is_some(),
            candidate_count,
            nearest_candidate,
            mapped_candidate_count,
            map_error,
            generation_failures,
            first_generation_error
        );
        Err(Error::NoNearbyMemory)
    }

    pub(super) const fn address(&self) -> usize {
        self.address
    }

    const fn anonymous(address: usize, length: usize, direct: bool, protection: i32) -> Self {
        Self {
            address,
            length,
            direct,
            protection,
            reserved: false,
        }
    }

    /// Combines two adjacent arenas so a batch release can use one `munmap`.
    pub(super) fn coalesce_with(self, next: Self) -> Option<Self> {
        let end = self.address.checked_add(self.length)?;
        let length = self.length.checked_add(next.length)?;
        (self.direct == next.direct
            && self.protection == next.protection
            && self.reserved == next.reserved
            && end == next.address)
            .then_some(Self {
                address: self.address,
                length,
                direct: self.direct,
                protection: self.protection,
                reserved: self.reserved || next.reserved,
            })
    }

    pub(super) fn into_pages(self, page_size: usize) -> Vec<Self> {
        if page_size == 0 || !self.length.is_multiple_of(page_size) {
            crate::sys::fail_stop();
        }
        (0..self.length / page_size)
            .map(|index| Self {
                address: self.address + index * page_size,
                length: page_size,
                direct: self.direct,
                protection: self.protection,
                reserved: self.reserved,
            })
            .collect()
    }

    pub(super) fn record_in(&self, maps: &mut Vec<MapInfo>) {
        let map = MapInfo {
            start: self.address,
            end: self.address + self.length,
            perms: MapPerms::READ | MapPerms::EXEC,
            is_private: true,
            offset: 0,
            device: DeviceId::new(0, 0),
            inode: 0,
            path: None,
        };
        let index = maps.partition_point(|entry| entry.start < map.start);
        maps.insert(index, map);
    }

    pub(super) unsafe fn write(&self, bytes: &[u8], mem: Option<usize>) -> Result<()> {
        // SAFETY: forwarded from this arena's write ownership contract.
        unsafe { self.write_at(0, bytes, mem)? };
        let end = self
            .address
            .checked_add(bytes.len())
            .ok_or(Error::ArithmeticOverflow)?;
        // SAFETY: the just-written range remains live and readable. The
        // trampoline stays unpublished until the prepared return or target
        // commit performs process-wide instruction synchronization.
        unsafe { crate::sys::flush_instruction_cache_ranges_local(&[(self.address, end)]) }
    }

    pub(super) unsafe fn write_at(
        &self,
        offset: usize,
        bytes: &[u8],
        mem: Option<usize>,
    ) -> Result<()> {
        offset
            .checked_add(bytes.len())
            .filter(|&end| end <= self.length)
            .ok_or(Error::UnsupportedFeature("inline arena overflow"))?;
        if self.direct {
            let Some(fd) = mem else {
                // A direct arena exists only while its caller keeps the
                // forced-access descriptor of the same preparation open.
                crate::sys::fail_stop();
            };
            // SAFETY: the destination is caller-owned private memory and the
            // descriptor can write it without changing page permissions.
            unsafe { crate::sys::pwrite_self_mem(fd, self.address + offset, bytes) }
        } else {
            // SAFETY: the arena is caller-owned RW memory and does not overlap
            // the source allocation.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    std::ptr::with_exposed_provenance_mut(self.address + offset),
                    bytes.len(),
                );
            }
            Ok(())
        }
    }

    pub(super) unsafe fn make_executable(&self, protection: i32) -> Result<()> {
        if self.direct {
            return Ok(());
        }
        // SAFETY: the arena is one exact live page owned by the caller.
        unsafe { crate::sys::protect(self.address, self.length, protection) }
    }

    pub(super) unsafe fn release(&self) -> Result<()> {
        if self.reserved {
            return release_pool_arena(*self);
        }
        // SAFETY: the caller guarantees that no generated entry is in use and
        // retains this record when the syscall fails.
        unsafe { crate::sys::unmap(self.address, self.length) }
    }

    #[cfg(test)]
    pub(super) fn is_direct(&self) -> bool {
        self.direct
    }
}

pub(super) fn reserve_near(target: usize, length: usize) -> Result<()> {
    let page_size = crate::sys::page_size()?;
    let length = length
        .checked_add(page_size - 1)
        .map(|value| value & !(page_size - 1))
        .ok_or(Error::ArithmeticOverflow)?;
    if length == 0 {
        return Err(Error::ArithmeticOverflow);
    }
    let pool_length = length.max(POOL_SIZE);
    let arena = map_fixed_pool_near(target, pool_length, page_size, POOL_DISTANCE, None)?;
    insert_pool_range(arena.address, arena.length);
    Ok(())
}

#[cfg(test)]
pub(super) fn clear_pool_for_tests() {
    let mut pool = pool_lock();
    let ranges: Vec<(usize, usize)> = pool
        .iter()
        .map(|(&start, &length)| (start, length))
        .collect();
    for (start, length) in ranges {
        // SAFETY: only free pool ranges are stored; active hook arenas are
        // removed before installation and returned only after removal.
        unsafe { crate::sys::unmap(start, length) }.unwrap();
        pool.remove(&start);
    }
    pool.clear();
}

#[cfg(test)]
pub(super) fn reserved_pool_ranges_for_tests() -> Vec<(usize, usize)> {
    pool_lock()
        .iter()
        .map(|(&start, &length)| (start, start + length))
        .collect()
}

fn pool_lock() -> std::sync::MutexGuard<'static, BTreeMap<usize, usize>> {
    RESERVED_POOL
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

fn take_pool_arena(
    target: usize,
    max_distance: usize,
    length: usize,
    allowed: Option<(usize, usize)>,
    page_size: usize,
    excluded: &[usize],
) -> Option<Arena> {
    let mut pool = pool_lock();
    let mut best: Option<(usize, usize, usize, usize)> = None;
    for (&start, &range_length) in pool.iter() {
        let end = start.checked_add(range_length)?;
        let low = start.max(target.saturating_sub(max_distance));
        let Some(last) = end.checked_sub(length) else {
            continue;
        };
        let high = last.min(target.saturating_add(max_distance));
        let (low, high) = if let Some((allowed_low, allowed_high)) = allowed {
            (low.max(allowed_low), high.min(allowed_high))
        } else {
            (low, high)
        };
        let first = align_up(low, page_size).ok()?;
        let last = crate::sys::page_start(high, page_size);
        if first <= last {
            let target_page = crate::sys::page_start(target, page_size);
            let nearest = target_page.clamp(first, last);
            let candidate = [
                nearest,
                nearest.saturating_sub(page_size),
                nearest.saturating_add(page_size),
            ]
            .into_iter()
            .find(|candidate| {
                *candidate >= first && *candidate <= last && !excluded.contains(candidate)
            });
            let Some(candidate) = candidate else {
                continue;
            };
            let distance = candidate.abs_diff(target);
            if best.is_none_or(|(best_distance, _, _, _)| distance < best_distance) {
                best = Some((distance, start, candidate, end));
            }
        }
    }
    let (_, start, candidate, end) = best?;
    let range_length = *pool.get(&start)?;
    pool.remove(&start);
    if candidate > start {
        pool.insert(start, candidate - start);
    }
    let allocated_end = candidate.checked_add(length)?;
    if allocated_end < end {
        pool.insert(allocated_end, end - allocated_end);
    }
    let arena = Arena {
        address: candidate,
        length,
        direct: false,
        protection: libc::PROT_READ | libc::PROT_WRITE,
        reserved: true,
    };
    debug_assert!(range_length >= length);
    Some(arena)
}

fn release_pool_arena(arena: Arena) -> Result<()> {
    // SAFETY: the caller drained every trampoline call before removal, so
    // this page is no longer executable code.
    unsafe {
        crate::sys::protect(
            arena.address,
            arena.length,
            libc::PROT_READ | libc::PROT_WRITE,
        )?
    };
    insert_pool_range(arena.address, arena.length);
    Ok(())
}

fn insert_pool_range(start: usize, length: usize) {
    if length == 0 {
        return;
    }
    let mut pool = pool_lock();
    let Some(end) = start.checked_add(length) else {
        return;
    };
    let mut new_start = start;
    let mut new_end = end;
    if let Some((&previous_start, &previous_length)) = pool.range(..start).next_back()
        && let Some(previous_end) = previous_start.checked_add(previous_length)
        && previous_end == start
    {
        new_start = previous_start;
        pool.remove(&previous_start);
    }
    if let Some((&next_start, &next_length)) = pool.range(new_end..).next()
        && next_start == new_end
        && let Some(next_end) = next_start.checked_add(next_length)
    {
        new_end = next_end;
        pool.remove(&next_start);
    }
    pool.insert(new_start, new_end - new_start);
}

fn map_fixed_pool_near(
    target: usize,
    length: usize,
    page_size: usize,
    distance: usize,
    allowed: Option<(usize, usize)>,
) -> Result<Arena> {
    let maps = crate::maps::read_self_maps_pathless()?;
    let mut candidates = merge_candidates(&maps, target, distance, page_size, length)?;
    candidates.extend(gap_candidates(
        &maps, target, distance, page_size, length, allowed,
    )?);
    restrict_candidates(&mut candidates, allowed);
    candidates.sort_unstable_by_key(|candidate| candidate.abs_diff(target));
    candidates.dedup();
    let mut exact_supported = true;
    for exact in [true, false] {
        if exact && !exact_supported {
            continue;
        }
        for &candidate in &candidates {
            let flags = if exact { MAP_FIXED_NOREPLACE } else { 0 };
            // SAFETY: fixed candidates name captured free ranges; the hint
            // pass is for old kernels without MAP_FIXED_NOREPLACE, and both
            // forms reject any mapping the kernel moves elsewhere.
            let address = match unsafe { crate::sys::map_rw_anonymous(candidate, length, flags) } {
                Ok(address) => address,
                Err(error) => {
                    if exact && unsupported_fixed_mapping(&error) {
                        exact_supported = false;
                        break;
                    }
                    if exact && fixed_collision(&error) {
                        continue;
                    }
                    return Err(error);
                }
            };
            if address != candidate {
                // SAFETY: this call owns the unsuitable mapping and no code
                // has been written into it.
                if let Err(error) = unsafe { crate::sys::unmap(address, length) } {
                    return Err(super::cleanup_pending(error));
                }
                continue;
            }
            return Ok(Arena::anonymous(
                address,
                length,
                false,
                libc::PROT_READ | libc::PROT_WRITE,
            ));
        }
    }
    Err(Error::InlineArenaPlacement { target, distance })
}

fn fixed_collision(error: &Error) -> bool {
    matches!(
        error,
        Error::SystemCall { source, .. } if *source == syscalls::Errno::EEXIST
    )
}

fn unsupported_fixed_mapping(error: &Error) -> bool {
    matches!(
        error,
        Error::SystemCall { source, .. } if *source == syscalls::Errno::EINVAL
    )
}

/// Candidate addresses whose new anonymous executable mapping can merge into
/// an adjacent existing anonymous executable VMA.
///
/// Merging requires identical protection and flags on both sides of the
/// boundary, so only unnamed anonymous private `r-x` neighbors qualify; a
/// kernel that decides against merging still places the page as a standalone
/// entry with correct semantics. BTI state is invisible in `/proc/self/maps`,
/// so a guarded arena simply may fail to merge and remains a standalone
/// mapping.
fn merge_candidates(
    maps: &[MapInfo],
    target: usize,
    max_distance: usize,
    page_size: usize,
    length: usize,
) -> Result<Vec<usize>> {
    let low = align_up(target.saturating_sub(max_distance), page_size)?;
    let high = crate::sys::page_start(target.saturating_add(max_distance), page_size);
    if low > high {
        return Ok(Vec::new());
    }
    let mut candidates = Vec::new();
    for map in maps {
        if !map.is_private
            || map.device != DeviceId::new(0, 0)
            || map.inode != 0
            || map.perms != MapPerms::READ | MapPerms::EXEC
        {
            continue;
        }
        let after = crate::sys::page_start(map.end, page_size);
        if after >= low
            && after <= high
            && after.abs_diff(target) <= max_distance
            && after.checked_add(length).is_some()
        {
            candidates.push(after);
        }
        if let Some(before) = map.start.checked_sub(length) {
            let candidate = crate::sys::page_start(before, page_size);
            if candidate >= low
                && candidate <= high
                && candidate.abs_diff(target) <= max_distance
                && candidate.checked_add(length).is_some()
            {
                candidates.push(candidate);
            }
        }
    }
    candidates.sort_unstable_by_key(|candidate| candidate.abs_diff(target));
    candidates.dedup();
    Ok(candidates)
}

fn gap_candidates(
    maps: &[MapInfo],
    target: usize,
    max_distance: usize,
    page_size: usize,
    length: usize,
    allowed: Option<(usize, usize)>,
) -> Result<Vec<usize>> {
    let (low, high) = allowed.unwrap_or((0, usize::MAX));
    let low = align_up(target.saturating_sub(max_distance).max(low), page_size)?;
    let high = crate::sys::page_start(target.saturating_add(max_distance).min(high), page_size);
    if low > high {
        return Ok(Vec::new());
    }
    let target_page = crate::sys::page_start(target, page_size);
    let mut candidates = Vec::new();
    let mut cursor = low;

    let limit = high.saturating_add(length);
    let first = maps
        .partition_point(|map| map.start < low)
        .saturating_sub(1);
    let last = maps.partition_point(|map| map.start < limit);
    for map in &maps[first..last] {
        if cursor < map.start {
            push_gap_candidate(
                &mut candidates,
                cursor,
                map.start,
                target_page,
                high,
                page_size,
                length,
            );
        }
        cursor = cursor.max(align_up(map.end, page_size)?);
        if cursor > high {
            break;
        }
    }
    if cursor < limit {
        push_gap_candidate(
            &mut candidates,
            cursor,
            limit,
            target_page,
            high,
            page_size,
            length,
        );
    }
    candidates.sort_unstable_by_key(|candidate| candidate.abs_diff(target));
    candidates.dedup();
    Ok(candidates)
}

fn push_gap_candidate(
    candidates: &mut Vec<usize>,
    gap_start: usize,
    gap_end: usize,
    target_page: usize,
    high: usize,
    page_size: usize,
    length: usize,
) {
    let Some(last) = gap_end.checked_sub(length) else {
        return;
    };
    let last = crate::sys::page_start(last.min(high), page_size);
    let first = crate::sys::page_start(gap_start.saturating_add(page_size - 1), page_size);
    if first <= last {
        let nearest = target_page.clamp(first, last);
        candidates.push(nearest);
        // Variable-length relocations can invalidate only the boundary page
        // of their placement window; retain its usable neighbor in this gap.
        if nearest > first {
            candidates.push(nearest - page_size);
        }
        if nearest < last {
            candidates.push(nearest + page_size);
        }
    }
}

fn restrict_candidates(candidates: &mut Vec<usize>, allowed: Option<(usize, usize)>) {
    if let Some((low, high)) = allowed {
        candidates.retain(|candidate| *candidate >= low && *candidate <= high);
    }
}

fn align_up(value: usize, alignment: usize) -> Result<usize> {
    value
        .checked_add(alignment - 1)
        .map(|value| crate::sys::page_start(value, alignment))
        .ok_or(Error::ArithmeticOverflow)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::maps::{DeviceId, MapPerms};

    fn map(start: usize, end: usize) -> MapInfo {
        MapInfo {
            start,
            end,
            perms: MapPerms::READ,
            is_private: true,
            offset: 0,
            device: DeviceId::new(0, 0),
            inode: 0,
            path: None,
        }
    }

    #[test]
    fn coalesce_keeps_reserved_and_anonymous_arenas_separate() {
        let anonymous = Arena::anonymous(0x1000, 0x1000, false, libc::PROT_READ | libc::PROT_EXEC);
        let mut reserved = anonymous;
        reserved.reserved = true;
        assert!(anonymous.coalesce_with(reserved).is_none());
    }

    #[test]
    fn merge_candidates_prefer_anonymous_executable_neighbors() {
        let exec = |start: usize, end: usize| MapInfo {
            perms: MapPerms::READ | MapPerms::EXEC,
            ..map(start, end)
        };
        // An anonymous private executable VMA accepts merge candidates at
        // both boundaries; writable, shared, and file-backed mappings do not.
        let maps = vec![
            map(0x1000, 0x2000),
            exec(0x3000, 0x5000),
            MapInfo {
                perms: MapPerms::READ | MapPerms::WRITE | MapPerms::EXEC,
                ..map(0x6000, 0x7000)
            },
            MapInfo {
                device: DeviceId::new(8, 2),
                inode: 42,
                ..exec(0x8000, 0x9000)
            },
        ];
        let candidates = merge_candidates(&maps, 0x4000, 0x10000, 0x1000, 0x1000).unwrap();
        assert_eq!(candidates, vec![0x5000, 0x2000]);

        // A narrow window keeps only the in-range boundary.
        let candidates = merge_candidates(&maps, 0x4000, 0x1000, 0x1000, 0x1000).unwrap();
        assert_eq!(candidates, vec![0x5000]);
    }

    #[test]
    fn merge_candidates_survive_when_gap_scan_finds_no_gap() {
        let exec = |start: usize, end: usize| MapInfo {
            perms: MapPerms::READ | MapPerms::EXEC,
            ..map(start, end)
        };
        // Every address in the placement window belongs to a mapping, but the
        // anonymous executable boundary at 0x5000 remains a valid merge site.
        let maps = vec![
            map(0x1000, 0x3000),
            exec(0x3000, 0x5000),
            map(0x5000, 0x7000),
        ];
        let candidates = gap_candidates(&maps, 0x4000, 0x1000, 0x1000, 0x1000, None).unwrap();
        assert!(candidates.is_empty());
        let mut merged = merge_candidates(&maps, 0x4000, 0x1000, 0x1000, 0x1000).unwrap();
        merged.extend(gap_candidates(&maps, 0x4000, 0x1000, 0x1000, 0x1000, None).unwrap());
        assert_eq!(merged, vec![0x5000]);
    }

    #[test]
    fn candidate_windows_restrict_gap_selection() {
        let mut candidates = vec![0x2000, 0x4000];
        restrict_candidates(&mut candidates, Some((0x4000, 0x5000)));
        assert_eq!(candidates, vec![0x4000]);
        let maps = [map(0x1000, 0x2000), map(0xa000, 0xb000)];
        assert_eq!(
            gap_candidates(
                &maps,
                0x2000,
                0x9000,
                0x1000,
                0x1000,
                Some((0x5001, 0x8000))
            )
            .unwrap(),
            vec![0x6000, 0x7000]
        );
        assert_eq!(
            gap_candidates(
                &maps,
                0x2000,
                0x9000,
                0x1000,
                0x1000,
                Some((0x9000, 0x9000))
            )
            .unwrap(),
            vec![0x9000]
        );
        assert!(
            gap_candidates(
                &maps,
                0x2000,
                0x9000,
                0x1000,
                0x2000,
                Some((0x9000, 0x9000))
            )
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn placement_retries_inside_a_gap_and_a_coalesced_pool() {
        let _guard = crate::sys::recover_lock(crate::inline::INLINE_TEST_LOCK.lock());
        pool_lock().clear();
        let maps = [map(0x1000, 0x2000), map(0x8000, 0x9000)];
        assert_eq!(
            gap_candidates(
                &maps,
                0x1000,
                usize::MAX,
                0x1000,
                0x1000,
                Some((0x2000, 0x7000))
            )
            .unwrap(),
            [0x2000, 0x3000]
        );
        assert_eq!(
            gap_candidates(
                &maps,
                0x9000,
                usize::MAX,
                0x1000,
                0x1000,
                Some((0x2000, 0x7000))
            )
            .unwrap(),
            [0x7000, 0x6000]
        );
        insert_pool_range(0x2000, 0x6000);
        for (target, rejected, expected) in [(0x1000, 0x2000, 0x3000), (0x9000, 0x7000, 0x6000)] {
            let arena = take_pool_arena(
                target,
                usize::MAX,
                0x1000,
                Some((0x2000, 0x7000)),
                0x1000,
                &[rejected],
            )
            .unwrap();
            assert_eq!(arena.address(), expected);
            insert_pool_range(arena.address(), 0x1000);
        }
        pool_lock().clear();
    }

    #[test]
    fn chooses_the_nearest_complete_gap_page() {
        let mut maps = vec![map(0x1000, 0x3000), map(0x5000, 0x8000)];
        let candidates = gap_candidates(&maps, 0x4000, 0x5000, 0x1000, 0x1000, None).unwrap();
        assert_eq!(candidates[0], 0x4000);

        Arena::anonymous(0x4000, 0x1000, false, libc::PROT_READ | libc::PROT_WRITE)
            .record_in(&mut maps);
        let candidates = gap_candidates(&maps, 0x4000, 0x5000, 0x1000, 0x1000, None).unwrap();
        assert_eq!(candidates[0], 0x3000);

        let candidates =
            gap_candidates(&[map(0x1000, 0x3800)], 0x4000, 0x1000, 0x1000, 0x1000, None).unwrap();
        assert_eq!(candidates[0], 0x4000);
    }

    #[test]
    fn unconstrained_distance_still_honours_relay_windows() {
        let _guard = crate::sys::recover_lock(crate::inline::INLINE_TEST_LOCK.lock());
        let target = 0x2000_0000;
        let maps = vec![
            map(target - 0x1000, target),
            map(target + 0x1000, target + 0x2000),
        ];

        // SAFETY: the synthetic maps name an unmapped page, the arena owns the
        // new mapping, and the closure only records the candidate address.
        let (arena, address) = unsafe {
            Arena::allocate_near(
                &maps,
                target,
                usize::MAX,
                0x1000,
                0x1000,
                ArenaPlacement {
                    direct: None,
                    allowed: Some((target, target + 0x1000)),
                },
                Ok,
            )
        }
        .unwrap();

        assert_eq!(arena.address(), target);
        assert_eq!(address, target);
    }

    #[test]
    fn reserved_arena_is_consumed_and_survives_release() {
        let _guard = crate::sys::recover_lock(crate::inline::INLINE_TEST_LOCK.lock());
        pool_lock().clear();
        let page_size = crate::sys::page_size().unwrap();
        // SAFETY: this test owns the complete anonymous mapping.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        let address = mapping as usize;
        insert_pool_range(address, page_size);
        let maps = Vec::new();

        // SAFETY: the synthetic arena is not a live mapping, but reservation
        // consumption returns before any mapping operation.
        let (allocated, ()) = unsafe {
            Arena::allocate_near(
                &maps,
                address,
                0x10000,
                page_size,
                page_size,
                ArenaPlacement {
                    direct: None,
                    allowed: None,
                },
                |_| Ok(()),
            )
        }
        .unwrap();

        assert_eq!(allocated.address, address);
        assert!(allocated.reserved);
        assert!(pool_lock().is_empty());
        // SAFETY: reserved pages return to the process-wide pool instead of
        // being unmapped.
        unsafe { allocated.release() }.unwrap();
        assert_eq!(*pool_lock().get(&address).unwrap(), page_size);
        // SAFETY: the test owns the mapping and no code remains in it.
        assert_eq!(unsafe { libc::munmap(mapping, page_size) }, 0);
        pool_lock().clear();
    }

    #[test]
    fn pool_allocation_selects_inside_the_distance_window() {
        let _guard = crate::sys::recover_lock(crate::inline::INLINE_TEST_LOCK.lock());
        pool_lock().clear();
        insert_pool_range(0x1000, 0x3000);

        // SAFETY: the synthetic pool range is consumed without mapping.
        let (arena, ()) = unsafe {
            Arena::allocate_near(
                &[],
                0x3000,
                0x1000,
                0x1000,
                0x1000,
                ArenaPlacement {
                    direct: None,
                    allowed: None,
                },
                |_| Ok(()),
            )
        }
        .unwrap();

        assert_eq!(arena.address, 0x3000);
        assert_eq!(*pool_lock().get(&0x1000).unwrap(), 0x2000);
        let boundary = take_pool_arena(0x1000, 0x1000, 0x1000, Some((0x2000, 0x2000)), 0x1000, &[])
            .expect("the inclusive upper bound is a valid arena start");
        assert_eq!(boundary.address, 0x2000);
        assert_eq!(*pool_lock().get(&0x1000).unwrap(), 0x1000);
        pool_lock().clear();
    }

    #[test]
    fn pool_generation_failure_tries_the_next_candidate() {
        let _guard = crate::sys::recover_lock(crate::inline::INLINE_TEST_LOCK.lock());
        pool_lock().clear();
        let page_size = crate::sys::page_size().unwrap();
        let length = page_size
            .checked_mul(3)
            .expect("test mapping length overflow");
        // SAFETY: this test owns the complete anonymous mapping.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        let first = mapping as usize;
        let third = first + 2 * page_size;
        // The middle page stays mapped but is not registered in the pool, so
        // the two pool ranges remain separate and the final unmap owns all
        // three pages.
        insert_pool_range(first, page_size);
        insert_pool_range(third, page_size);
        let attempts = std::cell::Cell::new(0_usize);

        // SAFETY: the synthetic pool ranges are consumed without mapping and
        // the closure only records the candidate address.
        let (arena, ()) = unsafe {
            Arena::allocate_near(
                &[],
                third,
                2 * page_size,
                page_size,
                page_size,
                ArenaPlacement {
                    direct: None,
                    allowed: None,
                },
                |_| {
                    if attempts.replace(attempts.get() + 1) == 0 {
                        Err(Error::NoNearbyMemory)
                    } else {
                        Ok(())
                    }
                },
            )
        }
        .unwrap();

        assert_eq!(arena.address(), first);
        assert_eq!(attempts.get(), 2);
        // SAFETY: the arena belongs to this test and no code remains in it.
        unsafe { arena.release() }.unwrap();
        pool_lock().clear();
        // SAFETY: this test owns the remaining mapped pages.
        assert_eq!(unsafe { libc::munmap(mapping, length) }, 0);
    }

    #[test]
    fn preserves_mmap_failure() {
        // Bionic's allocator treats a failed mmap as fatal, so the failure is
        // injected before the kernel is asked for a page rather than through
        // a process-wide seccomp filter.
        let _guard = crate::sys::recover_lock(crate::inline::INLINE_TEST_LOCK.lock());
        let _injection_guard =
            crate::sys::recover_lock(crate::sys::tests::SYSCALL_INJECTION_LOCK.lock());
        clear_pool_for_tests();
        // Complete every file-reading setup before arming: growing a std Vec
        // can fault in new pages on this host, and the injection must name
        // only the arena mapping attempt.
        let maps = crate::read_self_maps().unwrap();
        let fd = crate::sys::open_self_mem().unwrap();
        let marker = (merge_candidates as *const ()).expose_provenance();
        let target = maps
            .iter()
            .find(|map| map.contains(marker))
            .map(|map| map.start)
            .unwrap_or(marker);
        crate::sys::fail_next_map_times(2);
        // SAFETY: the injected mmap failure returns before any mapping is
        // created, so no allocation contract can be violated.
        let error = unsafe {
            Arena::allocate_near(
                &maps,
                target,
                usize::MAX,
                crate::sys::page_size().unwrap(),
                crate::sys::page_size().unwrap(),
                ArenaPlacement {
                    direct: Some((libc::PROT_READ | libc::PROT_EXEC, fd)),
                    allowed: None,
                },
                |_| Ok(()),
            )
        }
        .err()
        .expect("mmap rejection unexpectedly succeeded");
        crate::sys::tests::restore_next_map();
        assert!(crate::sys::close_self_mem(fd).is_none());
        assert!(matches!(
            error,
            Error::SystemCall {
                operation: "mmap",
                ..
            }
        ));
    }

    #[test]
    fn old_kernel_hint_reserves_the_selected_gap() {
        let _guard = crate::sys::recover_lock(crate::inline::INLINE_TEST_LOCK.lock());
        let _injection_guard =
            crate::sys::recover_lock(crate::sys::tests::SYSCALL_INJECTION_LOCK.lock());
        clear_pool_for_tests();
        let page_size = crate::sys::page_size().unwrap();
        let length = page_size
            .checked_mul(3)
            .expect("test mapping length overflow");
        // Keep the gap away from top-down malloc mappings made by procfs parsing.
        // SAFETY: this is only a hint; the test owns the returned mapping.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::with_exposed_provenance_mut(0x1000_0000),
                length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        let target = mapping as usize + page_size;
        // SAFETY: the middle page is owned by this test and is intentionally
        // returned to the kernel as the placement gap.
        assert_eq!(unsafe { libc::munmap(target as *mut _, page_size) }, 0);
        crate::sys::fail_next_map_with_einval();
        let arena = map_fixed_pool_near(target, page_size, page_size, page_size, None)
            .expect("hint fallback did not reserve the gap");
        crate::sys::restore_next_map_with_einval();
        assert_eq!(arena.address(), target);
        // SAFETY: the complete test mapping, including the reserved middle
        // page, is owned by this test.
        assert_eq!(unsafe { libc::munmap(mapping, length) }, 0);
    }

    #[test]
    fn unpublished_arena_cleanup_failure_reports_cleanup_pending() {
        // The arena never received a published entry and no target was
        // touched, so an unreleasable mapping is reported to the caller
        // instead of terminating the process.
        let _guard = crate::sys::recover_lock(crate::inline::INLINE_TEST_LOCK.lock());
        let _injection_guard =
            crate::sys::recover_lock(crate::sys::tests::SYSCALL_INJECTION_LOCK.lock());
        clear_pool_for_tests();
        let maps = crate::read_self_maps().unwrap();
        let fd = crate::sys::open_self_mem().unwrap();
        let marker = (merge_candidates as *const ()).expose_provenance();
        let target = maps
            .iter()
            .find(|map| map.contains(marker))
            .map(|map| map.start)
            .unwrap_or(marker);
        crate::sys::fail_next_map();
        crate::sys::fail_next_unmap();
        // SAFETY: the injected unmap failure means no new mapping is released;
        // the allocation contract is exercised without a live arena.
        let error = unsafe {
            Arena::allocate_near(
                &maps,
                target,
                usize::MAX,
                crate::sys::page_size().unwrap(),
                crate::sys::page_size().unwrap(),
                ArenaPlacement {
                    direct: Some((libc::PROT_READ | libc::PROT_EXEC, fd)),
                    allowed: None,
                },
                |_| Err::<(), _>(Error::NoNearbyMemory),
            )
        }
        .err()
        .expect("generation always fails");
        crate::sys::tests::restore_next_unmap();
        assert!(crate::sys::close_self_mem(fd).is_none());
        assert!(
            matches!(error, Error::InlineCleanupPending(_)),
            "unexpected error: {error:?}"
        );
    }
}

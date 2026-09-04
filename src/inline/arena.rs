use crate::maps::{DeviceId, MapInfo, MapPerms};
use crate::{Error, Result};

const MAP_FIXED_NOREPLACE: i32 = 0x100000;

#[derive(Clone, Copy)]
pub(super) struct Arena {
    address: usize,
    length: usize,
    /// Mapped with its final protection at birth; writes go through the
    /// forced-access channel instead of a writable mapping.
    direct: bool,
}

impl Arena {
    pub(super) unsafe fn allocate_near<T>(
        maps: &[MapInfo],
        target: usize,
        max_distance: usize,
        page_size: usize,
        length: usize,
        direct: Option<(i32, usize)>,
        mut generate: impl FnMut(usize) -> Result<T>,
    ) -> Result<(Self, T)> {
        if length == 0 || !length.is_multiple_of(page_size) {
            return Err(Error::ArithmeticOverflow);
        }
        let mut candidates = merge_candidates(maps, target, max_distance, page_size, length)?;
        candidates.extend(gap_candidates(
            maps,
            target,
            max_distance,
            page_size,
            length,
        )?);
        candidates.sort_unstable_by_key(|candidate| candidate.abs_diff(target));
        candidates.dedup();
        let mut mapped_candidate = false;
        let mut map_error = None;
        // The exact pass runs first: an occupied candidate then fails with
        // EEXIST and costs nothing, whereas the hint pass has to map and unmap
        // every candidate the kernel decides to place somewhere unusable. Old
        // kernels reject MAP_FIXED_NOREPLACE with EINVAL; the fallback pass
        // then retries the same candidates with a plain address hint, and the
        // address check below discards any mapping the kernel misplaced.
        for exact in [true, false] {
            for &candidate in &candidates {
                let flags = if exact { MAP_FIXED_NOREPLACE } else { 0 };
                let address = match direct {
                    // SAFETY: fixed candidates name complete captured ranges;
                    // ordinary mmap treats the same address only as a hint.
                    Some((protection, _)) => {
                        let mapped = unsafe {
                            crate::sys::map_exec_anonymous(candidate, length, protection, flags)
                        };
                        match mapped {
                            Ok(address) => address,
                            Err(error) => {
                                if !exact || !fixed_collision(&error) {
                                    map_error = Some(error);
                                }
                                continue;
                            }
                        }
                    }
                    _ => match unsafe { crate::sys::map_rw_anonymous(candidate, length, flags) } {
                        Ok(address) => address,
                        Err(error) => {
                            if !exact || !fixed_collision(&error) {
                                map_error = Some(error);
                            }
                            continue;
                        }
                    },
                };
                mapped_candidate = true;
                if (exact && address != candidate) || address.abs_diff(target) > max_distance {
                    // SAFETY: this call owns the unsuitable mapping. There is no
                    // handle through which a failed cleanup could be retried, so
                    // the mapping leaks; no target byte has been written, so the
                    // caller decides what a leaked mapping is worth.
                    if let Err(error) = unsafe { crate::sys::unmap(address, length) } {
                        return Err(super::cleanup_pending(error));
                    }
                    continue;
                }

                let arena = Self {
                    address,
                    length,
                    direct: direct.is_some(),
                };
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
                        if let Err(unmap_error) = unsafe { arena.unmap() } {
                            return Err(super::cleanup_pending(unmap_error));
                        }
                        if !matches!(error, Error::NoNearbyMemory) {
                            return Err(error);
                        }
                    }
                }
            }
        }
        if !mapped_candidate && let Some(error) = map_error {
            return Err(error);
        }
        Err(Error::NoNearbyMemory)
    }

    pub(super) const fn address(&self) -> usize {
        self.address
    }

    /// Combines two adjacent arenas so a batch release can use one `munmap`.
    pub(super) fn coalesce_with(self, next: Self) -> Option<Self> {
        let end = self.address.checked_add(self.length)?;
        let length = self.length.checked_add(next.length)?;
        (self.direct == next.direct && end == next.address).then_some(Self {
            address: self.address,
            length,
            direct: self.direct,
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
        // SAFETY: the just-written range remains live and readable.
        unsafe { crate::sys::flush_instruction_cache_ranges(&[(self.address, end)]) }
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
            // SAFETY: the direct arena is caller-owned private memory and the
            // forced-access descriptor covers its complete range.
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

    pub(super) unsafe fn unmap(&self) -> Result<()> {
        // SAFETY: the caller guarantees that no generated entry is in use and
        // retains this ledger when the syscall fails.
        unsafe { crate::sys::unmap(self.address, self.length) }
    }
}

fn fixed_collision(error: &Error) -> bool {
    matches!(
        error,
        Error::SystemCall { source, .. } if source.raw_os_error() == Some(libc::EEXIST)
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
) -> Result<Vec<usize>> {
    let low = align_up(target.saturating_sub(max_distance), page_size)?;
    let high = crate::sys::page_start(target.saturating_add(max_distance), page_size);
    if low > high {
        return Err(Error::NoNearbyMemory);
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
    if candidates.is_empty() {
        return Err(Error::NoNearbyMemory);
    }
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
        candidates.push(target_page.clamp(first, last));
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
    fn chooses_the_nearest_complete_gap_page() {
        let mut maps = vec![map(0x1000, 0x3000), map(0x5000, 0x8000)];
        let candidates = gap_candidates(&maps, 0x4000, 0x5000, 0x1000, 0x1000).unwrap();
        assert_eq!(candidates[0], 0x4000);

        Arena {
            address: 0x4000,
            length: 0x1000,
            direct: false,
        }
        .record_in(&mut maps);
        let candidates = gap_candidates(&maps, 0x4000, 0x5000, 0x1000, 0x1000).unwrap();
        assert_eq!(candidates[0], 0x3000);

        let candidates =
            gap_candidates(&[map(0x1000, 0x3800)], 0x4000, 0x1000, 0x1000, 0x1000).unwrap();
        assert_eq!(candidates[0], 0x4000);
    }

    #[test]
    fn preserves_mmap_failure() {
        const CHILD: &str = "OMHOOK_ARENA_MMAP_FAILURE_CHILD";
        if std::env::var_os(CHILD).is_some() {
            #[cfg(any(target_arch = "x86", target_arch = "arm"))]
            let syscall = syscalls::Sysno::mmap2;
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            let syscall = syscalls::Sysno::mmap;
            let page_size = crate::sys::page_size().unwrap();
            let maps = crate::read_self_maps().unwrap();
            // Bionic's allocator treats a failed mmap as a fatal error, so
            // the child bounds candidate collection to a few live mappings
            // instead of prewarming size classes the allocator quarantines.
            let maps = &maps[..maps.len().min(4)];
            crate::sys::tests::install_test_seccomp_errno(&[syscall]);
            let error = unsafe {
                Arena::allocate_near(
                    maps,
                    maps[0].start,
                    usize::MAX,
                    page_size,
                    page_size,
                    None,
                    |_| Ok(()),
                )
            }
            .err()
            .expect("mmap rejection unexpectedly succeeded");
            assert!(matches!(
                error,
                Error::SystemCall {
                    operation: "mmap",
                    ..
                }
            ));
            // SAFETY: the child has completed its only assertion. Returning
            // to the Android test harness could require another mmap, which
            // this process deliberately rejects.
            let _ = unsafe { syscalls::raw_syscall!(syscalls::Sysno::exit_group, 0) };
            crate::sys::fail_stop();
        }

        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "inline::arena::tests::preserves_mmap_failure",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn unpublished_arena_cleanup_failure_reports_cleanup_pending() {
        // The arena never received a published entry and no target was
        // touched, so an unreleasable mapping is reported to the caller
        // instead of terminating the process.
        const CHILD: &str = "OMHOOK_ARENA_MUNMAP_FAILURE_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let page_size = crate::sys::page_size().unwrap();
            let maps = crate::read_self_maps().unwrap();
            let error = unsafe {
                Arena::allocate_near(
                    &maps,
                    maps[0].start,
                    usize::MAX,
                    page_size,
                    page_size,
                    None,
                    |_| {
                        crate::sys::tests::install_test_seccomp_errno(&[syscalls::Sysno::munmap]);
                        Err::<(), _>(Error::NoNearbyMemory)
                    },
                )
            }
            .err()
            .expect("generation always fails in this child");
            assert!(
                matches!(error, Error::InlineCleanupPending(_)),
                "unexpected error: {error:?}"
            );
            crate::sys::tests::exit_seccomp_child();
        }

        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "inline::arena::tests::unpublished_arena_cleanup_failure_reports_cleanup_pending",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success());
    }
}

//! Byte-preserving parsing of Linux and Android `/proc/<pid>/maps` snapshots.

use crate::{Error, Result};
use log::debug;
use std::ffi::OsString;
use std::fs;
use std::io::{BufRead, BufReader};
use std::ops::BitOr;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

mod hook;
mod smaps;

pub(crate) use hook::MappingSnapshot;
pub(crate) use hook::find_map_containing;
#[cfg(test)]
pub(crate) use smaps::SmapVmFlags;
#[cfg(target_arch = "aarch64")]
pub(crate) use smaps::read_self_smaps_for_ranges;
#[cfg(all(test, feature = "inline", target_arch = "aarch64"))]
pub(crate) use smaps::tests::{reset_smaps_reads, smaps_reads};
#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) use smaps::validate_page_write_access;
pub(crate) use smaps::{SmapInfo, extend_self_smaps_for_ranges};

/// Linux device major/minor pair used by `/proc/<pid>/maps`.
///
/// Anonymous mappings conventionally use `(0, 0)` and inode zero.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct DeviceId {
    /// Device major number.
    pub major: u32,
    /// Device minor number.
    pub minor: u32,
}

impl DeviceId {
    /// Creates a device identifier from its major and minor numbers.
    pub const fn new(major: u32, minor: u32) -> Self {
        Self { major, minor }
    }
}

/// Permission bits from a `/proc/<pid>/maps` entry.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MapPerms(u8);

impl MapPerms {
    /// The mapping can be read.
    pub const READ: Self = Self(1 << 0);
    /// The mapping can be written.
    pub const WRITE: Self = Self(1 << 1);
    /// The mapping can be executed.
    pub const EXEC: Self = Self(1 << 2);

    pub(crate) const fn empty() -> Self {
        Self(0)
    }

    /// Returns whether all requested permission bits are set.
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for MapPerms {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

/// One point-in-time entry from `/proc/<pid>/maps`.
///
/// Addresses belong to the process whose snapshot was read. An entry does not
/// prove that its mapping still exists, and an address from another process
/// must not be dereferenced in the current process.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MapInfo {
    /// Inclusive mapping start address.
    pub start: usize,
    /// Exclusive mapping end address.
    pub end: usize,
    /// Mapping permissions.
    pub perms: MapPerms,
    /// Whether the mapping is private (`p`) rather than shared (`s`).
    pub is_private: bool,
    /// File offset corresponding to [`MapInfo::start`].
    pub offset: u64,
    /// Backing device, or `(0, 0)` for an anonymous mapping.
    pub device: DeviceId,
    /// Backing inode, or zero for an anonymous mapping.
    pub inode: u64,
    /// Byte-preserving path or kernel mapping label when present.
    ///
    /// The value need not be valid UTF-8 and is not used as file identity.
    pub path: Option<PathBuf>,
}

impl MapInfo {
    /// Returns whether `address` lies in this mapping.
    pub const fn contains(&self, address: usize) -> bool {
        self.start <= address && address < self.end
    }
}

/// Reads a point-in-time snapshot of `/proc/self/maps`.
///
/// # Examples
///
/// ```rust,no_run
/// use omhook::{MapPerms, read_self_maps};
///
/// fn main() -> omhook::Result<()> {
///     let main_address = main as *const () as usize;
///     let maps = read_self_maps()?;
///     let code = maps
///         .iter()
///         .find(|map| map.contains(main_address))
///         .expect("main is missing from the process map");
///     assert!(code.perms.contains(MapPerms::EXEC));
///     Ok(())
/// }
/// ```
///
/// # Errors
///
/// Returns [`Error::Io`] when the proc file cannot be read or
/// [`Error::InvalidMapsLine`] when an entry is malformed.
/// Snapshots torn by concurrent mapping changes in this process are re-read
/// a bounded number of times before the typed error is returned.
pub fn read_self_maps() -> Result<Vec<MapInfo>> {
    debug!("self maps snapshot requested");
    let maps = retry_transient_procfs_parse(|| read_maps(PathBuf::from("/proc/self/maps")))
        .inspect_err(|_| debug!("self maps snapshot failed"))?;
    debug!("self maps snapshot complete: entries={}", maps.len());
    Ok(maps)
}

/// Reads one parse of `/proc/<pid>/maps`.
///
/// This general inspection API can read another process when permissions allow;
/// hook installers still modify only the current process. Returned addresses
/// belong to the selected process and are not pointers in the caller.
/// A concurrent remap in the selected process can produce a list that is
/// line-valid but not one coherent layout; retrying and consistency checks
/// are the caller's job.
///
/// # Errors
///
/// Returns [`Error::Io`] when the proc file cannot be read or
/// [`Error::InvalidMapsLine`] when an entry is malformed.
pub fn read_process_maps(pid: u32) -> Result<Vec<MapInfo>> {
    debug!("process maps snapshot requested");
    let path = PathBuf::from("/proc").join(pid.to_string()).join("maps");
    let maps = read_maps(path).inspect_err(|_| debug!("process maps snapshot failed"))?;
    debug!("process maps snapshot complete: entries={}", maps.len());
    Ok(maps)
}

fn read_maps(path: PathBuf) -> Result<Vec<MapInfo>> {
    let file = fs::File::open(path)?;
    let mut reader = BufReader::new(file);
    let mut maps = Vec::new();
    let mut previous_start = None;
    scan_lines(&mut reader, |line| {
        if line.is_empty() {
            return Ok(false);
        }
        let map = parse_line(line, true)?;
        if previous_start.is_some_and(|start| start > map.start) {
            return Err(invalid_maps_line(line));
        }
        previous_start = Some(map.start);
        if map.start < map.end {
            maps.push(map);
        }
        Ok(false)
    })?;
    Ok(maps)
}

/// Re-reads a self-procfs snapshot whose parse failed transiently.
///
/// Another thread of this process may map, remap, or unmap memory while
/// `/proc/self/maps` or `smaps` is being read, and procfs emits rows from
/// that changing table: one read can observe a truncated line or temporarily
/// unordered entries. Such a snapshot is inconsistent rather than malformed,
/// so a bounded retry with a thread yield recovers it; persistent parse
/// failures still return their typed error.
pub(crate) fn retry_transient_procfs_parse<T>(mut read: impl FnMut() -> Result<T>) -> Result<T> {
    const ATTEMPTS: usize = 8;
    let mut attempt = 0;
    loop {
        attempt += 1;
        match read() {
            Ok(value) => return Ok(value),
            Err(error)
                if attempt < ATTEMPTS
                    && match &error {
                        Error::InvalidMapsLine(_) | Error::InvalidSmaps(_) => true,
                        Error::Io(source) => source.kind() == std::io::ErrorKind::Interrupted,
                        _ => false,
                    } =>
            {
                if attempt == 1 {
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                std::thread::yield_now();
            }
            Err(error) => return Err(error),
        }
    }
}

pub(crate) fn read_self_maps_pathless() -> Result<Vec<MapInfo>> {
    // A full snapshot parses every row while keeping small-stack callers safe.
    const FULL_MAPS_READ_SIZE: usize = 12 * 1024;
    let fd = crate::sys::open_self_proc_file(b"maps", (libc::O_RDONLY | libc::O_CLOEXEC) as usize)
        .map_err(|errno| Error::system_call("openat", errno))?;
    let result = {
        let mut reader = crate::sys::RawProcReader::<FULL_MAPS_READ_SIZE>::new(fd);
        let mut first_attempt = true;
        retry_transient_procfs_parse(|| {
            if first_attempt {
                first_attempt = false;
            } else {
                reader
                    .rewind()
                    .map_err(|errno| Error::system_call("lseek", errno))?;
            }
            read_maps_for_ranges(&mut reader, &[(0, usize::MAX)], false)
        })
    };
    // SAFETY: fd is owned by this call, the reader is finished, and the
    // descriptor is never reused afterwards.
    let close_result = unsafe { crate::sys::close_procmap(fd) };
    match (result, close_result) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(close)) => Err(Error::system_call("close", close)),
        (Ok(maps), Ok(())) => Ok(maps),
    }
}

/// Reads an image extent derived from its first live mapping in the same scan.
#[cfg(all(feature = "plt", target_pointer_width = "64"))]
pub(crate) fn read_self_maps_for_image(
    start: usize,
    mut image_end: impl FnMut(&MapInfo) -> Result<usize>,
) -> Result<Vec<MapInfo>> {
    #[cfg(target_arch = "aarch64")]
    const MAPS_READ_SIZE: usize = 1536;
    #[cfg(not(target_arch = "aarch64"))]
    const MAPS_READ_SIZE: usize = 12 * 1024;
    const FIRST_READ_SIZE: usize = if cfg!(target_arch = "aarch64") {
        768
    } else {
        MAPS_READ_SIZE
    };
    let seed_end = start.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
    let fd = crate::sys::open_self_proc_file(b"maps", (libc::O_RDONLY | libc::O_CLOEXEC) as usize)
        .map_err(|errno| Error::system_call("openat", errno))?;
    let result = (|| {
        if let Some(mut maps) = query_self_maps_with_fd(fd, &[(start, seed_end)])? {
            let first = maps.first().ok_or(Error::UnmappedRead {
                address: start,
                length: 1,
            })?;
            let end = image_end(first)?;
            if end <= start {
                return Err(Error::ArithmeticOverflow);
            }
            if end <= first.end {
                return Ok(maps);
            }
            if let Some(tail) = query_self_maps_with_fd(fd, &[(first.end, end)])? {
                maps.extend(tail);
                sort_dedup_procmap_maps(&mut maps);
                return Ok(maps);
            }
        }
        let mut reader = crate::sys::RawProcReader::<MAPS_READ_SIZE, FIRST_READ_SIZE>::new(fd);
        let mut first_attempt = true;
        retry_transient_procfs_parse(|| {
            if first_attempt {
                first_attempt = false;
            } else {
                reader
                    .rewind()
                    .map_err(|errno| Error::system_call("lseek", errno))?;
            }
            read_maps_for_image(&mut reader, start, &mut image_end)
        })
    })();
    // SAFETY: fd is owned by this call and is never reused after closing.
    let close_result = unsafe { crate::sys::close_procmap(fd) };
    match (result, close_result) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(close)) => Err(Error::system_call("close", close)),
        (Ok(maps), Ok(())) => Ok(maps),
    }
}

pub(crate) fn read_self_maps_for_ranges(ranges: &[(usize, usize)]) -> Result<Vec<MapInfo>> {
    #[cfg(target_arch = "aarch64")]
    const MAPS_READ_SIZE: usize = 1536;
    #[cfg(not(target_arch = "aarch64"))]
    const MAPS_READ_SIZE: usize = 12 * 1024;
    const FIRST_READ_SIZE: usize = if cfg!(target_arch = "aarch64") {
        768
    } else {
        MAPS_READ_SIZE
    };
    if ranges.is_empty() {
        return Ok(Vec::new());
    }
    let fd = crate::sys::open_self_proc_file(b"maps", (libc::O_RDONLY | libc::O_CLOEXEC) as usize)
        .map_err(|errno| Error::system_call("openat", errno))?;
    // One descriptor serves both channels: the PROCMAP_QUERY fast path, and
    // after an unsupported ioctl, a rewind plus the text scan. Opening twice
    // would double the per-call procfs traffic on kernels without the ioctl.
    //
    let result = (|| -> Result<Vec<MapInfo>> {
        let queried = query_self_maps_with_fd(fd, ranges)?;
        if let Some(mut maps) = queried {
            sort_dedup_procmap_maps(&mut maps);
            return Ok(maps);
        }
        let mut reader = crate::sys::RawProcReader::<MAPS_READ_SIZE, FIRST_READ_SIZE>::new(fd);
        let mut first_attempt = true;
        retry_transient_procfs_parse(|| {
            // A fresh descriptor starts at offset zero; only a retry after a
            // torn snapshot needs to rewind the consumed stream.
            if first_attempt {
                first_attempt = false;
            } else {
                reader
                    .rewind()
                    .map_err(|errno| Error::system_call("lseek", errno))?;
            }
            read_maps_for_ranges(&mut reader, ranges, false)
        })
    })();
    // SAFETY: fd is owned by this call, the reader above is finished, and the
    // descriptor is never reused afterwards.
    let close_result = unsafe { crate::sys::close_procmap(fd) };
    match (result, close_result) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(close)) => Err(Error::system_call("close", close)),
        (Ok(maps), Ok(())) => Ok(maps),
    }
}

/// Reads VMAs covering ordered target ranges plus one allocation window.
///
/// One procfs descriptor serves every range, so an install pays one open/io
/// sequence even though it needs both the target and arena neighborhoods.
/// The PROCMAP_QUERY fast path answers one VMA per ioctl, so its results span
/// several short queries rather than one text scan; every consumer of this
/// snapshot revalidates mapping identity and target bytes before mutating, so
/// a layout change between ioctls fails closed instead of installing.
#[cfg(all(feature = "inline", not(target_arch = "arm")))]
pub(crate) fn read_self_maps_for_ordered_ranges_with_window(
    target_ranges: &[(usize, usize)],
    window: (usize, usize),
) -> Result<Vec<MapInfo>> {
    let fd = crate::sys::open_self_proc_file(b"maps", (libc::O_RDONLY | libc::O_CLOEXEC) as usize)
        .map_err(|errno| Error::system_call("openat", errno))?;
    let mut all_ranges = target_ranges.to_vec();
    all_ranges.push(window);
    all_ranges.sort_unstable();
    all_ranges = coalesce_ordered_ranges(all_ranges);
    let result = (|| -> Result<Vec<MapInfo>> {
        Ok(match query_self_maps_with_fd(fd, &all_ranges)? {
            Some(maps) => maps,
            None => {
                // One scan over the merged range list keeps the snapshot atomic:
                // scanning target and window separately could observe a mapping
                // change between the two passes and stitch a layout that never
                // existed. It also halves the procfs traffic on ioctl-less
                // kernels, which read the complete stream once per query.
                let mut reader = crate::sys::RawProcReader::<608>::new(fd);
                let mut first_attempt = true;
                retry_transient_procfs_parse(|| {
                    // A fresh descriptor starts at offset zero; only a retry
                    // after a torn snapshot needs to rewind.
                    if first_attempt {
                        first_attempt = false;
                    } else {
                        reader
                            .rewind()
                            .map_err(|errno| Error::system_call("lseek", errno))?;
                    }
                    read_maps_for_ranges(&mut reader, &all_ranges, false)
                })?
            }
        })
    })();
    let mut maps = match result {
        Ok(maps) => maps,
        Err(error) => {
            // SAFETY: fd is owned by this call and never reused afterwards.
            let _close_result = unsafe { crate::sys::close_procmap(fd) };
            return Err(error);
        }
    };
    sort_dedup_procmap_maps(&mut maps);
    // SAFETY: fd is owned by this call and never reused afterwards.
    if let Err(close) = unsafe { crate::sys::close_procmap(fd) } {
        return Err(Error::system_call("close", close));
    }
    Ok(maps)
}

#[cfg(all(feature = "inline", not(target_arch = "arm")))]
fn coalesce_ordered_ranges(mut ranges: Vec<(usize, usize)>) -> Vec<(usize, usize)> {
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ranges.len());
    for current in ranges.drain(..) {
        match merged.last_mut() {
            Some(previous) if previous.1 >= current.0 => previous.1 = previous.1.max(current.1),
            _ => merged.push(current),
        }
    }
    merged
}

/// Normalizes PROCMAP_QUERY results into procfs order without duplicates.
///
/// Each range is queried independently, so one VMA covering two ranges is
/// reported twice. Targeted maps consumers rely on procfs order and one entry
/// per VMA, exactly as `read_maps_for_ranges` yields them.
fn sort_dedup_procmap_maps(maps: &mut Vec<MapInfo>) {
    maps.sort_unstable_by_key(|map| map.start);
    maps.dedup_by(|current, next| {
        current.start == next.start
            && current.end == next.end
            && current.perms == next.perms
            && current.is_private == next.is_private
            && current.offset == next.offset
            && current.device == next.device
            && current.inode == next.inode
    });
}

fn query_self_maps_with_fd(fd: usize, ranges: &[(usize, usize)]) -> Result<Option<Vec<MapInfo>>> {
    if crate::sys::procmap_query_unsupported() {
        return Ok(None);
    }
    let mut maps = Vec::new();
    for &(start, end) in ranges {
        let mut address = start;
        while address < end {
            let mut query = crate::sys::ProcmapQuery::covering_or_next(address);
            // SAFETY: fd names this process's maps and query is initialized.
            let query = match unsafe { crate::sys::procmap_query(fd, &mut query) } {
                Ok(()) => query,
                Err(errno) => {
                    // COVERING_OR_NEXT_VMA returns ENOENT when the query
                    // address is above the process's highest VMA, which is a
                    // normal end of range, not unsupported ioctl plumbing.
                    if errno == syscalls::Errno::ENOENT {
                        break;
                    }
                    let unsupported = matches!(
                        errno,
                        syscalls::Errno::ENOTTY
                            | syscalls::Errno::ENOSYS
                            | syscalls::Errno::EINVAL
                            | syscalls::Errno::EACCES
                            | syscalls::Errno::EPERM
                    );
                    return if unsupported {
                        if matches!(errno, syscalls::Errno::ENOTTY | syscalls::Errno::EINVAL) {
                            crate::sys::record_procmap_query_unsupported();
                        }
                        Ok(None)
                    } else {
                        Err(Error::system_call("ioctl", errno))
                    };
                }
            };
            let vma_start =
                usize::try_from(query.vma_start).map_err(|_| Error::ArithmeticOverflow)?;
            let vma_end = usize::try_from(query.vma_end).map_err(|_| Error::ArithmeticOverflow)?;
            if vma_start >= vma_end {
                return Ok(None);
            }
            if vma_start >= end {
                break;
            }
            let perms = procmap_perms(query.vma_flags);
            maps.push(MapInfo {
                start: vma_start,
                end: vma_end,
                perms,
                is_private: procmap_is_private(query.vma_flags),
                offset: query.vma_offset,
                device: DeviceId::new(query.dev_major, query.dev_minor),
                inode: query.inode,
                path: None,
            });
            address = vma_end;
        }
    }
    Ok(Some(maps))
}

fn procmap_perms(vma_flags: u64) -> MapPerms {
    const VMA_READ: u64 = 0x01;
    const VMA_WRITE: u64 = 0x02;
    const VMA_EXEC: u64 = 0x04;

    let mut perms = MapPerms::empty();
    if vma_flags & VMA_READ != 0 {
        perms = perms | MapPerms::READ;
    }
    if vma_flags & VMA_WRITE != 0 {
        perms = perms | MapPerms::WRITE;
    }
    if vma_flags & VMA_EXEC != 0 {
        perms = perms | MapPerms::EXEC;
    }
    perms
}

const fn procmap_is_private(vma_flags: u64) -> bool {
    const VMA_SHARED: u64 = 0x08;
    vma_flags & VMA_SHARED == 0
}

pub(crate) fn page_ranges(
    addresses: impl IntoIterator<Item = usize>,
) -> Result<Vec<(usize, usize)>> {
    let page_size = crate::sys::page_size()?;
    let mut pages = addresses
        .into_iter()
        .map(|address| crate::sys::page_start(address, page_size))
        .collect::<Vec<_>>();
    pages.sort_unstable();
    pages.dedup();
    page_ranges_for_sorted_pages(pages, page_size)
}

pub(crate) fn page_ranges_for_sorted_pages(
    pages: impl IntoIterator<Item = usize>,
    page_size: usize,
) -> Result<Vec<(usize, usize)>> {
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for start in pages {
        let end = start
            .checked_add(page_size)
            .ok_or(Error::ArithmeticOverflow)?;
        match ranges.last_mut() {
            Some(previous) if previous.1 == start => previous.1 = end,
            Some(previous) if previous.1 > start => {}
            _ => ranges.push((start, end)),
        }
    }
    Ok(ranges)
}

#[cfg(test)]
fn parse_maps(contents: &[u8]) -> Result<Vec<MapInfo>> {
    parse_maps_with_paths(contents, true)
}

#[cfg(test)]
fn parse_maps_with_paths(contents: &[u8], keep_paths: bool) -> Result<Vec<MapInfo>> {
    // One entry per line, counted exactly. Estimating from the byte length
    // instead either over-allocates for path-bearing snapshots or leaves the
    // vector doubling its way up through a process with thousands of mappings.
    let mut maps = Vec::with_capacity(contents.iter().filter(|byte| **byte == b'\n').count());
    // The kernel emits mappings in ascending start order. A full snapshot is
    // read with one syscall sequence while mappings can change; a backwards
    // jump proves the lines are not one coherent snapshot, and downstream
    // consumers such as ordered lookups must not silently trust it.
    let mut previous_start = None;
    for line in contents.split(|byte| *byte == b'\n') {
        if !line.is_empty() {
            let map = parse_line(line, keep_paths)?;
            if previous_start.is_some_and(|start| start > map.start) {
                return Err(invalid_maps_line(line));
            }
            previous_start = Some(map.start);
            // GKI page-size migration kernels emit empty file-backed entries
            // when a whole VMA became padding. They cover no address, so skip
            // them while still validating and ordering every line above.
            if map.start < map.end {
                maps.push(map);
            }
        }
    }
    Ok(maps)
}

fn read_maps_for_ranges(
    mut reader: impl BufRead,
    ranges: &[(usize, usize)],
    keep_paths: bool,
) -> Result<Vec<MapInfo>> {
    if ranges.iter().any(|&(start, end)| start >= end)
        || ranges.windows(2).any(|pair| pair[0].1 > pair[1].0)
    {
        return Err(invalid_maps_line(b"target ranges are not ordered"));
    }
    let mut maps = Vec::with_capacity(ranges.len());
    let mut range_index = 0;
    let mut previous_start = None;
    scan_lines(&mut reader, |line| {
        if line.is_empty() {
            return Ok(false);
        }
        let (map_start, map_end, fields) = parse_address_prefix(line)?;
        if previous_start.is_some_and(|start| start > map_start) {
            return Err(unordered_maps_line(line));
        }
        previous_start = Some(map_start);
        while ranges
            .get(range_index)
            .is_some_and(|&(_, end)| end <= map_start)
        {
            range_index += 1;
        }
        let Some(&(start, end)) = ranges.get(range_index) else {
            return Ok(true);
        };
        if start < map_end && map_start < map_end && map_start < end {
            maps.push(parse_line_fields(
                line, map_start, map_end, fields, keep_paths,
            )?);
            return Ok(ranges.last().is_some_and(|&(_, end)| map_end >= end));
        }
        Ok(false)
    })?;
    Ok(maps)
}

#[cfg(all(feature = "plt", target_pointer_width = "64"))]
fn read_maps_for_image(
    mut reader: impl BufRead,
    start: usize,
    image_end: &mut impl FnMut(&MapInfo) -> Result<usize>,
) -> Result<Vec<MapInfo>> {
    // Ordinary loader segments, RELRO splits, and BSS fit without growing.
    let mut maps = Vec::with_capacity(6);
    let mut end = None;
    let mut previous_start = None;
    scan_lines(&mut reader, |line| {
        if line.is_empty() {
            return Ok(false);
        }
        let (map_start, map_end, fields) = parse_address_prefix(line)?;
        if previous_start.is_some_and(|previous| previous > map_start) {
            return Err(unordered_maps_line(line));
        }
        previous_start = Some(map_start);
        if end.is_some_and(|end| map_start >= end) {
            return Ok(true);
        }
        if map_end <= start || map_start == map_end {
            return Ok(false);
        }
        let map = parse_line_fields(line, map_start, map_end, fields, false)?;
        if end.is_none() {
            if map_start > start {
                return Err(Error::UnmappedRead {
                    address: start,
                    length: 1,
                });
            }
            let limit = image_end(&map)?;
            if limit <= start {
                return Err(Error::ArithmeticOverflow);
            }
            end = Some(limit);
        }
        let complete = end.is_some_and(|end| map.end >= end);
        maps.push(map);
        Ok(complete)
    })?;
    Ok(maps)
}

fn scan_lines(
    reader: &mut impl BufRead,
    mut visit: impl FnMut(&[u8]) -> Result<bool>,
) -> Result<()> {
    let mut partial = Vec::new();
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            if !partial.is_empty() {
                visit(trim_line_ending(&partial))?;
            }
            return Ok(());
        }

        let mut start = 0;
        while let Some(newline) = find_newline(&buffer[start..]) {
            let end = start + newline + 1;
            let stop = if partial.is_empty() {
                visit(trim_line_ending(&buffer[start..end]))?
            } else {
                partial.extend_from_slice(&buffer[start..end]);
                let stop = visit(trim_line_ending(&partial))?;
                partial.clear();
                stop
            };
            if stop {
                return Ok(());
            }
            start = end;
        }
        if start < buffer.len() {
            partial.extend_from_slice(&buffer[start..]);
        }
        let consumed = buffer.len();
        reader.consume(consumed);
    }
}

/// Word-at-a-time newline scan for procfs streams measured in megabytes.
#[inline(always)]
fn find_newline(buffer: &[u8]) -> Option<usize> {
    const ONES: usize = usize::from_ne_bytes([1; std::mem::size_of::<usize>()]);
    const HIGH: usize = ONES << 7;
    let word_size = std::mem::size_of::<usize>();
    let mut chunks = buffer.chunks_exact(word_size);
    let mut offset = 0;
    for chunk in &mut chunks {
        let Ok(bytes) = <[u8; std::mem::size_of::<usize>()]>::try_from(chunk) else {
            continue;
        };
        let word = usize::from_ne_bytes(bytes) ^ (usize::from(b'\n') * ONES);
        if word.wrapping_sub(ONES) & !word & HIGH != 0 {
            return chunk
                .iter()
                .position(|byte| *byte == b'\n')
                .map(|position| offset + position);
        }
        offset += word_size;
    }
    chunks
        .remainder()
        .iter()
        .position(|byte| *byte == b'\n')
        .map(|position| offset + position)
}

#[inline(always)]
fn trim_line_ending(line: &[u8]) -> &[u8] {
    line.strip_suffix(b"\n").unwrap_or(line)
}

fn parse_line(line: &[u8], keep_path: bool) -> Result<MapInfo> {
    let (start, end, fields) = parse_address_prefix(line)?;
    parse_line_fields(line, start, end, fields, keep_path)
}

fn parse_line_fields(
    line: &[u8],
    start: usize,
    end: usize,
    fields: &[u8],
    keep_path: bool,
) -> Result<MapInfo> {
    let Some((&[read, write, execute, sharing, separator], mut fields)) =
        fields.trim_ascii_start().split_first_chunk::<5>()
    else {
        return Err(invalid_maps_line(line));
    };
    if !matches!(read, b'r' | b'-')
        || !matches!(write, b'w' | b'-')
        || !matches!(execute, b'x' | b'-')
        || !matches!(sharing, b'p' | b's')
        || !separator.is_ascii_whitespace()
    {
        return Err(invalid_maps_line(line));
    }

    let mut perms = MapPerms::empty();
    if read == b'r' {
        perms.0 |= MapPerms::READ.0;
    }
    if write == b'w' {
        perms.0 |= MapPerms::WRITE.0;
    }
    if execute == b'x' {
        perms.0 |= MapPerms::EXEC.0;
    }

    fields = fields.trim_ascii_start();
    let offset =
        parse_ascii_number(&mut fields, 16, None).ok_or_else(|| invalid_maps_line(line))?;
    fields = fields.trim_ascii_start();
    let major =
        parse_ascii_number(&mut fields, 16, Some(b':')).ok_or_else(|| invalid_maps_line(line))?;
    let minor = parse_ascii_number(&mut fields, 16, None).ok_or_else(|| invalid_maps_line(line))?;
    let major = u32::try_from(major).map_err(|_| invalid_maps_line(line))?;
    let minor = u32::try_from(minor).map_err(|_| invalid_maps_line(line))?;
    fields = fields.trim_ascii_start();
    let inode = parse_ascii_number(&mut fields, 10, None).ok_or_else(|| invalid_maps_line(line))?;
    let path = if keep_path {
        let path = fields.trim_ascii_start();
        (!path.is_empty()).then(|| path_from_bytes(path))
    } else {
        None
    };

    Ok(MapInfo {
        start,
        end,
        perms,
        is_private: sharing == b'p',
        offset,
        device: DeviceId::new(major, minor),
        inode,
        path,
    })
}

fn parse_address_prefix(line: &[u8]) -> Result<(usize, usize, &[u8])> {
    let bytes = line.trim_ascii_start();
    let Some((start, separator)) = parse_hex_start(bytes) else {
        return Err(invalid_maps_line(line));
    };
    let Some((end, fields)) = parse_hex_prefix(&bytes[separator + 1..]) else {
        return Err(invalid_maps_line(line));
    };
    let start = usize::try_from(start).map_err(|_| invalid_maps_address(line))?;
    let end = usize::try_from(end).map_err(|_| invalid_maps_address(line))?;
    if start > end {
        return Err(invalid_maps_line(line));
    }
    Ok((start, end, fields))
}

#[inline(always)]
fn parse_hex_start(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut value = 0_u64;
    for (index, &byte) in bytes.iter().enumerate() {
        if byte == b'-' {
            if index == 0 {
                return None;
            }
            return Some((value, index));
        }
        let digit = match byte {
            b'0'..=b'9' => u64::from(byte - b'0'),
            b'a'..=b'f' => u64::from(byte - b'a' + 10),
            b'A'..=b'F' => u64::from(byte - b'A' + 10),
            _ => return None,
        };
        value = value.checked_mul(16)?.checked_add(digit)?;
    }
    None
}

#[inline(always)]
fn parse_hex_prefix(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let mut value = 0_u64;
    for (index, &byte) in bytes.iter().enumerate() {
        if byte.is_ascii_whitespace() {
            if index == 0 {
                return None;
            }
            return Some((value, &bytes[index..]));
        }
        let digit = match byte {
            b'0'..=b'9' => u64::from(byte - b'0'),
            b'a'..=b'f' => u64::from(byte - b'a' + 10),
            b'A'..=b'F' => u64::from(byte - b'A' + 10),
            _ => return None,
        };
        value = value.checked_mul(16)?.checked_add(digit)?;
    }
    if bytes.is_empty() {
        return None;
    }
    Some((value, &bytes[bytes.len()..]))
}

#[cold]
fn invalid_maps_address(line: &[u8]) -> Error {
    invalid_maps_line(line)
}

#[inline(always)]
fn parse_ascii_number(input: &mut &[u8], radix: u64, separator: Option<u8>) -> Option<u64> {
    let bytes = *input;
    let mut value = 0_u64;
    let mut digits = 0_usize;
    let hex = radix == 16;
    if radix != 10 && !hex {
        return None;
    }
    for (index, byte) in bytes.iter().copied().enumerate() {
        if separator.map_or_else(|| byte.is_ascii_whitespace(), |separator| byte == separator) {
            if index == 0 || (hex && digits > 16) {
                return None;
            }
            *input = if separator.is_some() {
                &bytes[index + 1..]
            } else {
                &bytes[index..]
            };
            return Some(value);
        }
        let digit = match byte {
            b'0'..=b'9' => u64::from(byte - b'0'),
            b'a'..=b'f' => u64::from(byte - b'a' + 10),
            b'A'..=b'F' => u64::from(byte - b'A' + 10),
            _ => return None,
        };
        if digit >= radix {
            return None;
        }
        if hex {
            value = value.wrapping_mul(radix).wrapping_add(digit);
        } else {
            value = value.checked_mul(radix)?.checked_add(digit)?;
        }
        digits += 1;
    }
    if bytes.is_empty() || separator.is_some() || (hex && digits > 16) {
        return None;
    }
    *input = &[];
    Some(value)
}

fn invalid_maps_line(line: &[u8]) -> Error {
    Error::InvalidMapsLine(line.to_vec())
}

#[cold]
fn unordered_maps_line(line: &[u8]) -> Error {
    invalid_maps_line(line)
}

fn path_from_bytes(path: &[u8]) -> PathBuf {
    PathBuf::from(OsString::from_vec(path.to_vec()))
}

#[cfg(test)]
pub(crate) mod tests;

//! Byte-preserving parsing of Linux and Android `/proc/<pid>/maps` snapshots.

use crate::{Error, Result};
use log::debug;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::ops::BitOr;
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

mod hook;
#[cfg(any(target_arch = "aarch64", test))]
mod smaps;

pub(crate) use hook::{MappingIdentity, find_map_containing};
#[cfg(target_arch = "aarch64")]
pub(crate) use smaps::{SmapInfo, read_self_smaps_for_ranges};

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

/// Reads a point-in-time snapshot of `/proc/<pid>/maps`.
///
/// This general inspection API can read another process when permissions allow;
/// hook installers still modify only the current process. Returned addresses
/// belong to the selected process and are not pointers in the caller.
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
    let contents = fs::read(path)?;
    parse_maps(&contents)
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
    const ATTEMPTS: usize = 3;
    let mut attempt = 0;
    loop {
        attempt += 1;
        match read() {
            Ok(value) => return Ok(value),
            Err(error)
                if matches!(error, Error::InvalidMapsLine(_) | Error::InvalidSmaps(_))
                    && attempt < ATTEMPTS =>
            {
                std::thread::yield_now();
            }
            Err(error) => return Err(error),
        }
    }
}

pub(crate) fn read_self_maps_pathless() -> Result<Vec<MapInfo>> {
    // Procfs reports no size, so this only picks a starting point. Sixteen
    // kibibytes covers a few hundred mappings without charging every small
    // process for the few that have thousands; `read_to_end` grows from here.
    retry_transient_procfs_parse(|| {
        let mut contents = Vec::with_capacity(16 * 1024);
        File::open("/proc/self/maps")?.read_to_end(&mut contents)?;
        parse_maps_with_paths(&contents, false)
    })
}

pub(crate) fn read_self_maps_for_ranges(ranges: &[(usize, usize)]) -> Result<Vec<MapInfo>> {
    if let Some(maps) = query_self_maps_for_ranges(ranges)? {
        return Ok(maps);
    }
    read_self_maps_ranges_with(ranges, false)
}

fn query_self_maps_for_ranges(ranges: &[(usize, usize)]) -> Result<Option<Vec<MapInfo>>> {
    const SELF_MAPS: &[u8] = b"/proc/self/maps\0";

    // SAFETY: SELF_MAPS is NUL-terminated and names this process's maps file.
    let fd = match unsafe { crate::sys::open_readonly(SELF_MAPS) } {
        Ok(fd) => fd,
        Err(error) => {
            let unsupported = matches!(error, Error::SystemCall { ref source, .. }
                if source.raw_os_error().is_some_and(|errno|
                    errno == libc::ENOTTY || errno == libc::EINVAL));
            return if unsupported { Ok(None) } else { Err(error) };
        }
    };
    let maps = query_self_maps_with_fd(fd, ranges)?;
    // SAFETY: fd is owned by this call and never reused afterwards.
    unsafe { crate::sys::close_procmap(fd)? };
    Ok(maps)
}

fn query_self_maps_with_fd(fd: usize, ranges: &[(usize, usize)]) -> Result<Option<Vec<MapInfo>>> {
    const VMA_READ: u64 = 0x01;
    const VMA_WRITE: u64 = 0x02;
    const VMA_EXEC: u64 = 0x04;
    const VMA_SHARED: u64 = 0x08;
    let mut maps = Vec::with_capacity(ranges.len());
    for &(start, end) in ranges {
        let mut address = start;
        while address < end {
            let mut query = crate::sys::ProcmapQuery::covering(address);
            // SAFETY: fd names this process's maps and query is initialized.
            let query = match unsafe { crate::sys::procmap_query(fd, &mut query) } {
                Ok(()) => query,
                Err(error) => {
                    let unsupported = matches!(error, Error::SystemCall { ref source, .. }
                        if source.raw_os_error().is_some_and(|errno|
                            errno == libc::ENOTTY || errno == libc::EINVAL));
                    return if unsupported { Ok(None) } else { Err(error) };
                }
            };
            let vma_start =
                usize::try_from(query.vma_start).map_err(|_| Error::ArithmeticOverflow)?;
            let vma_end = usize::try_from(query.vma_end).map_err(|_| Error::ArithmeticOverflow)?;
            if vma_start >= vma_end || !(vma_start..vma_end).contains(&address) {
                return Ok(None);
            }
            let mut perms = MapPerms::empty();
            if query.vma_flags & VMA_READ != 0 {
                perms = perms | MapPerms::READ;
            }
            if query.vma_flags & VMA_WRITE != 0 {
                perms = perms | MapPerms::WRITE;
            }
            if query.vma_flags & VMA_EXEC != 0 {
                perms = perms | MapPerms::EXEC;
            }
            maps.push(MapInfo {
                start: vma_start,
                end: vma_end,
                perms,
                is_private: query.vma_flags & VMA_SHARED == 0,
                offset: query.vma_offset,
                device: DeviceId::new(query.dev_major, query.dev_minor),
                inode: query.inode,
                path: None,
            });
            address = if vma_end < end { vma_end } else { end };
        }
    }
    Ok(Some(maps))
}

fn read_self_maps_ranges_with(ranges: &[(usize, usize)], keep_paths: bool) -> Result<Vec<MapInfo>> {
    if ranges.is_empty() {
        return Ok(Vec::new());
    }
    retry_transient_procfs_parse(|| {
        let file = File::open("/proc/self/maps")?;
        read_maps_for_ranges(
            BufReader::with_capacity(64 * 1024, file),
            ranges,
            keep_paths,
        )
    })
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
        if let Some(previous) = ranges.last_mut()
            && previous.1 == start
        {
            previous.1 = end;
        } else {
            ranges.push((start, end));
        }
    }
    Ok(ranges)
}

fn parse_maps(contents: &[u8]) -> Result<Vec<MapInfo>> {
    parse_maps_with_paths(contents, true)
}

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
            maps.push(map);
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
    let mut maps = Vec::new();
    let mut range_index = 0;
    let mut previous_start = None;
    scan_lines(&mut reader, |line| {
        if line.is_empty() {
            return Ok(false);
        }
        let (map_start, map_end, _) = parse_address_prefix(line)?;
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
        let Some(&(start, _)) = ranges.get(range_index) else {
            return Ok(true);
        };
        if start < map_end {
            maps.push(parse_line(line, keep_paths)?);
        }
        Ok(false)
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
        while let Some(newline) = buffer[start..].iter().position(|byte| *byte == b'\n') {
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

fn trim_line_ending(mut line: &[u8]) -> &[u8] {
    while line
        .last()
        .is_some_and(|byte| matches!(byte, b'\n' | b'\r'))
    {
        line = &line[..line.len() - 1];
    }
    line
}

fn parse_line(line: &[u8], keep_path: bool) -> Result<MapInfo> {
    let (start, end, mut fields) = parse_address_prefix(line)?;
    let permissions = take_field(&mut fields).ok_or_else(|| invalid_maps_line(line))?;

    let &[read, write, execute, sharing] = permissions else {
        return Err(invalid_maps_line(line));
    };
    if !matches!(read, b'r' | b'-')
        || !matches!(write, b'w' | b'-')
        || !matches!(execute, b'x' | b'-')
        || !matches!(sharing, b'p' | b's')
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
    let mut fields = line.trim_ascii_start();
    let start =
        parse_ascii_number(&mut fields, 16, Some(b'-')).ok_or_else(|| invalid_maps_line(line))?;
    let end = parse_ascii_number(&mut fields, 16, None).ok_or_else(|| invalid_maps_line(line))?;
    let start = usize::try_from(start).map_err(|_| invalid_maps_address(line))?;
    let end = usize::try_from(end).map_err(|_| invalid_maps_address(line))?;
    if start >= end {
        return Err(invalid_maps_line(line));
    }
    Ok((start, end, fields))
}

#[cold]
fn invalid_maps_address(line: &[u8]) -> Error {
    invalid_maps_line(line)
}

#[inline(always)]
fn parse_ascii_number(input: &mut &[u8], radix: u64, separator: Option<u8>) -> Option<u64> {
    let bytes = *input;
    let mut value = 0_u64;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if separator.map_or_else(|| byte.is_ascii_whitespace(), |separator| byte == separator) {
            if index == 0 {
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
        value = value.checked_mul(radix)?.checked_add(digit)?;
    }
    if bytes.is_empty() || separator.is_some() {
        return None;
    }
    *input = &[];
    Some(value)
}

fn take_field<'a>(input: &mut &'a [u8]) -> Option<&'a [u8]> {
    let start = input.iter().position(|byte| !byte.is_ascii_whitespace())?;
    let trimmed = &input[start..];
    let end = trimmed
        .iter()
        .position(u8::is_ascii_whitespace)
        .unwrap_or(trimmed.len());
    let (field, rest) = trimmed.split_at(end);
    *input = rest;
    (!field.is_empty()).then_some(field)
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
mod tests;

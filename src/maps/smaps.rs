use super::retry_transient_procfs_parse;
use super::{MapInfo, parse_address_prefix, parse_line_fields, scan_lines};
use crate::{Error, Result};
use std::io::BufRead;

const SMAPS_READ_SIZE: usize = 8192;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct SmapVmFlags {
    pub(crate) bti: bool,
    pub(crate) mte: bool,
    pub(crate) locked: bool,
    pub(crate) dont_dump: bool,
    pub(crate) dont_fork: bool,
    pub(crate) wipe_on_fork: bool,
    pub(crate) hugepage: bool,
    pub(crate) non_hugepage: bool,
    pub(crate) mixed_map: bool,
    pub(crate) io_map: bool,
    pub(crate) lock_on_fault: bool,
    pub(crate) sync: bool,
    pub(crate) unknown: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SmapInfo {
    pub(crate) map: MapInfo,
    pub(crate) vm_flags: SmapVmFlags,
    pub(crate) protection_key: u64,
}

/// Checks thread-local restrictions which ordinary mprotect cannot remove.
/// `pages` must be sorted, deduplicated page starts from readable mappings.
#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) fn validate_page_write_access(
    maps: &[MapInfo],
    pages: &[usize],
    page_size: usize,
) -> Result<()> {
    // The public contract requires readable targets; only readable keys with
    // write denial need a live maps-to-key check.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    let (restricted, bits_per_key) = {
        let pkru = u64::from(crate::sys::x86_pkru()?);
        ((pkru >> 1) & !pkru & 0x5555_5555, 2)
    };
    #[cfg(target_arch = "aarch64")]
    let (restricted, bits_per_key) = {
        let por = crate::sys::aarch64_por_el0();
        (por & !(por >> 2) & 0x1111_1111, 4)
    };
    if restricted == 0 || pages.is_empty() {
        return Ok(());
    }
    let ranges = super::page_ranges_for_sorted_pages(pages.iter().copied(), page_size)?;
    let mut smaps = Vec::new();
    extend_self_smaps_for_ranges(&mut smaps, &ranges)?;
    for &page in pages {
        let map = super::find_map_containing(maps, page, page_size).ok_or(Error::MappingChanged)?;
        let entry = smaps
            .iter()
            .find(|entry| entry.map.contains_range(page, page_size))
            .ok_or(Error::MappingChanged)?;
        if !super::MappingSnapshot::from_map(map).matches_at(&entry.map, page) {
            return Err(Error::MappingChanged);
        }
        let shift = u32::try_from(entry.protection_key)
            .ok()
            .and_then(|key| key.checked_mul(bits_per_key))
            .filter(|&shift| shift < 32)
            .ok_or(Error::InvalidSmaps("invalid protection key"))?;
        if restricted & (1 << shift) != 0 {
            return Err(Error::system_call(
                "pkey write access",
                syscalls::Errno::EACCES,
            ));
        }
    }
    Ok(())
}

/// Reads targeted `smaps` entries without backing paths. AArch64 consumers
/// use page-protection features, while private-file validation consumers use mapping
/// semantics on every supported architecture.
#[cfg(target_arch = "aarch64")]
pub(crate) fn read_self_smaps_for_ranges(ranges: &[(usize, usize)]) -> Result<Vec<SmapInfo>> {
    #[cfg(test)]
    tests::record_smaps_read();
    read_self_smaps_ranges_with(ranges, false)
}

pub(crate) fn extend_self_smaps_for_ranges(
    entries: &mut Vec<SmapInfo>,
    ranges: &[(usize, usize)],
) -> Result<()> {
    #[cfg(test)]
    tests::record_smaps_read();
    if ranges.is_empty() {
        return Ok(());
    }
    retry_transient_procfs_parse(|| {
        let fd =
            crate::sys::open_self_proc_file(b"smaps", (libc::O_RDONLY | libc::O_CLOEXEC) as usize)
                .map_err(|errno| Error::system_call("openat", errno))?;
        let mut reader = crate::sys::RawProcReader::<SMAPS_READ_SIZE>::new(fd);
        let result = read_smaps_for_ranges_with(&mut reader, ranges, false).map(|mut fresh| {
            if entries.is_empty() {
                *entries = fresh;
            } else {
                entries.append(&mut fresh);
            }
            normalize_by_identity(entries);
        });
        // SAFETY: fd is owned by this closure and never reused afterwards.
        let close_result = unsafe { crate::sys::close_procmap(fd) };
        match (result, close_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Ok(()), Err(errno)) => Err(Error::system_call("close", errno)),
            (Err(error), _) => Err(error),
        }
    })
}

fn normalize_by_identity(entries: &mut Vec<SmapInfo>) {
    if entries.len() < 2 {
        return;
    }
    entries.sort_unstable_by_key(|entry| entry.map.start);
    entries.dedup_by(|current, next| {
        current.map == next.map
            && current.vm_flags == next.vm_flags
            && current.protection_key == next.protection_key
    });
}

/// Reads targeted `smaps` entries while retaining each mapping's backing path.
#[cfg(target_arch = "aarch64")]
fn read_self_smaps_ranges_with(
    ranges: &[(usize, usize)],
    keep_paths: bool,
) -> Result<Vec<SmapInfo>> {
    if ranges.is_empty() {
        return Ok(Vec::new());
    }
    retry_transient_procfs_parse(|| {
        let fd =
            crate::sys::open_self_proc_file(b"smaps", (libc::O_RDONLY | libc::O_CLOEXEC) as usize)
                .map_err(|errno| Error::system_call("openat", errno))?;
        let mut reader = crate::sys::RawProcReader::<SMAPS_READ_SIZE>::new(fd);
        let result = read_smaps_for_ranges_with(&mut reader, ranges, keep_paths);
        // SAFETY: fd is owned by this closure and never reused afterwards.
        let close_result = unsafe { crate::sys::close_procmap(fd) };
        match (result, close_result) {
            (Ok(entries), Ok(())) => Ok(entries),
            (Ok(_), Err(errno)) => Err(Error::system_call("close", errno)),
            (Err(error), _) => Err(error),
        }
    })
}

pub(super) fn read_smaps_for_ranges_with(
    mut reader: impl BufRead,
    ranges: &[(usize, usize)],
    keep_paths: bool,
) -> Result<Vec<SmapInfo>> {
    if ranges.is_empty() {
        return Ok(Vec::new());
    }
    if ranges.iter().any(|&(start, end)| start >= end)
        || ranges.windows(2).any(|pair| pair[0].1 > pair[1].0)
    {
        return Err(Error::InvalidSmaps("target ranges are not ordered"));
    }

    let mut entries = Vec::with_capacity(ranges.len());
    let mut current: Option<(MapInfo, Option<SmapVmFlags>, Option<u64>)> = None;
    let mut range_index = 0;
    let mut previous_start = None;
    scan_lines(&mut reader, |line| {
        if line.is_empty() {
            return Ok(false);
        }
        if looks_like_map_header(line) {
            finish_smap_entry(&mut entries, current.take())?;
            let (map_start, map_end, fields) = parse_address_prefix(line)?;
            if previous_start.is_some_and(|start| start > map_start) {
                return Err(unordered_smaps());
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
                current = Some((
                    parse_line_fields(line, map_start, map_end, fields, keep_paths)?,
                    None,
                    None,
                ));
            }
        } else if let Some((_, vm_flags, protection_key)) = current.as_mut() {
            if let Some(flags) = line.strip_prefix(b"VmFlags:") {
                if vm_flags.is_some() {
                    return Err(Error::InvalidSmaps("duplicate VmFlags for one mapping"));
                }
                *vm_flags = Some(parse_vm_flags(flags));
            } else if let Some(key) = line.strip_prefix(b"ProtectionKey:") {
                if protection_key.is_some() {
                    return Err(Error::InvalidSmaps("duplicate protection key"));
                }
                *protection_key = Some(parse_protection_key(key)?);
            }
        }
        Ok(false)
    })?;
    finish_smap_entry(&mut entries, current)?;
    Ok(entries)
}

fn parse_vm_flags(flags: &[u8]) -> SmapVmFlags {
    let mut parsed = SmapVmFlags::default();
    for flag in flags.split(|byte| byte.is_ascii_whitespace()) {
        match flag {
            // `dw` (`VM_DENYWRITE`) and Android's page-size-migration padding
            // metadata are normal for executable mappings and do not change
            // private copy-on-write semantics.
            b"rd" | b"wr" | b"ex" | b"mr" | b"mw" | b"me" | b"ac" | b"sd" | b"dw" => {}
            token if is_pad_metadata(token) => {}
            b"bt" => parsed.bti = true,
            b"mt" => parsed.mte = true,
            b"lo" => parsed.locked = true,
            b"dd" => parsed.dont_dump = true,
            b"df" => parsed.dont_fork = true,
            b"wf" => parsed.wipe_on_fork = true,
            b"hg" => parsed.hugepage = true,
            b"nh" => parsed.non_hugepage = true,
            b"mm" => parsed.mixed_map = true,
            b"io" => parsed.io_map = true,
            b"lf" => parsed.lock_on_fault = true,
            b"sr" => parsed.sync = true,
            [] => {}
            _ => parsed.unknown = true,
        }
    }
    parsed
}

fn is_pad_metadata(token: &[u8]) -> bool {
    token.len() > 6
        && token.starts_with(b"pad=")
        && token.ends_with(b"kB")
        && token[4..token.len() - 2]
            .iter()
            .all(|byte| byte.is_ascii_digit())
}

#[cold]
fn unordered_smaps() -> Error {
    Error::InvalidSmaps("mappings are not ordered")
}

fn parse_protection_key(value: &[u8]) -> Result<u64> {
    std::str::from_utf8(value)
        .map_err(|_| Error::InvalidSmaps("invalid protection key"))?
        .trim()
        .parse()
        .map_err(|_| Error::InvalidSmaps("invalid protection key"))
}

fn looks_like_map_header(line: &[u8]) -> bool {
    // smaps headers tolerate leading spaces, so skip the cheap prefilter
    // whenever the line does not start at column zero; the trimmed path
    // below keeps its exact original semantics.
    if !line.first().is_some_and(|byte| byte.is_ascii_hexdigit()) && !line.starts_with(b" ") {
        return false;
    }
    let line = line.trim_ascii_start();
    let digits = line
        .iter()
        .take_while(|byte| byte.is_ascii_hexdigit())
        .count();
    digits != 0 && line.get(digits) == Some(&b'-')
}

fn finish_smap_entry(
    entries: &mut Vec<SmapInfo>,
    current: Option<(MapInfo, Option<SmapVmFlags>, Option<u64>)>,
) -> Result<()> {
    let Some((map, vm_flags, protection_key)) = current else {
        return Ok(());
    };
    entries.push(SmapInfo {
        map,
        vm_flags: vm_flags.ok_or(Error::InvalidSmaps("mapping has no VmFlags"))?,
        protection_key: protection_key.unwrap_or_default(),
    });
    Ok(())
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::thread::ThreadId;

    // Per-thread counts keep parallel tests from cross-polluting assertions.
    static SMAPS_READS: Mutex<Vec<(ThreadId, usize)>> = Mutex::new(Vec::new());

    pub(super) fn record_smaps_read() {
        let id = std::thread::current().id();
        let mut reads = SMAPS_READS.lock().unwrap();
        match reads.iter_mut().find(|(thread, _)| *thread == id) {
            Some((_, count)) => *count += 1,
            None => reads.push((id, 1)),
        }
    }

    #[cfg(all(target_arch = "aarch64", feature = "inline"))]
    pub(crate) fn smaps_reads() -> usize {
        let id = std::thread::current().id();
        SMAPS_READS
            .lock()
            .unwrap()
            .iter()
            .find(|(thread, _)| *thread == id)
            .map(|(_, count)| *count)
            .unwrap_or(0)
    }

    #[cfg(all(target_arch = "aarch64", feature = "inline"))]
    pub(crate) fn reset_smaps_reads() {
        let id = std::thread::current().id();
        let mut reads = SMAPS_READS.lock().unwrap();
        match reads.iter_mut().find(|(thread, _)| *thread == id) {
            Some((_, count)) => *count = 0,
            None => reads.push((id, 0)),
        }
    }

    pub(crate) fn read_smaps_for_ranges(
        reader: impl BufRead,
        ranges: &[(usize, usize)],
    ) -> Result<Vec<SmapInfo>> {
        read_smaps_for_ranges_with(reader, ranges, false)
    }

    pub(crate) fn parse_smaps(contents: &[u8]) -> Result<Vec<SmapInfo>> {
        let mut entries = Vec::new();
        let mut current: Option<(MapInfo, Option<SmapVmFlags>, Option<u64>)> = None;

        for line in contents
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
        {
            if looks_like_map_header(line) {
                finish_smap_entry(&mut entries, current.take())?;
                let (start, end, fields) = parse_address_prefix(line)?;
                current = Some((
                    parse_line_fields(line, start, end, fields, false)?,
                    None,
                    None,
                ));
                continue;
            }
            if let Some(flags) = line.strip_prefix(b"VmFlags:") {
                let Some((_, vm_flags, _)) = current.as_mut() else {
                    return Err(Error::InvalidSmaps("VmFlags precedes a mapping header"));
                };
                if vm_flags.is_some() {
                    return Err(Error::InvalidSmaps("duplicate VmFlags for one mapping"));
                }
                *vm_flags = Some(parse_vm_flags(flags));
            } else if let Some(key) = line.strip_prefix(b"ProtectionKey:") {
                let Some((_, _, protection_key)) = current.as_mut() else {
                    return Err(Error::InvalidSmaps(
                        "protection key precedes a mapping header",
                    ));
                };
                if protection_key.is_some() {
                    return Err(Error::InvalidSmaps("duplicate protection key"));
                }
                *protection_key = Some(parse_protection_key(key)?);
            }
        }
        finish_smap_entry(&mut entries, current)?;
        Ok(entries)
    }
}

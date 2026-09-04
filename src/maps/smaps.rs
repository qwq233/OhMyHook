#[cfg(target_arch = "aarch64")]
use super::retry_transient_procfs_parse;
use super::{MapInfo, parse_address_prefix, parse_line, scan_lines};
use crate::{Error, Result};
#[cfg(target_arch = "aarch64")]
use std::fs::File;
use std::io::BufRead;
#[cfg(target_arch = "aarch64")]
use std::io::BufReader;

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

#[cfg(target_arch = "aarch64")]
pub(crate) fn read_self_smaps_for_ranges(ranges: &[(usize, usize)]) -> Result<Vec<SmapInfo>> {
    read_self_smaps_ranges_with(ranges, false)
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
        let file = File::open("/proc/self/smaps")?;
        read_smaps_for_ranges_with(
            BufReader::with_capacity(64 * 1024, file),
            ranges,
            keep_paths,
        )
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
            let (map_start, map_end, _) = parse_address_prefix(line)?;
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
            let Some(&(start, _)) = ranges.get(range_index) else {
                return Ok(true);
            };
            if start < map_end {
                current = Some((parse_line(line, keep_paths)?, None, None));
            }
        } else if let (Some(flags), Some((_, vm_flags, _))) =
            (line.strip_prefix(b"VmFlags:"), current.as_mut())
        {
            if vm_flags.is_some() {
                return Err(Error::InvalidSmaps("duplicate VmFlags for one mapping"));
            }
            *vm_flags = Some(parse_vm_flags(flags));
        } else if let (Some(key), Some((_, _, protection_key))) =
            (line.strip_prefix(b"ProtectionKey:"), current.as_mut())
        {
            if protection_key.is_some() {
                return Err(Error::InvalidSmaps("duplicate protection key"));
            }
            *protection_key = Some(parse_protection_key(key)?);
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
            b"rd" | b"wr" | b"ex" | b"mr" | b"mw" | b"me" | b"ac" | b"sd" => {}
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
            b"la" => parsed.lock_on_fault = true,
            b"sr" => parsed.sync = true,
            [] => {}
            _ => parsed.unknown = true,
        }
    }
    parsed
}

fn parse_protection_key(value: &[u8]) -> Result<u64> {
    std::str::from_utf8(value)
        .map_err(|_| Error::InvalidSmaps("invalid protection key"))?
        .trim()
        .parse()
        .map_err(|_| Error::InvalidSmaps("invalid protection key"))
}

#[cold]
fn unordered_smaps() -> Error {
    Error::InvalidSmaps("mappings are not ordered")
}

fn looks_like_map_header(line: &[u8]) -> bool {
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
                current = Some((parse_line(line, false)?, None, None));
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

use crate::maps::{
    MapInfo, MapPerms, MappingSnapshot, find_map_containing, read_self_maps_for_ranges,
};
use crate::{Error, MutationPath, Result};
#[cfg(test)]
use std::fs::File;
#[cfg(test)]
use std::os::unix::fs::MetadataExt;
use syscalls::Errno;

#[cfg(target_arch = "arm")]
#[path = "patch/arm.rs"]
mod arm;
#[cfg(target_arch = "aarch64")]
#[path = "patch/aarch64.rs"]
mod page;
#[cfg(not(target_arch = "aarch64"))]
#[path = "patch/generic.rs"]
mod page;

#[cfg(target_arch = "arm")]
pub(super) use arm::copy_literal;
#[cfg(target_arch = "aarch64")]
pub(super) type PageFlags = Option<Vec<crate::maps::SmapInfo>>;
#[cfg(not(target_arch = "aarch64"))]
pub(super) type PageFlags = ();
#[derive(Clone)]
pub(super) struct CodePage {
    start: usize,
    length: usize,
    original_protection: i32,
    mapping: MappingSnapshot,
}

pub(super) fn page_protections<'a>(
    pages: impl Iterator<Item = &'a CodePage>,
) -> std::sync::Arc<[super::InlinePageProtection]> {
    let mut protections: Vec<_> = pages
        .map(|page| super::InlinePageProtection {
            address: page.start,
            length: page.length,
            protection: page.original_protection,
        })
        .collect();
    protections.sort_unstable_by_key(|page| page.address);
    protections.dedup_by_key(|page| page.address);
    protections.into()
}

pub(super) fn copy_executable_window(
    maps: &[MapInfo],
    address: usize,
    output: &mut [u8],
) -> Result<usize> {
    let map = find_map_containing(maps, address, 1)
        .filter(|map| executable_code_map(map))
        .ok_or(Error::MappingChanged)?;
    let mapping = MappingSnapshot::from_map(map);
    let mut written = 0;
    let mut cursor = address;
    while written < output.len() {
        let Some(map) = find_map_containing(maps, cursor, 1)
            .filter(|map| executable_code_map(map) && mapping.matches_at(map, cursor))
        else {
            break;
        };
        let length = (output.len() - written).min(map.end - cursor);
        if length == 0 {
            break;
        }
        // SAFETY: this captured readable mapping covers the copied chunk; the
        // public install contract keeps it stable.
        let chunk = unsafe {
            std::slice::from_raw_parts(std::ptr::with_exposed_provenance(cursor), length)
        };
        output[written..written + length].copy_from_slice(chunk);
        written += length;
        cursor = cursor
            .checked_add(length)
            .ok_or(Error::ArithmeticOverflow)?;
    }
    if written == 0 {
        return Err(Error::MappingChanged);
    }
    Ok(written)
}

pub(super) fn validate_executable_entry(
    maps: &[MapInfo],
    address: usize,
    length: usize,
) -> Result<()> {
    find_map_containing(maps, address, length)
        .filter(|map| map.perms.contains(MapPerms::READ | MapPerms::EXEC))
        .ok_or(Error::MappingChanged)?;
    Ok(())
}

pub(super) fn probe_maps(
    maps: &[MapInfo],
    address: usize,
    length: usize,
) -> Result<Option<Vec<MapInfo>>> {
    if validate_executable_entry(maps, address, length).is_ok() {
        return Ok(None);
    }
    let last = address
        .checked_add(length.saturating_sub(1))
        .ok_or(Error::ArithmeticOverflow)?;
    let ranges = crate::maps::page_ranges([address, last])?;
    Ok(Some(crate::maps::read_self_maps_for_ranges(&ranges)?))
}

pub(super) fn capture_pages(
    maps: &[MapInfo],
    page_flags: &PageFlags,
    address: usize,
    length: usize,
    replacement: usize,
    page_size: usize,
) -> Result<(Vec<CodePage>, bool)> {
    let end = range_end(address, length)?;
    let mut page = crate::sys::page_start(address, page_size);
    let span_pages = end.saturating_sub(page).saturating_add(page_size - 1) / page_size;
    let mut pages = Vec::with_capacity(span_pages.max(1));
    while page < end {
        let map = find_map_containing(maps, page, page_size)
            .filter(|map| executable_code_map(map))
            .ok_or(Error::MappingChanged)?;
        pages.push(CodePage {
            start: page,
            length: page_size,
            original_protection: map.perms.to_prot(),
            mapping: MappingSnapshot::from_map(map),
        });
        page = page
            .checked_add(page_size)
            .ok_or(Error::ArithmeticOverflow)?;
    }

    let replacement_guarded = page::capture_flags(&mut pages, maps, page_flags, replacement)?;
    Ok((pages, replacement_guarded))
}

#[cfg(target_arch = "arm")]
pub(super) fn read_page_flags(ranges: &[(usize, usize)]) -> Result<PageFlags> {
    page::read_flags(ranges)
}

pub(super) fn apply_protection_flags(
    pages: &mut [impl AsMut<[CodePage]>],
    snapshot: Option<&[crate::maps::SmapInfo]>,
) -> Result<()> {
    page::apply_protection_flags(pages, snapshot)
}

pub(super) const fn arena_protection(pages: &[CodePage]) -> i32 {
    page::arena_protection(pages)
}

#[cfg(target_arch = "aarch64")]
pub(super) fn is_guarded(pages: &[CodePage]) -> bool {
    page::is_guarded(pages)
}

fn validate_pages(maps: &[MapInfo], pages: &[CodePage]) -> Result<()> {
    for page in pages {
        let map = find_map_containing(maps, page.start, page.length)
            .filter(|map| page.mapping.matches_at_ignoring_write(map, page.start))
            .ok_or(Error::MappingChanged)?;
        if !executable_code_map(map)
            && !(map.perms.contains(MapPerms::WRITE)
                && page.original_protection & libc::PROT_EXEC != 0)
        {
            return Err(Error::MappingChanged);
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
pub(super) struct Replacement<'a> {
    pub(super) pages: &'a [CodePage],
    pub(super) address: usize,
    /// Exclusive end of `expected`, precomputed before the mutation window so
    /// the window itself never constructs or drops a `Result`.
    pub(super) end: usize,
    pub(super) expected: &'a [u8],
    pub(super) replacement: &'a [u8],
}

fn replacement_page_ranges(replacements: &[Replacement<'_>]) -> Result<Vec<(usize, usize)>> {
    let mut ranges = Vec::new();
    for replacement in replacements {
        for page in replacement.pages {
            let end = range_end(page.start, page.length)?;
            ranges.push((page.start, end));
        }
    }
    ranges.sort_unstable();
    let mut merged = 0_usize;
    for index in 0..ranges.len() {
        let current = ranges[index];
        if merged > 0 && ranges[merged - 1].1 >= current.0 {
            ranges[merged - 1].1 = ranges[merged - 1].1.max(current.1);
        } else {
            ranges[merged] = current;
            merged += 1;
        }
    }
    ranges.truncate(merged);
    Ok(ranges)
}

/// What a completed mutation did, beyond succeeding.
///
/// Cleanup fields let the caller act after it has released the process
/// lock: this crate emits no log record while an internal guard is held.
#[derive(Clone, Copy)]
pub(super) struct MutationOutcome {
    pub(super) path: MutationPath,
    /// Whether this mutation's publication barrier synchronized every core.
    pub(super) sync_core: bool,
    /// Failed `close(2)` error after a mutation that otherwise fully succeeded.
    pub(super) descriptor_close_errno: Option<Errno>,
    /// A keeping-exec mutation published its bytes but could not remove
    /// `PROT_WRITE`; the page stayed executable.
    pub(super) left_writable: Option<Errno>,
}

pub(super) enum MutationFailure {
    Error(Error),
    /// The executable fallback itself failed after protection flags were
    /// captured; the forced errno is carried separately by the caller.
    KeepExec(ElevationFailure),
    /// Target bytes were rolled back, but at least one executable page
    /// could not regain its captured protection.
    KeepExecRollback(Errno),
    /// The forced channel failed after restoring every target byte, and the
    /// automatic elevation fallback needs the caller to capture protection
    /// flags outside the mutation window first.
    ProtectionFlagsRequired {
        write: Option<Errno>,
    },
}

#[derive(Clone, Copy)]
pub(super) struct ElevationFailure {
    pub(super) operation: &'static str,
    pub(super) errno: Errno,
    pub(super) page: Option<(usize, usize)>,
}

type MutationResult = std::result::Result<MutationOutcome, MutationFailure>;

impl From<Error> for MutationFailure {
    fn from(error: Error) -> Self {
        Self::Error(error)
    }
}

#[inline(never)]
pub(super) unsafe fn replace_many(
    replacements: &[Replacement<'_>],
    validation_maps: Option<&[MapInfo]>,
    mem: Option<usize>,
    request: Option<MutationPath>,
    fallback_retry: bool,
) -> MutationResult {
    let count = replacements.len();
    // Ownership starts at entry: every preflight exit below and the empty
    // batch must close the descriptor exactly once.
    let mut fd_guard = PreflightFd(mem);
    if count == 0 {
        return Ok(MutationOutcome {
            path: MutationPath::DropExec,
            sync_core: false,
            descriptor_close_errno: None,
            left_writable: None,
        });
    }
    let mut byte_ranges = Vec::with_capacity(count);
    for &replacement in replacements {
        if replacement.expected.len() != replacement.replacement.len()
            || replacement.expected.is_empty()
        {
            return Err(MutationFailure::Error(Error::InvalidInlineTarget(
                "invalid patch byte count",
            )));
        }
        let end = range_end(replacement.address, replacement.expected.len())?;
        if replacement.end != end {
            return Err(MutationFailure::Error(Error::InvalidInlineTarget(
                "replacement end does not match its expected byte range",
            )));
        }
        byte_ranges.push((replacement.address, end));
    }
    // One ordered pass replaces the former adjacent-pair plus quadratic
    // fallback: sorting handles every input order and still rejects any
    // overlap between target byte ranges.
    byte_ranges.sort_unstable();
    for pair in byte_ranges.windows(2) {
        if pair[0].1 > pair[1].0 {
            return Err(MutationFailure::Error(Error::Conflict));
        }
    }

    let mut ranges = None;
    if validation_maps.is_none() {
        ranges = Some(replacement_page_ranges(replacements)?);
    }
    let loaded_maps = match ranges.as_deref() {
        Some(ranges) => Some(read_self_maps_for_ranges(ranges)?),
        None if validation_maps.is_some() => None,
        None => {
            return Err(MutationFailure::Error(Error::InvalidInlineTarget(
                "missing validation maps",
            )));
        }
    };
    let maps = match validation_maps {
        Some(maps) => maps,
        None => loaded_maps.as_deref().unwrap_or(&[]),
    };
    for &replacement in replacements {
        validate_pages(maps, replacement.pages)?;
    }
    for &replacement in replacements {
        if !mapped_bytes_match(replacement.pages, replacement.address, replacement.expected)? {
            return Err(MutationFailure::Error(Error::Conflict));
        }
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
    if matches!(
        request,
        Some(MutationPath::KeepExec | MutationPath::DropExec)
    ) {
        let mut pages = Vec::new();
        for replacement in replacements {
            for page in replacement.pages {
                pages.push(page.start);
            }
        }
        pages.sort_unstable();
        pages.dedup();
        crate::maps::validate_page_write_access(maps, &pages, crate::sys::page_size()?)?;
    }
    if request == Some(MutationPath::DropExec) {
        protection_regrant_probe(replacements, maps)?;
    }

    for index in 0..replacements.len() {
        for page_index in 0..replacements[index].pages.len() {
            let page = &replacements[index].pages[page_index];
            let mut previous_index = 0;
            while previous_index < index {
                let previous_pages = replacements[previous_index].pages;
                let mut candidate_index = 0;
                while candidate_index < previous_pages.len() {
                    let candidate = &previous_pages[candidate_index];
                    if candidate.start == page.start
                        && (candidate.length != page.length
                            || candidate.original_protection != page.original_protection)
                    {
                        return Err(MutationFailure::Error(Error::MappingChanged));
                    }
                    candidate_index += 1;
                }
                previous_index += 1;
            }
        }
    }

    // All heap-backed validation scratch is gone before the first target byte
    // changes. The mutation and successful-return path is allocation-free and
    // drop-glue-free: no `Result` temporary or other value with non-trivial
    // drop may be created between opening and closing pages, because the
    // linker can place the compiler-generated drop glue on the mutated page.
    drop(ranges);
    drop(loaded_maps);
    let ranges = RawRangeStorage::from_vec(byte_ranges);

    // Ownership boundary: the mutating half below closes or consumes `mem` on
    // every one of its outcomes. Preflight still owns it here, so release the
    // guard only after the handoff; every earlier error path drops it and
    // closes the descriptor exactly once.
    crate::sys::enter_mutation();
    // SAFETY: forwarded from this function's complete contract.
    let ranges = unsafe { std::slice::from_raw_parts(ranges.pointer, ranges.length) };
    // SAFETY: the raw storage was built from the validated, non-overlapping
    // replacement ranges and remains live until after `leave_mutation`.
    let outcome =
        unsafe { replace_many_mutating(replacements, ranges, mem, request, fallback_retry) };
    // The mutating half now owns the descriptor on every outcome.
    fd_guard.0 = None;
    // Reached only on a normal return. Unwinding past this point deliberately
    // leaves the flag set, because a panic inside the window is the one case
    // where a later poisoned lock must still terminate the process.
    crate::sys::leave_mutation();
    outcome
}

/// Proves that a private file page can regain `PROT_EXEC` after a write.
///
/// The probe maps a different page of the same backing file, drops and
/// restores its protection, and never touches a target byte. A policy refusal
/// here means the requested drop-exec path would strand the real target, so
/// the request fails before mutation. An unavailable probe is inconclusive and
/// lets the explicit request proceed.
fn protection_regrant_probe(replacements: &[Replacement<'_>], maps: &[MapInfo]) -> Result<()> {
    let page_size = crate::sys::page_size()?;
    let mut pages = Vec::new();
    for replacement in replacements {
        for page in replacement.pages {
            pages.push(page.start);
        }
    }
    pages.sort_unstable();
    pages.dedup();
    for page in pages {
        let map = find_map_containing(maps, page, page_size).ok_or(Error::MappingChanged)?;
        probe_file_page(map, page_size)?;
    }
    Ok(())
}

fn probe_file_page(map: &MapInfo, page_size: usize) -> Result<()> {
    let mut leaf = [0_u8; 64];
    let leaf_length = write_map_files_leaf(&mut leaf, map);
    let opened = crate::sys::open_self_proc_file(
        &leaf[..leaf_length],
        (libc::O_RDONLY | libc::O_CLOEXEC) as usize,
    );
    let Ok(fd) = opened else {
        return Ok(());
    };
    let offset = map.offset - map.offset % u64::try_from(page_size).unwrap_or(1);
    probe_file_descriptor(fd, offset, page_size)
}

/// Proves that one private file page can regain `PROT_EXEC` after a write.
fn probe_file_descriptor(fd: usize, offset: u64, page_size: usize) -> Result<()> {
    let Ok(offset) = libc::off_t::try_from(offset) else {
        close_raw_fd(fd)?;
        return Ok(());
    };
    #[cfg(any(target_arch = "x86", target_arch = "arm"))]
    let offset_pages = {
        let Ok(offset) = u64::try_from(offset) else {
            close_raw_fd(fd)?;
            return Ok(());
        };
        // mmap2 counts fixed 4 KiB units, including on larger-page kernels.
        let Ok(pages) = usize::try_from(offset / 4096) else {
            close_raw_fd(fd)?;
            return Ok(());
        };
        pages
    };
    // SAFETY: mmap receives a live file descriptor, a page-aligned length and
    // offset, and returns either a new private mapping or MAP_FAILED.
    let address = unsafe {
        #[cfg(any(target_arch = "x86", target_arch = "arm"))]
        {
            syscalls::syscall!(
                syscalls::Sysno::mmap2,
                0_usize,
                page_size,
                (libc::PROT_READ | libc::PROT_EXEC) as usize,
                libc::MAP_PRIVATE as usize,
                fd,
                offset_pages
            )
        }
        #[cfg(not(any(target_arch = "x86", target_arch = "arm")))]
        {
            syscalls::syscall!(
                syscalls::Sysno::mmap,
                0_usize,
                page_size,
                (libc::PROT_READ | libc::PROT_EXEC) as usize,
                libc::MAP_PRIVATE as usize,
                fd,
                offset as usize
            )
        }
    };
    let mapped = match address {
        Ok(mapped) => mapped,
        Err(_) => {
            close_raw_fd(fd)?;
            return Ok(());
        }
    };
    if mapped == usize::MAX {
        close_raw_fd(fd)?;
        return Ok(());
    }
    // SAFETY: the successful mapping owns exactly one writable candidate page.
    let writable = unsafe {
        crate::sys::protect_checked(mapped, page_size, libc::PROT_READ | libc::PROT_WRITE)
    };
    let mut refusal = None;
    if writable.is_none() {
        // SAFETY: the probe page is private and this volatile write dirties it.
        unsafe {
            let byte = mapped as *mut u8;
            let original = std::ptr::read_volatile(byte);
            #[cfg(test)]
            tests::PROBE_FIRST_BYTE.store(original, std::sync::atomic::Ordering::Relaxed);
            std::ptr::write_volatile(byte, original);
        }
        // SAFETY: this exact private page is currently writable.
        if let Some(errno) = unsafe {
            crate::sys::protect_checked(mapped, page_size, libc::PROT_READ | libc::PROT_EXEC)
        } && (errno == Errno::EACCES || errno == Errno::EPERM)
        {
            refusal = Some(errno);
        }
    }
    // SAFETY: this call owns the complete temporary mapping.
    let unmap_result = unsafe { syscalls::syscall!(syscalls::Sysno::munmap, mapped, page_size) };
    let close_result = close_raw_fd(fd);
    if let Err(errno) = unmap_result {
        return Err(Error::system_call("munmap", errno));
    }
    close_result?;
    if let Some(errno) = refusal {
        return Err(Error::MutationPathUnavailable {
            forced_access: None,
            protection_keeping_exec: None,
            protection: Some(errno),
        });
    }
    Ok(())
}

fn close_raw_fd(fd: usize) -> Result<()> {
    crate::sys::close_self_mem(fd).map_or(Ok(()), |errno| Err(Error::system_call("close", errno)))
}

fn write_map_files_leaf(output: &mut [u8; 64], map: &MapInfo) -> usize {
    const PREFIX: &[u8] = b"map_files/";
    output[..PREFIX.len()].copy_from_slice(PREFIX);
    let mut cursor = PREFIX.len();
    cursor = write_hex(output, cursor, map.start);
    output[cursor] = b'-';
    cursor += 1;
    cursor = write_hex(output, cursor, map.end);
    cursor
}

fn write_hex(output: &mut [u8; 64], mut cursor: usize, value: usize) -> usize {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut digits = [0_u8; 16];
    let mut length = 0;
    let mut remaining = value;
    loop {
        digits[length] = HEX[remaining & 0xf];
        length += 1;
        remaining >>= 4;
        if remaining == 0 {
            break;
        }
    }
    while length > 0 {
        length -= 1;
        output[cursor] = digits[length];
        cursor += 1;
    }
    cursor
}

#[cfg(test)]
fn open_path_if_same_file(map: &MapInfo) -> std::io::Result<File> {
    let path = map
        .path
        .as_deref()
        .ok_or_else(|| std::io::Error::other("the map has no pathname fallback"))?;
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if decode_device(metadata.dev())? != map.device || metadata.ino() != map.inode {
        return Err(std::io::Error::other("the pathname names a different file"));
    }
    Ok(file)
}

#[cfg(test)]
fn decode_device(raw_dev: u64) -> std::io::Result<crate::maps::DeviceId> {
    let device = libc::dev_t::try_from(raw_dev)
        .map_err(|_| std::io::Error::other("device number is too large"))?;
    #[cfg(target_os = "android")]
    let major = u32::try_from(libc::major(device))
        .map_err(|_| std::io::Error::other("device major is too large"))?;
    #[cfg(target_os = "android")]
    let minor = u32::try_from(libc::minor(device))
        .map_err(|_| std::io::Error::other("device minor is too large"))?;
    #[cfg(target_os = "linux")]
    let major = libc::major(device);
    #[cfg(target_os = "linux")]
    let minor = libc::minor(device);
    Ok(crate::maps::DeviceId::new(major, minor))
}

struct PreflightFd(Option<usize>);
impl Drop for PreflightFd {
    fn drop(&mut self) {
        if let Some(fd) = self.0.take() {
            // SAFETY: the fd belongs to one replace_many call and was never
            // handed to its mutating half.
            let _ = crate::sys::close_self_mem(fd);
        }
    }
}

/// Raw storage for replacement ranges across the inline mutation window.
///
/// Like `RawReplacementStorage`, this keeps a heap allocation alive without a
/// Vec drop inside the window. `(usize, usize)` has no drop glue, so only the
/// allocation itself is reclaimed later.
struct RawRangeStorage {
    pointer: *mut (usize, usize),
    length: usize,
    capacity: usize,
}

impl RawRangeStorage {
    fn from_vec(mut ranges: Vec<(usize, usize)>) -> Self {
        let storage = Self {
            pointer: ranges.as_mut_ptr(),
            length: ranges.len(),
            capacity: ranges.capacity(),
        };
        std::mem::forget(ranges);
        storage
    }
}

impl Drop for RawRangeStorage {
    fn drop(&mut self) {
        if self.capacity == 0 {
            return;
        }
        let layout = std::alloc::Layout::array::<(usize, usize)>(self.capacity)
            .unwrap_or_else(|_| crate::sys::fail_stop());
        // SAFETY: pointer and capacity came from the same Vec allocation; the
        // tuple has no drop glue, so reclaiming the allocation is sufficient.
        unsafe { std::alloc::dealloc(self.pointer.cast(), layout) };
    }
}

/// Flushes every replacement range in one cache-maintenance call.
///
/// # Safety
///
/// Every range must name live readable bytes, and the caller must keep the
/// complete pages quiescent and writer-exclusive.
#[inline(never)]
unsafe fn flush_replacements(
    replacements: &[Replacement<'_>],
    ranges: &[(usize, usize)],
    sync_core: &mut bool,
) -> Option<(&'static str, Errno)> {
    // SAFETY: every named range remains live and readable.
    let failure =
        unsafe { crate::sys::flush_instruction_cache_ranges_checked(ranges, true, sync_core) };
    let _ = replacements;
    failure
}

/// The half of `replace_many` that can leave a target only partly written.
///
/// # Safety
///
/// The same contract as [`replace_many`] applies.
unsafe fn replace_many_mutating(
    replacements: &[Replacement<'_>],
    ranges: &[(usize, usize)],
    mem: Option<usize>,
    request: Option<MutationPath>,
    fallback_retry: bool,
) -> MutationResult {
    // Prefer the channel that never removes PROT_EXEC. This avoids the one
    // real Android failure mode: SELinux may allow dropping executable
    // protection but refuse to restore a written page.
    if request == Some(MutationPath::DropExec) {
        // SAFETY: the validated private mappings cover every elevation.
        return match unsafe { elevate(replacements, ranges) } {
            Ok(outcome) => Ok(outcome),
            Err(failure) => Err(MutationFailure::Error(elevation_error(failure))),
        };
    }
    if request == Some(MutationPath::KeepExec) {
        // SAFETY: the validated private mappings cover every elevation.
        return match unsafe { elevate_keeping_exec(replacements, ranges) } {
            Ok(outcome) => Ok(outcome),
            Err(failure) => {
                if failure.page.is_some() {
                    Err(MutationFailure::KeepExecRollback(failure.errno))
                } else if fallback_retry {
                    Err(MutationFailure::KeepExec(failure))
                } else {
                    Err(MutationFailure::Error(elevation_error(failure)))
                }
            }
        };
    }
    let forced_only = request == Some(MutationPath::ForcedWrite);
    // SAFETY: the validated private mappings cover every forced write.
    match unsafe { replace_many_forced(replacements, ranges, mem) } {
        // The forced path closes or consumes `mem` on every outcome, so no
        // caller-side cleanup may touch it after this point.
        ForcedOutcome::Done(sync_core) => Ok(MutationOutcome {
            path: MutationPath::ForcedWrite,
            sync_core,
            descriptor_close_errno: None,
            left_writable: None,
        }),
        // The hooks are installed. Reporting failure here would make the caller
        // discard the batch and unmap the arenas the new entries branch into,
        // turning a leaked descriptor into a crash at the next call through any
        // patched target. The leak is carried out for the caller to log once it
        // has released the process lock.
        ForcedOutcome::DoneWithCloseError(errno, sync_core) => Ok(MutationOutcome {
            path: MutationPath::ForcedWrite,
            sync_core,
            // The public install_cleanup_status carries the kernel's own errno rather
            // than a synthesized placeholder.
            descriptor_close_errno: Some(errno),
            left_writable: None,
        }),
        // Both outcomes below restored whatever bytes the forced attempt
        // changed, so every target holds its captured bytes again and the
        // elevation sequence can take over. Recognising only one errno here
        // was the defect: a process that cannot use `/proc/self/mem` at all
        // reports `Unavailable` or the kernel's own errno, never `EIO`.
        ForcedOutcome::Unavailable => {
            // SAFETY: the forced attempt restored every byte it changed.
            unsafe { forced_failure(forced_only, None) }
        }
        ForcedOutcome::Failed("pwrite64", errno) => {
            // SAFETY: the forced attempt restored every byte it changed.
            unsafe { forced_failure(forced_only, Some(errno)) }
        }
        ForcedOutcome::Failed(operation, errno) => {
            Err(MutationFailure::Error(Error::system_call(operation, errno)))
        }
        // Reported only after the mutation was undone, so every target holds
        // the bytes it held before this call and only the descriptor leaked.
        // This must not be `InlineCleanupPending`: for a removal, "undone"
        // means the target is still patched, and that variant promises the
        // opposite.
        ForcedOutcome::RolledBackWithCloseError => Err(MutationFailure::Error(
            Error::ForcedMutationRolledBackWithCloseError,
        )),
    }
}

/// Runs the page-elevation sequence and reports that path.
///
/// # Safety
///
/// The same contract as [`replace_many_with_elevation`] applies.
#[inline(never)]
unsafe fn elevate(
    replacements: &[Replacement<'_>],
    ranges: &[(usize, usize)],
) -> std::result::Result<MutationOutcome, ElevationFailure> {
    let mut sync_core = false;
    // SAFETY: the validated private mappings cover every elevation.
    unsafe { replace_many_with_elevation(replacements, ranges, false, &mut sync_core)? };
    Ok(MutationOutcome {
        path: MutationPath::DropExec,
        sync_core,
        descriptor_close_errno: None,
        left_writable: None,
    })
}

#[inline(never)]
unsafe fn elevate_keeping_exec(
    replacements: &[Replacement<'_>],
    ranges: &[(usize, usize)],
) -> std::result::Result<MutationOutcome, ElevationFailure> {
    let mut sync_core = false;
    // SAFETY: forwarded from the elevation contract; the page remains
    // executable throughout this variant.
    match unsafe { replace_many_with_elevation(replacements, ranges, true, &mut sync_core) } {
        Ok(left_writable) => {
            let left_writable = page_protection_failure(left_writable);
            Ok(MutationOutcome {
                path: MutationPath::KeepExec,
                sync_core,
                descriptor_close_errno: None,
                left_writable,
            })
        }
        Err(failure) => Err(failure),
    }
}

fn page_protection_failure(left_writable: Option<(usize, usize, Errno)>) -> Option<Errno> {
    left_writable.map(page_protection_failure_from_tuple)
}

#[inline(never)]
fn page_protection_failure_from_tuple((_, _, errno): (usize, usize, Errno)) -> Errno {
    errno
}

/// Resolves a forced-access attempt that left every target unchanged.
///
/// A request that pinned that channel fails with its errno instead of
/// degrading; every other request takes the documented fallback.
///
/// # Safety
///
/// The same contract as [`replace_many_with_elevation`] applies.
#[inline(never)]
unsafe fn forced_failure(forced_only: bool, write: Option<Errno>) -> MutationResult {
    if forced_only {
        return Err(MutationFailure::Error(Error::MutationPathUnavailable {
            forced_access: Some(write.unwrap_or(Errno::EIO)),
            protection_keeping_exec: None,
            protection: None,
        }));
    }
    Err(MutationFailure::ProtectionFlagsRequired { write })
}

/// Applies every replacement through the baseline page-elevation sequence.
///
/// # Safety
///
/// Every replacement must name live, validated private executable pages, and
/// the caller must keep those pages quiescent and writer-exclusive.
#[inline(never)]
pub(super) unsafe fn replace_many_with_elevation(
    replacements: &[Replacement<'_>],
    ranges: &[(usize, usize)],
    keeping_exec: bool,
    sync_core: &mut bool,
) -> std::result::Result<Option<(usize, usize, Errno)>, ElevationFailure> {
    if let Some(errno) = open_unique_pages(replacements, keeping_exec) {
        // open_unique_pages restored every page it opened before returning.
        return Err(ElevationFailure {
            operation: "mprotect",
            errno,
            page: None,
        });
    }
    let mut write_index = 0;
    while write_index < replacements.len() {
        // Borrowing avoids copying the replacement struct: a debug build
        // lowers that copy to an external memcpy call, which the linker may
        // place inside the non-executable window.
        let replacement = &replacements[write_index];
        // SAFETY: every affected page is now RW and quiescent.
        unsafe {
            copy_mapped_bytes(
                replacement.pages,
                replacement.address,
                replacement.replacement,
            )
        };
        write_index += 1;
    }
    // SAFETY: every written byte range remains mapped RW and quiescent. The
    // raw range storage stays alive across the window without a Vec drop.
    match unsafe { flush_replacements(replacements, ranges, sync_core) } {
        None => {}
        Some((operation, errno)) => {
            // SAFETY: all pages remain open and every saved byte range is valid.
            if let Some(stuck) = unsafe { rollback_open_many(replacements, keeping_exec) } {
                return Err(elevation_failure("mprotect", stuck));
            }
            return Err(ElevationFailure {
                operation,
                errno,
                page: None,
            });
        }
    }
    if let Some(stuck) = close_unique_pages(replacements) {
        if keeping_exec {
            // The bytes are live and the page is still executable. Removing
            // `PROT_WRITE` failed, so report a successful mutation with a
            // degraded final protection rather than discarding live arenas.
            return Ok(Some(stuck));
        }
        // A failed restoration leaves a mixed page state. Reopen every page,
        // restore bytes, and close coherently.
        reopen_unique_pages(replacements, keeping_exec);
        // SAFETY: every page is again RW.
        if let Some(stuck) = unsafe { rollback_open_many(replacements, keeping_exec) } {
            return Err(elevation_failure("mprotect", stuck));
        }
        return Err(ElevationFailure {
            operation: "mprotect",
            errno: stuck.2,
            page: None,
        });
    }
    Ok(None)
}

fn elevation_failure(
    operation: &'static str,
    (address, length, errno): (usize, usize, Errno),
) -> ElevationFailure {
    ElevationFailure {
        operation,
        errno,
        page: Some((address, length)),
    }
}

fn elevation_error(failure: ElevationFailure) -> Error {
    let Some((address, length)) = failure.page else {
        return Error::system_call(failure.operation, failure.errno);
    };
    Error::TargetPageProtectionLost {
        address,
        length,
        source: failure.errno,
    }
}

/// Reports whether a page-elevation failure is worth retrying through the
/// forced-access channel.
///
/// `ENOMEM` belongs here even though it does not name a policy: `mprotect`
/// returns it when splitting the target mapping would cross `vm.max_map_count`,
/// and a process with enough mappings to hit that limit is exactly the case the
/// forced channel handles, because writing through `/proc/self/mem` never
/// splits a mapping.
pub(super) fn retryable_page_elevation_failure(error: &Error) -> bool {
    matches!(
        error,
        Error::SystemCall {
            operation: "mprotect",
            source,
            ..
        } if matches!(
            *source,
            Errno::EPERM
                | Errno::EACCES
                | Errno::ENOSYS
                | Errno::EIO
                | Errno::ENOMEM
        )
    )
}

/// Reports whether a direct arena write is worth retrying with an RW arena.
///
/// The failed direct arena is unmapped by its preparation error path, so this
/// retry leaves no executable mapping behind.
pub(super) fn retryable_direct_arena_write_failure(error: &Error) -> bool {
    matches!(
        error,
        Error::SystemCall {
            operation: "pwrite64",
            source,
            ..
        } if matches!(
            *source,
            Errno::EPERM
                | Errno::EACCES
                | Errno::ENOSYS
                | Errno::EIO
                | Errno::ENOMEM
        )
    )
}

/// Outcome of one forced-access mutation attempt.
///
/// The variants carry only `Copy` values so the mutation stays free of
/// compiler-generated drop glue between the first changed byte and the
/// return.
#[derive(Clone, Copy)]
enum ForcedOutcome {
    /// Every range was written, verified, and flushed.
    Done(bool),
    /// The forced-access file is unavailable, or it reported success without
    /// changing what this process reads and executes. The caller keeps the
    /// page-elevation error.
    Unavailable,
    /// The attempt failed after restoring every byte it changed.
    Failed(&'static str, Errno),
    /// The kernel refused to close the forced-access descriptor after the
    /// mutation had already been rolled back.
    ///
    /// The target holds its original bytes, so reporting a failure is accurate
    /// and the descriptor is the only thing leaked.
    RolledBackWithCloseError,
    /// Every replacement was written, verified, and flushed, and only the
    /// closing of the forced-access descriptor failed.
    ///
    /// The hooks are live. This must be reported as success: a caller that
    /// believes the installation failed discards the batch, which unmaps the
    /// arenas the freshly written entries now branch into. A leaked descriptor
    /// is the far smaller problem.
    /// The writes are live; only the descriptor close failed. Carries the
    /// close errno so the caller reports the kernel's own failure.
    DoneWithCloseError(Errno, bool),
}

/// Writes every replacement through `/proc/self/mem` without changing page
/// permissions.
///
/// This function belongs to the closed inline mutation-window code set: keep
/// it free of closures, iterator adapters, and values with non-trivial drop
/// glue, because the linker may place that glue on a page whose bytes this
/// loop is changing.
#[inline(never)]
unsafe fn replace_many_forced(
    replacements: &[Replacement<'_>],
    ranges: &[(usize, usize)],
    mem: Option<usize>,
) -> ForcedOutcome {
    // A test that models a process which cannot use this channel at all has to
    // fail from inside this call: simulating the refusal by skipping the call
    // would bypass the caller's fallback, which is the code under test.
    #[cfg(test)]
    if tests::take_forced_unavailable_failure() {
        if let Some(fd) = mem
            && close_forced_descriptor(fd).is_some()
        {
            return ForcedOutcome::RolledBackWithCloseError;
        }
        return ForcedOutcome::Unavailable;
    }
    let Some(fd) = mem else {
        return ForcedOutcome::Unavailable;
    };
    let mut completed = 0_usize;
    while completed < replacements.len() {
        let replacement = &replacements[completed];
        let mut written = 0_usize;
        // SAFETY: the validated private mapping covers this forced write.
        let failure = unsafe {
            crate::sys::pwrite_self_mem_checked(
                fd,
                replacement.address,
                replacement.replacement.as_ptr() as usize,
                replacement.replacement.len(),
                &mut written,
            )
        };
        // The injected failure follows a write that really happened, so
        // `written` is accurate and the restore below undoes exactly it.
        #[cfg(test)]
        let failure = match failure {
            Some(errno) => Some(errno),
            None if tests::take_forced_write_failure() => Some(Errno::EPERM),
            None => None,
        };
        // Pattern matching keeps this window free of Option helper calls.
        let errno = match failure {
            Some(errno) => errno,
            None => {
                completed += 1;
                continue;
            }
        };
        // SAFETY: this call changed only the prefix restored here.
        unsafe { forced_restore(fd, replacements, completed, written) };
        if close_forced_descriptor(fd).is_some() {
            return ForcedOutcome::RolledBackWithCloseError;
        }
        return ForcedOutcome::Failed("pwrite64", errno);
    }
    // Verify every written range before publishing it to instruction fetch.
    let mut verify_index = 0;
    while verify_index < replacements.len() {
        let replacement = &replacements[verify_index];
        if !forced_bytes_match(replacement.address, replacement.replacement) {
            // `forced_bytes_match` reads through the writing process's own page
            // table. A kernel can accept a forced write and surface it through
            // the very `/proc/self/mem` descriptor that performed it while
            // those bytes stay invisible to the process: the write landed on
            // the backing object instead of a private copy. Nothing this engine
            // does makes such bytes executable, so report the channel as
            // unavailable and let the caller elevate the page. A partial write
            // is covered by the same branch: the elevation path revalidates
            // every expected byte before it touches the page, so a target that
            // really did change fails closed with `Conflict` rather than being
            // overwritten. This runs while the target pages are still
            // executable, so it needs no cache maintenance of its own.
            // SAFETY: every completed range is restored from its expected
            // bytes before the failure is reported.
            unsafe { forced_restore(fd, replacements, replacements.len(), 0) };
            if close_forced_descriptor(fd).is_some() {
                return ForcedOutcome::RolledBackWithCloseError;
            }
            return ForcedOutcome::Unavailable;
        }
        verify_index += 1;
    }
    let mut sync_core = false;
    // SAFETY: every freshly written range remains live and readable.
    match unsafe { flush_replacements(replacements, ranges, &mut sync_core) } {
        None => {}
        Some((operation, errno)) => {
            // SAFETY: every completed range is restored before the failure is
            // reported.
            unsafe { forced_restore(fd, replacements, replacements.len(), 0) };
            if close_forced_descriptor(fd).is_some() {
                return ForcedOutcome::RolledBackWithCloseError;
            }
            return ForcedOutcome::Failed(operation, errno);
        }
    }
    if let Some(errno) = close_forced_descriptor(fd) {
        return ForcedOutcome::DoneWithCloseError(errno, sync_core);
    }
    ForcedOutcome::Done(sync_core)
}

/// Closes the forced-access descriptor, reporting whether it failed.
///
/// Every exit from the forced path goes through here so a test can make the
/// close fail wherever it is reached, without the injection having to guess
/// which exit an operation will take.
#[inline(never)]
fn close_forced_descriptor(fd: usize) -> Option<Errno> {
    let failed = crate::sys::close_self_mem(fd);
    #[cfg(test)]
    let failed = if tests::take_forced_close_failure() {
        failed.or(Some(Errno::EIO))
    } else {
        failed
    };
    failed
}

/// Restores the changed prefix of a failed forced mutation.
///
/// `completed` names the number of fully written replacements and `partial`
/// the byte count written from the replacement at index `completed`. A
/// restoration failure means target bytes can no longer be proven coherent,
/// so the process terminates instead of returning.
#[inline(never)]
unsafe fn forced_restore(
    fd: usize,
    replacements: &[Replacement<'_>],
    completed: usize,
    partial: usize,
) {
    let mut index = 0;
    while index < completed {
        let replacement = &replacements[index];
        let mut written = 0_usize;
        // SAFETY: this descriptor wrote this exact range.
        // The let-None form keeps this window free of Option helper calls.
        let None = (unsafe {
            crate::sys::pwrite_self_mem_checked(
                fd,
                replacement.address,
                replacement.expected.as_ptr() as usize,
                replacement.expected.len(),
                &mut written,
            )
        }) else {
            crate::sys::fail_stop();
        };
        if !forced_bytes_match(replacement.address, replacement.expected) {
            crate::sys::fail_stop();
        }
        let ranges = [(replacement.address, replacement.end)];
        // SAFETY: the restored range remains live and readable.
        let None = (unsafe {
            crate::sys::flush_instruction_cache_ranges_checked(&ranges, true, &mut false)
        }) else {
            crate::sys::fail_stop();
        };
        index += 1;
    }
    if partial > 0 && completed < replacements.len() {
        let replacement = &replacements[completed];
        let mut written = 0_usize;
        // SAFETY: only this prefix of the range changed.
        let None = (unsafe {
            crate::sys::pwrite_self_mem_checked(
                fd,
                replacement.address,
                replacement.expected.as_ptr() as usize,
                partial,
                &mut written,
            )
        }) else {
            crate::sys::fail_stop();
        };
        if !forced_bytes_match(replacement.address, &replacement.expected[..partial]) {
            crate::sys::fail_stop();
        }
        let ranges = [(replacement.address, replacement.address + partial)];
        // SAFETY: the restored prefix remains live and readable.
        let None = (unsafe {
            crate::sys::flush_instruction_cache_ranges_checked(&ranges, true, &mut false)
        }) else {
            crate::sys::fail_stop();
        };
    }
}

/// Compares stored bytes at `address` with `expected` using plain loads.
#[inline(never)]
fn forced_bytes_match(address: usize, expected: &[u8]) -> bool {
    let mut index = 0_usize;
    while index < expected.len() {
        // SAFETY: the freshly validated mapping covers this readable byte.
        let current = unsafe { *std::ptr::with_exposed_provenance::<u8>(address + index) };
        if current != expected[index] {
            return false;
        }
        index += 1;
    }
    true
}

#[inline(never)]
fn page_is_first(replacements: &[Replacement<'_>], index: usize, page_index: usize) -> bool {
    let page = &replacements[index].pages[page_index];
    // This function runs while target pages are non-executable, so it belongs
    // to the closed mutation-window code set: no closures, iterator adapters,
    // or values with non-trivial drop glue such as `Result` temporaries, which
    // the linker may place outside the rejected page span.
    let mut previous_index = 0;
    while previous_index < index {
        let previous_pages = replacements[previous_index].pages;
        let mut candidate_index = 0;
        while candidate_index < previous_pages.len() {
            if previous_pages[candidate_index].start == page.start {
                return false;
            }
            candidate_index += 1;
        }
        previous_index += 1;
    }
    let pages = replacements[index].pages;
    let mut candidate_index = 0;
    while candidate_index < page_index {
        if pages[candidate_index].start == page.start {
            return false;
        }
        candidate_index += 1;
    }
    true
}

#[inline(never)]
fn open_unique_pages(replacements: &[Replacement<'_>], keeping_exec: bool) -> Option<Errno> {
    let mut opened = 0_usize;
    let mut index = 0;
    while index < replacements.len() {
        let pages = replacements[index].pages;
        let mut page_index = 0;
        while page_index < pages.len() {
            if !page_is_first(replacements, index, page_index) {
                page_index += 1;
                continue;
            }
            let page = &pages[page_index];
            // SAFETY: the exact captured page remains live and caller-quiescent.
            let failure = unsafe {
                crate::sys::protect_checked(
                    page.start,
                    page.length,
                    writable_protection(page, keeping_exec),
                )
            };
            if let Some(failure) = failure {
                restore_first_pages(replacements, opened);
                return Some(failure);
            }
            opened += 1;
            page_index += 1;
        }
        index += 1;
    }
    None
}

#[inline(never)]
fn restore_first_pages(replacements: &[Replacement<'_>], limit: usize) {
    let mut restored = 0_usize;
    let mut index = 0;
    while index < replacements.len() {
        let pages = replacements[index].pages;
        let mut page_index = 0;
        while page_index < pages.len() {
            if !page_is_first(replacements, index, page_index) {
                page_index += 1;
                continue;
            }
            let page = &pages[page_index];
            if restored < limit {
                // SAFETY: this page was opened by the current operation.
                // A let-else keeps this window free of Option helper calls.
                let None = (unsafe {
                    crate::sys::protect_checked(page.start, page.length, page.original_protection)
                }) else {
                    crate::sys::fail_stop();
                };
                restored += 1;
            }
            page_index += 1;
        }
        index += 1;
    }
}

#[inline(never)]
fn close_unique_pages(replacements: &[Replacement<'_>]) -> Option<(usize, usize, Errno)> {
    let mut index = 0;
    let mut stuck = None;
    while index < replacements.len() {
        let pages = replacements[index].pages;
        let mut page_index = 0;
        while page_index < pages.len() {
            if !page_is_first(replacements, index, page_index) {
                page_index += 1;
                continue;
            }
            let page = &pages[page_index];
            // SAFETY: this exact page is currently RW and remains live.
            let failure = unsafe {
                crate::sys::protect_checked(page.start, page.length, page.original_protection)
            };
            if let Some(errno) = failure {
                stuck = stuck.or(Some((page.start, page.length, errno)));
            }
            page_index += 1;
        }
        index += 1;
    }
    stuck
}

#[inline(never)]
fn reopen_unique_pages(replacements: &[Replacement<'_>], keeping_exec: bool) {
    let mut index = 0;
    while index < replacements.len() {
        let pages = replacements[index].pages;
        let mut page_index = 0;
        while page_index < pages.len() {
            if !page_is_first(replacements, index, page_index) {
                page_index += 1;
                continue;
            }
            let page = &pages[page_index];
            // SAFETY: the page remains live and is reopened for rollback.
            let None = (unsafe {
                crate::sys::protect_checked(
                    page.start,
                    page.length,
                    writable_protection(page, keeping_exec),
                )
            }) else {
                crate::sys::fail_stop();
            };
            page_index += 1;
        }
        index += 1;
    }
}

/// Restores every target byte and closes every page opened by this operation.
///
/// Returns the first page that could not be closed, as `(start, length,
/// errno)`, after attempting every other page. The bytes are always restored
/// first, so a reported page has correct contents and only its protection is
/// wrong — but it is left writable and non-executable, which no later call in
/// this process can repair. Any further page that failed the same way is in the
/// same state and is not reported separately.
#[inline(never)]
unsafe fn rollback_open_many(
    replacements: &[Replacement<'_>],
    _keeping_exec: bool,
) -> Option<(usize, usize, Errno)> {
    let mut stuck: Option<(usize, usize, Errno)> = None;
    let mut restore_index = 0;
    while restore_index < replacements.len() {
        let replacement = &replacements[restore_index];
        // SAFETY: every page covering this target is RW and expected is disjoint.
        unsafe { copy_mapped_bytes(replacement.pages, replacement.address, replacement.expected) };
        restore_index += 1;
    }
    let mut flush_index = 0;
    while flush_index < replacements.len() {
        let replacement = &replacements[flush_index];
        let ranges = [(replacement.address, replacement.end)];
        // SAFETY: every restored target range remains live and writable.
        let None = (unsafe {
            crate::sys::flush_instruction_cache_ranges_checked(&ranges, true, &mut false)
        }) else {
            crate::sys::fail_stop();
        };
        flush_index += 1;
    }
    let mut index = 0;
    while index < replacements.len() {
        let pages = replacements[index].pages;
        let mut page_index = 0;
        while page_index < pages.len() {
            if !page_is_first(replacements, index, page_index) {
                page_index += 1;
                continue;
            }
            let page = &pages[page_index];
            // SAFETY: restore each exact page to its captured protection.
            // A let-else keeps this window free of Option helper calls.
            let Some(errno) = (unsafe {
                crate::sys::protect_checked(page.start, page.length, page.original_protection)
            }) else {
                page_index += 1;
                continue;
            };
            // Keep going: every other page must still be closed, and reporting
            // the first failure while silently leaving later pages open would
            // understate the damage.
            if stuck.is_none() {
                stuck = Some((page.start, page.length, errno));
            }
            page_index += 1;
        }
        index += 1;
    }
    stuck
}

/// Every page from the lowest to two pages beyond the highest address of the
/// inline mutation window's closed function set.
///
/// A target sharing one of these pages with the installer itself cannot
/// satisfy the whole-page quiescence contract: the installing thread must run
/// this code to complete the mutation. The rejected set is the complete page
/// span between the lowest and highest listed function plus two trailing
/// pages, not only each entry page: a debug build can place several kilobytes
/// of one listed function or clone after a late entry address, so a single
/// trailing page no longer bounds every body, and unrelated code inside the
/// span is rejected conservatively. Keep the entry list synchronized with the
/// functions and closures that execute between [`replace_many`] opening and
/// closing pages; the window functions must stay free of closures, iterator
/// adapters, and values with non-trivial drop glue such as `Result`
/// temporaries.
pub(super) fn mutation_code_pages(page_size: usize) -> Vec<usize> {
    let addresses = mutation_code_addresses();
    let mut lowest = usize::MAX;
    let mut highest = 0_usize;
    for &address in &addresses {
        lowest = lowest.min(address);
        highest = highest.max(address);
    }
    let mut page = crate::sys::page_start(lowest, page_size);
    let last_page = crate::sys::page_start(highest.saturating_add(2 * page_size), page_size);
    let span_pages = last_page.saturating_sub(page).saturating_add(page_size - 1) / page_size;
    let mut pages = Vec::with_capacity(span_pages.max(1));
    while page <= last_page {
        pages.push(page);
        match page.checked_add(page_size) {
            Some(next) => page = next,
            None => break,
        }
    }
    pages
}

/// Returns whether any captured page contains the inline mutation code.
pub(super) fn pages_overlap_mutation_code(pages: &[CodePage], code: &[usize]) -> bool {
    pages.iter().any(|page| code.contains(&page.start))
}

/// Entry addresses of every function in the closed inline mutation-window
/// code set.
///
/// The raw three-argument syscall stub backs every in-window `mprotect` and
/// ARM `cacheflush`; the remaining syscallN stubs are reached only on the
/// already-terminal fail_stop path.
///
/// A failed DropExec restore can leave a target page non-executable while the
/// installer is still unwinding, so the error-return path from
/// `replace_many` up to the public entry points belongs to the closed set
/// too: a target page overlapping any of those frames would fault on return.
fn mutation_code_addresses() -> Vec<usize> {
    vec![
        replace_many as *const () as usize,
        replace_many_mutating as *const () as usize,
        replace_many_forced as *const () as usize,
        replace_many_with_elevation as *const () as usize,
        flush_replacements as *const () as usize,
        elevate as *const () as usize,
        elevate_keeping_exec as *const () as usize,
        page_protection_failure as *const () as usize,
        page_protection_failure_from_tuple as *const () as usize,
        forced_failure as *const () as usize,
        // These run after `replace_many_with_elevation` returns, which can
        // leave a target page in a protection state the caller must repair.
        retryable_page_elevation_failure as *const () as usize,
        elevation_failure as *const () as usize,
        elevation_error as *const () as usize,
        forced_restore as *const () as usize,
        forced_bytes_match as *const () as usize,
        page_is_first as *const () as usize,
        open_unique_pages as *const () as usize,
        restore_first_pages as *const () as usize,
        close_unique_pages as *const () as usize,
        reopen_unique_pages as *const () as usize,
        rollback_open_many as *const () as usize,
        mapped_bytes_match as *const () as usize,
        copy_mapped_bytes as *const () as usize,
        range_end as *const () as usize,
        writable_protection as *const () as usize,
        page::writable_protection as *const () as usize,
        crate::sys::protect as *const () as usize,
        crate::sys::protect_checked as *const () as usize,
        crate::sys::flush_instruction_cache_ranges_checked as *const () as usize,
        crate::sys::sync_instruction_stream as *const () as usize,
        crate::sys::page_start as *const () as usize,
        crate::sys::fail_stop as *const () as usize,
        syscalls::raw::syscall3 as *const () as usize,
        syscalls::raw::syscall1 as *const () as usize,
        crate::sys::pwrite_self_mem_checked as *const () as usize,
        crate::sys::pwrite64 as *const () as usize,
        crate::sys::close_self_mem as *const () as usize,
        close_forced_descriptor as *const () as usize,
        // Error-return frames that keep executing after a target page may
        // have been left without `PROT_EXEC`: the commit and removal
        // entry points, their error construction and cleanup helpers, and
        // the byte-encoding toggle used on the unhook rollback path.
        super::install_inline_hook as *const () as usize,
        super::install_inline_hooks as *const () as usize,
        super::unhook_inline_hooks as *const () as usize,
        super::commit_prepared_inline_hooks as *const () as usize,
        super::commit_replacements as *const () as usize,
        super::unhook_replacements as *const () as usize,
        super::apply_protection_flags_to as *const () as usize,
        super::register_inline_targets as *const () as usize,
        super::reserve_inline_targets as *const () as usize,
        super::inline_targets_installed as *const () as usize,
        super::preferred_error as *const () as usize,
        super::release_arenas as *const () as usize,
        super::discard_prepared_inline_hooks as *const () as usize,
        crate::sys::toggle_bytes_encoding as *const () as usize,
        crate::sys::erase_bytes as *const () as usize,
        crate::sys::enter_mutation as *const () as usize,
        crate::sys::leave_mutation as *const () as usize,
        forced_syscall_stub(),
    ]
}

/// The raw `pwrite64` syscall stub used by the forced mutation path.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn forced_syscall_stub() -> usize {
    syscalls::raw::syscall4 as *const () as usize
}

/// The raw `pwrite64` syscall stub used by the forced mutation path.
#[cfg(target_arch = "arm")]
fn forced_syscall_stub() -> usize {
    syscalls::raw::syscall6 as *const () as usize
}

/// The raw `pwrite64` syscall stub used by the forced mutation path.
#[cfg(target_arch = "x86")]
fn forced_syscall_stub() -> usize {
    syscalls::raw::syscall5 as *const () as usize
}

#[inline(never)]
fn mapped_bytes_match(pages: &[CodePage], address: usize, expected: &[u8]) -> Result<bool> {
    let end = range_end(address, expected.len())?;
    let mut offset = 0_usize;
    let mut page_index = 0;
    while page_index < pages.len() {
        let page = &pages[page_index];
        let page_end = range_end(page.start, page.length)?;
        let start = address.max(page.start);
        let limit = end.min(page_end);
        if start >= limit {
            page_index += 1;
            continue;
        }
        let length = limit - start;
        let next = match offset.checked_add(length) {
            Some(next) if next <= expected.len() => next,
            _ => return Err(Error::MappingChanged),
        };
        // SAFETY: the freshly validated page covers this readable chunk.
        let current: &[u8] =
            unsafe { std::slice::from_raw_parts(std::ptr::with_exposed_provenance(start), length) };
        if current != &expected[offset..next] {
            return Ok(false);
        }
        offset = next;
        page_index += 1;
    }
    if offset != expected.len() {
        return Err(Error::MappingChanged);
    }
    Ok(true)
}

/// Copies `bytes` to `address` across the pages covering it.
///
/// The bytes go down in order. `KeepExec` intentionally writes while every
/// affected page stays executable and depends on whole-page quiescence;
/// `DropExec` removes `PROT_EXEC` first, and forced access bypasses this
/// function through `/proc/self/mem`.
///
/// # Safety
///
/// Every page must be writable and cover its part of the range, and `bytes`
/// must not alias the destination.
#[inline(never)]
unsafe fn copy_mapped_bytes(pages: &[CodePage], address: usize, bytes: &[u8]) {
    let first = address;
    let end = address + bytes.len();
    let mut page_index = 0;
    while page_index < pages.len() {
        let page = &pages[page_index];
        // Keep the mutation window free of Ord helper calls: debug builds can
        // leave `usize::max`/`min` out of the closed code set.
        let start = if first > page.start {
            first
        } else {
            page.start
        };
        let page_end = page.start + page.length;
        let limit = if end < page_end { end } else { page_end };
        if start >= limit {
            page_index += 1;
            continue;
        }
        let length = limit - start;
        let offset = start - address;
        // Volatile byte stores keep LLVM from replacing this loop with an
        // external `memcpy` call, including in optimized builds. That call
        // or its PLT stub could sit on the page being mutated.
        // SAFETY: the caller made this page writable, and each byte stays
        // within one mapping while reading a disjoint source slice.
        // SAFETY: both base pointers come from the validated ranges above.
        let (source, destination) = unsafe {
            (
                bytes.as_ptr().add(offset),
                std::ptr::with_exposed_provenance_mut::<u8>(start),
            )
        };
        let mut index = 0;
        while index < length {
            // SAFETY: both pointers stay inside the validated ranges above.
            unsafe { std::ptr::write_volatile(destination.add(index), *source.add(index)) };
            index += 1;
        }
        page_index += 1;
    }
}

fn executable_code_map(map: &MapInfo) -> bool {
    map.is_private
        && map.perms.contains(MapPerms::READ | MapPerms::EXEC)
        && !map.perms.contains(MapPerms::WRITE)
}

#[inline(never)]
fn writable_protection(page: &CodePage, keeping_exec: bool) -> i32 {
    if keeping_exec {
        page.original_protection | libc::PROT_WRITE
    } else {
        page::writable_protection(page)
    }
}

#[inline(never)]
fn range_end(address: usize, length: usize) -> Result<usize> {
    address.checked_add(length).ok_or(Error::ArithmeticOverflow)
}

#[cfg(test)]
pub(super) mod tests;

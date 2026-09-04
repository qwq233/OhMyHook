use crate::maps::{
    MapInfo, MapPerms, MappingIdentity, find_map_containing, read_self_maps_for_ranges,
};
use crate::{Error, MutationPath, Result};

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
pub(super) struct CodePage {
    start: usize,
    length: usize,
    original_protection: i32,
    mapping: MappingIdentity,
}

impl CodePage {
    /// Returns the page's start address and length.
    pub(super) const fn span(&self) -> (usize, usize) {
        (self.start, self.length)
    }
}

pub(super) fn copy_executable_window(
    maps: &[MapInfo],
    address: usize,
    output: &mut [u8],
) -> Result<usize> {
    let map = find_map_containing(maps, address, 1)
        .filter(|map| executable_code_map(map))
        .ok_or(Error::MappingChanged)?;
    let mapping = MappingIdentity::from_map(map);
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
        .filter(|map| executable_code_map(map))
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
    let ranges = crate::maps::page_ranges([address])?;
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
            mapping: MappingIdentity::from_map(map),
        });
        page = page
            .checked_add(page_size)
            .ok_or(Error::ArithmeticOverflow)?;
    }

    let replacement_guarded = page::capture_flags(&mut pages, maps, page_flags, replacement)?;
    Ok((pages, replacement_guarded))
}

pub(super) fn read_page_flags(ranges: &[(usize, usize)]) -> Result<PageFlags> {
    page::read_flags(ranges)
}

pub(super) fn arena_protection(pages: &[CodePage]) -> i32 {
    page::arena_protection(pages)
}

#[cfg(target_arch = "aarch64")]
pub(super) fn is_guarded(pages: &[CodePage]) -> bool {
    page::is_guarded(pages)
}

pub(super) fn validate_pages(maps: &[MapInfo], pages: &[CodePage]) -> Result<()> {
    for page in pages {
        let map = find_map_containing(maps, page.start, page.length)
            .filter(|map| page.mapping.matches_at(map, page.start))
            .ok_or(Error::MappingChanged)?;
        if !executable_code_map(map) {
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

/// What a completed mutation did, beyond succeeding.
///
/// Both fields exist so the caller can act after it has released the process
/// lock: this crate emits no log record while an internal guard is held.
#[derive(Clone, Copy)]
pub(super) struct MutationOutcome {
    pub(super) path: MutationPath,
    /// Failed `close(2)` errno after a mutation that otherwise fully succeeded.
    pub(super) descriptor_close_errno: Option<i32>,
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

#[inline(never)]
pub(super) unsafe fn replace_many(
    replacements: &[Replacement<'_>],
    validation_maps: Option<&[MapInfo]>,
) -> Result<MutationOutcome> {
    let count = replacements.len();
    if count == 0 {
        return Ok(MutationOutcome {
            path: MutationPath::Protection,
            descriptor_close_errno: None,
        });
    }
    let mut byte_ranges = Vec::with_capacity(count);
    for &replacement in replacements {
        if replacement.expected.len() != replacement.replacement.len()
            || replacement.expected.is_empty()
        {
            return Err(Error::InvalidInlineTarget("invalid patch byte count"));
        }
        let end = range_end(replacement.address, replacement.expected.len())?;
        if replacement.end != end {
            return Err(Error::InvalidInlineTarget(
                "replacement end does not match its expected byte range",
            ));
        }
        byte_ranges.push((replacement.address, end));
    }
    for pair in byte_ranges.windows(2) {
        // The input is normally already target ordered; sort-free overlap
        // checking keeps the preflight allocation bounded to one small list.
        if pair[0].0 < pair[1].1 && pair[1].0 < pair[0].1 {
            return Err(Error::Conflict);
        }
    }
    for left in 0..byte_ranges.len() {
        for right in left + 1..byte_ranges.len() {
            if byte_ranges[left].0 < byte_ranges[right].1
                && byte_ranges[right].0 < byte_ranges[left].1
            {
                return Err(Error::Conflict);
            }
        }
    }

    let mut ranges = None;
    if validation_maps.is_none() {
        ranges = Some(replacement_page_ranges(replacements)?);
    }
    let loaded_maps = match ranges.as_deref() {
        Some(ranges) => Some(read_self_maps_for_ranges(ranges)?),
        None if validation_maps.is_some() => None,
        None => return Err(Error::InvalidInlineTarget("missing validation maps")),
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
            return Err(Error::Conflict);
        }
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
                        return Err(Error::MappingChanged);
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
    drop(byte_ranges);
    drop(loaded_maps);

    crate::sys::enter_mutation();
    // SAFETY: forwarded from this function's complete contract.
    let outcome: Result<MutationOutcome> = unsafe { replace_many_mutating(replacements) };
    // Reached only on a normal return. Unwinding past this point deliberately
    // leaves the flag set, because a panic inside the window is the one case
    // where a later poisoned lock must still terminate the process.
    crate::sys::leave_mutation();
    outcome
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
) -> Option<(RawRangeStorage, (&'static str, i32))> {
    let mut ranges = Vec::with_capacity(replacements.len());
    let mut index = 0;
    while index < replacements.len() {
        let replacement = &replacements[index];
        ranges.push((replacement.address, replacement.end));
        index += 1;
    }
    let storage = RawRangeStorage::from_vec(ranges);
    // SAFETY: every named range remains live and readable.
    let failure = unsafe {
        crate::sys::flush_instruction_cache_ranges_checked(std::slice::from_raw_parts(
            storage.pointer,
            storage.length,
        ))
    };
    failure.map(|failure| (storage, failure))
}

/// The half of `replace_many` that can leave a target only partly written.
///
/// # Safety
///
/// The same contract as [`replace_many`] applies.
unsafe fn replace_many_mutating(replacements: &[Replacement<'_>]) -> Result<MutationOutcome> {
    // Prefer the channel that never removes PROT_EXEC. This avoids the one
    // real Android failure mode: SELinux may allow dropping executable
    // protection but refuse to restore a written page.
    #[cfg(test)]
    let forced_unavailable = tests::take_forced_unavailable_failure();
    #[cfg(not(test))]
    let forced_unavailable = false;
    let mem = if forced_unavailable {
        None
    } else {
        Some(crate::sys::open_self_mem()?)
    };
    if mem.is_none() {
        // SAFETY: the validated private mappings cover every forced write.
        unsafe { replace_many_with_elevation(replacements) }?;
        return Ok(MutationOutcome {
            path: MutationPath::Protection,
            descriptor_close_errno: None,
        });
    }
    // SAFETY: the validated private mappings cover every forced write.
    match unsafe { replace_many_forced(replacements, mem) } {
        ForcedOutcome::Done => Ok(MutationOutcome {
            path: MutationPath::ForcedAccess,
            descriptor_close_errno: None,
        }),
        // The hooks are installed. Reporting failure here would make the caller
        // discard the batch and unmap the arenas the new entries branch into,
        // turning a leaked descriptor into a crash at the next call through any
        // patched target. The leak is carried out for the caller to log once it
        // has released the process lock.
        ForcedOutcome::DoneWithLeakedDescriptor => Ok(MutationOutcome {
            path: MutationPath::ForcedAccess,
            descriptor_close_errno: Some(libc::EIO),
        }),
        ForcedOutcome::Unavailable => Err(Error::UnsupportedFeature(
            "forced-access mutation is unavailable",
        )),
        ForcedOutcome::Failed(operation, errno) => Err(Error::system_call(operation, errno)),
        ForcedOutcome::Corrupted => Err(Error::Conflict),
        // Reported only after the mutation was undone, so every target holds
        // the bytes it held before this call and only the descriptor leaked.
        // This must not be `InlineCleanupPending`: for a removal, "undone"
        // means the target is still patched, and that variant promises the
        // opposite.
        ForcedOutcome::CloseFailed => Err(Error::ForcedDescriptorLeaked),
    }
}

/// Applies every replacement through the baseline page-elevation sequence.
///
/// # Safety
///
/// Every replacement must name live, validated private executable pages, and
/// the caller must keep those pages quiescent and writer-exclusive.
#[inline(never)]
unsafe fn replace_many_with_elevation(replacements: &[Replacement<'_>]) -> Result<()> {
    if let Some((operation, errno)) = open_unique_pages(replacements) {
        // open_unique_pages restored every page it opened before returning.
        return Err(Error::system_call(operation, errno));
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
    match unsafe { flush_replacements(replacements) } {
        None => {}
        Some((_ranges, (operation, errno))) => {
            // SAFETY: all pages remain open and every saved byte range is valid.
            if let Some(stuck) = unsafe { rollback_open_many(replacements) } {
                return Err(page_protection_lost(stuck));
            }
            return Err(Error::system_call(operation, errno));
        }
    }
    if let Some((operation, errno)) = close_unique_pages(replacements) {
        // A failed restoration leaves a mixed page state. Reopen every page,
        // restore bytes, and close coherently.
        reopen_unique_pages(replacements);
        // SAFETY: every page is again RW.
        if let Some(stuck) = unsafe { rollback_open_many(replacements) } {
            return Err(page_protection_lost(stuck));
        }
        return Err(Error::system_call(operation, errno));
    }
    Ok(())
}

/// Builds the error for a page a rollback could not close.
fn page_protection_lost((address, length, errno): (usize, usize, i32)) -> Error {
    Error::TargetPageProtectionLost {
        address,
        length,
        source: std::io::Error::from_raw_os_error(errno),
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
pub(super) fn page_elevation_denied(error: &Error) -> bool {
    matches!(
        error,
        Error::SystemCall {
            operation: "mprotect",
            source,
            ..
        } if matches!(
            source.raw_os_error().unwrap_or(0),
            libc::EPERM | libc::EACCES | libc::ENOSYS | libc::EIO | libc::ENOMEM
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
    Done,
    /// The forced-access file is unavailable; the caller keeps the page-elevation error.
    Unavailable,
    /// The attempt failed after restoring every byte it changed.
    Failed(&'static str, i32),
    /// A written range did not read back as its replacement bytes.
    Corrupted,
    /// The kernel refused to close the forced-access descriptor after the
    /// mutation had already been rolled back.
    ///
    /// The target holds its original bytes, so reporting a failure is accurate
    /// and the descriptor is the only thing leaked.
    CloseFailed,
    /// Every replacement was written, verified, and flushed, and only the
    /// closing of the forced-access descriptor failed.
    ///
    /// The hooks are live. This must be reported as success: a caller that
    /// believes the installation failed discards the batch, which unmaps the
    /// arenas the freshly written entries now branch into. A leaked descriptor
    /// is the far smaller problem.
    DoneWithLeakedDescriptor,
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
    mem: Option<usize>,
) -> ForcedOutcome {
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
            None if tests::take_forced_write_failure() => Some(libc::EPERM),
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
            return ForcedOutcome::CloseFailed;
        }
        return ForcedOutcome::Failed("pwrite64", errno);
    }
    // Verify every written range before publishing it to instruction fetch.
    let mut verify_index = 0;
    while verify_index < replacements.len() {
        let replacement = &replacements[verify_index];
        if !forced_bytes_match(replacement.address, replacement.replacement) {
            // SAFETY: every completed range is restored from its expected
            // bytes before the failure is reported.
            unsafe { forced_restore(fd, replacements, replacements.len(), 0) };
            if close_forced_descriptor(fd).is_some() {
                return ForcedOutcome::CloseFailed;
            }
            return ForcedOutcome::Corrupted;
        }
        verify_index += 1;
    }
    // SAFETY: every freshly written range remains live and readable.
    match unsafe { flush_replacements(replacements) } {
        None => {}
        Some((_ranges, (operation, errno))) => {
            // SAFETY: every completed range is restored before the failure is
            // reported.
            unsafe { forced_restore(fd, replacements, replacements.len(), 0) };
            if close_forced_descriptor(fd).is_some() {
                return ForcedOutcome::CloseFailed;
            }
            return ForcedOutcome::Failed(operation, errno);
        }
    }
    if close_forced_descriptor(fd).is_some() {
        return ForcedOutcome::DoneWithLeakedDescriptor;
    }
    ForcedOutcome::Done
}

/// Closes the forced-access descriptor, reporting whether it failed.
///
/// Every exit from the forced path goes through here so a test can make the
/// close fail wherever it is reached, without the injection having to guess
/// which exit an operation will take.
#[inline(never)]
fn close_forced_descriptor(fd: usize) -> Option<i32> {
    let failed = crate::sys::close_self_mem(fd);
    #[cfg(test)]
    let failed = if tests::take_forced_close_failure() {
        failed.or(Some(libc::EIO))
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
        let ranges = [(replacement.address, replacement.end)];
        // SAFETY: the restored range remains live and readable.
        let None = (unsafe { crate::sys::flush_instruction_cache_ranges_checked(&ranges) }) else {
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
        let ranges = [(replacement.address, replacement.address + partial)];
        // SAFETY: the restored prefix remains live and readable.
        let None = (unsafe { crate::sys::flush_instruction_cache_ranges_checked(&ranges) }) else {
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
fn open_unique_pages(replacements: &[Replacement<'_>]) -> Option<(&'static str, i32)> {
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
                    page::writable_protection(page),
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
fn close_unique_pages(replacements: &[Replacement<'_>]) -> Option<(&'static str, i32)> {
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
            // SAFETY: this exact page is currently RW and remains live.
            let failure = unsafe {
                crate::sys::protect_checked(page.start, page.length, page.original_protection)
            };
            let None = failure else {
                return failure;
            };
            page_index += 1;
        }
        index += 1;
    }
    None
}

#[inline(never)]
fn reopen_unique_pages(replacements: &[Replacement<'_>]) {
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
                    page::writable_protection(page),
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
unsafe fn rollback_open_many(replacements: &[Replacement<'_>]) -> Option<(usize, usize, i32)> {
    let mut stuck: Option<(usize, usize, i32)> = None;
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
        let None = (unsafe { crate::sys::flush_instruction_cache_ranges_checked(&ranges) }) else {
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
            let Some((_, errno)) = (unsafe {
                crate::sys::protect_checked(page.start, page.length, page.original_protection)
            }) else {
                page_index += 1;
                continue;
            };
            // A refusal to give a written page its executable protection back
            // is the signature of a domain without `execmod`, and it is
            // permanent. Record it here rather than where elevation itself
            // fails: an `EPERM` from opening the page is an ordinary blanket
            // denial, already handled by falling through to the forced channel,
            // and treating the two alike would strand every later installation
            // on a domain that can still use elevation.
            if errno == libc::EACCES || errno == libc::EPERM {
                EXEC_RESTORE_DENIED.store(true, std::sync::atomic::Ordering::Release);
            }
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

/// Set once a policy has refused to restore a written page's executable
/// protection.
///
/// This costs one installation to learn: nothing distinguishes such a domain
/// before the first write, because the refusal only applies to a page the
/// process has already modified. Every installation after that skips elevation
/// and writes through the forced channel, which never reprotects anything.
static EXEC_RESTORE_DENIED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

fn exec_restore_denied() -> bool {
    EXEC_RESTORE_DENIED.load(std::sync::atomic::Ordering::Acquire)
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
fn mutation_code_addresses() -> Vec<usize> {
    vec![
        replace_many as *const () as usize,
        replace_many_mutating as *const () as usize,
        replace_many_forced as *const () as usize,
        replace_many_with_elevation as *const () as usize,
        // These run after `replace_many_with_elevation` returns, which on the
        // stuck-page path still leaves a target page non-executable.
        page_elevation_denied as *const () as usize,
        page_protection_lost as *const () as usize,
        exec_restore_denied as *const () as usize,
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
        page::writable_protection as *const () as usize,
        crate::sys::flush_instruction_cache_ranges as *const () as usize,
        crate::sys::protect as *const () as usize,
        crate::sys::protect_checked as *const () as usize,
        crate::sys::flush_instruction_cache_ranges_checked as *const () as usize,
        crate::sys::sync_instruction_stream as *const () as usize,
        crate::sys::syscall_result as *const () as usize,
        crate::sys::syscall_failure as *const () as usize,
        crate::sys::page_start as *const () as usize,
        crate::sys::fail_stop as *const () as usize,
        syscalls::raw::syscall3 as *const () as usize,
        syscalls::raw::syscall1 as *const () as usize,
        crate::sys::pwrite_self_mem_checked as *const () as usize,
        crate::sys::pwrite64 as *const () as usize,
        crate::sys::close_self_mem as *const () as usize,
        close_forced_descriptor as *const () as usize,
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
/// The bytes go down in order. Publishing the entry word last would only matter
/// on a path that keeps the page executable while it writes, and this function
/// is not on one: the elevation path makes every target page non-executable
/// first, and the forced-access path writes through `/proc/self/mem` instead of
/// coming here at all.
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
        // A plain byte loop replaces `ptr::copy_nonoverlapping` here: the
        // latter lowers to an external `memcpy` call in debug builds, and
        // that call or its PLT stub could sit on the page being mutated.
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
            unsafe { *destination.add(index) = *source.add(index) };
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
fn range_end(address: usize, length: usize) -> Result<usize> {
    address.checked_add(length).ok_or(Error::ArithmeticOverflow)
}

#[cfg(test)]
pub(super) mod tests;

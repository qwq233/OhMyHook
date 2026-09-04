pub(super) fn mutation_scope(
    maps: &[MapInfo],
    plans: &[Option<HookPlan>],
    saved_protections: Option<&BTreeMap<usize, i32>>,
) -> Result<MutationScope> {
    let page_size = crate::sys::page_size()?;
    let mut images = Vec::with_capacity(plans.len());
    let mut slots = Vec::with_capacity(plans.len());
    let mut pages = Vec::with_capacity(plans.len());
    for write in plans.iter().flatten().flat_map(|plan| &plan.writes) {
        images.push(write.image);
        slots.push(write.address);
        pages.push(crate::sys::page_start(write.address, page_size));
    }
    images.sort_unstable();
    images.dedup();
    slots.sort_unstable();
    slots.dedup();
    pages.sort_unstable();
    pages.dedup();
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
    crate::maps::validate_page_write_access(maps, &pages, page_size)?;
    let image_count = images.len();
    let slot_count = slots.len();
    let page_count = pages.len();
    let mut writable = Vec::new();
    for start in pages {
        let (map_index, map) = find_page_map_index(maps, start, page_size)?;
        if map.perms.contains(MapPerms::EXEC) {
            return Err(Error::UnsupportedFeature("executable relocation page"));
        }
        if !map.perms.contains(MapPerms::WRITE) {
            let original_protection = match saved_protections {
                Some(protections) => {
                    let saved = *protections.get(&start).ok_or(Error::MappingChanged)?;
                    let rwx = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
                    map.perms.to_prot() | (saved & !rwx)
                }
                None => map.perms.to_prot(),
            };
            writable.push(WritablePage {
                start,
                map_index,
                original_protection,
            });
        }
    }
    Ok(MutationScope {
        writable,
        images: image_count,
        slots: slot_count,
        pages: page_count,
        page_size,
    })
}

#[cfg(target_arch = "aarch64")]
use crate::maps::SmapInfo;

#[cfg(target_arch = "aarch64")]
pub(super) fn installation_mutation_scope(
    maps: &[MapInfo],
    plans: &[Option<HookPlan>],
    replacement_landings: Option<&[SmapInfo]>,
    validated_page_smaps: &[crate::maps::SmapInfo],
) -> Result<MutationScope> {
    let scope = mutation_scope(maps, plans, None)?;
    {
        let mut scope = scope;
        let features = crate::sys::aarch64_memory_protection_features();
        let needs_exact_protection_features = features.mte;
        if features.bti && !needs_exact_protection_features {
            // mutation_scope rejects executable pages; BTI leaves data access unchanged.
            for page in &mut scope.writable {
                page.original_protection |= PROT_BTI;
            }
        }
        if !scope.writable.is_empty() && needs_exact_protection_features {
            let page_size = scope.page_size;
            let mut smaps = replacement_landings.unwrap_or(&[]).to_vec();
            smaps.extend(validated_page_smaps.iter().cloned());
            let missing = scope.writable.iter().any(|page| {
                !smaps
                    .iter()
                    .any(|entry| entry.map.contains_range(page.start, page_size))
            });
            let needed_ranges = if missing {
                page_ranges_for_sorted_pages(
                    scope.writable.iter().map(|page| page.start),
                    page_size,
                )?
            } else {
                Vec::new()
            };
            if !needed_ranges.is_empty() {
                smaps.extend(read_self_smaps_for_ranges(&needed_ranges)?);
            }
            normalize_smaps(&mut smaps);
            let smaps = smaps.as_slice();
            add_aarch64_protection_flags(maps, smaps, page_size, &mut scope.writable)?;
        }
        Ok(scope)
    }
}

#[cfg(target_arch = "aarch64")]
pub(super) fn normalize_smaps(smaps: &mut Vec<SmapInfo>) {
    smaps.sort_unstable_by_key(|entry| entry.map.start);
    smaps.dedup_by(|current, next| {
        current.map == next.map
            && current.vm_flags == next.vm_flags
            && current.protection_key == next.protection_key
    });
}

#[cfg(test)]
pub(super) fn mutation_plan(
    maps: &[MapInfo],
    plans: &[Option<HookPlan>],
    scope: MutationScope,
) -> Result<MutationPlan> {
    mutation_plan_with_channel(maps, plans, scope, None, None)
}

pub(super) fn mutation_plan_with_channel(
    maps: &[MapInfo],
    plans: &[Option<HookPlan>],
    scope: MutationScope,
    forced_fd: Option<usize>,
    forced_open_errno: Option<syscalls::Errno>,
) -> Result<MutationPlan> {
    let MutationScope {
        writable,
        images,
        slots,
        pages,
        page_size,
    } = scope;
    let writable_ranges = coalesce_writable_pages(&writable, page_size)?;
    let write_count = plans.iter().flatten().try_fold(0_usize, |total, plan| {
        total
            .checked_add(plan.writes.len())
            .ok_or(Error::ArithmeticOverflow)
    })?;
    let mut scheduled = Vec::with_capacity(write_count);
    for (hook_index, plan) in plans.iter().enumerate() {
        let Some(plan) = plan else {
            continue;
        };
        for &write in &plan.writes {
            let range = writable_range_index(&writable_ranges, write.address)?;
            if range.is_none()
                && !find_map_containing(maps, write.address, std::mem::size_of::<usize>())
                    .is_some_and(|map| map.perms.contains(MapPerms::WRITE))
            {
                return Err(Error::MappingChanged);
            }
            let order = scheduled.len();
            scheduled.push((range, hook_index, order, write));
        }
    }
    scheduled.sort_unstable_by_key(|&(range, hook_index, order, _)| (range, hook_index, order));

    let mut chunks = Vec::with_capacity(plans.len().min(write_count));
    let mut writes = Vec::with_capacity(write_count);
    let mut next = 0;
    while scheduled
        .get(next)
        .is_some_and(|(range, _, _, _)| range.is_none())
    {
        append_range_chunk(&mut chunks, &mut writes, &scheduled, &mut next)?;
    }
    let initially_writable_chunks = 0..chunks.len();

    let mut ranges = Vec::with_capacity(writable_ranges.len());
    for (range_index, range) in writable_ranges.into_iter().enumerate() {
        let start = chunks.len();
        while scheduled
            .get(next)
            .is_some_and(|(group_range, _, _, _)| *group_range == Some(range_index))
        {
            append_range_chunk(&mut chunks, &mut writes, &scheduled, &mut next)?;
        }
        if start == chunks.len() {
            return Err(Error::InvalidElf("writable range has no relocation write"));
        }
        ranges.push(RangeWork {
            range,
            chunks: start..chunks.len(),
        });
    }
    if next != scheduled.len() || writes.len() != write_count {
        return Err(Error::InvalidElf("relocation write scheduling mismatch"));
    }

    Ok(MutationPlan {
        ranges,
        initially_writable_chunks,
        chunks,
        writes,
        forced_fd,
        forced_open_errno,
        images,
        slots,
        pages,
    })
}

fn writable_range_index(ranges: &[WritableRange], address: usize) -> Result<Option<usize>> {
    let index = ranges.partition_point(|range| range.start <= address);
    let Some(index) = index.checked_sub(1) else {
        return Ok(None);
    };
    let range = &ranges[index];
    let end = range
        .start
        .checked_add(range.length)
        .ok_or(Error::ArithmeticOverflow)?;
    Ok((address < end).then_some(index))
}

fn append_range_chunk(
    chunks: &mut Vec<RangeChunk>,
    writes: &mut Vec<StoredPointerWrite>,
    scheduled: &[(Option<usize>, usize, usize, StoredPointerWrite)],
    next: &mut usize,
) -> Result<()> {
    let &(range, hook_index, _, _) = scheduled
        .get(*next)
        .ok_or(Error::InvalidElf("empty relocation write chunk"))?;
    let start = writes.len();
    while let Some(&(next_range, next_hook, _, write)) = scheduled.get(*next) {
        if (next_range, next_hook) != (range, hook_index) {
            break;
        }
        writes.push(write);
        *next += 1;
    }
    chunks.push(RangeChunk {
        hook_index,
        writes: start..writes.len(),
        committed: false,
    });
    Ok(())
}

pub(super) fn coalesce_writable_pages(
    pages: &[WritablePage],
    page_size: usize,
) -> Result<Vec<WritableRange>> {
    let mut ranges: Vec<WritableRange> = Vec::with_capacity(pages.len());
    for page in pages {
        if let Some(previous) = ranges.last_mut() {
            let previous_end = previous
                .start
                .checked_add(previous.length)
                .ok_or(Error::ArithmeticOverflow)?;
            if previous.map_index == page.map_index
                && previous.original_protection == page.original_protection
                && previous_end == page.start
            {
                previous.length = previous
                    .length
                    .checked_add(page_size)
                    .ok_or(Error::ArithmeticOverflow)?;
                continue;
            }
        }
        ranges.push(WritableRange {
            start: page.start,
            length: page_size,
            map_index: page.map_index,
            original_protection: page.original_protection,
        });
    }
    Ok(ranges)
}

#[cfg(target_arch = "aarch64")]
pub(super) fn add_aarch64_protection_flags(
    maps: &[MapInfo],
    smaps: &[SmapInfo],
    page_size: usize,
    pages: &mut [WritablePage],
) -> Result<()> {
    if smaps
        .windows(2)
        .any(|pair| pair[0].map.start > pair[1].map.start)
    {
        return Err(Error::InvalidSmaps("mappings are not ordered"));
    }
    let mut smap_index = 0;
    for page in pages {
        let map = find_page_map(maps, page.start, page_size)?;
        while smaps
            .get(smap_index)
            .is_some_and(|entry| entry.map.end <= page.start)
        {
            smap_index += 1;
        }
        let smap = smaps
            .get(smap_index)
            .filter(|entry| entry.map.contains_range(page.start, page_size))
            .ok_or(Error::InvalidSmaps("target page has no matching mapping"))?;
        if smaps
            .get(smap_index + 1)
            .is_some_and(|entry| entry.map.contains_range(page.start, page_size))
        {
            return Err(Error::InvalidSmaps(
                "target page has multiple matching mappings",
            ));
        }
        if !MappingSnapshot::from_map(map).matches(&smap.map) {
            return Err(Error::MappingChanged);
        }
        if smap.vm_flags.bti {
            page.original_protection |= PROT_BTI;
        }
        if smap.vm_flags.mte {
            page.original_protection |= PROT_MTE;
        }
    }
    Ok(())
}

pub(super) fn find_page_map_index(
    maps: &[MapInfo],
    page: usize,
    page_size: usize,
) -> Result<(usize, &MapInfo)> {
    let index = maps.partition_point(|map| map.start <= page);
    let index = index.checked_sub(1).ok_or(Error::MappingChanged)?;
    let map = maps
        .get(index)
        .filter(|map| map.contains_range(page, page_size))
        .filter(|map| map.perms.contains(MapPerms::READ))
        .ok_or(Error::MappingChanged)?;
    if !map.is_private {
        return Err(Error::UnsupportedFeature("shared relocation page"));
    }
    Ok((index, map))
}

#[cfg(target_arch = "aarch64")]
fn find_page_map(maps: &[MapInfo], page: usize, page_size: usize) -> Result<&MapInfo> {
    find_page_map_index(maps, page, page_size).map(|(_, map)| map)
}

/// Applies one hook_index-local write chunk and rolls back its successful prefix.
///
/// # Safety
///
/// Every write must identify a live, writable, naturally aligned slot and no
/// competing writer may access those slots for the operation.
pub(super) unsafe fn write_chunk(writes: &[StoredPointerWrite]) -> Result<()> {
    for (index, write) in writes.iter().enumerate() {
        // SAFETY: forwarded from this function's slot contract.
        let exchanged = unsafe {
            crate::sys::compare_exchange_pointer(write.address, write.expected, write.replacement)
        };
        let error = match exchanged {
            Ok(true) => continue,
            Ok(false) => Error::Conflict,
            Err(error) => error,
        };
        // SAFETY: the prefix contains exactly this operation's successful
        // writes and remains writable and writer-exclusive.
        unsafe { rollback_or_abort(&writes[..index]) };
        return Err(error);
    }
    Ok(())
}

/// Applies one chunk through `/proc/self/mem` without changing protections.
///
/// # Safety
///
/// Every slot must remain live, naturally aligned, and readable through the
/// forced-access descriptor, with no competing writer for the operation.
pub(super) unsafe fn write_chunk_forced(writes: &[StoredPointerWrite], fd: usize) -> Result<()> {
    for (index, write) in writes.iter().enumerate() {
        let mut current = 0_usize;
        // SAFETY: forwarded from this function's slot and descriptor contract.
        let errno =
            // SAFETY: forwarded from this function's slot and descriptor contract.
            unsafe { crate::sys::pread_pointer_self_mem(fd, write.address, &mut current) };
        if let Some(errno) = errno {
            // SAFETY: the prefix contains only this operation's successful
            // writes and remains writable through the same descriptor.
            unsafe { rollback_forced_or_abort(&writes[..index], fd) };
            // A read refusal makes the channel unusable just like a write
            // refusal: the caller falls back to ordinary elevation.
            return Err(forced_channel_unavailable(errno));
        }
        if current != write.expected {
            // SAFETY: no write in this chunk happened yet, and the prefix
            // remains writable through the same descriptor.
            unsafe { rollback_forced_or_abort(&writes[..index], fd) };
            return Err(Error::Conflict);
        }
        let bytes = write.replacement.to_ne_bytes();
        let expected = write.expected.to_ne_bytes();
        let mut written = 0_usize;
        // SAFETY: the slot is live, naturally aligned, and writable through
        // the forced-access descriptor.
        // SAFETY: a partial write is restored below before the earlier
        // successful prefix, so no torn pointer survives the error path.
        let failure = unsafe {
            crate::sys::pwrite_self_mem_checked(
                fd,
                write.address,
                bytes.as_ptr() as usize,
                bytes.len(),
                &mut written,
            )
        };
        if let Some(errno) = failure {
            if written > 0 {
                // SAFETY: forwarded from this function's exact ElfImageSelector-range
                // contract.
                unsafe { restore_prefix_or_stop(fd, write.address, &expected[..written]) };
            }
            // The partial restore above is proven in the process view or the
            // process stopped; a torn slot can never reach the fallback.
            let observed =
                // SAFETY: the slot is live, naturally aligned, and readable,
                // and the volatile read cannot be folded with any earlier
                // load.
                unsafe { std::ptr::read_volatile(write.address as *const usize) };
            if observed != write.expected {
                crate::sys::fail_stop();
            }
            // SAFETY: the prefix contains only this operation's successful
            // writes and remains writable through the same descriptor.
            unsafe { rollback_forced_or_abort(&writes[..index], fd) };
            // A write refusal makes the channel unusable, exactly like an
            // open refusal: the caller falls back to ordinary elevation.
            return Err(forced_channel_unavailable(errno));
        }
        // Verify through the process's own page table, not through the
        // descriptor: a kernel can accept a forced write and surface it back
        // through `/proc/self/mem` while the bytes stay invisible to the
        // process, because the write landed on the backing object instead of
        // the private copy. Such a chunk must not be reported as installed.
        let observed =
            // SAFETY: the slot is live, naturally aligned, and readable, and
            // the volatile read cannot be folded with any earlier load.
            unsafe { std::ptr::read_volatile(write.address as *const usize) };
        if observed != write.replacement {
            // The write is invisible to the process. The only safe value for
            // the caller is the expected one: anything else means a torn slot
            // or a forbidden concurrent writer, and neither can be reported
            // as "unchanged" or "installed".
            if observed != write.expected {
                crate::sys::fail_stop();
            }
            // The process view is proven unchanged, so the descriptor-side
            // restore below only keeps `/proc` readers from observing the
            // replacement; its failure cannot affect execution.
            let mut restored = 0_usize;
            // SAFETY: the slot is live, naturally aligned, and writable
            // through the descriptor; the expected bytes are a stack value.
            let _ = unsafe {
                crate::sys::pwrite_self_mem_checked(
                    fd,
                    write.address,
                    expected.as_ptr() as usize,
                    expected.len(),
                    &mut restored,
                )
            };
            // SAFETY: the prefix contains only verified writes and remains
            // writable through the same descriptor.
            unsafe { rollback_forced_or_abort(&writes[..index], fd) };
            return Err(forced_channel_unavailable(syscalls::Errno::EIO));
        }
    }
    Ok(())
}

/// Reports a forced channel that cannot deliver process-visible writes.
fn forced_channel_unavailable(errno: syscalls::Errno) -> Error {
    Error::MutationPathUnavailable {
        forced_access: Some(errno),
        protection_keeping_exec: None,
        protection: None,
    }
}

/// Restores the exact partial prefix of one pointer slot.
///
/// # Safety
///
/// `address..address + prefix.len()` must remain live and writable through
/// the descriptor.
unsafe fn restore_prefix_or_stop(fd: usize, address: usize, prefix: &[u8]) {
    let mut written = 0_usize;
    // SAFETY: forwarded from this function's exact ElfImageSelector-range contract.
    let failure = unsafe {
        crate::sys::pwrite_self_mem_checked(
            fd,
            address,
            prefix.as_ptr() as usize,
            prefix.len(),
            &mut written,
        )
    };
    if failure.is_some() || written != prefix.len() {
        crate::sys::fail_stop();
    }
}

/// Reverts successful forced writes, proving the restoration in the process's
/// own page tables. A mismatch is unrecoverable.
///
/// # Safety
///
/// Every slot must remain live and writable through the descriptor.
unsafe fn rollback_forced_or_abort(writes: &[StoredPointerWrite], fd: usize) {
    for write in writes.iter().rev() {
        let bytes = write.expected.to_ne_bytes();
        let mut current = 0_usize;
        // SAFETY: forwarded from this function's slot and descriptor contract.
        if unsafe { crate::sys::pread_pointer_self_mem(fd, write.address, &mut current) }.is_some()
            || current != write.replacement
        {
            crate::sys::fail_stop();
        }
        // SAFETY: the slot is live, naturally aligned, and writable through
        // the forced-access descriptor.
        let mut written = 0_usize;
        // SAFETY: a partial restore below is itself unrecoverable, so it is
        // followed by fail-stop rather than a retryable error.
        let failure = unsafe {
            crate::sys::pwrite_self_mem_checked(
                fd,
                write.address,
                bytes.as_ptr() as usize,
                bytes.len(),
                &mut written,
            )
        };
        if failure.is_some() || written != bytes.len() {
            crate::sys::fail_stop();
        }
        // The descriptor view alone cannot prove the slot the process will
        // execute through was restored: the same kernel that accepted a write
        // invisible to the process could accept an invisible restore. A slot
        // still holding its replacement would leave a live hook_index with no
        // removal record, so the process stops instead of returning a state
        // neither side of the fallback can reason about.
        let observed =
            // SAFETY: the slot is live, naturally aligned, and readable, and
            // the volatile read cannot be folded with any earlier load.
            unsafe { std::ptr::read_volatile(write.address as *const usize) };
        if observed != write.expected {
            crate::sys::fail_stop();
        }
    }
}

/// Commits every planned chunk while elevating at most one read-only range.
///
/// # Safety
///
/// The complete installer mapping, writer-exclusion, and replacement-lifetime
/// contract applies. `state` and `mutation` must be fresh for this call.
pub(super) unsafe fn commit_mutation(
    mutation: &mut MutationPlan,
    state: &mut CommitState,
    policy: CommitPolicy,
) -> std::result::Result<(), CommitFailure> {
    // SAFETY: forwarded from this function's exact range-lifetime contract.
    unsafe {
        commit_mutation_with(mutation, state, policy, |start, length, protection| {
            // SAFETY: every call is for the currently owned planned range.
            crate::sys::protect(start, length, protection)
        })
    }
}

#[cfg(not(target_arch = "aarch64"))]
pub(super) fn installation_mutation_scope(
    maps: &[MapInfo],
    plans: &[Option<HookPlan>],
    _replacement_landings: Option<&[crate::maps::MapInfo]>,
    _validated_page_smaps: &[crate::maps::SmapInfo],
) -> Result<MutationScope> {
    mutation_scope(maps, plans, None)
}

/// Internal seam allowing deterministic protection-order and recovery tests.
///
/// # Safety
///
/// The same contract as [`commit_mutation`] applies.
pub(super) unsafe fn commit_mutation_with<P>(
    mutation: &mut MutationPlan,
    state: &mut CommitState,
    policy: CommitPolicy,
    protect: P,
) -> std::result::Result<(), CommitFailure>
where
    P: FnMut(usize, usize, i32) -> Result<()>,
{
    let mut forced_failure = mutation.forced_open_errno;
    if let Some(fd) = mutation.forced_fd {
        // The forced path changes ElfImageSelector bytes without changing protections,
        // so it runs inside the same mutation window as the elevation path: a
        // panic with half-written slots must keep the fail-stop lock policy.
        crate::sys::enter_mutation();
        // SAFETY: every planned slot was validated as a private mapping and
        // the public contract keeps it live and writer-exclusive.
        let outcome = unsafe { commit_forced(mutation, state, policy, fd) };
        // Reached only on a normal return; an unwind keeps the window open.
        crate::sys::leave_mutation();
        let channel_unusable = matches!(
            outcome.as_ref().err().map(|failure| &failure.source),
            Some(Error::MutationPathUnavailable { .. })
        );
        if !channel_unusable {
            return outcome;
        }
        if let Err(failure) = &outcome
            && let Error::MutationPathUnavailable {
                forced_access: Some(errno),
                ..
            } = &failure.source
        {
            forced_failure = Some(*errno);
        }
        // The channel cannot deliver process-visible writes and the failed
        // attempt restored every slot. Fall back to the documented ordinary
        // elevation channel, which still produces the same private
        // copy-on-write page for a Validated request.
        mutation.forced_fd = None;
    }
    crate::sys::enter_mutation();
    // SAFETY: forwarded from this function's complete contract.
    let mut outcome = unsafe { commit_mutation_inner(mutation, state, policy, protect) };
    // Reached only on a normal return. Unwinding past this point deliberately
    // leaves the flag set, because a panic with slots half-written is the one
    // case where a later poisoned lock must still terminate the process.
    crate::sys::leave_mutation();
    if let Err(failure) = &mut outcome
        && let Some(forced_errno) = forced_failure
        && let Error::SystemCall { source, .. } = failure.source
    {
        failure.source = Error::MutationPathUnavailable {
            forced_access: Some(forced_errno),
            protection_keeping_exec: Some(source),
            protection: None,
        };
    }
    outcome
}

/// Commits every chunk through `/proc/self/mem`, changing no protections.
///
/// # Safety
///
/// Every slot must remain live, naturally aligned, readable and writable
/// through `fd`, and free of competing writers for the complete call.
unsafe fn commit_forced(
    mutation: &mut MutationPlan,
    state: &mut CommitState,
    policy: CommitPolicy,
    fd: usize,
) -> std::result::Result<(), CommitFailure> {
    for chunk_index in 0..mutation.chunks.len() {
        let hook_index = mutation.chunks[chunk_index].hook_index;
        if state.failed_hooks[hook_index] {
            continue;
        }
        let writes = mutation.chunks[chunk_index].writes.clone();
        // SAFETY: forwarded from this function's complete slot contract.
        match unsafe { write_chunk_forced(&mutation.writes[writes], fd) } {
            Ok(()) => mutation.chunks[chunk_index].committed = true,
            Err(source) if matches!(source, Error::MutationPathUnavailable { .. }) => {
                // The channel is unusable for every remaining write, so an
                // independent batch cannot continue through it either. The
                // complete commit is reverted and the caller retries the
                // batch through the ordinary elevation channel.
                // SAFETY: no protection range exists and the record names
                // exactly the successful earlier chunks.
                unsafe { rollback_committed_forced(mutation, None, fd) };
                state.rollback_hooks.fill(false);
                return Err(CommitFailure {
                    hook_index: Some(hook_index),
                    source,
                });
            }
            Err(source) => match policy {
                CommitPolicy::Independent => {
                    state.failed_hooks[hook_index] = true;
                    state.rollback_hooks[hook_index] = true;
                    state.hook_errors[hook_index] = Some(source);
                }
                CommitPolicy::RollbackAllOnFailure => {
                    // SAFETY: no protection range exists and the record names
                    // exactly the successful earlier chunks.
                    unsafe { rollback_committed_forced(mutation, None, fd) };
                    return Err(CommitFailure {
                        hook_index: Some(hook_index),
                        source,
                    });
                }
            },
        }
    }
    if state.rollback_hooks.iter().any(|failed| *failed) {
        // SAFETY: selected chunks can be reverted directly through the
        // descriptor; no range was ever elevated.
        unsafe { rollback_committed_forced(mutation, Some(&state.rollback_hooks), fd) };
        state.rollback_hooks.fill(false);
    }
    Ok(())
}

unsafe fn commit_mutation_inner<P>(
    mutation: &mut MutationPlan,
    state: &mut CommitState,
    policy: CommitPolicy,
    mut protect: P,
) -> std::result::Result<(), CommitFailure>
where
    P: FnMut(usize, usize, i32) -> Result<()>,
{
    for chunk_index in mutation.initially_writable_chunks.clone() {
        let hook_index = mutation.chunks[chunk_index].hook_index;
        if state.failed_hooks[hook_index] {
            continue;
        }
        let writes = mutation.chunks[chunk_index].writes.clone();
        // SAFETY: these slots were validated as already writable and remain
        // live and writer-exclusive under the public contract.
        match unsafe { write_chunk(&mutation.writes[writes]) } {
            Ok(()) => mutation.chunks[chunk_index].committed = true,
            Err(source) => match policy {
                CommitPolicy::Independent => {
                    state.failed_hooks[hook_index] = true;
                    state.rollback_hooks[hook_index] = true;
                    state.hook_errors[hook_index] = Some(source);
                }
                CommitPolicy::RollbackAllOnFailure => {
                    // SAFETY: no protected range is open, and the record
                    // contains exactly the successful earlier chunks.
                    unsafe { rollback_committed(mutation, None, &mut protect) };
                    return Err(CommitFailure {
                        hook_index: Some(hook_index),
                        source,
                    });
                }
            },
        }
    }

    if state.rollback_hooks.iter().any(|failed| *failed) {
        // SAFETY: initially-writable chunks are not protected by a range;
        // selected committed chunks can be reverted directly, and no range
        // is open yet.
        unsafe { rollback_committed(mutation, Some(&state.rollback_hooks), &mut protect) };
        state.rollback_hooks.fill(false);
    }

    for range_index in 0..mutation.ranges.len() {
        if !mutation.ranges[range_index]
            .chunks
            .clone()
            .any(|index| !state.failed_hooks[mutation.chunks[index].hook_index])
        {
            continue;
        }
        let range = mutation.ranges[range_index].range;
        if let Err(source) = protect(
            range.start,
            range.length,
            range.original_protection | libc::PROT_WRITE,
        ) {
            // This range lies wholly in one stable captured VMA and received
            // no relocation write. Earlier ranges are already closed, so
            // recovery can reopen them one at a time.
            unsafe {
                // SAFETY: earlier ranges were closed and this rollback only
                // reopens the ranges it needs to restore.
                rollback_committed(mutation, None, &mut protect)
            };
            return Err(CommitFailure {
                hook_index: None,
                source,
            });
        }

        let chunks = mutation.ranges[range_index].chunks.clone();
        for chunk_index in chunks {
            let hook_index = mutation.chunks[chunk_index].hook_index;
            if state.failed_hooks[hook_index] {
                continue;
            }
            let writes = mutation.chunks[chunk_index].writes.clone();
            // SAFETY: the current range alone is elevated and covers every
            // validated slot in this hook_index-local chunk.
            match unsafe { write_chunk(&mutation.writes[writes]) } {
                Ok(()) => mutation.chunks[chunk_index].committed = true,
                Err(source) => match policy {
                    CommitPolicy::Independent => {
                        state.failed_hooks[hook_index] = true;
                        state.rollback_hooks[hook_index] = true;
                        state.hook_errors[hook_index] = Some(source);
                    }
                    CommitPolicy::RollbackAllOnFailure => {
                        // SAFETY: the current range is writable; remove every
                        // completed chunk in it before closing the range.
                        unsafe { rollback_open_range(mutation, range_index, None) };
                        if let Err(error) =
                            protect(range.start, range.length, range.original_protection)
                        {
                            // SAFETY: recovery first makes the failed current
                            // range coherent, then visits earlier ranges.
                            let source = unsafe {
                                recover_close_failure(mutation, range_index, &mut protect, error)
                            };
                            return Err(CommitFailure {
                                hook_index: None,
                                source,
                            });
                        }
                        // SAFETY: the current range is closed and cleared;
                        // earlier ranges are reopened one at a time.
                        unsafe { rollback_committed(mutation, None, &mut protect) };
                        return Err(CommitFailure {
                            hook_index: Some(hook_index),
                            source,
                        });
                    }
                },
            }
        }

        if let Err(source) = protect(range.start, range.length, range.original_protection) {
            // SAFETY: the current range may still be writable. Recovery makes
            // it coherent before touching any earlier range.
            let source =
                unsafe { recover_close_failure(mutation, range_index, &mut protect, source) };
            return Err(CommitFailure {
                hook_index: None,
                source,
            });
        }

        if state.rollback_hooks.iter().any(|failed| *failed) {
            // SAFETY: no protected range is open. Only chunks belonging to
            // Hooks which failed in this range are selected for rollback.
            unsafe { rollback_committed(mutation, Some(&state.rollback_hooks), &mut protect) };
            state.rollback_hooks.fill(false);
        }
    }

    Ok(())
}

/// Reverts successful writes. Any mismatch means coherence can no longer be
/// proven, so recovery is fail-stop.
///
/// # Safety
///
/// Every slot must remain live, writable, and free of competing writers.
pub(super) unsafe fn rollback_or_abort(writes: &[StoredPointerWrite]) {
    for write in writes.iter().rev() {
        // SAFETY: forwarded from this function's slot contract.
        match unsafe {
            crate::sys::compare_exchange_pointer(write.address, write.replacement, write.expected)
        } {
            Ok(true) => {}
            Ok(false) | Err(_) => crate::sys::fail_stop(),
        }
    }
}

/// Reverts selected committed chunks through the forced-write descriptor.
///
/// # Safety
///
/// Every slot must remain live and writable through `fd`, with no competing
/// writer for the complete recovery.
unsafe fn rollback_committed_forced(
    mutation: &mut MutationPlan,
    hooks: Option<&[bool]>,
    fd: usize,
) {
    for chunk_index in (0..mutation.chunks.len()).rev() {
        if !chunk_selected(&mutation.chunks[chunk_index], hooks) {
            continue;
        }
        let writes = mutation.chunks[chunk_index].writes.clone();
        // SAFETY: forwarded from this function's complete slot contract.
        unsafe { rollback_forced_or_abort(&mutation.writes[writes], fd) };
        mutation.chunks[chunk_index].committed = false;
    }
}

fn chunk_selected(chunk: &RangeChunk, hooks: Option<&[bool]>) -> bool {
    chunk.committed
        && hooks.is_none_or(|hooks| hooks.get(chunk.hook_index).copied().unwrap_or(false))
}

/// Rolls back selected committed chunks while the named range is writable.
///
/// # Safety
///
/// `range_index` must be the only temporarily elevated range, and all selected
/// slots must remain live, writable, and writer-exclusive.
unsafe fn rollback_open_range(
    mutation: &mut MutationPlan,
    range_index: usize,
    hooks: Option<&[bool]>,
) {
    for chunk_index in mutation.ranges[range_index].chunks.clone().rev() {
        if !chunk_selected(&mutation.chunks[chunk_index], hooks) {
            continue;
        }
        let writes = mutation.chunks[chunk_index].writes.clone();
        // SAFETY: this committed chunk lies wholly in the open range.
        unsafe { rollback_or_abort(&mutation.writes[writes]) };
        mutation.chunks[chunk_index].committed = false;
    }
}

/// Reopens closed ranges one at a time and reverts selected committed chunks.
///
/// # Safety
///
/// No planned read-only range may be open on entry. Mappings and slots must
/// satisfy the complete installer lifetime and writer-exclusion contract.
unsafe fn rollback_committed<P>(
    mutation: &mut MutationPlan,
    hooks: Option<&[bool]>,
    protect: &mut P,
) where
    P: FnMut(usize, usize, i32) -> Result<()>,
{
    for range_index in (0..mutation.ranges.len()).rev() {
        let has_committed = mutation.ranges[range_index]
            .chunks
            .clone()
            .any(|index| chunk_selected(&mutation.chunks[index], hooks));
        if !has_committed {
            continue;
        }
        let range = mutation.ranges[range_index].range;
        if protect(
            range.start,
            range.length,
            range.original_protection | libc::PROT_WRITE,
        )
        .is_err()
        {
            crate::sys::fail_stop();
        }
        // SAFETY: this is the sole open range and it contains the selected
        // committed chunks identified above.
        unsafe { rollback_open_range(mutation, range_index, hooks) };
        if protect(range.start, range.length, range.original_protection).is_err() {
            crate::sys::fail_stop();
        }
    }

    for chunk_index in mutation.initially_writable_chunks.clone().rev() {
        if !chunk_selected(&mutation.chunks[chunk_index], hooks) {
            continue;
        }
        let writes = mutation.chunks[chunk_index].writes.clone();
        // SAFETY: these slots were originally writable and remain so.
        unsafe { rollback_or_abort(&mutation.writes[writes]) };
        mutation.chunks[chunk_index].committed = false;
    }
}

/// Recovers an unsuccessful range restoration before touching earlier ranges.
///
/// # Safety
///
/// `range_index` names the failed current range. Every mapping and slot must
/// remain live and writer-exclusive for the complete recovery.
unsafe fn recover_close_failure<P>(
    mutation: &mut MutationPlan,
    range_index: usize,
    protect: &mut P,
    error: Error,
) -> Error
where
    P: FnMut(usize, usize, i32) -> Result<()>,
{
    let range = mutation.ranges[range_index].range;
    if protect(
        range.start,
        range.length,
        range.original_protection | libc::PROT_WRITE,
    )
    .is_err()
    {
        crate::sys::fail_stop();
    }
    // SAFETY: recovery has re-established the current range as writable.
    unsafe { rollback_open_range(mutation, range_index, None) };
    if protect(range.start, range.length, range.original_protection).is_err() {
        crate::sys::fail_stop();
    }
    // SAFETY: the failed current range is now closed and clear.
    unsafe { rollback_committed(mutation, None, protect) };
    error
}
use super::*;

/// Owns a `/proc/self/mem` descriptor until the channel decision is final.
pub(super) struct ForcedFd {
    fd: Option<usize>,
    open_errno: Option<syscalls::Errno>,
}

impl ForcedFd {
    /// Opens the forced channel only when `wanted`, leaving the elevation
    /// path active whenever the descriptor cannot be opened.
    pub(super) fn open(wanted: bool) -> Self {
        if !wanted {
            return Self {
                fd: None,
                open_errno: None,
            };
        }
        match crate::sys::open_self_mem() {
            Ok(fd) => Self {
                fd: Some(fd),
                open_errno: None,
            },
            Err(errno) => Self {
                fd: None,
                open_errno: Some(errno),
            },
        }
    }

    pub(super) fn get(&self) -> Option<usize> {
        self.fd
    }

    pub(super) fn open_errno(&self) -> Option<syscalls::Errno> {
        self.open_errno
    }

    /// Releases ownership and returns the descriptor for an explicit close.
    pub(super) fn take(&mut self) -> Option<usize> {
        self.fd.take()
    }

    /// Closes the descriptor if present and reports a close failure.
    ///
    /// Callers must release the process guard first: the record runs the
    /// caller's logger.
    pub(super) fn close_and_report(&mut self) {
        // A plain match avoids a monomorphized `Option::and_then` wrapper
        // whose symbol name would collide with the mutation-window text
        // audit.
        let leaked = match self.fd.take() {
            Some(fd) => crate::sys::close_self_mem(fd).is_some(),
            None => false,
        };
        debug!("PLT forced descriptor close: leaked={leaked}");
    }
}

impl Drop for ForcedFd {
    fn drop(&mut self) {
        if let Some(fd) = self.fd.take() {
            let _ = crate::sys::close_self_mem(fd);
        }
    }
}

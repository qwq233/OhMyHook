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

pub(super) fn installation_mutation_scope(
    maps: &[MapInfo],
    plans: &[Option<HookPlan>],
) -> Result<MutationScope> {
    let scope = mutation_scope(maps, plans, None)?;
    #[cfg(target_arch = "aarch64")]
    {
        let mut scope = scope;
        if !scope.writable.is_empty() && crate::sys::aarch64_bti_supported() {
            let page_size = scope.page_size;
            let ranges = page_ranges_for_sorted_pages(
                scope.writable.iter().map(|page| page.start),
                page_size,
            )?;
            let smaps = read_self_smaps_for_ranges(&ranges)?;
            add_aarch64_protection_flags(maps, &smaps, page_size, &mut scope.writable)?;
        }
        Ok(scope)
    }
    #[cfg(not(target_arch = "aarch64"))]
    Ok(scope)
}

pub(super) fn mutation_plan(
    maps: &[MapInfo],
    plans: &[Option<HookPlan>],
    scope: MutationScope,
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
    for (hook, plan) in plans.iter().enumerate() {
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
            scheduled.push((range, hook, order, write));
        }
    }
    scheduled.sort_unstable_by_key(|&(range, hook, order, _)| (range, hook, order));

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
    writes: &mut Vec<PointerWrite>,
    scheduled: &[(Option<usize>, usize, usize, PointerWrite)],
    next: &mut usize,
) -> Result<()> {
    let &(range, hook, _, _) = scheduled
        .get(*next)
        .ok_or(Error::InvalidElf("empty relocation write chunk"))?;
    let start = writes.len();
    while let Some(&(next_range, next_hook, _, write)) = scheduled.get(*next) {
        if (next_range, next_hook) != (range, hook) {
            break;
        }
        writes.push(write);
        *next += 1;
    }
    chunks.push(RangeChunk {
        hook,
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
        if !MappingIdentity::from_map(map).matches(&smap.map) {
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

/// Applies one Hook-local write chunk and rolls back its successful prefix.
///
/// # Safety
///
/// Every write must identify a live, writable, naturally aligned slot and no
/// competing writer may access those slots for the operation.
pub(super) unsafe fn write_chunk(writes: &[PointerWrite]) -> Result<()> {
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
    crate::sys::enter_mutation();
    // SAFETY: forwarded from this function's complete contract.
    let outcome = unsafe { commit_mutation_inner(mutation, state, policy, protect) };
    // Reached only on a normal return. Unwinding past this point deliberately
    // leaves the flag set, because a panic with slots half-written is the one
    // case where a later poisoned lock must still terminate the process.
    crate::sys::leave_mutation();
    outcome
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
        let hook = mutation.chunks[chunk_index].hook;
        if state.failed_hooks[hook] {
            continue;
        }
        let writes = mutation.chunks[chunk_index].writes.clone();
        // SAFETY: these slots were validated as already writable and remain
        // live and writer-exclusive under the public contract.
        match unsafe { write_chunk(&mutation.writes[writes]) } {
            Ok(()) => mutation.chunks[chunk_index].committed = true,
            Err(source) => match policy {
                CommitPolicy::Independent => {
                    state.failed_hooks[hook] = true;
                    state.rollback_hooks[hook] = true;
                    state.hook_errors[hook] = Some(source);
                }
                CommitPolicy::Atomic => {
                    // SAFETY: no protected range is open, and the ledger
                    // contains exactly the successful earlier chunks.
                    unsafe { rollback_committed(mutation, None, &mut protect) };
                    return Err(CommitFailure {
                        hook: Some(hook),
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
            .any(|index| !state.failed_hooks[mutation.chunks[index].hook])
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
            unsafe { rollback_committed(mutation, None, &mut protect) };
            return Err(CommitFailure { hook: None, source });
        }

        let chunks = mutation.ranges[range_index].chunks.clone();
        for chunk_index in chunks {
            let hook = mutation.chunks[chunk_index].hook;
            if state.failed_hooks[hook] {
                continue;
            }
            let writes = mutation.chunks[chunk_index].writes.clone();
            // SAFETY: the current range alone is elevated and covers every
            // validated slot in this Hook-local chunk.
            match unsafe { write_chunk(&mutation.writes[writes]) } {
                Ok(()) => mutation.chunks[chunk_index].committed = true,
                Err(source) => match policy {
                    CommitPolicy::Independent => {
                        state.failed_hooks[hook] = true;
                        state.rollback_hooks[hook] = true;
                        state.hook_errors[hook] = Some(source);
                    }
                    CommitPolicy::Atomic => {
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
                            return Err(CommitFailure { hook: None, source });
                        }
                        // SAFETY: the current range is closed and cleared;
                        // earlier ranges are reopened one at a time.
                        unsafe { rollback_committed(mutation, None, &mut protect) };
                        return Err(CommitFailure {
                            hook: Some(hook),
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
            return Err(CommitFailure { hook: None, source });
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
pub(super) unsafe fn rollback_or_abort(writes: &[PointerWrite]) {
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

fn chunk_selected(chunk: &RangeChunk, hooks: Option<&[bool]>) -> bool {
    chunk.committed && hooks.is_none_or(|hooks| hooks.get(chunk.hook).copied().unwrap_or(false))
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

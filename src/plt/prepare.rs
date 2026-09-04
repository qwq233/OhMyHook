use super::ElfImageSelector;

pub(super) unsafe fn prepare_hooks(
    hooks: &[PltHookRequest<'_>],
    maps: &[MapInfo],
    collect_inspection_details: bool,
) -> Result<PreparedBatch> {
    let mut outcomes = std::iter::repeat_with(|| None)
        .take(hooks.len())
        .collect::<Vec<Option<Result<PltHookHandle>>>>();
    let mut scanned = std::iter::repeat_with(|| None)
        .take(hooks.len())
        .collect::<Vec<Option<ScannedHook>>>();
    let mut hook_images = if collect_inspection_details {
        std::iter::repeat_with(|| None)
            .take(hooks.len())
            .collect::<Vec<Option<Arc<[FoundImage]>>>>()
    } else {
        Vec::new()
    };
    let mut rejected = if collect_inspection_details {
        (0..hooks.len()).map(|_| Vec::new()).collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    let mut groups = BTreeMap::<&ElfImageSelector, Vec<usize>>::new();
    for (index, request) in hooks.iter().enumerate() {
        groups
            .entry(request.image_selector)
            .or_default()
            .push(index);
    }
    for (selector, indices) in groups {
        let queries = indices
            .iter()
            .map(|&index| hooks[index].query)
            .collect::<Vec<_>>();
        // SAFETY: forwarded from the caller's mapping and metadata stability
        // contract; scanning performs no relocation writes.
        let found = unsafe {
            elf::find_symbol_relocations(selector, maps, &queries, collect_inspection_details)?
        };
        let Some(found) = found else {
            for index in indices {
                outcomes[index] = Some(Err(Error::TargetNotLoaded));
            }
            continue;
        };
        if found.by_symbol.len() != indices.len() {
            return Err(Error::InvalidElf("symbol result count mismatch"));
        }
        let images: Arc<[FoundImage]> = found.images.into();
        for (index, mut found_symbol) in indices.into_iter().zip(found.by_symbol) {
            let request = &hooks[index];
            let mut error = apply_hook_selection(
                request,
                &mut found_symbol.relocations,
                &mut found_symbol.rejected,
            );
            if error.is_none() && request.single_image_and_slot_required {
                if images.len() != 1 {
                    error = Some(Error::MultipleLoadedImages {
                        actual: images.len(),
                    });
                } else if found_symbol.relocations.len() != 1 {
                    error = Some(Error::UnexpectedSlotCount {
                        expected: 1,
                        actual: found_symbol.relocations.len(),
                    });
                }
            }
            if collect_inspection_details {
                hook_images[index] = Some(Arc::clone(&images));
                rejected[index] = found_symbol.rejected;
            }
            if !found_symbol.relocations.is_empty() {
                scanned[index] = Some(ScannedHook {
                    relocations: found_symbol.relocations,
                    images: Arc::clone(&images),
                });
            }
            if let Some(error) = error {
                outcomes[index] = Some(Err(error));
            }
        }
    }

    let eligible = outcomes.iter().map(Option::is_none).collect::<Vec<_>>();
    let conflicting_slots = conflicting_slots(&scanned, &eligible)?;
    for (index, conflicts) in conflicting_slots.iter().enumerate() {
        if !conflicts.is_empty() {
            outcomes[index] = Some(Err(Error::Conflict));
        }
    }

    #[cfg(target_arch = "aarch64")]
    let replacement_landings = capture_replacement_landings(
        hooks,
        &scanned,
        &outcomes,
        maps,
        !collect_inspection_details,
    );
    #[cfg(target_arch = "aarch64")]
    for (index, error) in
        validate_replacement_landings(hooks, &scanned, &outcomes, maps, &replacement_landings)
    {
        outcomes[index] = Some(Err(error));
    }

    let mut plans = std::iter::repeat_with(|| None)
        .take(hooks.len())
        .collect::<Vec<Option<HookPlan>>>();
    for (index, scan) in scanned.iter().enumerate() {
        if outcomes[index].is_some() {
            continue;
        }
        let Some(scan) = scan else {
            continue;
        };
        match build_hook_plan(&hooks[index], scan) {
            Ok(plan) => plans[index] = Some(plan),
            Err(error) => outcomes[index] = Some(Err(error)),
        }
    }

    for (index, error) in validate_plan_mappings(hooks, &scanned, &plans, maps) {
        plans[index] = None;
        outcomes[index] = Some(Err(error));
    }

    let original_conflicts = original_pointer_cell_conflicts(hooks, &plans);
    for (index, conflict) in original_conflicts.into_iter().enumerate() {
        if conflict {
            plans[index] = None;
            outcomes[index] = Some(Err(Error::OriginalPointerCellConflict));
        }
    }

    Ok(PreparedBatch {
        outcomes,
        scanned,
        images: hook_images,
        rejected,
        conflicting_slots: if collect_inspection_details {
            conflicting_slots
        } else {
            Vec::new()
        },
        plans,
        #[cfg(target_arch = "aarch64")]
        replacement_landings,
    })
}

/// Validates that every planned slot belongs to the image that named it.
///
/// ELF metadata alone proves an address is inside a `PT_LOAD` range; the live
/// mapping must still be either that image's file mapping or loader-owned BSS.
/// Running this check in `prepare_hooks` makes inspection, installation, and
/// group installation share the same fail-closed boundary.
fn validate_plan_mappings(
    hooks: &[PltHookRequest<'_>],
    scanned: &[Option<ScannedHook>],
    plans: &[Option<HookPlan>],
    maps: &[MapInfo],
) -> Vec<(usize, Error)> {
    let mut failures = Vec::new();
    for (((request, scan), plan), index) in hooks.iter().zip(scanned).zip(plans).zip(0..) {
        let (Some(scan), Some(plan)) = (scan, plan) else {
            continue;
        };
        for write in &plan.writes {
            if let Err(error) = validate_pointer_mapping(
                request.image_selector,
                maps,
                write.image,
                write.address,
                &scan.images,
            ) {
                failures.push((index, error));
                break;
            }
        }
    }
    failures
}

pub(super) fn apply_hook_selection(
    request: &PltHookRequest<'_>,
    relocations: &mut Vec<FoundRelocation>,
    rejected: &mut Vec<RejectedRelocation>,
) -> Option<Error> {
    relocations.retain(|relocation| {
        request.relocation_kinds.contains(relocation.kind)
            && request
                .slot_selector
                .is_none_or(|selector| selector.matches_relocation(relocation))
    });
    rejected.retain(|relocation| {
        request.relocation_kinds.contains(relocation.kind)
            && request
                .slot_selector
                .is_none_or(|selector| selector.matches_rejected(relocation))
    });

    if request.slot_selector.is_some() && relocations.is_empty() && rejected.is_empty() {
        return Some(Error::SlotSelectorMismatch);
    }
    if rejected
        .iter()
        .any(|relocation| relocation.reason == RelocationRejection::PacPltVerificationFailed)
    {
        return Some(Error::Conflict);
    }
    if rejected
        .iter()
        .any(|relocation| relocation.reason == RelocationRejection::ImplicitAddend)
    {
        return Some(Error::UnsupportedFeature(
            "implicit-addend absolute relocation",
        ));
    }
    if rejected
        .iter()
        .any(|relocation| relocation.reason == RelocationRejection::UnsupportedAddend)
    {
        return Some(Error::UnsupportedFeature(
            "non-zero explicit addend on x86-64 relocation",
        ));
    }
    if let Some(expected) = request.expected_slots
        && relocations.len() != expected.get()
    {
        return Some(Error::UnexpectedSlotCount {
            expected: expected.get(),
            actual: relocations.len(),
        });
    }
    relocations
        .is_empty()
        .then_some(Error::NoMatchingRelocation)
}

pub(super) fn original_pointer_cell_conflicts(
    hooks: &[PltHookRequest<'_>],
    plans: &[Option<HookPlan>],
) -> Vec<bool> {
    let mut previous_by_slot = BTreeMap::<*const OriginalPointerCell, (usize, bool)>::new();
    for (request, plan) in hooks.iter().zip(plans) {
        let (Some(original), Some(plan)) = (request.original_pointer_cell, plan) else {
            continue;
        };
        previous_by_slot
            .entry(original)
            .and_modify(|(previous, conflict)| *conflict |= *previous != plan.previous)
            .or_insert((plan.previous, false));
    }

    hooks
        .iter()
        .zip(plans)
        .map(|(request, plan)| {
            let (Some(original), Some(plan)) = (request.original_pointer_cell, plan) else {
                return false;
            };
            original
                .value
                .get()
                .is_some_and(|published| *published != plan.previous)
                || previous_by_slot[&(original as *const OriginalPointerCell)].1
        })
        .collect()
}

pub(super) fn publish_originals(hooks: &[PltHookRequest<'_>], plans: &[Option<HookPlan>]) {
    for (request, plan) in hooks.iter().zip(plans) {
        let Some(plan) = plan else {
            continue;
        };
        publish_original(request, plan.previous);
    }
}

pub(super) fn publish_original(request: &PltHookRequest<'_>, previous: usize) {
    let Some(original) = request.original_pointer_cell else {
        return;
    };
    if let Err(value) = original.value.set(previous)
        && original.value.get() != Some(&value)
    {
        crate::sys::fail_stop();
    }
}

/// Rechecks mutable slot and original-publication state immediately before
/// mutation.
///
/// # Safety
///
/// Every planned slot must remain live and readable under the public install
/// contract, and the caller must hold the process read or write lock.
pub(super) unsafe fn revalidate_hook_plans(
    hooks: &[PltHookRequest<'_>],
    plans: &[Option<HookPlan>],
) -> Result<Vec<Option<Error>>> {
    if hooks.len() != plans.len() {
        return Err(Error::InvalidElf("request plan count mismatch"));
    }
    let mut errors = std::iter::repeat_with(|| None)
        .take(plans.len())
        .collect::<Vec<_>>();
    for (index, plan) in plans.iter().enumerate() {
        let Some(plan) = plan else {
            continue;
        };
        for write in &plan.writes {
            // SAFETY: forwarded from this function's slot-lifetime contract.
            if unsafe { crate::sys::read_pointer(write.address)? } != write.expected {
                errors[index] = Some(Error::Conflict);
                break;
            }
        }
        if errors[index].is_none()
            && hooks[index].original_pointer_cell.is_some_and(|original| {
                original
                    .value
                    .get()
                    .is_some_and(|published| *published != plan.previous)
            })
        {
            errors[index] = Some(Error::OriginalPointerCellConflict);
        }
    }
    Ok(errors)
}

/// Process-local stack of installed replacement pointers per relocation slot.
///
/// The registry is accessed only while `PROCESS_LOCK` is held for writing, so
/// the mutex only keeps the map `Sync` and is never contended. It enforces
/// LIFO removal: removing a hook which another hook was stacked on fails with
/// [`Error::Conflict`] instead of silently bypassing the newer request. Every
/// stored slot and replacement value is obfuscated so the registry does not
/// expose a plaintext map of hooked relocation slots.
static NEXT_INSTALL_ID: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);

static INSTALLED_SLOT_STACKS: std::sync::Mutex<BTreeMap<usize, Vec<(usize, usize)>>> =
    std::sync::Mutex::new(BTreeMap::new());

pub(super) fn next_install_id() -> Result<usize> {
    let mut current = NEXT_INSTALL_ID.load(std::sync::atomic::Ordering::Relaxed);
    loop {
        let next = current.checked_add(1).ok_or(Error::ArithmeticOverflow)?;
        match NEXT_INSTALL_ID.compare_exchange_weak(
            current,
            next,
            std::sync::atomic::Ordering::Relaxed,
            std::sync::atomic::Ordering::Relaxed,
        ) {
            Ok(_) => return Ok(current),
            Err(observed) => current = observed,
        }
    }
}

fn installed_slot_stacks() -> std::sync::MutexGuard<'static, BTreeMap<usize, Vec<(usize, usize)>>> {
    crate::sys::recover_lock(INSTALLED_SLOT_STACKS.lock())
}

/// Returns whether `value` is the newest replacement this process installed
/// at `address`.
///
/// The registry mutex keeps the map `Sync`; a caller that must observe one
/// complete install or removal transaction holds `PROCESS_LOCK` for writing,
/// while read-only classification may run without it. A lazy-looking jump
/// slot whose value is our own committed replacement holds a previously
/// installed request, not an unresolved resolver.
pub(super) fn registered_top_replacement_matches(address: usize, value: usize) -> bool {
    installed_slot_stacks()
        .get(&crate::sys::encode_usize(address))
        .and_then(|stack| stack.last())
        .is_some_and(|&(_, encoded_replacement)| {
            encoded_replacement == crate::sys::encode_usize(value)
        })
}

pub(super) fn registered_top_install_matches(address: usize, value: usize, id: usize) -> bool {
    installed_slot_stacks()
        .get(&crate::sys::encode_usize(address))
        .and_then(|stack| stack.last())
        .is_some_and(|&(encoded_id, encoded_replacement)| {
            encoded_id == crate::sys::encode_usize(id)
                && encoded_replacement == crate::sys::encode_usize(value)
        })
}

/// Records one request's finally committed slot writes.
///
/// The caller must hold `PROCESS_LOCK` for writing.
pub(super) fn record_installed_writes(id: usize, writes: &[StoredPointerWrite]) {
    let mut stacks = installed_slot_stacks();
    for write in writes {
        stacks
            .entry(crate::sys::encode_usize(write.address))
            .or_default()
            .push((
                crate::sys::encode_usize(id),
                crate::sys::encode_usize(write.replacement),
            ));
    }
}

/// Validates that every removed hook is the newest request on each of its slots.
///
/// Each entry is `(install id, slot address, installed replacement)`. A batch
/// may remove a complete stack in one transaction: for every address, the
/// selected entries must be exactly the stack's top entries. Install ids keep
/// repeated replacement values distinct. The caller must hold `PROCESS_LOCK`
/// for writing.
pub(super) fn validate_removal_order(installed: &[(usize, usize, usize)]) -> Result<()> {
    let mut batches: BTreeMap<usize, BTreeMap<usize, usize>> = BTreeMap::new();
    for &(id, address, replacement) in installed {
        if batches
            .entry(address)
            .or_default()
            .insert(id, replacement)
            .is_some()
        {
            return Err(Error::Conflict);
        }
    }
    let stacks = installed_slot_stacks();
    for (address, batch) in batches {
        let Some(stack) = stacks.get(&crate::sys::encode_usize(address)) else {
            return Err(Error::Conflict);
        };
        if stack.len() < batch.len() {
            return Err(Error::Conflict);
        }
        let Some((_, encoded_current)) = stack.last() else {
            return Err(Error::Conflict);
        };
        // SAFETY: the caller holds the process write lock and the record
        // mapping checks establish a live, readable, aligned slot.
        if unsafe { crate::sys::read_pointer(address)? }
            != crate::sys::decode_usize(*encoded_current)
        {
            return Err(Error::Conflict);
        }
        for &(encoded_id, encoded_replacement) in &stack[stack.len() - batch.len()..] {
            let id = crate::sys::decode_usize(encoded_id);
            let replacement = crate::sys::decode_usize(encoded_replacement);
            if batch.get(&id) != Some(&replacement) {
                return Err(Error::Conflict);
            }
        }
    }
    Ok(())
}

/// Pops restored slot stacks after a successful removal transaction.
///
/// The caller must hold `PROCESS_LOCK` for writing and must have validated the
/// same entries immediately before the transaction.
pub(super) fn complete_removal(installed: &[(usize, usize, usize)]) {
    let mut batches: BTreeMap<usize, BTreeMap<usize, usize>> = BTreeMap::new();
    for &(id, address, replacement) in installed {
        if batches
            .entry(address)
            .or_default()
            .insert(id, replacement)
            .is_some()
        {
            crate::sys::fail_stop();
        }
    }
    let mut stacks = installed_slot_stacks();
    for (address, mut batch) in batches {
        let encoded_address = crate::sys::encode_usize(address);
        let Some(stack) = stacks.get_mut(&encoded_address) else {
            crate::sys::fail_stop();
        };
        for _ in 0..batch.len() {
            let Some((encoded_id, encoded_replacement)) = stack.pop() else {
                crate::sys::fail_stop();
            };
            let id = crate::sys::decode_usize(encoded_id);
            let replacement = crate::sys::decode_usize(encoded_replacement);
            if batch.remove(&id) != Some(replacement) {
                crate::sys::fail_stop();
            }
        }
        if !batch.is_empty() {
            crate::sys::fail_stop();
        }
        if stack.is_empty() {
            stacks.remove(&encoded_address);
        }
    }
}

/// Pops one finally restored slot without the batch map.
///
/// The caller must hold `PROCESS_LOCK` for writing and must have validated the
/// same entry immediately before the successful write.
pub(super) fn complete_single_removal(id: usize, address: usize, replacement: usize) {
    let encoded_address = crate::sys::encode_usize(address);
    let mut stacks = installed_slot_stacks();
    let Some(stack) = stacks.get_mut(&encoded_address) else {
        crate::sys::fail_stop();
    };
    let Some((encoded_id, encoded_replacement)) = stack.last().copied() else {
        crate::sys::fail_stop();
    };
    if crate::sys::decode_usize(encoded_id) != id
        || crate::sys::decode_usize(encoded_replacement) != replacement
    {
        crate::sys::fail_stop();
    }
    stack.pop();
    if stack.is_empty() {
        stacks.remove(&encoded_address);
    }
}

pub(super) fn prepare_plt_records(
    hooks: &[PltHookRequest<'_>],
    maps: &[MapInfo],
    scanned: &[Option<ScannedHook>],
    plans: &[Option<HookPlan>],
    protections: &Arc<BTreeMap<usize, i32>>,
) -> Result<Vec<Option<PltRemovalRecord>>> {
    if hooks.len() != scanned.len() || hooks.len() != plans.len() {
        return Err(Error::InvalidElf("request record count mismatch"));
    }
    let mut records = Vec::with_capacity(hooks.len());
    for ((request, scan), plan) in hooks.iter().zip(scanned).zip(plans) {
        let (Some(scan), Some(plan)) = (scan, plan) else {
            records.push(None);
            continue;
        };
        let (&first, writes) = plan
            .writes
            .split_first()
            .ok_or(Error::InvalidElf("empty request record"))?;
        let map = find_map_containing(maps, first.address, std::mem::size_of::<usize>())
            .ok_or(Error::MappingChanged)?;
        let first = PltRemovalEntry {
            write: encode_pointer_write(first),
            mapping: MappingSnapshot::from_map(map),
        };
        let mut rest = Vec::with_capacity(writes.len());
        for &write in writes {
            let map = find_map_containing(maps, write.address, std::mem::size_of::<usize>())
                .ok_or(Error::MappingChanged)?;
            rest.push(PltRemovalEntry {
                write: encode_pointer_write(write),
                mapping: MappingSnapshot::from_map(map),
            });
        }
        records.push(Some(PltRemovalRecord {
            id: next_install_id()?,
            image_selector: *request.image_selector,
            images: Arc::clone(&scan.images),
            first,
            rest,
            protections: PltSavedProtections::Shared(Arc::clone(protections)),
        }));
    }
    Ok(records)
}

/// Scrambles the pointer-shaped fields of one stored record write.
///
/// Image identity is not a pointer and stays plain so image bookkeeping can
/// compare it without decoding.
pub(super) fn encode_pointer_write(write: StoredPointerWrite) -> StoredPointerWrite {
    StoredPointerWrite {
        image: write.image,
        address: crate::sys::encode_usize(write.address),
        expected: crate::sys::encode_usize(write.expected),
        replacement: crate::sys::encode_usize(write.replacement),
    }
}

pub(super) fn validate_plt_record<'a>(
    record: &PltRemovalRecord,
    maps: &'a [MapInfo],
) -> Result<Option<&'a MapInfo>> {
    let mut last_map = None;
    for entry in record.entries() {
        let write = entry.decoded_write();
        let map = validate_pointer_mapping(
            &record.image_selector,
            maps,
            write.image,
            write.address,
            &record.images,
        )?;
        // PrivateFileValidation never replaces the page, so a live PrivateFileValidation selector
        // must still match its captured mapping identity exactly.
        if !entry.mapping.matches_at(map, write.address) {
            return Err(Error::MappingChanged);
        }
        if !map.perms.contains(MapPerms::READ) {
            return Err(Error::MappingChanged);
        }
        last_map = Some(map);
    }
    Ok(last_map)
}

pub(super) fn conflicting_slots(
    scanned: &[Option<ScannedHook>],
    eligible: &[bool],
) -> Result<Vec<BTreeSet<usize>>> {
    if scanned.len() != eligible.len() {
        return Err(Error::InvalidElf("request eligibility count mismatch"));
    }
    let slot_count = scanned
        .iter()
        .zip(eligible)
        .filter_map(|(scan, &eligible)| eligible.then_some(scan.as_ref()).flatten())
        .try_fold(0_usize, |total, scan| {
            total
                .checked_add(scan.relocations.len())
                .ok_or(Error::ArithmeticOverflow)
        })?;
    let mut slots = Vec::with_capacity(slot_count);
    for (request, (scan, &eligible)) in scanned.iter().zip(eligible).enumerate() {
        if !eligible {
            continue;
        }
        if let Some(scan) = scan {
            slots.extend(
                scan.relocations
                    .iter()
                    .map(|relocation| (relocation.address, request)),
            );
        }
    }
    slots.sort_unstable();

    let mut conflicts = vec![BTreeSet::new(); scanned.len()];
    let mut start = 0;
    while start < slots.len() {
        let mut end = start + 1;
        while end < slots.len() && slots[end].0 == slots[start].0 {
            end += 1;
        }
        if end - start > 1 {
            for &(_, request) in &slots[start..end] {
                conflicts[request].insert(slots[start].0);
            }
        }
        start = end;
    }
    Ok(conflicts)
}

pub(super) fn build_hook_plan(
    request: &PltHookRequest<'_>,
    scan: &ScannedHook,
) -> Result<HookPlan> {
    build_hook_plan_for_relocations(request, &scan.relocations)
}

pub(super) fn build_hook_plan_for_relocations(
    request: &PltHookRequest<'_>,
    relocations: &[FoundRelocation],
) -> Result<HookPlan> {
    let mut writes = Vec::with_capacity(relocations.len());
    let mut previous = None;
    for relocation in relocations {
        let (write, current) = build_pointer_write(request, relocation)?;
        match previous {
            None => previous = Some(current),
            Some(previous) if previous != current => {
                return Err(Error::AmbiguousPreviousPointer);
            }
            Some(_) => {}
        }
        writes.push(write);
    }

    let slots = NonZeroUsize::new(writes.len()).ok_or(Error::NoMatchingRelocation)?;
    if let Some(expected) = request.expected_slots
        && slots != expected
    {
        return Err(Error::UnexpectedSlotCount {
            expected: expected.get(),
            actual: slots.get(),
        });
    }
    let previous = previous.unwrap_or_else(|| crate::sys::fail_stop());
    if request.non_null_previous && previous == 0 {
        return Err(Error::NullPreviousPointer);
    }
    Ok(HookPlan {
        previous,
        slots,
        writes,
    })
}

pub(super) struct SingleHookPlan {
    pub(super) previous: usize,
    pub(super) write: StoredPointerWrite,
}

pub(super) fn build_single_hook_plan(
    request: &PltHookRequest<'_>,
    relocation: &FoundRelocation,
) -> Result<SingleHookPlan> {
    let (write, previous) = build_pointer_write(request, relocation)?;
    if let Some(expected) = request.expected_slots
        && expected.get() != 1
    {
        return Err(Error::UnexpectedSlotCount {
            expected: expected.get(),
            actual: 1,
        });
    }
    if request.non_null_previous && previous == 0 {
        return Err(Error::NullPreviousPointer);
    }
    Ok(SingleHookPlan { previous, write })
}

fn build_pointer_write(
    request: &PltHookRequest<'_>,
    relocation: &FoundRelocation,
) -> Result<(StoredPointerWrite, usize)> {
    let replacement = apply_addend(request.replacement, relocation.addend)?;
    // SAFETY: ELF scanning proves a live, readable, naturally aligned slot;
    // the public contract keeps it stable.
    let stored = unsafe { crate::sys::read_pointer(relocation.address)? };
    if request
        .slot_selector
        .is_some_and(|selector| selector.stored_value != stored)
    {
        return Err(Error::Conflict);
    }
    let current = if relocation.aarch64_pac_plt {
        crate::sys::verify_pac_plt(stored, relocation.address).ok_or(Error::Conflict)?
    } else {
        stored
    };
    if current == replacement {
        return Err(Error::Conflict);
    }
    let previous = match relocation.jump_slot_state {
        JumpSlotState::Lazy(resolver)
            if current == resolver
                // The registry records the slot's stored form; for a
                // PAC-PLT slot that is the signed value, so compare
                // against `stored` rather than the PAC-stripped `current`.
                && !registered_top_replacement_matches(relocation.address, stored) =>
        {
            let previous = request
                .resolved_original
                .ok_or(Error::UnsupportedFeature("unresolved lazy PLT relocation"))?;
            if previous == 0 || previous == resolver || previous == replacement {
                return Err(Error::Conflict);
            }
            previous
        }
        JumpSlotState::AmbiguousIfunc if request.resolved_ifunc != Some(current) => {
            return Err(Error::UnsupportedFeature("ambiguous IFUNC jump-slot state"));
        }
        _ => current,
    };
    Ok((
        StoredPointerWrite {
            image: relocation.image,
            address: relocation.address,
            expected: stored,
            replacement: if relocation.aarch64_pac_plt {
                crate::sys::sign_pac_plt(replacement, relocation.address)
            } else {
                replacement
            },
        },
        previous,
    ))
}

/// Captures replacement landings and installation page flags in one procfs read.
#[cfg(target_arch = "aarch64")]
fn capture_replacement_landings(
    hooks: &[PltHookRequest<'_>],
    scanned: &[Option<ScannedHook>],
    outcomes: &[Option<Result<PltHookHandle>>],
    maps: &[MapInfo],
    include_mutation_pages: bool,
) -> Option<Vec<SmapInfo>> {
    let features = crate::sys::aarch64_memory_protection_features();
    let include_mutation_pages = include_mutation_pages && (features.bti || features.mte);
    if !features.bti && !include_mutation_pages {
        return Some(Vec::new());
    }
    let page_size = crate::sys::page_size().ok()?;
    let mut pages = Vec::new();
    for ((request, scan), outcome) in hooks.iter().zip(scanned).zip(outcomes) {
        if outcome.is_none() {
            let Some(scan) = scan else {
                continue;
            };
            for relocation in &scan.relocations {
                if include_mutation_pages
                    && find_map_containing(maps, relocation.address, std::mem::size_of::<usize>())
                        .is_some_and(|map| !map.perms.contains(MapPerms::WRITE))
                {
                    pages.push(crate::sys::page_start(relocation.address, page_size));
                }
                let replacement = apply_addend(request.replacement, relocation.addend).ok()?;
                let untagged = replacement & !(0xff_usize << 56);
                if features.bti
                    && (relocation.kind == RelocationKind::JumpSlot
                        || maps.iter().any(|map| {
                            map.contains(untagged) && map.perms.contains(MapPerms::EXEC)
                        }))
                {
                    pages.push(crate::sys::page_start(untagged, page_size));
                }
            }
        }
    }
    pages.sort_unstable();
    pages.dedup();
    if pages.is_empty() {
        return Some(Vec::new());
    }
    let ranges = page_ranges_for_sorted_pages(pages, page_size).ok()?;
    read_self_smaps_for_ranges(&ranges).ok()
}

/// Fallback per-relocation scan used only when the batched capture above failed.
#[cfg(target_arch = "aarch64")]
pub(super) fn validate_replacement_landing(
    replacement: usize,
    kind: RelocationKind,
    function_symbol: bool,
    maps: &[MapInfo],
) -> Result<()> {
    if !crate::sys::aarch64_bti_supported() {
        return Ok(());
    }
    if !replacement_requires_landing_check(replacement, kind, maps)? {
        return Ok(());
    }
    let page_size = crate::sys::page_size()?;
    let untagged = replacement & !(0xff_usize << 56);
    let start = crate::sys::page_start(untagged, page_size);
    let end = start
        .checked_add(page_size)
        .ok_or(Error::ArithmeticOverflow)?;
    let smaps = read_self_smaps_for_ranges(&[(start, end)])?;
    check_replacement_landing(replacement, kind, function_symbol, maps, &smaps)
}

#[cfg(target_arch = "aarch64")]
pub(super) fn check_replacement_landing(
    replacement: usize,
    kind: RelocationKind,
    function_symbol: bool,
    maps: &[MapInfo],
    smaps: &[SmapInfo],
) -> Result<()> {
    if !replacement_requires_landing_check(replacement, kind, maps)? {
        return Ok(());
    }
    let untagged = replacement & !(0xff_usize << 56);
    let guarded = smaps
        .iter()
        .find(|entry| entry.map.contains(untagged))
        .ok_or(Error::MappingChanged)?
        .vm_flags
        .bti;
    if !guarded {
        return Ok(());
    }
    find_map_containing(maps, untagged, 4)
        .filter(|map| map.perms.contains(MapPerms::READ))
        .ok_or(Error::MappingChanged)?;
    // SAFETY: the validated executable mapping covers this instruction read.
    let instruction = unsafe {
        u32::from_le(std::ptr::read_unaligned(std::ptr::with_exposed_provenance(
            replacement,
        )))
    };
    if crate::sys::aarch64_universal_bti_landing(instruction)
        || ((kind == RelocationKind::JumpSlot || function_symbol)
            && crate::sys::aarch64_call_bti_landing(instruction))
    {
        Ok(())
    } else {
        Err(Error::UnsupportedFeature(
            "guarded PLT replacement lacks a compatible BTI landing",
        ))
    }
}

/// A jump slot must name executable code. Other relocation kinds may name
/// ordinary data, so they only need a BTI landing when they name executable
/// memory and could therefore be called indirectly.
#[cfg(target_arch = "aarch64")]
fn replacement_requires_landing_check(
    replacement: usize,
    kind: RelocationKind,
    maps: &[MapInfo],
) -> Result<bool> {
    // AArch64 ignores the top byte for TBI/MTE addresses, while procfs reports
    // the untagged mapping address.
    let untagged = replacement & !(0xff_usize << 56);
    let map = find_map_containing(maps, untagged, 1).ok_or(Error::MappingChanged)?;
    let executable = map.perms.contains(MapPerms::EXEC);
    if !executable && !map.perms.contains(MapPerms::READ) {
        return Err(Error::MappingChanged);
    }
    if kind == RelocationKind::JumpSlot && !executable {
        return Err(Error::MappingChanged);
    }
    let end = untagged.checked_add(4).ok_or(Error::ArithmeticOverflow)?;
    if end > map.end {
        if kind == RelocationKind::JumpSlot || !map.perms.contains(MapPerms::READ) {
            return Err(Error::MappingChanged);
        }
        return Ok(false);
    }
    Ok(executable)
}

#[cfg(target_arch = "aarch64")]
fn validate_replacement_landings(
    hooks: &[PltHookRequest<'_>],
    scanned: &[Option<ScannedHook>],
    outcomes: &[Option<Result<PltHookHandle>>],
    maps: &[MapInfo],
    replacement_landings: &Option<Vec<SmapInfo>>,
) -> Vec<(usize, Error)> {
    let mut failures = Vec::new();
    if !crate::sys::aarch64_bti_supported() {
        return failures;
    }
    for ((index, request), scan) in hooks.iter().enumerate().zip(scanned) {
        if outcomes.get(index).is_some_and(Option::is_some) {
            continue;
        }
        let Some(scan) = scan else {
            continue;
        };
        for relocation in &scan.relocations {
            let replacement = apply_addend(request.replacement, relocation.addend);
            let result = match (replacement, replacement_landings) {
                (Ok(replacement), Some(smaps)) => check_replacement_landing(
                    replacement,
                    relocation.kind,
                    relocation.function_symbol && relocation.addend == 0,
                    maps,
                    smaps,
                ),
                (Ok(replacement), None) => validate_replacement_landing(
                    replacement,
                    relocation.kind,
                    relocation.function_symbol && relocation.addend == 0,
                    maps,
                ),
                (Err(error), _) => Err(error),
            };
            if let Err(error) = result {
                failures.push((index, error));
                break;
            }
        }
    }
    failures
}

pub(super) fn validate_pointer_mapping<'a>(
    selector: &ElfImageSelector,
    maps: &'a [MapInfo],
    image_id: ImageMappingKey,
    address: usize,
    images: &[FoundImage],
) -> Result<&'a MapInfo> {
    let image = images
        .binary_search_by_key(&image_id, |image| image.id)
        .ok()
        .and_then(|index| images.get(index))
        .ok_or(Error::InvalidElf("relocation references unknown image"))?;
    if selector.bound_image().is_some_and(|bound| {
        image.id.header != bound.header || image.id.loader_base != Some(bound.loader_base)
    }) {
        return Err(Error::MappingChanged);
    }

    let pointer_size = std::mem::size_of::<usize>();
    let map = find_map_containing(maps, address, pointer_size)
        .filter(|map| map.is_private && map.perms.contains(MapPerms::READ))
        .ok_or(Error::MappingChanged)?;
    let file_backed = map.device == image_id.device && map.inode == image_id.inode;
    // Loader-owned anonymous memory must be anchored to this image, exactly
    // like the loader-shaped preflight check: either the caller bound the
    // image explicitly, or the anonymous range starts right after one of the
    // image's own file mappings (loader BSS placement). A bare "anonymous
    // inside load_ranges" would also accept a third party's MAP_FIXED
    // replacement of the GOT.
    let follows_image_file = map.device == DeviceId::new(0, 0)
        && map.inode == 0
        && map.path.is_none()
        && elf::range_in_ranges(address, pointer_size, &image.load_ranges)
        && (selector.bound_image().is_some()
            || maps.iter().any(|candidate| {
                candidate.end == map.start
                    && candidate.is_private
                    && candidate.device == image_id.device
                    && candidate.inode == image_id.inode
            }));
    if file_backed || follows_image_file {
        Ok(map)
    } else {
        Err(Error::MappingChanged)
    }
}

pub(super) fn apply_addend(replacement: usize, addend: i64) -> Result<usize> {
    if addend >= 0 {
        replacement
            .checked_add(usize::try_from(addend).map_err(|_| Error::ArithmeticOverflow)?)
            .ok_or(Error::ArithmeticOverflow)
    } else {
        replacement
            .checked_sub(
                usize::try_from(addend.unsigned_abs()).map_err(|_| Error::ArithmeticOverflow)?,
            )
            .ok_or(Error::ArithmeticOverflow)
    }
}
use super::*;

#[cfg(test)]
mod tests {
    use super::*;

    fn plan_for(image: ImageMappingKey, address: usize) -> HookPlan {
        HookPlan {
            previous: 1,
            slots: NonZeroUsize::new(1).unwrap(),
            writes: vec![StoredPointerWrite {
                image,
                address,
                expected: 1,
                replacement: 2,
            }],
        }
    }

    #[test]
    fn plan_mapping_validation_rejects_unanchored_anonymous_slots() {
        let device = crate::DeviceId::new(1, 2);
        let image_selector = ElfImageSelector::new(device, 3).unwrap();
        let image = ImageMappingKey::for_test(device, 3, 0x1000);
        let maps = vec![MapInfo {
            start: 0x2000,
            end: 0x3000,
            perms: crate::MapPerms::READ | crate::MapPerms::WRITE,
            is_private: true,
            offset: 0,
            device: crate::DeviceId::new(0, 0),
            inode: 0,
            path: None,
        }];
        let images: Arc<[FoundImage]> = Arc::from([FoundImage {
            id: image,
            load_ranges: vec![(0x2000, 0x3000)],
            build_id: None,
        }]);
        let scanned = vec![
            Some(ScannedHook {
                relocations: Vec::new(),
                images: Arc::clone(&images),
            }),
            Some(ScannedHook {
                relocations: Vec::new(),
                images: Arc::clone(&images),
            }),
        ];
        let plans = vec![Some(plan_for(image, 0x2000)), Some(plan_for(image, 0x2000))];
        let hooks = vec![
            PltHookRequest::new(&image_selector, c"symbol", std::ptr::without_provenance(2))
                .unwrap(),
            PltHookRequest::new(&image_selector, c"other", std::ptr::without_provenance(3))
                .unwrap(),
        ];

        let failures = validate_plan_mappings(&hooks, &scanned, &plans, &maps);
        assert_eq!(failures.len(), 2);
        assert!(matches!(failures[0], (0, Error::MappingChanged)));
        assert!(matches!(failures[1], (1, Error::MappingChanged)));
    }

    #[test]
    fn plan_mapping_validation_accepts_loader_owned_bss() {
        let device = crate::DeviceId::new(1, 2);
        let image_selector = ElfImageSelector::new(device, 3).unwrap();
        let image = ImageMappingKey::for_test(device, 3, 0x1000);
        let maps = vec![
            MapInfo {
                start: 0x1000,
                end: 0x2000,
                perms: crate::MapPerms::READ,
                is_private: true,
                offset: 0,
                device,
                inode: 3,
                path: None,
            },
            MapInfo {
                start: 0x2000,
                end: 0x3000,
                perms: crate::MapPerms::READ | crate::MapPerms::WRITE,
                is_private: true,
                offset: 0,
                device: crate::DeviceId::new(0, 0),
                inode: 0,
                path: None,
            },
        ];
        let scanned = vec![Some(ScannedHook {
            relocations: Vec::new(),
            images: Arc::from([FoundImage {
                id: image,
                load_ranges: vec![(0x1000, 0x3000)],
                build_id: None,
            }]),
        })];
        let plans = vec![Some(plan_for(image, 0x2000))];
        let hooks = vec![
            PltHookRequest::new(&image_selector, c"symbol", std::ptr::without_provenance(2))
                .unwrap(),
        ];

        assert!(validate_plan_mappings(&hooks, &scanned, &plans, &maps).is_empty());
    }

    #[cfg(target_arch = "aarch64")]
    fn replacement_map(start: usize, end: usize, perms: crate::MapPerms) -> MapInfo {
        MapInfo {
            start,
            end,
            perms,
            is_private: true,
            offset: 0,
            device: crate::DeviceId::new(0, 0),
            inode: 0,
            path: None,
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn replacement_smap(map: MapInfo) -> crate::maps::SmapInfo {
        crate::maps::SmapInfo {
            map,
            vm_flags: crate::maps::SmapVmFlags::default(),
            protection_key: 0,
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn data_replacements_do_not_require_executable_landings() {
        let maps = vec![replacement_map(
            0x2000,
            0x3000,
            crate::MapPerms::READ | crate::MapPerms::WRITE,
        )];
        for kind in [RelocationKind::Absolute, RelocationKind::GlobalData] {
            assert!(
                check_replacement_landing(0x2000, kind, false, &maps, &[]).is_ok(),
                "{kind:?} data replacement was rejected"
            );
        }
        assert!(matches!(
            check_replacement_landing(0x2000, RelocationKind::JumpSlot, false, &maps, &[]),
            Err(Error::MappingChanged)
        ));
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn execute_only_replacements_only_require_reads_when_guarded() {
        let maps = vec![replacement_map(0x2000, 0x3000, crate::MapPerms::EXEC)];
        let mut smaps = [replacement_smap(maps[0].clone())];
        for address in [0x2000, (0xab_usize << 56) | 0x2000] {
            for kind in [
                RelocationKind::JumpSlot,
                RelocationKind::GlobalData,
                RelocationKind::Absolute,
            ] {
                assert!(check_replacement_landing(address, kind, false, &maps, &smaps).is_ok());
                assert!(matches!(
                    check_replacement_landing(address, kind, false, &maps, &[]),
                    Err(Error::MappingChanged)
                ));
                smaps[0].vm_flags.bti = true;
                assert!(matches!(
                    check_replacement_landing(address, kind, false, &maps, &smaps),
                    Err(Error::MappingChanged)
                ));
                smaps[0].vm_flags.bti = false;
            }
        }
        for kind in [
            RelocationKind::JumpSlot,
            RelocationKind::GlobalData,
            RelocationKind::Absolute,
        ] {
            assert!(matches!(
                check_replacement_landing(0x2fff, kind, false, &maps, &smaps),
                Err(Error::MappingChanged)
            ));
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn guarded_function_entries_accept_call_landings_without_weakening_data_checks() {
        for instruction in [
            0xd503_24df_u32,
            0xd503_245f,
            0xd503_233f,
            0xd503_237f,
            0xd503_249f,
            0xd503_241f,
            0xd280_0000,
        ] {
            let instruction = instruction.to_le();
            let entry = (&raw const instruction).addr();
            let map = replacement_map(
                entry,
                entry + 4,
                crate::MapPerms::READ | crate::MapPerms::EXEC,
            );
            let mut smap = replacement_smap(map.clone());
            smap.vm_flags.bti = true;
            let maps = [map];
            let smaps = [smap];
            for kind in [
                RelocationKind::JumpSlot,
                RelocationKind::GlobalData,
                RelocationKind::Absolute,
            ] {
                for function_symbol in [false, true] {
                    let expected = u32::from_le(instruction) == 0xd503_24df
                        || ((kind == RelocationKind::JumpSlot || function_symbol)
                            && matches!(
                                u32::from_le(instruction),
                                0xd503_245f | 0xd503_233f | 0xd503_237f
                            ));
                    assert_eq!(
                        check_replacement_landing(entry, kind, function_symbol, &maps, &smaps)
                            .is_ok(),
                        expected,
                        "{kind:?}, function={function_symbol}, instruction={instruction:#x}"
                    );
                }
            }
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn landing_validation_uses_the_addend_adjusted_replacement() {
        let device = crate::DeviceId::new(1, 2);
        let image_selector = ElfImageSelector::new(device, 3).unwrap();
        let image = ImageMappingKey::for_test(device, 3, 0x1000);
        let map = replacement_map(
            0x2008,
            0x3008,
            crate::MapPerms::READ | crate::MapPerms::EXEC,
        );
        let maps = vec![map.clone()];
        let smaps = vec![replacement_smap(map)];
        let scanned = vec![Some(ScannedHook {
            relocations: vec![FoundRelocation::for_test(
                0x1000,
                image,
                RelocationKind::JumpSlot,
                8,
                JumpSlotState::Resolved,
            )],
            images: Arc::from(Vec::new()),
        })];
        let hooks = vec![
            PltHookRequest::new(
                &image_selector,
                c"symbol",
                std::ptr::without_provenance(0x2000),
            )
            .unwrap(),
        ];
        let outcomes = vec![None];

        let failures =
            validate_replacement_landings(&hooks, &scanned, &outcomes, &maps, &Some(smaps));
        assert!(failures.is_empty(), "unexpected failures: {failures:?}");
    }
}

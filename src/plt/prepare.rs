pub(super) unsafe fn prepare_hooks(
    hooks: &[Hook<'_>],
    maps: &[MapInfo],
    include_build_ids: bool,
) -> Result<PreparedBatch> {
    let mut outcomes = std::iter::repeat_with(|| None)
        .take(hooks.len())
        .collect::<Vec<Option<Result<AppliedHook>>>>();
    let mut scanned = std::iter::repeat_with(|| None)
        .take(hooks.len())
        .collect::<Vec<Option<ScannedHook>>>();
    let mut hook_images = if include_build_ids {
        std::iter::repeat_with(|| None)
            .take(hooks.len())
            .collect::<Vec<Option<Arc<[FoundImage]>>>>()
    } else {
        Vec::new()
    };
    let mut rejected = if include_build_ids {
        (0..hooks.len()).map(|_| Vec::new()).collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    let mut groups = BTreeMap::<&Target, Vec<usize>>::new();
    for (index, hook) in hooks.iter().enumerate() {
        groups.entry(hook.target).or_default().push(index);
    }
    for (target, indices) in groups {
        let queries = indices
            .iter()
            .map(|&index| hooks[index].query)
            .collect::<Vec<_>>();
        // SAFETY: forwarded from the caller's mapping and metadata stability
        // contract; scanning performs no relocation writes.
        let found =
            unsafe { elf::find_symbol_relocations(target, maps, &queries, include_build_ids)? };
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
            let hook = &hooks[index];
            let mut error = apply_hook_selection(
                hook,
                &mut found_symbol.relocations,
                &mut found_symbol.rejected,
            );
            if error.is_none() && hook.unique_match {
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
            if include_build_ids {
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
    let replacement_landings = capture_replacement_landings(hooks, &outcomes);
    for (index, hook) in hooks.iter().enumerate() {
        if outcomes[index].is_some() {
            continue;
        }
        #[cfg(target_arch = "aarch64")]
        {
            let result = match &replacement_landings {
                Some(smaps) => check_replacement_landing(hook.replacement, maps, smaps),
                None => validate_replacement_landing(hook.replacement, maps),
            };
            if let Err(error) = result {
                outcomes[index] = Some(Err(error));
            }
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            if let Err(error) = validate_replacement_landing(hook.replacement, maps) {
                outcomes[index] = Some(Err(error));
            }
        }
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

    let original_conflicts = original_slot_conflicts(hooks, &plans);
    for (index, conflict) in original_conflicts.into_iter().enumerate() {
        if conflict {
            plans[index] = None;
            outcomes[index] = Some(Err(Error::OriginalSlotConflict));
        }
    }

    Ok(PreparedBatch {
        outcomes,
        scanned,
        images: hook_images,
        rejected,
        conflicting_slots: if include_build_ids {
            conflicting_slots
        } else {
            Vec::new()
        },
        plans,
    })
}

pub(super) fn apply_hook_selection(
    hook: &Hook<'_>,
    relocations: &mut Vec<FoundRelocation>,
    rejected: &mut Vec<RejectedRelocation>,
) -> Option<Error> {
    relocations.retain(|relocation| {
        hook.relocation_kinds.contains(relocation.kind)
            && hook
                .slot_selector
                .is_none_or(|selector| selector.matches_relocation(relocation))
    });
    rejected.retain(|relocation| {
        hook.relocation_kinds.contains(relocation.kind)
            && hook
                .slot_selector
                .is_none_or(|selector| selector.matches_rejected(relocation))
    });

    if hook.slot_selector.is_some() && relocations.is_empty() && rejected.is_empty() {
        return Some(Error::SlotSelectorMismatch);
    }
    if rejected
        .iter()
        .any(|relocation| relocation.reason == RelocationRejection::Aarch64PacPlt)
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
    if let Some(expected) = hook.expected_slots
        && relocations.len() != expected.get()
    {
        return Some(Error::UnexpectedSlotCount {
            expected: expected.get(),
            actual: relocations.len(),
        });
    }
    relocations.is_empty().then_some(Error::SymbolNotFound)
}

pub(super) fn original_slot_conflicts(hooks: &[Hook<'_>], plans: &[Option<HookPlan>]) -> Vec<bool> {
    let mut previous_by_slot = BTreeMap::<*const OriginalSlot, (usize, bool)>::new();
    for (hook, plan) in hooks.iter().zip(plans) {
        let (Some(original), Some(plan)) = (hook.original_slot, plan) else {
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
        .map(|(hook, plan)| {
            let (Some(original), Some(plan)) = (hook.original_slot, plan) else {
                return false;
            };
            original
                .value
                .get()
                .is_some_and(|published| *published != plan.previous)
                || previous_by_slot[&(original as *const OriginalSlot)].1
        })
        .collect()
}

pub(super) fn publish_originals(hooks: &[Hook<'_>], plans: &[Option<HookPlan>]) {
    for (hook, plan) in hooks.iter().zip(plans) {
        let (Some(original), Some(plan)) = (hook.original_slot, plan) else {
            continue;
        };
        if let Err(value) = original.value.set(plan.previous)
            && original.value.get() != Some(&value)
        {
            crate::sys::fail_stop();
        }
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
    hooks: &[Hook<'_>],
    plans: &[Option<HookPlan>],
) -> Result<Vec<Option<Error>>> {
    if hooks.len() != plans.len() {
        return Err(Error::InvalidElf("hook plan count mismatch"));
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
            && hooks[index].original_slot.is_some_and(|original| {
                original
                    .value
                    .get()
                    .is_some_and(|published| *published != plan.previous)
            })
        {
            errors[index] = Some(Error::OriginalSlotConflict);
        }
    }
    Ok(errors)
}

/// Process-local stack of installed replacement pointers per relocation slot.
///
/// The registry is accessed only while `PROCESS_LOCK` is held for writing, so
/// the mutex only keeps the map `Sync` and is never contended. It enforces
/// LIFO removal: removing a hook which another hook was stacked on fails with
/// [`Error::Conflict`] instead of silently bypassing the newer hook. Every
/// stored slot and replacement value is obfuscated so the registry does not
/// expose a plaintext map of hooked relocation slots.
static NEXT_INSTALL_ID: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);

static INSTALLED_SLOT_STACKS: std::sync::Mutex<BTreeMap<usize, Vec<(usize, usize)>>> =
    std::sync::Mutex::new(BTreeMap::new());

fn next_install_id() -> Result<usize> {
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
/// installed hook, not an unresolved resolver.
pub(super) fn installed_replacement_is_current(address: usize, value: usize) -> bool {
    installed_slot_stacks()
        .get(&crate::sys::encode_usize(address))
        .and_then(|stack| stack.last())
        .is_some_and(|&(_, encoded_replacement)| {
            encoded_replacement == crate::sys::encode_usize(value)
        })
}

/// Records one hook's finally committed slot writes.
///
/// The caller must hold `PROCESS_LOCK` for writing.
pub(super) fn record_installed_writes(id: usize, writes: &[PointerWrite]) {
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

/// Validates that every removed hook is the newest hook on each of its slots.
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
        // SAFETY: the caller holds the process write lock and the ledger
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

pub(super) fn prepare_plt_ledgers(
    hooks: &[Hook<'_>],
    maps: &[MapInfo],
    scanned: &[Option<ScannedHook>],
    plans: &[Option<HookPlan>],
    protections: &Arc<BTreeMap<usize, i32>>,
) -> Result<Vec<Option<PltLedger>>> {
    if hooks.len() != scanned.len() || hooks.len() != plans.len() {
        return Err(Error::InvalidElf("hook ledger count mismatch"));
    }
    let mut ledgers = Vec::with_capacity(hooks.len());
    for ((hook, scan), plan) in hooks.iter().zip(scanned).zip(plans) {
        let (Some(scan), Some(plan)) = (scan, plan) else {
            ledgers.push(None);
            continue;
        };
        let (&first, writes) = plan
            .writes
            .split_first()
            .ok_or(Error::InvalidElf("empty hook ledger"))?;
        let map = find_map_containing(maps, first.address, std::mem::size_of::<usize>())
            .ok_or(Error::MappingChanged)?;
        let first = PltLedgerEntry {
            write: encode_pointer_write(first),
            mapping: MappingIdentity::from_map(map),
        };
        let mut rest = Vec::with_capacity(writes.len());
        for &write in writes {
            let map = find_map_containing(maps, write.address, std::mem::size_of::<usize>())
                .ok_or(Error::MappingChanged)?;
            rest.push(PltLedgerEntry {
                write: encode_pointer_write(write),
                mapping: MappingIdentity::from_map(map),
            });
        }
        ledgers.push(Some(PltLedger {
            id: next_install_id()?,
            target: hook.target.clone(),
            images: Arc::clone(&scan.images),
            first,
            rest,
            protections: Arc::clone(protections),
        }));
    }
    Ok(ledgers)
}

/// Scrambles the pointer-shaped fields of one stored ledger write.
///
/// Image identity is not a pointer and stays plain so image bookkeeping can
/// compare it without decoding.
fn encode_pointer_write(write: PointerWrite) -> PointerWrite {
    PointerWrite {
        image: write.image,
        address: crate::sys::encode_usize(write.address),
        expected: crate::sys::encode_usize(write.expected),
        replacement: crate::sys::encode_usize(write.replacement),
    }
}

pub(super) fn validate_plt_ledger(ledger: &PltLedger, maps: &[MapInfo]) -> Result<()> {
    for entry in ledger.entries() {
        let write = entry.decoded_write();
        validate_pointer_mapping(
            &ledger.target,
            maps,
            write.image,
            write.address,
            &ledger.images,
        )?;
        let map = find_map_containing(maps, write.address, std::mem::size_of::<usize>())
            .ok_or(Error::MappingChanged)?;
        // A concealed range keeps its captured mapping identity pointing at
        // the original file mapping while the live page belongs to this
        // process's anonymous copy, so that exact swap is accepted here.
        let concealed = conceal::covers(write.address)
            && map.is_private
            && map.perms.contains(MapPerms::READ)
            && map.device == DeviceId::new(0, 0)
            && map.inode == 0
            && map.path.is_none();
        if !concealed && !entry.mapping.matches_at(map, write.address) {
            return Err(Error::MappingChanged);
        }
        if !map.perms.contains(MapPerms::READ) {
            return Err(Error::MappingChanged);
        }
    }
    Ok(())
}

pub(super) fn conflicting_slots(
    scanned: &[Option<ScannedHook>],
    eligible: &[bool],
) -> Result<Vec<BTreeSet<usize>>> {
    if scanned.len() != eligible.len() {
        return Err(Error::InvalidElf("hook eligibility count mismatch"));
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
    for (hook, (scan, &eligible)) in scanned.iter().zip(eligible).enumerate() {
        if !eligible {
            continue;
        }
        if let Some(scan) = scan {
            slots.extend(
                scan.relocations
                    .iter()
                    .map(|relocation| (relocation.address, hook)),
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
            for &(_, hook) in &slots[start..end] {
                conflicts[hook].insert(slots[start].0);
            }
        }
        start = end;
    }
    Ok(conflicts)
}

pub(super) fn build_hook_plan(hook: &Hook<'_>, scan: &ScannedHook) -> Result<HookPlan> {
    let mut writes = Vec::with_capacity(scan.relocations.len());
    let mut previous = None;
    for relocation in &scan.relocations {
        let replacement = apply_addend(hook.replacement, relocation.addend)?;
        // SAFETY: ELF scanning proves a live, readable, naturally aligned slot;
        // the public contract keeps it stable.
        let stored = unsafe { crate::sys::read_pointer(relocation.address)? };
        if hook
            .slot_selector
            .is_some_and(|selector| selector.current != stored)
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
        match relocation.jump_slot_state {
            JumpSlotState::Lazy(resolver)
                if current == resolver
                    && !installed_replacement_is_current(relocation.address, current) =>
            {
                return Err(Error::UnsupportedFeature("unresolved lazy PLT relocation"));
            }
            JumpSlotState::AmbiguousIfunc if hook.resolved_ifunc != Some(current) => {
                return Err(Error::UnsupportedFeature("ambiguous IFUNC jump-slot state"));
            }
            _ => {}
        }
        match previous {
            None => previous = Some(current),
            Some(previous) if previous != current => {
                return Err(Error::AmbiguousPreviousPointer);
            }
            Some(_) => {}
        }
        writes.push(PointerWrite {
            image: relocation.image,
            address: relocation.address,
            expected: stored,
            replacement: if relocation.aarch64_pac_plt {
                crate::sys::sign_pac_plt(replacement, relocation.address)
            } else {
                replacement
            },
        });
    }

    let slots = NonZeroUsize::new(writes.len()).ok_or(Error::SymbolNotFound)?;
    if let Some(expected) = hook.expected_slots
        && slots != expected
    {
        return Err(Error::UnexpectedSlotCount {
            expected: expected.get(),
            actual: slots.get(),
        });
    }
    let previous = previous.unwrap_or_else(|| crate::sys::fail_stop());
    if hook.non_null_previous && previous == 0 {
        return Err(Error::NullPreviousPointer);
    }
    Ok(HookPlan {
        previous,
        slots,
        writes,
    })
}

/// Rejects an AArch64 replacement whose guarded page requires a BTI landing
/// the stored pointer cannot satisfy for every caller of the slot.
///
/// A relocation-slot target is reachable through both the `br x17` of a PLT
/// stub, by `blr` from no-PLT callers, or by another indirect branch, so a
/// guarded replacement must begin with `bti jc`; plain `bti`, `bti c`,
/// `bti j`, and PAC prologues are not universal landings. Unguarded
/// replacements and hardware without BTI are accepted unchanged.
#[cfg(target_arch = "aarch64")]
fn capture_replacement_landings(
    hooks: &[Hook<'_>],
    outcomes: &[Option<Result<AppliedHook>>],
) -> Option<Vec<SmapInfo>> {
    if !crate::sys::aarch64_bti_supported() {
        return Some(Vec::new());
    }
    let page_size = crate::sys::page_size().ok()?;
    let mut pages = Vec::new();
    for (hook, outcome) in hooks.iter().zip(outcomes) {
        if outcome.is_none() {
            pages.push(crate::sys::page_start(hook.replacement, page_size));
        }
    }
    pages.sort_unstable();
    pages.dedup();
    let ranges = page_ranges_for_sorted_pages(pages, page_size).ok()?;
    read_self_smaps_for_ranges(&ranges).ok()
}

/// Fallback per-hook scan used only when the batched capture above failed.
#[cfg(target_arch = "aarch64")]
fn validate_replacement_landing(replacement: usize, maps: &[MapInfo]) -> Result<()> {
    if !crate::sys::aarch64_bti_supported() {
        return Ok(());
    }
    find_map_containing(maps, replacement, 4)
        .filter(|map| map.perms.contains(MapPerms::READ | MapPerms::EXEC))
        .ok_or(Error::MappingChanged)?;
    let page_size = crate::sys::page_size()?;
    let start = crate::sys::page_start(replacement, page_size);
    let end = start
        .checked_add(page_size)
        .ok_or(Error::ArithmeticOverflow)?;
    let smaps = read_self_smaps_for_ranges(&[(start, end)])?;
    check_replacement_landing(replacement, maps, &smaps)
}

#[cfg(target_arch = "aarch64")]
fn check_replacement_landing(
    replacement: usize,
    maps: &[MapInfo],
    smaps: &[SmapInfo],
) -> Result<()> {
    if !crate::sys::aarch64_bti_supported() {
        return Ok(());
    }
    find_map_containing(maps, replacement, 4)
        .filter(|map| map.perms.contains(MapPerms::READ | MapPerms::EXEC))
        .ok_or(Error::MappingChanged)?;
    let guarded = smaps
        .iter()
        .find(|entry| entry.map.contains(replacement))
        .ok_or(Error::MappingChanged)?
        .vm_flags
        .bti;
    if !guarded {
        return Ok(());
    }
    // SAFETY: the validated executable mapping covers this instruction read.
    let instruction = unsafe {
        u32::from_le(std::ptr::read_unaligned(std::ptr::with_exposed_provenance(
            replacement,
        )))
    };
    if crate::sys::aarch64_universal_bti_landing(instruction) {
        Ok(())
    } else {
        Err(Error::UnsupportedFeature(
            "guarded PLT replacement lacks a `bti jc` landing",
        ))
    }
}

#[cfg(not(target_arch = "aarch64"))]
fn validate_replacement_landing(_: usize, _: &[MapInfo]) -> Result<()> {
    Ok(())
}

fn validate_pointer_mapping(
    target: &Target,
    maps: &[MapInfo],
    image_id: ImageId,
    address: usize,
    images: &[FoundImage],
) -> Result<()> {
    let image = images
        .binary_search_by_key(&image_id, |image| image.id)
        .ok()
        .and_then(|index| images.get(index))
        .ok_or(Error::InvalidElf("relocation references unknown image"))?;
    if target.bound_image().is_some_and(|bound| {
        image.id.header != bound.header || image.id.loader_base != Some(bound.loader_base)
    }) {
        return Err(Error::MappingChanged);
    }

    let pointer_size = std::mem::size_of::<usize>();
    let map = find_map_containing(maps, address, pointer_size)
        .filter(|map| map.is_private && map.perms.contains(MapPerms::READ))
        .ok_or(Error::MappingChanged)?;
    let file_backed = map.device == image_id.device && map.inode == image_id.inode;
    let loader_owned_anonymous = map.device == DeviceId::new(0, 0)
        && map.inode == 0
        && elf::range_in_ranges(address, pointer_size, &image.load_ranges);
    if file_backed || loader_owned_anonymous {
        Ok(())
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

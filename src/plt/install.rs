use log::{debug, error, warn};

/// Installs one removable PLT/GOT hook in the current process.
///
/// This is the single-hook counterpart to [`install_hooks`]. hook-specific
/// failures are returned directly rather than nested in an [`InstallReport`].
///
/// # Errors
///
/// Returns operation-wide discovery, validation, or mutation failures, and
/// directly returns the sole request's selection or installation failure.
///
/// # Safety
///
/// The complete safety contract of [`install_hooks`] applies.
pub unsafe fn install_hook(request: PltHookRequest<'_>) -> Result<PltHookHandle> {
    // SAFETY: forwarded from this function's complete public contract.
    let mut report = unsafe { install_hooks(std::slice::from_ref(&request))? };
    match report.0.pop() {
        Some(Ok(applied)) if report.is_empty() => Ok(applied),
        Some(Err(error)) if report.is_empty() => {
            warn!("PLT hook rejected: final_installation=false");
            Err(error)
        }
        _ => Err(Error::InternalInstallState(
            "single-hook report shape changed",
        )),
    }
}

/// Installs one removable hook subject to hard mutation limits.
///
/// This is the single-hook counterpart to [`install_hooks_with_budget`].
/// hook-specific failures are returned directly.
///
/// # Errors
///
/// Returns operation-wide discovery, validation, or mutation failures, and
/// directly returns the sole request's selection or installation failure.
/// [`Error::MutationBudgetExceeded`] is returned before original publication or
/// page mutation.
///
/// # Safety
///
/// The complete safety contract of [`install_hooks`] applies.
pub unsafe fn install_hook_with_budget(
    request: PltHookRequest<'_>,
    budget: MutationBudget,
) -> Result<PltHookHandle> {
    // SAFETY: forwarded from this function's complete public contract.
    let mut report = unsafe { install_hooks_with_budget(std::slice::from_ref(&request), budget)? };
    match report.0.pop() {
        Some(Ok(applied)) if report.is_empty() => Ok(applied),
        Some(Err(error)) if report.is_empty() => {
            warn!("budgeted PLT hook rejected: final_installation=false");
            Err(error)
        }
        _ => Err(Error::InternalInstallState(
            "single-hook report shape changed",
        )),
    }
}

/// Installs a batch of removable PLT/GOT hooks in the current process.
///
/// The returned report is aligned with `hooks`: every success contains the
/// unique previous pointer and number of changed slots for that input. A loaded image
/// that is not currently loaded produces [`Error::TargetNotLoaded`]; a loaded
/// selector without a selected supported matching relocation produces
/// [`Error::NoMatchingRelocation`]. Per-hook failures are fully rolled back while
/// independent hooks continue.
///
/// An outer error is operation-wide. It is returned only after this call has
/// restored every pointer written by the batch and every page permission it
/// changed. If rollback or permission restoration cannot re-establish a
/// coherent state, the process aborts instead of returning an untrustworthy
/// result. A successful single-hook fast path restores its relocation page before
/// returning; dropping the handle does not mutate it further.
///
/// On AArch64 with BTI but without MTE, non-executable relocation pages may
/// acquire BTI. Read/write/execute access is restored, but the added BTI bit
/// and resulting VMA boundaries can remain after removal or rollback. A later
/// change to executable access must explicitly specify its intended BTI state.
///
/// # Safety
///
/// For every potentially matched relocation, the replacement must have the
/// exact function or data ABI and must already be fully callable before this
/// function is entered. It must remain valid while any returned handle is
/// installed and until every call which could have loaded it has finished.
///
/// Every selected image, ELF metadata mapping, relocation slot, and bound
/// loader header must remain loaded, readable, content-stable,
/// protection-stable, and fixed at the same address for the complete call and,
/// on success, until the corresponding handle is removed. A
/// request made with [`ElfImageSelector::bind_loaded_elf_header`] must actually describe
/// the source of that exact loader image; the safe binding method cannot prove
/// that association. Concurrent `dlopen`, `dlclose`, remapping, reprotection,
/// lazy binding, loader relocation, and other hook or slot writers affecting
/// the selected images are forbidden. No other thread may create a child with
/// `fork`, `vfork`, or an equivalent operation during the call: a child could
/// otherwise inherit transient writes, permissions, and an inherited locked
/// installation mutex.
///
/// For every selected PAC-PLT entry, the installer thread and every thread
/// which can execute that entry must use the same IA key. `PR_PAC_RESET_KEYS`,
/// debugger or ptrace PAC-key replacement, and every other key change are
/// forbidden from any inspection used for selection through installation,
/// removal, and drainage of all affected calls.
///
/// A value supplied by [`PltHookRequest::with_resolved_ifunc`] must be the final resolved
/// implementation, not a lazy trampoline.
/// A value supplied by [`PltHookRequest::with_resolved_original`] must be the
/// callable implementation for the exact selected import's symbol version,
/// loader namespace, and interposition scope, with the correct ABI and a
/// lifetime covering every original call. It must not enter lazy resolution
/// for a selected slot, which could overwrite the installed replacement.
/// Compatible naturally aligned
/// pointer-sized PLT/GOT readers may observe either the old or new value, but a
/// multi-slot batch is not globally atomic and this platform property does not
/// legalize a Rust or C source-level data race.
///
/// A replacement can execute after its first slot is changed, before this
/// function returns its previous pointer, and even during a call which later
/// rolls back and returns an error. If the replacement depends on that returned
/// pointer, the caller must keep relevant callers quiescent or publish a valid
/// previous/fallback first. Even after an error, the replacement and all state
/// it uses must remain valid until every call which could have loaded it during
/// that transient window has finished. A replacement, signal handler, or
/// callback must not re-enter any Oh My Hook discovery, inspection, or
/// installation entry point while this call holds their shared non-reentrant
/// mutex.
///
/// # Errors
///
/// Outer errors cover operation-wide maps, ELF, page-planning, and page-
/// protection failures and guarantee no final installation from this call.
/// hook-specific errors are returned in the report and guarantee that hook was
/// completely rolled back.
///
/// Originally read-only ranges are elevated and restored before returning.
/// Pages which were already writable are never passed to `mprotect`.
///
pub unsafe fn install_hooks(hooks: &[PltHookRequest<'_>]) -> Result<InstallReport> {
    debug!(
        "PLT hook batch requested: hooks={}, budget=false",
        hooks.len()
    );
    // SAFETY: forwarded from this function's complete public contract.
    unsafe { install_hooks_inner(hooks, None) }
}

/// Installs a removable PLT hook batch subject to hard mutation limits.
///
/// The final selected image, slot, and containing-page counts must fit `budget`.
/// A budget failure rejects the complete call before originals are published
/// or page permissions change. The safety and rollback contract is otherwise
/// identical to [`install_hooks`].
///
/// # Safety
///
/// The complete safety contract of [`install_hooks`] applies.
pub unsafe fn install_hooks_with_budget(
    hooks: &[PltHookRequest<'_>],
    budget: MutationBudget,
) -> Result<InstallReport> {
    debug!(
        "PLT hook batch requested: hooks={}, budget=true",
        hooks.len()
    );
    // SAFETY: forwarded from this function's complete public contract.
    unsafe { install_hooks_inner(hooks, Some(budget)) }
}

struct PltMutationSetup {
    private_file_validation_results: conceal::PrivateFileValidationResults,
    records: Vec<Option<PltRemovalRecord>>,
    forced_fd: ForcedFd,
    mutation: MutationPlan,
}

struct PreparedSingleHook {
    plan: SingleHookPlan,
    images: Arc<[FoundImage]>,
    actual_map: MapInfo,
    original_protection: i32,
    private_file_validation: PrivateFileValidation,
}

unsafe fn prepare_and_revalidate_hooks(
    hooks: &[PltHookRequest<'_>],
    maps: &[MapInfo],
) -> Result<PreparedBatch> {
    // SAFETY: the caller holds the process write lock and the public PltHookRequest
    // contract keeps every selected image and slot stable.
    let mut prepared = unsafe { prepare_hooks(hooks, maps, false)? };
    // SAFETY: the same lock and stability contract covers the final reads.
    let revalidation = unsafe { revalidate_hook_plans(hooks, &prepared.plans)? };
    for (index, error) in revalidation.into_iter().enumerate() {
        if let Some(error) = error {
            prepared.plans[index] = None;
            prepared.outcomes[index] = Some(Err(error));
        }
    }
    Ok(prepared)
}

fn build_plt_mutation(
    hooks: &[PltHookRequest<'_>],
    maps: &[MapInfo],
    prepared: &PreparedBatch,
) -> Result<PltMutationSetup> {
    let mut private_file_validation_results =
        conceal::PrivateFileValidationResults::not_requested();
    if conceal::requested(hooks) {
        private_file_validation_results = conceal::apply(hooks, &prepared.plans, maps)?;
    }
    let scope = installation_mutation_scope(
        maps,
        &prepared.plans,
        #[cfg(target_arch = "aarch64")]
        prepared.replacement_landings.as_deref(),
        #[cfg(not(target_arch = "aarch64"))]
        None::<&[crate::maps::MapInfo]>,
        &private_file_validation_results.smaps,
    )?;
    let protections = Arc::new(
        scope
            .writable
            .iter()
            .map(|page| (page.start, page.original_protection))
            .collect::<BTreeMap<_, _>>(),
    );
    let records = prepare_plt_records(
        hooks,
        maps,
        &prepared.scanned,
        &prepared.plans,
        &protections,
    )?;
    // PLT readers are not quiesced. `/proc/self/mem` writes have no atomicity
    // ABI, so the default path must always use the atomic CAS elevation path.
    let forced_fd = ForcedFd::open(false);
    let mutation = mutation_plan_with_channel(
        maps,
        &prepared.plans,
        scope,
        forced_fd.get(),
        forced_fd.open_errno(),
    )?;
    Ok(PltMutationSetup {
        private_file_validation_results,
        records,
        forced_fd,
        mutation,
    })
}

/// Opportunistically prepares one bound-image hook without generic batch containers.
///
/// # Safety
///
/// The caller must hold the process write lock, and the public hook contract
/// must keep the bound loader image stable for the complete call.
unsafe fn try_prepare_fast_single_hook(hooks: &[PltHookRequest<'_>]) -> Option<PreparedSingleHook> {
    let request = &hooks[0];
    // SAFETY: forwarded from this function's mapping-stability contract.
    let found =
        unsafe { elf::find_bound_symbol_relocation(request.image_selector, &request.query).ok()? }?;
    let (relocation, image) = (found.relocation, found.image);
    let replacement = apply_addend(request.replacement, relocation.addend).ok()?;
    if !request.relocation_kinds.contains(relocation.kind)
        || request
            .slot_selector
            .is_some_and(|selector| !selector.matches_relocation(&relocation))
        || request
            .expected_slots
            .is_some_and(|expected| expected.get() != 1)
    {
        return None;
    }
    let plan = build_single_hook_plan(request, &relocation).ok()?;
    if request.original_pointer_cell.is_some_and(|cell| {
        cell.get()
            .is_some_and(|previous| previous.addr() != plan.previous)
    }) {
        return None;
    }
    let image_id = image.id;
    let images: Arc<[FoundImage]> = Arc::from([image]);
    let write = plan.write;
    let page_size = crate::sys::page_size().ok()?;
    let slot_page = crate::sys::page_start(write.address, page_size);
    let replacement_page = crate::sys::page_start(replacement, page_size);
    let needs_replacement_map =
        relocation.kind == RelocationKind::JumpSlot || cfg!(target_arch = "aarch64");
    let maps =
        if !needs_replacement_map || find_map_containing(&found.maps, replacement, 4).is_some() {
            found.maps
        } else {
            let ranges = page_ranges([slot_page, replacement_page]).ok()?;
            read_self_maps_for_ranges(&ranges).ok()?
        };
    let actual_map = validate_pointer_mapping(
        request.image_selector,
        &maps,
        image_id,
        write.address,
        images.as_ref(),
    )
    .ok()?;
    if actual_map.perms.contains(MapPerms::EXEC)
        || !actual_map.perms.contains(MapPerms::READ)
        || !actual_map.is_private
    {
        return None;
    }
    let actual_map = actual_map.clone();
    #[cfg(target_arch = "aarch64")]
    let mut replacement_map = None;
    if needs_replacement_map {
        let replacement_entry = maps.iter().find(|map| map.contains_range(replacement, 4))?;
        if !replacement_entry.perms.contains(MapPerms::READ) {
            return None;
        }
        if relocation.kind == RelocationKind::JumpSlot
            && !replacement_entry.perms.contains(MapPerms::EXEC)
        {
            return None;
        }
        #[cfg(target_arch = "aarch64")]
        {
            replacement_map = Some(replacement_entry.clone());
        }
    }
    #[cfg(target_arch = "aarch64")]
    let needs_replacement_smaps = {
        if replacement_map.is_some_and(|map| map.perms.contains(MapPerms::EXEC)) {
            // SAFETY: the live procfs snapshot proves this executable mapping
            // covers the replacement entry.
            let instruction = unsafe {
                u32::from_le(std::ptr::read_unaligned(std::ptr::with_exposed_provenance(
                    replacement,
                )))
            };
            !(crate::sys::aarch64_universal_bti_landing(instruction)
                || ((relocation.kind == RelocationKind::JumpSlot
                    || (relocation.function_symbol && relocation.addend == 0))
                    && crate::sys::aarch64_call_bti_landing(instruction)))
        } else {
            false
        }
    };
    #[cfg(target_arch = "aarch64")]
    let features = crate::sys::aarch64_memory_protection_features();
    #[cfg(target_arch = "aarch64")]
    let needs_slot_flags = !actual_map.perms.contains(MapPerms::WRITE) && features.mte;
    #[cfg(not(target_arch = "aarch64"))]
    let (needs_replacement_smaps, needs_slot_flags) = (false, false);
    let mut smaps = Vec::new();
    match (
        (needs_slot_flags || request.require_private_file_pages).then_some(slot_page),
        needs_replacement_smaps.then_some(replacement_page),
    ) {
        (None, None) => {}
        (Some(page), None) | (None, Some(page)) => {
            let end = page.checked_add(page_size)?;
            crate::maps::extend_self_smaps_for_ranges(&mut smaps, &[(page, end)]).ok()?;
        }
        (Some(slot), Some(replacement)) => {
            let ranges = page_ranges([slot, replacement]).ok()?;
            crate::maps::extend_self_smaps_for_ranges(&mut smaps, &ranges).ok()?;
        }
    }
    #[cfg(target_arch = "aarch64")]
    if needs_replacement_smaps {
        check_replacement_landing(
            replacement,
            relocation.kind,
            relocation.function_symbol && relocation.addend == 0,
            &maps,
            &smaps,
        )
        .ok()?;
    }
    let original_protection = actual_map.perms.to_prot();
    #[cfg(target_arch = "aarch64")]
    let original_protection = if needs_slot_flags {
        let mut pages = [WritablePage {
            start: slot_page,
            map_index: 0,
            original_protection,
        }];
        add_aarch64_protection_flags(
            std::slice::from_ref(&actual_map),
            &smaps,
            page_size,
            &mut pages,
        )
        .ok()?;
        pages[0].original_protection
    } else {
        // BTI does not change data access on this non-executable page.
        if !actual_map.perms.contains(MapPerms::WRITE) && features.bti {
            original_protection | PROT_BTI
        } else {
            original_protection
        }
    };
    let private_file_validation = if request.require_private_file_pages {
        let selected_page = (slot_page, actual_map.clone());
        let selection = crate::conceal::PageSelection {
            pages: std::slice::from_ref(&selected_page),
            smaps: &smaps,
            page_size,
            reject_executable: true,
        };
        crate::conceal::validate_selection(&selection).ok()?;
        PrivateFileValidation::Validated
    } else {
        PrivateFileValidation::Unvalidated
    };
    Some(PreparedSingleHook {
        plan,
        images,
        actual_map,
        original_protection,
        private_file_validation,
    })
}

/// Commits one fast-path hook with a single-page mutation plan.
///
/// # Safety
///
/// The caller must hold the process write lock and the complete public PltHookRequest
/// contract must remain satisfied for the operation.
unsafe fn install_fast_single_hook(
    hooks: &[PltHookRequest<'_>],
    prepared: PreparedSingleHook,
) -> Result<PltHookHandle> {
    let PreparedSingleHook {
        plan,
        images,
        actual_map,
        original_protection,
        private_file_validation,
    } = prepared;
    if actual_map.perms.contains(MapPerms::EXEC)
        || !actual_map.perms.contains(MapPerms::READ)
        || !actual_map.is_private
    {
        return Err(Error::MappingChanged);
    }
    let write = plan.write;
    if !actual_map.contains_range(write.address, std::mem::size_of::<usize>()) {
        return Err(Error::MappingChanged);
    }

    let page_size = crate::sys::page_size()?;
    let page = crate::sys::page_start(write.address, page_size);
    let install_id = next_install_id()?;
    let mutation_length = page_size;
    let writable = actual_map.perms.contains(MapPerms::WRITE);
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
    crate::maps::validate_page_write_access(std::slice::from_ref(&actual_map), &[page], page_size)?;
    publish_original(&hooks[0], plan.previous);

    crate::sys::enter_mutation();
    let commit_result = (|| -> Result<()> {
        if !writable {
            // SAFETY: the actual map covers this complete range.
            unsafe {
                crate::sys::protect(
                    page,
                    mutation_length,
                    original_protection | libc::PROT_WRITE,
                )?
            };
        }
        // SAFETY: the page is writable and the public contract excludes writers.
        let write_result = unsafe { write_chunk(std::slice::from_ref(&write)) };
        if !writable {
            // SAFETY: the same complete map range is being restored.
            let restore_result =
                unsafe { crate::sys::protect(page, mutation_length, original_protection) };
            if let Err(restore_error) = restore_result {
                if write_result.is_err() {
                    crate::sys::fail_stop();
                }
                if write_result.is_ok() {
                    // SAFETY: the successful write is the only transient slot.
                    let rollback = unsafe {
                        crate::sys::compare_exchange_pointer(
                            write.address,
                            write.replacement,
                            write.expected,
                        )
                    };
                    if !matches!(rollback, Ok(true)) {
                        crate::sys::fail_stop();
                    }
                    // SAFETY: retry the restore after rolling back the write.
                    if unsafe { crate::sys::protect(page, mutation_length, original_protection) }
                        .is_err()
                    {
                        crate::sys::fail_stop();
                    }
                }
                return Err(restore_error);
            }
        }
        write_result
    })();
    crate::sys::leave_mutation();
    commit_result?;

    let record = PltRemovalRecord {
        id: install_id,
        image_selector: *hooks[0].image_selector,
        images,
        first: PltRemovalEntry {
            write: encode_pointer_write(write),
            mapping: MappingSnapshot::from_map(&actual_map),
        },
        rest: Vec::new(),
        protections: PltSavedProtections::Fast {
            page,
            protection: original_protection,
        },
    };

    record_installed_writes(record.id, std::slice::from_ref(&plan.write));
    Ok(PltHookHandle {
        previous: crate::sys::encode_usize(plan.previous),
        slots: NonZeroUsize::new(1)
            .ok_or(Error::InternalInstallState("fast path lost slot count"))?,
        private_file_validation,
        forced_descriptor_close_errno: None,
        record: Some(record),
    })
}

unsafe fn install_hooks_inner(
    hooks: &[PltHookRequest<'_>],
    budget: Option<MutationBudget>,
) -> Result<InstallReport> {
    if hooks.is_empty() {
        return Ok(InstallReport(Vec::new()));
    }

    let _guard = crate::sys::recover_lock(crate::sys::PROCESS_LOCK.write());
    // A log record runs a caller-supplied logger. Unwinding out of one while
    // the write guard is held would poison the process lock, after which every
    // later acquisition terminates the process, so records are emitted only
    // once the guard has been released.
    let fast_path =
        hooks.len() == 1 && hooks[0].image_selector.bound_image().is_some() && budget.is_none();

    let mut prepared = None;
    let mut mutation_maps = Vec::new();

    if fast_path {
        // SAFETY: the public contract keeps the bound loader image stable.
        let fast = unsafe { try_prepare_fast_single_hook(hooks) };
        if let Some(fast) = fast {
            // SAFETY: the caller holds the process write lock and the public
            // contract keeps the bound image stable for this call.
            let applied = unsafe { install_fast_single_hook(hooks, fast) };
            if let Ok(applied) = applied {
                drop(_guard);
                return Ok(InstallReport(vec![Ok(applied)]));
            }
        }
    }

    if prepared.is_none() {
        let maps = match read_self_maps_pathless() {
            Ok(maps) => maps,
            Err(error) => {
                drop(_guard);
                error!("PLT preflight maps snapshot failed");
                return Err(error);
            }
        };
        // SAFETY: the write lock excludes every in-crate mapping and slot
        // writer; the public contract excludes foreign writers for the call.
        prepared = match unsafe { prepare_and_revalidate_hooks(hooks, &maps) } {
            Ok(prepared) => Some(prepared),
            Err(error) => {
                drop(_guard);
                error!("PLT hook preflight failed");
                return Err(error);
            }
        };
        mutation_maps = maps;
    }

    let prepared = match prepared {
        Some(prepared) => prepared,
        None => {
            drop(_guard);
            return Err(Error::InternalInstallState("PLT prepared batch was lost"));
        }
    };
    let PltMutationSetup {
        private_file_validation_results,
        mut records,
        mut forced_fd,
        mut mutation,
    } = match build_plt_mutation(hooks, &mutation_maps, &prepared) {
        Ok(setup) => setup,
        Err(error) => {
            drop(_guard);
            return Err(error);
        }
    };
    let PreparedBatch {
        mut outcomes,
        plans,
        ..
    } = prepared;

    if let Some(budget) = budget
        && let Err(error) = mutation.enforce(budget)
    {
        drop(_guard);
        forced_fd.close_and_report();
        return Err(error);
    }
    let mut state = CommitState::new(plans.len());
    publish_originals(hooks, &plans);
    // From here on, slots may already hold their new replacements. A shape
    // violation after commit can no longer honestly be returned as "nothing
    // was installed": the writes are live with no handle to remove them, so a
    // broken internal invariant stops the process instead.

    // SAFETY: page planning verified every complete private page and slot;
    // the public contract keeps them stable and writer-exclusive.
    let committed = unsafe {
        // SAFETY: page planning verified every complete private page and slot;
        // the public contract keeps them stable and writer-exclusive.
        commit_mutation(&mut mutation, &mut state, CommitPolicy::Independent)
    };
    if let Err(failure) = committed {
        // The uncommitted writes were rolled back before the descriptor
        // closed, so a close failure is only a leaked resource here.
        drop(_guard);
        forced_fd.close_and_report();
        error!("PLT hook batch commit failed: final_installation=false");
        return Err(failure.source);
    }
    // A failed close after publication leaves live slots with no rollback
    // path, so it is reported through the success path like the inline
    // engine's `ForcedDescriptorCloseFailed`; dropping the guard closes the
    // descriptor and the leak is observable only as a process resource.
    // A plain match avoids a monomorphized `Option::and_then` wrapper whose
    // symbol name would collide with the mutation-window text audit.
    let forced_close_errno = match forced_fd.take() {
        Some(fd) => crate::sys::close_self_mem(fd),
        None => None,
    };

    for (index, plan) in plans.iter().enumerate() {
        let Some(plan) = plan else {
            continue;
        };
        outcomes[index] = Some(match state.hook_errors[index].take() {
            Some(error) => Err(error),
            None if !state.failed_hooks[index] => {
                let Some(record) = records[index].take() else {
                    // The mutation already committed this hook's slots; losing
                    // its only removal record leaves a live hook nobody can
                    // remove. This is a broken invariant, not a reportable
                    // installation failure.
                    crate::sys::fail_stop();
                };
                record_installed_writes(record.id, &plan.writes);
                Ok(PltHookHandle {
                    previous: crate::sys::encode_usize(plan.previous),
                    slots: plan.slots,
                    private_file_validation: private_file_validation_results.get(index),
                    forced_descriptor_close_errno: forced_close_errno,
                    record: Some(record),
                })
            }
            // Same reasoning as the missing record above: this branch exists
            // only if the commit state machine contradicted itself after the
            // writes became live.
            None => crate::sys::fail_stop(),
        });
    }
    let report = outcomes
        .into_iter()
        .map(|outcome| {
            // The aligned outcome vector is fully populated by the loop above;
            // a missing entry means slots were written without a matching
            // report entry, so the process stops instead of losing the only
            // removal handles for those writes.
            outcome.unwrap_or_else(|| crate::sys::fail_stop())
        })
        .collect();
    drop(_guard);
    debug!(
        "PLT forced descriptor close: leaked={}",
        forced_close_errno.is_some()
    );
    Ok(InstallReport(report))
}

/// Installs required and optional PLT hook groups with final all-or-none rollback.
///
/// Every present, installable hook is applied; groups do not select only their
/// first match. `TargetNotLoaded` and `NoMatchingRelocation` are candidate absence,
/// while every other hook error rejects the complete call. A required group
/// must produce at least one final slot. Any commit failure removes all Hooks
/// written by this call before returning.
///
/// The nested success report preserves group and hook input order. Absent
/// optional candidates retain their aligned absence errors.
///
/// # Safety
///
/// The complete safety contract of [`install_hooks`] applies simultaneously to
/// every hook in every group. Replacements and any state they access must stay
/// valid after an error until transient calls have drained. Published
/// [`OriginalPointerCell`] values are not rolled back.
///
/// # Errors
///
/// Returns [`GroupInstallError`] with both indices for a hook-specific hard
/// failure, only `group` for a missing required group, and neither index for an
/// operation-wide maps, ELF, page, or restoration failure.
pub unsafe fn install_hook_groups(
    groups: &[PltHookRequestGroup<'_, '_>],
) -> std::result::Result<GroupInstallReport, GroupInstallError> {
    debug!(
        "PLT hook group batch requested: groups={}, budget=false",
        groups.len()
    );
    // SAFETY: forwarded from this function's complete public contract.
    unsafe { install_hook_groups_inner(groups, None) }
}

/// Installs PLT hook groups with final all-or-none rollback and hard mutation limits.
///
/// The final selected image, slot, and containing-page counts must fit `budget`.
/// A budget failure rejects the complete operation before originals are
/// published or page permissions change. Group policy, safety, and rollback
/// semantics are otherwise identical to [`install_hook_groups`].
///
/// # Safety
///
/// The complete safety contract of [`install_hook_groups`] applies.
pub unsafe fn install_hook_groups_with_budget(
    groups: &[PltHookRequestGroup<'_, '_>],
    budget: MutationBudget,
) -> std::result::Result<GroupInstallReport, GroupInstallError> {
    debug!(
        "PLT hook group batch requested: groups={}, budget=true",
        groups.len()
    );
    // SAFETY: forwarded from this function's complete public contract.
    unsafe { install_hook_groups_inner(groups, Some(budget)) }
}

unsafe fn install_hook_groups_inner(
    groups: &[PltHookRequestGroup<'_, '_>],
    budget: Option<MutationBudget>,
) -> std::result::Result<GroupInstallReport, GroupInstallError> {
    if groups.is_empty() {
        return Ok(GroupInstallReport(Vec::new()));
    }
    for (group, descriptor) in groups.iter().enumerate() {
        if descriptor.kind == HookGroupKind::Required && descriptor.hooks.is_empty() {
            warn!("required PLT hook group is empty: group_index={group}");
            return Err(GroupInstallError {
                group: Some(group),
                hook_index: None,
                source: Error::RequiredGroupMissing,
            });
        }
    }

    let hook_count = groups.iter().try_fold(0_usize, |total, group| {
        total
            .checked_add(group.hooks.len())
            .ok_or(GroupInstallError {
                group: None,
                hook_index: None,
                source: Error::ArithmeticOverflow,
            })
    })?;
    if hook_count == 0 {
        return Ok(GroupInstallReport(
            groups.iter().map(|_| InstallReport(Vec::new())).collect(),
        ));
    }
    let mut hooks = Vec::with_capacity(hook_count);
    let mut locations = Vec::with_capacity(hook_count);
    let mut ranges = Vec::with_capacity(groups.len());
    for (group_index, group) in groups.iter().enumerate() {
        let start = hooks.len();
        for (hook_index, mut request) in group.hooks.iter().copied().enumerate() {
            if group.private_file_validation_requested() {
                request = request.require_private_file_pages();
            }
            hooks.push(request);
            locations.push((group_index, hook_index));
        }
        ranges.push(start..hooks.len());
    }

    let _guard = crate::sys::recover_lock(crate::sys::PROCESS_LOCK.write());
    // See `install_hooks_inner`: every record is emitted after the write guard
    // is released so a panicking logger cannot poison the process lock.
    let maps = match read_self_maps_pathless() {
        Ok(maps) => maps,
        Err(error) => {
            drop(_guard);
            error!("PLT group preflight maps snapshot failed");
            return Err(group_operation_error(error));
        }
    };
    // SAFETY: the write lock excludes every in-crate mapping and slot writer;
    // the public contract excludes foreign writers for the complete call.
    let mut prepared = match unsafe { prepare_and_revalidate_hooks(&hooks, &maps) } {
        Ok(prepared) => prepared,
        Err(error) => {
            drop(_guard);
            error!("PLT hook group preflight failed");
            return Err(group_operation_error(error));
        }
    };
    for (index, outcome) in prepared.outcomes.iter().enumerate() {
        let Some(Err(error)) = outcome else {
            continue;
        };
        if matches!(error, Error::TargetNotLoaded | Error::NoMatchingRelocation) {
            continue;
        }
        let source = match prepared.outcomes[index].take() {
            Some(Err(error)) => error,
            _ => Error::InternalInstallState("hook outcome changed while rejecting"),
        };
        let (group, hook_index) = locations[index];
        drop(_guard);
        warn!("PLT hook group rejected: group_index={group}, hook_index={hook_index}");
        return Err(GroupInstallError {
            group: Some(group),
            hook_index: Some(hook_index),
            source,
        });
    }

    for (group_index, (group, range)) in groups.iter().zip(&ranges).enumerate() {
        if group.kind == HookGroupKind::Required
            && !range.clone().any(|index| prepared.plans[index].is_some())
        {
            drop(_guard);
            warn!(
                "required PLT hook group has no installable candidate: group_index={group_index}"
            );
            return Err(GroupInstallError {
                group: Some(group_index),
                hook_index: None,
                source: Error::RequiredGroupMissing,
            });
        }
    }

    let PltMutationSetup {
        private_file_validation_results,
        mut records,
        mut forced_fd,
        mut mutation,
    } = match build_plt_mutation(&hooks, &maps, &prepared) {
        Ok(setup) => setup,
        Err(error) => {
            drop(_guard);
            return Err(group_operation_error(error));
        }
    };

    if let Some(budget) = budget
        && let Err(error) = mutation.enforce(budget)
    {
        drop(_guard);
        forced_fd.close_and_report();
        return Err(group_operation_error(error));
    }
    let mut state = CommitState::new(prepared.plans.len());
    publish_originals(&hooks, &prepared.plans);
    // Everything below runs after slot writes may already be live. A shape
    // violation from here on cannot be returned as "nothing was installed":
    // the writes exist with no handle to remove them, so a broken internal
    // invariant stops the process instead.

    // SAFETY: page planning validated the complete group batch and the public
    // contract keeps each page and slot stable and writer-exclusive.
    let committed = unsafe {
        // SAFETY: page planning validated the complete group batch and the
        // public contract keeps each page and slot stable and writer-exclusive.
        commit_mutation(
            &mut mutation,
            &mut state,
            CommitPolicy::RollbackAllOnFailure,
        )
    };
    if let Err(failure) = committed {
        let located = failure.hook_index.map(|index| locations[index]);
        drop(_guard);
        forced_fd.close_and_report();
        if let Some((group, hook_index)) = located {
            error!(
                "PLT hook group commit failed: group_index={group}, hook_index={hook_index}, final_installation=false"
            );
            return Err(GroupInstallError {
                group: Some(group),
                hook_index: Some(hook_index),
                source: failure.source,
            });
        }
        error!("PLT hook group commit failed: final_installation=false");
        return Err(group_operation_error(failure.source));
    }
    // Same audit constraint as the single-install close above.
    let forced_close_errno = match forced_fd.take() {
        Some(fd) => crate::sys::close_self_mem(fd),
        None => None,
    };

    for (index, plan) in prepared.plans.iter().enumerate() {
        let Some(plan) = plan else {
            continue;
        };
        let Some(record) = records[index].take() else {
            // The atomic commit already wrote this hook's slots; losing the
            // removal record leaves a live hook nobody can remove.
            crate::sys::fail_stop();
        };
        record_installed_writes(record.id, &plan.writes);
        prepared.outcomes[index] = Some(Ok(PltHookHandle {
            previous: crate::sys::encode_usize(plan.previous),
            slots: plan.slots,
            private_file_validation: private_file_validation_results.get(index),
            forced_descriptor_close_errno: forced_close_errno,
            record: Some(record),
        }));
    }

    let mut flat = prepared.outcomes.into_iter();
    let mut report = Vec::with_capacity(groups.len());
    for range in ranges {
        let group = range
            .map(|_| {
                flat.next().flatten().unwrap_or_else(|| {
                    // A slot-bearing outcome was lost between the aligned
                    // vectors; its writes are live and unremovable.
                    crate::sys::fail_stop()
                })
            })
            .collect::<Vec<_>>();
        report.push(InstallReport(group));
    }
    if flat.next().is_some() {
        // An extra live outcome was never handed to the caller.
        crate::sys::fail_stop();
    }
    drop(_guard);
    debug!(
        "PLT forced descriptor close: leaked={}",
        forced_close_errno.is_some()
    );
    Ok(GroupInstallReport(report))
}

fn group_operation_error(source: Error) -> GroupInstallError {
    GroupInstallError {
        group: None,
        hook_index: None,
        source,
    }
}

use super::*;

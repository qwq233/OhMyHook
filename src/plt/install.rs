use log::{error, info, warn};

/// Installs one removable PLT/GOT Hook in the current process.
///
/// This is the single-Hook counterpart to [`install_hooks`]. Hook-specific
/// failures are returned directly rather than nested in an [`InstallReport`].
///
/// # Errors
///
/// Returns operation-wide discovery, validation, or mutation failures, and
/// directly returns the sole Hook's selection or installation failure.
///
/// # Safety
///
/// The complete safety contract of [`install_hooks`] applies.
pub unsafe fn install_hook(hook: Hook<'_>) -> Result<AppliedHook> {
    // SAFETY: forwarded from this function's complete public contract.
    let mut report = unsafe { install_hooks(std::slice::from_ref(&hook))? };
    match report.pop() {
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

/// Installs one removable Hook subject to hard mutation limits.
///
/// This is the single-Hook counterpart to [`install_hooks_with_budget`].
/// Hook-specific failures are returned directly.
///
/// # Errors
///
/// Returns operation-wide discovery, validation, or mutation failures, and
/// directly returns the sole Hook's selection or installation failure.
/// [`Error::MutationBudgetExceeded`] is returned before original publication or
/// page mutation.
///
/// # Safety
///
/// The complete safety contract of [`install_hooks`] applies.
pub unsafe fn install_hook_with_budget(
    hook: Hook<'_>,
    budget: MutationBudget,
) -> Result<AppliedHook> {
    // SAFETY: forwarded from this function's complete public contract.
    let mut report = unsafe { install_hooks_with_budget(std::slice::from_ref(&hook), budget)? };
    match report.pop() {
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
/// unique previous pointer and number of changed slots for that input. A target
/// that is not currently loaded produces [`Error::TargetNotLoaded`]; a loaded
/// target without a selected supported matching relocation produces
/// [`Error::SymbolNotFound`]. Per-hook failures are fully rolled back while
/// independent hooks continue.
///
/// An outer error is operation-wide. It is returned only after this call has
/// restored every pointer written by the batch and every page permission it
/// changed. If rollback or permission restoration cannot re-establish a
/// coherent state, the process aborts instead of returning an untrustworthy
/// result.
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
/// target made with [`Target::bind_loaded_elf_header`] must actually describe
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
/// A value supplied by [`Hook::with_resolved_ifunc`] must be the final resolved
/// implementation, not a lazy trampoline. Compatible naturally aligned
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
/// Hook-specific errors are returned in the report and guarantee that Hook was
/// completely rolled back.
///
/// Originally read-only ranges are elevated and restored one at a time. Pages
/// which were already writable are never passed to `mprotect`.
///
pub unsafe fn install_hooks(hooks: &[Hook<'_>]) -> Result<InstallReport> {
    info!(
        "PLT hook batch requested: hooks={}, budget=false",
        hooks.len()
    );
    // SAFETY: forwarded from this function's complete public contract.
    unsafe { install_hooks_inner(hooks, None) }
}

/// Installs a removable Hook batch subject to hard mutation limits.
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
    hooks: &[Hook<'_>],
    budget: MutationBudget,
) -> Result<InstallReport> {
    info!(
        "PLT hook batch requested: hooks={}, budget=true",
        hooks.len()
    );
    // SAFETY: forwarded from this function's complete public contract.
    unsafe { install_hooks_inner(hooks, Some(budget)) }
}

unsafe fn install_hooks_inner(
    hooks: &[Hook<'_>],
    budget: Option<MutationBudget>,
) -> Result<InstallReport> {
    if hooks.is_empty() {
        return Ok(Vec::new());
    }

    let _guard = crate::sys::recover_lock(crate::sys::PROCESS_LOCK.write());
    // A log record runs a caller-supplied logger. Unwinding out of one while
    // the write guard is held would poison the process lock, after which every
    // later acquisition terminates the process, so records are emitted only
    // once the guard has been released.
    let maps = match read_self_maps_pathless() {
        Ok(maps) => maps,
        Err(error) => {
            drop(_guard);
            error!("PLT preflight maps snapshot failed");
            return Err(error);
        }
    };
    // SAFETY: the write lock excludes every in-crate mapping and slot writer;
    // the public contract excludes foreign writers for the complete call.
    let mut prepared = match unsafe { prepare_hooks(hooks, &maps, false) } {
        Ok(prepared) => prepared,
        Err(error) => {
            drop(_guard);
            error!("PLT hook preflight failed");
            return Err(error);
        }
    };
    // SAFETY: the write lock keeps the preflight snapshot current for every
    // in-crate writer; this final read also catches a forbidden foreign slot
    // writer before originals are published or permissions change.
    let revalidation = match unsafe { revalidate_hook_plans(hooks, &prepared.plans) } {
        Ok(revalidation) => revalidation,
        Err(error) => {
            drop(_guard);
            return Err(error);
        }
    };
    for (index, error) in revalidation.into_iter().enumerate() {
        if let Some(error) = error {
            prepared.plans[index] = None;
            prepared.outcomes[index] = Some(Err(error));
        }
    }
    let scope = match installation_mutation_scope(&maps, &prepared.plans) {
        Ok(scope) => scope,
        Err(error) => {
            drop(_guard);
            return Err(error);
        }
    };
    let protections = Arc::new(
        scope
            .writable
            .iter()
            .map(|page| (page.start, page.original_protection))
            .collect::<BTreeMap<_, _>>(),
    );
    let mut ledgers = match prepare_plt_ledgers(
        hooks,
        &maps,
        &prepared.scanned,
        &prepared.plans,
        &protections,
    ) {
        Ok(ledgers) => ledgers,
        Err(error) => {
            drop(_guard);
            return Err(error);
        }
    };
    let mut new_concealed_ranges = Vec::new();
    let mut concealments = conceal::Concealments::not_requested();
    if conceal::requested(hooks) {
        concealments =
            match conceal::apply(hooks, &prepared.plans, &scope, &mut new_concealed_ranges) {
                Ok(concealments) => concealments,
                Err(error) => {
                    let source = rollback_concealment(error, &new_concealed_ranges);
                    drop(_guard);
                    return Err(source);
                }
            };
    }
    let mut mutation = match mutation_plan(&maps, &prepared.plans, scope) {
        Ok(mutation) => mutation,
        Err(error) => {
            let source = rollback_concealment(error, &new_concealed_ranges);
            drop(_guard);
            return Err(source);
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
        let source = rollback_concealment(error, &new_concealed_ranges);
        drop(_guard);
        return Err(source);
    }
    let mut state = CommitState::new(plans.len());
    publish_originals(hooks, &plans);

    // SAFETY: page planning verified every complete private page and slot;
    // the public contract keeps them stable and writer-exclusive.
    if let Err(failure) =
        unsafe { commit_mutation(&mut mutation, &mut state, CommitPolicy::Independent) }
    {
        let source = rollback_concealment(failure.source, &new_concealed_ranges);
        drop(_guard);
        error!("PLT hook batch commit failed: final_installation=false");
        return Err(source);
    }

    for (index, plan) in plans.iter().enumerate() {
        let Some(plan) = plan else {
            continue;
        };
        outcomes[index] = Some(match state.hook_errors[index].take() {
            Some(error) => Err(error),
            None if !state.failed_hooks[index] => {
                let Some(ledger) = ledgers[index].take() else {
                    outcomes[index] = Some(Err(Error::InternalInstallState(
                        "installable hook had no ledger",
                    )));
                    continue;
                };
                record_installed_writes(ledger.id, &plan.writes);
                conceal::attach(ledger.id, &plan.writes);
                Ok(AppliedHook {
                    previous: crate::sys::encode_usize(plan.previous),
                    slots: plan.slots,
                    concealment: concealments.get(index),
                    ledger: Some(ledger),
                })
            }
            None => Err(Error::InternalInstallState("hook mutation state changed")),
        });
    }
    if let Err(cleanup) = conceal::restore_abandoned(&new_concealed_ranges) {
        drop(_guard);
        return Err(cleanup);
    }

    let report = outcomes
        .into_iter()
        .map(|outcome| {
            outcome.unwrap_or({
                Err(Error::InternalInstallState(
                    "hook outcome was not populated",
                ))
            })
        })
        .collect();
    drop(_guard);
    Ok(report)
}

/// Installs required and optional Hook groups with final all-or-none rollback.
///
/// Every present, installable Hook is applied; groups do not select only their
/// first match. `TargetNotLoaded` and `SymbolNotFound` are candidate absence,
/// while every other Hook error rejects the complete call. A required group
/// must produce at least one final slot. Any commit failure removes all Hooks
/// written by this call before returning.
///
/// The nested success report preserves group and Hook input order. Absent
/// optional candidates retain their aligned absence errors.
///
/// # Safety
///
/// The complete safety contract of [`install_hooks`] applies simultaneously to
/// every Hook in every group. Replacements and any state they access must stay
/// valid after an error until transient calls have drained. Published
/// [`OriginalSlot`] values are not rolled back.
///
/// # Errors
///
/// Returns [`GroupInstallError`] with both indices for a Hook-specific hard
/// failure, only `group` for a missing required group, and neither index for an
/// operation-wide maps, ELF, page, or restoration failure.
pub unsafe fn install_hook_groups(
    groups: &[HookGroup<'_, '_>],
) -> std::result::Result<GroupInstallReport, GroupInstallError> {
    info!(
        "PLT hook group batch requested: groups={}, budget=false",
        groups.len()
    );
    // SAFETY: forwarded from this function's complete public contract.
    unsafe { install_hook_groups_inner(groups, None) }
}

/// Installs Hook groups with final all-or-none rollback and hard mutation limits.
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
    groups: &[HookGroup<'_, '_>],
    budget: MutationBudget,
) -> std::result::Result<GroupInstallReport, GroupInstallError> {
    info!(
        "PLT hook group batch requested: groups={}, budget=true",
        groups.len()
    );
    // SAFETY: forwarded from this function's complete public contract.
    unsafe { install_hook_groups_inner(groups, Some(budget)) }
}

unsafe fn install_hook_groups_inner(
    groups: &[HookGroup<'_, '_>],
    budget: Option<MutationBudget>,
) -> std::result::Result<GroupInstallReport, GroupInstallError> {
    if groups.is_empty() {
        return Ok(Vec::new());
    }
    for (group, descriptor) in groups.iter().enumerate() {
        if descriptor.kind == HookGroupKind::Required && descriptor.hooks.is_empty() {
            warn!("required PLT hook group is empty: group_index={group}");
            return Err(GroupInstallError {
                group: Some(group),
                hook: None,
                source: Error::RequiredGroupMissing,
            });
        }
    }

    let hook_count = groups.iter().try_fold(0_usize, |total, group| {
        total
            .checked_add(group.hooks.len())
            .ok_or(GroupInstallError {
                group: None,
                hook: None,
                source: Error::ArithmeticOverflow,
            })
    })?;
    if hook_count == 0 {
        return Ok(groups.iter().map(|_| Vec::new()).collect());
    }
    let mut hooks = Vec::with_capacity(hook_count);
    let mut locations = Vec::with_capacity(hook_count);
    let mut ranges = Vec::with_capacity(groups.len());
    for (group_index, group) in groups.iter().enumerate() {
        let start = hooks.len();
        for (hook_index, hook) in group.hooks.iter().copied().enumerate() {
            hooks.push(hook);
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
    let mut prepared = match unsafe { prepare_hooks(&hooks, &maps, false) } {
        Ok(prepared) => prepared,
        Err(error) => {
            drop(_guard);
            error!("PLT hook group preflight failed");
            return Err(group_operation_error(error));
        }
    };
    // SAFETY: the write lock keeps the preflight snapshot current for every
    // in-crate writer; this final read also catches a forbidden foreign slot
    // writer before originals are published or permissions change.
    let revalidation = match unsafe { revalidate_hook_plans(&hooks, &prepared.plans) } {
        Ok(revalidation) => revalidation,
        Err(error) => {
            drop(_guard);
            return Err(group_operation_error(error));
        }
    };
    if let Some((index, source)) = revalidation
        .into_iter()
        .enumerate()
        .find_map(|(index, error)| error.map(|error| (index, error)))
    {
        let (group, hook) = locations[index];
        drop(_guard);
        warn!(
            "PLT hook group rejected during revalidation: group_index={group}, hook_index={hook}"
        );
        return Err(GroupInstallError {
            group: Some(group),
            hook: Some(hook),
            source,
        });
    }

    for (index, outcome) in prepared.outcomes.iter().enumerate() {
        let Some(Err(error)) = outcome else {
            continue;
        };
        if matches!(error, Error::TargetNotLoaded | Error::SymbolNotFound) {
            continue;
        }
        let source = match prepared.outcomes[index].take() {
            Some(Err(error)) => error,
            _ => Error::InternalInstallState("hook outcome changed while rejecting"),
        };
        let (group, hook) = locations[index];
        drop(_guard);
        warn!("PLT hook group rejected: group_index={group}, hook_index={hook}");
        return Err(GroupInstallError {
            group: Some(group),
            hook: Some(hook),
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
                hook: None,
                source: Error::RequiredGroupMissing,
            });
        }
    }

    let scope = match installation_mutation_scope(&maps, &prepared.plans) {
        Ok(scope) => scope,
        Err(error) => {
            drop(_guard);
            return Err(group_operation_error(error));
        }
    };
    let protections = Arc::new(
        scope
            .writable
            .iter()
            .map(|page| (page.start, page.original_protection))
            .collect::<BTreeMap<_, _>>(),
    );
    let mut ledgers = match prepare_plt_ledgers(
        &hooks,
        &maps,
        &prepared.scanned,
        &prepared.plans,
        &protections,
    ) {
        Ok(ledgers) => ledgers,
        Err(error) => {
            drop(_guard);
            return Err(group_operation_error(error));
        }
    };
    let mut new_concealed_ranges = Vec::new();
    let mut concealments = conceal::Concealments::not_requested();
    if conceal::requested(&hooks) {
        concealments =
            match conceal::apply(&hooks, &prepared.plans, &scope, &mut new_concealed_ranges) {
                Ok(concealments) => concealments,
                Err(error) => {
                    let source = rollback_concealment(error, &new_concealed_ranges);
                    drop(_guard);
                    return Err(group_operation_error(source));
                }
            };
    }
    let mut mutation = match mutation_plan(&maps, &prepared.plans, scope) {
        Ok(mutation) => mutation,
        Err(error) => {
            let source = rollback_concealment(error, &new_concealed_ranges);
            drop(_guard);
            return Err(group_operation_error(source));
        }
    };

    if let Some(budget) = budget
        && let Err(error) = mutation.enforce(budget)
    {
        let source = rollback_concealment(error, &new_concealed_ranges);
        drop(_guard);
        return Err(group_operation_error(source));
    }
    let mut state = CommitState::new(prepared.plans.len());
    publish_originals(&hooks, &prepared.plans);

    // SAFETY: page planning validated the complete group batch and the public
    // contract keeps each page and slot stable and writer-exclusive.
    if let Err(failure) =
        unsafe { commit_mutation(&mut mutation, &mut state, CommitPolicy::Atomic) }
    {
        let source = rollback_concealment(failure.source, &new_concealed_ranges);
        let located = failure.hook.map(|index| locations[index]);
        drop(_guard);
        if let Some((group, hook)) = located {
            error!(
                "PLT hook group commit failed: group_index={group}, hook_index={hook}, final_installation=false"
            );
            return Err(GroupInstallError {
                group: Some(group),
                hook: Some(hook),
                source,
            });
        }
        error!("PLT hook group commit failed: final_installation=false");
        return Err(group_operation_error(source));
    }

    for (index, plan) in prepared.plans.iter().enumerate() {
        let Some(plan) = plan else {
            continue;
        };
        let Some(ledger) = ledgers[index].take() else {
            drop(_guard);
            return Err(group_operation_error(Error::InternalInstallState(
                "installable group hook had no ledger",
            )));
        };
        record_installed_writes(ledger.id, &plan.writes);
        conceal::attach(ledger.id, &plan.writes);
        prepared.outcomes[index] = Some(Ok(AppliedHook {
            previous: crate::sys::encode_usize(plan.previous),
            slots: plan.slots,
            concealment: concealments.get(index),
            ledger: Some(ledger),
        }));
    }

    let mut flat = prepared.outcomes.into_iter();
    let mut report = Vec::with_capacity(groups.len());
    for range in ranges {
        let group = match range
            .map(|_| {
                flat.next().flatten().ok_or(Error::InternalInstallState(
                    "group report outcome was missing",
                ))
            })
            .collect::<Result<Vec<_>>>()
        {
            Ok(group) => group,
            Err(error) => {
                drop(_guard);
                return Err(group_operation_error(error));
            }
        };
        report.push(group);
    }
    if flat.next().is_some() {
        drop(_guard);
        return Err(group_operation_error(Error::InternalInstallState(
            "group report had extra outcomes",
        )));
    }
    drop(_guard);
    Ok(report)
}

fn group_operation_error(source: Error) -> GroupInstallError {
    GroupInstallError {
        group: None,
        hook: None,
        source,
    }
}

fn rollback_concealment(source: Error, new_ranges: &[usize]) -> Error {
    match conceal::restore_abandoned(new_ranges) {
        Ok(()) => source,
        Err(cleanup) => cleanup,
    }
}
use super::*;

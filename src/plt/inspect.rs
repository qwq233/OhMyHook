use super::ElfImageSelector;
use log::{debug, warn};

/// One currently loaded ELF image selected from a source [`ElfImageSelector`].
///
/// The addresses and optional raw GNU build-id are a point-in-time inspection
/// result, not a persistent process or file identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LoadedImageSnapshot {
    pub(super) source: ElfImageSelector,
    pub(super) header: usize,
    pub(super) loader_base: usize,
    pub(super) build_id: Option<Arc<[u8]>>,
}

impl LoadedImageSnapshot {
    /// Source selector from which this image was discovered.
    pub const fn source_selector(&self) -> &ElfImageSelector {
        &self.source
    }

    /// Runtime address of this image's ELF header.
    pub fn elf_header(&self) -> *const () {
        std::ptr::with_exposed_provenance(self.header)
    }

    /// Base address registered for this image by the dynamic loader.
    pub fn loader_base(&self) -> *const () {
        std::ptr::with_exposed_provenance(self.loader_base)
    }

    /// Raw GNU build-id descriptor, when the image contains one.
    pub fn build_id(&self) -> Option<&[u8]> {
        self.build_id.as_deref()
    }

    /// Returns a selector bound to this exact loaded image.
    ///
    /// The original source selector is cloned so archive-member bounds remain
    /// intact.
    pub fn bound_selector(&self) -> ElfImageSelector {
        let mut selector = self.source;
        selector.bound_image = Some(BoundImage {
            header: self.header,
            loader_base: self.loader_base,
        });
        selector
    }
}

/// Discovers every currently loaded image selected by `selector`.
///
/// No match returns an empty vector. GNU build-id bytes are copied from
/// accessible `PT_NOTE` entries and are not used as image identity.
///
/// # Safety
///
/// Matching mappings, loader registrations, ELF headers, program headers, and
/// readable `PT_LOAD` contents must remain loaded, readable, content-stable,
/// and fixed at the same addresses for the call. A bound selector must describe
/// the source of that exact loader image.
///
/// This call holds no internal lock, but it must not re-enter a mutating Oh My
/// Hook entry point from a signal handler or callback because that can change
/// mappings or relocation slots while discovery is reading them.
///
/// # Errors
///
/// Returns maps, ELF, arithmetic, or unsupported-platform errors encountered
/// while discovering the selected images.
pub unsafe fn find_loaded_images(selector: &ElfImageSelector) -> Result<Vec<LoadedImageSnapshot>> {
    debug!("loaded ELF image discovery requested");
    let maps =
        read_self_maps_pathless().inspect_err(|_| warn!("loaded image maps snapshot failed"))?;
    // SAFETY: forwarded from this function's mapping and metadata stability
    // contract; discovery performs no writes.
    let images = unsafe { elf::find_loaded_images(selector, &maps) }
        .inspect_err(|_| warn!("loaded ELF image discovery failed"))?;
    let images = images
        .into_iter()
        .map(|image| loaded_image_from_found(selector, &image))
        .collect::<Result<Vec<_>>>()
        .inspect_err(|_| warn!("loaded ELF image report construction failed"))?;
    debug!(
        "loaded ELF image discovery complete: images={}, build_ids={}",
        images.len(),
        images
            .iter()
            .filter(|image| image.build_id.is_some())
            .count()
    );
    Ok(images)
}

fn loaded_image_from_found(
    selector: &ElfImageSelector,
    image: &FoundImage,
) -> Result<LoadedImageSnapshot> {
    let loader_base = image
        .id
        .loader_base
        .ok_or(Error::InvalidElf("loaded image has no loader base"))?;
    Ok(LoadedImageSnapshot {
        source: *selector,
        header: image.id.header,
        loader_base,
        build_id: image.build_id.clone(),
    })
}

/// Inspects a PLT hook batch using the installer's read-only relocation-selection checks.
///
/// The result preserves input order and groups relocation facts by exact loaded
/// image. This function never changes page permissions, writes a relocation,
/// or publishes an [`OriginalPointerCell`].
/// Selection eligibility does not guarantee installation: private-file validation,
/// final mutation planning, budgets, and write permission checks may still reject it.
///
/// # Safety
///
/// The image, mapping, loader, symbol, relocation, and writer-exclusion
/// requirements of [`install_hooks`] apply for the duration of this read-only
/// scan. Replacement pointers are not called or written, but their arithmetic
/// and conflict behavior is inspected as if installation were attempted.
/// Every thread which can execute a selected PAC-PLT entry must use the same IA
/// key as the inspecting thread. PAC key reset, debugger or ptrace key
/// replacement, and other key changes are forbidden for the inspection and,
/// when its selector is reused, through installation, removal, and affected
/// call drainage.
/// This call must not re-enter any Oh My hook discovery, inspection, or
/// installation entry point from a signal handler or callback because those
/// APIs may acquire the same process-local non-reentrant read/write lock. The
/// internal lock does not replace the full-call stability and writer-exclusion
/// requirements above.
///
/// # Errors
///
/// Returns operation-wide maps, ELF, page-planning, or arithmetic errors.
/// hook-specific absence and rejection reasons are stored in the aligned
/// [`HookInspection::error`] entries.
pub unsafe fn inspect_hooks(hooks: &[PltHookRequest<'_>]) -> Result<InspectionReport> {
    debug!("PLT hook inspection requested: hooks={}", hooks.len());
    if hooks.is_empty() {
        debug!("PLT hook inspection complete: hooks=0, images=0, slots=0, rejected_hooks=0");
        return Ok(Vec::new());
    }
    drop(crate::sys::recover_lock(crate::sys::PROCESS_LOCK.read()));
    let maps =
        read_self_maps_pathless().inspect_err(|_| warn!("PLT inspection maps snapshot failed"))?;
    // SAFETY: forwarded from this function's read-only mapping and metadata
    // stability contract.
    let mut prepared = unsafe { prepare_hooks(hooks, &maps, true) }
        .inspect_err(|_| warn!("PLT hook inspection preflight failed"))?;
    let _guard = crate::sys::recover_lock(crate::sys::PROCESS_LOCK.read());
    let ranges = match page_ranges(
        prepared
            .scanned
            .iter()
            .flatten()
            .flat_map(|scan| scan.relocations.iter().map(|relocation| relocation.address))
            .chain(
                prepared
                    .rejected
                    .iter()
                    .flatten()
                    .map(|relocation| relocation.address),
            ),
    ) {
        Ok(ranges) => ranges,
        Err(error) => {
            drop(_guard);
            return Err(error);
        }
    };
    let maps = match read_self_maps_for_ranges(&ranges) {
        Ok(maps) => maps,
        Err(error) => {
            drop(_guard);
            return Err(error);
        }
    };
    // SAFETY: the read lock excludes in-crate writers while the report reads
    // the final slot and OriginalPointerCell state.
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
    let _scope = match mutation_scope(&maps, &prepared.plans, None) {
        Ok(scope) => scope,
        Err(error) => {
            drop(_guard);
            return Err(error);
        }
    };
    let report = build_inspection_report(hooks, &maps, prepared);
    drop(_guard);
    let report = report.inspect_err(|_| warn!("PLT hook inspection report failed"))?;
    debug!(
        "PLT hook inspection complete: hooks={}, images={}, slots={}, rejected_hooks={}",
        report.len(),
        report
            .iter()
            .map(|request| request.images.len())
            .sum::<usize>(),
        report
            .iter()
            .flat_map(|request| &request.images)
            .map(|image| image.slots.len())
            .sum::<usize>(),
        report
            .iter()
            .filter(|request| request.error.is_some())
            .count()
    );
    Ok(report)
}

pub(super) fn build_inspection_report(
    hooks: &[PltHookRequest<'_>],
    maps: &[MapInfo],
    prepared: PreparedBatch,
) -> Result<InspectionReport> {
    let PreparedBatch {
        outcomes,
        scanned,
        images,
        rejected,
        conflicting_slots,
        plans,
        ..
    } = prepared;
    let mut report = Vec::with_capacity(hooks.len());
    for ((((((request, outcome), scan), found_images), rejected), conflicting_slots), plan) in hooks
        .iter()
        .zip(outcomes)
        .zip(scanned)
        .zip(images)
        .zip(rejected)
        .zip(conflicting_slots)
        .zip(plans)
    {
        let error = match outcome {
            Some(Err(error)) => Some(error),
            Some(Ok(_)) => {
                return Err(Error::InternalInstallState(
                    "inspection prepared an installed hook outcome",
                ));
            }
            None => None,
        };
        let previous = plan
            .as_ref()
            .map(|plan| std::ptr::with_exposed_provenance(plan.previous));
        let mut image_reports = Vec::with_capacity(
            found_images
                .as_ref()
                .map_or(0, |found_images| found_images.len()),
        );
        let mut accepted_by_image = BTreeMap::<ImageMappingKey, Vec<FoundRelocation>>::new();
        if let Some(scan) = scan {
            for relocation in scan.relocations {
                accepted_by_image
                    .entry(relocation.image)
                    .or_default()
                    .push(relocation);
            }
        }
        let mut rejected_by_image = BTreeMap::<ImageMappingKey, Vec<RejectedRelocation>>::new();
        for relocation in rejected {
            rejected_by_image
                .entry(relocation.image)
                .or_default()
                .push(relocation);
        }
        if let Some(found_images) = found_images {
            for found_image in found_images.iter() {
                let mut slots = Vec::new();
                for relocation in accepted_by_image
                    .remove(&found_image.id)
                    .unwrap_or_default()
                {
                    let map =
                        find_map_containing(maps, relocation.address, std::mem::size_of::<usize>())
                            .ok_or(Error::MappingChanged)?;
                    // SAFETY: the shared scanner and public contract prove
                    // this slot remains live, aligned, and readable.
                    let stored = unsafe { crate::sys::read_pointer(relocation.address)? };
                    slots.push(SlotSnapshot {
                        address: std::ptr::with_exposed_provenance_mut(relocation.address),
                        kind: relocation.kind,
                        current: std::ptr::with_exposed_provenance(stored),
                        addend: Some(relocation.addend),
                        permissions: map.perms,
                        status: inspection_status(
                            request,
                            &relocation,
                            stored,
                            conflicting_slots.contains(&relocation.address),
                            error.as_ref(),
                        )?,
                        selector: StoredValueSelector {
                            image: relocation.image,
                            archive_member_size: request.image_selector.archive_member_size(),
                            address: relocation.address,
                            kind: relocation.kind,
                            stored_value: stored,
                            addend: Some(relocation.addend),
                        },
                    });
                }
                for relocation in rejected_by_image
                    .remove(&found_image.id)
                    .unwrap_or_default()
                {
                    let map =
                        find_map_containing(maps, relocation.address, std::mem::size_of::<usize>())
                            .ok_or(Error::MappingChanged)?;
                    // SAFETY: the shared scanner and public contract prove
                    // this rejected slot remains live, aligned, and readable.
                    let stored = unsafe { crate::sys::read_pointer(relocation.address)? };
                    slots.push(SlotSnapshot {
                        address: std::ptr::with_exposed_provenance_mut(relocation.address),
                        kind: relocation.kind,
                        current: std::ptr::with_exposed_provenance(stored),
                        addend: relocation.addend,
                        permissions: map.perms,
                        status: match relocation.reason {
                            RelocationRejection::PacPltVerificationFailed => {
                                InspectionStatus::PacPltVerificationFailed
                            }
                            RelocationRejection::ImplicitAddend => InspectionStatus::ImplicitAddend,
                            RelocationRejection::UnsupportedAddend => {
                                InspectionStatus::UnsupportedAddend
                            }
                        },
                        selector: StoredValueSelector {
                            image: relocation.image,
                            archive_member_size: request.image_selector.archive_member_size(),
                            address: relocation.address,
                            kind: relocation.kind,
                            stored_value: stored,
                            addend: relocation.addend,
                        },
                    });
                }
                slots.sort_unstable_by_key(|slot| slot.address.addr());
                image_reports.push(ImageInspection {
                    image: loaded_image_from_found(request.image_selector, found_image)?,
                    slots,
                });
            }
        }
        report.push(HookInspection {
            images: image_reports,
            previous,
            error,
        });
    }
    Ok(report)
}

fn inspection_status(
    request: &PltHookRequest<'_>,
    relocation: &FoundRelocation,
    stored: usize,
    conflicting_slot: bool,
    error: Option<&Error>,
) -> Result<InspectionStatus> {
    if conflicting_slot
        || request
            .slot_selector
            .is_some_and(|selector| selector.stored_value != stored)
    {
        return Ok(InspectionStatus::Conflict);
    }
    let current = if relocation.aarch64_pac_plt {
        let Some(current) = crate::sys::verify_pac_plt(stored, relocation.address) else {
            return Ok(InspectionStatus::PacPltVerificationFailed);
        };
        current
    } else {
        stored
    };
    if current == apply_addend(request.replacement, relocation.addend)? {
        return Ok(InspectionStatus::Conflict);
    }
    match relocation.jump_slot_state {
        JumpSlotState::Lazy(resolver)
            if current == resolver
                && !registered_top_replacement_matches(relocation.address, stored)
                && matches!(
                    error,
                    Some(Error::UnsupportedFeature("unresolved lazy PLT relocation"))
                ) =>
        {
            return Ok(InspectionStatus::UnresolvedLazy);
        }
        JumpSlotState::AmbiguousIfunc if request.resolved_ifunc != Some(current) => {
            return Ok(InspectionStatus::AmbiguousIfunc);
        }
        _ => {}
    }
    Ok(match error {
        Some(Error::AmbiguousPreviousPointer) => InspectionStatus::AmbiguousPreviousPointer,
        Some(Error::OriginalPointerCellConflict) => InspectionStatus::OriginalPointerCellConflict,
        Some(_) => InspectionStatus::Rejected,
        None => InspectionStatus::SelectionEligible,
    })
}
use super::*;

//! Transactional PLT/GOT hook installation and explicit removal.

mod arch;
mod conceal;
mod elf;
mod target;

pub use arch::{RelocationKind, RelocationKinds};
pub use target::ElfImageSelector;

use self::elf::{
    FoundImage, FoundRelocation, ImageMappingKey, JumpSlotState, RejectedRelocation,
    RelocationRejection,
};
use self::target::BoundImage;
use crate::maps::{
    DeviceId, MapInfo, MapPerms, MappingSnapshot, find_map_containing, page_ranges,
    read_self_maps_for_ranges, read_self_maps_pathless,
};
#[cfg(target_arch = "aarch64")]
use crate::maps::{SmapInfo, page_ranges_for_sorted_pages, read_self_smaps_for_ranges};
use crate::{Error, HookHandle, Result};
use log::{debug, trace};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CStr;
use std::fmt;
use std::num::NonZeroUsize;
use std::ops::Range;
use std::sync::{Arc, OnceLock};

/// A dynamic-symbol name and optional GNU version selector.
///
/// [`SymbolQuery::any_version`] preserves the traditional ELF lookup behavior:
/// it matches by name and does not inspect GNU version metadata. The other
/// constructors opt into version-aware matching.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SymbolQuery<'a> {
    name: &'a CStr,
    version: SymbolVersion<'a>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SymbolVersion<'a> {
    Any,
    Unversioned,
    Exact(&'a CStr),
}

impl<'a> SymbolQuery<'a> {
    /// Matches `name` without reading or filtering by GNU symbol version.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptySymbol`] when `name` is empty.
    pub fn any_version(name: &'a CStr) -> Result<Self> {
        Self::new(name, SymbolVersion::Any)
    }

    /// Matches only an unversioned occurrence of `name`.
    ///
    /// An image without `DT_VERSYM` treats all dynamic symbols as
    /// unversioned.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptySymbol`] when `name` is empty.
    pub fn unversioned(name: &'a CStr) -> Result<Self> {
        Self::new(name, SymbolVersion::Unversioned)
    }

    /// Matches `name` carrying the exact GNU `version` name.
    ///
    /// The hidden/default bit does not affect matching. Defined symbols use
    /// `VERDEF`; undefined symbols use `VERNEED`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptySymbol`] when `name` is empty or
    /// [`Error::EmptySymbolVersion`] when `version` is empty.
    pub fn exact_version(name: &'a CStr, version: &'a CStr) -> Result<Self> {
        if version.to_bytes().is_empty() {
            return Err(Error::EmptySymbolVersion);
        }
        Self::new(name, SymbolVersion::Exact(version))
    }

    fn new(name: &'a CStr, version: SymbolVersion<'a>) -> Result<Self> {
        if name.to_bytes().is_empty() {
            return Err(Error::EmptySymbol);
        }
        Ok(Self { name, version })
    }

    /// Dynamic symbol name.
    pub const fn name(self) -> &'a CStr {
        self.name
    }

    pub(crate) const fn version(self) -> SymbolVersion<'a> {
        self.version
    }
}

/// A borrowed description of one symbol replacement.
///
/// Constructing a request does not inspect an ELF image or mutate memory. The
/// borrowed image selector and symbol only need to live through the inspection or
/// installation call; the replacement itself has the longer lifetime required
/// by the installer safety contract.
#[must_use = "a request only takes effect when passed to an installer"]
#[derive(Clone, Copy)]
pub struct PltHookRequest<'a> {
    image_selector: &'a ElfImageSelector,
    query: SymbolQuery<'a>,
    replacement: usize,
    relocation_kinds: RelocationKinds,
    slot_selector: Option<StoredValueSelector>,
    expected_slots: Option<NonZeroUsize>,
    single_image_and_slot_required: bool,
    non_null_previous: bool,
    require_private_file_pages: bool,
    resolved_ifunc: Option<usize>,
    resolved_original: Option<usize>,
    original_pointer_cell: Option<&'a OriginalPointerCell>,
}

impl<'a> fmt::Debug for PltHookRequest<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PltHookRequest")
            .field("request", &"[redacted]")
            .field("query", &self.query)
            .field("replacement", &"[redacted]")
            .field("relocation_kinds", &self.relocation_kinds)
            .field(
                "slot_selector",
                &self.slot_selector.as_ref().map(|_| "[redacted]"),
            )
            .field("expected_slots", &self.expected_slots)
            .field(
                "single_image_and_slot_required",
                &self.single_image_and_slot_required,
            )
            .field("non_null_previous", &self.non_null_previous)
            .field(
                "require_private_file_pages",
                &self.require_private_file_pages,
            )
            .field("resolved_ifunc", &self.resolved_ifunc.map(|_| "[redacted]"))
            .field(
                "resolved_original",
                &self.resolved_original.map(|_| "[redacted]"),
            )
            .field(
                "original_pointer_cell",
                &self.original_pointer_cell.map(|_| "[redacted]"),
            )
            .finish()
    }
}

impl<'a> PltHookRequest<'a> {
    /// Describes a replacement for every supported relocation named `symbol`
    /// in each currently loaded image selected by the selector.
    ///
    /// This method is safe because it only validates and records addresses.
    /// Pointer validity, ABI compatibility, mapping stability, and lifetime are
    /// checked by the caller when entering [`install_hooks`]'s unsafe contract.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptySymbol`] for an empty name or
    /// [`Error::NullReplacement`] for a null replacement.
    pub fn new(
        image_selector: &'a ElfImageSelector,
        symbol: &'a CStr,
        replacement: *const (),
    ) -> Result<Self> {
        Self::new_query(
            image_selector,
            SymbolQuery::any_version(symbol)?,
            replacement,
        )
    }

    /// Describes a replacement selected by a name-and-version query.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NullReplacement`] for a null replacement. Query
    /// constructors validate their borrowed names separately.
    pub fn new_query(
        image_selector: &'a ElfImageSelector,
        query: SymbolQuery<'a>,
        replacement: *const (),
    ) -> Result<Self> {
        if replacement.is_null() {
            return Err(Error::NullReplacement);
        }
        Ok(Self {
            image_selector,
            query,
            replacement: replacement.expose_provenance(),
            relocation_kinds: RelocationKinds::ALL,
            slot_selector: None,
            expected_slots: None,
            single_image_and_slot_required: false,
            non_null_previous: false,
            require_private_file_pages: false,
            resolved_ifunc: None,
            resolved_original: None,
            original_pointer_cell: None,
        })
    }

    /// Requires every selected relocation page to stay Validated.
    ///
    /// A Validated mutation requires every selected relocation page to be a readable
    /// private file mapping, so the slot write stays a private copy and never
    /// reaches the backing file. Failure rolls the complete operation back
    /// without degrading to an unvalidated in-place write.
    pub fn require_private_file_pages(mut self) -> Self {
        self.require_private_file_pages = true;
        self
    }

    /// Restricts this request to the selected semantic relocation kinds.
    ///
    /// The default is [`RelocationKinds::ALL`]. Narrowing the set can exclude
    /// valid call paths, such as `-fno-plt` calls through global-data
    /// relocations, so the caller must choose it deliberately.
    pub fn with_relocation_kinds(mut self, kinds: RelocationKinds) -> Self {
        self.relocation_kinds = kinds;
        self
    }

    /// Requires this request's image selector to be bound to one exact loaded image.
    ///
    /// This is a fail-closed assertion over the existing request binding; it
    /// does not create another image identity or extend the binding lifetime.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BoundImageRequired`] for an unbound source selector.
    pub fn require_bound_image(self) -> Result<Self> {
        if self.image_selector.bound_image().is_none() {
            return Err(Error::BoundImageRequired);
        }
        Ok(self)
    }

    /// Requires exactly `expected` selected relocation slots.
    ///
    /// The assertion is checked after relocation-kind and inspected-slot
    /// selection, before original publication or page protection changes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidSlotCount`] when `expected` is zero.
    pub fn expect_slots(mut self, expected: usize) -> Result<Self> {
        self.expected_slots = Some(NonZeroUsize::new(expected).ok_or(Error::InvalidSlotCount)?);
        Ok(self)
    }

    /// Requires a present request to select one loaded image and one relocation.
    ///
    /// Candidate absence remains [`Error::TargetNotLoaded`] or
    /// [`Error::NoMatchingRelocation`]. A present ambiguous selector or relocation
    /// fails closed before original publication or page protection changes.
    pub fn require_single_image_and_slot(mut self) -> Self {
        self.single_image_and_slot_required = true;
        self
    }

    /// Requires this request to select one bound loaded image and one relocation.
    ///
    /// This is the strict single-slot shorthand for [`PltHookRequest::require_bound_image`]
    /// followed by [`PltHookRequest::require_single_image_and_slot`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::BoundImageRequired`] for an unbound source selector.
    pub fn require_bound_image_and_single_slot(self) -> Result<Self> {
        Ok(self.require_bound_image()?.require_single_image_and_slot())
    }

    /// Requires all selected slots to share a non-null previous pointer.
    ///
    /// This opt-in assertion is checked during preflight before original
    /// publication, page protection changes, or relocation writes. A non-null
    /// value does not prove the pointer has the correct ABI or remains valid.
    pub fn require_non_null_previous(mut self) -> Self {
        self.non_null_previous = true;
        self
    }

    /// Restricts this request to one opaque slot returned by an inspection.
    ///
    /// Installation still performs a fresh maps and ELF scan and verifies the
    /// selector's exact image, relocation metadata, and inspected stored value.
    /// The selector is a point-in-time process-local constraint, not a
    /// persistent image generation identity.
    ///
    /// # Errors
    ///
    /// Returns [`Error::BoundImageRequired`] for an unbound selector or
    /// [`Error::SlotSelectorMismatch`] when the selector names another image.
    pub fn with_slot_selector(mut self, selector: StoredValueSelector) -> Result<Self> {
        let bound = self
            .image_selector
            .bound_image()
            .ok_or(Error::BoundImageRequired)?;
        if selector.image.device != self.image_selector.device()
            || selector.image.inode != self.image_selector.inode()
            || selector.image.elf_header_offset != self.image_selector.elf_header_offset()
            || selector.archive_member_size != self.image_selector.archive_member_size()
            || selector.image.header != bound.header
            || selector.image.loader_base != Some(bound.loader_base)
        {
            return Err(Error::SlotSelectorMismatch);
        }
        self.slot_selector = Some(selector);
        Ok(self)
    }

    /// Supplies the final implementation address for an ambiguous GNU/Linux
    /// `STT_GNU_IFUNC` jump slot.
    ///
    /// Linux ELF state cannot always distinguish a resolved IFUNC from a lazy
    /// trampoline in the same image. The installer accepts such a slot only
    /// when its current value equals this address. Android resolves jump slots
    /// eagerly and normally does not need this hint. For PAC-PLT, pass the raw
    /// implementation address rather than the signed stored slot value.
    ///
    /// This setter only records the address. Its truthfulness remains part of
    /// [`install_hooks`]'s safety contract.
    pub fn with_resolved_ifunc(mut self, previous: *const ()) -> Self {
        self.resolved_ifunc = Some(previous.expose_provenance());
        self
    }

    /// Supplies the callable original for an unresolved lazy jump slot.
    ///
    /// This permits installation before the first call without invoking the
    /// loader's resolver. The original must be the implementation that this
    /// exact import would resolve to, including its symbol version, namespace,
    /// and interposition scope. Null, resolver, and replacement addresses are
    /// rejected. Already resolved slots keep their actual previous pointer.
    /// Removal restores the raw lazy slot, not this supplied implementation.
    /// For PAC-PLT, supply the unsigned implementation address.
    ///
    /// This setter only records the address; its ABI, lookup correctness, and
    /// lifetime remain part of [`install_hooks`]'s unsafe contract. Ambiguous
    /// IFUNC slots still require [`Self::with_resolved_ifunc`].
    pub fn with_resolved_original(mut self, previous: *const ()) -> Self {
        self.resolved_original = Some(previous.expose_provenance());
        self
    }

    /// Makes the accepted original available through `slot` before the first
    /// page-permission change or relocation write.
    ///
    /// The value may have been supplied by [`OriginalPointerCell::from_expected`] or
    /// resolved by preflight. It does not mean the hook remains installed.
    /// Publication is intentionally not undone if this or a later PltHookRequest is
    /// rolled back.
    pub fn with_original_pointer_cell(mut self, slot: &'a OriginalPointerCell) -> Self {
        self.original_pointer_cell = Some(slot);
        self
    }
}

/// One-time cell for an expected or installer-resolved original pointer.
///
/// Multiple Hooks may share a cell only when every present installable PltHookRequest
/// resolves the same value. The value can outlive a failed or rolled-back
/// installation and therefore must not be used as an installation-state flag.
/// An installer-resolved PAC-PLT original is stored only after verification and
/// without its PAC.
#[derive(Default)]
pub struct OriginalPointerCell {
    value: OnceLock<usize>,
}

impl fmt::Debug for OriginalPointerCell {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OriginalPointerCell")
            .field("value", &self.value.get().map(|_| "[redacted]"))
            .finish()
    }
}

impl OriginalPointerCell {
    /// Creates an empty original-pointer cell.
    pub const fn new() -> Self {
        Self {
            value: OnceLock::new(),
        }
    }

    /// Creates a cell pre-populated with the only acceptable original pointer.
    ///
    /// Passing this cell through [`PltHookRequest::with_original_pointer_cell`] makes a mismatch
    /// fail during preflight with [`Error::OriginalPointerCellConflict`] while also
    /// making the expected original immediately available to the replacement.
    /// The pointer may be null; this cell does not validate its ABI, provenance,
    /// or loaded-image lifetime.
    pub fn from_expected(previous: *const ()) -> Self {
        Self {
            value: OnceLock::from(previous.expose_provenance()),
        }
    }

    /// Returns the accepted original pointer, if one is available.
    ///
    /// `Some` may contain a null pointer. Availability does not indicate that a
    /// PltHookRequest is installed or that the pointer remains callable or dereferenceable.
    #[inline]
    pub fn get(&self) -> Option<*const ()> {
        self.value
            .get()
            .copied()
            .map(std::ptr::with_exposed_provenance)
    }
}

/// Installed PLT/GOT hook and the record needed to remove it.
///
/// Dropping this value does not remove the hook. Before calling
/// [`HookHandle::unhook`], the caller must drain replacement and original
/// calls, while preserving all mapping, ABI, lifetime, writer-exclusion, and
/// non-reentrancy guarantees required by installation. Concurrent readers of
/// a selected slot may observe the old or the new value, never a torn one;
/// no relocation-page quiescence is required. Selected images must not be
/// unloaded, remapped, or
/// reprotected while this handle is installed; a fresh maps check cannot rule
/// out same-address ABA replacement.
///
/// For PAC-PLT slots, every thread which can execute the selected PLT entry
/// must keep the same IA key used by the installer. PAC key reset, debugger or
/// ptrace key replacement, and any other key change remain forbidden until the
/// PltHookRequest is removed and all affected calls have drained.
#[must_use = "the previous pointer must usually be published to the replacement"]
#[non_exhaustive]
pub struct PltHookHandle {
    previous: usize,
    slots: NonZeroUsize,
    private_file_validation: PrivateFileValidation,
    /// Errno reported when the installing operation could not close the
    /// forced-access descriptor. The installation itself succeeded.
    forced_descriptor_close_errno: Option<syscalls::Errno>,
    record: Option<PltRemovalRecord>,
}

// The handle is meant to be installed once and removed later, which requires
// storing it or moving it between threads. Keeping the previous slot value as
// an exposed address rather than a raw pointer field is what keeps that legal.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<PltHookHandle>();
};

impl PltHookHandle {
    /// Non-zero number of selected slots changed across loaded images.
    pub fn slots(&self) -> NonZeroUsize {
        self.slots
    }

    /// Unique untyped original for every selected slot. For unresolved lazy
    /// slots this is the supplied resolved original rather than the resolver.
    /// A PAC-PLT value is verified and returned without its PAC.
    ///
    /// This value may be null. Converting it to a function pointer, calling it,
    /// or dereferencing it remains unsafe and requires the caller to prove the
    /// correct ABI, provenance, and loaded-image lifetime.
    pub fn previous(&self) -> *const () {
        std::ptr::with_exposed_provenance(crate::sys::decode_usize(self.previous))
    }

    /// Returns the errno of a failed forced-descriptor close during the
    /// operation that installed this handle. The current PLT path always uses
    /// atomic CAS through the elevation channel, so this is normally `None`.
    ///
    /// `None` means the descriptor closed or no forced channel was used. When
    /// set, the installation still succeeded and the hook is fully usable:
    /// Linux may have released the descriptor anyway, so do not retry the
    /// close. Every handle from the same batch reports the same value.
    pub fn forced_descriptor_close_errno(&self) -> Option<syscalls::Errno> {
        self.forced_descriptor_close_errno
    }
}

impl fmt::Debug for PltHookHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PltHookHandle")
            .field("previous", &"[redacted]")
            .field("slots", &self.slots)
            .field("private_file_validation", &self.private_file_validation)
            .field(
                "forced_descriptor_close_errno",
                &self.forced_descriptor_close_errno,
            )
            .finish()
    }
}

impl HookHandle for PltHookHandle {
    fn original(&self) -> Option<*const ()> {
        self.record.is_some().then(|| self.previous())
    }

    fn is_installed(&self) -> bool {
        self.record.is_some()
    }

    fn private_file_validation(&self) -> PrivateFileValidation {
        self.private_file_validation
    }

    unsafe fn unhook(&mut self) -> Result<()> {
        // SAFETY: forwarded from this method's complete public contract; a
        // one-element batch has exactly the same requirements.
        unsafe { unhook_hooks(std::slice::from_mut(self)) }
    }
}

/// Removes one in-place bound-image PltHookRequest after a targeted live maps check.
/// A fast installation which left its page writable restores it here.
///
/// # Safety
///
/// The caller must hold the process write lock and the public unhook contract
/// must remain satisfied for the operation.
unsafe fn try_unhook_fast_single_hook(request: &mut PltHookHandle) -> Option<PltRemovalRecord> {
    if !matches!(
        request.private_file_validation,
        PrivateFileValidation::Unvalidated | PrivateFileValidation::Validated
    ) {
        return None;
    }
    let record = request.record.as_ref()?;
    if record.image_selector.bound_image().is_none() || !record.rest.is_empty() {
        return None;
    }
    let entry = &record.first;
    let write = entry.decoded_write();
    let page_size = crate::sys::page_size().ok()?;
    let page = crate::sys::page_start(write.address, page_size);
    let page_end = page.checked_add(page_size)?;
    let maps = read_self_maps_for_ranges(&[(page, page_end)]).ok()?;
    let actual_map = validate_plt_record(record, &maps).ok()??;
    if actual_map.perms.contains(MapPerms::EXEC)
        || !actual_map.perms.contains(MapPerms::READ)
        || !actual_map.is_private
        || !actual_map.contains_range(page, page_size)
    {
        return None;
    }
    #[cfg(target_arch = "aarch64")]
    let extension_mask = PROT_BTI | PROT_MTE;
    #[cfg(not(target_arch = "aarch64"))]
    let extension_mask = 0;
    let original_protection = record.protections.get(page)?;
    if (original_protection & !extension_mask) != actual_map.perms.to_prot() {
        return None;
    }
    let writable = actual_map.perms.contains(MapPerms::WRITE);
    // SAFETY: the record mapping and slot-lifetime contract cover this read.
    if unsafe { crate::sys::read_pointer(write.address).ok()? } != write.replacement {
        return None;
    }
    if !registered_top_install_matches(write.address, write.replacement, record.id) {
        return None;
    }
    #[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
    crate::maps::validate_page_write_access(&maps, &[page], page_size).ok()?;

    let reverse = StoredPointerWrite {
        image: write.image,
        address: write.address,
        expected: write.replacement,
        replacement: write.expected,
    };
    crate::sys::enter_mutation();
    let commit_result = (|| -> Result<()> {
        if !writable {
            // SAFETY: the actual map covers this complete page.
            unsafe {
                crate::sys::protect(page, page_size, original_protection | libc::PROT_WRITE)?
            };
        }
        // SAFETY: the page is writable and the public contract excludes writers.
        let write_result = unsafe { write_chunk(std::slice::from_ref(&reverse)) };
        if !writable {
            // SAFETY: the same complete page is being restored.
            let restore_result =
                unsafe { crate::sys::protect(page, page_size, original_protection) };
            if let Err(restore_error) = restore_result {
                if write_result.is_err() {
                    crate::sys::fail_stop();
                }
                if write_result.is_ok() {
                    // SAFETY: the successful write is the only transient slot.
                    let rollback = unsafe {
                        crate::sys::compare_exchange_pointer(
                            reverse.address,
                            reverse.replacement,
                            reverse.expected,
                        )
                    };
                    if !matches!(rollback, Ok(true)) {
                        crate::sys::fail_stop();
                    }
                    // SAFETY: retry the restore after rolling back the write.
                    if unsafe { crate::sys::protect(page, page_size, original_protection) }.is_err()
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
    commit_result.ok()?;
    complete_single_removal(record.id, write.address, write.replacement);
    request.record.take()
}

/// Removes an installed PLT/GOT hook batch in one serialized transaction.
///
/// Handles which are already removed are skipped, and a batch containing only
/// those is a no-op. Every remaining handle is validated against one shared
/// `/proc/self/maps` snapshot, and each relocation page shared by several
/// handles is elevated and restored once for the complete batch rather than
/// once per handle. Successful removal clears every handle. Removal is
/// last-installed-first-removed: a handle whose slot another still-installed
/// handle was stacked on is rejected with [`Error::Conflict`] before any page
/// or pointer changes, while a batch may remove one complete stack together.
///
/// # Errors
///
/// Returns the first record-validation or mutation failure. Every pointer this
/// call wrote is rolled back before the error is returned and no handle is
/// cleared, so the complete batch stays retryable.
/// A close failure of the forced descriptor after a successful atomic removal
/// is different: every slot and handle was already restored and cleared, and
/// the error only reports the leaked resource, mirroring the inline engine.
///
/// # Safety
///
/// The complete removal contract of [`HookHandle::unhook`] applies to every
/// handle in `hooks` at once: every replacement and original call must be
/// drained before entry. Concurrent slot readers may observe the old or the
/// restored value, never a torn one, so no page quiescence is required.
pub unsafe fn unhook_hooks(hooks: &mut [PltHookHandle]) -> Result<()> {
    let installed = hooks
        .iter()
        .filter(|request| request.record.is_some())
        .count();
    if installed == 0 {
        trace!("PLT unhook skipped: state=removed");
        return Ok(());
    }
    debug!("PLT unhook requested: hooks={installed}");

    let fast_single = installed == 1;

    let mut plan_order = Vec::new();
    let mut removed_records = Vec::new();
    if !fast_single {
        // Canonicalize complete-stack removal before taking the process lock.
        // A newer install id must be removed first; already-removed handles
        // sort after installed handles and are ignored by mutation planning.
        plan_order = (0..hooks.len()).collect::<Vec<_>>();
        plan_order.sort_unstable_by(|&left, &right| {
            hooks[right]
                .record
                .as_ref()
                .map(|record| record.id)
                .cmp(&hooks[left].record.as_ref().map(|record| record.id))
        });

        // Keep output collections outside the guard's declaration; every error
        // path below releases the guard before the remaining scratch is dropped.
        removed_records = Vec::with_capacity(installed);
    }
    let mut removals: Vec<(usize, usize, usize)> = Vec::new();
    let _guard = crate::sys::recover_lock(crate::sys::PROCESS_LOCK.write());
    let page_size = match crate::sys::page_size() {
        Ok(page_size) => page_size,
        Err(error) => {
            drop(_guard);
            return Err(error);
        }
    };
    if fast_single {
        let Some(request) = hooks.iter_mut().find(|request| request.record.is_some()) else {
            drop(_guard);
            return Err(Error::InternalInstallState("unhook lost its only record"));
        };
        // SAFETY: the caller holds the process write lock and the public
        // unhook contract remains satisfied.
        if let Some(record) = unsafe { try_unhook_fast_single_hook(request) } {
            drop(record);
            drop(_guard);
            debug!("PLT unhook complete: hooks=1");
            return Ok(());
        }
        plan_order = (0..hooks.len()).collect::<Vec<_>>();
        plan_order.sort_unstable_by(|&left, &right| {
            hooks[right]
                .record
                .as_ref()
                .map(|record| record.id)
                .cmp(&hooks[left].record.as_ref().map(|record| record.id))
        });
        removed_records = Vec::with_capacity(installed);
    }
    let mut validation_addresses = Vec::new();
    for request in hooks.iter().filter(|request| request.record.is_some()) {
        let Some(record) = request.record.as_ref() else {
            continue;
        };
        for entry in record.entries() {
            let write = entry.decoded_write();
            validation_addresses.push(write.address);
            let page = crate::sys::page_start(write.address, page_size);
            validation_addresses.push(page.saturating_sub(page_size));
        }
    }
    let ranges = match page_ranges(validation_addresses) {
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

    // One shared saved-protection view. Two handles covering the same page must
    // agree on what that page was before installation; disagreement means the
    // mapping changed underneath them.
    let mut protections = BTreeMap::new();
    let mut plans = Vec::with_capacity(hooks.len());
    for &index in &plan_order {
        let request = &hooks[index];
        let Some(record) = request.record.as_ref() else {
            plans.push(None);
            continue;
        };
        if let Err(error) = validate_plt_record(record, &maps) {
            drop(_guard);
            return Err(error);
        }
        for entry in record.entries() {
            let write = entry.decoded_write();
            removals.push((record.id, write.address, write.replacement));
        }
        for (start, protection) in record.protections.iter() {
            if protections
                .insert(start, protection)
                .is_some_and(|previous| previous != protection)
            {
                drop(_guard);
                return Err(Error::MappingChanged);
            }
        }
        plans.push(Some(HookPlan {
            previous: crate::sys::decode_usize(request.previous),
            slots: request.slots,
            writes: record
                .entries()
                .map(|entry| {
                    let write = entry.decoded_write();
                    StoredPointerWrite {
                        image: write.image,
                        address: write.address,
                        expected: write.replacement,
                        replacement: write.expected,
                    }
                })
                .collect(),
        }));
    }
    // Reject removal of a hook which another hook was stacked on before any
    // page or pointer changes.
    if let Err(error) = validate_removal_order(&removals) {
        drop(_guard);
        return Err(error);
    }

    let scope = match mutation_scope(&maps, &plans, Some(&protections)) {
        Ok(scope) => scope,
        Err(error) => {
            drop(_guard);
            return Err(error);
        }
    };
    // Removal has the same concurrent-reader contract as installation.
    let mut forced_fd = ForcedFd::open(false);
    let mut mutation = match mutation_plan_with_channel(
        &maps,
        &plans,
        scope,
        forced_fd.get(),
        forced_fd.open_errno(),
    ) {
        Ok(mutation) => mutation,
        Err(error) => {
            drop(_guard);
            forced_fd.close_and_report();
            return Err(error);
        }
    };
    let mut state = CommitState::new(plans.len());
    // SAFETY: the caller preserves the installed mappings and excludes every
    // competing reader/writer required by the public handle contract.
    let committed = unsafe {
        // SAFETY: the caller preserves the installed mappings and excludes
        // every competing reader/writer required by the public handle contract.
        commit_mutation(
            &mut mutation,
            &mut state,
            CommitPolicy::RollbackAllOnFailure,
        )
    };
    if let Err(failure) = committed {
        // The atomic rollback completed before the descriptor closed, so a
        // close failure only leaks the resource.
        drop(_guard);
        forced_fd.close_and_report();
        return Err(failure.source);
    }
    // The slots are already restored here; a failed close after a successful
    // atomic removal must not leave an installed-looking handle behind, so it
    // is reported as a leaked resource after the records are cleared.
    // A plain match avoids a monomorphized `Option::and_then` wrapper whose
    // symbol name would collide with the mutation-window text audit.
    let forced_close_errno = match forced_fd.take() {
        Some(fd) => crate::sys::close_self_mem(fd),
        None => None,
    };
    complete_removal(&removals);
    for request in hooks.iter_mut() {
        if let Some(record) = request.record.take() {
            removed_records.push(record);
        }
    }
    drop(_guard);
    debug!("PLT unhook complete: hooks={installed}");
    // The removal is already complete and every handle was cleared; this
    // error only reports the leaked descriptor, like the inline engine.
    match forced_close_errno {
        Some(errno) => Err(Error::system_call("close", errno)),
        None => Ok(()),
    }
}

/// Per-PltHookRequest results returned by [`install_hooks`].
///
/// The report always has the same length and order as the input slice. An inner
/// error means that input hook left no installed slot; independent Hooks may
/// still have succeeded. Prefer [`install_hook`] for one request so its hook-level
/// error is returned directly.
/// Use [`Self::into_parts`] to retain every installed handle when processing
/// partial failures. Dropping this report does not remove installed hooks.
/// A short-circuiting collection cannot consume its successful handles:
///
/// ```compile_fail
/// use omhook::{InstallReport, PltHookHandle, Result};
/// fn collect_report(report: InstallReport) -> Result<Vec<PltHookHandle>> {
///     report.into_iter().collect()
/// }
/// ```
#[derive(Debug)]
#[must_use = "retain the installed handles until explicit removal"]
pub struct InstallReport(Vec<Result<PltHookHandle>>);

/// Installed handles and failures, each paired with its original request index.
pub type InstallReportParts = (Vec<(usize, PltHookHandle)>, Vec<(usize, Error)>);

impl InstallReport {
    /// Separates all installed handles from failures without short-circuiting.
    #[must_use = "retain the installed handles until explicit removal"]
    pub fn into_parts(self) -> InstallReportParts {
        let mut installed = Vec::new();
        let mut failed = Vec::new();
        for (index, result) in self.0.into_iter().enumerate() {
            match result {
                Ok(handle) => installed.push((index, handle)),
                Err(error) => failed.push((index, error)),
            }
        }
        (installed, failed)
    }
}

impl std::ops::Deref for InstallReport {
    type Target = [Result<PltHookHandle>];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Hard operation-wide limits for the final selected mutation.
///
/// Limits are checked after PltHookRequest selection and conflict preflight but before
/// publishing originals or changing page permissions. Exceeding a limit
/// rejects the complete operation; the installer never trims a plan to fit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MutationBudget {
    /// Maximum loaded images containing at least one selected slot.
    max_images: usize,
    /// Maximum unique selected relocation slots.
    max_slots: usize,
    /// Maximum unique pages containing selected slots, including pages which
    /// were already writable.
    max_pages: usize,
}

impl MutationBudget {
    /// Creates operation-wide mutation limits.
    pub const fn new(max_images: usize, max_slots: usize, max_pages: usize) -> Self {
        Self {
            max_images,
            max_slots,
            max_pages,
        }
    }
}

/// Read-only preflight status for one inspected relocation slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum InspectionStatus {
    /// Relocation selection succeeded for this slot. Private-file-page
    /// validation and final mutation planning are checked only at install.
    SelectionEligible,
    /// Another input request selected the same slot, the slot already holds the
    /// requested replacement, or a reused selector no longer matches its
    /// inspected stored value.
    Conflict,
    /// The slot points at a lazy-binding resolver without an accepted original hint.
    UnresolvedLazy,
    /// The slot is an ambiguous GNU IFUNC without a matching supplied hint.
    AmbiguousIfunc,
    /// Slots selected by this request do not share one previous pointer.
    AmbiguousPreviousPointer,
    /// A shared [`OriginalPointerCell`] disagrees with this request's original pointer.
    OriginalPointerCellConflict,
    /// The stored AArch64 PAC-PLT value failed PAC verification.
    PacPltVerificationFailed,
    /// The relocation requires reading an implicit addend from its slot.
    ImplicitAddend,
    /// The x86-64 slot carries a non-zero explicit relocation addend, which
    /// the installer refuses instead of writing a replacement without it.
    UnsupportedAddend,
    /// Another PltHookRequest-level preflight error rejects this slot.
    Rejected,
}

/// Opaque process-local selector for one inspected relocation slot.
///
/// A selector cannot authorize an arbitrary address write. The installer
/// accepts it only after a fresh ELF scan finds the same exact image,
/// relocation address, semantic kind, addend, and literal stored slot value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StoredValueSelector {
    image: ImageMappingKey,
    archive_member_size: Option<u64>,
    address: usize,
    kind: crate::RelocationKind,
    stored_value: usize,
    addend: Option<i64>,
}

impl StoredValueSelector {
    fn matches_relocation(self, relocation: &FoundRelocation) -> bool {
        self.image == relocation.image
            && self.address == relocation.address
            && self.kind == relocation.kind
            && self.addend == Some(relocation.addend)
    }

    fn matches_rejected(self, relocation: &RejectedRelocation) -> bool {
        self.image == relocation.image
            && self.address == relocation.address
            && self.kind == relocation.kind
            && self.addend == relocation.addend
    }
}

/// Point-in-time read-only facts about one matching relocation slot.
///
/// The report does not prove that `address` remains mapped or writable. Do not
/// write it directly; pass [`SlotSnapshot::selector`] back to an installer so
/// the image, relocation metadata, and stored value are validated again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlotSnapshot {
    /// Runtime address of the relocation slot at inspection time.
    pub address: *mut (),
    /// Supported semantic relocation kind.
    pub kind: crate::RelocationKind,
    /// Literal value stored in the slot at inspection time. A valid PAC-PLT slot may hold
    /// a signed value rather than the verified raw pointer.
    pub current: *const (),
    /// Explicit or loader-defined relocation addend, or `None` when the
    /// rejected relocation requires an implicit addend.
    pub addend: Option<i64>,
    /// RWX permissions visible in `/proc/self/maps`.
    pub permissions: MapPerms,
    /// Result of applying the batch's read-only relocation-selection checks.
    pub status: InspectionStatus,
    selector: StoredValueSelector,
}

impl SlotSnapshot {
    /// Returns the opaque selector for this inspected relocation.
    pub const fn selector(&self) -> StoredValueSelector {
        self.selector
    }
}

/// Per-image relocation facts for one input hook.
#[derive(Debug)]
pub struct ImageInspection {
    /// Exact loaded image that was inspected.
    pub image: LoadedImageSnapshot,
    /// Matching supported and explicitly rejected relocation slots in address
    /// order.
    pub slots: Vec<SlotSnapshot>,
}

/// Read-only preflight result for one input hook.
#[derive(Debug)]
pub struct HookInspection {
    // Private because `into_unique_eligible` relies on the crate-established
    // invariant that an error-free inspection with one eligible slot always
    // carries a previous value.
    images: Vec<ImageInspection>,
    previous: Option<*const ()>,
    error: Option<Error>,
}

impl HookInspection {
    /// Every loaded image selected by this request's image selector, including images with
    /// no matching relocation.
    pub fn images(&self) -> &[ImageInspection] {
        &self.images
    }

    /// Consumes this inspection and returns its per-image results.
    pub fn into_images(self) -> Vec<ImageInspection> {
        self.images
    }

    /// Unique original pointer accepted by relocation-selection preflight.
    /// A PAC-PLT result is verified and returned without its PAC. Private-file
    /// validation and final mutation planning still occur during installation.
    pub const fn previous(&self) -> Option<*const ()> {
        self.previous
    }

    /// PltHookRequest-level absence or rejection reason, if any.
    pub const fn error(&self) -> Option<&Error> {
        self.error.as_ref()
    }

    /// Consumes this inspection and returns its only eligible exact slot.
    ///
    /// PltHookRequest-level preflight errors are returned first. The remaining report must
    /// contain exactly one eligible relocation across all loaded images, and
    /// its verified previous pointer must be non-null. Installation must still
    /// use the returned selector and repeat strict checks against its fresh
    /// snapshot.
    ///
    /// # Errors
    ///
    /// Returns the stored PltHookRequest-level error, [`Error::UnexpectedSlotCount`] when
    /// the eligible slot count is not one, or [`Error::NullPreviousPointer`] when
    /// the unique verified previous pointer is null.
    pub fn into_unique_eligible(self) -> Result<(LoadedImageSnapshot, SlotSnapshot)> {
        let previous = self.previous;
        if let Some(error) = self.error {
            return Err(error);
        }

        let mut eligible = None;
        let mut actual = 0;
        for image in self.images {
            for slot in image
                .slots
                .iter()
                .copied()
                .filter(|slot| slot.status == InspectionStatus::SelectionEligible)
            {
                actual += 1;
                if eligible.is_none() {
                    eligible = Some((image.image.clone(), slot));
                }
            }
        }
        if actual != 1 {
            return Err(Error::UnexpectedSlotCount {
                expected: 1,
                actual,
            });
        }
        let (image, slot) = eligible.unwrap_or_else(|| crate::sys::fail_stop());
        if previous
            .unwrap_or_else(|| crate::sys::fail_stop())
            .is_null()
        {
            return Err(Error::NullPreviousPointer);
        }
        Ok((image, slot))
    }
}

/// Ordered read-only results returned by [`inspect_hooks`].
pub type InspectionReport = Vec<HookInspection>;

/// Required/optional policy for one borrowed PLT hook group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HookGroupKind {
    /// At least one candidate must produce a final installed slot.
    Required,
    /// A group with only absent candidates is accepted.
    Optional,
}

/// A borrowed group of candidate or complementary Hooks installed as one
/// operation-wide rollback unit.
#[derive(Clone, Copy, Debug)]
pub struct PltHookRequestGroup<'hooks, 'request> {
    hooks: &'hooks [PltHookRequest<'request>],
    kind: HookGroupKind,
    require_private_file_pages: bool,
}

impl<'hooks, 'request> PltHookRequestGroup<'hooks, 'request> {
    /// Creates a group which requires at least one present installable request.
    pub const fn required(hooks: &'hooks [PltHookRequest<'request>]) -> Self {
        Self {
            hooks,
            kind: HookGroupKind::Required,
            require_private_file_pages: false,
        }
    }

    /// Creates a group which may have no present hook.
    ///
    /// An empty slice is a valid no-op and produces an aligned empty report.
    pub const fn optional(hooks: &'hooks [PltHookRequest<'request>]) -> Self {
        Self {
            hooks,
            kind: HookGroupKind::Optional,
            require_private_file_pages: false,
        }
    }

    /// Borrowed Hooks in this group.
    pub const fn hooks(self) -> &'hooks [PltHookRequest<'request>] {
        self.hooks
    }

    /// Required/optional policy for this group.
    pub const fn kind(self) -> HookGroupKind {
        self.kind
    }

    /// Requires every selected relocation page of every request in this group to
    /// stay Validated.
    ///
    /// A Validated mutation requires every selected relocation page to be a readable
    /// private file mapping, so the slot write stays a private copy and never
    /// reaches the backing file. Failure rolls the complete operation back
    /// without degrading to an unvalidated in-place write. The default is
    /// in-place; this changes every request in the group without changing the
    /// borrowed PltHookRequest values themselves.
    pub const fn require_private_file_pages(mut self) -> Self {
        self.require_private_file_pages = true;
        self
    }

    /// Whether PrivateFileValidation was requested for every request in this group.
    pub const fn private_file_validation_requested(self) -> bool {
        self.require_private_file_pages
    }
}

/// Per-group, per-PltHookRequest results from [`install_hook_groups`].
/// Dropping this report does not remove installed hooks.
#[derive(Debug)]
#[must_use = "retain every group's installed handles until explicit removal"]
pub struct GroupInstallReport(Vec<InstallReport>);

impl GroupInstallReport {
    /// Returns all groups in input order, including empty groups.
    #[must_use = "retain every group's installed handles until explicit removal"]
    pub fn into_groups(self) -> Vec<InstallReport> {
        self.0
    }
}

impl std::ops::Deref for GroupInstallReport {
    type Target = [InstallReport];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Indexed failure from a group installation with operation-wide rollback.
#[derive(Debug)]
pub struct GroupInstallError {
    /// Group index for a group policy or hook-specific failure.
    pub group: Option<usize>,
    /// PltHookRequest index within [`GroupInstallError::group`], when applicable.
    pub hook_index: Option<usize>,
    /// Underlying hook or operation error.
    pub source: Error,
}

impl fmt::Display for GroupInstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.group, self.hook_index) {
            (Some(group), Some(hook_index)) => {
                write!(
                    f,
                    "PLT hook group {group}, hook index {hook_index}: {}",
                    self.source
                )
            }
            (Some(group), None) => write!(f, "PLT hook group {group}: {}", self.source),
            (None, Some(hook_index)) => {
                write!(f, "PLT hook index {hook_index}: {}", self.source)
            }
            (None, None) => fmt::Display::fmt(&self.source, f),
        }
    }
}

impl std::error::Error for GroupInstallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

struct ScannedHook {
    relocations: Vec<FoundRelocation>,
    images: Arc<[FoundImage]>,
}

struct HookPlan {
    previous: usize,
    slots: NonZeroUsize,
    writes: Vec<StoredPointerWrite>,
}

struct PltRemovalRecord {
    id: usize,
    image_selector: ElfImageSelector,
    images: Arc<[FoundImage]>,
    first: PltRemovalEntry,
    rest: Vec<PltRemovalEntry>,
    protections: PltSavedProtections,
}

#[derive(Clone)]
enum PltSavedProtections {
    Fast { page: usize, protection: i32 },
    Shared(Arc<BTreeMap<usize, i32>>),
}

impl PltSavedProtections {
    fn get(&self, page: usize) -> Option<i32> {
        match self {
            Self::Fast {
                page: saved_page,
                protection,
            } => (*saved_page == page).then_some(*protection),
            Self::Shared(protections) => protections.get(&page).copied(),
        }
    }

    fn iter(&self) -> Box<dyn Iterator<Item = (usize, i32)> + '_> {
        match self {
            Self::Fast { page, protection } => Box::new(std::iter::once((*page, *protection))),
            Self::Shared(protections) => Box::new(
                protections
                    .iter()
                    .map(|(&page, &protection)| (page, protection)),
            ),
        }
    }
}

impl PltRemovalRecord {
    fn entries(&self) -> impl Iterator<Item = &PltRemovalEntry> {
        std::iter::once(&self.first).chain(&self.rest)
    }
}

struct PltRemovalEntry {
    write: StoredPointerWrite,
    mapping: MappingSnapshot,
}

impl PltRemovalEntry {
    /// Returns the plaintext write record for transient validation use.
    fn decoded_write(&self) -> StoredPointerWrite {
        StoredPointerWrite {
            image: self.write.image,
            address: crate::sys::decode_usize(self.write.address),
            expected: crate::sys::decode_usize(self.write.expected),
            replacement: crate::sys::decode_usize(self.write.replacement),
        }
    }
}

struct PreparedBatch {
    outcomes: Vec<Option<Result<PltHookHandle>>>,
    scanned: Vec<Option<ScannedHook>>,
    images: Vec<Option<Arc<[FoundImage]>>>,
    rejected: Vec<Vec<RejectedRelocation>>,
    conflicting_slots: Vec<BTreeSet<usize>>,
    plans: Vec<Option<HookPlan>>,
    #[cfg(target_arch = "aarch64")]
    replacement_landings: Option<Vec<SmapInfo>>,
}

#[derive(Clone, Copy)]
struct StoredPointerWrite {
    image: ImageMappingKey,
    address: usize,
    expected: usize,
    replacement: usize,
}

#[derive(Clone, Copy)]
struct WritablePage {
    start: usize,
    map_index: usize,
    original_protection: i32,
}

struct MutationScope {
    writable: Vec<WritablePage>,
    images: usize,
    slots: usize,
    pages: usize,
    page_size: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WritableRange {
    start: usize,
    length: usize,
    map_index: usize,
    original_protection: i32,
}

#[derive(Clone, Copy)]
enum CommitPolicy {
    Independent,
    RollbackAllOnFailure,
}

#[derive(Debug)]
struct RangeChunk {
    hook_index: usize,
    writes: Range<usize>,
    committed: bool,
}

#[derive(Debug)]
struct RangeWork {
    range: WritableRange,
    chunks: Range<usize>,
}

struct MutationPlan {
    ranges: Vec<RangeWork>,
    initially_writable_chunks: Range<usize>,
    chunks: Vec<RangeChunk>,
    writes: Vec<StoredPointerWrite>,
    /// Forced-write descriptor for Validated private file pages, if any.
    ///
    /// `None` keeps the ordinary elevation channel; `Some(fd)` writes every
    /// chunk through `/proc/self/mem` instead, leaving page protections and
    /// VMA layout untouched for the complete transaction.
    forced_fd: Option<usize>,
    /// Failure from attempting to open the forced channel.
    ///
    /// This is retained when the ordinary elevation channel must run as a
    /// fallback, so a later elevation failure can report both paths.
    forced_open_errno: Option<syscalls::Errno>,
    images: usize,
    slots: usize,
    pages: usize,
}

struct CommitState {
    hook_errors: Vec<Option<Error>>,
    failed_hooks: Vec<bool>,
    rollback_hooks: Vec<bool>,
}

impl CommitState {
    fn new(hooks: usize) -> Self {
        Self {
            hook_errors: std::iter::repeat_with(|| None).take(hooks).collect(),
            failed_hooks: vec![false; hooks],
            rollback_hooks: vec![false; hooks],
        }
    }
}

#[derive(Debug)]
struct CommitFailure {
    hook_index: Option<usize>,
    source: Error,
}

impl MutationPlan {
    fn enforce(&self, budget: MutationBudget) -> Result<()> {
        if self.images > budget.max_images
            || self.slots > budget.max_slots
            || self.pages > budget.max_pages
        {
            return Err(Error::MutationBudgetExceeded {
                images: self.images,
                slots: self.slots,
                pages: self.pages,
                max_images: budget.max_images,
                max_slots: budget.max_slots,
                max_pages: budget.max_pages,
            });
        }
        Ok(())
    }
}

#[cfg(target_arch = "aarch64")]
const PROT_BTI: i32 = 0x10;
#[cfg(target_arch = "aarch64")]
const PROT_MTE: i32 = 0x20;

mod inspect;
mod install;
mod mutation;
mod prepare;

pub use crate::conceal::PrivateFileValidation;
pub use inspect::{LoadedImageSnapshot, find_loaded_images, inspect_hooks};
pub use install::{
    install_hook, install_hook_groups, install_hook_groups_with_budget, install_hook_with_budget,
    install_hooks, install_hooks_with_budget,
};
use mutation::*;
use prepare::*;

#[cfg(test)]
pub(crate) mod tests;

//! Transactional PLT/GOT hook installation and explicit removal.

mod arch;
mod conceal;
mod elf;
mod target;

pub use arch::{RelocationKind, RelocationKinds};
pub use conceal::{
    concealed_mutations_supported, restore_concealed_mutations, set_enforce_concealed_mutations,
};
pub use target::Target;

use self::elf::{
    FoundImage, FoundRelocation, ImageId, JumpSlotState, RejectedRelocation, RelocationRejection,
};
use self::target::BoundImage;
use crate::maps::{
    DeviceId, MapInfo, MapPerms, MappingIdentity, find_map_containing, page_ranges,
    read_self_maps_for_ranges, read_self_maps_pathless,
};
#[cfg(target_arch = "aarch64")]
use crate::maps::{SmapInfo, page_ranges_for_sorted_pages, read_self_smaps_for_ranges};
use crate::{Error, HookHandle, Result};
use log::{info, trace};
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
/// Constructing a hook does not inspect an ELF image or mutate memory. The
/// borrowed target and symbol only need to live through the inspection or
/// installation call; the replacement itself has the longer lifetime required
/// by the installer safety contract.
#[must_use = "a Hook only takes effect when passed to an installer"]
#[derive(Clone, Copy, Debug)]
pub struct Hook<'a> {
    target: &'a Target,
    query: SymbolQuery<'a>,
    replacement: usize,
    relocation_kinds: RelocationKinds,
    slot_selector: Option<SlotSelector>,
    expected_slots: Option<NonZeroUsize>,
    unique_match: bool,
    non_null_previous: bool,
    enforce_concealed: bool,
    resolved_ifunc: Option<usize>,
    original_slot: Option<&'a OriginalSlot>,
}

impl<'a> Hook<'a> {
    /// Describes a replacement for every supported relocation named `symbol`
    /// in each currently loaded image selected by `target`.
    ///
    /// This method is safe because it only validates and records addresses.
    /// Pointer validity, ABI compatibility, mapping stability, and lifetime are
    /// checked by the caller when entering [`install_hooks`]'s unsafe contract.
    ///
    /// # Errors
    ///
    /// Returns [`Error::EmptySymbol`] for an empty name or
    /// [`Error::NullReplacement`] for a null replacement.
    pub fn new(target: &'a Target, symbol: &'a CStr, replacement: *const ()) -> Result<Self> {
        Self::new_query(target, SymbolQuery::any_version(symbol)?, replacement)
    }

    /// Describes a replacement selected by a name-and-version query.
    ///
    /// # Errors
    ///
    /// Returns [`Error::NullReplacement`] for a null replacement. Query
    /// constructors validate their borrowed names separately.
    pub fn new_query(
        target: &'a Target,
        query: SymbolQuery<'a>,
        replacement: *const (),
    ) -> Result<Self> {
        if replacement.is_null() {
            return Err(Error::NullReplacement);
        }
        Ok(Self {
            target,
            query,
            replacement: replacement.expose_provenance(),
            relocation_kinds: RelocationKinds::ALL,
            slot_selector: None,
            expected_slots: None,
            unique_match: false,
            non_null_previous: false,
            enforce_concealed: false,
            resolved_ifunc: None,
            original_slot: None,
        })
    }

    /// Requires every selected relocation page to stay concealed.
    ///
    /// Concealment is disabled in this release; installation fails before
    /// target mutation with [`Error::UnsupportedFeature`].
    pub fn enforce_concealed_mutations(mut self) -> Self {
        self.enforce_concealed = true;
        self
    }

    /// Restricts this Hook to the selected semantic relocation kinds.
    ///
    /// The default is [`RelocationKinds::ALL`]. Narrowing the set can exclude
    /// valid call paths, such as `-fno-plt` calls through global-data
    /// relocations, so the caller must choose it deliberately.
    pub fn with_relocation_kinds(mut self, kinds: RelocationKinds) -> Self {
        self.relocation_kinds = kinds;
        self
    }

    /// Requires this Hook's Target to be bound to one exact loaded image.
    ///
    /// This is a fail-closed assertion over the existing Target binding; it
    /// does not create another image identity or extend the binding lifetime.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ExactImageRequired`] for an unbound source selector.
    pub fn require_exact_image(self) -> Result<Self> {
        if self.target.bound_image().is_none() {
            return Err(Error::ExactImageRequired);
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

    /// Requires a present Hook to select one loaded image and one relocation.
    ///
    /// Candidate absence remains [`Error::TargetNotLoaded`] or
    /// [`Error::SymbolNotFound`]. A present ambiguous target or relocation
    /// fails closed before original publication or page protection changes.
    pub fn require_unique_match(mut self) -> Self {
        self.unique_match = true;
        self
    }

    /// Requires this Hook to target one exact loaded image and one relocation.
    ///
    /// This is the strict single-slot shorthand for [`Hook::require_exact_image`]
    /// followed by [`Hook::require_unique_match`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::ExactImageRequired`] for an unbound source selector.
    pub fn require_exactly_one_slot(self) -> Result<Self> {
        Ok(self.require_exact_image()?.require_unique_match())
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

    /// Restricts this Hook to one opaque slot returned by an inspection.
    ///
    /// Installation still performs a fresh maps and ELF scan and verifies the
    /// selector's exact image, relocation metadata, and inspected stored value.
    /// The selector is a point-in-time process-local constraint, not a
    /// persistent image generation identity.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ExactImageRequired`] for an unbound Target or
    /// [`Error::SlotSelectorMismatch`] when the selector names another image.
    pub fn with_slot_selector(mut self, selector: SlotSelector) -> Result<Self> {
        let bound = self.target.bound_image().ok_or(Error::ExactImageRequired)?;
        if selector.image.device != self.target.device()
            || selector.image.inode != self.target.inode()
            || selector.image.elf_header_offset != self.target.elf_header_offset()
            || selector.archive_member_size != self.target.archive_member_size()
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

    /// Makes the accepted original available through `slot` before the first
    /// page-permission change or relocation write.
    ///
    /// The value may have been supplied by [`OriginalSlot::from_expected`] or
    /// resolved by preflight. It does not mean the Hook remains installed.
    /// Publication is intentionally not undone if this or a later Hook is
    /// rolled back.
    pub fn with_original_slot(mut self, slot: &'a OriginalSlot) -> Self {
        self.original_slot = Some(slot);
        self
    }
}

/// One-time cell for an expected or installer-resolved original pointer.
///
/// Multiple Hooks may share a cell only when every present installable Hook
/// resolves the same value. The value can outlive a failed or rolled-back
/// installation and therefore must not be used as an installation-state flag.
/// An installer-resolved PAC-PLT original is stored only after verification and
/// without its PAC.
#[derive(Debug, Default)]
pub struct OriginalSlot {
    value: OnceLock<usize>,
}

/// How an installed Hook's relocation pages were published.
///
/// Reports how an installed Hook's relocation pages were published. Requests
/// for new concealment fail before mutation in this release.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Concealment {
    /// Every selected relocation page was published through a concealed
    /// anonymous copy. This release never returns it.
    Concealed,
    /// At least one selected page was changed in its original mapping; the
    /// value is the first degradation reason.
    InPlace(&'static str),
}

impl OriginalSlot {
    /// Creates an empty original-pointer cell.
    pub const fn new() -> Self {
        Self {
            value: OnceLock::new(),
        }
    }

    /// Creates a cell pre-populated with the only acceptable original pointer.
    ///
    /// Passing this cell through [`Hook::with_original_slot`] makes a mismatch
    /// fail during preflight with [`Error::OriginalSlotConflict`] while also
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
    /// Hook is installed or that the pointer remains callable or dereferenceable.
    pub fn get(&self) -> Option<*const ()> {
        self.value
            .get()
            .copied()
            .map(std::ptr::with_exposed_provenance)
    }
}

/// Installed PLT/GOT hook and its caller-owned removal ledger.
///
/// Dropping this value does not remove the hook. Before calling
/// [`HookHandle::unhook`], the caller must quiesce every selected relocation
/// page and drain replacement/original calls, while preserving all mapping,
/// ABI, lifetime, writer-exclusion, and non-reentrancy guarantees required by
/// installation. Selected images must not be unloaded, remapped, or
/// reprotected while this handle is installed; a fresh maps check cannot rule
/// out same-address ABA replacement.
///
/// For PAC-PLT slots, every thread which can execute the selected PLT entry
/// must keep the same IA key used by the installer. PAC key reset, debugger or
/// ptrace key replacement, and any other key change remain forbidden until the
/// hook is removed and all affected calls have drained.
#[must_use = "the previous pointer must usually be published to the replacement"]
#[non_exhaustive]
pub struct AppliedHook {
    previous: usize,
    /// Non-zero number of selected slots changed across loaded images.
    pub slots: NonZeroUsize,
    /// How this Hook's relocation pages were published.
    pub concealment: Concealment,
    ledger: Option<PltLedger>,
}

// The handle is meant to be installed once and removed later, which requires
// storing it or moving it between threads. Keeping the previous slot value as
// an exposed address rather than a raw pointer field is what keeps that legal.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<AppliedHook>();
};

impl AppliedHook {
    /// Unique untyped relocation result held by every selected slot before
    /// installation. A PAC-PLT value is verified and returned without its PAC.
    ///
    /// This value may be null. Converting it to a function pointer, calling it,
    /// or dereferencing it remains unsafe and requires the caller to prove the
    /// correct ABI, provenance, and loaded-image lifetime.
    pub fn previous(&self) -> *const () {
        std::ptr::with_exposed_provenance(crate::sys::decode_usize(self.previous))
    }

    /// Returns how this Hook's relocation pages were published.
    pub const fn concealment(&self) -> Concealment {
        self.concealment
    }
}

impl fmt::Debug for AppliedHook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppliedHook")
            .field("previous", &"[redacted]")
            .field("slots", &self.slots)
            .field("concealment", &self.concealment)
            .finish()
    }
}

impl HookHandle for AppliedHook {
    fn original(&self) -> Option<*const ()> {
        self.ledger.is_some().then(|| self.previous())
    }

    fn is_installed(&self) -> bool {
        self.ledger.is_some()
    }

    unsafe fn unhook(&mut self) -> Result<()> {
        // SAFETY: forwarded from this method's complete public contract; a
        // one-element batch has exactly the same requirements.
        unsafe { unhook_hooks(std::slice::from_mut(self)) }
    }
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
/// Returns the first ledger-validation or mutation failure. Every pointer this
/// call wrote is rolled back before the error is returned and no handle is
/// cleared, so the complete batch stays retryable.
///
/// # Safety
///
/// The complete removal contract of [`HookHandle::unhook`] applies to every
/// handle in `hooks` at once: all affected relocation pages must be quiesced
/// and every replacement and original call drained before entry.
pub unsafe fn unhook_hooks(hooks: &mut [AppliedHook]) -> Result<()> {
    let installed = hooks.iter().filter(|hook| hook.ledger.is_some()).count();
    if installed == 0 {
        trace!("PLT unhook skipped: state=removed");
        return Ok(());
    }
    info!("PLT unhook requested: hooks={installed}");

    // Canonicalize complete-stack removal before taking the process lock. A
    // newer install id must be removed first; already-removed handles sort
    // after installed handles and are ignored by mutation planning.
    let mut plan_order = (0..hooks.len()).collect::<Vec<_>>();
    plan_order.sort_unstable_by(|&left, &right| {
        hooks[right]
            .ledger
            .as_ref()
            .map(|ledger| ledger.id)
            .cmp(&hooks[left].ledger.as_ref().map(|ledger| ledger.id))
    });

    // Keep output collections outside the guard's declaration; every error
    // path below releases the guard before the remaining scratch is dropped.
    let mut removals: Vec<(usize, usize, usize)> = Vec::new();
    let mut removed_ledgers: Vec<PltLedger> = Vec::with_capacity(installed);
    let _guard = crate::sys::recover_lock(crate::sys::PROCESS_LOCK.write());
    let ranges = match page_ranges(
        hooks
            .iter()
            .filter_map(|hook| hook.ledger.as_ref())
            .flat_map(|ledger| ledger.entries().map(|entry| entry.decoded_write().address)),
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

    // One shared saved-protection view. Two handles covering the same page must
    // agree on what that page was before installation; disagreement means the
    // mapping changed underneath them.
    let mut protections = BTreeMap::new();
    let mut plans = Vec::with_capacity(hooks.len());
    for &index in &plan_order {
        let hook = &hooks[index];
        let Some(ledger) = hook.ledger.as_ref() else {
            plans.push(None);
            continue;
        };
        if let Err(error) = validate_plt_ledger(ledger, &maps) {
            drop(_guard);
            return Err(error);
        }
        for entry in ledger.entries() {
            let write = entry.decoded_write();
            removals.push((ledger.id, write.address, write.replacement));
        }
        for (&start, &protection) in ledger.protections.iter() {
            if protections
                .insert(start, protection)
                .is_some_and(|previous| previous != protection)
            {
                drop(_guard);
                return Err(Error::MappingChanged);
            }
        }
        plans.push(Some(HookPlan {
            previous: crate::sys::decode_usize(hook.previous),
            slots: hook.slots,
            writes: ledger
                .entries()
                .map(|entry| {
                    let write = entry.decoded_write();
                    PointerWrite {
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
    let mut mutation = match mutation_plan(&maps, &plans, scope) {
        Ok(mutation) => mutation,
        Err(error) => {
            drop(_guard);
            return Err(error);
        }
    };
    let mut state = CommitState::new(plans.len());
    // SAFETY: the caller preserves the installed mappings and excludes every
    // competing reader/writer required by the public handle contract.
    if let Err(failure) =
        unsafe { commit_mutation(&mut mutation, &mut state, CommitPolicy::Atomic) }
    {
        drop(_guard);
        return Err(failure.source);
    }
    complete_removal(&removals);
    for hook in hooks.iter_mut() {
        if let Some(ledger) = hook.ledger.take() {
            removed_ledgers.push(ledger);
        }
    }
    if let Err(error) = conceal::after_removal(&removals) {
        drop(_guard);
        return Err(error);
    }
    drop(_guard);
    info!("PLT unhook complete: hooks={installed}");
    Ok(())
}

/// Per-hook results returned by [`install_hooks`].
///
/// The vector always has the same length and order as the input slice. An inner
/// error means that input Hook left no installed slot; independent Hooks may
/// still have succeeded. Prefer [`install_hook`] for one Hook so its Hook-level
/// error is returned directly.
pub type InstallReport = Vec<Result<AppliedHook>>;

/// Hard operation-wide limits for the final selected mutation.
///
/// Limits are checked after Hook selection and conflict preflight but before
/// publishing originals or changing page permissions. Exceeding a limit
/// rejects the complete operation; the installer never trims a plan to fit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MutationBudget {
    /// Maximum loaded images containing at least one selected slot.
    pub max_images: usize,
    /// Maximum unique selected relocation slots.
    pub max_slots: usize,
    /// Maximum unique pages containing selected slots, including pages which
    /// were already writable.
    pub max_pages: usize,
}

/// Read-only preflight status for one inspected relocation slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InspectionStatus {
    /// The complete inspected batch could install this slot.
    Eligible,
    /// Another input Hook selected the same slot, the slot already holds the
    /// requested replacement, or a reused selector no longer matches its
    /// inspected stored value.
    Conflict,
    /// The slot still points at a lazy-binding resolver.
    UnresolvedLazy,
    /// The slot is an ambiguous GNU IFUNC without a matching supplied hint.
    AmbiguousIfunc,
    /// Slots selected by this Hook do not share one previous pointer.
    AmbiguousPreviousPointer,
    /// A shared [`OriginalSlot`] disagrees with this Hook's original pointer.
    OriginalSlotConflict,
    /// The stored AArch64 PAC-PLT value failed PAC verification.
    Aarch64PacPlt,
    /// The relocation requires reading an implicit addend from its slot.
    ImplicitAddend,
    /// The x86-64 slot carries a non-zero explicit relocation addend, which
    /// the installer refuses instead of writing a replacement without it.
    UnsupportedAddend,
    /// Another hook-level preflight error rejects this slot.
    Rejected,
}

/// Opaque process-local selector for one inspected relocation slot.
///
/// A selector cannot authorize an arbitrary address write. The installer
/// accepts it only after a fresh ELF scan finds the same exact image,
/// relocation address, semantic kind, addend, and literal stored slot value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlotSelector {
    image: ImageId,
    archive_member_size: Option<u64>,
    address: usize,
    kind: crate::RelocationKind,
    current: usize,
    addend: Option<i64>,
}

impl SlotSelector {
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
/// write it directly; pass [`SlotInspection::selector`] back to an installer so
/// the image, relocation metadata, and stored value are validated again.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlotInspection {
    /// Runtime address of the relocation slot at inspection time.
    pub address: *mut (),
    /// Supported semantic relocation kind.
    pub kind: crate::RelocationKind,
    /// Current literal value stored in the slot. A valid PAC-PLT slot may hold
    /// a signed value rather than the verified raw pointer.
    pub current: *const (),
    /// Explicit or loader-defined relocation addend, or `None` when the
    /// rejected relocation requires an implicit addend.
    pub addend: Option<i64>,
    /// RWX permissions visible in `/proc/self/maps`.
    pub permissions: MapPerms,
    /// Result of applying the complete batch preflight to this slot.
    pub status: InspectionStatus,
    selector: SlotSelector,
}

impl SlotInspection {
    /// Returns the opaque selector for this inspected relocation.
    pub const fn selector(&self) -> SlotSelector {
        self.selector
    }
}

/// Per-image relocation facts for one input Hook.
#[derive(Debug)]
pub struct ImageInspection {
    /// Exact loaded image that was inspected.
    pub image: LoadedImage,
    /// Matching supported and explicitly rejected relocation slots in address
    /// order.
    pub slots: Vec<SlotInspection>,
}

/// Read-only preflight result for one input Hook.
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
    /// Every loaded image selected by this Hook's Target, including images with
    /// no matching relocation.
    pub fn images(&self) -> &[ImageInspection] {
        &self.images
    }

    /// Consumes this inspection and returns its per-image results.
    pub fn into_images(self) -> Vec<ImageInspection> {
        self.images
    }

    /// Unique original relocation result when the complete Hook is
    /// installable. A PAC-PLT result is verified and returned without its PAC.
    pub const fn previous(&self) -> Option<*const ()> {
        self.previous
    }

    /// Hook-level absence or rejection reason, if any.
    pub const fn error(&self) -> Option<&Error> {
        self.error.as_ref()
    }

    /// Consumes this inspection and returns its only eligible exact slot.
    ///
    /// Hook-level preflight errors are returned first. The remaining report must
    /// contain exactly one eligible relocation across all loaded images, and
    /// its verified previous pointer must be non-null. Installation must still
    /// use the returned selector and repeat strict checks against its fresh
    /// snapshot.
    ///
    /// # Errors
    ///
    /// Returns the stored Hook-level error, [`Error::UnexpectedSlotCount`] when
    /// the eligible slot count is not one, or [`Error::NullPreviousPointer`] when
    /// the unique verified previous pointer is null.
    pub fn into_unique_eligible(self) -> Result<(LoadedImage, SlotInspection)> {
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
                .filter(|slot| slot.status == InspectionStatus::Eligible)
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

/// Required/optional policy for one borrowed Hook group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HookGroupKind {
    /// At least one candidate must produce a final installed slot.
    Required,
    /// A group with only absent candidates is accepted.
    Optional,
}

/// A borrowed group of candidate or complementary Hooks installed as one
/// operation-wide rollback unit.
#[derive(Clone, Copy, Debug)]
pub struct HookGroup<'hooks, 'hook> {
    hooks: &'hooks [Hook<'hook>],
    kind: HookGroupKind,
}

impl<'hooks, 'hook> HookGroup<'hooks, 'hook> {
    /// Creates a group which requires at least one present installable Hook.
    pub const fn required(hooks: &'hooks [Hook<'hook>]) -> Self {
        Self {
            hooks,
            kind: HookGroupKind::Required,
        }
    }

    /// Creates a group which may have no present Hook.
    ///
    /// An empty slice is a valid no-op and produces an aligned empty report.
    pub const fn optional(hooks: &'hooks [Hook<'hook>]) -> Self {
        Self {
            hooks,
            kind: HookGroupKind::Optional,
        }
    }

    /// Borrowed Hooks in this group.
    pub const fn hooks(self) -> &'hooks [Hook<'hook>] {
        self.hooks
    }

    /// Required/optional policy for this group.
    pub const fn kind(self) -> HookGroupKind {
        self.kind
    }
}

/// Per-group, per-Hook results from [`install_hook_groups`].
pub type GroupInstallReport = Vec<InstallReport>;

/// Indexed failure from a group installation with operation-wide rollback.
#[derive(Debug)]
pub struct GroupInstallError {
    /// Group index for a group policy or Hook-specific failure.
    pub group: Option<usize>,
    /// Hook index within [`GroupInstallError::group`], when applicable.
    pub hook: Option<usize>,
    /// Underlying Hook or operation error.
    pub source: Error,
}

impl fmt::Display for GroupInstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match (self.group, self.hook) {
            (Some(group), Some(hook)) => {
                write!(f, "hook group {group}, hook {hook}: {}", self.source)
            }
            (Some(group), None) => write!(f, "hook group {group}: {}", self.source),
            (None, Some(hook)) => write!(f, "hook {hook}: {}", self.source),
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
    writes: Vec<PointerWrite>,
}

struct PltLedger {
    id: usize,
    target: Target,
    images: Arc<[FoundImage]>,
    first: PltLedgerEntry,
    rest: Vec<PltLedgerEntry>,
    protections: Arc<BTreeMap<usize, i32>>,
}

impl PltLedger {
    fn entries(&self) -> impl Iterator<Item = &PltLedgerEntry> {
        std::iter::once(&self.first).chain(&self.rest)
    }
}

struct PltLedgerEntry {
    write: PointerWrite,
    mapping: MappingIdentity,
}

impl PltLedgerEntry {
    /// Returns the plaintext write record for transient validation use.
    fn decoded_write(&self) -> PointerWrite {
        PointerWrite {
            image: self.write.image,
            address: crate::sys::decode_usize(self.write.address),
            expected: crate::sys::decode_usize(self.write.expected),
            replacement: crate::sys::decode_usize(self.write.replacement),
        }
    }
}

struct PreparedBatch {
    outcomes: Vec<Option<Result<AppliedHook>>>,
    scanned: Vec<Option<ScannedHook>>,
    images: Vec<Option<Arc<[FoundImage]>>>,
    rejected: Vec<Vec<RejectedRelocation>>,
    conflicting_slots: Vec<BTreeSet<usize>>,
    plans: Vec<Option<HookPlan>>,
}

#[derive(Clone, Copy)]
struct PointerWrite {
    image: ImageId,
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
    Atomic,
}

#[derive(Debug)]
struct RangeChunk {
    hook: usize,
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
    writes: Vec<PointerWrite>,
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
    hook: Option<usize>,
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

pub use inspect::{LoadedImage, find_loaded_images, inspect_hooks};
pub use install::{
    install_hook, install_hook_groups, install_hook_groups_with_budget, install_hook_with_budget,
    install_hooks, install_hooks_with_budget,
};
use mutation::*;
use prepare::*;

#[cfg(test)]
mod tests;

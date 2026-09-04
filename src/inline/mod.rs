//! Inline hook installation and removal.

mod arena;
mod patch;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "arm")]
mod arm;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
mod x86;

#[cfg(target_arch = "aarch64")]
use aarch64 as arch;
#[cfg(target_arch = "arm")]
use arm as arch;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use x86 as arch;

#[cfg(not(target_arch = "arm"))]
use crate::maps::page_ranges;
use crate::maps::{MapInfo, read_self_maps_for_ranges, read_self_maps_pathless};
use crate::{Error, HookHandle, Result};
use arena::Arena;
use log::{debug, error, info, trace, warn};
use patch::CodePage;
use std::io;
use std::ops::{Deref, DerefMut};
use std::sync::Mutex;

/// Entry addresses of inline targets installed in this process.
///
/// Guarded by this mutex; mutations additionally hold `PROCESS_LOCK` for
/// writing. Entries appear after a successful commit and disappear once the
/// target bytes are restored, so a target cannot be chained through a second
/// hook with an independent handle. A dropped handle keeps its entry because
/// its hook remains installed. Every stored address is obfuscated so the
/// registry does not expose a plaintext list of hooked entries.
// ponytail: linear install-time scans keep post-mutation insert/remove
// allocator-free; use an allocation-free index only if hook counts prove large.
static ACTIVE_INLINE_TARGETS: Mutex<Vec<usize>> = Mutex::new(Vec::new());

fn inline_targets_installed(targets: &[usize]) -> bool {
    let installed = crate::sys::recover_lock(ACTIVE_INLINE_TARGETS.lock());
    targets
        .iter()
        .any(|target| installed.contains(&crate::sys::encode_usize(*target)))
}

fn register_inline_targets(targets: &[usize]) {
    let mut installed = crate::sys::recover_lock(ACTIVE_INLINE_TARGETS.lock());
    if installed.capacity().saturating_sub(installed.len()) < targets.len() {
        crate::sys::fail_stop();
    }
    for target in targets {
        installed.push(crate::sys::encode_usize(*target));
    }
}

fn unregister_inline_targets(targets: &[usize]) {
    let mut installed = crate::sys::recover_lock(ACTIVE_INLINE_TARGETS.lock());
    for target in targets {
        let encoded = crate::sys::encode_usize(*target);
        if let Some(index) = installed.iter().position(|candidate| *candidate == encoded) {
            installed.swap_remove(index);
        }
    }
}

fn reserve_inline_targets(additional: usize) {
    let mut installed = crate::sys::recover_lock(ACTIVE_INLINE_TARGETS.lock());
    installed.reserve(additional);
}

/// Closes the forced-access descriptor, reporting a leak instead of
/// terminating.
///
/// Preparation never changes a target byte, so a descriptor this process can no
/// longer reclaim is a resource failure the caller can act on. Nothing is
/// logged here: every caller holds the process lock, and this crate emits no
/// record through the caller's logger while an internal guard is held.
#[must_use = "a leaked forced-access descriptor must reach the caller"]
fn close_preparation_mem(mem: &mut Option<usize>) -> Option<i32> {
    if let Some(fd) = mem.take() {
        return crate::sys::close_self_mem(fd);
    }
    None
}

/// Combines an operation's error with the error from cleaning up after it,
/// keeping whichever the caller has to act on first.
fn preferred_error(source: Error, cleanup: Result<()>) -> Error {
    match cleanup {
        Err(cleanup) => Error::InlineCleanupComposite {
            source: Box::new(source),
            cleanup: Box::new(cleanup),
        },
        Ok(()) => source,
    }
}

/// Owns a transient byte buffer and scrubs it on every drop path.
///
/// Growth is performed manually so the old allocation is erased before it is
/// released. The wrapper dereferences to a byte slice, not to `Vec<u8>`, so a
/// caller cannot bypass that rule with an untracked capacity-changing method.
pub(super) struct TransientBytes(Vec<u8>);

impl TransientBytes {
    pub(super) fn len(&self) -> usize {
        self.0.len()
    }

    pub(super) fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.grow_for(bytes.len());
        self.0.extend_from_slice(bytes);
    }

    pub(super) fn resize(&mut self, length: usize, value: u8) {
        if length > self.0.len() {
            self.grow_for(length - self.0.len());
        }
        self.0.resize(length, value);
    }

    fn grow_for(&mut self, additional: usize) {
        let required = self
            .0
            .len()
            .checked_add(additional)
            .unwrap_or_else(|| crate::sys::fail_stop());
        if required <= self.0.capacity() {
            return;
        }

        let doubled = self.0.capacity().max(1).checked_mul(2).unwrap_or(required);
        let mut next = Vec::with_capacity(doubled.max(required));
        // SAFETY: `next` has capacity for the initialized prefix, and the
        // source and destination allocations do not overlap.
        unsafe {
            std::ptr::copy_nonoverlapping(self.0.as_ptr(), next.as_mut_ptr(), self.0.len());
            next.set_len(self.0.len());
        }
        crate::sys::erase_bytes(&mut self.0);
        self.0 = next;
    }

    pub(super) fn into_vec(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

impl From<Vec<u8>> for TransientBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl Deref for TransientBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for TransientBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Drop for TransientBytes {
    fn drop(&mut self) {
        crate::sys::erase_bytes(&mut self.0);
    }
}

pub(super) struct Generated {
    bytes: Vec<u8>,
    patch: Vec<u8>,
    original: usize,
    auxiliary: Option<Arena>,
}

impl Drop for Generated {
    fn drop(&mut self) {
        crate::sys::erase_bytes(&mut self.bytes);
        crate::sys::erase_bytes(&mut self.patch);
    }
}

/// One inline target and replacement pair for [`install_inline_hooks`].
#[derive(Clone, Copy)]
pub struct InlineHook {
    target: *const (),
    replacement: *const (),
}

impl InlineHook {
    /// Creates one inline hook request without validating either pointer.
    ///
    /// Null pointers, executable mappings, ABI compatibility, and instruction
    /// relocatability are checked or remain the caller's responsibility when
    /// the request is passed to [`install_inline_hooks`].
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use omhook::InlineHook;
    ///
    /// extern "C" fn target(value: i32) -> i32 {
    ///     value + 1
    /// }
    ///
    /// extern "C" fn replacement(value: i32) -> i32 {
    ///     value + 2
    /// }
    ///
    /// fn main() {
    ///     let _request = InlineHook::new(target as *const (), replacement as *const ());
    /// }
    /// ```
    pub const fn new(target: *const (), replacement: *const ()) -> Self {
        Self {
            target,
            replacement,
        }
    }
}

enum InlineState {
    Active(Vec<Arena>),
    CleanupPending(Vec<Arena>),
    Removed,
}

/// Maps a failed arena release onto the crate's cleanup-pending error.
///
/// Every caller reaches this with the target in a correct state: either it was
/// restored, or it was never written. What leaked is an unpublished executable
/// mapping, which is a resource failure the caller can report or retry, not a
/// reason to take the host process down.
pub(super) fn cleanup_pending(error: Error) -> Error {
    match error {
        Error::SystemCall { source, .. } => Error::InlineCleanupPending(source),
        other => other,
    }
}

unsafe fn unmap_arenas(arenas: Vec<Arena>) -> std::result::Result<(), (Error, Vec<Arena>)> {
    let mut first_error = None;
    let mut pending = Vec::new();
    let Some(&first) = arenas.first() else {
        return Ok(());
    };

    // A batch arena is split into per-hook pages for independent ownership,
    // but releasing a complete batch can coalesce those neighbors again.
    let mut merged = first;
    let mut group_start = 0;
    for index in 1..=arenas.len() {
        let next = arenas.get(index).copied();
        if let Some(combined) = next.and_then(|next| merged.coalesce_with(next)) {
            merged = combined;
            continue;
        }
        // SAFETY: callers ensure that no generated entry remains reachable.
        if let Err(error) = unsafe { merged.unmap() } {
            first_error.get_or_insert(error);
            pending.extend_from_slice(&arenas[group_start..index]);
        }
        if let Some(next) = next {
            merged = next;
            group_start = index;
        }
    }
    match first_error {
        Some(error) => Err((error, pending)),
        None => Ok(()),
    }
}

/// Installed inline hook and its caller-owned removal ledger.
///
/// Dropping this value leaves the hook and its executable arenas installed.
/// Use [`HookHandle::unhook`] after quiescing every thread that could execute
/// the target, replacement, or trampoline.
#[must_use = "dropping the handle does not remove the inline hook"]
pub struct AppliedInlineHook {
    target_address: usize,
    patch_address: usize,
    original_bytes: Vec<u8>,
    patch_bytes: Vec<u8>,
    trampoline: usize,
    pages: Vec<CodePage>,
    state: InlineState,
    mutation_path: MutationPath,
    sync_core: bool,
}

/// How an inline mutation reached its target's bytes.
///
/// The default path writes through `/proc/self/mem`, leaving every target page
/// executable. The caller's quiescence proof is therefore always required;
/// there is no non-executable window that turns a violation into a fault.
///
/// If that descriptor is unavailable, the fallback temporarily drops
/// `PROT_EXEC`. Inspect [`AppliedInlineHook::mutation_path`] to learn which
/// path ran.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MutationPath {
    /// Page protection was changed for the write; target pages were not
    /// executable while their bytes changed.
    Protection,
    /// Bytes were written through `/proc/self/mem`; target pages stayed
    /// executable for the complete write. This is the preferred path on
    /// Android, where an SELinux policy may refuse `execmod` after a page has
    /// been written.
    ForcedAccess,
}

struct PreparedInlineHook {
    target_address: usize,
    patch_address: usize,
    original_bytes: Vec<u8>,
    patch_bytes: Vec<u8>,
    trampoline: usize,
    pages: Vec<CodePage>,
    arenas: Vec<Arena>,
}

/// Transient plaintext view of one installed inline hook.
///
/// Dropping a view erases its decoded byte buffers, so no exit path can leak
/// a plaintext copy of the stored material.
struct DecodedInlineHook {
    target_address: usize,
    patch_address: usize,
    original_bytes: Vec<u8>,
    patch_bytes: Vec<u8>,
}

impl DecodedInlineHook {
    fn decode(hook: &AppliedInlineHook) -> Self {
        Self {
            target_address: crate::sys::decode_usize(hook.target_address),
            patch_address: crate::sys::decode_usize(hook.patch_address),
            original_bytes: crate::sys::decode_bytes(&hook.original_bytes),
            patch_bytes: crate::sys::decode_bytes(&hook.patch_bytes),
        }
    }
}

impl Drop for DecodedInlineHook {
    fn drop(&mut self) {
        crate::sys::erase_bytes(&mut self.original_bytes);
        crate::sys::erase_bytes(&mut self.patch_bytes);
    }
}

/// Owns the replacement array while its borrowed entries are used under the
/// process write lock. The allocation is deliberately reclaimed by `Drop`
/// only after that lock is released; `Replacement` is a `Copy` record with no
/// element drop glue, so deallocation is sufficient here.
struct RawReplacementStorage {
    pointer: *mut u8,
    length: usize,
    capacity: usize,
}

impl RawReplacementStorage {
    fn from_vec(mut replacements: Vec<patch::Replacement<'_>>) -> Self {
        let storage = Self {
            pointer: replacements.as_mut_ptr().cast(),
            length: replacements.len(),
            capacity: replacements.capacity(),
        };
        std::mem::forget(replacements);
        storage
    }
}

impl Drop for RawReplacementStorage {
    fn drop(&mut self) {
        if self.capacity == 0 {
            return;
        }
        let layout = std::alloc::Layout::array::<patch::Replacement<'static>>(self.capacity)
            .unwrap_or_else(|_| crate::sys::fail_stop());
        // SAFETY: `pointer` and `capacity` came from the same Vec allocation;
        // `Replacement` has no drop glue, so only the allocation is reclaimed.
        unsafe { std::alloc::dealloc(self.pointer, layout) };
    }
}

/// Unpublished inline hooks prepared under a caller lifecycle read lease.
///
/// Preparation allocates and seals executable trampolines but does not change
/// target bytes. The value borrows the [`crate::LifecycleReadLease`] used to
/// create it, so the caller cannot release that lease before committing or
/// explicitly discarding the prepared arenas.
///
/// Dropping this value intentionally leaves its unpublished arenas mapped.
/// Call [`PreparedInlineHooks::commit`] or [`PreparedInlineHooks::discard`].
#[must_use = "prepared inline hooks must be committed or explicitly discarded"]
pub struct PreparedInlineHooks<'lease> {
    hooks: Option<Vec<AppliedInlineHook>>,
    lease: &'lease crate::LeaseToken,
    /// Fresh maps for a one-shot install that never exposed its prepare phase.
    ///
    /// Two-phase commits keep this empty and perform a fresh final validation.
    validation_maps: Option<Vec<MapInfo>>,
}

/// Installed inline handles together with their post-commit completion state.
#[must_use = "check the installation completion before ignoring cleanup errors"]
pub struct InlineInstallOutcome<T> {
    installed: T,
    completion: InlineInstallCompletion,
}

/// Cleanup status of a successfully published inline mutation.
#[non_exhaustive]
pub enum InlineInstallCompletion {
    /// Every mutation and cleanup step completed.
    Complete,
    /// The mutation is live, but its forced descriptor failed to close.
    ///
    /// Linux may have released the descriptor anyway; do not retry the close.
    ForcedDescriptorCloseFailed(io::Error),
}

impl<T> InlineInstallOutcome<T> {
    /// Returns the installed handle or batch.
    pub const fn installed(&self) -> &T {
        &self.installed
    }

    /// Returns the post-commit cleanup state.
    pub const fn completion(&self) -> &InlineInstallCompletion {
        &self.completion
    }

    /// Splits the installed value from its cleanup state.
    pub fn into_parts(self) -> (T, InlineInstallCompletion) {
        (self.installed, self.completion)
    }
}

impl<'lease> PreparedInlineHooks<'lease> {
    /// Number of prepared hooks.
    pub fn len(&self) -> usize {
        self.hooks.as_ref().map_or(0, Vec::len)
    }

    /// Returns whether this prepared batch is empty.
    pub fn is_empty(&self) -> bool {
        self.hooks.as_ref().is_none_or(Vec::is_empty)
    }

    /// Returns one prepared original trampoline.
    ///
    /// Calling or publishing this pointer requires the same ABI, mapping,
    /// lifecycle, and quiescence proof as [`HookHandle::original`]. It remains
    /// valid while this prepared batch is retained, after a successful commit
    /// until removal, or until this prepared batch is explicitly discarded.
    pub fn trampoline(&self, index: usize) -> Option<*const ()> {
        self.hooks.as_ref()?.get(index).map(|hook| {
            std::ptr::with_exposed_provenance(crate::sys::decode_usize(hook.trampoline))
        })
    }

    /// Serializes and commits the prepared target-byte transaction.
    ///
    /// A failure returns [`InlineCommitError`] containing the complete prepared
    /// batch, so the caller can correct the external condition and retry or
    /// explicitly discard it. Success transfers every arena to the returned
    /// installed handles.
    ///
    /// # Safety
    ///
    /// From preparation through this call, the caller must preserve the full
    /// mapping, loader, ABI, writer-exclusion, quiescence, and non-reentrancy
    /// contract of [`install_inline_hooks`]. A successful commit does not pin
    /// the lease in the returned handles; keep the lease, loader handle, and
    /// image generation alive until successful unhook and call drainage.
    pub unsafe fn commit(
        self,
    ) -> std::result::Result<InlineInstallOutcome<Vec<AppliedInlineHook>>, InlineCommitError<'lease>>
    {
        // SAFETY: forwarded from this method's complete public contract.
        unsafe { commit_prepared_inline_hooks(self, false) }
    }

    /// Releases every unpublished executable arena without changing a target.
    ///
    /// # Safety
    ///
    /// Every call through a pointer returned by [`PreparedInlineHooks::trampoline`]
    /// must first be revoked or otherwise prevented from being entered again, and
    /// then drained. The caller must preserve the prepared mappings and exclude
    /// re-entry for the complete cleanup. This is required because the pointer can
    /// have been published as a raw function pointer and `discard` unmaps its
    /// executable arenas.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InlineCleanupPending`] when an executable arena could
    /// not be unmapped. No target was changed and this call consumed the only
    /// ownership ledger, so the mapping stays live for the rest of the process;
    /// the error reports that leak rather than hiding it.
    pub unsafe fn discard(self) -> Result<()> {
        let PreparedInlineHooks {
            hooks,
            validation_maps,
            lease: _,
        } = self;
        // SAFETY: forwarded from this method's complete public contract.
        let discarded = unsafe { discard_prepared_inline_hooks(hooks) };
        drop(validation_maps);
        discarded
    }
}

/// Failed inline commit together with its retryable prepared ownership.
///
/// Dropping this error intentionally keeps the executable arenas mapped. Use
/// [`InlineCommitError::into_parts`] and then [`PreparedInlineHooks::discard`]
/// after revoking any published trampoline pointers and draining their calls.
#[must_use = "the prepared inline batch must be retried or explicitly discarded"]
pub struct InlineCommitError<'lease> {
    source: Error,
    prepared: PreparedInlineHooks<'lease>,
}

impl<'lease> InlineCommitError<'lease> {
    /// Commit failure reported after complete byte rollback.
    pub const fn error(&self) -> &Error {
        &self.source
    }

    /// Splits the failure from the retryable prepared batch.
    pub fn into_parts(self) -> (Error, PreparedInlineHooks<'lease>) {
        (self.source, self.prepared)
    }
}

impl std::fmt::Debug for InlineCommitError<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InlineCommitError")
            .field("source", &self.source)
            .field("hooks", &self.prepared.len())
            .finish()
    }
}

impl std::fmt::Display for InlineCommitError<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.source.fmt(formatter)
    }
}

impl std::error::Error for InlineCommitError<'_> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

struct AnalyzedInlineHook {
    code_address: usize,
    analysis: arch::Analysis,
    replacement: usize,
    pages: Vec<CodePage>,
    #[cfg(target_arch = "aarch64")]
    guarded: bool,
    #[cfg(target_arch = "aarch64")]
    replacement_guarded: bool,
}

impl AppliedInlineHook {
    /// Reports how the installer reached this target's bytes.
    ///
    /// [`MutationPath::ForcedAccess`] means the target pages stayed executable
    /// for the complete write. Nothing is wrong with the installed hook; the
    /// caller's whole-page quiescence proof was required.
    pub const fn mutation_path(&self) -> MutationPath {
        self.mutation_path
    }

    /// Reports whether cross-core instruction-stream synchronization is
    /// active in this process.
    ///
    /// `false` means the kernel refused the sync-core membarrier, so other
    /// cores are only synchronized by the caller's quiescence contract.
    pub const fn sync_core(&self) -> bool {
        self.sync_core
    }
}

impl HookHandle for AppliedInlineHook {
    fn original(&self) -> Option<*const ()> {
        matches!(self.state, InlineState::Active(_))
            .then(|| std::ptr::with_exposed_provenance(crate::sys::decode_usize(self.trampoline)))
    }

    fn is_installed(&self) -> bool {
        matches!(self.state, InlineState::Active(_))
    }

    unsafe fn unhook(&mut self) -> Result<()> {
        // SAFETY: forwarded from this method's complete public contract.
        unsafe { unhook_inline_hooks(std::slice::from_mut(self)) }
    }
}

/// Returns whether cross-core instruction-stream synchronization is active.
///
/// The first call registers the private expedited sync-core membarrier once.
/// `false` means the kernel refused it, so a caller relying on more than its
/// own quiescence discipline must treat every published instruction change as
/// synchronized only on the writing core.
pub fn instruction_stream_sync_capability() -> bool {
    crate::sys::sync_instruction_stream_ready()
}

fn warn_missing_sync_core_once(sync_core: bool) {
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !sync_core && !WARNED.swap(true, std::sync::atomic::Ordering::AcqRel) {
        log::warn!(
            "cross-core instruction-stream synchronization unavailable; caller quiescence is the only cross-core guarantee"
        );
    }
}

/// Restores an inline hook batch and releases all of its executable arenas.
///
/// Target bytes and mapping identities are validated for the complete active
/// batch before any page is changed. Overlapping target ranges are rejected.
/// If an arena cannot be unmapped after successful restoration, its handle
/// remains retryable in cleanup-only state.
///
/// # Errors
///
/// A failure before target restoration leaves affected handles installed and
/// retryable. [`Error::InlineCleanupPending`] means every target was restored;
/// affected handles then report no installed hook or original trampoline, and
/// retrying this function only releases remaining executable arenas.
///
/// # Safety
///
/// The caller must uphold every handle's mapping, quiescence, lifetime,
/// writer-exclusion, and non-reentrancy contract. All calls through the
/// targets, replacements, and trampolines must have drained before entry.
/// Restoration uses the same mutation paths as installation, so the caller
/// must equally exclude concurrent execution of every complete target page,
/// not only of the patched entries. The default path makes the page
/// non-executable; the forced path keeps it executable but may expose a partial
/// multi-instruction restoration.
pub unsafe fn unhook_inline_hooks(hooks: &mut [AppliedInlineHook]) -> Result<()> {
    let active = hooks
        .iter()
        .filter(|hook| matches!(&hook.state, InlineState::Active(_)))
        .count();
    let arenas = hooks
        .iter()
        .map(|hook| match &hook.state {
            InlineState::Active(arenas) | InlineState::CleanupPending(arenas) => arenas.len(),
            InlineState::Removed => 0,
        })
        .sum::<usize>();
    if arenas == 0 {
        trace!("inline batch unhook skipped: state=removed");
        return Ok(());
    }
    info!("inline batch unhook requested: hooks={active}, arenas={arenas}");

    let _guard = crate::sys::recover_lock(crate::sys::PROCESS_LOCK.write());
    let mut restored_page_starts = hooks
        .iter()
        .filter(|hook| matches!(&hook.state, InlineState::Active(_)))
        .flat_map(|hook| hook.pages.iter().map(|page| page.span().0))
        .collect::<Vec<_>>();
    restored_page_starts.sort_unstable();
    restored_page_starts.dedup();
    let cleanup_ranges = crate::maps::page_ranges_for_sorted_pages(
        restored_page_starts.iter().copied(),
        crate::sys::page_size()?,
    )?;
    let cleanup_maps = read_self_maps_for_ranges(&cleanup_ranges)?;
    // Decode the only persisted byte copies in place. A failed transaction
    // restores their encoded form before returning a retryable batch.
    //
    // Mark the region: between the two toggles the handles hold their bytes in
    // a form only this call knows how to undo, so a panic here must stay fatal
    // rather than let a retry toggle a second time and corrupt them.
    crate::sys::enter_mutation();
    for hook in hooks
        .iter_mut()
        .filter(|hook| matches!(&hook.state, InlineState::Active(_)))
    {
        crate::sys::toggle_bytes_encoding(&mut hook.original_bytes);
        crate::sys::toggle_bytes_encoding(&mut hook.patch_bytes);
    }
    let replacements = hooks
        .iter()
        .filter_map(|hook| match &hook.state {
            InlineState::Active(_) => {
                let patch_address = crate::sys::decode_usize(hook.patch_address);
                Some(patch::Replacement {
                    pages: &hook.pages,
                    address: patch_address,
                    end: patch_address
                        .checked_add(hook.patch_bytes.len())
                        .unwrap_or_else(|| crate::sys::fail_stop()),
                    expected: &hook.patch_bytes,
                    replacement: &hook.original_bytes,
                })
            }
            InlineState::CleanupPending(_) | InlineState::Removed => None,
        })
        .collect::<Vec<_>>();
    // Keep the allocation alive across the mutation lock without retaining a
    // Rust borrow of `hooks`: its owner was declared before the guard, so
    // unwind and normal return both release the guard before deallocation.
    let replacements = RawReplacementStorage::from_vec(replacements);
    let restored_targets: Vec<usize> = hooks
        .iter()
        .filter(|hook| matches!(&hook.state, InlineState::Active(_)))
        .map(|hook| crate::sys::decode_usize(hook.target_address))
        .collect();
    let mut removed_arenas = Vec::with_capacity(hooks.len());
    let mut unmap_arenas_batch = Vec::with_capacity(arenas);
    let mut arena_pending = vec![false; arenas];
    // Reserve every retry buffer before taking PROCESS_LOCK. A failed munmap
    // must not invoke the allocator while an in-crate writer is serialized.
    let mut failed_buffers = hooks
        .iter()
        .map(|hook| match &hook.state {
            InlineState::Active(arenas) | InlineState::CleanupPending(arenas) => {
                Vec::with_capacity(arenas.len())
            }
            InlineState::Removed => Vec::new(),
        })
        .collect::<Vec<_>>();
    // SAFETY: the caller keeps every captured page stable and quiescent and
    // excludes competing writers for the complete batch.
    let mutation_result = unsafe {
        let replacements = std::slice::from_raw_parts(
            replacements.pointer.cast::<patch::Replacement<'_>>(),
            replacements.length,
        );
        patch::replace_many(replacements, Some(&cleanup_maps))
    };
    let descriptor_close_errno = match mutation_result {
        Ok(outcome) => outcome.descriptor_close_errno,
        Err(error) => {
            drop(_guard);
            for hook in hooks
                .iter_mut()
                .filter(|hook| matches!(&hook.state, InlineState::Active(_)))
            {
                crate::sys::toggle_bytes_encoding(&mut hook.original_bytes);
                crate::sys::toggle_bytes_encoding(&mut hook.patch_bytes);
            }
            crate::sys::leave_mutation();
            warn!("inline batch unhook failed: targets_restored=false");
            return Err(error);
        }
    };
    unregister_inline_targets(&restored_targets);

    let mut first_error = None;
    for (index, hook) in hooks.iter_mut().enumerate() {
        let (arenas, restored_target) =
            match std::mem::replace(&mut hook.state, InlineState::Removed) {
                InlineState::Active(arenas) => (arenas, true),
                InlineState::CleanupPending(arenas) => (arenas, false),
                InlineState::Removed => continue,
            };
        if restored_target {
            crate::sys::erase_bytes(&mut hook.original_bytes);
            crate::sys::erase_bytes(&mut hook.patch_bytes);
        }
        unmap_arenas_batch.extend_from_slice(&arenas);
        removed_arenas.push((index, arenas));
    }
    let Some(&first_arena) = unmap_arenas_batch.first() else {
        crate::sys::fail_stop();
    };
    let mut merged = first_arena;
    let mut group_start = 0;
    for index in 1..=unmap_arenas_batch.len() {
        let next = unmap_arenas_batch.get(index).copied();
        if let Some(combined) = next.and_then(|next| merged.coalesce_with(next)) {
            merged = combined;
            continue;
        }
        // SAFETY: no target reaches these arenas and the caller drained every
        // earlier trampoline call.
        if let Err(error) = unsafe { merged.unmap() } {
            first_error.get_or_insert(cleanup_pending(error));
            for pending in &mut arena_pending[group_start..index] {
                *pending = true;
            }
        }
        if let Some(next) = next {
            merged = next;
            group_start = index;
        }
    }
    let mut pending_index = 0;
    for &(hook_index, ref arenas) in &removed_arenas {
        let hook = &mut hooks[hook_index];
        let mut failed = std::mem::take(&mut failed_buffers[hook_index]);
        failed.clear();
        for arena in arenas {
            if arena_pending[pending_index] {
                failed.push(*arena);
            }
            pending_index += 1;
        }
        if !failed.is_empty() {
            hook.state = InlineState::CleanupPending(failed);
        } else {
            failed_buffers[hook_index] = failed;
        }
    }
    // Every decoded byte copy has been consumed or erased, so the region opened
    // before the toggle is closed.
    crate::sys::leave_mutation();
    drop(_guard);
    drop(cleanup_maps);
    if let Some(errno) = descriptor_close_errno {
        let close_error = Error::system_call("close", errno);
        if let Some(error) = first_error {
            return Err(Error::InlineCleanupComposite {
                source: Box::new(close_error),
                cleanup: Box::new(error),
            });
        }
        return Err(close_error);
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Installs one inline hook in the current process.
///
/// The returned handle owns an executable trampoline. Its
/// [`HookHandle::original`] value is callable only while the handle remains
/// installed. Existing x86 ENDBR and AArch64 BTI landing instructions are
/// preserved, and the trampoline has its own landing instruction. An x86-64
/// replacement outside direct branch range is reached through a relay; an
/// ENDBR bridge is mapped only when the relay cannot reach the replacement
/// with a plain jump and the replacement lacks its own ENDBR landing.
///
/// Unsupported instructions are rejected rather than relocated with unknown
/// PC or call/return semantics. The trampoline is not unwind- or
/// backtrace-transparent. ARM PC-relative literals are accepted only from
/// private read-only mappings, whose contents must remain immutable while the
/// hook is installed.
///
/// # Errors
///
/// Returns pointer, mapping, instruction-relocation, arena-allocation, or
/// target-mutation errors. An error leaves no installed inline hook.
/// A target that is already hooked in this process is rejected with
/// [`Error::Conflict`].
///
/// # Page protection
///
/// The default path writes through `/proc/self/mem` and leaves every target
/// page executable; it never depends on restoring `PROT_EXEC` after a write.
/// If that descriptor is unavailable, the fallback temporarily removes
/// executable protection. [`AppliedInlineHook::mutation_path`] reports which
/// path ran. The forced channel cannot publish a multi-instruction entry
/// atomically, so caller quiescence remains the complete guarantee.
///
/// # Safety
///
/// `target` must be a normal callable entry, not an address inside a Thumb IT
/// block. `target` and `replacement` must be live executable entries with
/// compatible calling conventions and lifetimes. Except for calls or tail calls
/// intentionally entering the exact `target` entry, no control-flow edge may
/// enter the overwritten instruction range from outside it while the Hook is
/// installed; in particular, the remaining function body must not branch back
/// into that range. The caller must exclude concurrent execution of every
/// complete target page while it is patched, exclude competing code writers,
/// loader changes, remapping, reprotection, `fork`/`vfork`, and re-entry into Oh
/// My Hook, and must keep every target page quiescent from entry until this
/// function returns. All captured mappings must remain at the same addresses
/// until successful removal. Before unhooking, the caller must also drain
/// target, replacement, and original/trampoline calls.
pub unsafe fn install_inline_hook(
    target: *const (),
    replacement: *const (),
) -> Result<InlineInstallOutcome<AppliedInlineHook>> {
    let request = InlineHook::new(target, replacement);
    // SAFETY: forwarded from this function's complete public contract.
    let mut installed = unsafe { install_inline_hooks(std::slice::from_ref(&request))? };
    let completion = installed.completion;
    let installed = installed.installed.pop().ok_or(Error::InvalidInlineTarget(
        "inline installer returned no handle",
    ))?;
    Ok(InlineInstallOutcome {
        installed,
        completion,
    })
}

/// Installs a transactional inline hook batch in the current process.
///
/// Each Hook owns one or more executable arenas. The installer validates every
/// mapping and expected target byte before changing any target page, opens each
/// shared target page only once, and rolls the complete byte mutation back on
/// failure. An error returns no installed hook.
///
/// # Errors
///
/// Returns pointer, mapping, instruction-relocation, arena-allocation, overlap,
/// or target-mutation errors. Failure rolls back the complete batch.
/// A target that is already hooked in this process is rejected with
/// [`Error::Conflict`].
/// A target page that contains this crate's own page-mutation code is rejected
/// with [`Error::InvalidInlineTarget`] because the default path would make the
/// installer non-executable and the forced path cannot satisfy whole-page
/// quiescence while the installer is running there.
///
/// # Safety
///
/// The complete safety contract of [`install_inline_hook`] applies to every
/// request and to the union of their target pages. Target ranges must not
/// overlap. The caller must exclude execution and mutation for the complete
/// batch until this function returns.
pub unsafe fn install_inline_hooks(
    hooks: &[InlineHook],
) -> Result<InlineInstallOutcome<Vec<AppliedInlineHook>>> {
    let token = crate::LeaseToken;
    // Reuse the two-phase flow: preparation stays outside the process write
    // lock, and commit validates a fresh maps snapshot before mutation.
    let committed = {
        // SAFETY: forwarded from this function's complete public contract.
        let prepared = unsafe { prepare_inline_hooks_inner(hooks, &token)? };
        // SAFETY: forwarded from this function's complete public contract.
        unsafe { commit_prepared_inline_hooks(prepared, true) }
    };
    match committed {
        Ok(installed) => Ok(installed),
        Err(error) => {
            let (source, prepared) = error.into_parts();
            // SAFETY: commit restored every target and no prepared trampoline
            // was exposed by this one-shot entry point.
            let discarded = unsafe { prepared.discard() };
            // A leaked executable mapping outranks an ordinary commit failure:
            // the caller can retry the latter but can never reclaim the former.
            // A stuck target page outranks both.
            Err(preferred_error(source, discarded))
        }
    }
}

pub(crate) unsafe fn prepare_inline_hooks_inner<'lease>(
    hooks: &[InlineHook],
    lease: &'lease crate::LeaseToken,
) -> Result<PreparedInlineHooks<'lease>> {
    unsafe { prepare_inline_hooks_locked(hooks, lease) }
}

unsafe fn prepare_inline_hooks_locked<'lease>(
    hooks: &[InlineHook],
    lease: &'lease crate::LeaseToken,
) -> Result<PreparedInlineHooks<'lease>> {
    if hooks.is_empty() {
        trace!("inline hook batch skipped: hooks=0");
        return Ok(PreparedInlineHooks {
            hooks: Some(Vec::new()),
            lease,
            validation_maps: None,
        });
    }
    info!(
        "inline hook batch requested: hooks={}, arch={}",
        hooks.len(),
        std::env::consts::ARCH
    );
    let normalized = hooks
        .iter()
        .copied()
        .map(normalize_inline_hook)
        .collect::<Result<Vec<_>>>()?;
    for (index, hook) in normalized.iter().enumerate() {
        if hook.code_address == hook.replacement_address
            || normalized[..index]
                .iter()
                .any(|previous| previous.code_address == hook.code_address)
        {
            debug!("inline hook batch rejected: reason=duplicate_target");
            return Err(Error::Conflict);
        }
    }
    let batch_targets: Vec<usize> = normalized.iter().map(|hook| hook.code_address).collect();
    if inline_targets_installed(&batch_targets) {
        debug!("inline hook batch rejected: reason=target_already_hooked");
        return Err(Error::Conflict);
    }
    let page_size = crate::sys::page_size()?;
    debug!("inline hook entries validated; entering serialized analysis");

    let _guard = crate::sys::recover_lock(crate::sys::PROCESS_LOCK.read());
    let (maps, page_flags) = match read_inline_maps(&normalized).inspect_err(|_| {
        warn!("inline hook batch preflight failed: stage=maps, targets_installed=false")
    }) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            drop(_guard);
            return Err(error);
        }
    };
    let mut analyzed = match analyze_inline_hooks(&maps, &page_flags, &normalized, page_size) {
        Ok(analyzed) => analyzed,
        Err(error) => {
            drop(_guard);
            return Err(error);
        }
    };
    if let Err(error) = validate_analyzed_hooks(&analyzed, &normalized, page_size) {
        analyzed.clear();
        drop(_guard);
        return Err(error);
    }

    let mut allocation_maps = maps.clone();
    let mut fallback_maps = None;
    // Arenas take the fast writable-to-executable path first. A sandbox that
    // rejects `mprotect` cleans the complete unpublished batch and retries with
    // direct executable arenas written through the forced-access channel.
    let prepare = |allocation_maps: &mut Vec<MapInfo>,
                   fallback_maps: &mut Option<Vec<MapInfo>>,
                   analyzed: &mut Vec<AnalyzedInlineHook>,
                   mem: Option<usize>|
     -> Result<Vec<PreparedInlineHook>> {
        let batch = if analyzed.len() > 1 {
            match unsafe {
                prepare_inline_batch(
                    &maps,
                    allocation_maps,
                    fallback_maps,
                    analyzed,
                    page_size,
                    mem,
                )
            } {
                Ok(batch) => Some(batch),
                Err(Error::NoNearbyMemory) => None,
                Err(error) => return Err(error),
            }
        } else {
            None
        };
        if let Some((arenas, generated)) = batch {
            analyzed
                .drain(..)
                .zip(arenas)
                .zip(generated)
                .map(|((mut hook, arena), mut generated)| {
                    let mut arenas = vec![arena];
                    arenas.extend(generated.auxiliary.take());
                    let original_bytes = std::mem::take(&mut hook.analysis.original);
                    let patch_bytes = std::mem::take(&mut generated.patch);
                    let prepared = PreparedInlineHook {
                        target_address: hook.code_address,
                        patch_address: hook.analysis.patch_address,
                        original_bytes,
                        patch_bytes,
                        trampoline: generated.original,
                        pages: hook.pages,
                        arenas,
                    };
                    crate::sys::erase_bytes(&mut generated.bytes);
                    Ok(prepared)
                })
                .collect::<Result<Vec<_>>>()
        } else {
            let mut prepared = Vec::with_capacity(analyzed.len());
            for hook in analyzed.drain(..) {
                // SAFETY: no target reaches this unpublished arena.
                match unsafe {
                    prepare_analyzed_inline_hook(
                        &maps,
                        allocation_maps,
                        fallback_maps,
                        hook,
                        page_size,
                        mem,
                    )
                } {
                    Ok(hook) => {
                        for arena in &hook.arenas {
                            arena.record_in(allocation_maps);
                            if let Some(maps) = fallback_maps.as_mut() {
                                arena.record_in(maps);
                            }
                        }
                        prepared.push(hook);
                    }
                    Err(error) => {
                        // SAFETY: no target reaches any prepared arena.
                        let discarded = unsafe { discard_unpublished_inline_hooks(prepared) };
                        // A leaked executable mapping outranks the preparation
                        // failure: the caller can retry the latter but can
                        // never reclaim the former.
                        return Err(preferred_error(error, discarded));
                    }
                }
            }
            Ok(prepared)
        }
    };
    let mut mem = None;
    let prepared = match prepare(
        &mut allocation_maps,
        &mut fallback_maps,
        &mut analyzed,
        None,
    ) {
        Ok(prepared) => prepared,
        Err(error) if patch::page_elevation_denied(&error) => {
            analyzed.clear();
            analyzed = match analyze_inline_hooks(&maps, &page_flags, &normalized, page_size) {
                Ok(analyzed) => analyzed,
                Err(error) => {
                    drop(_guard);
                    return Err(error);
                }
            };
            if let Err(error) = validate_analyzed_hooks(&analyzed, &normalized, page_size) {
                analyzed.clear();
                drop(_guard);
                warn!("inline hook batch preparation failed: targets_installed=false");
                return Err(error);
            }
            let fd = match crate::sys::open_self_mem() {
                Ok(fd) => fd,
                Err(_) => {
                    analyzed.clear();
                    drop(_guard);
                    warn!("inline hook batch preparation failed: targets_installed=false");
                    return Err(error);
                }
            };
            mem = Some(fd);
            debug!("inline arena page elevation unavailable: retrying_with_forced_write");
            allocation_maps.clear();
            allocation_maps.extend(maps.iter().cloned());
            fallback_maps = None;
            match prepare(&mut allocation_maps, &mut fallback_maps, &mut analyzed, mem) {
                Ok(prepared) => prepared,
                Err(error) => {
                    analyzed.clear();
                    let close_errno = close_preparation_mem(&mut mem);
                    drop(_guard);
                    warn!("inline hook batch preparation failed: targets_installed=false");
                    return match close_errno {
                        Some(errno) => Err(Error::InlineCleanupComposite {
                            source: Box::new(error),
                            cleanup: Box::new(Error::system_call("close", errno)),
                        }),
                        None => Err(error),
                    };
                }
            }
        }
        Err(error) => {
            analyzed.clear();
            // The preparation error is already on its way out; a leaked
            // descriptor is logged inside and cannot be reported twice.
            let close_errno = close_preparation_mem(&mut mem);
            drop(_guard);
            warn!("inline hook batch preparation failed: targets_installed=false");
            return match close_errno {
                Some(errno) => Err(Error::InlineCleanupComposite {
                    source: Box::new(error),
                    cleanup: Box::new(Error::system_call("close", errno)),
                }),
                None => Err(error),
            };
        }
    };
    let descriptor_close_errno = close_preparation_mem(&mut mem);
    analyzed.clear();
    drop(fallback_maps);
    drop(allocation_maps);
    drop(_guard);
    if let Some(errno) = descriptor_close_errno {
        // SAFETY: no target reaches any prepared arena, and this path owns the
        // only handle to them.
        let discarded = unsafe { discard_unpublished_inline_hooks(prepared) };
        let source = Error::system_call("close", errno);
        return match discarded {
            Ok(()) => Err(source),
            Err(cleanup) => Err(Error::InlineCleanupComposite {
                source: Box::new(source),
                cleanup: Box::new(cleanup),
            }),
        };
    }

    // Build the final ownership ledger before any target byte can change. The
    // same allocation is retained by a failed commit and returned unchanged.
    let mut installed = Vec::with_capacity(prepared.len());
    for hook in prepared {
        let PreparedInlineHook {
            target_address,
            patch_address,
            mut original_bytes,
            mut patch_bytes,
            trampoline,
            pages,
            arenas,
        } = hook;
        installed.push(AppliedInlineHook {
            target_address: crate::sys::encode_usize(target_address),
            patch_address: crate::sys::encode_usize(patch_address),
            original_bytes: crate::sys::encode_bytes(&original_bytes),
            patch_bytes: crate::sys::encode_bytes(&patch_bytes),
            trampoline: crate::sys::encode_usize(trampoline),
            pages,
            state: InlineState::Active(arenas),
            // Replaced with the path the commit actually took.
            mutation_path: MutationPath::Protection,
            sync_core: false,
        });
        crate::sys::erase_bytes(&mut original_bytes);
        crate::sys::erase_bytes(&mut patch_bytes);
    }
    Ok(PreparedInlineHooks {
        hooks: Some(installed),
        lease,
        validation_maps: None,
    })
}

unsafe fn commit_prepared_inline_hooks<'lease>(
    prepared: PreparedInlineHooks<'lease>,
    one_shot_lock_held: bool,
) -> std::result::Result<InlineInstallOutcome<Vec<AppliedInlineHook>>, InlineCommitError<'lease>> {
    let PreparedInlineHooks {
        hooks,
        lease,
        validation_maps,
    } = prepared;
    let Some(mut installed) = hooks else {
        return Ok(InlineInstallOutcome {
            installed: Vec::new(),
            completion: InlineInstallCompletion::Complete,
        });
    };
    if installed.is_empty() {
        return Ok(InlineInstallOutcome {
            installed,
            completion: InlineInstallCompletion::Complete,
        });
    }

    // Built before the first target byte changes: no heap operation happens
    // between opening and closing the mutation pages. All heap-owning fields
    // already belong to `installed`, and these temporaries are released only
    // after the last page is restored.
    let mut decoded = Vec::with_capacity(installed.len());
    let mut replacements = Vec::with_capacity(installed.len());
    let mut commit_targets = Vec::with_capacity(installed.len());
    for hook in &installed {
        decoded.push(DecodedInlineHook::decode(hook));
    }
    for (hook, decoded) in installed.iter().zip(&decoded) {
        replacements.push(patch::Replacement {
            pages: &hook.pages,
            address: decoded.patch_address,
            end: decoded
                .patch_address
                .checked_add(decoded.original_bytes.len())
                .unwrap_or_else(|| crate::sys::fail_stop()),
            expected: &decoded.original_bytes,
            replacement: &decoded.patch_bytes,
        });
        commit_targets.push(decoded.target_address);
    }
    // SAFETY: `true` is private to the one-shot installer, which holds this
    // write guard across both preparation and commit.
    let _guard = if one_shot_lock_held {
        None
    } else {
        Some(crate::sys::recover_lock(crate::sys::PROCESS_LOCK.write()))
    };
    // A two-phase prepare ran under a read lock, so a competing commit may have
    // installed one of these targets in between. A one-shot prepare ran under
    // this same write guard. The check and insertion below remain serialized in
    // both cases.
    if inline_targets_installed(&commit_targets) {
        drop(_guard);
        drop(validation_maps);
        return Err(InlineCommitError {
            source: Error::Conflict,
            prepared: PreparedInlineHooks {
                hooks: Some(installed),
                lease,
                validation_maps: None,
            },
        });
    }
    // Reserve before target mutation so successful registration cannot invoke
    // the allocator while the process write lock is held.
    reserve_inline_targets(commit_targets.len());
    // SAFETY: the public contract keeps every target page stable and
    // quiescent and excludes competing writers for the complete batch.
    let result = unsafe { patch::replace_many(&replacements, validation_maps.as_deref()) };
    let outcome = match result {
        Ok(outcome) => outcome,
        Err(source) => {
            drop(_guard);
            drop(validation_maps);
            return Err(InlineCommitError {
                source,
                prepared: PreparedInlineHooks {
                    hooks: Some(installed),
                    lease,
                    validation_maps: None,
                },
            });
        }
    };
    let mutation_path = outcome.path;
    let sync_core = crate::sys::sync_instruction_stream_ready();
    for hook in &mut installed {
        hook.mutation_path = mutation_path;
        hook.sync_core = sync_core;
    }
    register_inline_targets(&commit_targets);
    drop(_guard);
    warn_missing_sync_core_once(sync_core);
    let completion = match outcome.descriptor_close_errno {
        Some(errno) => InlineInstallCompletion::ForcedDescriptorCloseFailed(
            io::Error::from_raw_os_error(errno),
        ),
        None => InlineInstallCompletion::Complete,
    };
    Ok(InlineInstallOutcome {
        installed,
        completion,
    })
}

struct NormalizedInlineHook {
    target: usize,
    replacement: usize,
    code_address: usize,
    replacement_address: usize,
}

fn normalize_inline_hook(hook: InlineHook) -> Result<NormalizedInlineHook> {
    if hook.target.is_null() {
        debug!("inline hook rejected: reason=null_target");
        return Err(Error::NullTarget);
    }
    if hook.replacement.is_null() {
        debug!("inline hook rejected: reason=null_replacement");
        return Err(Error::NullReplacement);
    }
    let target = hook.target.expose_provenance();
    let replacement = hook.replacement.expose_provenance();
    let code_address = arch::mapped_target(target)
        .inspect_err(|_| debug!("inline hook rejected: reason=invalid_target_entry"))?;
    let replacement_address = arch::mapped_replacement(replacement)
        .inspect_err(|_| debug!("inline hook rejected: reason=invalid_replacement_entry"))?;
    trace!(
        "inline entry normalization: target_adjusted={}, replacement_adjusted={}",
        code_address != target,
        replacement_address != replacement
    );
    Ok(NormalizedInlineHook {
        target,
        replacement,
        code_address,
        replacement_address,
    })
}

#[cfg(target_arch = "arm")]
fn read_inline_maps(_: &[NormalizedInlineHook]) -> Result<(Vec<MapInfo>, patch::PageFlags)> {
    // ARM relocation may copy a PC-relative literal outside the entry pages.
    Ok((read_self_maps_pathless()?, patch::read_page_flags(&[])?))
}

#[cfg(not(target_arch = "arm"))]
fn read_inline_maps(hooks: &[NormalizedInlineHook]) -> Result<(Vec<MapInfo>, patch::PageFlags)> {
    let mut addresses = Vec::with_capacity(hooks.len() * 3);
    for hook in hooks {
        addresses.push(hook.code_address);
        addresses.push(
            hook.code_address
                .checked_add(arch::WINDOW_LENGTH - 1)
                .ok_or(Error::ArithmeticOverflow)?,
        );
        addresses.push(hook.replacement_address);
    }
    let ranges = page_ranges(addresses)?;
    #[cfg(target_arch = "aarch64")]
    let page_flags = patch::read_page_flags(&ranges)?;
    #[cfg(not(target_arch = "aarch64"))]
    patch::read_page_flags(&ranges)?;
    #[cfg(not(target_arch = "aarch64"))]
    let page_flags = ();
    #[cfg(target_arch = "aarch64")]
    let maps = match &page_flags {
        Some(entries) => entries.iter().map(|entry| entry.map.clone()).collect(),
        None => read_self_maps_for_ranges(&ranges)?,
    };
    #[cfg(not(target_arch = "aarch64"))]
    let maps = read_self_maps_for_ranges(&ranges)?;
    Ok((maps, page_flags))
}

fn analyze_inline_hook(
    maps: &[MapInfo],
    page_flags: &patch::PageFlags,
    hook: &NormalizedInlineHook,
    page_size: usize,
) -> Result<AnalyzedInlineHook> {
    let mut code = [0; arch::WINDOW_LENGTH];
    let length = patch::copy_executable_window(maps, hook.code_address, &mut code);
    let length = match length {
        Ok(length) => length,
        Err(error) => {
            crate::sys::erase_bytes(&mut code);
            return Err(error);
        }
    };
    let analysis = arch::analyze(hook.target, &code[..length]);
    // Keep the stack copy no longer than the decoder needs it. The owned
    // `Analysis` retains its own scrubbed original-byte ledger when required.
    crate::sys::erase_bytes(&mut code);
    let analysis = analysis?;
    let target_entry_end = analysis
        .patch_address
        .checked_add(analysis.original.len())
        .ok_or(Error::ArithmeticOverflow)?;
    if (hook.code_address..target_entry_end).contains(&hook.replacement_address) {
        return Err(Error::Conflict);
    }
    if arch::redirects_to(&analysis, hook.replacement, maps)? {
        return Err(Error::Conflict);
    }
    patch::validate_executable_entry(maps, hook.replacement_address, 1)?;
    #[cfg(target_arch = "aarch64")]
    if let Some(reference) = analysis.address_reference.as_ref() {
        // A later instruction that reads the overwritten bytes through the
        // referenced address cannot be preserved by any entry patch; detect
        // the provable case and fail closed with a typed error.
        const LOOKAHEAD: usize = 128;
        let scan_start = target_entry_end;
        let mut window = [0_u8; LOOKAHEAD];
        let length = match patch::copy_executable_window(maps, scan_start, &mut window) {
            Ok(length) => length,
            Err(error) => {
                crate::sys::erase_bytes(&mut window);
                return Err(error);
            }
        };
        let mut words = [0_u32; LOOKAHEAD / 4];
        let count = length / 4;
        for (index, word) in words.iter_mut().enumerate().take(count) {
            let first = index * 4;
            *word = u32::from_le_bytes([
                window[first],
                window[first + 1],
                window[first + 2],
                window[first + 3],
            ]);
        }
        crate::sys::erase_bytes(&mut window);
        let reference_hit = arch::detect_data_reference(
            &words[..count],
            scan_start,
            reference.register,
            reference.target,
            analysis.patch_address,
            target_entry_end,
        );
        for word in &mut words[..count] {
            // SAFETY: the word is a live stack value and the volatile store
            // cannot be elided as a dead write.
            unsafe { std::ptr::write_volatile(word, 0) };
        }
        if let Some((instruction, address)) = reference_hit {
            return Err(Error::InlineDataReference {
                instruction,
                address,
            });
        }
    }
    #[cfg(target_arch = "aarch64")]
    let (pages, replacement_guarded) = patch::capture_pages(
        maps,
        page_flags,
        analysis.patch_address,
        analysis.original.len(),
        hook.replacement_address,
        page_size,
    )?;
    #[cfg(not(target_arch = "aarch64"))]
    let (pages, _) = patch::capture_pages(
        maps,
        page_flags,
        analysis.patch_address,
        analysis.original.len(),
        hook.replacement_address,
        page_size,
    )?;
    #[cfg(target_arch = "aarch64")]
    let guarded = patch::is_guarded(&pages);
    Ok(AnalyzedInlineHook {
        code_address: hook.code_address,
        analysis,
        replacement: hook.replacement,
        pages,
        #[cfg(target_arch = "aarch64")]
        guarded,
        #[cfg(target_arch = "aarch64")]
        replacement_guarded,
    })
}

fn analyze_inline_hooks(
    maps: &[MapInfo],
    page_flags: &patch::PageFlags,
    normalized: &[NormalizedInlineHook],
    page_size: usize,
) -> Result<Vec<AnalyzedInlineHook>> {
    let mut analyzed = Vec::with_capacity(normalized.len());
    for hook in normalized {
        match analyze_inline_hook(maps, page_flags, hook, page_size) {
            Ok(hook) => analyzed.push(hook),
            Err(error) => {
                warn!(
                    "inline hook batch preflight failed: stage=analysis, targets_installed=false"
                );
                analyzed.clear();
                return Err(error);
            }
        }
    }
    Ok(analyzed)
}

fn validate_analyzed_hooks(
    analyzed: &[AnalyzedInlineHook],
    normalized: &[NormalizedInlineHook],
    page_size: usize,
) -> Result<()> {
    // The installer must never execute from a captured page: the default path
    // makes it non-executable, while the forced path cannot satisfy whole-page
    // quiescence while mutation code is running there. Reject either path.
    let mutation_pages = patch::mutation_code_pages(page_size);
    if analyzed
        .iter()
        .any(|hook| patch::pages_overlap_mutation_code(&hook.pages, &mutation_pages))
    {
        warn!(
            "inline hook batch rejected: reason=target_page_contains_mutation_code, targets_installed=false"
        );
        return Err(Error::InvalidInlineTarget(
            "target page contains the inline mutation code",
        ));
    }
    let replacement_overlaps_target = normalized.iter().any(|request| {
        analyzed.iter().zip(normalized).any(|(hook, target)| {
            hook.analysis
                .patch_address
                .checked_add(hook.analysis.original.len())
                .is_some_and(|end| {
                    (target.code_address..end).contains(&request.replacement_address)
                })
        })
    });
    if replacement_overlaps_target {
        debug!(
            "inline hook batch rejected: reason=replacement_overlaps_target, targets_installed=false"
        );
        return Err(Error::Conflict);
    }
    Ok(())
}

fn generate_inline_hook(
    hook: &AnalyzedInlineHook,
    address: usize,
    validation_maps: &[MapInfo],
    _allocation_maps: &[MapInfo],
    allow_auxiliary: bool,
    _mem: Option<usize>,
) -> Result<Generated> {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    return arch::generate(
        &hook.analysis,
        address,
        hook.replacement,
        validation_maps,
        _allocation_maps,
        allow_auxiliary,
        _mem,
    );
    #[cfg(target_arch = "aarch64")]
    return arch::generate(
        &hook.analysis,
        address,
        hook.replacement,
        validation_maps,
        hook.guarded,
        hook.replacement_guarded,
        allow_auxiliary,
    );
    #[cfg(target_arch = "arm")]
    arch::generate(
        &hook.analysis,
        address,
        hook.replacement,
        validation_maps,
        allow_auxiliary,
        _mem,
    )
}

unsafe fn prepare_inline_batch(
    validation_maps: &[MapInfo],
    allocation_maps: &[MapInfo],
    fallback_maps: &mut Option<Vec<MapInfo>>,
    hooks: &[AnalyzedInlineHook],
    page_size: usize,
    mem: Option<usize>,
) -> Result<(Vec<Arena>, Vec<Generated>)> {
    let Some(first) = hooks.first() else {
        return Err(Error::NoNearbyMemory);
    };
    let protection = patch::arena_protection(&first.pages);
    if hooks
        .iter()
        .any(|hook| patch::arena_protection(&hook.pages) != protection)
    {
        return Err(Error::NoNearbyMemory);
    }
    let length = page_size
        .checked_mul(hooks.len())
        .ok_or(Error::ArithmeticOverflow)?;
    let mut attempt = |allow_auxiliary: bool| -> Result<(Arena, Vec<Generated>)> {
        let allocate = |candidate_maps: &[MapInfo]| {
            // SAFETY: MAP_FIXED_NOREPLACE candidates cannot replace an
            // uncaptured mapping, ordinary candidates are hints, and the
            // public contract excludes concurrent mapping changes.
            unsafe {
                Arena::allocate_near(
                    candidate_maps,
                    first.analysis.patch_address,
                    arch::max_distance(&first.analysis),
                    page_size,
                    length,
                    mem.map(|fd| (protection, fd)),
                    |base| {
                        let mut generated = Vec::with_capacity(hooks.len());
                        for (index, hook) in hooks.iter().enumerate() {
                            let address = index
                                .checked_mul(page_size)
                                .and_then(|offset| base.checked_add(offset))
                                .ok_or(Error::ArithmeticOverflow)?;
                            match generate_inline_hook(
                                hook,
                                address,
                                validation_maps,
                                candidate_maps,
                                allow_auxiliary,
                                mem,
                            ) {
                                Ok(hook) => generated.push(hook),
                                Err(error) => {
                                    for generated in &mut generated {
                                        crate::sys::erase_bytes(&mut generated.bytes);
                                        crate::sys::erase_bytes(&mut generated.patch);
                                    }
                                    let auxiliaries = generated
                                        .iter_mut()
                                        .filter_map(|hook| hook.auxiliary.take())
                                        .collect::<Vec<_>>();
                                    // SAFETY: generation failed before any
                                    // entry could reach these unpublished
                                    // auxiliaries.
                                    if let Err((unmap_error, _leaked)) = unmap_arenas(auxiliaries) {
                                        error!(
                                            "inline hook cleanup failed: stage=batch_generation, target_installed=false"
                                        );
                                        return Err(cleanup_pending(unmap_error));
                                    }
                                    return Err(error);
                                }
                            }
                        }
                        Ok(generated)
                    },
                )
            }
        };
        match allocate(allocation_maps) {
            Ok(prepared) => Ok(prepared),
            Err(Error::NoNearbyMemory) => {
                if fallback_maps.is_none() {
                    *fallback_maps = Some(read_self_maps_pathless()?);
                }
                allocate(
                    fallback_maps
                        .as_deref()
                        .unwrap_or_else(|| crate::sys::fail_stop()),
                )
            }
            Err(error) => Err(error),
        }
    };
    // The strict pass first seeks one arena whose plain relative jumps reach
    // every replacement; only an exhausted placement retries with the
    // auxiliary-bridge layout, which maps a second executable page. On
    // architectures that never map auxiliaries the retry only repeats the
    // already-failing search.
    let (arena, mut generated) = match attempt(false) {
        Ok(prepared) => prepared,
        Err(Error::NoNearbyMemory) => attempt(true)?,
        Err(error) => return Err(error),
    };

    let prepared = (|| {
        let mut ranges = Vec::with_capacity(generated.len());
        for (index, (hook, generated)) in hooks.iter().zip(&generated).enumerate() {
            let offset = index
                .checked_mul(page_size)
                .ok_or(Error::ArithmeticOverflow)?;
            let start = arena
                .address()
                .checked_add(offset)
                .ok_or(Error::ArithmeticOverflow)?;
            let end = start
                .checked_add(generated.bytes.len())
                .ok_or(Error::ArithmeticOverflow)?;
            let page_end = start
                .checked_add(page_size)
                .ok_or(Error::ArithmeticOverflow)?;
            if generated.patch.len() != hook.analysis.original.len()
                || generated.patch.is_empty()
                || end > page_end
                || !(start..end).contains(&generated.original)
            {
                return Err(Error::InvalidInlineTarget("invalid generated inline hook"));
            }
            // SAFETY: this disjoint private arena is either RW-owned by this
            // preparation or final-protected and writable only through the
            // matching forced-access descriptor.
            unsafe { arena.write_at(offset, &generated.bytes, mem)? };
            ranges.push((start, end));
        }
        // SAFETY: all freshly written ranges remain live, readable, and
        // unpublished for the complete cache-maintenance sequence.
        unsafe { crate::sys::flush_instruction_cache_ranges(&ranges)? };
        // SAFETY: RW arenas receive their sole RW-to-executable transition;
        // direct arenas already have their final protection and are unchanged.
        unsafe { arena.make_executable(protection)? };
        Ok(())
    })();
    if let Err(error) = prepared {
        let mut arenas = vec![arena];
        for generated in &mut generated {
            crate::sys::erase_bytes(&mut generated.bytes);
            crate::sys::erase_bytes(&mut generated.patch);
        }
        arenas.extend(
            generated
                .iter_mut()
                .filter_map(|hook| hook.auxiliary.take()),
        );
        // SAFETY: no target reaches the unpublished batch or auxiliaries.
        if let Err((unmap_error, _leaked)) = unsafe { unmap_arenas(arenas) } {
            error!("inline hook cleanup failed: stage=batch_preparation, target_installed=false");
            return Err(cleanup_pending(unmap_error));
        }
        return Err(error);
    }

    Ok((arena.into_pages(page_size), generated))
}

unsafe fn prepare_analyzed_inline_hook(
    validation_maps: &[MapInfo],
    allocation_maps: &[MapInfo],
    fallback_maps: &mut Option<Vec<MapInfo>>,
    mut hook: AnalyzedInlineHook,
    page_size: usize,
    mem: Option<usize>,
) -> Result<PreparedInlineHook> {
    let protection = patch::arena_protection(&hook.pages);
    let mut attempt = |allow_auxiliary: bool| -> Result<(Arena, Generated)> {
        let allocate = |candidate_maps: &[MapInfo]| {
            // SAFETY: MAP_FIXED_NOREPLACE candidates cannot replace an
            // uncaptured mapping, ordinary candidates are hints, and the
            // public contract excludes concurrent mapping changes.
            unsafe {
                Arena::allocate_near(
                    candidate_maps,
                    hook.analysis.patch_address,
                    arch::max_distance(&hook.analysis),
                    page_size,
                    page_size,
                    mem.map(|fd| (protection, fd)),
                    |address| {
                        generate_inline_hook(
                            &hook,
                            address,
                            validation_maps,
                            candidate_maps,
                            allow_auxiliary,
                            mem,
                        )
                    },
                )
            }
        };
        match allocate(allocation_maps) {
            Ok(prepared) => Ok(prepared),
            Err(Error::NoNearbyMemory) => {
                if fallback_maps.is_none() {
                    *fallback_maps = Some(read_self_maps_pathless()?);
                }
                allocate(
                    fallback_maps
                        .as_deref()
                        .unwrap_or_else(|| crate::sys::fail_stop()),
                )
            }
            Err(error) => Err(error),
        }
    };
    // See `prepare_inline_batch`: the strict pass prefers an arena reachable
    // by plain relative jumps before the auxiliary-bridge layout.
    let (arena, mut generated) = match attempt(false) {
        Ok(prepared) => prepared,
        Err(Error::NoNearbyMemory) => match attempt(true) {
            Ok(prepared) => prepared,
            Err(error) => {
                crate::sys::erase_bytes(&mut hook.analysis.original);
                return Err(error);
            }
        },
        Err(error) => {
            crate::sys::erase_bytes(&mut hook.analysis.original);
            return Err(error);
        }
    };

    let prepared = (|| {
        let generated_end = arena
            .address()
            .checked_add(generated.bytes.len())
            .ok_or(Error::ArithmeticOverflow)?;
        if generated.patch.len() != hook.analysis.original.len()
            || generated.patch.is_empty()
            || !(arena.address()..generated_end).contains(&generated.original)
        {
            return Err(Error::InvalidInlineTarget("invalid generated inline hook"));
        }
        // SAFETY: the arena is caller-owned private memory.
        unsafe { arena.write(&generated.bytes, mem)? };
        // SAFETY: RW arenas receive their sole RW-to-executable transition;
        // direct arenas already have their final protection and are unchanged.
        unsafe { arena.make_executable(protection)? };
        Ok(())
    })();
    if let Err(error) = prepared {
        let mut arenas = vec![arena];
        arenas.extend(generated.auxiliary.take());
        crate::sys::erase_bytes(&mut generated.bytes);
        crate::sys::erase_bytes(&mut generated.patch);
        // SAFETY: no target reaches these unpublished arenas.
        let leaked = unsafe { unmap_arenas(arenas) };
        crate::sys::erase_bytes(&mut hook.analysis.original);
        if let Err((unmap_error, _leaked)) = leaked {
            error!("inline hook cleanup failed: target_installed=false");
            return Err(cleanup_pending(unmap_error));
        }
        return Err(error);
    }

    let mut arenas = vec![arena];
    arenas.extend(generated.auxiliary.take());
    crate::sys::erase_bytes(&mut generated.bytes);
    let original_bytes = std::mem::take(&mut hook.analysis.original);
    let patch_bytes = std::mem::take(&mut generated.patch);
    Ok(PreparedInlineHook {
        target_address: hook.code_address,
        patch_address: hook.analysis.patch_address,
        original_bytes,
        patch_bytes,
        trampoline: generated.original,
        pages: hook.pages,
        arenas,
    })
}

/// Releases unpublished arenas, continuing past a failure so one unreleasable
/// mapping cannot strand the rest.
unsafe fn discard_unpublished_inline_hooks(hooks: Vec<PreparedInlineHook>) -> Result<()> {
    let mut first_error = None;
    for mut hook in hooks {
        crate::sys::erase_bytes(&mut hook.original_bytes);
        crate::sys::erase_bytes(&mut hook.patch_bytes);
        // SAFETY: no target reaches these unpublished arenas.
        if let Err((error, _leaked)) = unsafe { unmap_arenas(hook.arenas) } {
            error!("inline hook batch cleanup failed: targets_installed=false");
            first_error.get_or_insert(error);
        }
    }
    match first_error {
        Some(error) => Err(cleanup_pending(error)),
        None => Ok(()),
    }
}

unsafe fn discard_prepared_inline_hooks(hooks: Option<Vec<AppliedInlineHook>>) -> Result<()> {
    let Some(hooks) = hooks else {
        return Ok(());
    };
    let mut first_error = None;
    for hook in hooks {
        let arenas = match hook.state {
            InlineState::Active(arenas) | InlineState::CleanupPending(arenas) => arenas,
            InlineState::Removed => continue,
        };
        // SAFETY: the public discard contract guarantees that no published
        // trampoline call remains in flight.
        if let Err((error, _leaked)) = unsafe { unmap_arenas(arenas) } {
            error!("inline prepared cleanup failed: targets_installed=false");
            first_error.get_or_insert(error);
        }
    }
    match first_error {
        Some(error) => Err(cleanup_pending(error)),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    unsafe extern "C" {
        fn abs(value: libc::c_int) -> libc::c_int;
    }

    type Unary = unsafe extern "C" fn(i32) -> i32;
    static ORIGINAL: AtomicUsize = AtomicUsize::new(0);
    static PREPARED_ORIGINAL: AtomicUsize = AtomicUsize::new(0);

    #[inline(never)]
    extern "C" fn replacement(value: i32) -> i32 {
        let original = std::ptr::with_exposed_provenance(ORIGINAL.load(Ordering::Acquire));
        // SAFETY: the test publishes this hook's live trampoline and drains
        // the call before removal.
        let original = unsafe { std::mem::transmute::<*const (), Unary>(original) };
        // SAFETY: every i32 is valid input for C abs.
        unsafe { original(value) + 10 }
    }

    #[inline(never)]
    extern "C" fn prepared_replacement(value: i32) -> i32 {
        let original = std::ptr::with_exposed_provenance(PREPARED_ORIGINAL.load(Ordering::Acquire));
        // SAFETY: the test publishes this hook's live trampoline and drains
        // every call before removal.
        let original = unsafe { std::mem::transmute::<*const (), Unary>(original) };
        // SAFETY: both functions use the Unary ABI.
        unsafe { original(value) + 10 }
    }

    fn call(entry: *const (), value: i32) -> i32 {
        // SAFETY: every test entry uses the Unary ABI and remains live here.
        let entry = unsafe { std::mem::transmute::<*const (), Unary>(entry) };
        // SAFETY: the tests pass values valid for the selected libc entry.
        unsafe { std::hint::black_box(entry)(value) }
    }

    #[test]
    fn cleanup_pending_retains_arenas_for_retry() {
        const CHILD: &str = "OMHOOK_INLINE_CLEANUP_RETRY_CHILD";
        if std::env::var_os(CHILD).is_some() {
            // SAFETY: this child excludes target execution and competing mutation.
            let mut hook =
                unsafe { install_inline_hook(abs as *const (), replacement as *const ()) }
                    .expect("inline hook installation failed")
                    .into_parts()
                    .0;
            let trampoline = hook.original().unwrap().expose_provenance();
            crate::sys::fail_next_unmap();

            // SAFETY: no target, replacement, original, or trampoline call is in flight.
            let error = unsafe { hook.unhook() }.expect_err("cleanup failure was not reported");
            assert!(matches!(error, Error::InlineCleanupPending(_)));
            assert!(!hook.is_installed());
            assert!(hook.original().is_none());
            assert!(
                crate::read_self_maps()
                    .unwrap()
                    .iter()
                    .any(|map| map.start <= trampoline && trampoline < map.end)
            );

            // SAFETY: the target is already restored; this retries only pending cleanup.
            unsafe { hook.unhook().expect("cleanup retry failed") };
            assert!(
                crate::read_self_maps()
                    .unwrap()
                    .iter()
                    .all(|map| !(map.start <= trampoline && trampoline < map.end))
            );
            return;
        }

        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "inline::tests::cleanup_pending_retains_arenas_for_retry",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn install_rollback_that_cannot_unmap_arenas_reports_cleanup_pending() {
        // No target byte was written, so an arena this process can no longer
        // release is a resource failure, not a reason to terminate. The error
        // names the leak in preference to the installation failure that caused
        // the rollback, because only the leak is unrecoverable.
        const CHILD: &str = "OMHOOK_INLINE_ROLLBACK_MUNMAP_FAILURE_CHILD";
        if std::env::var_os(CHILD).is_some() {
            // The failures are injected in-process rather than through a
            // seccomp filter: 32-bit bionic's atexit machinery mprotects its
            // handler array, enters its fatal path when that denial arrives
            // mid-flight, and deadlocks before this child can finish. The
            // injected failing protection change stops the arena's transition
            // to executable memory, and the injected unmap strands it.
            crate::sys::tests::fail_next_protect();
            crate::sys::fail_next_unmap();
            // SAFETY: both entries are live and ABI-compatible; the arena
            // cannot become executable and cannot be released.
            let error = unsafe { install_inline_hook(abs as *const (), replacement as *const ()) }
                .err()
                .expect("installation cannot succeed with every mutation syscall denied");
            assert!(
                matches!(error, Error::InlineCleanupPending(_)),
                "unexpected error: {error:?}"
            );
            return;
        }

        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "inline::tests::install_rollback_that_cannot_unmap_arenas_reports_cleanup_pending",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn installs_calls_original_and_removes_inline_hook() {
        // Patching a live entry drops PROT_EXEC from its complete page, so the
        // contract requires excluding concurrent execution of that whole page.
        // A libtest worker cannot prove that while sibling tests run, so the
        // body executes in a child that runs this test alone.
        const CHILD: &str = "OMHOOK_INLINE_INSTALL_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "inline::tests::installs_calls_original_and_removes_inline_hook",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }

        let target_entry = abs as *const ();
        // SAFETY: installation is rejected before mutating code because the
        // replacement overlaps the analyzed target entry.
        assert!(matches!(
            unsafe { install_inline_hook(target_entry, target_entry) },
            Err(Error::Conflict)
        ));
        // SAFETY: this single test excludes target execution and competing
        // mutation while installing and removing ABI-compatible functions.
        let mut hook = unsafe { install_inline_hook(target_entry, replacement as *const ()) }
            .expect("inline hook installation failed")
            .into_parts()
            .0;
        assert_eq!(hook.mutation_path(), MutationPath::ForcedAccess);
        // SAFETY: the first handle still owns the exact installed redirection;
        // a second installation must fail without changing it.
        assert!(matches!(
            unsafe { install_inline_hook(target_entry, replacement as *const ()) },
            Err(Error::Conflict)
        ));
        let original = hook.original().expect("missing original trampoline");
        ORIGINAL.store(original.expose_provenance(), Ordering::Release);

        assert!(hook.is_installed());
        assert_eq!(call(target_entry, -1), 11);
        assert_eq!(call(original, -1), 1);

        // SAFETY: all calls above completed and no other thread uses the page.
        unsafe { hook.unhook().expect("inline hook removal failed") };
        assert!(!hook.is_installed());
        assert!(hook.original().is_none());
        assert_eq!(call(target_entry, -1), 1);
        // SAFETY: successful removal is explicitly idempotent.
        unsafe { hook.unhook().expect("repeated removal failed") };
    }

    #[test]
    fn a_leaked_descriptor_after_a_published_mutation_still_reports_success() {
        // The forced path wrote, verified and flushed every byte before its
        // descriptor failed to close. The hooks are live at that point, so the
        // call must succeed: reporting failure makes the one-shot entry point
        // discard the batch and unmap the arenas the new entries branch into,
        // which turns a leaked descriptor into a crash at the next call.
        const CHILD: &str = "OMHOOK_INLINE_LEAKED_DESCRIPTOR_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "inline::tests::a_leaked_descriptor_after_a_published_mutation_still_reports_success",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }

        let target_entry = abs as *const ();
        patch::tests::fail_next_forced_close();
        // SAFETY: this single-threaded child keeps the complete target page
        // quiescent and excludes competing writers.
        let (mut hook, completion) =
            unsafe { install_inline_hook(target_entry, replacement as *const ()) }
                .expect("a descriptor close failure must not fail a published mutation")
                .into_parts();
        assert!(matches!(
            completion,
            InlineInstallCompletion::ForcedDescriptorCloseFailed(_)
        ));
        assert!(
            !patch::tests::forced_close_failure_pending(),
            "the close injection was never reached; the injection point moved"
        );
        assert_eq!(hook.mutation_path(), MutationPath::ForcedAccess);
        ORIGINAL.store(
            hook.original()
                .expect("missing trampoline")
                .expose_provenance(),
            Ordering::Release,
        );
        // The hook is live, which is the whole point: the arenas it branches
        // into were not discarded.
        assert_eq!(call(target_entry, -5), 15);
        // SAFETY: the call above completed and this child is quiescent.
        unsafe { hook.unhook().expect("removal failed") };
        assert_eq!(call(target_entry, -5), 5);
        crate::sys::tests::exit_seccomp_child();
    }

    unsafe extern "C" {
        fn labs(value: libc::c_long) -> libc::c_long;
        fn atoi(value: *const libc::c_char) -> libc::c_int;
        fn getpid() -> libc::c_int;
        fn getppid() -> libc::c_int;
        fn getuid() -> libc::uid_t;
        fn getgid() -> libc::gid_t;
    }

    extern "C" fn same_page_first_replacement(_: i32) -> i32 {
        0x1111
    }

    extern "C" fn same_page_second_replacement(_: i32) -> i32 {
        0x2222
    }

    /// Finds two libc entries that sit on different pages.
    fn page_strangers(page_size: usize) -> Option<(*const (), *const ())> {
        let first = abs as *const ();
        let first_page = crate::sys::page_start(first.expose_provenance(), page_size);
        for second in [
            getppid as *const (),
            getpid as *const (),
            atoi as *const (),
            labs as *const (),
        ] {
            if crate::sys::page_start(second.expose_provenance(), page_size) != first_page {
                return Some((first, second));
            }
        }
        None
    }

    /// Finds two libc entries that share one page.
    ///
    /// The pair has to come from libc: a target defined next to this crate's
    /// own code is rejected by the mutation-window guard, which is exactly the
    /// guard working. Which entries share a page is a property of the libc
    /// build, so the pair is discovered instead of hard-coded.
    fn page_mates(page_size: usize) -> Option<(*const (), *const ())> {
        // The no-argument identifier stubs are last: 32-bit bionic emits
        // them as A32 `mov r12, r7` prologues packed onto one page, which
        // the Thumb-only `abs`/`labs` family never shares there.
        let candidates: [*const (); 7] = [
            abs as *const (),
            labs as *const (),
            atoi as *const (),
            getpid as *const (),
            getppid as *const (),
            getuid as *const (),
            getgid as *const (),
        ];
        for (index, &first) in candidates.iter().enumerate() {
            for &second in &candidates[index + 1..] {
                let first_page = crate::sys::page_start(first.expose_provenance(), page_size);
                let second_page = crate::sys::page_start(second.expose_provenance(), page_size);
                if first_page == second_page {
                    return Some((first, second));
                }
            }
        }
        None
    }

    #[test]
    fn a_failed_install_leaves_another_hook_on_the_same_page_intact() {
        // Two targets can share a page: only a repeated target is rejected. A
        // rollback that could not restore the page protection must therefore
        // touch nothing but its own bytes. Reverting the page to its file
        // contents here would silently un-patch the first hook while its handle
        // still claimed to be installed.
        const CHILD: &str = "OMHOOK_INLINE_SAME_PAGE_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "inline::tests::a_failed_install_leaves_another_hook_on_the_same_page_intact",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }

        let page_size = crate::sys::page_size().unwrap();
        let Some((first_entry, second_entry)) = page_mates(page_size) else {
            panic!("no two probed libc entries share a page; pick different candidates");
        };
        let page = crate::sys::page_start(first_entry.expose_provenance(), page_size);
        let untouched = call(first_entry, 7);

        // SAFETY: this single-threaded child keeps the shared page quiescent
        // and excludes competing writers.
        let (mut first, _) =
            unsafe { install_inline_hook(first_entry, same_page_first_replacement as *const ()) }
                .expect("first installation failed")
                .into_parts();
        assert_eq!(call(first_entry, 7), 0x1111);

        patch::tests::fail_next_forced_unavailable();
        crate::sys::tests::deny_exec_protect_page(page);
        // SAFETY: same contract; the forced-unavailable fallback is expected
        // to fail while restoring the shared page's executable protection.
        let result =
            unsafe { install_inline_hook(second_entry, same_page_second_replacement as *const ()) };
        crate::sys::tests::deny_exec_protect_page(0);
        assert!(
            matches!(result, Err(Error::TargetPageProtectionLost { address, .. }) if address == page),
            "unexpected second installation result"
        );

        // The page is stuck non-executable, so put it back before calling into
        // it. Only then can the first hook be observed.
        // SAFETY: this is the captured page of both targets and remains mapped.
        unsafe { crate::sys::protect(page, page_size, libc::PROT_READ | libc::PROT_EXEC) }
            .expect("restoring the shared page protection");

        assert!(first.is_installed());
        assert_eq!(
            call(first_entry, 7),
            0x1111,
            "the failed installation reverted the first hook's bytes"
        );

        // SAFETY: every call above completed and this child is quiescent.
        unsafe { first.unhook().expect("first removal failed") };
        assert_eq!(call(first_entry, 7), untouched);
    }

    #[test]
    fn a_refused_protection_restore_sends_later_installations_to_the_forced_path() {
        // A domain without `execmod` lets a page drop PROT_EXEC and then
        // refuses to give it back once the page has been written. Nothing
        // distinguishes such a domain before the first write, so the first
        // installation is lost. Every later one must skip elevation entirely:
        // repeating it would strand one more page non-executable.
        const CHILD: &str = "OMHOOK_INLINE_EXEC_RESTORE_DENIED_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "inline::tests::a_refused_protection_restore_sends_later_installations_to_the_forced_path",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }

        let page_size = crate::sys::page_size().unwrap();
        let Some((first_entry, second_entry)) = page_strangers(page_size) else {
            panic!("every probed libc entry shares one page; pick different candidates");
        };
        let first_page = crate::sys::page_start(first_entry.expose_provenance(), page_size);

        // Prove the normal path stays on the forced-access channel.
        // SAFETY: this single-threaded child keeps the target pages quiescent
        // and excludes competing writers.
        let mut warmup = unsafe { install_inline_hook(second_entry, replacement as *const ()) }
            .expect("warm-up installation failed")
            .into_parts()
            .0;
        assert_eq!(warmup.mutation_path(), MutationPath::ForcedAccess);
        ORIGINAL.store(
            warmup
                .original()
                .expect("missing warm-up trampoline")
                .expose_provenance(),
            Ordering::Release,
        );
        // SAFETY: the warm-up published no call and this child is quiescent.
        unsafe { warmup.unhook().expect("warm-up removal failed") };

        // Now refuse to restore PROT_EXEC on the first target's page.
        patch::tests::fail_next_forced_unavailable();
        crate::sys::tests::deny_exec_protect_page(first_page);
        // SAFETY: same contract; the elevation fallback is expected to fail.
        let refused = unsafe { install_inline_hook(first_entry, replacement as *const ()) };
        crate::sys::tests::deny_exec_protect_page(0);
        assert!(
            matches!(refused, Err(Error::TargetPageProtectionLost { address, .. }) if address == first_page),
            "unexpected first installation result"
        );
        // That page is stuck; put it back so this child can keep running.
        // SAFETY: it is the captured target page and remains mapped.
        unsafe { crate::sys::protect(first_page, page_size, libc::PROT_READ | libc::PROT_EXEC) }
            .expect("restoring the refused page protection");

        // The refusal was recorded, so a second target on a completely
        // different page now goes straight to the channel that never
        // reprotects — even though nothing would deny its elevation.
        // SAFETY: same contract as the warm-up.
        let mut hook = unsafe { install_inline_hook(second_entry, replacement as *const ()) }
            .expect("installation after a refused restore failed")
            .into_parts()
            .0;
        assert_eq!(
            hook.mutation_path(),
            MutationPath::ForcedAccess,
            "elevation was attempted again after a refused protection restore"
        );
        ORIGINAL.store(
            hook.original()
                .expect("missing trampoline")
                .expose_provenance(),
            Ordering::Release,
        );
        // SAFETY: no call is in flight in this single-threaded child.
        unsafe { hook.unhook().expect("removal failed") };
    }

    #[test]
    fn an_undone_removal_does_not_claim_the_target_was_restored() {
        // A forced removal whose write fails is rolled back by writing the
        // patch bytes again -- the hook is still installed. If the descriptor
        // then fails to close, the error must not be `InlineCleanupPending`:
        // that variant is documented as "the target is restored, only arenas
        // remain", and a caller acting on it would drop a live hook believing
        // it was gone.
        const CHILD: &str = "OMHOOK_INLINE_UNDONE_REMOVAL_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "inline::tests::an_undone_removal_does_not_claim_the_target_was_restored",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }

        let target_entry = abs as *const ();
        // SAFETY: this single-threaded child keeps the complete target page
        // quiescent and excludes competing writers.
        let mut hook = unsafe { install_inline_hook(target_entry, replacement as *const ()) }
            .expect("forced installation failed")
            .into_parts()
            .0;
        assert_eq!(hook.mutation_path(), MutationPath::ForcedAccess);
        ORIGINAL.store(
            hook.original()
                .expect("missing trampoline")
                .expose_provenance(),
            Ordering::Release,
        );
        assert_eq!(call(target_entry, -5), 15);

        patch::tests::fail_next_forced_write();
        patch::tests::fail_next_forced_close();
        // SAFETY: the call above completed and this child is quiescent.
        let error =
            unsafe { hook.unhook() }.expect_err("the injected write failure aborts removal");
        assert!(
            !patch::tests::forced_write_failure_pending(),
            "the write injection was never reached; the injection point moved"
        );
        assert!(
            !patch::tests::forced_close_failure_pending(),
            "the close injection was never reached; the injection point moved"
        );
        assert!(
            matches!(error, Error::ForcedDescriptorLeaked),
            "an undone removal must not report a restored target: {error:?}"
        );

        // The rollback put the patch bytes back, so the hook is still live and
        // the handle says so. Both must agree.
        assert!(hook.is_installed());
        assert_eq!(call(target_entry, -5), 15);

        // And the removal is genuinely retryable.
        // SAFETY: the call above completed and this child is quiescent.
        unsafe { hook.unhook().expect("retrying the removal failed") };
        assert!(!hook.is_installed());
        assert_eq!(call(target_entry, -5), 5);
        crate::sys::tests::exit_seccomp_child();
    }

    #[test]
    fn stuck_page_protection_is_reported_instead_of_terminating() {
        // A policy that lets a page drop PROT_EXEC but refuses to grant it back
        // once the page has been written -- an SELinux domain without
        // `execmod` -- used to terminate the process from the rollback path on
        // every inline installation. The rollback now puts the bytes back and
        // reports the page it could not close, as an error the caller can act
        // on. The body runs in a child because the target page is left
        // non-executable until this test puts it back.
        const CHILD: &str = "OMHOOK_INLINE_STUCK_PROTECTION_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "inline::tests::stuck_page_protection_is_reported_instead_of_terminating",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }

        let target_entry = abs as *const ();
        let page_size = crate::sys::page_size().unwrap();
        let page = crate::sys::page_start(target_entry.expose_provenance(), page_size);

        patch::tests::fail_next_forced_unavailable();
        crate::sys::tests::deny_exec_protect_page(page);
        // SAFETY: this single-threaded child keeps the complete target page
        // quiescent and excludes competing writers and loader changes.
        // SAFETY: the contract above holds for this single-threaded child.
        let result = unsafe { install_inline_hook(target_entry, replacement as *const ()) };
        crate::sys::tests::deny_exec_protect_page(0);
        let Err(error) = result else {
            panic!("installation succeeded while PROT_EXEC was refused");
        };

        match error {
            Error::TargetPageProtectionLost {
                address, length, ..
            } => {
                assert_eq!(address, page);
                assert_eq!(length, page_size);
            }
            other => panic!("unexpected error: {other:?}"),
        }

        // The rollback restored every byte, so the only damage left is the
        // protection the policy refused. Put it back now that the test policy
        // is disarmed and prove the target entry runs again.
        // SAFETY: this is the captured target page and it remains mapped.
        unsafe { crate::sys::protect(page, page_size, libc::PROT_READ | libc::PROT_EXEC) }
            .expect("restoring the target page protection");
        assert_eq!(call(target_entry, -1), 1);
    }

    #[test]
    fn installs_and_removes_without_any_mprotect() {
        // The forced-access pipeline maps arenas with their final protection
        // and writes target bytes through /proc/self/mem, so a process that
        // rejects every mprotect on the target page can still install and
        // remove an inline hook.
        // The body runs in a child because the whole target page must stay
        // quiescent.
        const CHILD: &str = "OMHOOK_INLINE_NO_MPROTECT_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "inline::tests::installs_and_removes_without_any_mprotect",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }

        let target_entry = abs as *const ();
        fn fd_count() -> usize {
            std::fs::read_dir("/proc/self/fd")
                .map(|entries| entries.count())
                .unwrap_or_else(|_| crate::sys::fail_stop())
        }
        fn mapping_count() -> usize {
            crate::read_self_maps()
                .map(|maps| {
                    maps.iter()
                        // Count only anonymous executable mappings: every
                        // arena this lifecycle maps is anonymous and
                        // executable, while the process allocator freely
                        // splits and extends its own named heap VMAs.
                        .filter(|map| {
                            map.perms.contains(crate::maps::MapPerms::EXEC) && map.path.is_none()
                        })
                        .count()
                })
                .unwrap_or_else(|_| crate::sys::fail_stop())
        }
        // The first forced placement can split an existing anonymous VMA when
        // its arena merges with a neighbor; that bounded split is not a leak.
        // Warm it up before taking the stable resource baseline.
        let mut warmup = unsafe { install_inline_hook(target_entry, replacement as *const ()) }
            .expect("forced inline installation requires no mprotect")
            .into_parts()
            .0;
        // The caller can tell that the target page kept PROT_EXEC for the
        // whole write, so the fault that normally catches a thread entering
        // the range never existed for this installation.
        assert_eq!(warmup.mutation_path(), MutationPath::ForcedAccess);
        ORIGINAL.store(
            warmup
                .original()
                .expect("missing forced warm-up trampoline")
                .expose_provenance(),
            Ordering::Release,
        );
        assert_eq!(call(target_entry, -5), 15);
        // SAFETY: the warm-up call completed and this child is quiescent.
        unsafe { warmup.unhook().expect("forced warm-up removal failed") };
        assert_eq!(call(target_entry, -5), 5);
        let fds_before = fd_count();
        let mappings_before = mapping_count();
        for _ in 0..32 {
            // SAFETY: this child excludes target execution and competing
            // writers for every complete lifecycle.
            let mut hook = unsafe { install_inline_hook(target_entry, replacement as *const ()) }
                .expect("forced inline installation requires no mprotect")
                .into_parts()
                .0;
            ORIGINAL.store(
                hook.original()
                    .expect("missing forced trampoline")
                    .expose_provenance(),
                Ordering::Release,
            );
            assert_eq!(call(target_entry, -5), 15);

            // SAFETY: the forced call completed and no other thread uses the page.
            unsafe { hook.unhook().expect("forced removal requires no mprotect") };
            assert_eq!(call(target_entry, -5), 5);
        }
        let fds_after = fd_count();
        let mappings_after = mapping_count();
        assert!(
            fds_after <= fds_before,
            "forced lifecycle leaked descriptors: {fds_before} -> {fds_after}"
        );
        assert!(
            mappings_after <= mappings_before,
            "forced lifecycle leaked mappings: {mappings_before} -> {mappings_after}"
        );
        crate::sys::tests::exit_seccomp_child();
    }

    #[test]
    fn installs_and_removes_when_forced_writes_are_denied() {
        // The permission-changing path is independent of `/proc/self/mem`, so
        // rejecting writes to that file cannot affect a normal installation.
        const CHILD: &str = "OMHOOK_INLINE_FORCED_DENIED_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "inline::tests::installs_and_removes_when_forced_writes_are_denied",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }

        let target_entry = abs as *const ();
        // SAFETY: this child excludes target execution and competing writers
        // for the complete lifecycle.
        let mut hook = unsafe { install_inline_hook(target_entry, replacement as *const ()) }
            .expect("denied forced writes must fall back to page elevation")
            .into_parts()
            .0;
        ORIGINAL.store(
            hook.original()
                .expect("missing fallback trampoline")
                .expose_provenance(),
            Ordering::Release,
        );
        assert_eq!(call(target_entry, -6), 16);

        // SAFETY: the fallback call completed and no other thread uses the page.
        unsafe { hook.unhook().expect("fallback removal failed") };
        assert_eq!(call(target_entry, -6), 6);
        crate::sys::tests::exit_seccomp_child();
    }

    #[test]
    fn rejects_chained_hooks_and_allows_removal_then_reinstall() {
        // See `installs_calls_original_and_removes_inline_hook`: page-wide
        // quiescence requires a child that runs this test alone.
        const CHILD: &str = "OMHOOK_INLINE_CHAIN_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "inline::tests::rejects_chained_hooks_and_allows_removal_then_reinstall",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }

        let target_entry = abs as *const ();
        // SAFETY: this test excludes target execution and competing mutation
        // while installing and removing ABI-compatible functions.
        let (mut first, _) = unsafe { install_inline_hook(target_entry, replacement as *const ()) }
            .expect("first inline hook installation failed")
            .into_parts();
        ORIGINAL.store(
            first
                .original()
                .expect("missing original trampoline")
                .expose_provenance(),
            Ordering::Release,
        );

        // SAFETY: the second request names the same target with a different
        // replacement; the registry must reject chaining before any change.
        assert!(matches!(
            unsafe { install_inline_hook(target_entry, prepared_replacement as *const ()) },
            Err(Error::Conflict)
        ));
        assert!(first.is_installed());
        assert_eq!(call(target_entry, -3), 13);

        // SAFETY: all calls above completed and no other thread uses the page.
        unsafe { first.unhook().expect("first removal failed") };
        assert_eq!(call(target_entry, -3), 3);

        // SAFETY: removal restored the entry bytes, so the target is hookable
        // again through an independent handle.
        let (mut second, _) =
            unsafe { install_inline_hook(target_entry, prepared_replacement as *const ()) }
                .expect("reinstalling the removed target failed")
                .into_parts();
        PREPARED_ORIGINAL.store(
            second
                .original()
                .expect("missing retry trampoline")
                .expose_provenance(),
            Ordering::Release,
        );
        assert_eq!(call(target_entry, -4), 14);

        // SAFETY: the retried hook's calls have drained.
        unsafe { second.unhook().expect("second removal failed") };
        assert_eq!(call(target_entry, -4), 4);
    }

    #[test]
    fn prepared_batches_serialize_commit_and_retain_retryable_ownership() {
        // See `installs_calls_original_and_removes_inline_hook`: the commit and
        // both removals drop PROT_EXEC from libc's complete abs page, so the
        // body needs a process where no sibling test is running. The libc
        // target page also cannot contain this crate's mutation code, which
        // would make the installer fault on its own pages.
        const CHILD: &str = "OMHOOK_INLINE_PREPARED_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "inline::tests::prepared_batches_serialize_commit_and_retain_retryable_ownership",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success());
            return;
        }

        let lifecycle = std::sync::RwLock::new(());
        // SAFETY: this test uses the same lock for its complete synthetic
        // lifecycle and performs no loader transition while the lease is live.
        let lease = unsafe { crate::LifecycleReadLease::acquire(&lifecycle) }.unwrap();
        let request = InlineHook::new(abs as *const (), prepared_replacement as *const ());
        // SAFETY: the target is quiescent and both entries remain live and
        // ABI-compatible through commit, calls, and removal.
        let first = unsafe { lease.prepare_inline_hooks(std::slice::from_ref(&request)) }.unwrap();
        // SAFETY: a shared prepare phase changes no target bytes, so a second
        // prepared candidate can coexist under the same lifecycle generation.
        let second = unsafe { lease.prepare_inline_hooks(std::slice::from_ref(&request)) }.unwrap();
        let first_original = first.trampoline(0).unwrap();
        let second_original = second.trampoline(0).unwrap();

        // SAFETY: the target remains quiescent for serialized commit.
        let mut installed = unsafe { first.commit() }.unwrap();
        let mut hook = installed.installed.pop().unwrap();
        assert!(installed.installed.is_empty());
        // SAFETY: the first commit changed the expected target bytes, so the
        // second commit must roll back and retain its unpublished arenas.
        let error = match unsafe { second.commit() } {
            Ok(_) => panic!("second prepared commit unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(matches!(error.error(), Error::Conflict));
        let (_, second) = error.into_parts();

        PREPARED_ORIGINAL.store(first_original.expose_provenance(), Ordering::Release);
        assert_eq!(call(abs as *const (), -2), 12);
        // SAFETY: all calls drained and the same lifecycle lease remains live.
        unsafe { lease.unhook(&mut hook) }.unwrap();
        assert_eq!(call(abs as *const (), -2), 2);

        // SAFETY: removal restored the expected bytes and the same lifecycle
        // generation remains stable and quiescent for retry.
        let mut retried = unsafe { second.commit() }.unwrap();
        let mut retried = retried.installed.pop().unwrap();
        PREPARED_ORIGINAL.store(second_original.expose_provenance(), Ordering::Release);
        assert_eq!(call(abs as *const (), -2), 12);
        // SAFETY: the retried target and trampoline calls have drained.
        unsafe { lease.unhook(&mut retried) }.unwrap();
        PREPARED_ORIGINAL.store(0, Ordering::Release);
        assert_eq!(call(abs as *const (), -2), 2);
    }
}

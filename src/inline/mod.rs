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

#[cfg(target_arch = "aarch64")]
use crate::maps::MappingSnapshot;
#[cfg(target_arch = "aarch64")]
use crate::maps::read_self_maps_for_ranges;
#[cfg(target_arch = "arm")]
use crate::maps::read_self_maps_pathless;
#[cfg(target_arch = "aarch64")]
use crate::maps::read_self_smaps_for_ranges;
use crate::maps::{MapInfo, SmapInfo, extend_self_smaps_for_ranges, page_ranges};
use crate::{Error, HookHandle, Result};
use arena::{Arena, ArenaPlacement};

/// Reserves one near-request executable-arena slot for the next inline request.
///
/// Call this immediately after a module is loaded and before other mappings
/// can consume the nearby address space. The reservation is consumed by the
/// next successful inline-hook preparation that can use it; remove operations
/// retain the mapping so the same process can reinstall without another
/// placement lottery.
pub fn reserve_inline_arena_near(target: usize, length: usize) -> Result<()> {
    arena::reserve_near(target, length)
}
use log::{debug, error, trace, warn};
use patch::CodePage;
#[cfg(target_arch = "aarch64")]
use std::cell::Cell;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex};

const USES_AUXILIARY: bool = cfg!(any(target_arch = "x86", target_arch = "x86_64"));

/// Serializes every test that reads or mutates live inline pages. The inline
/// lifecycle tests and the patch-module symbol audit share it: the audit walks
/// symbol strings on the very pages a sibling PrivateFileValidation test may swap.
#[cfg(test)]
pub(crate) static INLINE_TEST_LOCK: Mutex<()> = Mutex::new(());

/// Entry addresses of inline targets installed in this process.
///
/// Guarded by this mutex; mutations additionally hold `PROCESS_LOCK` for
/// writing. Entries appear after a successful commit and disappear once the
/// target bytes are restored, so a target cannot be chained through a second
/// PltHookRequest with an independent handle. A dropped handle keeps its entry because
/// its hook remains installed. Every stored address is obfuscated and kept in
/// sorted order so the registry does not expose a plaintext list of hooked
/// entries and conflict checks use binary search.
static ACTIVE_INLINE_TARGETS: Mutex<Vec<usize>> = Mutex::new(Vec::new());

/// Resets process-global inline test state after a sibling unwound.
#[cfg(test)]
pub(crate) fn reset_test_state() {
    crate::sys::recover_lock(ACTIVE_INLINE_TARGETS.lock()).clear();
    #[cfg(feature = "plt")]
    crate::plt::tests::reset_state();
    // A sibling may have unwound after arming a one-shot failure. The
    // inline module takes the injection lock only around `body`, so an
    // armed switch outside that region must be cleared explicitly.
    crate::sys::tests::restore_next_protect();
    crate::sys::tests::restore_next_unmap();
    crate::sys::tests::restore_next_map();
    crate::sys::restore_next_map_with_einval();
    crate::sys::tests::restore_exec_regrant();
    crate::sys::tests::restore_next_self_mem_open();
    crate::sys::tests::deny_exec_protect_page(0);
    patch::tests::restore_forced_close_failure();
    patch::tests::restore_forced_write_failure();
    patch::tests::restore_forced_unavailable_failure();
}

fn inline_targets_installed(targets: &[usize]) -> bool {
    let installed = crate::sys::recover_lock(ACTIVE_INLINE_TARGETS.lock());
    targets.iter().any(|target| {
        installed
            .binary_search(&crate::sys::encode_usize(*target))
            .is_ok()
    })
}

fn register_inline_targets(targets: &[usize]) {
    let mut installed = crate::sys::recover_lock(ACTIVE_INLINE_TARGETS.lock());
    if installed.capacity().saturating_sub(installed.len()) < targets.len() {
        crate::sys::fail_stop();
    }
    for target in targets {
        let encoded = crate::sys::encode_usize(*target);
        if let Err(index) = installed.binary_search(&encoded) {
            installed.insert(index, encoded);
        }
    }
}

fn unregister_inline_targets(targets: &[usize]) {
    let mut installed = crate::sys::recover_lock(ACTIVE_INLINE_TARGETS.lock());
    for target in targets {
        let encoded = crate::sys::encode_usize(*target);
        if let Ok(index) = installed.binary_search(&encoded) {
            installed.remove(index);
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
/// logged here: every caller holds the process lock, and this crate keeps the
/// serialized byte-mutation window free of records (preparation-phase records
/// outside that window are covered by the documented caller logger rules).
/// Closes a preparation-time forced-access descriptor, if one is still open.
fn close_preparation_mem_fd(mem: &mut Option<usize>) -> Option<syscalls::Errno> {
    if let Some(fd) = mem.take() {
        return crate::sys::close_self_mem(fd);
    }
    None
}

/// Combines a preparation failure with the errno of a failed descriptor close.
fn preparation_failure(error: Error, close_errno: Option<syscalls::Errno>) -> Error {
    match close_errno {
        Some(errno) => Error::InlineCleanupComposite {
            source: Box::new(error),
            cleanup: Box::new(Error::system_call("close", errno)),
        },
        None => error,
    }
}

/// Resolves the path constraint shared by one batch of requests.
///
/// `None` keeps the documented default: prefer forced access and fall back to
/// page elevation whenever this process cannot use `/proc/self/mem`. A batch
/// that pins both paths at once is unsatisfiable, so it is rejected before any
/// target byte changes.
fn resolve_path_request(
    requests: impl IntoIterator<Item = Option<MutationPath>>,
) -> Result<Option<MutationPath>> {
    let mut resolved = None;
    for request in requests {
        let Some(request) = request else {
            continue;
        };
        match resolved {
            None => resolved = Some(request),
            Some(pinned) if pinned == request => {}
            Some(_) => {
                return Err(Error::InvalidInlineTarget(
                    "conflicting mutation path constraints",
                ));
            }
        }
    }
    Ok(resolved)
}

/// Returns the single path pinned by a group of requests, if any.
///
/// Only callers whose group was already validated by [`resolve_path_request`]
/// use this: preparation rejects a mixed batch, so the first pinned constraint is
/// the whole group's constraint.
fn pinned_path_request(
    requests: impl IntoIterator<Item = Option<MutationPath>>,
) -> Option<MutationPath> {
    requests.into_iter().flatten().next()
}

/// Opens the forced-access descriptor the resolved request needs.
///
/// [`MutationPath::DropExec`] never opens `/proc/self/mem`: a process whose
/// own policy blocks that file would pay for a call that cannot succeed. When
/// the file cannot be opened, a pinned forced path reports the errno while an
/// unconstrained request simply continues to the elevation fallback.
fn forced_access_descriptor(
    request: Option<MutationPath>,
) -> Result<(Option<usize>, Option<syscalls::Errno>)> {
    if matches!(
        request,
        Some(MutationPath::DropExec) | Some(MutationPath::KeepExec)
    ) {
        return Ok((None, None));
    }
    match crate::sys::open_self_mem() {
        Ok(fd) => Ok((Some(fd), None)),
        Err(error) => match request {
            Some(MutationPath::ForcedWrite) => Err(Error::MutationPathUnavailable {
                forced_access: Some(error),
                protection_keeping_exec: None,
                protection: None,
            }),
            _ => Ok((None, Some(error))),
        },
    }
}

fn apply_protection_flags_to(
    hooks: &mut [InlineHookHandle],
    snapshot: Option<&[SmapInfo]>,
) -> Result<()> {
    let mut groups = Vec::new();
    for request in hooks.iter_mut() {
        if matches!(&request.state, InlineState::Active(_)) {
            groups.push(&mut request.pages);
        }
    }
    patch::apply_protection_flags(&mut groups, snapshot)?;
    Ok(())
}

fn pages_may_be_writable_error<'a>(
    pages: impl Iterator<Item = &'a CodePage>,
    source: syscalls::Errno,
    rolled_back: bool,
) -> Error {
    Error::TargetPagesMayBeWritable {
        pages: patch::page_protections(pages),
        source,
        rolled_back,
    }
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

/// One inline request and replacement pair for [`install_inline_hooks`].
#[derive(Clone, Copy)]
pub struct InlineHookRequest {
    target: *const (),
    replacement: *const (),
    require_private_file_pages: bool,
    path_request: Option<MutationPath>,
}

impl InlineHookRequest {
    /// Creates one inline request without validating either pointer.
    ///
    /// Null pointers, executable mappings, ABI compatibility, and instruction
    /// relocatability are checked or remain the caller's responsibility when
    /// the request is passed to [`install_inline_hooks`]. The target page must
    /// be a private read-only executable mapping; shared executable and
    /// writable JIT pages are rejected.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// use omhook::InlineHookRequest;
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
    ///     let _request = InlineHookRequest::new(target as *const (), replacement as *const ());
    /// }
    /// ```
    pub const fn new(target: *const (), replacement: *const ()) -> Self {
        Self {
            target,
            replacement,
            require_private_file_pages: false,
            path_request: None,
        }
    }

    /// Requires every selected target page to be validated.
    ///
    /// A validated mutation requires every selected target page to be a
    /// readable private file mapping, so the patch write stays a private
    /// copy and never reaches the backing file. When PrivateFileValidation is requested
    /// and cannot be performed, installation fails with
    /// [`Error::UnsupportedFeature`] rather than falling back to an
    /// unvalidated in-place write.
    pub const fn require_private_file_pages(mut self) -> Self {
        self.require_private_file_pages = true;
        self
    }

    /// Pins this request to one mutation path.
    ///
    /// The default tries [`MutationPath::ForcedWrite`] first and falls back to
    /// [`MutationPath::KeepExec`] whenever this process cannot use
    /// `/proc/self/mem`. Pinning a path removes that choice:
    ///
    /// - [`MutationPath::ForcedWrite`] never makes a target page
    ///   non-executable. If the channel is unusable the install fails with
    ///   [`Error::MutationPathUnavailable`] instead. The write itself is not
    ///   atomic; whole-page quiescence is still required.
    /// - [`MutationPath::KeepExec`] changes protection but never
    ///   removes `PROT_EXEC`.
    /// - [`MutationPath::DropExec`] never opens `/proc/self/mem` and never
    ///   requests a writable executable page, but it makes the complete target
    ///   page non-executable; see the quiescence chapter of the guide.
    ///
    /// The constraint belongs to the installed handle, so removal honours it
    /// too. A batch that pins both paths is rejected with
    /// [`Error::InvalidInlineTarget`] before any target byte changes.
    pub const fn with_mutation_path(mut self, path: MutationPath) -> Self {
        self.path_request = Some(path);
        self
    }
}

enum InlineState {
    Active(Vec<Arena>),
    CleanupPending(Vec<Arena>),
    Removed,
}

/// Maps a failed arena release onto the crate's cleanup-pending error.
///
/// Every caller reaches this with the request in a correct state: either it was
/// restored, or it was never written. What leaked is an unpublished executable
/// mapping, which is a resource failure the caller can report or retry, not a
/// reason to take the host process down.
pub(super) fn cleanup_pending(error: Error) -> Error {
    match error {
        Error::SystemCall { source, .. } => Error::InlineCleanupPending(source),
        other => other,
    }
}

/// Validates every requested file-backed target page for a validated
/// mutation.
///
/// Returns the validated page starts, or an empty list when no request wants
/// PrivateFileValidation. In-place is the default; only enforced requests are selected.
fn inline_private_file_validation_pages(
    windows: impl IntoIterator<Item = (usize, usize, bool)>,
    maps: &[MapInfo],
    page_size: usize,
    mutation_pages: &[usize],
) -> Result<Vec<(usize, MapInfo)>> {
    // A page containing the running mutation code cannot satisfy whole-page
    // quiescence, so it cannot be selected as an inline target.
    let mut pages: Vec<(usize, crate::maps::MapInfo)> = Vec::new();
    for (patch_address, patch_length, required) in windows {
        if !required {
            continue;
        }
        let patch_end = patch_address
            .checked_add(patch_length)
            .ok_or(Error::ArithmeticOverflow)?;
        let mut page = crate::sys::page_start(patch_address, page_size);
        while page < patch_end {
            if mutation_pages.contains(&page) {
                return Err(Error::UnsupportedFeature(
                    "inline target page contains the mutation code",
                ));
            }
            let map = crate::maps::find_map_containing(maps, page, page_size)
                .filter(|map| {
                    map.is_private
                        && map
                            .perms
                            .contains(crate::MapPerms::READ | crate::MapPerms::EXEC)
                        && !map.perms.contains(crate::MapPerms::WRITE)
                        && map.inode != 0
                        && map.device != crate::DeviceId::new(0, 0)
                })
                .cloned();
            if let Some(map) = map {
                if !pages.iter().any(|(existing, _)| *existing == page) {
                    pages.push((page, map));
                }
            } else {
                return Err(Error::UnsupportedFeature(
                    "inline target page is not a private-file mapping",
                ));
            }
            page = page
                .checked_add(page_size)
                .ok_or(Error::ArithmeticOverflow)?;
        }
    }
    Ok(pages)
}

fn validate_inline_private_file_pages(
    pages: &[(usize, MapInfo)],
    smaps: &[SmapInfo],
    page_size: usize,
) -> Result<Vec<usize>> {
    if pages.is_empty() {
        return Ok(Vec::new());
    }
    let selection = crate::conceal::PageSelection {
        pages,
        smaps,
        page_size,
        reject_executable: false,
    };
    crate::conceal::validate_selection(&selection)
}

/// Prefills replacement BTI state from one smaps snapshot.
///
/// Only hooks whose entry cannot branch directly to the replacement are
/// included; direct branches and direct relays do not need a BTI landing.
#[cfg(target_arch = "aarch64")]
fn prime_replacement_bti_cache(
    analyzed: &mut [AnalyzedInlineHook],
    maps: &[MapInfo],
    smaps: &[SmapInfo],
    page_size: usize,
) -> Result<()> {
    for request in analyzed {
        if request.replacement_bti.cache.get().is_some()
            || arch::branch_reaches(request.analysis.patch_address, request.replacement)
        {
            continue;
        }
        let page = crate::sys::page_start(request.replacement, page_size);
        let map = crate::maps::find_map_containing(maps, request.replacement, 4)
            .filter(|map| map.perms.contains(crate::MapPerms::EXEC))
            .ok_or(Error::MappingChanged)?;
        let identity = MappingSnapshot::from_map(map);
        let entry = smaps
            .iter()
            .find(|entry| entry.map.contains_range(page, page_size))
            .filter(|entry| identity.matches(&entry.map))
            .ok_or(Error::MappingChanged)?;
        request.replacement_bti.cache.set(Some(entry.vm_flags.bti));
    }
    Ok(())
}

unsafe fn release_arenas(arenas: Vec<Arena>) -> std::result::Result<(), (Error, Vec<Arena>)> {
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
        if let Err(error) = unsafe { merged.release() } {
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

/// Installed inline hook and its caller-owned removal record.
///
/// Dropping this value leaves the hook and its executable arenas installed.
/// Use [`HookHandle::unhook`] after quiescing every thread that could execute
/// the request, replacement, or trampoline.
#[must_use = "dropping the handle does not remove the inline hook"]
pub struct InlineHookHandle {
    target_address: usize,
    patch_address: usize,
    original_bytes: Vec<u8>,
    patch_bytes: Vec<u8>,
    trampoline: usize,
    pages: Vec<CodePage>,
    state: InlineState,
    install_mutation_path: MutationPath,
    /// Path the request pinned, honoured again on removal.
    path_request: Option<MutationPath>,
    private_file_validation: crate::PrivateFileValidation,
    sync_core: bool,
    install_cleanup_status: InlineInstallCleanupStatus,
}

/// Installed inline handles in request order, retained until explicit removal.
///
/// Dropping this batch leaves its hooks and executable arenas installed.
#[must_use = "retain the installed handles until explicit removal"]
pub struct InlineHookBatch(Vec<InlineHookHandle>);

impl InlineHookBatch {
    /// Transfers every installed handle to the caller.
    #[must_use = "retain the installed handles until explicit removal"]
    pub fn into_handles(self) -> Vec<InlineHookHandle> {
        self.0
    }
}

impl std::ops::Deref for InlineHookBatch {
    type Target = [InlineHookHandle];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl std::ops::DerefMut for InlineHookBatch {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

/// How an inline mutation reached its request's bytes.
///
/// The default path writes through `/proc/self/mem`, leaving every target page
/// executable. The caller's quiescence proof is therefore always required;
/// there is no non-executable window that turns a violation into a fault.
///
/// If that descriptor is unavailable, the fallback adds `PROT_WRITE` while
/// keeping `PROT_EXEC`; only an explicitly pinned `MutationPath::DropExec` request drops
/// `PROT_EXEC`. Inspect [`InlineHookHandle::install_mutation_path`] to learn which
/// path ran.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MutationPath {
    /// Page protection gained `PROT_WRITE` for the write while keeping
    /// `PROT_EXEC`; target pages stayed executable.
    KeepExec,
    /// Page protection was changed for the write; target pages were not
    /// executable while their bytes changed.
    DropExec,
    /// Bytes were written through `/proc/self/mem`; target pages stayed
    /// executable for the complete write. This is the preferred path on
    /// Android, where an SELinux policy may refuse `execmod` after a page has
    /// been written.
    ForcedWrite,
}

struct PreparedInlineHook {
    target_address: usize,
    patch_address: usize,
    original_bytes: Vec<u8>,
    patch_bytes: Vec<u8>,
    trampoline: usize,
    pages: Vec<CodePage>,
    arenas: Vec<Arena>,
    path_request: Option<MutationPath>,
    require_private_file_pages: bool,
}

/// Transient plaintext view of one installed inline request.
///
/// Dropping a view erases its decoded byte buffers, so no exit path can leak
/// a plaintext copy of the stored material.
#[derive(Clone)]
struct DecodedInlineHook {
    patch_address: usize,
    original_bytes: Vec<u8>,
    patch_bytes: Vec<u8>,
}

impl DecodedInlineHook {
    fn decode(request: &InlineHookHandle) -> Self {
        Self {
            patch_address: crate::sys::decode_usize(request.patch_address),
            original_bytes: crate::sys::decode_bytes(&request.original_bytes),
            patch_bytes: crate::sys::decode_bytes(&request.patch_bytes),
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

    fn into_vec<'a>(mut self) -> Vec<patch::Replacement<'a>> {
        // SAFETY: the pointer, length, and capacity came from one Vec whose
        // element has no drop glue; moving ownership back lets the caller end
        // the borrow before it mutates the referenced pages.
        let replacements = unsafe {
            Vec::from_raw_parts(
                std::ptr::with_exposed_provenance_mut::<patch::Replacement>(
                    self.pointer.expose_provenance(),
                ),
                self.length,
                self.capacity,
            )
        };
        self.pointer = std::ptr::null_mut();
        self.length = 0;
        self.capacity = 0;
        replacements
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
    hooks: Option<Vec<InlineHookHandle>>,
    lease: &'lease crate::LeaseToken,
    /// Descriptor retained by a one-shot direct arena for request mutation.
    mem: Option<usize>,
    /// Fresh maps for a one-shot install that never exposed its prepare phase.
    ///
    /// Two-phase commits keep this empty and perform a fresh final validation.
    validation_maps: Option<Vec<MapInfo>>,
    /// `smaps` snapshot covering every target page, captured once during
    /// preparation and reused by each protection-flag lookup in this batch.
    page_flags: Vec<SmapInfo>,
}

/// Captured protection of a page involved in an inline mutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InlinePageProtection {
    /// Page-aligned start address.
    pub address: usize,
    /// Length in bytes.
    pub length: usize,
    /// Complete protection flags to restore, including architecture extensions.
    pub protection: i32,
}

/// Cleanup status of a successfully published inline mutation.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum InlineInstallCleanupStatus {
    /// Every mutation and cleanup step completed.
    Complete,
    /// The mutation is live, but its forced descriptor failed to close.
    ///
    /// Linux may have released the descriptor anyway; do not retry the close.
    ForcedDescriptorCloseFailed(syscalls::Errno),
    /// The mutation is live, but at least one target page is still writable.
    ///
    /// The page remains executable and the hook is usable. A policy or resource
    /// failure only prevented removing `PROT_WRITE`; the caller must treat that
    /// pages as potentially writable until it verifies or restores every entry.
    /// Permission repair requires the same mapping lifetime, whole-page
    /// quiescence and writer exclusion as the mutation.
    PagesMayBeWritable {
        /// All unique pages involved in this batch, including pages that may
        /// already have been restored. Every handle shares this complete list.
        pages: Arc<[InlinePageProtection]>,
        /// Operating-system error from the first failed protection restore.
        source: syscalls::Errno,
    },
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
        self.hooks.as_ref()?.get(index).map(|request| {
            std::ptr::with_exposed_provenance(crate::sys::decode_usize(request.trampoline))
        })
    }

    /// Serializes and commits the prepared request-byte transaction.
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
    pub unsafe fn commit(self) -> std::result::Result<InlineHookBatch, InlineCommitError<'lease>> {
        // SAFETY: forwarded from this method's complete public contract.
        unsafe { commit_prepared_inline_hooks(self, false) }
    }

    /// Releases every unpublished executable arena without changing a request.
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
    /// ownership record, so the mapping stays live for the rest of the process;
    /// the error reports that leak rather than hiding it.
    pub unsafe fn discard(self) -> Result<()> {
        let PreparedInlineHooks {
            hooks,
            mut mem,
            validation_maps,
            page_flags,
            lease: _,
        } = self;
        let close_errno = close_preparation_mem_fd(&mut mem);
        // SAFETY: forwarded from this method's complete public contract.
        let discarded = unsafe { discard_prepared_inline_hooks(hooks) };
        drop(validation_maps);
        drop(page_flags);
        match (discarded, close_errno) {
            (Ok(()), None) => Ok(()),
            (Err(error), None) => Err(error),
            (Ok(()), Some(errno)) => Err(Error::system_call("close", errno)),
            (Err(source), Some(errno)) => Err(Error::InlineCleanupComposite {
                source: Box::new(source),
                cleanup: Box::new(Error::system_call("close", errno)),
            }),
        }
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
    prepared: Box<PreparedInlineHooks<'lease>>,
}

impl<'lease> InlineCommitError<'lease> {
    /// Commit failure reported after complete byte rollback.
    pub const fn error(&self) -> &Error {
        &self.source
    }

    /// Splits the failure from the retryable prepared batch.
    pub fn into_parts(self) -> (Error, PreparedInlineHooks<'lease>) {
        (self.source, *self.prepared)
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
    require_private_file_pages: bool,
    path_request: Option<MutationPath>,
    #[cfg(target_arch = "aarch64")]
    guarded: bool,
    #[cfg(target_arch = "aarch64")]
    replacement_bti: arch::ReplacementBti,
}

impl InlineHookHandle {
    /// Reports how the installer reached this target's bytes.
    ///
    /// [`MutationPath::ForcedWrite`] means the target pages stayed executable
    /// for the complete write. Nothing is wrong with the installed hook; the
    /// caller's whole-page quiescence proof was required.
    pub const fn install_mutation_path(&self) -> MutationPath {
        self.install_mutation_path
    }

    /// Returns the post-install cleanup state for this handle.
    ///
    /// Every handle from one batch reports the same install_cleanup_status state.
    pub fn install_cleanup_status(&self) -> InlineInstallCleanupStatus {
        self.install_cleanup_status.clone()
    }

    /// Reports whether this installation issued a cross-core instruction-stream
    /// synchronization barrier when publishing the target bytes.
    ///
    /// This is an installation result, not a live capability query. `false`
    /// means the barrier was unavailable; caller quiescence must supply the
    /// cross-core guarantee. Use [`ensure_sync_core_registered`] to probe the
    /// current thread's ability to issue a barrier.
    pub const fn sync_core(&self) -> bool {
        self.sync_core
    }

    #[cfg(test)]
    fn arenas_direct(&self) -> bool {
        match &self.state {
            InlineState::Active(arenas) | InlineState::CleanupPending(arenas) => {
                !arenas.is_empty() && arenas.iter().all(Arena::is_direct)
            }
            InlineState::Removed => false,
        }
    }
}

impl HookHandle for InlineHookHandle {
    fn original(&self) -> Option<*const ()> {
        matches!(self.state, InlineState::Active(_))
            .then(|| std::ptr::with_exposed_provenance(crate::sys::decode_usize(self.trampoline)))
    }

    fn is_installed(&self) -> bool {
        matches!(self.state, InlineState::Active(_))
    }

    fn private_file_validation(&self) -> crate::PrivateFileValidation {
        self.private_file_validation
    }

    unsafe fn unhook(&mut self) -> Result<()> {
        // SAFETY: forwarded from this method's complete public contract.
        unsafe { unhook_inline_hooks(std::slice::from_mut(self)) }
    }
}

/// Returns whether cross-core instruction-stream synchronization is active.
///
/// Registers the private expedited sync-core membarrier once and probes the
/// current thread's ability to issue it on every call. `false` means it was
/// unavailable, so a caller relying on more than its
/// own quiescence discipline must treat every published instruction change as
/// synchronized only on the writing core.
pub fn ensure_sync_core_registered() -> bool {
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
/// target bytes and mapping identities are validated for the complete active
/// batch before any page is changed. Overlapping request ranges are rejected.
/// If an arena cannot be unmapped after successful restoration, its handle
/// remains retryable in cleanup-only state.
///
/// # Errors
///
/// A failure before request restoration leaves affected handles installed and
/// retryable. After restoration, [`Error::InlineCleanupPending`] and
/// [`Error::InlineCleanupComposite`] leave affected handles removed; the former
/// can be retried only to release remaining arenas, while the latter also
/// carries its primary failure. [`Error::TargetPagesMayBeWritable`] reports
/// all pages requiring permission verification or repair. Its `rolled_back`
/// field distinguishes an undone removal with handles still installed from
/// a completed removal with handles removed. [`Error::ForcedMutationRolledBackWithCloseError`]
/// and [`Error::TargetPageProtectionLost`] leave handles installed; the former
/// may be retried, while the latter cannot be repaired by this library.
///
/// # Safety
///
/// The caller must uphold every handle's mapping, quiescence, lifetime,
/// writer-exclusion, and non-reentrancy contract. All calls through the
/// targets, replacements, and trampolines must have drained before entry.
/// Restoration uses the same mutation paths as installation, so the caller
/// must equally exclude concurrent execution of every complete target page,
/// not only of the patched entries. The default and keeping-exec paths leave
/// the page executable; only a handle pinned to `MutationPath::DropExec` drops `PROT_EXEC`.
/// Every path may expose a partial multi-instruction restoration.
pub unsafe fn unhook_inline_hooks(hooks: &mut [InlineHookHandle]) -> Result<()> {
    let active = hooks
        .iter()
        .filter(|request| matches!(&request.state, InlineState::Active(_)))
        .count();
    let arenas = hooks
        .iter()
        .map(|request| match &request.state {
            InlineState::Active(arenas) | InlineState::CleanupPending(arenas) => arenas.len(),
            InlineState::Removed => 0,
        })
        .sum::<usize>();
    if arenas == 0 {
        trace!("inline batch unhook skipped: state=removed");
        return Ok(());
    }
    // Resolve before the mutation window: a batch whose active handles pinned
    // conflicting paths can never be restored as one unit. Handles already
    // removed or awaiting arena cleanup contribute no target bytes, so their
    // historical constraints must not shape this retry.
    let mut path_request = resolve_path_request(
        hooks
            .iter()
            .filter(|request| matches!(&request.state, InlineState::Active(_)))
            .map(|request| request.path_request),
    )?;
    debug!("inline batch unhook requested: hooks={active}, arenas={arenas}");

    let _guard = crate::sys::recover_lock(crate::sys::PROCESS_LOCK.write());
    if matches!(
        path_request,
        Some(MutationPath::DropExec) | Some(MutationPath::KeepExec)
    ) {
        apply_protection_flags_to(hooks, None)?;
    }
    // Decode the only persisted byte copies in place. A failed transaction
    // restores their encoded form before returning a retryable batch.
    //
    // Mark the region: between the two toggles the handles hold their bytes in
    // a form only this call knows how to undo, so a panic here must stay fatal
    // rather than let a retry toggle a second time and corrupt them.
    //
    // The descriptor is opened first: it is a plain `openat` that touches no
    // target page, and returning early here must not leave the handles toggled
    // while the mutation region is still marked.
    let (mut mem, mut forced_open_errno) = if active == 0 {
        (None, None)
    } else {
        forced_access_descriptor(path_request)?
    };
    crate::sys::enter_mutation();
    for request in hooks
        .iter_mut()
        .filter(|request| matches!(&request.state, InlineState::Active(_)))
    {
        crate::sys::toggle_bytes_encoding(&mut request.original_bytes);
        crate::sys::toggle_bytes_encoding(&mut request.patch_bytes);
    }
    let replacements = unhook_replacements(hooks);
    // Keep the allocation alive across the mutation lock without retaining a
    // Rust borrow of `hooks`: its owner was declared before the guard, so
    // unwind and normal return both release the guard before deallocation.
    let replacements = RawReplacementStorage::from_vec(replacements);
    let restored_targets: Vec<usize> = hooks
        .iter()
        .filter(|request| matches!(&request.state, InlineState::Active(_)))
        .map(|request| crate::sys::decode_usize(request.target_address))
        .collect();
    let mut removed_arenas = Vec::with_capacity(hooks.len());
    let mut release_arenas_batch = Vec::with_capacity(arenas);
    let mut arena_pending = vec![false; arenas];
    // Reserve every retry buffer before the first target byte is changed. A
    // failed munmap must not invoke the allocator while that writer is serialized.
    let mut failed_buffers = hooks
        .iter()
        .map(|request| match &request.state {
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
            std::ptr::with_exposed_provenance::<patch::Replacement>(
                replacements.pointer.expose_provenance(),
            ),
            replacements.length,
        );
        // Removal honours the path its handles were installed with, so a
        // request that forbade the non-executable window cannot silently take
        // it on the way out.
        patch::replace_many(replacements, None, mem, path_request, false)
    };
    let mut fallback_forced_access = None;
    let mutation_result =
        if let Err(patch::MutationFailure::ProtectionFlagsRequired { write }) = mutation_result {
            fallback_forced_access = Some(
                forced_open_errno
                    .take()
                    .or(write)
                    .unwrap_or(syscalls::Errno::EIO),
            );
            // End the first mutation window, restore the encoded handle state,
            // capture protection flags, and retry once through the executable
            // fallback.
            drop(replacements.into_vec());
            for request in hooks
                .iter_mut()
                .filter(|request| matches!(&request.state, InlineState::Active(_)))
            {
                crate::sys::toggle_bytes_encoding(&mut request.original_bytes);
                crate::sys::toggle_bytes_encoding(&mut request.patch_bytes);
            }
            crate::sys::leave_mutation();
            if let Err(error) = apply_protection_flags_to(hooks, None) {
                drop(_guard);
                return Err(error);
            }
            path_request = Some(MutationPath::KeepExec);
            mem = None;
            crate::sys::enter_mutation();
            for request in hooks
                .iter_mut()
                .filter(|request| matches!(&request.state, InlineState::Active(_)))
            {
                crate::sys::toggle_bytes_encoding(&mut request.original_bytes);
                crate::sys::toggle_bytes_encoding(&mut request.patch_bytes);
            }
            let replacements = RawReplacementStorage::from_vec(unhook_replacements(hooks));
            unsafe {
                // SAFETY: the raw storage owns the replacement borrow and the
                // caller keeps every target page quiescent.
                let replacements = std::slice::from_raw_parts(
                    std::ptr::with_exposed_provenance::<patch::Replacement>(
                        replacements.pointer.expose_provenance(),
                    ),
                    replacements.length,
                );
                patch::replace_many(replacements, None, mem, path_request, true)
            }
        } else {
            // The first raw storage's replacements were consumed by the
            // mutation above; end its borrow before any handle bytes are
            // toggled or erased again on the non-fallback outcomes.
            drop(replacements.into_vec());
            mutation_result
        };
    let (descriptor_close_errno, left_writable) = match mutation_result {
        Ok(outcome) => (outcome.descriptor_close_errno, outcome.left_writable),
        Err(patch::MutationFailure::Error(error)) => {
            for request in hooks
                .iter_mut()
                .filter(|request| matches!(&request.state, InlineState::Active(_)))
            {
                crate::sys::toggle_bytes_encoding(&mut request.original_bytes);
                crate::sys::toggle_bytes_encoding(&mut request.patch_bytes);
            }
            crate::sys::leave_mutation();
            drop(_guard);
            warn!("inline batch unhook failed: targets_restored=false");
            return Err(error);
        }
        Err(patch::MutationFailure::KeepExecRollback(source)) => {
            for request in hooks
                .iter_mut()
                .filter(|request| matches!(&request.state, InlineState::Active(_)))
            {
                crate::sys::toggle_bytes_encoding(&mut request.original_bytes);
                crate::sys::toggle_bytes_encoding(&mut request.patch_bytes);
            }
            crate::sys::leave_mutation();
            drop(_guard);
            let pages = hooks
                .iter()
                .filter(|request| matches!(&request.state, InlineState::Active(_)))
                .flat_map(|request| &request.pages);
            return Err(pages_may_be_writable_error(pages, source, true));
        }
        Err(patch::MutationFailure::ProtectionFlagsRequired { .. }) => {
            for request in hooks
                .iter_mut()
                .filter(|request| matches!(&request.state, InlineState::Active(_)))
            {
                crate::sys::toggle_bytes_encoding(&mut request.original_bytes);
                crate::sys::toggle_bytes_encoding(&mut request.patch_bytes);
            }
            crate::sys::leave_mutation();
            drop(_guard);
            warn!("inline batch unhook failed: targets_restored=false");
            return Err(Error::UnsupportedFeature(
                "protection flags required after executable fallback",
            ));
        }
        Err(patch::MutationFailure::KeepExec(failure)) => {
            for request in hooks
                .iter_mut()
                .filter(|request| matches!(&request.state, InlineState::Active(_)))
            {
                crate::sys::toggle_bytes_encoding(&mut request.original_bytes);
                crate::sys::toggle_bytes_encoding(&mut request.patch_bytes);
            }
            crate::sys::leave_mutation();
            drop(_guard);
            warn!("inline batch unhook failed: targets_restored=false");
            return Err(Error::MutationPathUnavailable {
                forced_access: fallback_forced_access,
                protection_keeping_exec: Some(failure.errno),
                protection: None,
            });
        }
    };
    let mut first_error = None;
    for (index, request) in hooks.iter_mut().enumerate() {
        let (arenas, restored_target) =
            match std::mem::replace(&mut request.state, InlineState::Removed) {
                InlineState::Active(arenas) => (arenas, true),
                InlineState::CleanupPending(arenas) => (arenas, false),
                InlineState::Removed => continue,
            };
        if restored_target {
            crate::sys::erase_bytes(&mut request.original_bytes);
            crate::sys::erase_bytes(&mut request.patch_bytes);
        }
        release_arenas_batch.extend_from_slice(&arenas);
        removed_arenas.push((index, arenas));
    }
    let Some(&first_arena) = release_arenas_batch.first() else {
        crate::sys::fail_stop();
    };
    let mut merged = first_arena;
    let mut group_start = 0;
    for index in 1..=release_arenas_batch.len() {
        let next = release_arenas_batch.get(index).copied();
        if let Some(combined) = next.and_then(|next| merged.coalesce_with(next)) {
            merged = combined;
            continue;
        }
        // SAFETY: no target reaches these arenas and the caller drained every
        // earlier trampoline call.
        if let Err(error) = unsafe { merged.release() } {
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
        let request = &mut hooks[hook_index];
        let mut failed = std::mem::take(&mut failed_buffers[hook_index]);
        failed.clear();
        for arena in arenas {
            if arena_pending[pending_index] {
                failed.push(*arena);
            }
            pending_index += 1;
        }
        if !failed.is_empty() {
            request.state = InlineState::CleanupPending(failed);
        } else {
            failed_buffers[hook_index] = failed;
        }
    }
    unregister_inline_targets(&restored_targets);
    // Every decoded byte copy has been consumed or erased, so the region opened
    // before the toggle is closed.
    crate::sys::leave_mutation();
    drop(_guard);
    if let Some(source) = left_writable {
        let pages = hooks
            .iter()
            .filter(|request| {
                restored_targets.contains(&crate::sys::decode_usize(request.target_address))
            })
            .flat_map(|request| &request.pages);
        let error = pages_may_be_writable_error(pages, source, false);
        if let Some(cleanup) = first_error {
            return Err(Error::InlineCleanupComposite {
                source: Box::new(error),
                cleanup: Box::new(cleanup),
            });
        }
        return Err(error);
    }
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

fn unhook_replacements(hooks: &[InlineHookHandle]) -> Vec<patch::Replacement<'_>> {
    hooks
        .iter()
        .filter(|request| matches!(&request.state, InlineState::Active(_)))
        .map(|request| {
            let patch_address = crate::sys::decode_usize(request.patch_address);
            patch::Replacement {
                pages: &request.pages,
                address: patch_address,
                end: patch_address
                    .checked_add(request.patch_bytes.len())
                    .unwrap_or_else(|| crate::sys::fail_stop()),
                expected: &request.patch_bytes,
                replacement: &request.original_bytes,
            }
        })
        .collect()
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
/// An x86 entry shorter than five bytes needs its replacement or relay within
/// the two-byte short-jump range; otherwise installation returns
/// [`Error::NoNearbyMemory`] without overwriting the next function.
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
/// request-mutation errors. An error leaves no installed inline request.
/// A request that is already hooked in this process is rejected with
/// [`Error::Conflict`].
///
/// # Page protection
///
/// The default path writes through `/proc/self/mem` and leaves every target
/// page executable; it never depends on restoring `PROT_EXEC` after a write.
/// If that descriptor is unavailable, the fallback keeps `PROT_EXEC` while the
/// page is writable; only an explicitly pinned `MutationPath::DropExec` request removes it.
/// [`InlineHookHandle::install_mutation_path`] reports which
/// path ran. The forced channel cannot publish a multi-instruction entry
/// atomically, so caller quiescence remains the complete guarantee.
///
/// # Safety
///
/// `target` must be a normal callable entry, not an address inside a Thumb IT
/// block. `target` must be on a private read-only executable page, and
/// `replacement` must be a live executable entry with
/// compatible calling conventions and lifetimes. Except for calls or tail calls
/// intentionally entering the exact `target` entry, no control-flow edge may
/// enter the overwritten instruction range from outside it while the hook is
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
) -> Result<InlineHookHandle> {
    let request = InlineHookRequest::new(target, replacement);
    // SAFETY: forwarded from this function's complete public contract.
    let mut installed = unsafe { install_inline_hooks(std::slice::from_ref(&request))? };
    installed.0.pop().ok_or(Error::InvalidInlineTarget(
        "inline installer returned no handle",
    ))
}

/// Installs a transactional inline hook batch in the current process.
///
/// Each request owns one or more executable arenas. The installer validates every
/// mapping and expected target byte before changing any target page, opens each
/// shared target page only once, and rolls the complete byte mutation back on
/// failure. An error returns no installed request.
///
/// # Errors
///
/// Returns pointer, mapping, instruction-relocation, arena-allocation, overlap,
/// or request-mutation errors. Failure rolls back the complete batch.
/// A request that is already hooked in this process is rejected with
/// [`Error::Conflict`].
/// A target page that contains this crate's own page-mutation code is rejected
/// with [`Error::InvalidInlineTarget`] because the drop-exec path must
/// temporarily make the installer non-executable, while the forced path
/// cannot satisfy whole-page quiescence while the installer is running there.
///
/// # Safety
///
/// The complete safety contract of [`install_inline_hook`] applies to every
/// request and to the union of their target pages. request ranges must not
/// overlap. The caller must exclude execution and mutation for the complete
/// batch until this function returns.
pub unsafe fn install_inline_hooks(hooks: &[InlineHookRequest]) -> Result<InlineHookBatch> {
    let token = crate::LeaseToken;
    // One-shot install really holds the write lock across preparation and
    // commit: preparation skips its own read lock, and the commit's `None`
    // guard trusts this one. The snapshot captured during preparation stays
    // authoritative for the commit's validation pass, and no in-crate writer
    // can change the mappings between the two phases.
    let _process_guard = crate::sys::recover_lock(crate::sys::PROCESS_LOCK.write());
    let committed = {
        // SAFETY: forwarded from this function's complete public contract.
        let prepared = unsafe { prepare_inline_hooks_inner(hooks, &token, true)? };
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

fn finish_prepared_hooks<'lease>(
    prepared: Vec<PreparedInlineHook>,
    maps: Vec<MapInfo>,
    validated_page_starts: &[usize],
    lease: &'lease crate::LeaseToken,
    one_shot: bool,
    mem: Option<usize>,
    page_flags: Vec<SmapInfo>,
) -> PreparedInlineHooks<'lease> {
    let page_size = crate::sys::page_size().unwrap_or_else(|_| crate::sys::fail_stop());
    let mut installed = Vec::with_capacity(prepared.len());
    for request in prepared {
        let PreparedInlineHook {
            target_address,
            patch_address,
            mut original_bytes,
            mut patch_bytes,
            trampoline,
            pages,
            arenas,
            path_request,
            ..
        } = request;
        let patch_page_end = patch_address
            .checked_add(patch_bytes.len())
            .unwrap_or_else(|| crate::sys::fail_stop());
        let mut patch_page = crate::sys::page_start(patch_address, page_size);
        let mut all_pages_validated = true;
        while patch_page < patch_page_end {
            if !validated_page_starts.contains(&patch_page) {
                all_pages_validated = false;
                break;
            }
            patch_page = patch_page
                .checked_add(page_size)
                .unwrap_or_else(|| crate::sys::fail_stop());
        }
        let private_file_validation = if all_pages_validated {
            crate::PrivateFileValidation::Validated
        } else {
            crate::PrivateFileValidation::Unvalidated
        };
        installed.push(InlineHookHandle {
            target_address: crate::sys::encode_usize(target_address),
            patch_address: crate::sys::encode_usize(patch_address),
            original_bytes: crate::sys::encode_bytes(&original_bytes),
            patch_bytes: crate::sys::encode_bytes(&patch_bytes),
            trampoline: crate::sys::encode_usize(trampoline),
            pages,
            state: InlineState::Active(arenas),
            install_mutation_path: MutationPath::DropExec,
            path_request,
            private_file_validation,
            sync_core: false,
            install_cleanup_status: InlineInstallCleanupStatus::Complete,
        });
        crate::sys::erase_bytes(&mut original_bytes);
        crate::sys::erase_bytes(&mut patch_bytes);
    }
    PreparedInlineHooks {
        hooks: Some(installed),
        lease,
        mem,
        // A one-shot commit runs under the same write lock that protected this
        // snapshot, so the commit can reuse it instead of re-reading procfs.
        // Two-phase preparation must keep validating against a fresh snapshot
        // because the read lock was released between the phases.
        validation_maps: one_shot.then_some(maps),
        page_flags,
    }
}

fn private_file_validation_is_complete(
    prepared: &[PreparedInlineHook],
    validated_page_starts: &[usize],
    page_size: usize,
) -> Result<bool> {
    for request in prepared {
        if !request.require_private_file_pages {
            continue;
        }
        let patch_end = request
            .patch_address
            .checked_add(request.patch_bytes.len())
            .ok_or(Error::ArithmeticOverflow)?;
        let mut page = crate::sys::page_start(request.patch_address, page_size);
        while page < patch_end {
            if !validated_page_starts.contains(&page) {
                return Ok(false);
            }
            page = page
                .checked_add(page_size)
                .ok_or(Error::ArithmeticOverflow)?;
        }
    }
    Ok(true)
}

pub(crate) unsafe fn prepare_inline_hooks_inner<'lease>(
    hooks: &[InlineHookRequest],
    lease: &'lease crate::LeaseToken,
    one_shot: bool,
) -> Result<PreparedInlineHooks<'lease>> {
    unsafe {
        // SAFETY: the public function forwards its complete contract.
        prepare_inline_hooks_locked(hooks, lease, one_shot)
    }
}

unsafe fn prepare_inline_hooks_locked<'lease>(
    hooks: &[InlineHookRequest],
    lease: &'lease crate::LeaseToken,
    one_shot: bool,
) -> Result<PreparedInlineHooks<'lease>> {
    if hooks.is_empty() {
        trace!("inline hook batch skipped: hooks=0");
        return Ok(PreparedInlineHooks {
            hooks: Some(Vec::new()),
            lease,
            mem: None,
            validation_maps: None,
            page_flags: Vec::new(),
        });
    }
    debug!(
        "inline hook batch requested: hooks={}, arch={}",
        hooks.len(),
        std::env::consts::ARCH
    );
    let normalized = hooks
        .iter()
        .copied()
        .map(normalize_inline_hook)
        .collect::<Result<Vec<_>>>()?;
    // A batch is mutated as one unit on one path, so a mixed constraint can
    // never be satisfied. Reject it before any mapping work or target byte.
    let path_request = resolve_path_request(normalized.iter().map(|request| request.path_request))?;
    for (index, request) in normalized.iter().enumerate() {
        if request.code_address == request.replacement_address
            || normalized[..index]
                .iter()
                .any(|previous| previous.code_address == request.code_address)
        {
            debug!("inline hook batch rejected: reason=duplicate_target");
            return Err(Error::Conflict);
        }
    }
    let batch_targets: Vec<usize> = normalized
        .iter()
        .map(|request| request.code_address)
        .collect();
    if inline_targets_installed(&batch_targets) {
        debug!("inline hook batch rejected: reason=target_already_hooked");
        return Err(Error::Conflict);
    }
    let page_size = crate::sys::page_size()?;
    debug!("inline hook entries validated; entering serialized analysis");

    // A one-shot install already holds the write lock from its entry point;
    // taking the read lock here would be redundant (and, under the writer,
    // deadlock on the same thread). Two-phase preparation still runs under the
    // read lock because its caller exposed no locked window.
    let _guard = if one_shot {
        None
    } else {
        Some(crate::sys::recover_lock(crate::sys::PROCESS_LOCK.read()))
    };
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
    let mutation_pages = patch::mutation_code_pages(page_size);
    if let Err(error) = validate_analyzed_hooks(&analyzed, &mutation_pages) {
        analyzed.clear();
        drop(_guard);
        return Err(error);
    }
    let private_file_validation_pages = inline_private_file_validation_pages(
        analyzed.iter().map(|request| {
            (
                request.analysis.patch_address,
                request.analysis.original.len(),
                request.require_private_file_pages,
            )
        }),
        &maps,
        page_size,
        &mutation_pages,
    )
    .inspect_err(|_| warn!("inline PrivateFileValidation failed: targets_installed=false"))?;
    let mut smaps_pages = private_file_validation_pages
        .iter()
        .map(|(page, _)| *page)
        .collect::<Vec<_>>();
    #[cfg(target_arch = "aarch64")]
    for request in &analyzed {
        if !arch::branch_reaches(request.analysis.patch_address, request.replacement) {
            smaps_pages.push(crate::sys::page_start(request.replacement, page_size));
        }
    }
    if matches!(
        path_request,
        Some(MutationPath::DropExec) | Some(MutationPath::KeepExec)
    ) {
        for request in &analyzed {
            let patch_end = request
                .analysis
                .patch_address
                .checked_add(request.analysis.original.len())
                .ok_or(Error::ArithmeticOverflow)?;
            let mut page = crate::sys::page_start(request.analysis.patch_address, page_size);
            while page < patch_end {
                smaps_pages.push(page);
                page = page
                    .checked_add(page_size)
                    .ok_or(Error::ArithmeticOverflow)?;
            }
        }
    }
    // The analysis snapshot on AArch64 already covers the request, patch, and
    // replacement pages, so it seeds this lookup instead of being read twice.
    // Every other page in `smaps_pages` is extended on demand.
    let mut smaps: Vec<SmapInfo> = Vec::new();
    #[cfg(target_arch = "aarch64")]
    if let Some(entries) = page_flags.as_ref() {
        smaps.extend(entries.iter().cloned());
    }
    if !smaps_pages.is_empty() {
        let mut missing: Vec<usize> = Vec::new();
        for &page in &smaps_pages {
            if !smaps
                .iter()
                .any(|entry| entry.map.contains_range(page, page_size))
            {
                missing.push(page);
            }
        }
        if !missing.is_empty() {
            let ranges = page_ranges(missing)?;
            extend_self_smaps_for_ranges(&mut smaps, &ranges)?;
        }
    }
    let mut validated_page_starts =
        validate_inline_private_file_pages(&private_file_validation_pages, &smaps, page_size)
            .inspect_err(|_| {
                warn!("inline PrivateFileValidation failed: targets_installed=false")
            })?;
    #[cfg(target_arch = "aarch64")]
    prime_replacement_bti_cache(&mut analyzed, &maps, &smaps, page_size)?;

    // The preflight snapshot also covers the arena placement window, so
    // preparation reuses it and pays one procfs query per batch. On
    // NoNearbyMemory the existing fallback still loads the complete layout.
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
                // SAFETY: the captured maps and analyzed batch satisfy the
                // preparation contract.
                prepare_inline_batch(
                    allocation_maps,
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
                .map(|((mut request, arena), mut generated)| {
                    let mut arenas = vec![arena];
                    arenas.extend(generated.auxiliary.take());
                    let original_bytes = std::mem::take(&mut request.analysis.original);
                    let patch_bytes = std::mem::take(&mut generated.patch);
                    let prepared = PreparedInlineHook {
                        target_address: request.code_address,
                        patch_address: request.analysis.patch_address,
                        original_bytes,
                        patch_bytes,
                        trampoline: generated.original,
                        pages: request.pages,
                        arenas,
                        path_request: request.path_request,
                        require_private_file_pages: request.require_private_file_pages,
                    };
                    crate::sys::erase_bytes(&mut generated.bytes);
                    Ok(prepared)
                })
                .collect::<Result<Vec<_>>>()
        } else {
            let mut prepared = Vec::with_capacity(analyzed.len());
            for request in analyzed.drain(..) {
                // SAFETY: no target reaches this unpublished arena.
                match unsafe {
                    prepare_analyzed_inline_hook(
                        allocation_maps,
                        &page_flags,
                        allocation_maps,
                        fallback_maps,
                        request,
                        page_size,
                        mem,
                    )
                } {
                    Ok(request) => {
                        for arena in &request.arenas {
                            arena.record_in(allocation_maps);
                            if let Some(maps) = fallback_maps.as_mut() {
                                arena.record_in(maps);
                            }
                        }
                        prepared.push(request);
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
    // Prefer writing executable arenas through `/proc/self/mem`. Reserved
    // pool pages start RW and gain their final protection before this write.
    // DropExec requests exclude the forced-access descriptor entirely.
    let mut mem = None;
    let prefer_direct_arena = path_request != Some(MutationPath::DropExec);
    if prefer_direct_arena && let Ok(fd) = crate::sys::open_self_mem() {
        mem = Some(fd);
    }
    let mut direct_write_failed = false;
    let prepared = loop {
        let attempt = match prepare(&mut allocation_maps, &mut fallback_maps, &mut analyzed, mem) {
            Ok(prepared) => break prepared,
            Err(error) => error,
        };
        if (!patch::retryable_page_elevation_failure(&attempt)
            && !(mem.is_some() && patch::retryable_direct_arena_write_failure(&attempt)))
            || path_request == Some(MutationPath::DropExec)
        {
            analyzed.clear();
            // The preparation error is already on its way out; a leaked
            // descriptor is logged inside and cannot be reported twice.
            let error = preparation_failure(attempt, close_preparation_mem_fd(&mut mem));
            drop(_guard);
            warn!("inline hook batch preparation failed: targets_installed=false, error={error}");
            return Err(error);
        }
        // A direct arena can be refused by a process that can open but not
        // write `/proc/self/mem`. Drop that descriptor and retry the ordinary
        // RW-to-RX arena path once; a process that started with RW arenas
        // instead retries through the forced channel below.
        let direct_retry = mem.is_some();
        let close_errno = close_preparation_mem_fd(&mut mem);
        if let Some(errno) = close_errno {
            analyzed.clear();
            let error = Error::InlineCleanupComposite {
                source: Box::new(attempt),
                cleanup: Box::new(Error::system_call("close", errno)),
            };
            drop(_guard);
            warn!("inline hook batch preparation failed: targets_installed=false, error={error}");
            return Err(error);
        }
        if direct_retry {
            direct_write_failed = true;
            debug!("inline direct arena write unavailable: retrying_with_rw_arena");
        } else {
            if direct_write_failed {
                analyzed.clear();
                drop(_guard);
                warn!(
                    "inline hook batch preparation failed: targets_installed=false, error={attempt}"
                );
                return Err(attempt);
            }
            match crate::sys::open_self_mem() {
                Ok(fd) => mem = Some(fd),
                Err(_) => {
                    analyzed.clear();
                    drop(_guard);
                    warn!(
                        "inline hook batch preparation failed: targets_installed=false, error={attempt}"
                    );
                    return Err(attempt);
                }
            }
            debug!("inline arena page elevation unavailable: retrying_with_forced_write");
        }
        analyzed.clear();
        analyzed = match analyze_inline_hooks(&maps, &page_flags, &normalized, page_size) {
            Ok(analyzed) => analyzed,
            Err(error) => {
                // The retry owns `mem` from its own `open_self_mem` call, so
                // this early exit must close it like every other failure path.
                let error = preparation_failure(error, close_preparation_mem_fd(&mut mem));
                drop(_guard);
                warn!(
                    "inline hook batch preparation failed: targets_installed=false, error={error}"
                );
                return Err(error);
            }
        };
        if let Err(error) = validate_analyzed_hooks(&analyzed, &mutation_pages) {
            analyzed.clear();
            let error = preparation_failure(error, close_preparation_mem_fd(&mut mem));
            drop(_guard);
            warn!("inline hook batch preparation failed: targets_installed=false, error={error}");
            return Err(error);
        }
        // The rebuilt hooks start with empty replacement-BTI caches; refill
        // them from the snapshot this preparation already read.
        #[cfg(target_arch = "aarch64")]
        if let Err(error) = prime_replacement_bti_cache(&mut analyzed, &maps, &smaps, page_size) {
            let error = preparation_failure(error, close_preparation_mem_fd(&mut mem));
            drop(_guard);
            warn!("inline hook batch preparation failed: targets_installed=false, error={error}");
            return Err(error);
        }
        allocation_maps.clear();
        allocation_maps.extend(maps.iter().cloned());
        fallback_maps = None;
    };
    // Arena placement can expand a near patch into a far patch across pages.
    let final_validation = (|| -> Result<()> {
        validate_replacement_windows(
            prepared
                .iter()
                .map(|request| (request.patch_address, request.patch_bytes.len())),
            normalized.iter().map(|request| request.replacement_address),
        )?;
        if private_file_validation_is_complete(&prepared, &validated_page_starts, page_size)? {
            return Ok(());
        }
        let pages = inline_private_file_validation_pages(
            prepared.iter().map(|request| {
                (
                    request.patch_address,
                    request.patch_bytes.len(),
                    request.require_private_file_pages,
                )
            }),
            &allocation_maps,
            page_size,
            &mutation_pages,
        )?;
        let ranges = page_ranges(pages.iter().map(|(page, _)| *page))?;
        extend_self_smaps_for_ranges(&mut smaps, &ranges)?;
        validated_page_starts = validate_inline_private_file_pages(&pages, &smaps, page_size)?;
        Ok(())
    })()
    .and_then(|()| {
        // Prepared trampolines are callable before commit; one-shot installs
        // instead publish them through the target mutation's full flush.
        if !one_shot && let Some(errno) = crate::sys::sync_instruction_stream(&mut false) {
            return Err(Error::system_call("membarrier", errno));
        }
        Ok(())
    });
    if let Err(error) = final_validation {
        let error = preparation_failure(error, close_preparation_mem_fd(&mut mem));
        // SAFETY: no target reaches any prepared arena.
        let discarded = unsafe { discard_unpublished_inline_hooks(prepared) };
        return Err(preferred_error(error, discarded));
    }
    let retained_mem = if one_shot { mem.take() } else { None };
    let descriptor_close_errno = close_preparation_mem_fd(&mut mem);
    analyzed.clear();
    drop(fallback_maps);
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
    // Build the final ownership record before any target byte can change. The
    // same allocation is retained by a failed commit and returned unchanged.
    Ok(finish_prepared_hooks(
        prepared,
        allocation_maps,
        &validated_page_starts,
        lease,
        one_shot,
        retained_mem,
        smaps,
    ))
}

unsafe fn commit_prepared_inline_hooks<'lease>(
    prepared: PreparedInlineHooks<'lease>,
    one_shot_lock_held: bool,
) -> std::result::Result<InlineHookBatch, InlineCommitError<'lease>> {
    let PreparedInlineHooks {
        hooks,
        lease,
        mem: mut retained_mem,
        validation_maps,
        page_flags,
    } = prepared;
    let Some(mut installed) = hooks else {
        return Ok(InlineHookBatch(Vec::new()));
    };
    if installed.is_empty() {
        return Ok(InlineHookBatch(installed));
    }
    let commit_targets = installed
        .iter()
        .map(|request| crate::sys::decode_usize(request.target_address))
        .collect::<Vec<_>>();
    // SAFETY: `true` is private to the one-shot installer, which holds this
    // write guard across both preparation and commit.
    let _guard = if one_shot_lock_held {
        None
    } else {
        Some(crate::sys::recover_lock(crate::sys::PROCESS_LOCK.write()))
    };
    let mut path_request =
        pinned_path_request(installed.iter().map(|request| request.path_request));
    // A two-phase prepare ran under a read lock, so a competing commit may have
    // installed one of these targets in between. A one-shot prepare ran under
    // this same write guard. The check and insertion below remain serialized in
    // both cases.
    if inline_targets_installed(&commit_targets) {
        drop(_guard);
        drop(validation_maps);
        return Err(InlineCommitError {
            source: Error::Conflict,
            prepared: Box::new(PreparedInlineHooks {
                hooks: Some(installed),
                lease,
                mem: retained_mem,
                validation_maps: None,
                page_flags,
            }),
        });
    }
    if matches!(
        path_request,
        Some(MutationPath::DropExec) | Some(MutationPath::KeepExec)
    ) && let Some(errno) = close_preparation_mem_fd(&mut retained_mem)
    {
        drop(_guard);
        drop(validation_maps);
        return Err(InlineCommitError {
            source: Error::system_call("close", errno),
            prepared: Box::new(PreparedInlineHooks {
                hooks: Some(installed),
                lease,
                mem: None,
                validation_maps: None,
                page_flags,
            }),
        });
    }
    if matches!(
        path_request,
        Some(MutationPath::DropExec) | Some(MutationPath::KeepExec)
    ) && let Err(source) = apply_protection_flags_to(&mut installed, Some(&page_flags))
    {
        drop(_guard);
        drop(validation_maps);
        return Err(InlineCommitError {
            source,
            prepared: Box::new(PreparedInlineHooks {
                hooks: Some(installed),
                lease,
                mem: retained_mem,
                validation_maps: None,
                page_flags,
            }),
        });
    }
    // Built before the first target byte changes: no heap operation happens
    // between opening and closing the mutation pages. All heap-owning fields
    // already belong to `installed`, and these temporaries are released only
    // after the last page is restored.
    let mut decoded = Vec::with_capacity(installed.len());
    for request in &installed {
        decoded.push(DecodedInlineHook::decode(request));
    }
    let replacements = commit_replacements(&installed, &decoded);
    // A two-phase prepare does not hold the process lock any earlier, so its
    // captured maps can be stale by commit time; discard them and let the
    // mutation primitive read a fresh snapshot. A one-shot commit inherits the
    // prepare snapshot: both phases ran under one continuous write lock.
    let validation_maps = if one_shot_lock_held {
        validation_maps
    } else {
        None
    };
    // Reserve before request mutation so successful registration cannot invoke
    // the allocator while the process write lock is held.
    reserve_inline_targets(commit_targets.len());
    // Preparation already rejected a batch that pinned both paths, so the
    // pinned path is the same for every handle here. The prepare phase closed
    // its own descriptor; the commit opens the forced-access channel it needs
    // so a leaked close stays observable, and skips it entirely when the
    // request pinned page elevation.
    let (mem, forced_open_errno) = if let Some(fd) = retained_mem {
        (Some(fd), None)
    } else {
        match forced_access_descriptor(path_request) {
            Ok((mem, forced_open_errno)) => (mem, forced_open_errno),
            Err(source) => {
                drop(_guard);
                drop(validation_maps);
                return Err(InlineCommitError {
                    source,
                    prepared: Box::new(PreparedInlineHooks {
                        hooks: Some(installed),
                        lease,
                        mem: None,
                        validation_maps: None,
                        page_flags,
                    }),
                });
            }
        }
    };
    // SAFETY: the public contract keeps every target page stable and
    // quiescent and excludes competing writers for the complete batch.
    let mut result = unsafe {
        patch::replace_many(
            &replacements,
            validation_maps.as_deref(),
            mem,
            path_request,
            false,
        )
    };
    let mut fallback_forced_access = None;
    if let Err(patch::MutationFailure::ProtectionFlagsRequired { write }) = result {
        fallback_forced_access = Some(forced_open_errno.or(write).unwrap_or(syscalls::Errno::EIO));
        // The forced attempt closed its descriptor and restored every target
        // byte. Capture protection flags outside the mutation window, then
        // retry once through the executable fallback.
        drop(replacements);
        if let Err(source) = apply_protection_flags_to(&mut installed, Some(&page_flags)) {
            drop(_guard);
            drop(validation_maps);
            return Err(InlineCommitError {
                source,
                prepared: Box::new(PreparedInlineHooks {
                    hooks: Some(installed),
                    lease,
                    mem: None,
                    validation_maps: None,
                    page_flags,
                }),
            });
        }
        path_request = Some(MutationPath::KeepExec);
        let replacements = commit_replacements(&installed, &decoded);
        result = unsafe {
            // SAFETY: the decoded target bytes and quiescence contract cover
            // this retry.
            patch::replace_many(
                &replacements,
                validation_maps.as_deref(),
                None,
                path_request,
                true,
            )
        };
    }
    let outcome = match result {
        Ok(outcome) => outcome,
        Err(patch::MutationFailure::Error(source)) => {
            drop(_guard);
            drop(validation_maps);
            return Err(InlineCommitError {
                source,
                prepared: Box::new(PreparedInlineHooks {
                    hooks: Some(installed),
                    lease,
                    mem: None,
                    validation_maps: None,
                    page_flags,
                }),
            });
        }
        Err(patch::MutationFailure::KeepExecRollback(source)) => {
            drop(_guard);
            drop(validation_maps);
            let source = pages_may_be_writable_error(
                installed.iter().flat_map(|request| &request.pages),
                source,
                true,
            );
            return Err(InlineCommitError {
                source,
                prepared: Box::new(PreparedInlineHooks {
                    hooks: Some(installed),
                    lease,
                    mem: None,
                    validation_maps: None,
                    page_flags,
                }),
            });
        }
        Err(patch::MutationFailure::ProtectionFlagsRequired { .. }) => {
            drop(_guard);
            drop(validation_maps);
            return Err(InlineCommitError {
                source: Error::UnsupportedFeature(
                    "protection flags required after executable fallback",
                ),
                prepared: Box::new(PreparedInlineHooks {
                    hooks: Some(installed),
                    lease,
                    mem: None,
                    validation_maps: None,
                    page_flags,
                }),
            });
        }
        Err(patch::MutationFailure::KeepExec(failure)) => {
            drop(_guard);
            drop(validation_maps);
            return Err(InlineCommitError {
                source: Error::MutationPathUnavailable {
                    forced_access: fallback_forced_access,
                    protection_keeping_exec: Some(failure.errno),
                    protection: None,
                },
                prepared: Box::new(PreparedInlineHooks {
                    hooks: Some(installed),
                    lease,
                    mem: None,
                    validation_maps: None,
                    page_flags,
                }),
            });
        }
    };
    let install_mutation_path = outcome.path;
    let sync_core = outcome.sync_core;
    for request in installed.iter_mut() {
        request.install_mutation_path = install_mutation_path;
        request.sync_core = sync_core;
    }
    register_inline_targets(&commit_targets);
    drop(_guard);
    warn_missing_sync_core_once(sync_core);
    let install_cleanup_status = if let Some(source) = outcome.left_writable {
        InlineInstallCleanupStatus::PagesMayBeWritable {
            pages: patch::page_protections(installed.iter().flat_map(|request| &request.pages)),
            source,
        }
    } else {
        match outcome.descriptor_close_errno {
            Some(errno) => InlineInstallCleanupStatus::ForcedDescriptorCloseFailed(errno),
            None => InlineInstallCleanupStatus::Complete,
        }
    };
    for request in &mut installed {
        request.install_cleanup_status = install_cleanup_status.clone();
    }
    Ok(InlineHookBatch(installed))
}

fn commit_replacements<'a>(
    installed: &'a [InlineHookHandle],
    decoded: &'a [DecodedInlineHook],
) -> Vec<patch::Replacement<'a>> {
    installed
        .iter()
        .zip(decoded)
        .map(|(request, decoded)| patch::Replacement {
            pages: &request.pages,
            address: decoded.patch_address,
            end: decoded
                .patch_address
                .checked_add(decoded.original_bytes.len())
                .unwrap_or_else(|| crate::sys::fail_stop()),
            expected: &decoded.original_bytes,
            replacement: &decoded.patch_bytes,
        })
        .collect()
}

struct NormalizedInlineHook {
    replacement: usize,
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    target_entry: usize,
    code_address: usize,
    replacement_address: usize,
    require_private_file_pages: bool,
    path_request: Option<MutationPath>,
}

fn normalize_inline_hook(request: InlineHookRequest) -> Result<NormalizedInlineHook> {
    if request.target.is_null() {
        debug!("inline hook rejected: reason=null_target");
        return Err(Error::NullTarget);
    }
    if request.replacement.is_null() {
        debug!("inline hook rejected: reason=null_replacement");
        return Err(Error::NullReplacement);
    }
    let target = request.target.expose_provenance();
    let replacement = request.replacement.expose_provenance();
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
        replacement,
        #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
        target_entry: target,
        code_address,
        replacement_address,
        require_private_file_pages: request.require_private_file_pages,
        path_request: request.path_request,
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
    for request in hooks {
        addresses.push(request.code_address);
        #[cfg(target_arch = "aarch64")]
        let read_length = arch::FAR_READ_LENGTH;
        #[cfg(not(target_arch = "aarch64"))]
        let read_length = arch::WINDOW_LENGTH;
        addresses.push(
            request
                .code_address
                .checked_add(read_length - 1)
                .ok_or(Error::ArithmeticOverflow)?,
        );
        addresses.push(request.replacement_address);
    }
    // One PROCMAP_QUERY pass covers the request/replacement VMAs and the arena
    // placement window; prepare reuses this snapshot instead of re-querying.
    let target_ranges = page_ranges(addresses)?;
    let window = allocation_window(hooks, crate::sys::page_size()?)?;
    let maps = crate::maps::read_self_maps_for_ordered_ranges_with_window(&target_ranges, window)?;
    #[cfg(not(target_arch = "aarch64"))]
    let page_flags = ();
    // BTI and MTE state lives in `smaps`, not in the `maps` permission bits.
    // Only requests that can need that state pay for the snapshot: validated
    // pages, non-forced mutation paths, guarded landings, and literal relays.
    // A direct forced patch needs neither request nor replacement page flags.
    #[cfg(target_arch = "aarch64")]
    let page_flags = if inline_page_flags_needed(&maps, hooks)? {
        Some(read_self_smaps_for_ranges(&target_ranges)?)
    } else {
        None
    };
    Ok((maps, page_flags))
}

#[cfg(target_arch = "aarch64")]
fn inline_page_flags_needed(maps: &[MapInfo], hooks: &[NormalizedInlineHook]) -> Result<bool> {
    for request in hooks {
        if request.require_private_file_pages
            || matches!(
                request.path_request,
                Some(MutationPath::DropExec) | Some(MutationPath::KeepExec)
            )
        {
            return Ok(true);
        }
        let mut word = [0_u8; 4];
        let length = patch::copy_executable_window(maps, request.code_address, &mut word)?;
        if length < 4 {
            return Ok(true);
        }
        let instruction = u32::from_le_bytes(word);
        if arch::entry_needs_page_flags(instruction)
            || !arch::branch_reaches(request.code_address, request.replacement)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Near-request VMA window used for targeted arena-placement queries.
///
/// A bounded near-request VMA window. `NoNearbyMemory` still falls back to the
/// complete layout, so this only limits the size of the initial query.
#[cfg(not(target_arch = "arm"))]
fn allocation_window(hooks: &[NormalizedInlineHook], page_size: usize) -> Result<(usize, usize)> {
    let Some(first) = hooks.first() else {
        return Ok((0, 0));
    };
    let radius = 2 * 1024 * 1024;
    let low = first
        .code_address
        .checked_sub(radius)
        .map(|address| crate::sys::page_start(address, page_size))
        .unwrap_or(0);
    let high = first
        .code_address
        .checked_add(radius)
        .map(|address| crate::sys::page_start(address, page_size))
        .ok_or(Error::ArithmeticOverflow)?;
    Ok((low, high))
}

/// External relocation limits, optionally intersected with direct-relay ranges.
#[cfg(target_arch = "aarch64")]
fn arena_candidate_window(
    hooks: &[AnalyzedInlineHook],
    page_size: usize,
    prefer_direct: bool,
) -> Result<Option<(usize, usize)>> {
    let mut constrained = false;
    let mut low = 0_usize;
    let mut high = usize::MAX;
    for (index, request) in hooks.iter().enumerate() {
        let window = if request.analysis.far {
            arch::far_branch_window(&request.analysis, request.guarded)
        } else if prefer_direct
            && !arch::branch_reaches(request.analysis.patch_address, request.replacement)
        {
            let distance = arch::max_distance(&request.analysis, request.replacement);
            let patch = request.analysis.patch_address;
            let replacement = request.replacement;
            Some((
                patch
                    .saturating_sub(distance)
                    .max(replacement.saturating_sub(distance)),
                patch
                    .saturating_add(distance)
                    .min(replacement.saturating_add(distance)),
            ))
        } else {
            None
        };
        let Some((hook_low, hook_high)) = window else {
            continue;
        };
        constrained = true;
        let offset = index
            .checked_mul(page_size)
            .ok_or(Error::ArithmeticOverflow)?;
        let Some(hook_high) = hook_high.checked_sub(offset) else {
            return Ok(Some((1, 0)));
        };
        low = low.max(hook_low.saturating_sub(offset));
        high = high.min(hook_high);
    }
    Ok(constrained.then_some((low, high)))
}

fn analyze_inline_hook(
    maps: &[MapInfo],
    page_flags: &patch::PageFlags,
    request: &NormalizedInlineHook,
    page_size: usize,
) -> Result<AnalyzedInlineHook> {
    let mut code = [0; arch::WINDOW_LENGTH];
    let length = patch::copy_executable_window(maps, request.code_address, &mut code);
    let length = match length {
        Ok(length) => length,
        Err(error) => {
            crate::sys::erase_bytes(&mut code);
            return Err(error);
        }
    };
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    let analysis = arch::analyze(request.code_address, &code[..length], maps);
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    let analysis = arch::analyze(request.target_entry, &code[..length]);
    // Keep the stack copy no longer than the decoder needs it. The owned
    // `Analysis` retains its own scrubbed original-byte record when required.
    crate::sys::erase_bytes(&mut code);
    let analysis = analysis?;
    let target_entry_end = analysis
        .patch_address
        .checked_add(analysis.original.len())
        .ok_or(Error::ArithmeticOverflow)?;
    if (request.code_address..target_entry_end).contains(&request.replacement_address) {
        return Err(Error::Conflict);
    }
    if arch::redirects_to(&analysis, request.replacement, maps)? {
        return Err(Error::Conflict);
    }
    #[cfg(target_arch = "aarch64")]
    let replacement_length = 4;
    #[cfg(not(target_arch = "aarch64"))]
    let replacement_length = 1;
    crate::maps::find_map_containing(maps, request.replacement_address, replacement_length)
        .filter(|map| map.perms.contains(crate::maps::MapPerms::EXEC))
        .ok_or(Error::MappingChanged)?;
    #[cfg(target_arch = "aarch64")]
    scan_inline_data_references(&analysis, maps)?;
    #[cfg(target_arch = "aarch64")]
    let (pages, replacement_guarded) = patch::capture_pages(
        maps,
        page_flags,
        analysis.patch_address,
        analysis.original.len(),
        request.replacement,
        page_size,
    )?;
    #[cfg(not(target_arch = "aarch64"))]
    let (pages, _) = patch::capture_pages(
        maps,
        page_flags,
        analysis.patch_address,
        analysis.original.len(),
        request.replacement,
        page_size,
    )?;
    #[cfg(target_arch = "aarch64")]
    let guarded = patch::is_guarded(&pages);
    Ok(AnalyzedInlineHook {
        code_address: request.code_address,
        analysis,
        replacement: request.replacement,
        pages,
        require_private_file_pages: request.require_private_file_pages,
        path_request: request.path_request,
        #[cfg(target_arch = "aarch64")]
        guarded,
        #[cfg(target_arch = "aarch64")]
        replacement_bti: arch::ReplacementBti {
            hint: replacement_guarded,
            cache: Cell::new(None),
        },
    })
}

#[cfg(target_arch = "aarch64")]
fn scan_inline_data_references(analysis: &arch::Analysis, maps: &[MapInfo]) -> Result<()> {
    for reference in &analysis.address_references {
        const LOOKAHEAD: usize = 128;
        let mut scan_maps: Option<Vec<MapInfo>> = None;
        let mut offsets = [None; 32];
        offsets[reference.register as usize] = Some(0_isize);
        let mut scan_start = reference
            .address
            .checked_add(4)
            .ok_or(Error::ArithmeticOverflow)?;
        loop {
            let mut window = [0_u8; LOOKAHEAD];
            let first_chunk = scan_start == reference.address + 4;
            let active_maps = scan_maps.as_deref().unwrap_or(maps);
            let length = match patch::copy_executable_window(active_maps, scan_start, &mut window) {
                Ok(length) => length,
                Err(error) if first_chunk => {
                    crate::sys::erase_bytes(&mut window);
                    return Err(error);
                }
                Err(_) => {
                    let range_end = scan_start
                        .checked_add(LOOKAHEAD)
                        .ok_or(Error::ArithmeticOverflow)?;
                    let fresh_maps = read_self_maps_for_ranges(&[(scan_start, range_end)])?;
                    let has_executable_continuation = fresh_maps.iter().any(|map| {
                        map.contains(scan_start)
                            && map.perms.contains(crate::maps::MapPerms::READ)
                            && map.perms.contains(crate::maps::MapPerms::EXEC)
                    });
                    if !has_executable_continuation {
                        crate::sys::erase_bytes(&mut window);
                        break;
                    }
                    match patch::copy_executable_window(&fresh_maps, scan_start, &mut window) {
                        Ok(length) => {
                            scan_maps = Some(fresh_maps);
                            length
                        }
                        Err(_) => {
                            crate::sys::erase_bytes(&mut window);
                            return Err(Error::UnsupportedFeature(
                                "linear data-reference scan cannot read executable continuation",
                            ));
                        }
                    }
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
            let linear_flow_terminated = arch::linear_flow_terminated(&words[..count]);
            let reference_hit = arch::detect_data_reference_with_offsets(
                &words[..count],
                scan_start,
                &mut offsets,
                reference.target,
                analysis.patch_address,
                analysis
                    .patch_address
                    .checked_add(analysis.original.len())
                    .ok_or(Error::ArithmeticOverflow)?,
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
            // A live alias can access the stolen bytes beyond this window.
            if linear_flow_terminated || offsets.iter().all(Option::is_none) {
                break;
            }
            if length < LOOKAHEAD {
                let boundary = scan_start
                    .checked_add(length)
                    .ok_or(Error::ArithmeticOverflow)?;
                let range_end = boundary
                    .checked_add(LOOKAHEAD)
                    .ok_or(Error::ArithmeticOverflow)?;
                let fresh_maps = read_self_maps_for_ranges(&[(boundary, range_end)])?;
                let has_executable_continuation = fresh_maps.iter().any(|map| {
                    map.contains(boundary)
                        && map.perms.contains(crate::maps::MapPerms::READ)
                        && map.perms.contains(crate::maps::MapPerms::EXEC)
                });
                if !has_executable_continuation {
                    break;
                }
                scan_maps = Some(fresh_maps);
                scan_start = boundary;
                continue;
            }
            scan_start = scan_start
                .checked_add(length)
                .ok_or(Error::ArithmeticOverflow)?;
        }
    }
    Ok(())
}

fn analyze_inline_hooks(
    maps: &[MapInfo],
    page_flags: &patch::PageFlags,
    normalized: &[NormalizedInlineHook],
    page_size: usize,
) -> Result<Vec<AnalyzedInlineHook>> {
    let mut analyzed = Vec::with_capacity(normalized.len());
    for request in normalized {
        match analyze_inline_hook(maps, page_flags, request, page_size) {
            Ok(request) => analyzed.push(request),
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
    mutation_pages: &[usize],
) -> Result<()> {
    // The installer must never execute from a captured page: the drop-exec
    // path makes it non-executable, while the forced path cannot satisfy whole-page
    // quiescence while mutation code is running there. Reject either path.
    if analyzed
        .iter()
        .any(|request| patch::pages_overlap_mutation_code(&request.pages, mutation_pages))
    {
        warn!(
            "inline hook batch rejected: reason=target_page_contains_mutation_code, targets_installed=false"
        );
        return Err(Error::InvalidInlineTarget(
            "target page contains the inline mutation code",
        ));
    }
    validate_replacement_windows(
        analyzed.iter().map(|request| {
            (
                request.analysis.patch_address,
                request.analysis.original.len(),
            )
        }),
        analyzed.iter().map(|request| request.replacement),
    )
}

fn validate_replacement_windows(
    windows: impl Iterator<Item = (usize, usize)>,
    replacements: impl Iterator<Item = usize> + Clone,
) -> Result<()> {
    for (start, length) in windows {
        let end = start.checked_add(length).ok_or(Error::ArithmeticOverflow)?;
        if replacements
            .clone()
            .any(|replacement| (start..end).contains(&replacement))
        {
            debug!(
                "inline hook batch rejected: reason=replacement_overlaps_target, targets_installed=false"
            );
            return Err(Error::Conflict);
        }
    }
    Ok(())
}

fn generate_inline_hook(
    request: &AnalyzedInlineHook,
    address: usize,
    validation_maps: &[MapInfo],
    _allocation_maps: &[MapInfo],
    allow_auxiliary: bool,
    _mem: Option<usize>,
) -> Result<Generated> {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    return arch::generate(
        &request.analysis,
        address,
        request.replacement,
        validation_maps,
        _allocation_maps,
        allow_auxiliary,
        _mem,
    );
    #[cfg(target_arch = "aarch64")]
    return arch::generate(
        &request.analysis,
        address,
        request.replacement,
        validation_maps,
        request.guarded,
        &request.replacement_bti,
        allow_auxiliary,
    );
    #[cfg(target_arch = "arm")]
    arch::generate(
        &request.analysis,
        address,
        request.replacement,
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
        .any(|request| patch::arena_protection(&request.pages) != protection)
    {
        return Err(Error::NoNearbyMemory);
    }
    let length = page_size
        .checked_mul(hooks.len())
        .ok_or(Error::ArithmeticOverflow)?;
    let allocation_distance = hooks
        .iter()
        .map(|request| arch::max_distance(&request.analysis, request.replacement))
        .min()
        .ok_or(Error::NoNearbyMemory)?;
    #[cfg(target_arch = "aarch64")]
    let allowed = arena_candidate_window(hooks, page_size, false)?;
    #[cfg(target_arch = "aarch64")]
    let preferred = arena_candidate_window(hooks, page_size, true)?;
    #[cfg(not(target_arch = "aarch64"))]
    let allowed = None;
    #[cfg(not(target_arch = "aarch64"))]
    let preferred = None;
    let mut attempt = |allow_auxiliary: bool,
                       allowed: Option<(usize, usize)>|
     -> Result<(Arena, Vec<Generated>)> {
        let allocate = |candidate_maps: &[MapInfo]| {
            // SAFETY: MAP_FIXED_NOREPLACE candidates cannot replace an
            // uncaptured mapping, ordinary candidates are hints, and the
            // public contract excludes concurrent mapping changes.
            unsafe {
                Arena::allocate_near(
                    candidate_maps,
                    first.analysis.patch_address,
                    allocation_distance,
                    page_size,
                    length,
                    ArenaPlacement {
                        direct: mem.map(|fd| (protection, fd)),
                        allowed,
                    },
                    |base| {
                        let mut generated = Vec::with_capacity(hooks.len());
                        for (index, request) in hooks.iter().enumerate() {
                            let address = index
                                .checked_mul(page_size)
                                .and_then(|offset| base.checked_add(offset))
                                .ok_or(Error::ArithmeticOverflow)?;
                            match generate_inline_hook(
                                request,
                                address,
                                validation_maps,
                                candidate_maps,
                                allow_auxiliary,
                                mem,
                            ) {
                                Ok(request) => generated.push(request),
                                Err(error) => {
                                    for generated in &mut generated {
                                        crate::sys::erase_bytes(&mut generated.bytes);
                                        crate::sys::erase_bytes(&mut generated.patch);
                                    }
                                    let auxiliaries = generated
                                        .iter_mut()
                                        .filter_map(|request| request.auxiliary.take())
                                        .collect::<Vec<_>>();
                                    // SAFETY: generation failed before any
                                    // entry could reach these unpublished
                                    // auxiliaries.
                                    if let Err((unmap_error, _leaked)) = release_arenas(auxiliaries)
                                    {
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
                    *fallback_maps = Some(crate::maps::read_self_maps_pathless()?);
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
    // every replacement. x86 retries with the auxiliary-bridge layout; the
    // other architectures never map auxiliaries, so they skip the duplicate
    // search and go straight to the unrestricted fallback when needed.
    let direct_relay_only = preferred != allowed;
    let (arena, mut generated) = match attempt(false, preferred) {
        Ok(prepared) => prepared,
        Err(Error::NoNearbyMemory) if USES_AUXILIARY => match attempt(true, preferred) {
            Ok(prepared) => prepared,
            Err(Error::NoNearbyMemory) if direct_relay_only => attempt(true, allowed)?,
            Err(error) => return Err(error),
        },
        Err(Error::NoNearbyMemory) if direct_relay_only => attempt(true, allowed)?,
        Err(error) => return Err(error),
    };

    let prepared = (|| {
        let mut ranges = Vec::with_capacity(generated.len());
        for (index, (request, generated)) in hooks.iter().zip(&generated).enumerate() {
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
            if generated.patch.len() != request.analysis.original.len()
                || generated.patch.is_empty()
                || end > page_end
                || !(start..end).contains(&generated.original)
            {
                return Err(Error::InvalidInlineTarget("invalid generated inline hook"));
            }
            ranges.push((start, end));
        }
        for (index, generated) in generated.iter().enumerate() {
            let offset = index
                .checked_mul(page_size)
                .ok_or(Error::ArithmeticOverflow)?;
            // SAFETY: this disjoint private arena is either RW-owned by this
            // preparation or final-protected and writable only through the
            // matching forced-access descriptor.
            unsafe { arena.write_at(offset, &generated.bytes, mem)? };
        }
        // SAFETY: these live readable ranges remain unpublished until the
        // prepared return or target commit performs process-wide synchronization.
        unsafe { crate::sys::flush_instruction_cache_ranges_local(&ranges)? };
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
                .filter_map(|request| request.auxiliary.take()),
        );
        // SAFETY: no target reaches the unpublished batch or auxiliaries.
        if let Err((unmap_error, _leaked)) = unsafe { release_arenas(arenas) } {
            error!("inline hook cleanup failed: stage=batch_preparation, target_installed=false");
            return Err(cleanup_pending(unmap_error));
        }
        return Err(error);
    }

    Ok((arena.into_pages(page_size), generated))
}

unsafe fn prepare_analyzed_inline_hook(
    validation_maps: &[MapInfo],
    _page_flags: &patch::PageFlags,
    allocation_maps: &[MapInfo],
    fallback_maps: &mut Option<Vec<MapInfo>>,
    mut request: AnalyzedInlineHook,
    page_size: usize,
    mem: Option<usize>,
) -> Result<PreparedInlineHook> {
    let protection = patch::arena_protection(&request.pages);
    #[cfg(target_arch = "aarch64")]
    let allowed = arena_candidate_window(std::slice::from_ref(&request), page_size, false)?;
    #[cfg(target_arch = "aarch64")]
    let preferred = arena_candidate_window(std::slice::from_ref(&request), page_size, true)?;
    #[cfg(not(target_arch = "aarch64"))]
    let allowed = None;
    #[cfg(not(target_arch = "aarch64"))]
    let preferred = None;
    let mut attempt =
        |allow_auxiliary: bool, allowed: Option<(usize, usize)>| -> Result<(Arena, Generated)> {
            let allocate = |candidate_maps: &[MapInfo]| {
                // SAFETY: MAP_FIXED_NOREPLACE candidates cannot replace an
                // uncaptured mapping, ordinary candidates are hints, and the
                // public contract excludes concurrent mapping changes.
                unsafe {
                    Arena::allocate_near(
                        candidate_maps,
                        request.analysis.patch_address,
                        arch::max_distance(&request.analysis, request.replacement),
                        page_size,
                        page_size,
                        ArenaPlacement {
                            direct: mem.map(|fd| (protection, fd)),
                            allowed,
                        },
                        |address| {
                            generate_inline_hook(
                                &request,
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
                        *fallback_maps = Some(crate::maps::read_self_maps_pathless()?);
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
    // by plain relative jumps; only x86 uses the auxiliary-bridge layout.
    let direct_relay_only = preferred != allowed;
    let short_result = match attempt(false, preferred) {
        Ok(prepared) => Ok(prepared),
        Err(Error::NoNearbyMemory) if USES_AUXILIARY => attempt(true, preferred),
        Err(error) => Err(error),
    };
    let short_result = match short_result {
        Ok(prepared) => Ok(prepared),
        Err(Error::NoNearbyMemory) if direct_relay_only => attempt(true, allowed),
        Err(error) => Err(error),
    };
    let (arena, mut generated) = match short_result {
        Ok(prepared) => prepared,
        Err(Error::NoNearbyMemory) => {
            #[cfg(target_arch = "aarch64")]
            if request.analysis.far {
                crate::sys::erase_bytes(&mut request.analysis.original);
                return Err(Error::NoNearbyMemory);
            }
            #[cfg(target_arch = "aarch64")]
            {
                let far_hook = convert_analyzed_inline_hook_to_far(
                    validation_maps,
                    _page_flags,
                    request,
                    page_size,
                )?;
                // SAFETY: the unchanged preparation contract also covers the
                // expanded window; far analysis prevents another conversion.
                return unsafe {
                    prepare_analyzed_inline_hook(
                        validation_maps,
                        _page_flags,
                        allocation_maps,
                        fallback_maps,
                        far_hook,
                        page_size,
                        mem,
                    )
                };
            }
            #[cfg(not(target_arch = "aarch64"))]
            {
                return Err(Error::NoNearbyMemory);
            }
        }
        Err(error) => {
            crate::sys::erase_bytes(&mut request.analysis.original);
            return Err(error);
        }
    };

    let prepared = (|| {
        let generated_end = arena
            .address()
            .checked_add(generated.bytes.len())
            .ok_or(Error::ArithmeticOverflow)?;
        if generated.patch.len() != request.analysis.original.len()
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
        let leaked = unsafe { release_arenas(arenas) };
        crate::sys::erase_bytes(&mut request.analysis.original);
        if let Err((unmap_error, _leaked)) = leaked {
            error!("inline hook cleanup failed: target_installed=false");
            return Err(cleanup_pending(unmap_error));
        }
        return Err(error);
    }

    let mut arenas = vec![arena];
    let auxiliary = generated.auxiliary.take();
    crate::sys::erase_bytes(&mut generated.bytes);
    let original_bytes = std::mem::take(&mut request.analysis.original);
    let patch_bytes = std::mem::take(&mut generated.patch);
    Ok(PreparedInlineHook {
        target_address: request.code_address,
        patch_address: request.analysis.patch_address,
        original_bytes,
        patch_bytes,
        trampoline: generated.original,
        pages: request.pages,
        arenas: {
            arenas.extend(auxiliary);
            arenas
        },
        path_request: request.path_request,
        require_private_file_pages: request.require_private_file_pages,
    })
}

#[cfg(target_arch = "aarch64")]
fn convert_analyzed_inline_hook_to_far(
    validation_maps: &[MapInfo],
    page_flags: &patch::PageFlags,
    mut request: AnalyzedInlineHook,
    page_size: usize,
) -> Result<AnalyzedInlineHook> {
    let mut code = [0; arch::FAR_READ_LENGTH];
    let length = patch::copy_executable_window(validation_maps, request.code_address, &mut code)?;
    // A fast path may have skipped the smaps snapshot because the original
    // entry looked BTI-neutral. Once placement reaches the far fallback, the
    // target page must be re-read instead of treating that absence as proof.
    let live_page_flags;
    let page_flags: &patch::PageFlags = if page_flags.is_some() {
        page_flags
    } else {
        let patch_end = request
            .analysis
            .patch_address
            .checked_add(arch::FAR_READ_LENGTH - 1)
            .ok_or(Error::ArithmeticOverflow)?;
        let ranges = page_ranges([request.analysis.patch_address, patch_end])?;
        live_page_flags = Some(read_self_smaps_for_ranges(&ranges)?);
        &live_page_flags
    };
    let target_guarded = arch::page_bti_guarded(validation_maps, request.analysis.patch_address)?;
    let near_far = !target_guarded
        && arch::branch_reaches(request.analysis.patch_address, request.replacement);
    let analysis = analyze_inplace_far_variant(
        request.code_address,
        &code[..length],
        target_guarded,
        near_far,
    );
    crate::sys::erase_bytes(&mut code);
    let analysis = analysis?;
    let (pages, replacement_guarded) = patch::capture_pages(
        validation_maps,
        page_flags,
        analysis.patch_address,
        analysis.original.len(),
        request.replacement,
        page_size,
    )?;
    request.analysis = analysis;
    request.pages = pages;
    request.guarded = patch::is_guarded(&request.pages);
    request.replacement_bti.hint = replacement_guarded;
    request.replacement_bti.cache.set(None);
    scan_inline_data_references(&request.analysis, validation_maps)?;
    let mutation_pages = patch::mutation_code_pages(page_size);
    validate_analyzed_hooks(std::slice::from_ref(&request), &mutation_pages)?;
    Ok(request)
}

#[cfg(target_arch = "aarch64")]
fn analyze_inplace_far_variant(
    code_address: usize,
    code: &[u8],
    target_guarded: bool,
    near_far: bool,
) -> Result<arch::Analysis> {
    if near_far {
        return arch::analyze_inplace_near_far(code_address, code);
    }
    if !target_guarded {
        return match arch::analyze_inplace_compact_far(code_address, code) {
            Ok(analysis) => Ok(analysis),
            Err(Error::UnsupportedInstruction {
                reason: "AArch64 compact-far jump needs a final terminal or branch",
                ..
            }) => arch::analyze_inplace_far(code_address, code),
            Err(error) => Err(error),
        };
    }
    arch::analyze_inplace_far(code_address, code)
}

/// Releases unpublished arenas, continuing past a failure so one unreleasable
/// mapping cannot strand the rest.
unsafe fn discard_unpublished_inline_hooks(hooks: Vec<PreparedInlineHook>) -> Result<()> {
    let mut first_error = None;
    for mut request in hooks {
        crate::sys::erase_bytes(&mut request.original_bytes);
        crate::sys::erase_bytes(&mut request.patch_bytes);
        // SAFETY: no target reaches these unpublished arenas.
        if let Err((error, _leaked)) = unsafe { release_arenas(request.arenas) } {
            error!("inline hook batch cleanup failed: targets_installed=false");
            first_error.get_or_insert(error);
        }
    }
    match first_error {
        Some(error) => Err(cleanup_pending(error)),
        None => Ok(()),
    }
}

unsafe fn discard_prepared_inline_hooks(hooks: Option<Vec<InlineHookHandle>>) -> Result<()> {
    let Some(hooks) = hooks else {
        return Ok(());
    };
    let mut first_error = None;
    for request in hooks {
        let arenas = match request.state {
            InlineState::Active(arenas) | InlineState::CleanupPending(arenas) => arenas,
            InlineState::Removed => continue,
        };
        // SAFETY: the public discard contract guarantees that no published
        // trampoline call remains in flight.
        if let Err((error, _leaked)) = unsafe { release_arenas(arenas) } {
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
mod tests;

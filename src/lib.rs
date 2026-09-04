#![doc = include_str!("../README.md")]
#![deny(
    missing_docs,
    dead_code,
    unused_must_use,
    unused_imports,
    invalid_value,
    invalid_reference_casting,
    mutable_transmutes,
    deref_nullptr,
    invalid_null_arguments,
    dangerous_implicit_autorefs,
    static_mut_refs,
    unsafe_op_in_unsafe_fn,
    unsafe_attr_outside_unsafe,
    missing_unsafe_on_extern,
    missing_abi,
    improper_ctypes,
    improper_ctypes_definitions,
    named_asm_labels,
    binary_asm_labels,
    asm_sub_register
)]
#![deny(
    clippy::missing_safety_doc,
    clippy::undocumented_unsafe_blocks,
    clippy::not_unsafe_ptr_arg_deref,
    clippy::cast_ptr_alignment,
    clippy::let_underscore_must_use,
    clippy::mut_from_ref,
    clippy::transmute_null_to_fn,
    clippy::no_mangle_with_rust_abi,
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
#![warn(
    unpredictable_function_pointer_comparisons,
    bad_asm_style,
    ffi_unwind_calls,
    clippy::cast_ptr_alignment,
    clippy::missing_transmute_annotations
)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::unreachable,
        clippy::let_underscore_must_use
    )
)]

#[cfg(not(any(target_os = "android", target_os = "linux")))]
compile_error!("Oh My Hook supports only Linux and Android");

#[cfg(not(any(
    all(target_arch = "x86", target_pointer_width = "32"),
    all(target_arch = "x86_64", target_pointer_width = "64"),
    all(target_arch = "arm", target_pointer_width = "32"),
    all(target_arch = "aarch64", target_pointer_width = "64"),
)))]
compile_error!("Oh My Hook supports only i386, amd64, arm32, and arm64 ABIs");

#[cfg(not(target_endian = "little"))]
compile_error!("Oh My Hook supports only little-endian targets");

#[cfg(not(any(feature = "plt", feature = "inline")))]
compile_error!("at least one of the `plt` or `inline` features must be enabled");

#[cfg(all(feature = "inline", target_arch = "arm", not(omhook_arm_v6t2)))]
compile_error!(
    "ARM inline hooks require an armv7 or thumbv7neon request; disable the `inline` feature on older ARM targets"
);

mod conceal;
mod error;
#[cfg(feature = "inline")]
mod inline;
mod maps;
#[cfg(feature = "plt")]
mod plt;
mod sys;

pub use conceal::PrivateFileValidation;
pub use error::{Error, Result, errno_code};
#[cfg(feature = "inline")]
pub use inline::{
    InlineCommitError, InlineHookBatch, InlineHookHandle, InlineHookRequest,
    InlineInstallCleanupStatus, InlinePageProtection, MutationPath, PreparedInlineHooks,
    ensure_sync_core_registered, install_inline_hook, install_inline_hooks,
    reserve_inline_arena_near, unhook_inline_hooks,
};
pub use maps::{DeviceId, MapInfo, MapPerms, read_process_maps, read_self_maps};
#[cfg(feature = "plt")]
pub use plt::{
    ElfImageSelector, GroupInstallError, GroupInstallReport, HookGroupKind, HookInspection,
    ImageInspection, InspectionReport, InspectionStatus, InstallReport, InstallReportParts,
    LoadedImageSnapshot, MutationBudget, OriginalPointerCell, PltHookHandle, PltHookRequest,
    PltHookRequestGroup, RelocationKind, RelocationKinds, SlotSnapshot, StoredValueSelector,
    SymbolQuery, find_loaded_images, inspect_hooks, install_hook, install_hook_groups,
    install_hook_groups_with_budget, install_hook_with_budget, install_hooks,
    install_hooks_with_budget, unhook_hooks,
};
pub use syscalls::Errno;

struct LeaseToken;

/// Caller-provided read lease covering one loaded-image generation.
///
/// This type only proves that a specific caller-selected [`std::sync::RwLock`]
/// read guard remains alive. The library cannot verify that every `dlopen`,
/// `dlclose`, remap, reprotection, or other loader transition in the process
/// actually takes the same lock for writing.
///
/// The required lock order is this lifecycle read lease first, followed by Oh
/// My Hook's internal process lock. A loader transition takes the lifecycle
/// write lock only after all hook work and call drainage for the old generation
/// has finished. It must not re-enter a hook API while holding that write lock.
#[must_use = "the lifecycle read lease must remain alive for the coordinated operation"]
pub struct LifecycleReadLease<'lock> {
    _guard: std::sync::RwLockReadGuard<'lock, ()>,
    _token: LeaseToken,
}

impl<'lock> LifecycleReadLease<'lock> {
    /// Acquires a caller-owned loader lifecycle read lease.
    ///
    /// # Safety
    ///
    /// `lock` must be the single lock used by every cooperating loader
    /// transition affecting the selected images. Each transition must hold its
    /// write guard for the complete `dlopen`, `dlclose`, remap, or reprotection
    /// operation. The caller must retain the underlying loader handle until all
    /// installed hooks are successfully removed and affected calls are drained.
    /// Separate crate copies and foreign writers remain outside this proof.
    pub unsafe fn acquire(lock: &'lock std::sync::RwLock<()>) -> std::sync::LockResult<Self> {
        match lock.read() {
            Ok(guard) => Ok(Self {
                _guard: guard,
                _token: LeaseToken,
            }),
            Err(poisoned) => Err(std::sync::PoisonError::new(Self {
                _guard: poisoned.into_inner(),
                _token: LeaseToken,
            })),
        }
    }

    /// Prepares inline trampolines while borrowing this lifecycle lease.
    ///
    /// The returned value cannot outlive this lease. Preparation is concurrent
    /// with other in-crate preparations; [`PreparedInlineHooks::commit`]
    /// serializes inline target mutation and revalidates mappings and bytes.
    ///
    /// # Safety
    ///
    /// The complete safety contract of [`install_inline_hooks`] applies from
    /// entry until the prepared value is committed or discarded.
    #[cfg(feature = "inline")]
    pub unsafe fn prepare_inline_hooks<'lease>(
        &'lease self,
        hooks: &[InlineHookRequest],
    ) -> Result<PreparedInlineHooks<'lease>> {
        // SAFETY: construction ties the prepared ownership to this live lease;
        // the remaining contract is forwarded to the caller.
        unsafe { inline::prepare_inline_hooks_inner(hooks, &self._token, false) }
    }

    /// Installs a coordinated inline batch while this lease remains held.
    ///
    /// # Safety
    ///
    /// The complete safety contract of [`install_inline_hooks`] applies.
    /// Keep this lease, the cooperating loader handle, and the selected image
    /// generation alive until the returned hooks are successfully unhooked and
    /// all affected calls are drained.
    #[cfg(feature = "inline")]
    pub unsafe fn install_inline_hooks(
        &self,
        hooks: &[InlineHookRequest],
    ) -> Result<InlineHookBatch> {
        // SAFETY: this method only keeps the caller proof live while forwarding
        // the existing installer contract.
        unsafe { inline::install_inline_hooks(hooks) }
    }

    /// Discovers coordinated loaded images while this lease remains held.
    ///
    /// # Safety
    ///
    /// The complete safety contract of [`find_loaded_images`] applies.
    #[cfg(feature = "plt")]
    pub unsafe fn find_loaded_images(
        &self,
        selector: &ElfImageSelector,
    ) -> Result<Vec<LoadedImageSnapshot>> {
        // SAFETY: forwarded with the caller lifecycle read guard held.
        unsafe { plt::find_loaded_images(selector) }
    }

    /// Inspects coordinated PLT hooks while this lease remains held.
    ///
    /// # Safety
    ///
    /// The complete safety contract of [`inspect_hooks`] applies.
    #[cfg(feature = "plt")]
    pub unsafe fn inspect_hooks(&self, hooks: &[PltHookRequest<'_>]) -> Result<InspectionReport> {
        // SAFETY: forwarded with the caller lifecycle read guard held.
        unsafe { plt::inspect_hooks(hooks) }
    }

    /// Installs coordinated PLT hooks while this lease remains held.
    ///
    /// # Safety
    ///
    /// The complete safety contract of [`install_hooks`] applies.
    /// Keep this lease, the cooperating loader handle, and the selected image
    /// generation alive until the returned hooks are successfully unhooked and
    /// all affected calls are drained.
    #[cfg(feature = "plt")]
    pub unsafe fn install_hooks(&self, hooks: &[PltHookRequest<'_>]) -> Result<InstallReport> {
        // SAFETY: forwarded with the caller lifecycle read guard held.
        unsafe { plt::install_hooks(hooks) }
    }

    /// Removes one coordinated hook while this lease remains held.
    ///
    /// # Safety
    ///
    /// The handle's complete removal contract applies. All affected calls must
    /// be quiesced and drained before entry.
    pub unsafe fn unhook<H: HookHandle>(&self, request: &mut H) -> Result<()> {
        // SAFETY: forwarded from this method's complete public contract.
        unsafe { request.unhook() }
    }

    /// Removes a coordinated inline batch while this lease remains held.
    ///
    /// # Safety
    ///
    /// The complete safety contract of [`unhook_inline_hooks`] applies.
    #[cfg(feature = "inline")]
    pub unsafe fn unhook_inline_hooks(&self, hooks: &mut [InlineHookHandle]) -> Result<()> {
        // SAFETY: forwarded with the caller lifecycle read guard held.
        unsafe { inline::unhook_inline_hooks(hooks) }
    }
}

/// Common lifecycle operations for an installed hook.
///
/// Dropping a handle does not restore its hook. Call [`HookHandle::unhook`]
/// explicitly after satisfying the implementation's removal contract.
pub trait HookHandle {
    /// Returns the untyped PLT/GOT original or inline trampoline while usable.
    ///
    /// `None` means no original is currently usable. A PLT handle may return
    /// `Some` containing a null pointer unless installation required a non-null
    /// previous value. Converting, calling, or dereferencing any returned
    /// pointer requires the caller to prove its ABI, provenance, and lifetime.
    fn original(&self) -> Option<*const ()>;

    /// Returns whether the hook still redirects to the replacement.
    fn is_installed(&self) -> bool;

    /// Returns whether target pages satisfied the private-file contract.
    fn private_file_validation(&self) -> crate::conceal::PrivateFileValidation;

    /// Restores the hook and releases resources owned by this handle.
    ///
    /// Calling this method after successful removal is a no-op. An error leaves
    /// the handle retryable unless its documentation explicitly reports that
    /// the target was restored and only resource cleanup remains.
    ///
    /// # Safety
    ///
    /// The caller must uphold the implementation's mapping, quiescence,
    /// lifetime, ABI, writer-exclusion, and non-reentrancy contract.
    ///
    /// # Errors
    ///
    /// A restoration failure normally leaves the handle installed and
    /// retryable. After a successful removal, a failed close of the
    /// forced-access descriptor is reported as an ordinary `close`
    /// system-call error: the hook is already restored and retrying the
    /// removal is a no-op.
    #[cfg_attr(feature = "inline", doc = "")]
    #[cfg_attr(
        feature = "inline",
        doc = "Inline removal reports arena cleanup through [`Error::InlineCleanupPending`] or [`Error::InlineCleanupComposite`]. [`Error::TargetPagesMayBeWritable`] lists every involved page requiring permission verification or repair; `rolled_back` distinguishes an undone removal with the handle still installed from a completed removal. [`Error::ForcedMutationRolledBackWithCloseError`] reports that the removal was undone, leaves the handle installed, and only a descriptor leaked. [`Error::TargetPageProtectionLost`] also leaves the handle installed, but no retry can succeed because the target page is no longer executable."
    )]
    unsafe fn unhook(&mut self) -> Result<()>;
}

#![doc = include_str!("../README.md")]
#![deny(missing_docs)]
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
#![deny(unsafe_op_in_unsafe_fn)]

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
    "ARM inline hooks require an armv7 or thumbv7neon target; disable the `inline` feature on older ARM targets"
);

mod error;
#[cfg(feature = "inline")]
mod inline;
mod maps;
#[cfg(feature = "plt")]
mod plt;
mod sys;

pub use error::{Error, Result};
#[cfg(feature = "inline")]
pub use inline::{
    AppliedInlineHook, InlineCommitError, InlineHook, InlineInstallCompletion,
    InlineInstallOutcome, MutationPath, PreparedInlineHooks, install_inline_hook,
    install_inline_hooks, instruction_stream_sync_capability, unhook_inline_hooks,
};
pub use maps::{DeviceId, MapInfo, MapPerms, read_process_maps, read_self_maps};
#[cfg(feature = "plt")]
pub use plt::{
    AppliedHook, Concealment, GroupInstallError, GroupInstallReport, Hook, HookGroup,
    HookGroupKind, HookInspection, ImageInspection, InspectionReport, InspectionStatus,
    InstallReport, LoadedImage, MutationBudget, OriginalSlot, RelocationKind, RelocationKinds,
    SlotInspection, SlotSelector, SymbolQuery, Target, concealed_mutations_supported,
    find_loaded_images, inspect_hooks, install_hook, install_hook_groups,
    install_hook_groups_with_budget, install_hook_with_budget, install_hooks,
    install_hooks_with_budget, restore_concealed_mutations, set_enforce_concealed_mutations,
    unhook_hooks,
};

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
    /// serializes target mutation and revalidates mappings and bytes.
    ///
    /// # Safety
    ///
    /// The complete safety contract of [`install_inline_hooks`] applies from
    /// entry until the prepared value is committed or discarded.
    #[cfg(feature = "inline")]
    pub unsafe fn prepare_inline_hooks<'lease>(
        &'lease self,
        hooks: &[InlineHook],
    ) -> Result<PreparedInlineHooks<'lease>> {
        // SAFETY: construction ties the prepared ownership to this live lease;
        // the remaining contract is forwarded to the caller.
        unsafe { inline::prepare_inline_hooks_inner(hooks, &self._token) }
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
        hooks: &[InlineHook],
    ) -> Result<inline::InlineInstallOutcome<Vec<AppliedInlineHook>>> {
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
    pub unsafe fn find_loaded_images(&self, target: &Target) -> Result<Vec<LoadedImage>> {
        // SAFETY: forwarded with the caller lifecycle read guard held.
        unsafe { plt::find_loaded_images(target) }
    }

    /// Inspects coordinated PLT hooks while this lease remains held.
    ///
    /// # Safety
    ///
    /// The complete safety contract of [`inspect_hooks`] applies.
    #[cfg(feature = "plt")]
    pub unsafe fn inspect_hooks(&self, hooks: &[Hook<'_>]) -> Result<InspectionReport> {
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
    pub unsafe fn install_hooks(&self, hooks: &[Hook<'_>]) -> Result<InstallReport> {
        // SAFETY: forwarded with the caller lifecycle read guard held.
        unsafe { plt::install_hooks(hooks) }
    }

    /// Removes one coordinated hook while this lease remains held.
    ///
    /// # Safety
    ///
    /// The handle's complete removal contract applies. All affected calls must
    /// be quiesced and drained before entry.
    pub unsafe fn unhook<H: HookHandle>(&self, hook: &mut H) -> Result<()> {
        // SAFETY: forwarded from this method's complete public contract.
        unsafe { hook.unhook() }
    }

    /// Removes a coordinated inline batch while this lease remains held.
    ///
    /// # Safety
    ///
    /// The complete safety contract of [`unhook_inline_hooks`] applies.
    #[cfg(feature = "inline")]
    pub unsafe fn unhook_inline_hooks(&self, hooks: &mut [AppliedInlineHook]) -> Result<()> {
        // SAFETY: forwarded with the caller lifecycle read guard held.
        unsafe { inline::unhook_inline_hooks(hooks) }
    }
}

/// Common lifecycle operations for an installed hook.
///
/// Dropping a handle does not restore its target. Call [`HookHandle::unhook`]
/// explicitly after satisfying the implementation's removal contract.
pub trait HookHandle {
    /// Returns the untyped PLT/GOT original or inline trampoline while usable.
    ///
    /// `None` means no original is currently usable. A PLT handle may return
    /// `Some` containing a null pointer unless installation required a non-null
    /// previous value. Converting, calling, or dereferencing any returned
    /// pointer requires the caller to prove its ABI, provenance, and lifetime.
    fn original(&self) -> Option<*const ()>;

    /// Returns whether the target still redirects to the replacement.
    fn is_installed(&self) -> bool;

    /// Restores the target and releases resources owned by this handle.
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
    /// retryable, including [`Error::ForcedDescriptorLeaked`], which reports
    /// that the removal was undone and only a descriptor leaked. Inline removal
    /// may instead return [`Error::InlineCleanupPending`] after restoring the
    /// target; retrying then releases only the remaining executable arenas.
    /// [`Error::TargetPageProtectionLost`] leaves the handle installed but no
    /// retry can succeed, because the target page is no longer executable.
    unsafe fn unhook(&mut self) -> Result<()>;
}

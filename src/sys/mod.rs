//! Shared raw Linux/Android mutation primitives.
//!
//! Relocation slots are accessed atomically. Page permissions are changed with
//! raw syscalls so installing a hook cannot recurse through a libc PLT entry
//! that is being replaced by the same transaction.

use crate::{Error, Result};
use std::sync::{OnceLock, RwLock};

/// Internal result of a raw syscall wrapper.
///
/// The public `Result` alias belongs to crate errors; syscall plumbing keeps
/// the kernel's `Errno` until an operation decides which public error to
/// report.
pub(crate) type SyscallResult<T> = std::result::Result<T, syscalls::Errno>;

#[cfg(feature = "inline")]
mod inline;
mod mem;
mod opaque;
#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
mod pkey;
#[cfg(feature = "plt")]
mod plt;
mod procmap;

#[cfg(all(feature = "inline", test))]
pub(crate) use inline::tests::{
    fail_next_map, fail_next_map_times, fail_next_map_with_einval, fail_next_unmap,
    restore_next_map_with_einval,
};
#[cfg(feature = "inline")]
pub(crate) use inline::{
    flush_instruction_cache_ranges_checked, flush_instruction_cache_ranges_local,
    map_exec_anonymous, map_rw_anonymous, sync_instruction_stream, sync_instruction_stream_ready,
    unmap,
};
#[cfg(feature = "plt")]
pub(crate) use mem::pread_pointer_self_mem;
#[cfg(any(feature = "inline", test))]
pub(crate) use mem::pwrite_self_mem;
pub(crate) use mem::pwrite_self_mem_checked;
#[cfg(feature = "inline")]
pub(crate) use mem::pwrite64;
pub(crate) use mem::{close_self_mem, open_self_mem};
#[cfg(feature = "inline")]
pub(crate) use opaque::{decode_bytes, encode_bytes, erase_bytes, toggle_bytes_encoding};
pub(crate) use opaque::{decode_usize, encode_usize};
#[cfg(target_arch = "aarch64")]
pub(crate) use pkey::aarch64_por_el0;
#[cfg(all(
    test,
    any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64")
))]
pub(crate) use pkey::tests::PkeyTestRights;
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) use pkey::x86_pkru;
#[cfg(all(feature = "plt", target_arch = "aarch64"))]
pub(crate) use plt::{aarch64_call_bti_landing, aarch64_universal_bti_landing};
#[cfg(feature = "plt")]
pub(crate) use plt::{compare_exchange_pointer, read_pointer, sign_pac_plt, verify_pac_plt};
pub(crate) use procmap::{
    ProcmapQuery, RawProcReader, close as close_procmap, open_self_proc_file, procmap_query,
    procmap_query_unsupported, record_procmap_query_unsupported,
};
pub(crate) static PROCESS_LOCK: RwLock<()> = RwLock::new(());

/// Non-zero while this crate's persistent state or a target's bytes are in a
/// transient form that only the operation in progress knows how to finish.
///
/// A counter rather than a flag because the regions nest: an unhook marks its
/// byte-encoding toggle before calling the mutation primitive, which marks the
/// window again. A flag would let the inner region's exit clear the outer one.
///
/// This is deliberately not an RAII guard. Unwinding through such a region is
/// precisely the case that must stay fatal, and a guard would decrement on the
/// way out and hide it. A panic therefore leaves the count elevated, which
/// keeps the old fail-stop behaviour for exactly that case.
static MUTATION_IN_FLIGHT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

pub(crate) fn enter_mutation() {
    MUTATION_IN_FLIGHT.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
}

pub(crate) fn leave_mutation() {
    // A plain decrement is safe in the direction that matters: an unbalanced
    // one wraps to `usize::MAX`, which still reads as "a region is open" and
    // keeps recovery disabled. Wrapping the other way is what would be
    // dangerous, and cannot happen.
    MUTATION_IN_FLIGHT.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
}

/// Resolves a poisoned lock instead of terminating, unless a mutation region
/// was open when the panic happened.
///
/// A poisoned lock only proves that some caller unwound while holding it. When
/// that happened outside every region marked by [`enter_mutation`], the state
/// this crate owns is whole, and killing the host process over another thread's
/// panic is a far worse outcome than continuing — especially for removal, which
/// is the one operation a caller needs most after something else went wrong.
///
/// The marked regions are what makes that claim true, so they must cover every
/// transient form this crate creates, not only half-written target bytes.
pub(crate) fn recover_lock<T>(result: std::sync::LockResult<T>) -> T {
    match result {
        Ok(value) => value,
        Err(poisoned) => {
            if MUTATION_IN_FLIGHT.load(std::sync::atomic::Ordering::Acquire) != 0 {
                fail_stop();
            }
            poisoned.into_inner()
        }
    }
}

pub(crate) fn page_start(address: usize, page_size: usize) -> usize {
    debug_assert!(page_size.is_power_of_two());
    address & !(page_size - 1)
}

/// Returns the runtime page size, resolved at most once per process.
///
/// The resolver reaches libc, so it runs through the PLT of whichever image is
/// being patched. Caching the first successful answer keeps every later
/// operation — including removal — independent of a caller that replaces
/// `sysconf` in that image. Without the cache a caller who hooks `sysconf`
/// wedges the engine permanently: removal resolves the page size before it
/// touches anything, so the hooks it would remove are exactly what breaks it.
///
/// The page size cannot change while the process runs, so a cached value never
/// goes stale. Failures are not cached; a later call retries the resolver.
pub(crate) static PAGE_SIZE: OnceLock<usize> = OnceLock::new();

pub(crate) fn page_size() -> Result<usize> {
    if let Some(value) = PAGE_SIZE.get() {
        return Ok(*value);
    }
    // SAFETY: sysconf has no pointer arguments and retains no caller state.
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let value = usize::try_from(value).map_err(|_| Error::SystemCall {
        operation: "sysconf(_SC_PAGESIZE)",
        source: syscalls::Errno::last(),
    })?;
    if !value.is_power_of_two() {
        return Err(Error::UnsupportedFeature("non-power-of-two page size"));
    }
    Ok(*PAGE_SIZE.get_or_init(|| value))
}

#[cfg(target_arch = "aarch64")]
pub(crate) struct AArch64MemoryProtectionFeatures {
    pub(crate) bti: bool,
    pub(crate) mte: bool,
}

#[cfg(target_arch = "aarch64")]
static AARCH64_HWCAP2: OnceLock<libc::c_ulong> = OnceLock::new();

#[cfg(target_arch = "aarch64")]
pub(crate) fn aarch64_memory_protection_features() -> AArch64MemoryProtectionFeatures {
    const HWCAP2_BTI: libc::c_ulong = 1 << 17;
    const HWCAP2_MTE: libc::c_ulong = 1 << 18;

    // SAFETY: getauxval has no pointer arguments for AT_HWCAP2.
    let features = *AARCH64_HWCAP2.get_or_init(|| unsafe { libc::getauxval(libc::AT_HWCAP2) });
    AArch64MemoryProtectionFeatures {
        bti: features & HWCAP2_BTI != 0,
        mte: features & HWCAP2_MTE != 0,
    }
}

#[cfg(target_arch = "aarch64")]
#[cfg(any(feature = "plt", test))]
pub(crate) fn aarch64_bti_supported() -> bool {
    aarch64_memory_protection_features().bti
}

/// Changes protection for an exact page-aligned mapped range.
///
/// # Safety
///
/// The range must remain mapped and must not be concurrently unmapped,
/// remapped, or reprotected.
pub(crate) unsafe fn protect(address: usize, length: usize, protection: i32) -> Result<()> {
    let checked = unsafe {
        // SAFETY: the public function contract covers this exact range.
        protect_checked(address, length, protection)
    };
    match checked {
        Some(errno) => Err(Error::system_call("mprotect", errno)),
        None => Ok(()),
    }
}

/// `protect` without `Result` construction for the inline mutation window.
///
/// Dropping a `Result` calls compiler-generated drop glue that the linker may
/// place on a page the window makes temporarily non-executable, so callers
/// inside that window must use this `Copy`-returning form instead.
///
/// # Safety
///
/// The same contract as [`protect`] applies.
pub(crate) unsafe fn protect_checked(
    address: usize,
    length: usize,
    protection: i32,
) -> Option<syscalls::Errno> {
    #[cfg(test)]
    if tests::FAIL_NEXT_PROTECT.swap(false, std::sync::atomic::Ordering::AcqRel) {
        return Some(syscalls::Errno::EPERM);
    }
    #[cfg(test)]
    if protection & libc::PROT_EXEC != 0
        && address == tests::DENY_EXEC_PROTECT_PAGE.load(std::sync::atomic::Ordering::Acquire)
    {
        return Some(syscalls::Errno::EACCES);
    }
    #[cfg(test)]
    if protection & libc::PROT_WRITE == 0
        && (address
            == tests::DENY_PROTECT_RESTORE_PAGES[0].load(std::sync::atomic::Ordering::Acquire)
            || address
                == tests::DENY_PROTECT_RESTORE_PAGES[1].load(std::sync::atomic::Ordering::Acquire))
    {
        return Some(syscalls::Errno::EACCES);
    }
    #[cfg(test)]
    if protection & libc::PROT_EXEC != 0
        && address == tests::DENY_EXEC_REGRANT_PAGE.load(std::sync::atomic::Ordering::Acquire)
        && tests::EXEC_REGRANT_PROTECTION.load(std::sync::atomic::Ordering::Acquire)
            & libc::PROT_EXEC as usize
            == 0
    {
        return Some(syscalls::Errno::EACCES);
    }
    #[cfg(test)]
    if protection & libc::PROT_EXEC == 0 {
        tests::SAW_NON_EXEC_PROTECT.store(true, std::sync::atomic::Ordering::Release);
    } else if protection & libc::PROT_WRITE == 0
        && tests::SAW_NON_EXEC_PROTECT.swap(false, std::sync::atomic::Ordering::AcqRel)
        && tests::FAIL_NEXT_EXEC_REGRANT.load(std::sync::atomic::Ordering::Acquire)
    {
        return Some(syscalls::Errno::EACCES);
    }
    // SAFETY: the caller guarantees a live page-aligned range and a protection
    // bitset valid for this target kernel.
    let result = unsafe {
        syscalls::syscall!(
            syscalls::Sysno::mprotect,
            address,
            length,
            protection as usize
        )
    };
    if result.is_ok() {
        #[cfg(test)]
        if address == tests::DENY_EXEC_REGRANT_PAGE.load(std::sync::atomic::Ordering::Acquire) {
            tests::EXEC_REGRANT_PROTECTION
                .store(protection as usize, std::sync::atomic::Ordering::Release);
        }
        return None;
    }
    result.err()
}

/// Terminates the process without calling a hookable libc function.
#[cold]
pub(crate) fn fail_stop() -> ! {
    // Every syscall in this fallback chain is attempted at most once. A
    // SECCOMP_RET_USER_NOTIF supervisor can still keep any one call blocked;
    // no in-process fallback can run until such a syscall returns.
    unsafe {
        // SAFETY: exit_group has no pointer arguments and a successful call
        // terminates the complete thread group.
        let _ignored = syscalls::syscall!(syscalls::Sysno::exit_group, 134).is_err();

        // Raw syscall errors are negative errno values encoded as usize. Never
        // pass one through as a negative PID with process-group semantics.
        let pid = syscalls::syscall!(syscalls::Sysno::getpid).unwrap_or(0);
        if let Some(pid) = process_identifier(pid) {
            let _ignored =
                syscalls::syscall!(syscalls::Sysno::kill, pid, libc::SIGKILL as usize).is_err();

            // Reached only when kill returned. Keep both identifiers range-
            // checked before asking the kernel to signal this exact thread.
            let tid = syscalls::syscall!(syscalls::Sysno::gettid).unwrap_or(0);
            if let Some(tid) = process_identifier(tid) {
                let _ignored =
                    syscalls::syscall!(syscalls::Sysno::tgkill, pid, tid, libc::SIGKILL as usize)
                        .is_err();
            }
        }
    }

    loop {
        // SAFETY: these instructions have defined trap behavior and do not
        // invoke Rust undefined behavior. The loop covers a SIGILL handler
        // which returns after advancing the instruction pointer.
        unsafe {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            core::arch::asm!("ud2", options(nomem, nostack));

            #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
            core::arch::asm!("udf #0", options(nomem, nostack));
        }
    }
}

const fn process_identifier(raw: usize) -> Option<usize> {
    if raw >= 1 && raw <= i32::MAX as usize {
        Some(raw)
    } else {
        None
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    pub(crate) static FAIL_NEXT_PROTECT: AtomicBool = AtomicBool::new(false);

    pub(crate) static DENY_EXEC_PROTECT_PAGE: AtomicUsize = AtomicUsize::new(0);

    pub(crate) static DENY_EXEC_REGRANT_PAGE: AtomicUsize = AtomicUsize::new(0);

    pub(crate) static EXEC_REGRANT_PROTECTION: AtomicUsize = AtomicUsize::new(0);

    pub(crate) static FAIL_NEXT_EXEC_REGRANT: AtomicBool = AtomicBool::new(false);

    pub(crate) static SAW_NON_EXEC_PROTECT: AtomicBool = AtomicBool::new(false);

    pub(crate) static DENY_PROTECT_RESTORE_PAGES: [AtomicUsize; 2] =
        [const { AtomicUsize::new(0) }; 2];

    /// Serializes every test that arms a process-global syscall injection.
    ///
    /// The injected flags are one-shot and process-wide; without one common
    /// lock, a sibling can consume another test's planned failure.
    pub(crate) static SYSCALL_INJECTION_LOCK: Mutex<()> = Mutex::new(());

    /// Refuses to grant `PROT_EXEC` on one exact page for the rest of this
    /// process.
    ///
    /// This reproduces a policy that refuses to grant `PROT_EXEC` on one page.
    /// It is deliberately narrower than SELinux `execmod` (which keys on the
    /// COW state rather than the requested bits): the automatic fallback now
    /// keeps `PROT_EXEC`, so only an explicit drop-exec request can reach the
    /// lost-protection branch.
    #[cfg(feature = "inline")]
    pub(crate) fn deny_exec_protect_page(page_start: usize) {
        DENY_EXEC_PROTECT_PAGE.store(page_start, Ordering::Release);
    }

    /// Simulates SELinux `execmod` on one page.
    ///
    /// `current_protection` seeds the page's protection before the first
    /// intercepted `mprotect`. A request that adds `PROT_EXEC` to a page whose
    /// tracked protection lacks it fails with `EACCES`; keeping `PROT_EXEC`
    /// while adding `PROT_WRITE` succeeds and the later restore also succeeds.
    #[cfg(feature = "inline")]
    pub(crate) fn deny_exec_regrant(page_start: usize, current_protection: i32) {
        DENY_EXEC_REGRANT_PAGE.store(page_start, Ordering::Release);
        EXEC_REGRANT_PROTECTION.store(current_protection as usize, Ordering::Release);
    }

    #[cfg(feature = "inline")]
    pub(crate) fn restore_exec_regrant() {
        DENY_EXEC_REGRANT_PAGE.store(0, Ordering::Release);
        EXEC_REGRANT_PROTECTION.store(0, Ordering::Release);
        FAIL_NEXT_EXEC_REGRANT.store(false, Ordering::Release);
        SAW_NON_EXEC_PROTECT.store(false, Ordering::Release);
    }

    /// Simulates the next drop-exec/restore sequence being refused by
    /// `execmod`, regardless of which temporary page a preflight probe uses.
    #[cfg(feature = "inline")]
    pub(crate) fn fail_next_exec_regrant() {
        FAIL_NEXT_EXEC_REGRANT.store(true, Ordering::Release);
        SAW_NON_EXEC_PROTECT.store(false, Ordering::Release);
    }

    /// Rejects exactly the next `mprotect` this crate issues.
    ///
    /// Denying `mprotect` through a seccomp filter is not portable across
    /// libc builds: 32-bit bionic's exit machinery mprotects its atexit array,
    /// enters its fatal path when that fails, and deadlocks. This injection
    /// point reproduces the engine-visible permission failure without
    /// touching any other caller in the process.
    pub(crate) fn fail_next_protect() {
        FAIL_NEXT_PROTECT.store(true, Ordering::Release);
    }

    pub(crate) fn restore_next_protect() {
        FAIL_NEXT_PROTECT.store(false, Ordering::Release);
        deny_protect_restore_pages([0, 0]);
    }

    /// Refuses to remove `PROT_WRITE` from up to two exact pages.
    ///
    /// The keeping-exec path adds `PROT_WRITE` while keeping `PROT_EXEC`; this
    /// injection fails only the restore, so the mutation stays live and the
    /// page remains executable.
    pub(crate) fn deny_protect_restore_pages(pages: [usize; 2]) {
        DENY_PROTECT_RESTORE_PAGES[0].store(pages[0], Ordering::Release);
        DENY_PROTECT_RESTORE_PAGES[1].store(pages[1], Ordering::Release);
    }

    pub(crate) static FAIL_NEXT_SELF_MEM_OPEN: AtomicUsize = AtomicUsize::new(0);

    /// Rejects exactly the next `/proc/self/mem` open.
    ///
    /// This is the failure a real process hits when its own policy blocks that
    /// file: SELinux on a vendor domain, a seccomp filter, or a descriptor
    /// limit. It is separate from refusing the write, because the two are
    /// reported by different calls and a test of the fallback has to exercise
    /// the one the caller actually sees.
    pub(crate) fn fail_next_self_mem_open() {
        FAIL_NEXT_SELF_MEM_OPEN.store(1, Ordering::Release);
    }

    #[cfg(feature = "inline")]
    pub(crate) fn fail_next_self_mem_open_times(count: usize) {
        FAIL_NEXT_SELF_MEM_OPEN.store(count, Ordering::Release);
    }

    pub(crate) fn restore_next_self_mem_open() {
        FAIL_NEXT_SELF_MEM_OPEN.store(0, Ordering::Release);
    }

    pub(crate) fn take_self_mem_open_failure() -> bool {
        let mut current = FAIL_NEXT_SELF_MEM_OPEN.load(Ordering::Acquire);
        while current > 0 {
            match FAIL_NEXT_SELF_MEM_OPEN.compare_exchange(
                current,
                current - 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => current = actual,
            }
        }
        false
    }

    pub(crate) fn self_mem_open_failure_pending() -> bool {
        FAIL_NEXT_SELF_MEM_OPEN.load(Ordering::Acquire) > 0
    }

    pub(crate) static FAIL_NEXT_SELF_MEM_WRITE: AtomicBool = AtomicBool::new(false);

    /// Rejects exactly the next `/proc/self/mem` write.
    ///
    /// The file opens, but the write itself is refused: this is the channel
    /// denial a seccomp filter or an LSM can produce after a successful open,
    /// which is distinct from the open denial above.
    #[cfg(feature = "plt")]
    pub(crate) fn fail_next_self_mem_write() {
        FAIL_NEXT_SELF_MEM_WRITE.store(true, Ordering::Release);
    }

    #[cfg(feature = "plt")]
    pub(crate) fn restore_next_self_mem_write() {
        FAIL_NEXT_SELF_MEM_WRITE.store(false, Ordering::Release);
    }

    pub(crate) fn take_self_mem_write_failure() -> bool {
        FAIL_NEXT_SELF_MEM_WRITE.swap(false, Ordering::AcqRel)
    }

    /// Whether this kernel allows forced writes through `/proc/self/mem` into
    /// read-only executable pages.
    ///
    /// The probe writes the marker's existing bytes back, so it cannot change
    /// behavior. Kernels configured with `CONFIG_PROC_MEM_FORCE_PTRACE` refuse
    /// the write because a task is never its own ptracer; forced-only
    /// assertions cannot hold there.
    pub(crate) fn forced_writes_supported() -> bool {
        use std::sync::OnceLock;

        static SUPPORTED: OnceLock<bool> = OnceLock::new();
        *SUPPORTED.get_or_init(|| {
            let Ok(fd) = crate::sys::open_self_mem() else {
                return false;
            };
            let address = probe_marker as *const () as usize;
            // SAFETY: the marker is live and readable for the complete probe.
            let word = unsafe {
                std::ptr::read_unaligned(std::ptr::with_exposed_provenance::<u32>(address))
            };
            let bytes = word.to_ne_bytes();
            // SAFETY: the write restores the identical bytes in one live
            // private executable mapping.
            let refused = unsafe { crate::sys::pwrite_self_mem(fd, address, &bytes).is_err() };
            let _ = crate::sys::close_self_mem(fd);
            !refused
        })
    }

    #[inline(never)]
    fn probe_marker() {}

    #[cfg(feature = "inline")]
    pub(crate) use super::inline::tests::{
        FAIL_NEXT_SYNC, SYNC_CORE_ISSUES, restore_next_map, restore_next_unmap,
    };

    #[test]
    fn page_start_uses_the_runtime_power_of_two_alignment() {
        assert_eq!(page_start(0x2345, 0x1000), 0x2000);
    }

    #[test]
    fn poisoned_lock_recovers_outside_a_mutation_window() {
        // Another caller unwound while holding a lock. Nothing this crate owns
        // is half-written, so taking the host process down over it would be a
        // worse outcome than continuing -- removal especially must stay usable.
        #[cfg(feature = "inline")]
        let _inline_guard = crate::sys::recover_lock(crate::inline::INLINE_TEST_LOCK.lock());
        let _syscall_guard = recover_lock(tests::SYSCALL_INJECTION_LOCK.lock());
        #[cfg(feature = "plt")]
        let _process_guard = crate::sys::recover_lock(crate::plt::tests::PROCESS_TEST_LOCK.lock());
        let lock = std::sync::Mutex::new(7_u32);
        let guard = lock.lock().expect("lock is not poisoned");
        let recovered = recover_lock(Err(std::sync::PoisonError::new(guard)));
        assert_eq!(*recovered, 7);
    }

    #[test]
    fn leaving_a_mutation_window_restores_poison_recovery() {
        // The open window makes any sibling suite's poisoned lock a
        // fail-stop. Serialize against every lock-holding suite first.
        #[cfg(feature = "inline")]
        let _inline_guard = crate::sys::recover_lock(crate::inline::INLINE_TEST_LOCK.lock());
        let _syscall_guard = recover_lock(tests::SYSCALL_INJECTION_LOCK.lock());
        #[cfg(feature = "plt")]
        let _process_guard = crate::sys::recover_lock(crate::plt::tests::PROCESS_TEST_LOCK.lock());
        enter_mutation();
        leave_mutation();
        let lock = std::sync::Mutex::new(1_u32);
        let guard = lock.lock().expect("lock is not poisoned");
        let recovered = recover_lock(Err(std::sync::PoisonError::new(guard)));
        assert_eq!(*recovered, 1);
    }

    #[test]
    fn nested_mutation_regions_need_every_exit() {
        // An unhook marks its byte-encoding toggle and then calls the mutation
        // primitive, which marks the window again. Recovery must stay disabled
        // until both exits have run, so the inner exit alone cannot re-enable
        // it; this test pins that the counter comes back down.
        #[cfg(feature = "inline")]
        let _inline_guard = crate::sys::recover_lock(crate::inline::INLINE_TEST_LOCK.lock());
        let _syscall_guard = recover_lock(tests::SYSCALL_INJECTION_LOCK.lock());
        #[cfg(feature = "plt")]
        let _process_guard = crate::sys::recover_lock(crate::plt::tests::PROCESS_TEST_LOCK.lock());
        enter_mutation();
        enter_mutation();
        leave_mutation();
        leave_mutation();
        let lock = std::sync::Mutex::new(5_u32);
        let guard = lock.lock().expect("lock is not poisoned");
        let recovered = recover_lock(Err(std::sync::PoisonError::new(guard)));
        assert_eq!(*recovered, 5);
    }

    #[test]
    fn process_identifiers_reject_raw_errno_and_broad_kill_values() {
        assert_eq!(process_identifier(1), Some(1));
        assert_eq!(
            process_identifier(i32::MAX as usize),
            Some(i32::MAX as usize)
        );
        assert_eq!(process_identifier(0), None);
        assert_eq!(process_identifier(i32::MAX as usize + 1), None);
        assert_eq!(process_identifier((-libc::EPERM as isize) as usize), None);
        assert_eq!(process_identifier(usize::MAX), None);
    }
}

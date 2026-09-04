//! Shared raw Linux/Android mutation primitives.
//!
//! Relocation slots are accessed atomically. Page permissions are changed with
//! raw syscalls so installing a hook cannot recurse through a libc PLT entry
//! that is being replaced by the same transaction.

use crate::{Error, Result};
use std::sync::{OnceLock, RwLock};

#[cfg(feature = "inline")]
mod inline;
#[cfg(feature = "inline")]
mod mem;
mod opaque;
#[cfg(feature = "plt")]
mod plt;
mod procmap;

#[cfg(all(feature = "inline", test))]
pub(crate) use inline::tests::fail_next_unmap;
#[cfg(feature = "inline")]
pub(crate) use inline::{
    flush_instruction_cache_ranges, flush_instruction_cache_ranges_checked, map_exec_anonymous,
    map_rw_anonymous, sync_instruction_stream, sync_instruction_stream_ready, unmap,
};
#[cfg(feature = "inline")]
pub(crate) use mem::{
    close_self_mem, open_self_mem, pwrite_self_mem, pwrite_self_mem_checked, pwrite64,
};
#[cfg(feature = "inline")]
pub(crate) use opaque::{decode_bytes, encode_bytes, erase_bytes, toggle_bytes_encoding};
pub(crate) use opaque::{decode_usize, encode_usize};
#[cfg(all(feature = "plt", target_arch = "aarch64"))]
pub(crate) use plt::aarch64_universal_bti_landing;
#[cfg(feature = "plt")]
pub(crate) use plt::{compare_exchange_pointer, read_pointer, sign_pac_plt, verify_pac_plt};
pub(crate) use procmap::{ProcmapQuery, close as close_procmap, open_readonly, procmap_query};

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
pub(crate) fn page_size() -> Result<usize> {
    static PAGE_SIZE: OnceLock<usize> = OnceLock::new();
    if let Some(value) = PAGE_SIZE.get() {
        return Ok(*value);
    }
    // SAFETY: sysconf has no pointer arguments and retains no caller state.
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let value = usize::try_from(value).map_err(|_| Error::SystemCall {
        operation: "sysconf(_SC_PAGESIZE)",
        source: std::io::Error::last_os_error(),
    })?;
    if !value.is_power_of_two() {
        return Err(Error::UnsupportedFeature("non-power-of-two page size"));
    }
    Ok(*PAGE_SIZE.get_or_init(|| value))
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn aarch64_bti_supported() -> bool {
    const HWCAP2_BTI: libc::c_ulong = 1 << 17;

    // SAFETY: getauxval has no pointer arguments for AT_HWCAP2.
    unsafe { libc::getauxval(libc::AT_HWCAP2) & HWCAP2_BTI != 0 }
}

/// Changes protection for an exact page-aligned mapped range.
///
/// # Safety
///
/// The range must remain mapped and must not be concurrently unmapped,
/// remapped, or reprotected.
pub(crate) unsafe fn protect(address: usize, length: usize, protection: i32) -> Result<()> {
    match unsafe { protect_checked(address, length, protection) } {
        Some((operation, errno)) => Err(Error::system_call(operation, errno)),
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
) -> Option<(&'static str, i32)> {
    #[cfg(test)]
    if tests::FAIL_NEXT_PROTECT.swap(false, std::sync::atomic::Ordering::AcqRel) {
        return Some(("mprotect", libc::EPERM));
    }
    #[cfg(test)]
    if protection & libc::PROT_EXEC != 0
        && address == tests::DENY_EXEC_PROTECT_PAGE.load(std::sync::atomic::Ordering::Acquire)
    {
        return Some(("mprotect", libc::EACCES));
    }
    // SAFETY: the caller guarantees a live page-aligned range and a protection
    // bitset valid for this target kernel.
    let result = unsafe {
        syscalls::raw_syscall!(
            syscalls::Sysno::mprotect,
            address,
            length,
            protection as usize
        )
    };
    syscall_failure(result, "mprotect")
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
        let _ = syscalls::raw_syscall!(syscalls::Sysno::exit_group, 134);

        // Raw syscall errors are negative errno values encoded as usize. Never
        // pass one through as a negative PID with process-group semantics.
        let pid = syscalls::raw_syscall!(syscalls::Sysno::getpid);
        if let Some(pid) = process_identifier(pid) {
            let _ = syscalls::raw_syscall!(syscalls::Sysno::kill, pid, libc::SIGKILL as usize);

            // Reached only when kill returned. Keep both identifiers range-
            // checked before asking the kernel to signal this exact thread.
            let tid = syscalls::raw_syscall!(syscalls::Sysno::gettid);
            if let Some(tid) = process_identifier(tid) {
                let _ = syscalls::raw_syscall!(
                    syscalls::Sysno::tgkill,
                    pid,
                    tid,
                    libc::SIGKILL as usize
                );
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

pub(super) fn syscall_result(result: usize, operation: &'static str) -> Result<usize> {
    match syscall_failure(result, operation) {
        Some((operation, errno)) => Err(Error::system_call(operation, errno)),
        None => Ok(result),
    }
}

/// Reports a failed raw syscall without constructing an `Error`.
///
/// This is the drop-glue-free form shared by every mutation-window syscall
/// wrapper; it returns only `Copy` values.
pub(crate) fn syscall_failure(
    result: usize,
    operation: &'static str,
) -> Option<(&'static str, i32)> {
    let signed = result as isize;
    // A range pattern keeps this function call-free: generic helpers such as
    // `Range::contains` are separate code the linker may place on a page that
    // an active mutation window makes non-executable.
    match signed {
        -4095..=-1 => Some((operation, (-signed) as i32)),
        _ => None,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    const FAIL_STOP_CHILD: &str = "OMHOOK_FAIL_STOP_CHILD";

    pub(crate) static FAIL_NEXT_PROTECT: AtomicBool = AtomicBool::new(false);

    pub(crate) static DENY_EXEC_PROTECT_PAGE: AtomicUsize = AtomicUsize::new(0);

    /// Refuses to grant `PROT_EXEC` on one exact page for the rest of this
    /// process.
    ///
    /// This reproduces an SELinux domain without `execmod`, where dropping
    /// executability is permitted but restoring it on a page the process has
    /// written is not. Only the named page is affected, so arena mappings still
    /// become executable normally. Pass `0` to disable.
    pub(crate) fn deny_exec_protect_page(page_start: usize) {
        DENY_EXEC_PROTECT_PAGE.store(page_start, Ordering::Release);
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

    pub(crate) fn install_test_seccomp_errno(rejected: &[syscalls::Sysno]) {
        const BPF_LD_W_ABS: u16 = 0x20;
        const BPF_JMP_JEQ_K: u16 = 0x15;
        const BPF_RET_K: u16 = 0x06;

        let mut filter = Vec::with_capacity(2 + rejected.len() * 2);
        filter.push(libc::sock_filter {
            code: BPF_LD_W_ABS,
            jt: 0,
            jf: 0,
            k: 0,
        });
        for &syscall in rejected {
            filter.push(libc::sock_filter {
                code: BPF_JMP_JEQ_K,
                jt: 0,
                jf: 1,
                k: syscall as u32,
            });
            filter.push(libc::sock_filter {
                code: BPF_RET_K,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
            });
        }
        filter.push(libc::sock_filter {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        });
        apply_test_seccomp_filter(&mut filter);
    }

    fn apply_test_seccomp_filter(filter: &mut [libc::sock_filter]) {
        let program = libc::sock_fprog {
            len: u16::try_from(filter.len()).unwrap(),
            filter: filter.as_mut_ptr(),
        };
        // SAFETY: both prctl calls use documented scalar arguments; the filter
        // allocation remains live for the installation call.
        unsafe {
            assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
            assert_eq!(
                libc::prctl(
                    libc::PR_SET_SECCOMP,
                    libc::SECCOMP_MODE_FILTER,
                    &program as *const libc::sock_fprog,
                ),
                0
            );
        }
    }

    /// Ends a seccomp-filtered test child without entering libc's exit path.
    ///
    /// 32-bit bionic can deadlock in its fatal-exit machinery after a filter
    /// denies the `mprotect` on its atexit array (observed as `rt_sigsuspend`
    /// with `SIGSYS` blocked on armv7 Android), so a child owning a filter
    /// must not return through libtest and `exit`. The parent observes only
    /// the exit status, which the raw `exit_group` provides directly.
    pub(crate) fn exit_seccomp_child() -> ! {
        // SAFETY: exit_group takes a scalar status and terminates this child
        // without running any libc handler.
        unsafe {
            let _ = syscalls::raw_syscall!(syscalls::Sysno::exit_group, 0);
        }
        loop {
            // SAFETY: a filter that also blocks exit_group leaves only the
            // defined trap below; the loop covers a returning handler.
            unsafe {
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                core::arch::asm!("ud2", options(nomem, nostack));

                #[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
                core::arch::asm!("udf #0", options(nomem, nostack));
            }
        }
    }

    const POISON_IN_FLIGHT_CHILD: &str = "OMHOOK_POISON_IN_FLIGHT_CHILD";
    const NESTED_MUTATION_CHILD: &str = "OMHOOK_NESTED_MUTATION_CHILD";

    fn poison<T>(lock: &std::sync::Mutex<T>) {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = lock.lock().unwrap();
            panic!("poisoning this lock is the point of the test");
        }));
        assert!(lock.is_poisoned());
    }

    #[test]
    fn page_start_uses_the_runtime_power_of_two_alignment() {
        assert_eq!(page_start(0x2345, 0x1000), 0x2000);
    }

    #[test]
    fn poisoned_lock_recovers_outside_a_mutation_window() {
        // Another caller unwound while holding a lock. Nothing this crate owns
        // is half-written, so taking the host process down over it would be a
        // worse outcome than continuing -- removal especially must stay usable.
        let lock = std::sync::Mutex::new(7_u32);
        poison(&lock);
        assert_eq!(*recover_lock(lock.lock()), 7);
    }

    #[test]
    fn poisoned_lock_terminates_when_a_mutation_was_in_flight() {
        // Unwinding through a window where target bytes or relocation slots are
        // only partly written leaves state no later call can reason about, so
        // that case stays fail-stop.
        if std::env::var_os(POISON_IN_FLIGHT_CHILD).is_some() {
            let lock = std::sync::Mutex::new(());
            poison(&lock);
            enter_mutation();
            let _guard = recover_lock(lock.lock());
            panic!("recover_lock returned while a mutation was in flight");
        }

        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "sys::tests::poisoned_lock_terminates_when_a_mutation_was_in_flight",
                "--nocapture",
            ])
            .env(POISON_IN_FLIGHT_CHILD, "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(134));
    }

    #[test]
    fn leaving_a_mutation_window_restores_poison_recovery() {
        enter_mutation();
        leave_mutation();
        let lock = std::sync::Mutex::new(1_u32);
        poison(&lock);
        assert_eq!(*recover_lock(lock.lock()), 1);
    }

    #[test]
    fn nested_mutation_regions_need_every_exit() {
        // An unhook marks its byte-encoding toggle and then calls the mutation
        // primitive, which marks the window again. Recovery must stay disabled
        // until both exits have run, so the inner exit alone cannot re-enable
        // it. The disabled half is covered by the child test below; this one
        // pins that the counter comes back down.
        enter_mutation();
        enter_mutation();
        leave_mutation();
        leave_mutation();
        let lock = std::sync::Mutex::new(5_u32);
        poison(&lock);
        assert_eq!(*recover_lock(lock.lock()), 5);
    }

    #[test]
    fn an_inner_exit_alone_does_not_re_enable_recovery() {
        if std::env::var_os(NESTED_MUTATION_CHILD).is_some() {
            let lock = std::sync::Mutex::new(());
            poison(&lock);
            enter_mutation();
            enter_mutation();
            leave_mutation();
            let _guard = recover_lock(lock.lock());
            panic!("recover_lock returned while the outer region was still open");
        }

        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "sys::tests::an_inner_exit_alone_does_not_re_enable_recovery",
                "--nocapture",
            ])
            .env(NESTED_MUTATION_CHILD, "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.code(), Some(134));
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

    #[test]
    fn fail_stop_uses_finite_seccomp_fallbacks_without_broad_kill() {
        if let Some(case) = std::env::var_os(FAIL_STOP_CHILD) {
            install_fail_stop_filter(case.to_str().unwrap());
            fail_stop();
        }

        for case in ["exit", "signals", "identifiers"] {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "sys::tests::fail_stop_uses_finite_seccomp_fallbacks_without_broad_kill",
                    "--nocapture",
                ])
                .env(FAIL_STOP_CHILD, case)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(60);
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break status;
                }
                if Instant::now() >= deadline {
                    child.kill().unwrap();
                    let _ = child.wait();
                    panic!("fail_stop child remained alive for case {case}");
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            let signal = status.signal();
            match case {
                "exit" => assert_eq!(signal, Some(libc::SIGKILL)),
                "signals" => assert_eq!(signal, Some(libc::SIGILL)),
                "identifiers" => {
                    // Android crash handlers can turn the final synchronous
                    // UDF into SIGSEGV when getpid/gettid are denied.
                    assert!(
                        matches!(signal, Some(libc::SIGILL | libc::SIGSEGV)),
                        "unexpected identifier-case signal: {signal:?}"
                    );
                }
                _ => unreachable!(),
            }
        }
    }

    fn install_fail_stop_filter(case: &str) {
        let mut rejected = vec![syscalls::Sysno::exit_group];
        match case {
            "signals" => rejected.extend([syscalls::Sysno::kill, syscalls::Sysno::tgkill]),
            "identifiers" => rejected.extend([
                syscalls::Sysno::kill,
                syscalls::Sysno::tgkill,
                syscalls::Sysno::getpid,
                syscalls::Sysno::gettid,
            ]),
            "exit" => {}
            _ => panic!("unknown fail_stop child case"),
        }
        install_test_seccomp_errno(&rejected);
    }
}

#[cfg(target_arch = "aarch64")]
use super::page_start;
use crate::{Error, Result};
use std::sync::atomic::{AtomicU8, Ordering};

/// Maps one anonymous read/write arena using only the kernel ABI.
///
/// # Safety
///
/// `address`, `length`, and `extra_flags` must form a valid anonymous mmap
/// request. The caller owns any mapping returned by this function.
pub(crate) unsafe fn map_rw_anonymous(
    address: usize,
    length: usize,
    extra_flags: i32,
) -> Result<usize> {
    // SAFETY: forwarded from this function's mmap request contract.
    unsafe {
        map_anonymous(
            address,
            length,
            libc::PROT_READ | libc::PROT_WRITE,
            extra_flags,
        )
    }
}

/// Maps one anonymous page range with its final protection at birth.
///
/// The mapping never passes through a writable state, so its permissions are
/// stable from the first observable moment. Content is written later through
/// the forced-access channel in `crate::sys::mem`.
///
/// # Safety
///
/// `address`, `length`, `protection`, and `extra_flags` must form a valid
/// anonymous mmap request. The caller owns any mapping returned.
pub(crate) unsafe fn map_exec_anonymous(
    address: usize,
    length: usize,
    protection: i32,
    extra_flags: i32,
) -> Result<usize> {
    // SAFETY: forwarded from this function's mmap request contract.
    unsafe { map_anonymous(address, length, protection, extra_flags) }
}

unsafe fn map_anonymous(
    address: usize,
    length: usize,
    protection: i32,
    extra_flags: i32,
) -> Result<usize> {
    let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | extra_flags;
    #[cfg(test)]
    if tests::FAIL_NEXT_MAP_EINVAL.swap(false, Ordering::AcqRel) {
        return Err(Error::SystemCall {
            operation: "mmap",
            source: syscalls::Errno::EINVAL,
        });
    }
    #[cfg(test)]
    {
        let failures = tests::FAIL_NEXT_MAP_COUNT.swap(0, Ordering::AcqRel);
        if failures != 0 {
            if failures > 1 {
                tests::FAIL_NEXT_MAP_COUNT.store(failures - 1, Ordering::Release);
            }
            return Err(Error::SystemCall {
                operation: "mmap",
                source: syscalls::Errno::EPERM,
            });
        }
    }
    // SAFETY: the caller supplies a valid hint/range; fd and offset are the
    // required anonymous-mapping sentinels.
    let result = unsafe {
        #[cfg(any(target_arch = "x86", target_arch = "arm"))]
        {
            syscalls::syscall!(
                syscalls::Sysno::mmap2,
                address,
                length,
                protection as usize,
                flags as usize,
                usize::MAX,
                0
            )
        }
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            syscalls::syscall!(
                syscalls::Sysno::mmap,
                address,
                length,
                protection as usize,
                flags as usize,
                usize::MAX,
                0
            )
        }
    };
    match result {
        Ok(address) => Ok(address),
        Err(err) => Err(Error::system_call("mmap", err)),
    }
}

/// Releases an exact mapping using only the kernel ABI.
///
/// # Safety
///
/// The range must name a live mapping owned by the caller and must not be used
/// concurrently or after successful return.
pub(crate) unsafe fn unmap(address: usize, length: usize) -> Result<()> {
    #[cfg(test)]
    if tests::FAIL_NEXT_UNMAP.swap(false, Ordering::AcqRel) {
        return Err(Error::SystemCall {
            operation: "munmap",
            source: syscalls::Errno::EPERM,
        });
    }
    // SAFETY: forwarded from this function's ownership contract.
    let result = unsafe { syscalls::syscall!(syscalls::Sysno::munmap, address, length) };
    match result {
        Ok(_) => Ok(()),
        Err(err) => Err(Error::system_call("munmap", err)),
    }
}

/// Makes freshly written instruction ranges visible to this core only.
///
/// The prepared return or target commit supplies one process-wide sync-core
/// barrier ordering all earlier writes on the same thread before publication.
///
/// # Safety
///
/// Every `(start, end)` pair must name a live readable range with `start <=
/// end`, and the caller must not release the bytes for execution on another
/// core without later process-wide instruction synchronization.
pub(crate) unsafe fn flush_instruction_cache_ranges_local(ranges: &[(usize, usize)]) -> Result<()> {
    let checked = unsafe {
        // SAFETY: the public function contract covers every range.
        flush_instruction_cache_ranges_checked(ranges, false, &mut false)
    };
    match checked {
        Some((operation, errno)) => Err(Error::system_call(operation, errno)),
        None => Ok(()),
    }
}

/// Flushes instruction ranges without `Result` construction for the inline
/// mutation window, optionally synchronizing every core before publication.
///
/// Dropping a `Result` calls compiler-generated drop glue that the linker may
/// place on a page the window makes temporarily non-executable, so this form
/// returns only `Copy` values. A range that is out of order or whose line
/// arithmetic overflows violates an invariant validated before the window
/// opened; the process terminates rather than returning an unrepresentable
/// state.
///
/// # Safety
///
/// Every `(start, end)` pair must name a live readable range with `start <=
/// end`; no processor may execute bytes while the caller is modifying them.
/// When `sync_cores` is false, publication requires a later process-wide sync.
/// `synced` records whether this call actually completed that synchronization.
pub(crate) unsafe fn flush_instruction_cache_ranges_checked(
    ranges: &[(usize, usize)],
    sync_cores: bool,
    synced: &mut bool,
) -> Option<(&'static str, syscalls::Errno)> {
    // This function and its callees form the closed inline mutation-window
    // code set: keep it free of closures, iterator adapters, and values with
    // non-trivial drop glue such as `Result` temporaries, which the linker
    // may place on pages outside the rejected mutation-code span.
    *synced = false;
    let mut validation_index = 0;
    while validation_index < ranges.len() {
        let (start, end) = ranges[validation_index];
        if start > end {
            crate::sys::fail_stop();
        }
        validation_index += 1;
    }

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if let [_, ..] = ranges {
            // Keep the mutation window independent of the generic atomic
            // fence helper, which can remain an out-of-line call in debug
            // builds. `mfence` provides the same hardware ordering here.
            // SAFETY: `mfence` has no pointer or register preconditions.
            unsafe { core::arch::asm!("mfence", options(nostack, preserves_flags)) };
        }
    }

    #[cfg(target_arch = "arm")]
    {
        const ARM_NR_CACHEFLUSH: usize = 0x0f0002;
        let mut range_index = 0;
        while range_index < ranges.len() {
            let (address, end) = ranges[range_index];
            // The private ARM cacheflush number is intentionally absent from
            // the typed syscall table, so issue it through the raw ABI.
            // SAFETY: this is the documented ARM private cacheflush syscall;
            // the range belongs to the caller-provided validated pages.
            let result = unsafe { syscalls::raw::syscall3(ARM_NR_CACHEFLUSH, address, end, 0) };
            if let Err(err) = syscalls::Errno::from_ret(result) {
                return Some(("cacheflush", err));
            }
            range_index += 1;
        }
    }

    #[cfg(target_arch = "aarch64")]
    {
        let ctr: usize;
        // SAFETY: CTR_EL0 is readable at EL0 and has no memory side effects.
        unsafe {
            core::arch::asm!("mrs {ctr}, ctr_el0", ctr = out(reg) ctr, options(nomem, nostack))
        };
        let d_line = 4_usize << ((ctr >> 16) & 0xf);
        let i_line = 4_usize << (ctr & 0xf);

        // CTR_EL0.IDC: bit 28 set means the data-cache clean is not required.
        const IDC: usize = 1 << 28;
        // CTR_EL0.DIC: bit 29 set means instruction-cache invalidation is
        // not required. This follows the compiler-rt and Linux cache paths.
        const DIC: usize = 1 << 29;

        if ctr & IDC == 0 {
            let mut range_index = 0;
            while range_index < ranges.len() {
                let (address, end) = ranges[range_index];
                let mut line = page_start(address, d_line);
                while line < end {
                    // SAFETY: the caller keeps every cache line live.
                    unsafe {
                        core::arch::asm!("dc cvau, {line}", line = in(reg) line, options(nostack))
                    };
                    // A wrapping add plus a monotonicity check stays call-free
                    // so the loop cannot call `usize::checked_add` from the
                    // mutation window.
                    let next = line.wrapping_add(d_line);
                    if next <= line {
                        crate::sys::fail_stop();
                    }
                    line = next;
                }
                range_index += 1;
            }
        }
        // SAFETY: required ordering between data clean and instruction
        // invalidation for self-modifying code.
        unsafe { core::arch::asm!("dsb ish", options(nostack)) };
        if ctr & DIC == 0 {
            let mut range_index = 0;
            while range_index < ranges.len() {
                let (address, end) = ranges[range_index];
                let mut line = page_start(address, i_line);
                while line < end {
                    // SAFETY: the caller keeps every cache line live.
                    unsafe {
                        core::arch::asm!("ic ivau, {line}", line = in(reg) line, options(nostack))
                    };
                    let next = line.wrapping_add(i_line);
                    if next <= line {
                        crate::sys::fail_stop();
                    }
                    line = next;
                }
                range_index += 1;
            }
        }
        // SAFETY: completes invalidation before any subsequent instruction
        // fetch can observe the modified range.
        unsafe { core::arch::asm!("dsb ish", "isb sy", options(nostack)) };
    }
    if sync_cores
        && let [_, ..] = ranges
        && let Some(errno) = sync_instruction_stream(synced)
    {
        return Some(("membarrier", errno));
    }
    None
}

/// Unknown or registered. Plain atomics only: this runs inside the
/// mutation window, where a generic helper such as `OnceLock::get_or_init` may
/// live on a page the window made non-executable.
static SYNC_CORE_STATE: AtomicU8 = AtomicU8::new(SYNC_CORE_UNKNOWN);

const SYNC_CORE_UNKNOWN: u8 = 0;
const SYNC_CORE_READY: u8 = 1;

const MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE: usize = 1 << 5;
const MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE: usize = 1 << 6;

/// Makes every other core observe instructions this thread just published.
///
/// Cache maintenance orders memory and this thread's own pipeline; it does
/// nothing for a core already executing inside the patched range. `membarrier`
/// supplies the missing context-synchronizing event by interrupting every core
/// currently running this process.
///
/// Kernels without `SYNC_CORE` support leave the previous behaviour in place,
/// where the caller's quiescence contract is the only guarantee.
/// `synced` reports this call's result, including current-thread policy denial.
pub(crate) fn sync_instruction_stream(synced: &mut bool) -> Option<syscalls::Errno> {
    *synced = false;
    #[cfg(test)]
    if tests::FAIL_NEXT_SYNC.swap(false, Ordering::AcqRel) {
        return Some(syscalls::Errno::ENOMEM);
    }
    match register_sync_core() {
        Ok(true) => match issue_sync_core() {
            Ok(issued) => {
                *synced = issued;
                None
            }
            Err(errno) => Some(errno),
        },
        Ok(false) => None,
        Err(errno) => Some(errno),
    }
}

fn register_sync_core() -> std::result::Result<bool, syscalls::Errno> {
    let mut state = SYNC_CORE_STATE.load(Ordering::Acquire);
    while state == SYNC_CORE_UNKNOWN {
        // SAFETY: membarrier takes scalar arguments and retains no state.
        let registered = loop {
            // SAFETY: membarrier takes scalar arguments and retains no state.
            let result = unsafe {
                syscalls::syscall!(
                    syscalls::Sysno::membarrier,
                    MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE,
                    0,
                    0
                )
            };
            if !matches!(result, Err(syscalls::Errno::EINTR)) {
                break result;
            }
        };
        let resolved = match registered {
            Ok(_) => SYNC_CORE_READY,
            // Seccomp policy can differ by thread or change after registration.
            Err(error) if deterministic_registration_failure(&error) => return Ok(false),
            // A transient allocation failure must not poison the capability
            // for the rest of this process; leave the state unknown so the
            // next installation can retry registration.
            Err(error) => return Err(error),
        };
        // Two threads may resolve the capability concurrently. Publish only
        // while the state is still unknown so a losing thread cannot overwrite
        // a winner's decision, then re-read in case that winner went first.
        match SYNC_CORE_STATE.compare_exchange(
            SYNC_CORE_UNKNOWN,
            resolved,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => state = resolved,
            Err(observed) => state = observed,
        }
    }
    Ok(true)
}

fn deterministic_registration_failure(error: &syscalls::Errno) -> bool {
    matches!(
        *error,
        syscalls::Errno::ENOSYS
            | syscalls::Errno::EINVAL
            | syscalls::Errno::EPERM
            | syscalls::Errno::EACCES
    )
}

fn issue_sync_core() -> std::result::Result<bool, syscalls::Errno> {
    #[cfg(test)]
    tests::SYNC_CORE_ISSUES.fetch_add(1, Ordering::Relaxed);
    // SAFETY: membarrier takes scalar arguments and retains no state.
    // An issue failure must not stick. Registration stays valid, and the
    // next install tries the barrier again instead of skipping it forever.
    loop {
        // SAFETY: membarrier takes scalar arguments and retains no state.
        let issued = unsafe {
            syscalls::syscall!(
                syscalls::Sysno::membarrier,
                MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE,
                0,
                0
            )
        };
        if !matches!(issued, Err(syscalls::Errno::EINTR)) {
            return match issued {
                Ok(_) => Ok(true),
                Err(error) if deterministic_registration_failure(&error) => Ok(false),
                Err(error) => Err(error),
            };
        }
    }
}

/// Returns whether cross-core instruction-stream synchronization is active.
///
/// The first call registers the private expedited sync-core membarrier once,
/// then probes the current thread's ability to issue it. `false` means the
/// quiescence contract is the only remaining cross-core guarantee.
pub(crate) fn sync_instruction_stream_ready() -> bool {
    matches!(register_sync_core(), Ok(true)) && matches!(issue_sync_core(), Ok(true))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize};

    pub(crate) static FAIL_NEXT_MAP_COUNT: AtomicUsize = AtomicUsize::new(0);
    pub(crate) static FAIL_NEXT_MAP_EINVAL: AtomicBool = AtomicBool::new(false);
    pub(crate) static FAIL_NEXT_UNMAP: AtomicBool = AtomicBool::new(false);
    pub(crate) static FAIL_NEXT_SYNC: AtomicBool = AtomicBool::new(false);
    pub(crate) static SYNC_CORE_ISSUES: AtomicUsize = AtomicUsize::new(0);

    pub(crate) fn fail_next_map_times(count: usize) {
        assert!(count != 0);
        assert_eq!(FAIL_NEXT_MAP_COUNT.swap(count, Ordering::AcqRel), 0);
    }

    pub(crate) fn fail_next_map() {
        fail_next_map_times(1);
    }

    pub(crate) fn fail_next_map_with_einval() {
        assert!(!FAIL_NEXT_MAP_EINVAL.swap(true, Ordering::AcqRel));
    }

    pub(crate) fn restore_next_map() {
        FAIL_NEXT_MAP_COUNT.store(0, Ordering::Release);
    }

    pub(crate) fn restore_next_map_with_einval() {
        FAIL_NEXT_MAP_EINVAL.store(false, Ordering::Release);
    }

    pub(crate) fn fail_next_unmap() {
        FAIL_NEXT_UNMAP.store(true, std::sync::atomic::Ordering::Release);
    }

    pub(crate) fn restore_next_unmap() {
        FAIL_NEXT_UNMAP.store(false, std::sync::atomic::Ordering::Release);
    }
}

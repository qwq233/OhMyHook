#[cfg(target_arch = "aarch64")]
use super::page_start;
use super::syscall_result;
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
    // SAFETY: the caller supplies a valid hint/range; fd and offset are the
    // required anonymous-mapping sentinels.
    let result = unsafe {
        #[cfg(any(target_arch = "x86", target_arch = "arm"))]
        {
            syscalls::raw_syscall!(
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
            syscalls::raw_syscall!(
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
    syscall_result(result, "mmap")
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
            source: std::io::Error::from_raw_os_error(libc::EPERM),
        });
    }
    // SAFETY: forwarded from this function's ownership contract.
    let result = unsafe { syscalls::raw_syscall!(syscalls::Sysno::munmap, address, length) };
    syscall_result(result, "munmap").map(|_| ())
}

/// Makes freshly written instruction ranges visible to instruction fetch.
///
/// # Safety
///
/// Every `(start, end)` pair must name a live readable range with `start <=
/// end`; no processor may execute bytes while the caller is modifying them.
pub(crate) unsafe fn flush_instruction_cache_ranges(ranges: &[(usize, usize)]) -> Result<()> {
    match unsafe { flush_instruction_cache_ranges_checked(ranges) } {
        Some((operation, errno)) => Err(Error::system_call(operation, errno)),
        None => Ok(()),
    }
}

/// `flush_instruction_cache_ranges` without `Result` construction for the
/// inline mutation window.
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
/// The same contract as [`flush_instruction_cache_ranges`] applies.
pub(crate) unsafe fn flush_instruction_cache_ranges_checked(
    ranges: &[(usize, usize)],
) -> Option<(&'static str, i32)> {
    // This function and its callees form the closed inline mutation-window
    // code set: keep it free of closures, iterator adapters, and values with
    // non-trivial drop glue such as `Result` temporaries, which the linker
    // may place on pages outside the rejected mutation-code span.
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
            // SAFETY: this is the documented ARM private cacheflush syscall.
            let result =
                unsafe { syscalls::raw_syscall!(ARM_NR_CACHEFLUSH, address, end, 0_usize) };
            if let Some(failure) = super::syscall_failure(result, "cacheflush") {
                return Some(failure);
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

        if ctr & (1 << 28) == 0 {
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
        if ctr & (1 << 29) == 0 {
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
    if let [_, ..] = ranges {
        sync_instruction_stream();
    }
    None
}

/// Unknown, available, or unavailable. Plain atomics only: this runs inside the
/// mutation window, where a generic helper such as `OnceLock::get_or_init` may
/// live on a page the window made non-executable.
static SYNC_CORE_STATE: AtomicU8 = AtomicU8::new(SYNC_CORE_UNKNOWN);

const SYNC_CORE_UNKNOWN: u8 = 0;
const SYNC_CORE_READY: u8 = 1;
const SYNC_CORE_UNSUPPORTED: u8 = 2;

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
pub(crate) fn sync_instruction_stream() {
    let mut state = SYNC_CORE_STATE.load(Ordering::Acquire);
    if state == SYNC_CORE_UNKNOWN {
        // SAFETY: membarrier takes scalar arguments and retains no state.
        let registered = unsafe {
            syscalls::raw_syscall!(
                syscalls::Sysno::membarrier,
                MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE,
                0,
                0
            )
        };
        state = if super::syscall_failure(registered, "membarrier").is_none() {
            SYNC_CORE_READY
        } else {
            SYNC_CORE_UNSUPPORTED
        };
        SYNC_CORE_STATE.store(state, Ordering::Release);
    }
    if state != SYNC_CORE_READY {
        return;
    }
    // SAFETY: membarrier takes scalar arguments and retains no state.
    let issued = unsafe {
        syscalls::raw_syscall!(
            syscalls::Sysno::membarrier,
            MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE,
            0,
            0
        )
    };
    if super::syscall_failure(issued, "membarrier").is_some() {
        SYNC_CORE_STATE.store(SYNC_CORE_UNSUPPORTED, Ordering::Release);
    }
}

/// Returns whether cross-core instruction-stream synchronization is active.
///
/// The first call registers and issues the private expedited sync-core
/// membarrier once, then reports the cached capability. `false` means the
/// quiescence contract is the only remaining cross-core guarantee.
pub(crate) fn sync_instruction_stream_ready() -> bool {
    sync_instruction_stream();
    SYNC_CORE_STATE.load(Ordering::Acquire) == SYNC_CORE_READY
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::atomic::AtomicBool;

    pub(crate) static FAIL_NEXT_UNMAP: AtomicBool = AtomicBool::new(false);

    pub(crate) fn fail_next_unmap() {
        FAIL_NEXT_UNMAP.store(true, std::sync::atomic::Ordering::Release);
    }
}

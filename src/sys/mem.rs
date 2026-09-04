//! Forced writes into this process's non-writable private mappings.
//!
//! This is the fallback for sandboxes that reject page elevation. Writes go
//! through `/proc/self/mem`, whose `FOLL_FORCE` access performs the same
//! copy-on-write as an `mprotect` round trip without changing page permissions,
//! so the target keeps its captured protection for the complete operation.
//! Every kernel call bypasses libc so hook installation cannot recurse through
//! a libc PLT entry being replaced by the same transaction.

use super::{syscall_failure, syscall_result};
use crate::{Error, Result};

const SELF_MEM: &[u8] = b"/proc/self/mem\0";

/// Opens `/proc/self/mem` for forced read-write access.
///
/// The descriptor must be released with [`close_self_mem`].
pub(crate) fn open_self_mem() -> Result<usize> {
    // SAFETY: `SELF_MEM` holds one NUL-terminated path for this call.
    let result = unsafe {
        syscalls::raw_syscall!(
            syscalls::Sysno::openat,
            libc::AT_FDCWD as usize,
            SELF_MEM.as_ptr() as usize,
            (libc::O_RDWR | libc::O_CLOEXEC) as usize
        )
    };
    syscall_result(result, "openat")
}

/// Releases a descriptor from [`open_self_mem`].
///
/// This function is callable from inside the inline mutation window: it is a
/// single raw syscall with no closure, allocation, or drop glue.
/// Returns the failed `close` errno, if any. Linux may release the descriptor
/// even when it reports an error, so callers must never retry the same number.
pub(crate) fn close_self_mem(fd: usize) -> Option<i32> {
    // SAFETY: the caller owns the descriptor and never reuses it afterwards.
    let result = unsafe { syscalls::raw_syscall!(syscalls::Sysno::close, fd) };
    // The branch is deliberately explicit: `Option::map` would generate a
    // closure in this inline mutation-window wrapper.
    #[expect(clippy::manual_map)]
    match syscall_failure(result, "close") {
        Some((_, errno)) => Some(errno),
        None => None,
    }
}

/// Writes `bytes` at `address` through the forced-access file.
///
/// # Safety
///
/// `address..address + bytes.len()` must name live private mappings of this
/// process, and `fd` must come from [`open_self_mem`].
pub(crate) unsafe fn pwrite_self_mem(fd: usize, address: usize, bytes: &[u8]) -> Result<()> {
    let mut written = 0_usize;
    // SAFETY: forwarded from this function's forced-access target contract.
    if let Some(errno) = unsafe {
        pwrite_self_mem_checked(
            fd,
            address,
            bytes.as_ptr() as usize,
            bytes.len(),
            &mut written,
        )
    } {
        return Err(Error::system_call("pwrite64", errno));
    }
    Ok(())
}

/// `pwrite64` with the per-ABI raw argument layout.
///
/// 64-bit targets pass the offset in one register. ARM EABI aligns the 64-bit
/// offset to an even argument slot, while i386 passes the low/high pair
/// directly after `count`.
#[inline(never)]
pub(crate) fn pwrite64(fd: usize, address: usize, pointer: usize, length: usize) -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: the caller guarantees a live descriptor, readable buffer,
        // and a valid forced-access target range.
        unsafe {
            syscalls::raw::syscall4(
                syscalls::Sysno::pwrite64 as usize,
                fd,
                pointer,
                length,
                address,
            )
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: same contract as the x86_64 form.
        unsafe {
            syscalls::raw::syscall4(
                syscalls::Sysno::pwrite64 as usize,
                fd,
                pointer,
                length,
                address,
            )
        }
    }
    #[cfg(target_arch = "arm")]
    {
        // SAFETY: same contract; the split offset is aligned by one padding
        // argument before its low/high register pair.
        unsafe {
            syscalls::raw::syscall6(
                syscalls::Sysno::pwrite64 as usize,
                fd,
                pointer,
                length,
                0,
                address as u32 as usize,
                (address as u64 >> 32) as usize,
            )
        }
    }
    #[cfg(target_arch = "x86")]
    {
        // SAFETY: same contract; i386 has no 64-bit argument alignment rule.
        unsafe {
            syscalls::raw::syscall5(
                syscalls::Sysno::pwrite64 as usize,
                fd,
                pointer,
                length,
                address as u32 as usize,
                (address as u64 >> 32) as usize,
            )
        }
    }
}

/// `pwrite_self_mem` without `Result` construction for the inline mutation
/// window.
///
/// Returns the failure errno, if any. Partial progress is reported through
/// `written` so callers can restore exactly the bytes they changed. This form
/// is callable while target pages are being modified: it creates no closure,
/// allocation, or value with non-trivial drop glue.
pub(crate) unsafe fn pwrite_self_mem_checked(
    fd: usize,
    address: usize,
    pointer: usize,
    length: usize,
    written: &mut usize,
) -> Option<i32> {
    // Pointer arithmetic replaces range slicing: the slice-index helper is a
    // real call in debug builds and must never execute from the inline
    // mutation window.
    while *written < length {
        let result = pwrite64(
            fd,
            address + *written,
            pointer + *written,
            length - *written,
        );
        if let Some((_, errno)) = syscall_failure(result, "pwrite64") {
            return Some(errno);
        }
        if result == 0 || result > length - *written {
            return Some(libc::EIO);
        }
        *written += result;
    }
    None
}

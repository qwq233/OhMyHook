//! Forced writes into this process's non-writable private mappings.
//!
//! This is the fallback for sandboxes that reject page elevation. Writes go
//! through `/proc/self/mem`, whose `FOLL_FORCE` access performs the same
//! copy-on-write as an `mprotect` round trip without changing page permissions,
//! so the target keeps its captured protection for the complete operation.
//! Every kernel call bypasses libc so hook installation cannot recurse through
//! a libc PLT entry being replaced by the same transaction.

use super::{SyscallResult, open_self_proc_file};
#[cfg(any(feature = "inline", test))]
use crate::{Error, Result};

/// Opens `/proc/self/mem` for forced write access.
///
/// The descriptor must be released with [`close_self_mem`].
///
/// The error is returned raw rather than wrapped so callers can preserve the
/// errno: whether this file can be opened at all is a property of the calling
/// process's own policy (SELinux, seccomp, descriptor limits), and that errno
/// is the only way to tell those apart.
pub(crate) fn open_self_mem() -> SyscallResult<usize> {
    #[cfg(test)]
    if crate::sys::tests::take_self_mem_open_failure() {
        return Err(syscalls::Errno::EPERM);
    }
    open_self_proc_file(b"mem", (libc::O_RDWR | libc::O_CLOEXEC) as usize)
}

/// Releases a descriptor from [`open_self_mem`].
///
/// This function is callable from inside the inline mutation window: it is a
/// single raw syscall with no closure, allocation, or drop glue.
/// Returns the failed `close` errno, if any. Linux may release the descriptor
/// even when it reports an error, so callers must never retry the same number.
pub(crate) fn close_self_mem(fd: usize) -> Option<syscalls::Errno> {
    // SAFETY: the caller owns the descriptor and never reuses it afterwards.
    match unsafe { syscalls::syscall!(syscalls::Sysno::close, fd) } {
        Err(syscalls::Errno::EINTR) => None,
        other => other.err(),
    }
}

/// Writes `bytes` at `address` through the forced-access file.
///
/// # Safety
///
/// `address..address + bytes.len()` must name live private mappings of this
/// process, and `fd` must come from [`open_self_mem`].
#[cfg(any(feature = "inline", test))]
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
pub(crate) fn pwrite64(
    fd: usize,
    address: usize,
    pointer: usize,
    length: usize,
) -> SyscallResult<usize> {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: the caller guarantees a live descriptor, readable buffer,
        // and a valid forced-access target range.
        unsafe { syscalls::syscall!(syscalls::Sysno::pwrite64, fd, pointer, length, address) }
    }
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: same contract as the x86_64 form.
        unsafe { syscalls::syscall!(syscalls::Sysno::pwrite64, fd, pointer, length, address) }
    }
    #[cfg(target_arch = "arm")]
    {
        // SAFETY: same contract; the split offset is aligned by one padding
        // argument before its low/high register pair.
        unsafe {
            syscalls::syscall!(
                syscalls::Sysno::pwrite64,
                fd,
                pointer,
                length,
                0,
                address as u32 as usize,
                (address as u64 >> 32) as usize
            )
        }
    }
    #[cfg(target_arch = "x86")]
    {
        // SAFETY: same contract; i386 has no 64-bit argument alignment rule.
        unsafe {
            syscalls::syscall!(
                syscalls::Sysno::pwrite64,
                fd,
                pointer,
                length,
                address as u32 as usize,
                (address as u64 >> 32) as usize
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
) -> Option<syscalls::Errno> {
    #[cfg(test)]
    if crate::sys::tests::take_self_mem_write_failure() {
        return Some(syscalls::Errno::EPERM);
    }
    // Pointer arithmetic replaces range slicing: the slice-index helper is a
    // real call in debug builds and must never execute from the inline
    // mutation window.
    while *written < length {
        let result = loop {
            // SAFETY: the caller guarantees a live descriptor, readable
            // buffer, and valid forced-access target range.
            let result = pwrite64(
                fd,
                address + *written,
                pointer + *written,
                length - *written,
            );
            if !matches!(result, Err(syscalls::Errno::EINTR)) {
                break result;
            }
        };
        let result = match result {
            Ok(result) => result,
            Err(errno) => return Some(errno),
        };
        if result == 0 || result > length - *written {
            return Some(syscalls::Errno::EIO);
        }
        *written += result;
    }
    None
}

/// Reads the exact pointer-sized slot at `address` through `/proc/self/mem`.
///
/// # Safety
///
/// `address` must name a live, readable, naturally aligned pointer-sized slot
/// of this process, and `fd` must come from [`open_self_mem`].
#[cfg(feature = "plt")]
pub(crate) unsafe fn pread_pointer_self_mem(
    fd: usize,
    address: usize,
    value: &mut usize,
) -> Option<syscalls::Errno> {
    if !address.is_multiple_of(std::mem::align_of::<usize>()) {
        return Some(syscalls::Errno::EINVAL);
    }
    let mut buffer = [0_u8; std::mem::size_of::<usize>()];
    let mut read = 0_usize;
    while read < buffer.len() {
        let result = loop {
            // SAFETY: the caller guarantees a live descriptor, writable
            // buffer, and valid forced-access target range.
            let result = pread64(
                fd,
                address + read,
                // SAFETY: read is in-bounds of buffer by the loop condition.
                unsafe { buffer.as_mut_ptr().add(read) } as usize,
                buffer.len() - read,
            );
            if !matches!(result, Err(syscalls::Errno::EINTR)) {
                break result;
            }
        };
        let result = match result {
            Ok(result) => result,
            Err(errno) => return Some(errno),
        };
        if result == 0 || result > buffer.len() - read {
            return Some(syscalls::Errno::EIO);
        }
        read += result;
    }
    // SAFETY: the buffer holds exactly the bytes of one usize on this target.
    *value = usize::from_ne_bytes(buffer);
    None
}

/// `pread64` with the per-ABI raw argument layout.
#[cfg(feature = "plt")]
fn pread64(fd: usize, address: usize, pointer: usize, length: usize) -> SyscallResult<usize> {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: the caller guarantees a live descriptor, writable buffer,
        // and a valid forced-access target range.
        unsafe { syscalls::syscall!(syscalls::Sysno::pread64, fd, pointer, length, address) }
    }
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: same contract as the x86_64 form.
        unsafe { syscalls::syscall!(syscalls::Sysno::pread64, fd, pointer, length, address) }
    }
    #[cfg(target_arch = "arm")]
    {
        // SAFETY: same contract; the split offset is aligned by one padding
        // argument before its low/high register pair.
        unsafe {
            syscalls::syscall!(
                syscalls::Sysno::pread64,
                fd,
                pointer,
                length,
                0,
                address as u32 as usize,
                (address as u64 >> 32) as usize
            )
        }
    }
    #[cfg(target_arch = "x86")]
    {
        // SAFETY: same contract; i386 has no 64-bit argument alignment rule.
        unsafe {
            syscalls::syscall!(
                syscalls::Sysno::pread64,
                fd,
                pointer,
                length,
                address as u32 as usize,
                (address as u64 >> 32) as usize
            )
        }
    }
}

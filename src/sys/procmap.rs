//! Optional procfs VMA query fast path.

use super::syscall_failure;
use crate::{Error, Result};

/// Linux `struct procmap_query` ABI used by `PROCMAP_QUERY`.
///
/// Field order and widths mirror `linux/fs.h`; the kernel rejects a size it
/// does not recognize, so future extensions fail closed.
#[repr(C)]
pub(crate) struct ProcmapQuery {
    pub(crate) size: u64,
    pub(crate) query_flags: u64,
    pub(crate) query_addr: u64,
    pub(crate) vma_start: u64,
    pub(crate) vma_end: u64,
    pub(crate) vma_flags: u64,
    pub(crate) vma_page_size: u64,
    pub(crate) vma_offset: u64,
    pub(crate) inode: u64,
    pub(crate) dev_major: u32,
    pub(crate) dev_minor: u32,
    pub(crate) vma_name_size: u32,
    pub(crate) build_id_size: u32,
    pub(crate) vma_name_addr: u64,
    pub(crate) build_id_addr: u64,
}

impl ProcmapQuery {
    pub(crate) const fn covering(address: usize) -> Self {
        Self {
            size: std::mem::size_of::<Self>() as u64,
            query_flags: 0,
            query_addr: address as u64,
            vma_start: 0,
            vma_end: 0,
            vma_flags: 0,
            vma_page_size: 0,
            vma_offset: 0,
            inode: 0,
            dev_major: 0,
            dev_minor: 0,
            vma_name_size: 0,
            build_id_size: 0,
            vma_name_addr: 0,
            build_id_addr: 0,
        }
    }
}

/// Queries one covering VMA through the procfs `PROCMAP_QUERY` ioctl.
///
/// # Safety
///
/// `fd` must name this process's `/proc/self/maps` and remain live for the call.
pub(crate) unsafe fn procmap_query(fd: usize, query: &mut ProcmapQuery) -> Result<()> {
    const PROCMAP_QUERY_REQUEST: usize = 0xc068_6611;
    let result = unsafe {
        syscalls::raw_syscall!(
            syscalls::Sysno::ioctl,
            fd,
            PROCMAP_QUERY_REQUEST,
            query as *mut ProcmapQuery as usize
        )
    };
    match syscall_failure(result, "ioctl") {
        Some((operation, errno)) => Err(Error::system_call(operation, errno)),
        None => Ok(()),
    }
}

/// Opens a read-only descriptor with `O_CLOEXEC`.
///
/// # Safety
///
/// `path` must be NUL-terminated and name a readable file.
pub(crate) unsafe fn open_readonly(path: &[u8]) -> Result<usize> {
    let result = unsafe {
        syscalls::raw_syscall!(
            syscalls::Sysno::openat,
            libc::AT_FDCWD as usize,
            path.as_ptr() as usize,
            (libc::O_RDONLY | libc::O_CLOEXEC) as usize
        )
    };
    match syscall_failure(result, "openat") {
        Some((operation, errno)) => Err(Error::system_call(operation, errno)),
        None => Ok(result),
    }
}

/// Closes one procfs query descriptor without the concealment test injection.
///
/// # Safety
///
/// `fd` must be owned by this call and never be reused after it.
pub(crate) unsafe fn close(fd: usize) -> Result<()> {
    let result = unsafe { syscalls::raw_syscall!(syscalls::Sysno::close, fd) };
    match syscall_failure(result, "close") {
        Some((operation, errno)) => Err(Error::system_call(operation, errno)),
        None => Ok(()),
    }
}

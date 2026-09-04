//! Optional procfs VMA query fast path.

use super::SyscallResult;
use std::io::{self, BufRead, Read};
use std::sync::atomic::{AtomicU8, Ordering};

static PROCMAP_QUERY_STATE: AtomicU8 = AtomicU8::new(0);
const PROCMAP_QUERY_UNSUPPORTED: u8 = 1;

pub(crate) fn procmap_query_unsupported() -> bool {
    PROCMAP_QUERY_STATE.load(Ordering::Acquire) == PROCMAP_QUERY_UNSUPPORTED
}

pub(crate) fn record_procmap_query_unsupported() {
    PROCMAP_QUERY_STATE.store(PROCMAP_QUERY_UNSUPPORTED, Ordering::Release);
}

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
    pub(crate) const fn covering_or_next(address: usize) -> Self {
        const COVERING_OR_NEXT_VMA: u64 = 0x10;
        Self {
            size: std::mem::size_of::<Self>() as u64,
            query_flags: COVERING_OR_NEXT_VMA,
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

const _: () = assert!(std::mem::size_of::<ProcmapQuery>() == 104);
const _: () = assert!(ProcmapQuery::covering_or_next(0).size == 104);

/// Queries one covering VMA through the procfs `PROCMAP_QUERY` ioctl.
///
/// # Safety
///
/// `fd` must name this process's `/proc/self/maps` and remain live for the call.
pub(crate) unsafe fn procmap_query(fd: usize, query: &mut ProcmapQuery) -> SyscallResult<()> {
    const PROCMAP_QUERY_REQUEST: usize = 0xc068_6611;
    loop {
        // SAFETY: fd and query satisfy this function's contract.
        let result = unsafe {
            syscalls::syscall!(
                syscalls::Sysno::ioctl,
                fd,
                PROCMAP_QUERY_REQUEST,
                query as *mut ProcmapQuery as usize
            )
        };
        if !matches!(result, Err(syscalls::Errno::EINTR)) {
            return result.map(|_| ());
        }
    }
}

/// Opens a procfs file for this process through `/proc/self`.
pub(crate) fn open_self_proc_file(leaf: &[u8], flags: usize) -> SyscallResult<usize> {
    const PREFIX: &[u8] = b"/proc/self/";
    let mut path = [0_u8; 64];
    let mut cursor = PREFIX.len();
    path[..cursor].copy_from_slice(PREFIX);
    path[cursor..cursor + leaf.len()].copy_from_slice(leaf);
    cursor += leaf.len();
    path[cursor] = 0;
    loop {
        // SAFETY: path is NUL-terminated and names this process's procfs file.
        let result = unsafe {
            syscalls::syscall!(
                syscalls::Sysno::openat,
                libc::AT_FDCWD as usize,
                path.as_ptr(),
                flags
            )
        };
        if !matches!(result, Err(syscalls::Errno::EINTR)) {
            return result;
        }
    }
}

fn read(fd: usize, buffer: &mut [u8]) -> SyscallResult<usize> {
    loop {
        // SAFETY: fd is live and the complete buffer is writable for the call.
        let result = unsafe {
            syscalls::syscall!(
                syscalls::Sysno::read,
                fd,
                buffer.as_mut_ptr() as usize,
                buffer.len()
            )
        };
        if !matches!(result, Err(syscalls::Errno::EINTR)) {
            return result;
        }
    }
}

/// A raw, libc-free buffered procfs reader.
///
/// The caller remains responsible for closing `fd`; this type intentionally
/// does not own the descriptor, so it can be used with the existing
/// PROCMAP_QUERY fast path and manual close-error reporting.
pub(crate) struct RawProcReader<const N: usize = 1024, const FIRST: usize = N> {
    fd: usize,
    buffer: [u8; N],
    position: usize,
    filled: usize,
}

impl<const N: usize, const FIRST: usize> RawProcReader<N, FIRST> {
    pub(crate) const fn new(fd: usize) -> Self {
        Self {
            fd,
            buffer: [0; N],
            position: 0,
            filled: 0,
        }
    }

    pub(crate) fn rewind(&mut self) -> SyscallResult<()> {
        const SEEK_SET: usize = 0;
        // SAFETY: fd names a live procfs stream and this reader is not
        // concurrently used.
        let result = unsafe { syscalls::syscall!(syscalls::Sysno::lseek, self.fd, 0, SEEK_SET) };
        self.position = 0;
        self.filled = 0;
        result.map(|_| ())
    }
}

impl<const N: usize, const FIRST: usize> BufRead for RawProcReader<N, FIRST> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.position == self.filled {
            // Short targeted scans avoid generating unrelated procfs rows;
            // longer scans keep the full buffer after their first read.
            let length = if self.filled == 0 { FIRST.min(N) } else { N };
            self.position = 0;
            self.filled = 0;
            let result = read(self.fd, &mut self.buffer[..length]);
            match result {
                Ok(0) => {}
                Ok(count) => self.filled = count,
                Err(errno) => {
                    return Err(io::Error::from_raw_os_error(errno.into_raw()));
                }
            }
        }
        Ok(&self.buffer[self.position..self.filled])
    }

    fn consume(&mut self, amount: usize) {
        self.position = (self.position + amount).min(self.filled);
    }
}

impl<const N: usize, const FIRST: usize> Read for RawProcReader<N, FIRST> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let available = self.fill_buf()?;
        let amount = available.len().min(buffer.len());
        buffer[..amount].copy_from_slice(&available[..amount]);
        self.consume(amount);
        Ok(amount)
    }
}

/// Closes one procfs query descriptor without the private-file validation test injection.
///
/// # Safety
///
/// `fd` must be owned by this call and never be reused after it.
pub(crate) unsafe fn close(fd: usize) -> SyscallResult<()> {
    let result = unsafe {
        // SAFETY: fd is owned by this call and never reused after it.
        syscalls::syscall!(syscalls::Sysno::close, fd)
    };
    #[cfg(test)]
    let result = if tests::take_close_eintr() {
        Err(syscalls::Errno::EINTR)
    } else {
        result
    };
    match result {
        Err(syscalls::Errno::EINTR) => Ok(()),
        other => other.map(|_| ()),
    }
}

#[cfg(test)]
mod tests {
    use std::io::BufRead;
    use std::os::fd::AsRawFd;
    use std::sync::atomic::{AtomicBool, Ordering};

    static FAIL_NEXT_CLOSE_EINTR: AtomicBool = AtomicBool::new(false);

    #[test]
    fn short_first_read_grows_and_resets_after_rewind() {
        let file = std::fs::File::open("/proc/self/status").unwrap();
        let mut reader = super::RawProcReader::<16, 4>::new(file.as_raw_fd() as usize);
        assert_eq!(reader.fill_buf().unwrap(), b"Name");
        reader.consume(2);
        assert_eq!(reader.fill_buf().unwrap(), b"me");
        reader.consume(2);
        assert_eq!(reader.fill_buf().unwrap().len(), 16);
        reader.rewind().unwrap();
        assert_eq!(reader.fill_buf().unwrap(), b"Name");
    }

    pub(super) fn fail_next_close_eintr() {
        assert!(!FAIL_NEXT_CLOSE_EINTR.swap(true, Ordering::AcqRel));
    }

    pub(super) fn take_close_eintr() -> bool {
        FAIL_NEXT_CLOSE_EINTR.swap(false, Ordering::AcqRel)
    }

    #[test]
    fn close_treats_eintr_as_success() {
        let fd = super::open_self_proc_file(b"maps", (libc::O_RDONLY | libc::O_CLOEXEC) as usize)
            .unwrap();
        fail_next_close_eintr();
        // SAFETY: the descriptor is already closed when the injected EINTR is
        // reported, matching the kernel's Linux close(2) behavior.
        let result = unsafe { super::close(fd) };
        assert!(result.is_ok());
    }
}

use crate::maps::{DeviceId, MapInfo};
use crate::{Error, Result};
use std::fs;
use std::mem::MaybeUninit;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::ptr;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct BoundImage {
    pub(crate) header: usize,
    pub(crate) loader_base: usize,
}

/// Source identity used to select loaded ELF images.
///
/// A Target is a selector, not proof that an image is currently loaded or that
/// its source path still exists. Ordinary selectors match by device, inode, and
/// ELF-header file offset; a bound selector additionally names one exact
/// loader-registered image.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Target {
    pub(crate) device: DeviceId,
    pub(crate) inode: u64,
    pub(crate) elf_header_offset: u64,
    pub(crate) archive_member_size: Option<u64>,
    pub(crate) bound_image: Option<BoundImage>,
}

impl Target {
    /// Selects an ordinary ELF file whose header is at file offset zero.
    ///
    /// This constructor records identity only and does not read the file or
    /// current process mappings.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TargetNotFileBacked`] when `inode` is zero.
    pub const fn new(device: DeviceId, inode: u64) -> Result<Self> {
        if inode == 0 {
            return Err(Error::TargetNotFileBacked);
        }
        Ok(Self {
            device,
            inode,
            elf_header_offset: 0,
            archive_member_size: None,
            bound_image: None,
        })
    }

    /// Selects the current process executable through `/proc/self/exe`.
    ///
    /// Resolving the procfs link preserves access to the loaded executable when
    /// its original pathname has been renamed, replaced, or deleted.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Target::from_path`].
    pub fn current_executable() -> Result<Self> {
        // Prefer the mapping identity of the loader-registered executable so
        // overlayfs/docker and rustdoc temp binaries match `/proc/self/maps`.
        // SAFETY: getauxval has no pointer arguments for AT_PHDR.
        let phdr = unsafe { libc::getauxval(libc::AT_PHDR) } as usize;
        let Some(base) = (phdr != 0).then(|| loader_image_base(phdr)).flatten() else {
            return Self::from_path("/proc/self/exe");
        };
        let maps = crate::read_self_maps()?;
        match crate::maps::find_map_containing(&maps, base, 4) {
            Some(map) if map.inode != 0 => Self::from_elf_header_map(map),
            _ => Self::from_path("/proc/self/exe"),
        }
    }

    /// Selects the ordinary offset-zero ELF file at `path`.
    ///
    /// The path is resolved to its backing device and inode. Archive members
    /// and loader-owned anonymous images require the explicit constructors.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Io`] when metadata cannot be read,
    /// [`Error::TargetNotFileBacked`] when `path` is not a regular file, or
    /// [`Error::ArithmeticOverflow`] when its device identity does not fit.
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self> {
        let metadata = fs::metadata(path)?;
        if !metadata.is_file() {
            return Err(Error::TargetNotFileBacked);
        }
        let device =
            libc::dev_t::try_from(metadata.dev()).map_err(|_| Error::ArithmeticOverflow)?;
        #[cfg(target_os = "android")]
        let major = u32::try_from(libc::major(device)).map_err(|_| Error::ArithmeticOverflow)?;
        #[cfg(target_os = "android")]
        let minor = u32::try_from(libc::minor(device)).map_err(|_| Error::ArithmeticOverflow)?;
        #[cfg(target_os = "linux")]
        let major = libc::major(device);
        #[cfg(target_os = "linux")]
        let minor = libc::minor(device);
        Self::new(DeviceId::new(major, minor), metadata.ino())
    }

    /// Selects one ELF image stored inside an archive.
    ///
    /// `elf_header_offset` must match the file offset reported for the image's
    /// ELF-header mapping in `/proc/self/maps`. `archive_member_size` bounds ELF
    /// reads to `[elf_header_offset, elf_header_offset + archive_member_size)`;
    /// the constructor does not parse the member.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TargetNotFileBacked`] for a zero inode,
    /// [`Error::EmptyArchiveMember`] for a zero size, or
    /// [`Error::ArithmeticOverflow`] when the bounded range overflows.
    pub fn from_archive_member(
        device: DeviceId,
        inode: u64,
        elf_header_offset: u64,
        archive_member_size: u64,
    ) -> Result<Self> {
        if inode == 0 {
            return Err(Error::TargetNotFileBacked);
        }
        if archive_member_size == 0 {
            return Err(Error::EmptyArchiveMember);
        }
        elf_header_offset
            .checked_add(archive_member_size)
            .ok_or(Error::ArithmeticOverflow)?;
        Ok(Self {
            device,
            inode,
            elf_header_offset,
            archive_member_size: Some(archive_member_size),
            bound_image: None,
        })
    }

    /// Builds a target from the file-backed mapping that starts at the ELF
    /// header.
    ///
    /// Anonymous mappings do not carry a source identity and are rejected.
    /// Construct the source target explicitly and use
    /// [`Target::bind_loaded_elf_header`] for a loader-owned anonymous copy.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TargetNotFileBacked`] when `map` has a zero inode.
    pub const fn from_elf_header_map(map: &MapInfo) -> Result<Self> {
        if map.inode == 0 {
            return Err(Error::TargetNotFileBacked);
        }
        Ok(Self {
            device: map.device,
            inode: map.inode,
            elf_header_offset: map.offset,
            archive_member_size: None,
            bound_image: None,
        })
    }

    /// Binds this source identity to one loader-registered ELF header.
    ///
    /// This opt-in supports loaders which copy a file-backed ELF into private
    /// anonymous mappings. A bound target selects only this loaded image.
    ///
    /// The method only asks `dladdr` whether `header` belongs to a registered
    /// loader image and records its loader base. It does **not** prove that the
    /// image came from this Target's source identity. That association and the
    /// mapping lifetime are part of [`crate::install_hooks`]'s safety contract.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedFeature`] when `header` is not inside an
    /// image registered with the dynamic loader.
    pub fn bind_loaded_elf_header(mut self, header: *const ()) -> Result<Self> {
        let header = header.expose_provenance();
        let loader_base = loader_image_base(header).ok_or(Error::UnsupportedFeature(
            "ELF header is not registered with the dynamic loader",
        ))?;
        self.bound_image = Some(BoundImage {
            header,
            loader_base,
        });
        Ok(self)
    }

    /// Backing device used to match `/proc/self/maps`.
    pub const fn device(&self) -> DeviceId {
        self.device
    }

    /// Backing inode used to match `/proc/self/maps`.
    pub const fn inode(&self) -> u64 {
        self.inode
    }

    /// File offset at which the selected ELF header begins.
    pub const fn elf_header_offset(&self) -> u64 {
        self.elf_header_offset
    }

    /// Optional upper-bound size for an ELF image stored in an archive.
    pub const fn archive_member_size(&self) -> Option<u64> {
        self.archive_member_size
    }

    pub(crate) const fn bound_image(&self) -> Option<BoundImage> {
        self.bound_image
    }
}

pub(crate) fn loader_image_base(address: usize) -> Option<usize> {
    let mut info = MaybeUninit::<libc::Dl_info>::uninit();
    // SAFETY: dladdr initializes `info` when it reports success and does not
    // retain the supplied address or output pointer.
    if unsafe { libc::dladdr(ptr::with_exposed_provenance(address), info.as_mut_ptr()) } == 0 {
        return None;
    }
    // SAFETY: a nonzero dladdr result guarantees a fully initialized Dl_info.
    Some(unsafe { info.assume_init() }.dli_fbase.expose_provenance())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_executable_uses_procfs_identity() {
        let target = Target::current_executable().unwrap();
        let metadata = fs::metadata("/proc/self/exe").unwrap();

        let device = libc::dev_t::try_from(metadata.dev()).unwrap();
        #[cfg(target_os = "android")]
        let expected = DeviceId::new(
            u32::try_from(libc::major(device)).unwrap(),
            u32::try_from(libc::minor(device)).unwrap(),
        );
        #[cfg(target_os = "linux")]
        let expected = DeviceId::new(libc::major(device), libc::minor(device));
        assert_eq!(target.device(), expected);
        assert_eq!(target.inode(), metadata.ino());
        assert_eq!(target.elf_header_offset(), 0);
    }

    #[test]
    fn from_path_resolves_a_file_and_rejects_a_directory() {
        let executable = std::env::current_exe().unwrap();
        let metadata = fs::metadata(&executable).unwrap();
        let target = Target::from_path(&executable).unwrap();

        assert_eq!(target.inode(), metadata.ino());
        assert_eq!(target.elf_header_offset(), 0);
        assert!(matches!(
            Target::from_path(executable.parent().unwrap()),
            Err(Error::TargetNotFileBacked)
        ));
    }
}

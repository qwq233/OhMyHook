use super::{CodePage, PageFlags};
use crate::Result;
use crate::maps::MapInfo;

#[cfg(target_arch = "arm")]
pub(super) const fn read_flags(_: &[(usize, usize)]) -> Result<PageFlags> {
    Ok(())
}

pub(super) fn capture_flags(
    _: &mut [CodePage],
    _: &[MapInfo],
    _: &PageFlags,
    _: usize,
) -> Result<bool> {
    Ok(false)
}

pub(super) fn apply_protection_flags(
    _: &mut [impl AsMut<[CodePage]>],
    _: Option<&[crate::maps::SmapInfo]>,
) -> Result<()> {
    Ok(())
}

pub(super) const fn arena_protection(_: &[CodePage]) -> i32 {
    libc::PROT_READ | libc::PROT_EXEC
}

pub(super) const fn writable_protection(_: &CodePage) -> i32 {
    libc::PROT_READ | libc::PROT_WRITE
}

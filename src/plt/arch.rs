//! ABI-specific ELF class, machine, and supported PLT relocation numbers.

use crate::{Error, Result};
use std::ops::BitOr;

pub(crate) const ELFCLASS32: u8 = 1;
pub(crate) const ELFCLASS64: u8 = 2;
pub(crate) const EM_386: u16 = 3;
pub(crate) const EM_ARM: u16 = 40;
pub(crate) const EM_X86_64: u16 = 62;
pub(crate) const EM_AARCH64: u16 = 183;

/// Supported dynamic relocation kind used by the ELF scanner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelocationKind {
    /// An absolute pointer relocation.
    Absolute,
    /// A global data relocation.
    GlobalData,
    /// A procedure linkage table jump slot.
    JumpSlot,
}

/// Set of supported semantic relocation kinds selected by a Hook.
///
/// [`RelocationKinds::ALL`] preserves the traditional behavior. Combining
/// constants with `|` narrows a Hook to the requested subset without adding a
/// dependency on a general-purpose bitflag crate.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RelocationKinds(u8);

impl RelocationKinds {
    /// Absolute pointer relocations.
    pub const ABSOLUTE: Self = Self(1 << 0);
    /// Global data relocations.
    pub const GLOBAL_DATA: Self = Self(1 << 1);
    /// Procedure linkage table jump slots.
    pub const JUMP_SLOT: Self = Self(1 << 2);
    /// Every supported relocation kind.
    pub const ALL: Self = Self(Self::ABSOLUTE.0 | Self::GLOBAL_DATA.0 | Self::JUMP_SLOT.0);

    /// Returns whether this set contains `kind`.
    pub const fn contains(self, kind: RelocationKind) -> bool {
        let bit = match kind {
            RelocationKind::Absolute => Self::ABSOLUTE.0,
            RelocationKind::GlobalData => Self::GLOBAL_DATA.0,
            RelocationKind::JumpSlot => Self::JUMP_SLOT.0,
        };
        self.0 & bit != 0
    }
}

impl BitOr for RelocationKinds {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

#[cfg(target_arch = "x86")]
pub(crate) const ELF_CLASS: u8 = ELFCLASS32;
#[cfg(target_arch = "x86")]
pub(crate) const MACHINE: u16 = EM_386;

#[cfg(target_arch = "x86_64")]
pub(crate) const ELF_CLASS: u8 = ELFCLASS64;
#[cfg(target_arch = "x86_64")]
pub(crate) const MACHINE: u16 = EM_X86_64;

#[cfg(target_arch = "arm")]
pub(crate) const ELF_CLASS: u8 = ELFCLASS32;
#[cfg(target_arch = "arm")]
pub(crate) const MACHINE: u16 = EM_ARM;

#[cfg(target_arch = "aarch64")]
pub(crate) const ELF_CLASS: u8 = ELFCLASS64;
#[cfg(target_arch = "aarch64")]
pub(crate) const MACHINE: u16 = EM_AARCH64;

pub(crate) fn relocation_kind(
    machine: u16,
    relocation_type: u32,
) -> Result<Option<RelocationKind>> {
    let kind = match (machine, relocation_type) {
        (EM_386 | EM_X86_64, 1) | (EM_ARM, 2) | (EM_AARCH64, 257) => RelocationKind::Absolute,
        (EM_386 | EM_X86_64, 6) | (EM_ARM, 21) | (EM_AARCH64, 1025) => RelocationKind::GlobalData,
        (EM_386 | EM_X86_64, 7) | (EM_ARM, 22) | (EM_AARCH64, 1026) => RelocationKind::JumpSlot,
        (EM_386 | EM_ARM | EM_X86_64 | EM_AARCH64, _) => return Ok(None),
        _ => return Err(Error::UnsupportedFeature("ELF machine")),
    };
    Ok(Some(kind))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_all_requested_abis() {
        for (machine, relocation_type, expected) in [
            (EM_386, 1, RelocationKind::Absolute),
            (EM_386, 6, RelocationKind::GlobalData),
            (EM_386, 7, RelocationKind::JumpSlot),
            (EM_X86_64, 1, RelocationKind::Absolute),
            (EM_X86_64, 6, RelocationKind::GlobalData),
            (EM_X86_64, 7, RelocationKind::JumpSlot),
            (EM_ARM, 2, RelocationKind::Absolute),
            (EM_ARM, 21, RelocationKind::GlobalData),
            (EM_ARM, 22, RelocationKind::JumpSlot),
            (EM_AARCH64, 257, RelocationKind::Absolute),
            (EM_AARCH64, 1025, RelocationKind::GlobalData),
            (EM_AARCH64, 1026, RelocationKind::JumpSlot),
        ] {
            assert_eq!(
                relocation_kind(machine, relocation_type).unwrap(),
                Some(expected)
            );
        }
        assert_eq!(relocation_kind(EM_AARCH64, 1027).unwrap(), None);
    }
}

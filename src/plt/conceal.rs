//! Disabled concealed PLT mutations.
//!
//! Mapping replacement needs a safe backing-file identity and failed-remap
//! protocol that are not ready for release. New requests fail before mutation.

use super::{Hook, HookPlan, MutationScope};
use crate::{Error, Result};
use std::sync::atomic::{AtomicBool, Ordering};

static ENFORCE_CONCEALED: AtomicBool = AtomicBool::new(false);

/// Requests concealment process-wide.
///
/// The switch is retained for API compatibility, but concealment is disabled
/// in this release and every request fails before target mutation.
pub fn set_enforce_concealed_mutations(enforce: bool) {
    ENFORCE_CONCEALED.store(enforce, Ordering::Release);
}

/// Returns whether concealed PLT mutations are enabled.
///
/// This release reports a stable negative result and performs no probe.
pub fn concealed_mutations_supported() -> Result<bool> {
    Ok(false)
}

pub(super) struct Concealments;

impl Concealments {
    pub(super) fn not_requested() -> Self {
        Self
    }

    pub(super) fn get(&self, _index: usize) -> super::Concealment {
        super::Concealment::InPlace("concealment not requested")
    }
}

pub(super) fn apply(
    hooks: &[Hook<'_>],
    plans: &[Option<HookPlan>],
    _scope: &MutationScope,
    new_ranges: &mut Vec<usize>,
) -> Result<Concealments> {
    if hooks.len() != plans.len() {
        return Err(Error::InvalidElf("concealment plan count mismatch"));
    }
    new_ranges.clear();
    if requested(hooks) {
        return Err(Error::UnsupportedFeature(
            "concealed PLT mutations are disabled in this release",
        ));
    }
    Ok(Concealments::not_requested())
}

pub(super) fn requested(hooks: &[Hook<'_>]) -> bool {
    hooks.iter().any(|hook| hook.enforce_concealed) || ENFORCE_CONCEALED.load(Ordering::Acquire)
}

pub(super) fn attach(_id: usize, _writes: &[super::PointerWrite]) {}

pub(super) fn covers(_address: usize) -> bool {
    false
}

pub(super) fn replaces_file_mapping(
    _address: usize,
    _expected_offset: u64,
    _device: crate::maps::DeviceId,
    _inode: u64,
) -> bool {
    false
}

pub(super) fn after_removal(_removals: &[(usize, usize, usize)]) -> Result<()> {
    Ok(())
}

pub(super) fn restore_abandoned(_new_ranges: &[usize]) -> Result<()> {
    Ok(())
}

/// Restores concealed mutations.
///
/// This release creates none; the stable result is zero.
pub fn restore_concealed_mutations() -> Result<usize> {
    Ok(0)
}

#[cfg(test)]
mod tests {
    #[test]
    fn concealment_is_disabled_without_probing_or_mutating() {
        assert!(!super::concealed_mutations_supported().unwrap());
        assert_eq!(super::restore_concealed_mutations().unwrap(), 0);
    }
}

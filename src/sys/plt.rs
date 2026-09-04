use crate::{Error, Result};
use std::ptr;
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(target_arch = "aarch64")]
const BTI_JC: u32 = 0xd503_24df;

/// Returns whether one AArch64 instruction is a universal BTI landing.
///
/// Arbitrary code-pointer relocations may also be used with jump branches.
#[cfg(target_arch = "aarch64")]
pub(crate) fn aarch64_universal_bti_landing(instruction: u32) -> bool {
    instruction == BTI_JC
}

/// PLT `br x16`/`br x17` and indirect calls accept call-compatible landings.
#[cfg(target_arch = "aarch64")]
pub(crate) fn aarch64_call_bti_landing(instruction: u32) -> bool {
    matches!(
        instruction,
        BTI_JC | 0xd503_245f | 0xd503_233f | 0xd503_237f
    )
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn sign_pac_plt(pointer: usize, slot: usize) -> usize {
    let mut pointer = pointer;
    // SAFETY: PACIA1716 only reads the current thread's IA key and the fixed
    // input registers, then writes the signed value back to x17.
    unsafe {
        core::arch::asm!(
            "pacia1716",
            in("x16") slot,
            inout("x17") pointer,
            options(nomem, nostack)
        );
    }
    pointer
}

#[cfg(not(target_arch = "aarch64"))]
pub(crate) const fn sign_pac_plt(pointer: usize, _slot: usize) -> usize {
    pointer
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn verify_pac_plt(stored: usize, slot: usize) -> Option<usize> {
    if stored == 0 {
        return Some(0);
    }
    let mut raw = stored;
    // SAFETY: XPACLRI only strips PAC bits from the fixed x30 operand. Re-
    // signing and comparing avoids an AUTIA fault for an invalid signature.
    unsafe {
        core::arch::asm!(
            "xpaclri",
            inout("x30") raw,
            options(nomem, nostack)
        );
    }
    (sign_pac_plt(raw, slot) == stored).then_some(raw)
}

#[cfg(not(target_arch = "aarch64"))]
pub(crate) const fn verify_pac_plt(stored: usize, _slot: usize) -> Option<usize> {
    Some(stored)
}

/// Reads one naturally aligned pointer-sized relocation slot.
///
/// # Safety
///
/// `address` must remain mapped, readable, and naturally aligned for the call.
/// Every concurrent access to the slot must use ABI-supported atomic or
/// otherwise hardware-compatible pointer-sized operations. This requirement
/// does not make a Rust or C source-level data race valid.
pub(crate) unsafe fn read_pointer(address: usize) -> Result<usize> {
    if !address.is_multiple_of(std::mem::align_of::<AtomicUsize>()) {
        return Err(Error::InvalidElf("unaligned relocation slot"));
    }
    // SAFETY: the caller guarantees a live, readable, naturally aligned
    // pointer-sized slot for the lifetime of this temporary atomic reference.
    let pointer = unsafe { AtomicUsize::from_ptr(ptr::with_exposed_provenance_mut(address)) };
    Ok(pointer.load(Ordering::SeqCst))
}

/// Atomically replaces one relocation slot when it still has `expected`.
///
/// # Safety
///
/// `address` must remain mapped, readable, writable, and naturally aligned for
/// the call. The caller must exclude competing writers, and every concurrent
/// reader must use ABI-supported atomic or otherwise hardware-compatible
/// pointer-sized operations. This does not legalize a Rust or C data race.
pub(crate) unsafe fn compare_exchange_pointer(
    address: usize,
    expected: usize,
    replacement: usize,
) -> Result<bool> {
    if !address.is_multiple_of(std::mem::align_of::<AtomicUsize>()) {
        return Err(Error::InvalidElf("unaligned relocation slot"));
    }
    // SAFETY: the caller guarantees the complete validity and writer-
    // exclusivity contract documented above.
    let pointer = unsafe { AtomicUsize::from_ptr(ptr::with_exposed_provenance_mut(address)) };
    Ok(pointer
        .compare_exchange(expected, replacement, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok())
}

#[cfg(all(test, target_arch = "aarch64"))]
mod tests {
    use super::*;

    #[test]
    fn universal_bti_landing_requires_bti_jc() {
        // Untyped code pointers may be reached through arbitrary BR and BLR,
        // so only `bti jc` is universal.
        assert!(!aarch64_universal_bti_landing(0xd503_241f));
        assert!(aarch64_universal_bti_landing(0xd503_24df));
        // `bti c` (#34) and `bti j` (#36) each reject at least one legal
        // branch type, and PACIASP/PACIBSP act as `bti c` only.
        assert!(!aarch64_universal_bti_landing(0xd503_245f));
        assert!(!aarch64_universal_bti_landing(0xd503_249f));
        assert!(!aarch64_universal_bti_landing(0xd503_233f));
        assert!(!aarch64_universal_bti_landing(0xd503_237f));
        assert!(!aarch64_universal_bti_landing(0xd280_0000));
    }

    #[test]
    fn call_bti_landing_accepts_function_prologues() {
        for instruction in [0xd503_24df, 0xd503_245f, 0xd503_233f, 0xd503_237f] {
            assert!(aarch64_call_bti_landing(instruction));
        }
        for instruction in [0xd503_241f, 0xd503_249f, 0xd280_0000] {
            assert!(!aarch64_call_bti_landing(instruction));
        }
    }
}

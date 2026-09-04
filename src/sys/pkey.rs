#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
use crate::{Error, Result};

#[cfg(target_arch = "x86")]
use std::arch::x86 as x86_arch;
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64 as x86_arch;

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[derive(Clone, Copy)]
#[repr(C, align(64))]
struct XsaveBlock([u8; 64]);

/// Reads the calling thread's protection-key rights without changing them.
/// No state survives this call: different installer threads can have different
/// PKRU values even when their procfs mappings are identical.
#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
pub(crate) fn x86_pkru() -> Result<u32> {
    const PKRU: u64 = 1 << 9;
    let available = x86_arch::__cpuid(0).eax;
    if available < 7 {
        return Ok(0);
    }
    let keys = x86_arch::__cpuid_count(7, 0).ecx;
    if keys & ((1 << 3) | (1 << 4)) != ((1 << 3) | (1 << 4)) {
        return Ok(0);
    }
    let features = x86_arch::__cpuid(1).ecx;
    if available < 0x0d || features & ((1 << 26) | (1 << 27)) != ((1 << 26) | (1 << 27)) {
        return Err(Error::UnsupportedFeature("PKRU state cannot be read"));
    }
    // SAFETY: both XSAVE and OSXSAVE were checked above; XCR0 is index 0.
    if unsafe { x86_arch::_xgetbv(0) } & PKRU == 0 {
        return Err(Error::UnsupportedFeature("PKRU is absent from XCR0"));
    }
    let component = x86_arch::__cpuid_count(0x0d, 9);
    let compact = x86_arch::__cpuid_count(0x0d, 1).eax & (1 << 1) != 0;
    let offset = if compact { 576 } else { component.ebx as usize };
    if component.eax < 4 || offset < 576 {
        return Err(Error::UnsupportedFeature("invalid PKRU state layout"));
    }
    let length = offset
        .checked_add(component.eax as usize)
        .ok_or(Error::ArithmeticOverflow)?;
    // A compacted PKRU-only image normally occupies 584 bytes. Standard XSAVE
    // uses the CPU-reported component offset and may need a larger buffer.
    let mut local = [XsaveBlock([0; 64]); 10];
    let mut extended;
    let storage = if length <= std::mem::size_of_val(&local) {
        local.as_mut_slice()
    } else {
        extended = vec![XsaveBlock([0; 64]); length.div_ceil(64)];
        extended.as_mut_slice()
    };
    let buffer = storage.as_mut_ptr().cast::<u8>();
    // SAFETY: the buffer is live, 64-byte aligned, and covers the header and
    // the only requested component. CPU and OS support were checked above.
    unsafe {
        if compact {
            x86_arch::_xsavec(buffer, PKRU);
        } else {
            x86_arch::_xsave(buffer, PKRU);
        }
    }
    // SAFETY: the initialized buffer covers both the header and PKRU field.
    let present = unsafe { std::ptr::read_unaligned(buffer.add(512).cast::<u64>()) };
    if present & PKRU == 0 {
        return Ok(0);
    }
    // SAFETY: XSAVE marked the requested component present at this offset.
    Ok(unsafe { std::ptr::read_unaligned(buffer.add(offset).cast::<u32>()) })
}

/// Reads the calling thread's permission overlay without changing it.
#[cfg(target_arch = "aarch64")]
pub(crate) fn aarch64_por_el0() -> u64 {
    const HWCAP2_POE: libc::c_ulong = 1 << 63;
    // SAFETY: getauxval has no pointer arguments for AT_HWCAP2.
    let features =
        *super::AARCH64_HWCAP2.get_or_init(|| unsafe { libc::getauxval(libc::AT_HWCAP2) });
    if features & HWCAP2_POE == 0 {
        return 0x7777_7777;
    }
    let permissions: u64;
    // SAFETY: HWCAP2_POE guarantees that this read-only EL0 register exists.
    unsafe {
        core::arch::asm!(
            "mrs {permissions}, S3_3_C10_C2_4",
            permissions = out(reg) permissions,
            options(nostack, preserves_flags)
        );
    }
    permissions
}

#[cfg(test)]
pub(crate) mod tests {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    use super::{XsaveBlock, x86_arch};

    pub(crate) struct PkeyTestRights {
        #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
        saved_state: Vec<XsaveBlock>,
        #[cfg(target_arch = "aarch64")]
        saved_por: u64,
        pub(crate) key: usize,
        other_key: Option<usize>,
        denied: u64,
        allowed: u64,
    }

    impl PkeyTestRights {
        pub(crate) fn new() -> Option<Self> {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            let supported =
                x86_arch::__cpuid(0).eax >= 7 && x86_arch::__cpuid_count(7, 0).ecx & 0x18 == 0x18;
            #[cfg(target_arch = "aarch64")]
            // SAFETY: getauxval has no pointer arguments for AT_HWCAP2.
            let supported = unsafe { libc::getauxval(libc::AT_HWCAP2) } & (1 << 63) != 0;
            if !supported {
                assert!(
                    std::env::var_os("OHMYHOOK_REQUIRE_PKEY").is_none(),
                    "the required protection-key execution gate lacks CPU/OS support"
                );
                log::info!("protection-key execution unavailable: CPU/OS support");
                return None;
            }
            let original = Self::read();
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            let saved_state = {
                let offset = x86_arch::__cpuid_count(0x0d, 9).ebx as usize;
                assert!(offset >= 576);
                let mut state = vec![XsaveBlock([0; 64]); (offset + 8).div_ceil(64)];
                // SAFETY: the initialized aligned image contains only PKRU.
                unsafe {
                    let bytes = state.as_mut_ptr().cast::<u8>();
                    bytes.add(512).cast::<u64>().write_unaligned(1 << 9);
                    bytes
                        .add(offset)
                        .cast::<u32>()
                        .write_unaligned(original as u32);
                }
                state
            };
            // SAFETY: allocate a private key with write denial and no mappings.
            let allocated = unsafe { syscalls::syscall!(syscalls::Sysno::pkey_alloc, 0, 2) };
            let key = match allocated {
                Ok(key) => key,
                Err(error) => {
                    assert!(matches!(
                        error,
                        syscalls::Errno::ENOSPC | syscalls::Errno::ENOSYS
                    ));
                    assert!(
                        std::env::var_os("OHMYHOOK_REQUIRE_PKEY").is_none(),
                        "the required protection-key execution gate is unavailable: {error}"
                    );
                    log::info!("protection-key execution unavailable: {error}");
                    return None;
                }
            };
            let mut rights = Self {
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                saved_state,
                #[cfg(target_arch = "aarch64")]
                saved_por: original,
                key,
                other_key: None,
                denied: 0,
                allowed: 0,
            };
            // Keep another key restricted to exercise the smaps check even
            // when the selected key allows writes.
            rights.other_key = Some(unsafe {
                // SAFETY: this fresh key is owned here and has no mappings.
                syscalls::syscall!(syscalls::Sysno::pkey_alloc, 0, 2).unwrap()
            });
            rights.denied = Self::read();
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            {
                assert!(key < 16);
                assert_eq!((rights.denied >> (key * 2)) & 3, 2);
                rights.allowed = rights.denied & !(3 << (key * 2));
            }
            #[cfg(target_arch = "aarch64")]
            {
                assert!(key < 8);
                assert_eq!((rights.denied >> (key * 4)) & 15, 3);
                rights.allowed = (rights.denied & !(15 << (key * 4))) | (7 << (key * 4));
            }
            Some(rights)
        }

        fn read() -> u64 {
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            return u64::from(super::x86_pkru().unwrap());
            #[cfg(target_arch = "aarch64")]
            return super::aarch64_por_el0();
        }

        pub(crate) fn set_writable(&self, writable: bool) {
            let value = if writable { self.allowed } else { self.denied };
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            {
                let mut state = self.saved_state.clone();
                let offset = x86_arch::__cpuid_count(0x0d, 9).ebx as usize;
                // SAFETY: the validated standard-layout image restores only PKRU.
                unsafe {
                    let bytes = state.as_mut_ptr().cast::<u8>();
                    bytes
                        .add(offset)
                        .cast::<u32>()
                        .write_unaligned(value as u32);
                    x86_arch::_xrstor(bytes, 1 << 9);
                }
            }
            #[cfg(target_arch = "aarch64")]
            // SAFETY: this test changes only its own allocated key's permissions.
            unsafe {
                core::arch::asm!("msr S3_3_C10_C2_4, {value}", "isb", value = in(reg) value,
                    options(nostack, preserves_flags));
            }
            assert_eq!(Self::read(), value);
        }
    }

    impl Drop for PkeyTestRights {
        fn drop(&mut self) {
            // SAFETY: restore this thread's saved rights, including on panic.
            // All mappings using the test-owned keys must have been unmapped.
            unsafe {
                #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
                x86_arch::_xrstor(self.saved_state.as_ptr().cast(), 1 << 9);
                #[cfg(target_arch = "aarch64")]
                core::arch::asm!("msr S3_3_C10_C2_4, {value}", "isb", value = in(reg) self.saved_por,
                    options(nostack, preserves_flags));
                let _ = syscalls::syscall!(syscalls::Sysno::pkey_free, self.key);
                if let Some(key) = self.other_key {
                    let _ = syscalls::syscall!(syscalls::Sysno::pkey_free, key);
                }
            }
        }
    }
}

use super::*;
use crate::maps::DeviceId;
use std::fs;
use std::os::unix::fs::FileExt;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

static FAIL_FORCED_CLOSE: AtomicBool = AtomicBool::new(false);
static FAIL_FORCED_WRITE: AtomicBool = AtomicBool::new(false);
static FAIL_FORCED_UNAVAILABLE: AtomicBool = AtomicBool::new(false);
pub(super) static PROBE_FIRST_BYTE: AtomicU8 = AtomicU8::new(0);

/// Arms one forced-descriptor close failure. Every arm call must be paired
/// with [`restore_forced_close_failure`] before the test returns.
pub(crate) fn fail_next_forced_close() {
    assert!(!FAIL_FORCED_CLOSE.swap(true, Ordering::AcqRel));
}

pub(crate) fn restore_forced_close_failure() {
    FAIL_FORCED_CLOSE.store(false, Ordering::Release);
}

/// Arms one forced write failure *after* the real write, so the restore path
/// undoes exactly the bytes it changed.
pub(crate) fn fail_next_forced_write() {
    assert!(!FAIL_FORCED_WRITE.swap(true, Ordering::AcqRel));
}

pub(crate) fn restore_forced_write_failure() {
    FAIL_FORCED_WRITE.store(false, Ordering::Release);
}

/// Makes the next mutation behave as though `/proc/self/mem` were unavailable.
pub(crate) fn fail_next_forced_unavailable() {
    assert!(!FAIL_FORCED_UNAVAILABLE.swap(true, Ordering::AcqRel));
}

pub(crate) fn restore_forced_unavailable_failure() {
    FAIL_FORCED_UNAVAILABLE.store(false, Ordering::Release);
}

pub(super) fn take_forced_close_failure() -> bool {
    FAIL_FORCED_CLOSE.swap(false, Ordering::AcqRel)
}

pub(super) fn take_forced_write_failure() -> bool {
    FAIL_FORCED_WRITE.swap(false, Ordering::AcqRel)
}

pub(super) fn take_forced_unavailable_failure() -> bool {
    FAIL_FORCED_UNAVAILABLE.swap(false, Ordering::AcqRel)
}

pub(crate) fn forced_unavailable_failure_pending() -> bool {
    FAIL_FORCED_UNAVAILABLE.load(Ordering::Acquire)
}

#[test]
fn close_raw_fd_reports_cleanup_failure() {
    let error = close_raw_fd(usize::MAX).unwrap_err();
    assert!(
        matches!(
            error,
            Error::SystemCall {
                operation: "close",
                source: syscalls::Errno::EBADF
            }
        ),
        "unexpected close error: {error:?}"
    );
}

/// Only the classification is pinned here. That a denial really reaches the
/// forced channel end to end is covered by the inline integration tests, and
/// only for `EPERM`.
#[test]
fn mprotect_denials_and_mapping_limits_are_classified_as_retryable() {
    for errno in [
        syscalls::Errno::EPERM,
        syscalls::Errno::EACCES,
        syscalls::Errno::ENOSYS,
        syscalls::Errno::EIO,
        // vm.max_map_count reached while splitting the target mapping. The
        // forced channel never splits a mapping, so this is retryable.
        syscalls::Errno::ENOMEM,
    ] {
        let error = Error::SystemCall {
            operation: "mprotect",
            source: errno,
        };
        assert!(retryable_page_elevation_failure(&error), "errno {errno}");
    }

    // Only mprotect denials retry; an unrelated failure must surface.
    let unrelated = Error::SystemCall {
        operation: "mmap",
        source: syscalls::Errno::ENOMEM,
    };
    assert!(!retryable_page_elevation_failure(&unrelated));
    let other = Error::SystemCall {
        operation: "mprotect",
        source: syscalls::Errno::EFAULT,
    };
    assert!(!retryable_page_elevation_failure(&other));
}

#[cfg(target_arch = "aarch64")]
const SYSCALL3_NAME: &str = "syscalls::syscall::aarch64::syscall3";
#[cfg(all(target_arch = "arm", not(target_feature = "thumb-mode")))]
const SYSCALL3_NAME: &str = "syscalls::syscall::arm::syscall3";
#[cfg(all(target_arch = "arm", target_feature = "thumb-mode"))]
const SYSCALL3_NAME: &str = "syscalls::syscall::arm_thumb::syscall3";
#[cfg(target_arch = "x86")]
const SYSCALL3_NAME: &str = "syscalls::syscall::x86::syscall3";
#[cfg(target_arch = "x86_64")]
const SYSCALL3_NAME: &str = "syscalls::syscall::x86_64::syscall3";

#[cfg(target_arch = "aarch64")]
const SYSCALL1_NAME: &str = "syscalls::syscall::aarch64::syscall1";
#[cfg(all(target_arch = "arm", not(target_feature = "thumb-mode")))]
const SYSCALL1_NAME: &str = "syscalls::syscall::arm::syscall1";
#[cfg(all(target_arch = "arm", target_feature = "thumb-mode"))]
const SYSCALL1_NAME: &str = "syscalls::syscall::arm_thumb::syscall1";
#[cfg(target_arch = "x86")]
const SYSCALL1_NAME: &str = "syscalls::syscall::x86::syscall1";
#[cfg(target_arch = "x86_64")]
const SYSCALL1_NAME: &str = "syscalls::syscall::x86_64::syscall1";

#[cfg(target_arch = "aarch64")]
const SYSCALL4_NAME: &str = "syscalls::syscall::aarch64::syscall4";
#[cfg(all(target_arch = "arm", not(target_feature = "thumb-mode")))]
const SYSCALL6_NAME: &str = "syscalls::syscall::arm::syscall6";
#[cfg(all(target_arch = "arm", target_feature = "thumb-mode"))]
const SYSCALL6_NAME: &str = "syscalls::syscall::arm_thumb::syscall6";
#[cfg(target_arch = "x86_64")]
const SYSCALL4_NAME: &str = "syscalls::syscall::x86_64::syscall4";
#[cfg(target_arch = "x86")]
const SYSCALL5_NAME: &str = "syscalls::syscall::x86::syscall5";

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const SYSCALL_STUB_NAME: &str = SYSCALL4_NAME;
#[cfg(target_arch = "arm")]
const SYSCALL_STUB_NAME: &str = SYSCALL6_NAME;
#[cfg(target_arch = "x86")]
const SYSCALL_STUB_NAME: &str = SYSCALL5_NAME;

/// Symbol names of [`mutation_code_addresses`], in the same order.
///
/// Names stay out of production builds; this audit-only table verifies that
/// the address list keeps naming exactly the closed mutation-window set.
const WINDOW_FUNCTION_NAMES: &[&str] = &[
    "omhook::inline::patch::replace_many",
    "omhook::inline::patch::replace_many_mutating",
    "omhook::inline::patch::replace_many_forced",
    "omhook::inline::patch::replace_many_with_elevation",
    "omhook::inline::patch::flush_replacements",
    "omhook::inline::patch::elevate",
    "omhook::inline::patch::elevate_keeping_exec",
    "omhook::inline::patch::page_protection_failure",
    "omhook::inline::patch::page_protection_failure_from_tuple",
    "omhook::inline::patch::forced_failure",
    "omhook::inline::patch::retryable_page_elevation_failure",
    "omhook::inline::patch::elevation_failure",
    "omhook::inline::patch::elevation_error",
    "omhook::inline::patch::forced_restore",
    "omhook::inline::patch::forced_bytes_match",
    "omhook::inline::patch::page_is_first",
    "omhook::inline::patch::open_unique_pages",
    "omhook::inline::patch::restore_first_pages",
    "omhook::inline::patch::close_unique_pages",
    "omhook::inline::patch::reopen_unique_pages",
    "omhook::inline::patch::rollback_open_many",
    "omhook::inline::patch::mapped_bytes_match",
    "omhook::inline::patch::copy_mapped_bytes",
    "omhook::inline::patch::range_end",
    "omhook::inline::patch::writable_protection",
    "omhook::inline::patch::page::writable_protection",
    "omhook::sys::protect",
    "omhook::sys::protect_checked",
    "omhook::sys::inline::flush_instruction_cache_ranges_checked",
    "omhook::sys::inline::sync_instruction_stream",
    "omhook::sys::page_start",
    "omhook::sys::fail_stop",
    SYSCALL3_NAME,
    SYSCALL1_NAME,
    "omhook::sys::mem::pwrite_self_mem_checked",
    "omhook::sys::mem::pwrite64",
    "omhook::sys::mem::close_self_mem",
    "omhook::inline::patch::close_forced_descriptor",
];

/// Error-return frames that keep executing while a target page may be
/// non-executable. These deliberately may contain closures and iterator
/// adapters: the no-closure constraint protects only the code that runs
/// between `replace_many` opening and closing pages.
const ERROR_RETURN_NAMES: &[&str] = &[
    // Error-return frames that keep executing while a target page may be
    // non-executable; see `mutation_code_addresses` for the ordering.
    "omhook::inline::install_inline_hook",
    "omhook::inline::install_inline_hooks",
    "omhook::inline::unhook_inline_hooks",
    "omhook::inline::commit_prepared_inline_hooks",
    "omhook::inline::commit_replacements",
    "omhook::inline::unhook_replacements",
    "omhook::inline::apply_protection_flags_to",
    "omhook::inline::register_inline_targets",
    "omhook::inline::reserve_inline_targets",
    "omhook::inline::inline_targets_installed",
    "omhook::inline::preferred_error",
    "omhook::inline::release_arenas",
    "omhook::inline::discard_prepared_inline_hooks",
    "omhook::sys::opaque::toggle_bytes_encoding",
    "omhook::sys::opaque::erase_bytes",
    "omhook::sys::enter_mutation",
    "omhook::sys::leave_mutation",
];

/// The complete audit list, in `mutation_code_addresses` order.
fn mutation_window_names() -> Vec<&'static str> {
    let mut names = WINDOW_FUNCTION_NAMES.to_vec();
    names.extend_from_slice(ERROR_RETURN_NAMES);
    names.push(SYSCALL_STUB_NAME);
    names
}

#[derive(Clone, Debug)]
struct TestSymbol {
    address: usize,
    is_text: bool,
    name: String,
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    let end = offset.checked_add(2)?;
    let raw = bytes.get(offset..end)?;
    Some(u16::from_le_bytes(raw.try_into().ok()?))
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let raw = bytes.get(offset..end)?;
    Some(u32::from_le_bytes(raw.try_into().ok()?))
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    let end = offset.checked_add(8)?;
    let raw = bytes.get(offset..end)?;
    Some(u64::from_le_bytes(raw.try_into().ok()?))
}

fn parse_test_symbols() -> Vec<TestSymbol> {
    let executable = std::env::current_exe().unwrap();
    let bytes = fs::read(executable).unwrap();
    assert!(bytes.len() >= 64);
    assert_eq!(&bytes[..4], b"\x7fELF");
    assert!(
        bytes[4] == 1 || bytes[4] == 2,
        "the test binary must be ELF32 or ELF64"
    );
    assert_eq!(bytes[5], 1, "the test binary must be little endian");
    let elf64 = bytes[4] == 2;
    let (section_offset, section_size, section_count) = if elf64 {
        (
            u64_at(&bytes, 0x28).unwrap() as usize,
            usize::from(u16_at(&bytes, 0x3a).unwrap()),
            usize::from(u16_at(&bytes, 0x3c).unwrap()),
        )
    } else {
        (
            u32_at(&bytes, 0x20).unwrap() as usize,
            usize::from(u16_at(&bytes, 0x2e).unwrap()),
            usize::from(u16_at(&bytes, 0x30).unwrap()),
        )
    };
    let minimum_section_size = if elf64 { 64 } else { 40 };
    assert!(section_offset != 0 && section_size >= minimum_section_size && section_count > 0);

    let sections = (0..section_count)
        .map(|index| {
            let start = section_offset + index * section_size;
            let end = start + section_size;
            let section = bytes.get(start..end).unwrap();
            if elf64 {
                (
                    u32_at(section, 4).unwrap(),
                    u64_at(section, 8).unwrap(),
                    u64_at(section, 24).unwrap(),
                    u64_at(section, 32).unwrap(),
                    u32_at(section, 40).unwrap(),
                    u64_at(section, 56).unwrap(),
                )
            } else {
                (
                    u32_at(section, 4).unwrap(),
                    u32_at(section, 8).unwrap() as u64,
                    u32_at(section, 16).unwrap() as u64,
                    u32_at(section, 20).unwrap() as u64,
                    u32_at(section, 24).unwrap(),
                    u32_at(section, 36).unwrap() as u64,
                )
            }
        })
        .collect::<Vec<_>>();
    let (_, _, symtab_offset, symtab_size, strtab_index, symbol_size) = sections
        .iter()
        .copied()
        .find(|(kind, ..)| *kind == 2)
        .expect("the test binary has no .symtab");
    let symbol_size = symbol_size as usize;
    let expected_symbol_size = if elf64 { 24 } else { 16 };
    assert_eq!(symbol_size, expected_symbol_size);
    let symbol_count = symtab_size as usize / symbol_size;
    assert!(symbol_count > 0);
    let (_, _, strtab_offset, strtab_size, _, _) = sections[strtab_index as usize];
    let strtab_start = strtab_offset as usize;
    let strtab_end = strtab_start + strtab_size as usize;
    let strtab = bytes.get(strtab_start..strtab_end).unwrap();

    let mut symbols = Vec::with_capacity(symbol_count);
    for index in 0..symbol_count {
        let start = symtab_offset as usize + index * symbol_size;
        let symbol = bytes.get(start..start + symbol_size).unwrap();
        let name_offset = u32_at(symbol, 0).unwrap() as usize;
        let (section_index, address) = if elf64 {
            (
                u16_at(symbol, 6).unwrap() as usize,
                u64_at(symbol, 8).unwrap() as usize,
            )
        } else {
            (
                u16_at(symbol, 14).unwrap() as usize,
                u32_at(symbol, 4).unwrap() as usize,
            )
        };
        let name_end = strtab[name_offset..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|position| name_offset + position)
            .unwrap_or(strtab.len());
        let name = String::from_utf8_lossy(&strtab[name_offset..name_end]).into_owned();
        if name.is_empty() {
            continue;
        }
        let is_text = section_index != 0
            && section_index < sections.len()
            && sections[section_index].1 & 0x4 != 0;
        symbols.push(TestSymbol {
            address,
            is_text,
            name,
        });
    }
    symbols
}

#[test]
fn page_validation_accepts_an_equivalent_vma_split() {
    let map = |start, end, offset| MapInfo {
        start,
        end,
        perms: MapPerms::READ | MapPerms::EXEC,
        is_private: true,
        offset,
        device: DeviceId::new(8, 2),
        inode: 42,
        path: None,
    };
    let original = map(0x1000, 0x5000, 0);
    let page = CodePage {
        start: 0x2000,
        length: 0x1000,
        original_protection: original.perms.to_prot(),
        mapping: MappingSnapshot::from_map(&original),
    };

    assert!(validate_pages(&[map(0x2000, 0x3000, 0x1000)], std::slice::from_ref(&page),).is_ok());
    assert!(matches!(
        validate_pages(&[map(0x2000, 0x3000, 0)], std::slice::from_ref(&page),),
        Err(Error::MappingChanged)
    ));

    let anonymous = |start, end| MapInfo {
        device: DeviceId::new(0, 0),
        inode: 0,
        ..map(start, end, 0)
    };
    let original = anonymous(0x2000, 0x4000);
    let snapshot = MappingSnapshot::from_map(&original);
    let page = CodePage {
        mapping: snapshot,
        ..page
    };
    for current in [anonymous(0x1000, 0x4000), anonymous(0x2000, 0x3000)] {
        assert!(snapshot.matches_at(&current, 0x2000));
        assert!(
            validate_pages(std::slice::from_ref(&current), std::slice::from_ref(&page)).is_ok()
        );
        let writable = MapInfo {
            perms: current.perms | MapPerms::WRITE,
            ..current.clone()
        };
        assert!(!snapshot.matches_at(&writable, 0x2000));
        assert!(snapshot.matches_at_ignoring_write(&writable, 0x2000));
    }
    assert!(!snapshot.matches_at(&anonymous(0x1000, 0x5000), 0x1000));
    assert!(!snapshot.matches_at(&anonymous(0x1000, 0x5000), 0x4000));
    assert!(!snapshot.matches_at(&anonymous(0x3000, 0x4000), 0x2000));
    for changed in [
        MapInfo {
            is_private: false,
            ..original.clone()
        },
        MapInfo {
            inode: 1,
            ..original.clone()
        },
        MapInfo {
            device: DeviceId::new(8, 2),
            ..original.clone()
        },
        MapInfo {
            perms: MapPerms::READ,
            ..original
        },
    ] {
        assert!(!snapshot.matches_at(&changed, 0x2000));
        assert!(!snapshot.matches_at_ignoring_write(&changed, 0x2000));
    }
}

#[test]
fn drop_exec_preflight_refuses_a_denied_regrant() {
    // The exec-regrant injection is stateful across two protect calls, so
    // this test must serialize against every other protect user.
    let _inline_guard = crate::sys::recover_lock(crate::inline::INLINE_TEST_LOCK.lock());
    let _syscall_guard = crate::sys::recover_lock(crate::sys::tests::SYSCALL_INJECTION_LOCK.lock());
    let _process_guard = crate::sys::recover_lock(crate::sys::PROCESS_LOCK.write());
    let page_size = crate::sys::page_size().unwrap();
    let path = std::env::temp_dir().join(format!("omhook-probe-{}", std::process::id()));
    std::fs::create_dir_all(std::env::temp_dir()).unwrap();
    // Larger aligned lengths exercise mmap2's fixed offset unit even on a
    // kernel with 4 KiB pages. Only the requested file offset has the marker.
    for probe_size in [page_size, page_size * 4, page_size * 16] {
        let offset = probe_size as u64;
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        file.set_len(offset * 2).unwrap();
        file.write_all_at(&[0xa5], offset).unwrap();
        let fd = usize::try_from(file.as_raw_fd()).unwrap();
        PROBE_FIRST_BYTE.store(0, Ordering::Relaxed);
        crate::sys::tests::fail_next_exec_regrant();
        let result = probe_file_descriptor(fd, offset, probe_size);
        crate::sys::tests::restore_exec_regrant();
        std::mem::forget(file);
        let _ = fs::remove_file(&path);
        assert!(
            matches!(
                result,
                Err(Error::MutationPathUnavailable {
                    protection: Some(ref source),
                    ..
                }) if *source == syscalls::Errno::EACCES
            ),
            "unexpected preflight result: {result:?}"
        );
        assert_eq!(PROBE_FIRST_BYTE.load(Ordering::Relaxed), 0xa5);
    }
}

#[test]
fn device_decoding_uses_linux_major_minor() {
    assert_eq!(
        decode_device(0x0164_d22e).unwrap(),
        DeviceId::new(1234, 5678)
    );
}

#[test]
fn pathname_fallback_verifies_file_identity() {
    let path = std::env::current_exe().unwrap();
    let metadata = fs::metadata(&path).unwrap();
    let map = MapInfo {
        start: 0x1000,
        end: 0x2000,
        perms: crate::MapPerms::READ,
        is_private: true,
        offset: 0,
        device: decode_device(metadata.dev()).unwrap(),
        inode: metadata.ino(),
        path: Some(path),
    };

    assert!(open_path_if_same_file(&map).is_ok());

    let mut wrong_inode = map.clone();
    wrong_inode.inode += 1;
    assert!(open_path_if_same_file(&wrong_inode).is_err());

    let mut wrong_device = map;
    wrong_device.device = DeviceId::new(
        wrong_device.device.major.wrapping_add(1),
        wrong_device.device.minor,
    );
    assert!(open_path_if_same_file(&wrong_device).is_err());
}

#[test]
fn replace_many_closes_the_forced_descriptor_on_preflight_exits() {
    let _inline_guard = crate::sys::recover_lock(crate::inline::INLINE_TEST_LOCK.lock());
    let _syscall_guard = crate::sys::recover_lock(crate::sys::tests::SYSCALL_INJECTION_LOCK.lock());
    let _process_guard = crate::sys::recover_lock(crate::sys::PROCESS_LOCK.write());
    assert_preflight_closes(&[]);
    let replacement = Replacement {
        pages: &[],
        address: 0,
        end: 0,
        expected: &[],
        replacement: &[],
    };
    assert_preflight_closes(std::slice::from_ref(&replacement));
}

fn assert_preflight_closes(replacements: &[Replacement<'_>]) {
    let fd = crate::sys::open_self_mem().expect("open /proc/self/mem");
    // SAFETY: both forms name no target bytes; the non-empty form is rejected
    // during preflight before any memory is changed.
    let outcome = unsafe { replace_many(replacements, None, Some(fd), None, false) };
    assert!(
        outcome.is_ok()
            || matches!(
                outcome,
                Err(MutationFailure::Error(Error::InvalidInlineTarget(_)))
            ),
        "unexpected outcome: {}",
        match outcome {
            Ok(_) => "ok",
            Err(MutationFailure::Error(Error::InvalidInlineTarget(_))) => {
                "invalid-inline-target"
            }
            Err(_) => "unexpected",
        }
    );
    let path = format!("/proc/self/fd/{fd}");
    // A sibling test can reuse the descriptor number for an unrelated file
    // between the close and this check, so only a surviving procfs mem link
    // proves a leak.
    let leaked = fs::read_link(&path).is_ok_and(|target| {
        let target = target.to_string_lossy();
        target.starts_with("/proc/") && target.ends_with("/mem")
    });
    assert!(!leaked, "replace_many leaked {fd}");
}

#[test]
fn executable_page_validation_rejects_shared_mappings() {
    let map = MapInfo {
        start: 0x1000,
        end: 0x2000,
        perms: MapPerms::READ | MapPerms::EXEC,
        is_private: false,
        offset: 0,
        device: DeviceId::new(8, 2),
        inode: 42,
        path: None,
    };
    let pages = [CodePage {
        start: 0x1000,
        length: 0x1000,
        original_protection: map.perms.to_prot(),
        mapping: MappingSnapshot::from_map(&map),
    }];
    assert!(matches!(
        validate_pages(std::slice::from_ref(&map), &pages),
        Err(Error::MappingChanged)
    ));
    assert!(matches!(
        capture_pages(
            std::slice::from_ref(&map),
            &Default::default(),
            0x1000,
            1,
            0x1000,
            crate::sys::page_size().unwrap()
        ),
        Err(Error::MappingChanged)
    ));
}

#[test]
fn executable_window_crosses_an_equivalent_vma_split() {
    let mut bytes = [0x90_u8; 8];
    let base = bytes.as_mut_ptr() as usize;
    let map = |start, end, offset| MapInfo {
        start,
        end,
        perms: MapPerms::READ | MapPerms::EXEC,
        is_private: true,
        offset,
        device: DeviceId::new(8, 2),
        inode: 42,
        path: None,
    };
    let split = [map(base, base + 3, 0), map(base + 3, base + 8, 3)];
    let mut window = [0; 8];
    let length = copy_executable_window(&split, base, &mut window).unwrap();
    assert_eq!(&window[..length], &bytes);

    let changed = [map(base, base + 3, 0), map(base + 3, base + 8, 0)];
    let length = copy_executable_window(&changed, base, &mut window).unwrap();
    assert_eq!(length, 3);

    let pages = split.map(|map| CodePage {
        start: map.start,
        length: map.end - map.start,
        original_protection: map.perms.to_prot(),
        mapping: MappingSnapshot::from_map(&map),
    });
    assert!(mapped_bytes_match(&pages, base + 1, &bytes[1..7]).unwrap());
    // SAFETY: both synthetic page chunks are writable parts of `bytes`.
    unsafe { copy_mapped_bytes(&pages, base + 1, &[0xcc; 6]) };
    assert_eq!(bytes, [0x90, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0x90]);
}

#[test]
fn mutation_code_pages_reject_targets_on_those_pages() {
    let map = |start: usize| MapInfo {
        start,
        end: start + 0x1000,
        perms: MapPerms::READ | MapPerms::EXEC,
        is_private: true,
        offset: 0,
        device: DeviceId::new(8, 2),
        inode: 42,
        path: None,
    };
    let page_size = crate::sys::page_size().unwrap();
    let code = mutation_code_pages(page_size);
    assert!(!code.is_empty());
    assert!(code.iter().all(|page| page.is_multiple_of(page_size)));
    for pair in code.windows(2) {
        assert_eq!(pair[1] - pair[0], page_size);
    }

    let page = |start| CodePage {
        start,
        length: page_size,
        original_protection: libc::PROT_READ | libc::PROT_EXEC,
        mapping: MappingSnapshot::from_map(&map(start)),
    };
    assert!(pages_overlap_mutation_code(&[page(code[0])], &code));
    let unrelated = code[0].wrapping_add(0x1000_0000) & !(page_size - 1);
    assert!(!pages_overlap_mutation_code(&[page(unrelated)], &code));
}

#[test]
fn symbol_audit_covers_the_inline_mutation_window() {
    // No environment gate: a check nobody runs by default is not a check.
    //
    // Two things are checked: the length assertion keeps the two lists in
    // step, and the in-process ELF symbol table catches a function that runs
    // inside the window but was added to neither list. It is still only a
    // proxy: it measures the layout of this test binary, which the two
    // `#[cfg(test)]` injection points already make larger than a release one.
    // The audit reads live symbol and rodata pages while sibling suites may
    // swap exactly those pages through PrivateFileValidation; hold the shared process
    // test lock so it never overlaps an in-process mutation.
    let _process_guard = crate::sys::recover_lock(crate::inline::INLINE_TEST_LOCK.lock());
    // PLT PrivateFileValidation tests swap live pages under PROCESS_TEST_LOCK and the
    // shared private-file validation probe takes no lock at all; this audit walks symbol
    // strings that those swaps can invalidate mid-read, so serialize against
    // every page-mutating suite before reading the test executable.
    let _syscall_injections =
        crate::sys::recover_lock(crate::sys::tests::SYSCALL_INJECTION_LOCK.lock());
    #[cfg(feature = "plt")]
    let _plt_guard = crate::sys::recover_lock(crate::plt::tests::PROCESS_TEST_LOCK.lock());
    let addresses = mutation_code_addresses();
    let names = mutation_window_names();
    assert_eq!(
        addresses.len(),
        names.len(),
        "the production address list and audit name list drifted"
    );
    let entries: Vec<(&str, usize)> = names.iter().copied().zip(addresses).collect();
    let mut lowest = usize::MAX;
    let mut highest = 0_usize;
    for &(_, address) in &entries {
        lowest = lowest.min(address);
        highest = highest.max(address);
    }

    let symbols = parse_test_symbols();
    let patterns = entries
        .iter()
        .map(|(expected, _)| {
            let mut pattern = String::new();
            for segment in expected.split("::") {
                pattern.push_str(&segment.len().to_string());
                pattern.push_str(segment);
            }
            pattern
        })
        .collect::<Vec<_>>();

    // Symbols report link-time addresses while function pointers report the
    // relocated runtime addresses of this PIE; derive the load bias from an
    // exact anchor symbol first.
    let mut bias: Option<isize> = None;
    let mut matched_symbols: Vec<&TestSymbol> = Vec::with_capacity(entries.len());
    for (index, ((expected, runtime), pattern)) in entries.iter().zip(&patterns).enumerate() {
        let candidates = symbols
            .iter()
            .filter(|symbol| symbol.is_text && symbol.name.contains(pattern.as_str()))
            .collect::<Vec<_>>();
        assert!(
            !candidates.is_empty(),
            "mutation-window function {expected} has no symbol in the test binary"
        );
        // The no-closure rule protects the window code that runs between
        // opening and closing pages; error-return frames may use closures.
        for symbol in &candidates {
            assert!(
                !(index < WINDOW_FUNCTION_NAMES.len() && symbol.name.contains("NC")),
                "mutation-window function {expected} still has suspicious symbol \
                 {} at {:#x}",
                symbol.name,
                symbol.address
            );
        }
        if bias.is_none() {
            let anchor = candidates
                .iter()
                .copied()
                .find(|symbol| symbol.name.ends_with(pattern.as_str()))
                .unwrap_or(candidates[0]);
            bias = Some(*runtime as isize - anchor.address as isize);
        }
        let bias = bias.unwrap();
        let matched = candidates
            .iter()
            .copied()
            .find(|symbol| (symbol.address as isize + bias) as usize == *runtime)
            .unwrap_or_else(|| {
                panic!("mutation-window function {expected} has no matching symbol")
            });
        let address = (matched.address as isize + bias) as usize;
        assert!(
            address >= lowest && address <= highest,
            "mutation-window symbol {} at {address:#x} lies outside \
             the covered span {lowest:#x}..={highest:#x}",
            matched.name
        );
        matched_symbols.push(matched);
        assert_eq!(
            address, *runtime,
            "mutation-window symbol {} has an inconsistent load bias",
            matched.name
        );
    }

    // The rejected span includes the page starting two pages after the highest
    // entry page. Require every listed body to end before that final guard page
    // and bound each symbol by the next text symbol at a higher address.
    let page_size = crate::sys::page_size().unwrap();
    let bias = bias.unwrap();
    let covered_end = crate::sys::page_start(highest, page_size) + 2 * page_size;
    let covered_end = (covered_end as isize - bias) as usize;
    let mut text_addresses: Vec<usize> = symbols
        .iter()
        .filter(|symbol| symbol.is_text)
        .map(|symbol| symbol.address)
        .collect();
    text_addresses.sort_unstable();
    // Generic instantiations and cold closure bodies can reuse a listed
    // function's name while the linker places them far outside the span;
    // the body that must stay in-span is exactly the matched function.
    for symbol in &matched_symbols {
        let address = symbol.address;
        let Some(next) = text_addresses
            .iter()
            .find(|candidate| **candidate > address)
        else {
            continue;
        };
        assert!(
            *next <= covered_end,
            "mutation-window symbol {} can extend past the covered span \
             end {covered_end:#x} (next text symbol at {next:#x})",
            symbol.name
        );
    }
}

#[test]
fn page_walk_skips_non_overlapping_pages() {
    let mut bytes = [0x90_u8; 8];
    let base = bytes.as_mut_ptr() as usize;
    let page_size = crate::sys::page_size().unwrap();
    let real = crate::sys::page_start(base, page_size);
    let identity = MappingSnapshot::from_map(&MapInfo {
        start: real,
        end: real + page_size,
        perms: MapPerms::READ | MapPerms::WRITE,
        is_private: true,
        offset: 0,
        device: DeviceId::new(8, 2),
        inode: 42,
        path: None,
    });
    let page = |start| CodePage {
        start,
        length: page_size,
        original_protection: libc::PROT_READ | libc::PROT_WRITE,
        mapping: identity,
    };
    let pages = [page(real - page_size), page(real), page(real + page_size)];
    assert!(mapped_bytes_match(&pages, base, &bytes).unwrap());
    // SAFETY: only the middle synthetic page overlaps this stack slice.
    unsafe { copy_mapped_bytes(&pages, base, &[0xcc; 8]) };
    assert_eq!(bytes, [0xcc; 8]);
}

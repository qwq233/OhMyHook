use super::*;
use crate::maps::DeviceId;
use std::sync::atomic::{AtomicBool, Ordering};

static FAIL_FORCED_CLOSE: AtomicBool = AtomicBool::new(false);
static FAIL_FORCED_WRITE: AtomicBool = AtomicBool::new(false);
static FAIL_FORCED_UNAVAILABLE: AtomicBool = AtomicBool::new(false);

/// Makes the next close of the forced-access descriptor report failure,
/// wherever in the forced path it is reached.
pub(crate) fn fail_next_forced_close() {
    FAIL_FORCED_CLOSE.store(true, Ordering::Release);
}

/// Reports whether an armed close failure is still waiting to be consumed.
///
/// A test asserts this is `false` afterwards, so that moving or deleting the
/// injection point turns the test red instead of silently green.
pub(crate) fn forced_close_failure_pending() -> bool {
    FAIL_FORCED_CLOSE.load(Ordering::Acquire)
}

pub(super) fn take_forced_close_failure() -> bool {
    FAIL_FORCED_CLOSE.swap(false, Ordering::AcqRel)
}

/// Makes the next forced write report failure *after* really performing it, so
/// the restore that follows undoes exactly what was written.
pub(crate) fn fail_next_forced_write() {
    FAIL_FORCED_WRITE.store(true, Ordering::Release);
}

/// Reports whether an armed write failure is still waiting to be consumed.
pub(crate) fn forced_write_failure_pending() -> bool {
    FAIL_FORCED_WRITE.load(Ordering::Acquire)
}

pub(super) fn take_forced_write_failure() -> bool {
    FAIL_FORCED_WRITE.swap(false, Ordering::AcqRel)
}

/// Makes the next mutation behave as though `/proc/self/mem` were unavailable.
///
/// This exercises the elevation fallback without installing a broad seccomp
/// filter that can also break libc's own open/read/exit machinery.
pub(crate) fn fail_next_forced_unavailable() {
    FAIL_FORCED_UNAVAILABLE.store(true, Ordering::Release);
}

pub(super) fn take_forced_unavailable_failure() -> bool {
    FAIL_FORCED_UNAVAILABLE.swap(false, Ordering::AcqRel)
}

/// Only the classification is pinned here. That a denial really reaches the
/// forced channel end to end is covered by the inline integration tests, and
/// only for `EPERM`.
#[test]
fn mprotect_denials_and_mapping_limits_are_classified_as_retryable() {
    for errno in [
        libc::EPERM,
        libc::EACCES,
        libc::ENOSYS,
        libc::EIO,
        // vm.max_map_count reached while splitting the target mapping. The
        // forced channel never splits a mapping, so this is retryable.
        libc::ENOMEM,
    ] {
        let error = Error::SystemCall {
            operation: "mprotect",
            source: std::io::Error::from_raw_os_error(errno),
        };
        assert!(page_elevation_denied(&error), "errno {errno}");
    }

    // Only mprotect denials retry; an unrelated failure must surface.
    let unrelated = Error::SystemCall {
        operation: "mmap",
        source: std::io::Error::from_raw_os_error(libc::ENOMEM),
    };
    assert!(!page_elevation_denied(&unrelated));
    let other = Error::SystemCall {
        operation: "mprotect",
        source: std::io::Error::from_raw_os_error(libc::EFAULT),
    };
    assert!(!page_elevation_denied(&other));
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
const MUTATION_WINDOW_NAMES: &[&str] = &[
    "omhook::inline::patch::replace_many",
    "omhook::inline::patch::replace_many_mutating",
    "omhook::inline::patch::replace_many_forced",
    "omhook::inline::patch::replace_many_with_elevation",
    "omhook::inline::patch::page_elevation_denied",
    "omhook::inline::patch::page_protection_lost",
    "omhook::inline::patch::exec_restore_denied",
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
    "omhook::inline::patch::page::writable_protection",
    "omhook::sys::inline::flush_instruction_cache_ranges",
    "omhook::sys::protect",
    "omhook::sys::protect_checked",
    "omhook::sys::inline::flush_instruction_cache_ranges_checked",
    "omhook::sys::inline::sync_instruction_stream",
    "omhook::sys::syscall_result",
    "omhook::sys::syscall_failure",
    "omhook::sys::page_start",
    "omhook::sys::fail_stop",
    SYSCALL3_NAME,
    SYSCALL1_NAME,
    "omhook::sys::mem::pwrite_self_mem_checked",
    "omhook::sys::mem::pwrite64",
    "omhook::sys::mem::close_self_mem",
    "omhook::inline::patch::close_forced_descriptor",
    SYSCALL_STUB_NAME,
];

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
        mapping: MappingIdentity::from_map(&original),
    };

    assert!(validate_pages(&[map(0x2000, 0x3000, 0x1000)], std::slice::from_ref(&page),).is_ok());
    assert!(matches!(
        validate_pages(&[map(0x2000, 0x3000, 0)], std::slice::from_ref(&page),),
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
        mapping: MappingIdentity::from_map(&map),
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
        mapping: MappingIdentity::from_map(&map(start)),
    };
    assert!(pages_overlap_mutation_code(&[page(code[0])], &code));
    let unrelated = code[0].wrapping_add(0x1000_0000) & !(page_size - 1);
    assert!(!pages_overlap_mutation_code(&[page(unrelated)], &code));
}

#[test]
fn symbol_audit_covers_the_inline_mutation_window() {
    // No environment gate: a check nobody runs by default is not a check.
    //
    // Two different things are checked, and only one of them survives without
    // `nm`. The length assertion below only keeps the two lists in step with
    // each other; it cannot notice a function that runs inside the window and
    // was added to neither. Catching that needs the symbol table, so on a
    // device the audit degrades to the weaker half. It is also only ever a
    // proxy: it measures the layout of this test binary, which the two
    // `#[cfg(test)]` injection points already make larger than a release one.
    let addresses = mutation_code_addresses();
    assert_eq!(
        addresses.len(),
        MUTATION_WINDOW_NAMES.len(),
        "the production address list and audit name list drifted"
    );
    let entries: Vec<(&str, usize)> = MUTATION_WINDOW_NAMES
        .iter()
        .copied()
        .zip(addresses)
        .collect();
    let mut lowest = usize::MAX;
    let mut highest = 0_usize;
    for &(_, address) in &entries {
        lowest = lowest.min(address);
        highest = highest.max(address);
    }

    let executable = std::env::current_exe().unwrap();
    let mut symbols: Vec<(usize, bool, String)> = Vec::new();
    for (tool, demangle) in [("llvm-nm", "-C"), ("nm", "--demangle")] {
        let output = match std::process::Command::new(tool)
            .arg(demangle)
            .arg(&executable)
            .output()
        {
            Ok(output) => output,
            Err(_) => continue,
        };
        assert!(
            output.status.success(),
            "{tool} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = String::from_utf8_lossy(&output.stdout);
        let mut parsed: Vec<(usize, bool, String)> = Vec::new();
        for line in text.lines() {
            let mut fields = line.split_whitespace();
            let Some(address) = fields.next() else {
                continue;
            };
            let Some(kind) = fields.next() else {
                continue;
            };
            let name = fields.collect::<Vec<_>>().join(" ");
            let Ok(address) = usize::from_str_radix(address, 16) else {
                continue;
            };
            let is_text = kind.starts_with('t') || kind.starts_with('T');
            parsed.push((address, is_text, name));
        }
        if parsed.iter().any(|(_, _, name)| name.contains("::")) {
            symbols = parsed;
            break;
        }
        // This tool left Rust symbols mangled: for example the rustup
        // sysroot's `llvm-nm -C` has no Rust v0 demangler, so its output
        // keeps `_R…` names and every exact comparison below would fail.
        // Discard it and prefer a tool that really demangles.
    }
    if symbols.is_empty() {
        // No demangling `nm` here, which is normal when the suite runs on a
        // device. The list-length assertion above already ran, so a function
        // added to the window without being registered is still caught; only
        // the span check needs a symbol table and is skipped.
        log::warn!("symbol audit: no demangling llvm-nm or nm on PATH, span check skipped");
        return;
    }

    // Symbols report link-time addresses while function pointers report the
    // relocated runtime addresses of this PIE; derive the load bias from an
    // exact anchor symbol first.
    let bias = entries
        .iter()
        .find_map(|&(expected, runtime)| {
            symbols
                .iter()
                .find(|(_, _, name)| name.as_str() == expected)
                .map(|&(link, _, _)| runtime as isize - link as isize)
        })
        .expect("mutation-window anchor symbol is missing");

    for (expected, runtime) in &entries {
        let closure = format!("{expected}::{{closure");
        for (address, _, name) in &symbols {
            assert!(
                !name.contains(&closure),
                "mutation-window function {expected} still has closure symbol \
                 {name} at {address:#x}"
            );
        }
        let mut found = 0;
        for (link, _, name) in &symbols {
            let exact = name == expected;
            let clone = name
                .strip_prefix(expected)
                .is_some_and(|rest| rest.starts_with(" (.llvm."));
            if exact || clone {
                found += 1;
                let address = (*link as isize + bias) as usize;
                assert!(
                    address >= lowest && address <= highest,
                    "mutation-window symbol {name} at {address:#x} lies outside \
                     the covered span {lowest:#x}..={highest:#x}"
                );
                if exact {
                    assert_eq!(
                        address, *runtime,
                        "mutation-window symbol {name} has an inconsistent load bias"
                    );
                }
            }
        }
        assert!(
            found > 0,
            "mutation-window function {expected} has no symbol in the test binary"
        );
    }

    // The rejected span includes the page starting two pages after the highest
    // entry page. Require every listed body to end before that final guard page
    // and bound each symbol by the next text symbol at a higher address.
    let page_size = crate::sys::page_size().unwrap();
    let covered_end = crate::sys::page_start(highest, page_size) + 2 * page_size;
    let covered_end = (covered_end as isize - bias) as usize;
    let mut text_addresses: Vec<usize> = symbols
        .iter()
        .filter(|&&(_, is_text, _)| is_text)
        .map(|&(address, _, _)| address)
        .collect();
    text_addresses.sort_unstable();
    for (link, _, name) in &symbols {
        let exact = entries.iter().any(|(expected, _)| name == expected);
        let clone = entries.iter().any(|(expected, _)| {
            name.strip_prefix(expected)
                .is_some_and(|rest| rest.starts_with(" (.llvm."))
        });
        if !exact && !clone {
            continue;
        }
        let address = *link;
        let Some(next) = text_addresses
            .iter()
            .find(|candidate| **candidate > address)
        else {
            continue;
        };
        assert!(
            *next <= covered_end,
            "mutation-window symbol {name} can extend past the covered span \
             end {covered_end:#x} (next text symbol at {next:#x})"
        );
    }
}

#[test]
fn page_walk_skips_non_overlapping_pages() {
    let mut bytes = [0x90_u8; 8];
    let base = bytes.as_mut_ptr() as usize;
    let page_size = crate::sys::page_size().unwrap();
    let real = crate::sys::page_start(base, page_size);
    let identity = MappingIdentity::from_map(&MapInfo {
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

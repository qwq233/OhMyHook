use super::arch::RelocationKind;
use super::elf::ImageMappingKey;
use super::inspect::build_inspection_report;
use super::*;
use crate::maps::{DeviceId, read_self_maps};
#[cfg(target_arch = "aarch64")]
use crate::maps::{SmapInfo, SmapVmFlags};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

static FIRST_SLOT: AtomicUsize = AtomicUsize::new(20);
static SECOND_SLOT: AtomicUsize = AtomicUsize::new(21);
static LAZY_SLOT: AtomicUsize = AtomicUsize::new(0);
static RECORDED_LAZY_SLOT: AtomicUsize = AtomicUsize::new(0);
static IFUNC_SLOT: AtomicUsize = AtomicUsize::new(0);
static CURRENT_REPLACEMENT_SLOT: AtomicUsize = AtomicUsize::new(30);
/// Serializes tests that mutate the executable's own PLT or global switches.
pub(crate) static PROCESS_TEST_LOCK: Mutex<()> = Mutex::new(());

/// Locks `PROCESS_TEST_LOCK`, recovering it after a sibling test unwound.
pub(crate) fn process_test_guard() -> std::sync::MutexGuard<'static, ()> {
    // The inline tests take SYSCALL_INJECTION_LOCK first, then this lock.
    // Taking the injection lock here too makes every order safe without a
    // separate helper for callers that do not arm injections.
    let _injections = crate::sys::recover_lock(crate::sys::tests::SYSCALL_INJECTION_LOCK.lock());
    let guard = PROCESS_TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    drop(_injections);
    guard
}

/// Takes both the process and syscall-injection locks.
pub(crate) fn injection_test_guard() -> InjectionTestGuard {
    InjectionTestGuard {
        _injections: crate::sys::recover_lock(crate::sys::tests::SYSCALL_INJECTION_LOCK.lock()),
        _process: PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
    }
}

pub(crate) struct InjectionTestGuard {
    _process: std::sync::MutexGuard<'static, ()>,
    _injections: std::sync::MutexGuard<'static, ()>,
}

/// Resets process-global PLT test state after a sibling unwound.
#[cfg(feature = "inline")]
pub(crate) fn reset_state() {}

unsafe extern "C" {
    fn getpid() -> i32;
}

#[inline(never)]
fn executable_marker() {}

pub(crate) use crate::sys::tests::forced_writes_supported;

fn test_image(header: usize) -> ImageMappingKey {
    ImageMappingKey::for_test(DeviceId::new(1, 2), 3, header)
}

extern "C" fn passthrough_getpid() -> i32 {
    // SAFETY: SYS_getpid takes no arguments and cannot fail for a live
    // process. This fallback does not depend on the returned previous.
    unsafe { syscalls::syscall!(syscalls::Sysno::getpid).unwrap_or(0) as i32 }
}

fn scan_for(addresses: &[(usize, JumpSlotState)]) -> (ElfImageSelector, ScannedHook) {
    let maps = read_self_maps().unwrap();
    let map = find_map_containing(&maps, addresses[0].0, std::mem::size_of::<usize>()).unwrap();
    let image_selector = ElfImageSelector::current_executable().unwrap();
    let mut image =
        ImageMappingKey::for_test(image_selector.device, image_selector.inode, map.start);
    if let Some(bound) = image_selector.bound_image() {
        image.header = bound.header;
        image.loader_base = Some(bound.loader_base);
    }
    let relocations = addresses
        .iter()
        .map(|&(address, jump_slot_state)| {
            FoundRelocation::for_test(address, image, RelocationKind::JumpSlot, 0, jump_slot_state)
        })
        .collect();
    let images = Arc::from([FoundImage {
        id: image,
        load_ranges: vec![(map.start, map.end)],
        build_id: None,
    }]);
    (
        image_selector,
        ScannedHook {
            relocations,
            images,
        },
    )
}

fn installed_handle(slots: &[&AtomicUsize], previous: usize, replacement: usize) -> PltHookHandle {
    for slot in slots {
        slot.store(previous, Ordering::SeqCst);
    }
    let addresses = slots
        .iter()
        .map(|slot| (slot.as_ptr() as usize, JumpSlotState::Resolved))
        .collect::<Vec<_>>();
    let (image_selector, scan) = scan_for(&addresses);
    let request = PltHookRequest::new(
        &image_selector,
        c"symbol",
        std::ptr::with_exposed_provenance(replacement),
    )
    .unwrap();
    let maps = read_self_maps().unwrap();
    let plan = build_hook_plan(&request, &scan).unwrap();
    let scans = [Some(scan)];
    let plans = [Some(plan)];
    let mut records = prepare_plt_records(
        &[request],
        &maps,
        &scans,
        &plans,
        &Arc::new(BTreeMap::new()),
    )
    .unwrap();
    let plan = plans[0].as_ref().unwrap();
    for slot in slots {
        slot.store(replacement, Ordering::SeqCst);
    }
    let record = records[0].take().unwrap();
    {
        let _process_guard = crate::sys::PROCESS_LOCK.write().unwrap();
        record_installed_writes(record.id, &plan.writes);
    }
    PltHookHandle {
        previous: crate::sys::encode_usize(plan.previous),
        slots: plan.slots,
        private_file_validation: PrivateFileValidation::Unvalidated,
        forced_descriptor_close_errno: None,
        record: Some(record),
    }
}

fn empty_plan(previous: usize) -> HookPlan {
    HookPlan {
        previous,
        slots: NonZeroUsize::new(1).unwrap(),
        writes: Vec::new(),
    }
}

fn pointer_write(slot: &AtomicUsize, expected: usize, replacement: usize) -> StoredPointerWrite {
    StoredPointerWrite {
        image: test_image(0),
        address: slot.as_ptr() as usize,
        expected,
        replacement,
    }
}

fn range_work(start: usize, map_index: usize, chunks: Range<usize>) -> RangeWork {
    RangeWork {
        range: WritableRange {
            start,
            length: 0x1000,
            map_index,
            original_protection: libc::PROT_READ,
        },
        chunks,
    }
}

fn range_chunk(hook_index: usize, writes: Range<usize>) -> RangeChunk {
    RangeChunk {
        hook_index,
        writes,
        committed: false,
    }
}

#[cfg(target_arch = "aarch64")]
mod aarch64;
mod api;
mod groups;
mod install;
mod mutation;

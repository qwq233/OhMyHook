use super::arch::RelocationKind;
use super::elf::ImageId;
use super::inspect::build_inspection_report;
use super::*;
use crate::maps::read_self_maps;
use std::process::Command;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const INSPECT_CHILD: &str = "OMHOOK_INSPECT_CHILD";
const PUBLICATION_CHILD: &str = "OMHOOK_PUBLICATION_CHILD";
const STRICT_CHILD: &str = "OMHOOK_STRICT_CHILD";
const SYSCONF_CHILD: &str = "OMHOOK_SYSCONF_CHILD";

static FIRST_SLOT: AtomicUsize = AtomicUsize::new(20);
static SECOND_SLOT: AtomicUsize = AtomicUsize::new(21);
static LAZY_SLOT: AtomicUsize = AtomicUsize::new(0);
static RECORDED_LAZY_SLOT: AtomicUsize = AtomicUsize::new(0);
static IFUNC_SLOT: AtomicUsize = AtomicUsize::new(0);
static CURRENT_REPLACEMENT_SLOT: AtomicUsize = AtomicUsize::new(30);
static STATEFUL_SLOT_TEST_LOCK: Mutex<()> = Mutex::new(());

unsafe extern "C" {
    fn getpid() -> i32;
}

#[inline(never)]
fn executable_marker() {}

fn test_image(header: usize) -> ImageId {
    ImageId::for_test(DeviceId::new(1, 2), 3, header)
}

extern "C" fn passthrough_getpid() -> i32 {
    // SAFETY: SYS_getpid takes no arguments and cannot fail for a live
    // process. This fallback does not depend on the returned previous.
    unsafe { syscalls::raw_syscall!(syscalls::Sysno::getpid) as i32 }
}

fn scan_for(addresses: &[(usize, JumpSlotState)]) -> (Target, ScannedHook) {
    let maps = read_self_maps().unwrap();
    let map = find_map_containing(&maps, addresses[0].0, std::mem::size_of::<usize>()).unwrap();
    let target = Target::current_executable().unwrap();
    let image = ImageId::for_test(target.device, target.inode, map.start);
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
        target,
        ScannedHook {
            relocations,
            images,
        },
    )
}

fn run_child(test: &str, environment: &str) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env(environment, "1")
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let _ = child.wait();
            panic!("{test} child exceeded its deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(status.success(), "{test} child failed: {status}");
}

fn installed_handle(slots: &[&AtomicUsize], previous: usize, replacement: usize) -> AppliedHook {
    for slot in slots {
        slot.store(previous, Ordering::SeqCst);
    }
    let addresses = slots
        .iter()
        .map(|slot| (slot.as_ptr() as usize, JumpSlotState::Resolved))
        .collect::<Vec<_>>();
    let (target, scan) = scan_for(&addresses);
    let hook = Hook::new(
        &target,
        c"symbol",
        std::ptr::with_exposed_provenance(replacement),
    )
    .unwrap();
    let maps = read_self_maps().unwrap();
    let plan = build_hook_plan(&hook, &scan).unwrap();
    let scans = [Some(scan)];
    let plans = [Some(plan)];
    let mut ledgers =
        prepare_plt_ledgers(&[hook], &maps, &scans, &plans, &Arc::new(BTreeMap::new())).unwrap();
    let plan = plans[0].as_ref().unwrap();
    for slot in slots {
        slot.store(replacement, Ordering::SeqCst);
    }
    let ledger = ledgers[0].take().unwrap();
    {
        let _process_guard = crate::sys::PROCESS_LOCK.write().unwrap();
        record_installed_writes(ledger.id, &plan.writes);
    }
    AppliedHook {
        previous: crate::sys::encode_usize(plan.previous),
        slots: plan.slots,
        concealment: Concealment::InPlace("concealment not requested"),
        ledger: Some(ledger),
    }
}

fn empty_plan(previous: usize) -> HookPlan {
    HookPlan {
        previous,
        slots: NonZeroUsize::new(1).unwrap(),
        writes: Vec::new(),
    }
}

fn pointer_write(slot: &AtomicUsize, expected: usize, replacement: usize) -> PointerWrite {
    PointerWrite {
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

fn range_chunk(hook: usize, writes: Range<usize>) -> RangeChunk {
    RangeChunk {
        hook,
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

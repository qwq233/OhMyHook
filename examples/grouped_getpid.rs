use omhook::{
    Hook, HookGroup, MutationBudget, OriginalSlot, Target, install_hook_groups_with_budget,
};
use std::{io, mem};

type Getpid = unsafe extern "C" fn() -> i32;
static ORIGINAL_GETPID: OriginalSlot = OriginalSlot::new();

unsafe extern "C" {
    fn getpid() -> i32;
}

#[inline(never)]
fn call_getpid() -> i32 {
    // SAFETY: getpid has no arguments or caller-side preconditions.
    unsafe { getpid() }
}

fn raw_getpid() -> i32 {
    // SAFETY: SYS_getpid takes no arguments and cannot fail for a live process.
    unsafe { syscalls::raw_syscall!(syscalls::Sysno::getpid) as i32 }
}

extern "C" fn replacement_getpid() -> i32 {
    let pid = ORIGINAL_GETPID
        .get()
        .filter(|original| !original.is_null())
        .map_or_else(raw_getpid, |original| {
            // SAFETY: the installer publishes getpid's exact ABI pointer.
            let original = unsafe { mem::transmute::<*const (), Getpid>(original) };
            // SAFETY: getpid has no arguments or caller-side preconditions.
            unsafe { original() }
        });
    pid + 100_000
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let before = call_getpid();
    let target = Target::current_executable()?;

    let required_hooks = [
        Hook::new(&target, c"getpid", replacement_getpid as *const ())?
            .require_non_null_previous()
            .with_original_slot(&ORIGINAL_GETPID),
    ];
    let optional_hooks = [Hook::new(
        &target,
        c"omhook_optional_symbol",
        replacement_getpid as *const (),
    )?];
    let groups = [
        HookGroup::required(&required_hooks),
        HookGroup::optional(&optional_hooks),
    ];

    // SAFETY: this single-threaded process keeps the executable stable, excludes
    // competing writers, and keeps the ABI-compatible replacement alive.
    let report = unsafe {
        install_hook_groups_with_budget(
            &groups,
            MutationBudget {
                max_images: 1,
                max_slots: 4,
                max_pages: 4,
            },
        )?
    };
    let applied = report[0][0]
        .as_ref()
        .map_err(|error| io::Error::other(error.to_string()))?;
    assert_eq!(ORIGINAL_GETPID.get(), Some(applied.previous()));
    assert!(report[1][0].is_err());

    let hooked = call_getpid();
    assert_eq!(hooked, before + 100_000);
    println!("required group installed; optional symbol was absent");
    Ok(())
}

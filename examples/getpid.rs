use omhook::{ElfImageSelector, HookHandle, OriginalPointerCell, PltHookRequest, install_hook};
use std::mem;

type Getpid = unsafe extern "C" fn() -> i32;
static ORIGINAL_GETPID: OriginalPointerCell = OriginalPointerCell::new();

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
    unsafe { syscalls::syscall!(syscalls::Sysno::getpid).unwrap_or(0) as i32 }
}

extern "C" fn replacement_getpid() -> i32 {
    let pid = ORIGINAL_GETPID
        .get()
        .filter(|original| !original.is_null())
        .map_or_else(raw_getpid, |original| {
            // SAFETY: the installer published getpid's exact C ABI pointer.
            let original = unsafe { mem::transmute::<*const (), Getpid>(original) };
            // SAFETY: getpid has no arguments or caller-side preconditions.
            unsafe { original() }
        });
    pid + 100_000
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Resolve a lazy Linux PLT slot before installation.
    let before = call_getpid();
    let image_selector = ElfImageSelector::current_executable()?;
    let request = PltHookRequest::new(&image_selector, c"getpid", replacement_getpid as *const ())?
        .require_non_null_previous()
        .with_original_pointer_cell(&ORIGINAL_GETPID);

    // SAFETY: this single-threaded process keeps the executable stable, excludes
    // other relocation writers, and keeps the ABI-compatible replacement live.
    let mut applied = unsafe { install_hook(request)? };
    assert_eq!(ORIGINAL_GETPID.get(), Some(applied.previous()));
    assert_eq!(applied.original(), Some(applied.previous()));
    assert!(applied.is_installed());

    let hooked = call_getpid();
    assert_eq!(hooked, before + 100_000);
    println!(
        "getpid PLT hook succeeded: before={before}, hooked={hooked}, slots={}",
        applied.slots()
    );

    // SAFETY: all getpid and replacement calls have completed, and the
    // installation mapping and writer-exclusion guarantees still hold.
    unsafe { applied.unhook()? };
    assert!(!applied.is_installed());
    assert!(applied.original().is_none());
    assert_eq!(ORIGINAL_GETPID.get(), Some(applied.previous()));
    assert_eq!(call_getpid(), before);

    // SAFETY: successful removal is idempotent.
    unsafe { applied.unhook()? };
    Ok(())
}

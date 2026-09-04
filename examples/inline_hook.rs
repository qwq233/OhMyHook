#![allow(clippy::expect_used)]

use omhook::{HookHandle, install_inline_hook};
use std::sync::atomic::{AtomicUsize, Ordering};

type Unary = unsafe extern "C" fn(i32) -> i32;
static ORIGINAL: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" {
    fn abs(value: i32) -> i32;
}

extern "C" fn replacement(value: i32) -> i32 {
    let address = ORIGINAL.load(Ordering::Acquire);
    if address == 0 {
        std::process::abort();
    }
    let original = std::ptr::with_exposed_provenance::<()>(address);
    // SAFETY: main publishes abs's live trampoline before calling the target.
    let original = unsafe { std::mem::transmute::<*const (), Unary>(original) };
    // SAFETY: the caller supplied an input valid for abs.
    unsafe { original(value).wrapping_add(10) }
}

fn main() -> omhook::Result<()> {
    let target = std::hint::black_box(abs as Unary);
    // SAFETY: -1 is valid input for C abs.
    assert_eq!(unsafe { target(-1) }, 1);

    // SAFETY: this single-threaded process excludes execution and competing
    // writers while patching ABI-compatible functions that remain live.
    let (mut hook, completion) =
        unsafe { install_inline_hook(abs as *const (), replacement as *const ())? }.into_parts();
    assert!(matches!(
        completion,
        omhook::InlineInstallCompletion::Complete
    ));
    assert!(hook.is_installed());

    let original = hook.original().expect("missing original trampoline");
    ORIGINAL.store(original.expose_provenance(), Ordering::Release);
    // SAFETY: the installed hook exposes a live trampoline with abs's ABI.
    let original = unsafe { std::mem::transmute::<*const (), Unary>(original) };

    // SAFETY: -1 is valid input for the replacement and original abs.
    assert_eq!(unsafe { target(-1) }, 11);
    // SAFETY: -1 is valid input for C abs, and the hook remains installed.
    assert_eq!(unsafe { original(-1) }, 1);

    // SAFETY: all target, replacement, and trampoline calls have completed.
    ORIGINAL.store(0, Ordering::Release);
    unsafe { hook.unhook()? };
    assert!(!hook.is_installed());
    assert!(hook.original().is_none());
    // SAFETY: -1 is valid input for the restored C abs entry.
    assert_eq!(unsafe { target(-1) }, 1);
    // SAFETY: successful removal is idempotent.
    unsafe { hook.unhook()? };
    Ok(())
}

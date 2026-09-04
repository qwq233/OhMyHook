use omhook::{HookHandle, InlineHook, install_inline_hooks, unhook_inline_hooks};

// An optimized `value + 1` compiles down to a handful of bytes, which on x86_64
// leaves less room before the terminating `ret` than the patch needs, and the
// installer refuses rather than stealing bytes from the next function. The
// black box keeps these entries long enough to hook in a release build.
#[inline(never)]
extern "C" fn add_one(value: i32) -> i32 {
    std::hint::black_box(value) + 1
}

#[inline(never)]
extern "C" fn double(value: i32) -> i32 {
    std::hint::black_box(value) * 2
}

extern "C" fn add_ten(value: i32) -> i32 {
    value + 10
}

extern "C" fn triple(value: i32) -> i32 {
    value * 3
}

fn main() -> omhook::Result<()> {
    let add_one = std::hint::black_box(add_one as extern "C" fn(i32) -> i32);
    let double = std::hint::black_box(double as extern "C" fn(i32) -> i32);
    assert_eq!(add_one(2), 3);
    assert_eq!(double(2), 4);

    let requests = [
        InlineHook::new(add_one as *const (), add_ten as *const ()),
        InlineHook::new(double as *const (), triple as *const ()),
    ];
    // SAFETY: this single-threaded process keeps both target pages quiescent
    // and excludes competing writers while all four functions remain live.
    let (mut hooks, completion) = unsafe { install_inline_hooks(&requests)? }.into_parts();
    assert!(matches!(
        completion,
        omhook::InlineInstallCompletion::Complete
    ));
    assert!(hooks.iter().all(HookHandle::is_installed));
    assert_eq!(add_one(2), 12);
    assert_eq!(double(2), 6);

    // SAFETY: all target and replacement calls have completed, and the
    // installation guarantees still hold for the complete batch.
    unsafe { unhook_inline_hooks(&mut hooks)? };
    assert!(hooks.iter().all(|hook| !hook.is_installed()));
    assert_eq!(add_one(2), 3);
    assert_eq!(double(2), 4);
    Ok(())
}

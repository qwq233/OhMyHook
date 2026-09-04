use omhook::{
    HookHandle, InlineHookRequest, InlineInstallCleanupStatus, install_inline_hooks,
    unhook_inline_hooks,
};

// The black box gives x86 entries room for the normal 5-byte jump. Shorter
// entries need a replacement or relay within short-jump range.
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
        InlineHookRequest::new(add_one as *const (), add_ten as *const ()),
        InlineHookRequest::new(double as *const (), triple as *const ()),
    ];
    // SAFETY: this single-threaded process keeps both target pages quiescent
    // and excludes competing writers while all four functions remain live.
    let mut hooks = unsafe { install_inline_hooks(&requests)? };
    let install_cleanup_status = hooks
        .first()
        .map(|request| request.install_cleanup_status())
        .unwrap_or(InlineInstallCleanupStatus::Complete);
    assert!(matches!(
        install_cleanup_status,
        InlineInstallCleanupStatus::Complete
    ));
    assert!(hooks.iter().all(HookHandle::is_installed));
    assert_eq!(add_one(2), 12);
    assert_eq!(double(2), 6);

    // SAFETY: all target and replacement calls have completed, and the
    // installation guarantees still hold for the complete batch.
    unsafe { unhook_inline_hooks(&mut hooks)? };
    assert!(hooks.iter().all(|request| !request.is_installed()));
    assert_eq!(add_one(2), 3);
    assert_eq!(double(2), 4);
    Ok(())
}

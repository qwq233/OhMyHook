use omhook::{ElfImageSelector, HookHandle, PltHookRequest, install_hooks};

unsafe extern "C" {
    fn getpid() -> i32;
}

#[inline(never)]
fn call_getpid() -> i32 {
    // SAFETY: getpid has no arguments or caller-side preconditions.
    unsafe { getpid() }
}

extern "C" fn replacement_getpid() -> i32 {
    1
}

fn main() -> omhook::Result<()> {
    // Resolve a lazy Linux PLT slot before installation.
    let before = call_getpid();
    let image_selector = ElfImageSelector::current_executable()?;
    let hooks = [
        PltHookRequest::new(&image_selector, c"getpid", replacement_getpid as *const ())?
            .expect_slots(1)?
            .require_non_null_previous(),
        PltHookRequest::new(
            &image_selector,
            c"omhook_missing_symbol",
            replacement_getpid as *const (),
        )?,
    ];

    // SAFETY: this single-threaded process keeps the executable stable,
    // excludes competing writers, and keeps the replacement alive.
    let report = unsafe { install_hooks(&hooks)? };
    let (mut installed, failed) = report.into_parts();
    assert_eq!(installed.len(), 1);
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].0, 1);
    let (index, mut applied) = installed.pop().expect("missing installed handle");
    assert_eq!(index, 0);
    assert_eq!(call_getpid(), 1);
    assert_eq!(applied.original(), Some(applied.previous()));

    // SAFETY: all target and replacement calls have completed, and the
    // installation guarantees still hold during removal.
    unsafe { applied.unhook()? };
    assert_eq!(call_getpid(), before);
    Ok(())
}

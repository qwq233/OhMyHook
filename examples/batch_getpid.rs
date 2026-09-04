use omhook::{Hook, HookHandle, Target, install_hooks};

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
    let target = Target::current_executable()?;
    let hooks = [
        Hook::new(&target, c"getpid", replacement_getpid as *const ())?
            .expect_slots(1)?
            .require_non_null_previous(),
        Hook::new(
            &target,
            c"omhook_missing_symbol",
            replacement_getpid as *const (),
        )?,
    ];

    // SAFETY: this single-threaded process keeps the executable stable,
    // excludes competing writers, and keeps the replacement alive.
    let mut report = unsafe { install_hooks(&hooks)? };
    let missing = report.pop().expect("missing batch result");
    let mut applied = report.pop().expect("missing batch result")?;
    assert!(report.is_empty());
    assert!(missing.is_err());
    assert_eq!(call_getpid(), 1);
    assert_eq!(applied.original(), Some(applied.previous()));

    // SAFETY: all target and replacement calls have completed, and the
    // installation guarantees still hold during removal.
    unsafe { applied.unhook()? };
    assert_eq!(call_getpid(), before);
    Ok(())
}

# Oh My Hook

Oh My Hook is a pure Rust PLT/GOT and inline hook engine for little-endian Linux
and Android on i386, amd64, arm32, and arm64. On arm32, inline hooks require an
armv7 or thumbv7neon target.

On i386 an inline hook rejects any entry that opens with a `call`, which
includes the common position-independent `call __x86.get_pc_thunk.*` prologue.

## Quick Start

This example uses the default features, which enable both hook engines.

```rust,standalone_crate
use omhook::{Hook, HookHandle, Target, install_hook, install_inline_hook};

unsafe extern "C" {
    fn getpid() -> i32;
    fn abs(value: i32) -> i32;
}

extern "C" fn replacement_getpid() -> i32 {
    1
}

extern "C" fn replacement_abs(value: i32) -> i32 {
    let _ = value;
    7
}

fn main() -> omhook::Result<()> {
    // Resolve a lazy PLT slot before replacing it.
    // SAFETY: getpid takes no arguments and has no caller-side preconditions.
    let _ = unsafe { getpid() };
    let target = Target::current_executable()?;
    let hook = Hook::new(&target, c"getpid", replacement_getpid as *const ())?
        .require_non_null_previous();

    // SAFETY: the process keeps the image and ABI-compatible replacement live
    // and excludes loader changes, remapping, and competing writers.
    let mut plt_hook = unsafe { install_hook(hook)? };

    // SAFETY: this single-threaded process keeps libc's abs page quiescent
    // for installation, and both functions stay live with the same ABI.
    let (mut inline_hook, completion) = unsafe {
        install_inline_hook(abs as *const (), replacement_abs as *const ())?
        .into_parts()
    };
    assert!(matches!(completion, omhook::InlineInstallCompletion::Complete));

    // Call through the patched entries.
    // SAFETY: getpid takes no arguments and has no caller-side preconditions.
    assert_eq!(unsafe { getpid() }, 1);
    assert_eq!(unsafe { abs(-2) }, 7);

    // Quiesce affected callers before restoring either hook.
    // SAFETY: the installation guarantees above still hold during removal.
    unsafe {
        inline_hook.unhook()?;
        plt_hook.unhook()?;
    }
    assert_eq!(unsafe { abs(-2) }, 2);
    Ok(())
}
```

## Safety

PLT hooks replace supported ELF relocation slots; inline hooks patch a function
entry and expose its trampoline through `HookHandle::original`. Both return
explicit handles and remain installed if those handles are dropped.

Three obligations are easy to miss and are covered in the guide:

- Installing or removing an **inline** hook writes through
  `/proc/self/mem` while the target page stays executable; every function
  sharing that page must therefore be quiescent — not just the patched entry.
  If forced access is unavailable, the fallback temporarily drops `PROT_EXEC`.
  The installer itself cannot run from a target page in its own mutation-code
  span, so that target is rejected on both paths. PLT hooks carry no page
  requirement.
- The library **terminates the process** when an in-progress mutation cannot be
  rolled back or its internal lock is found poisoned, for example by a panic
  inside the library while the lock is held.
- Callers are responsible for excluding concurrent `dlopen`/`dlclose`/remap of
  the selected images. `LifecycleReadLease` makes that discipline checkable.

Read each unsafe API's complete contract before installing or removing a hook.

## Features

Both engines are enabled by default. To select one, disable default features
and enable either `plt` or `inline` on the `omhook` dependency.

## Documentation

- Guide: built with [mdBook](https://rust-lang.github.io/mdBook/) from `book/`
  and published to GitHub Pages.
- API reference: <https://docs.rs/omhook>
- Runnable examples: `cargo run --example <name>`, listed in the guide.

## License

This library uses `LGPL-3.0-or-later`.

# Getting Started

## Requirements

- A recent stable Rust toolchain. The crate uses edition 2024 and does not
  declare a pinned minimum version; build with an up-to-date toolchain.
- A little-endian Linux or Android target on i386, amd64, arm32, or arm64.
- On arm32, inline hooks additionally require an `armv7` or `thumbv7neon`
  target. Older ARM targets must disable the `inline` feature.

Building for any other platform fails at compile time with an explanatory
`compile_error!` rather than producing a broken library.

## Adding the dependency

```toml
[dependencies]
omhook = "0.1"
```

Both engines are enabled by default. To take only one:

```toml
# PLT/GOT hooks only. Drops the instruction-decoder dependencies entirely.
omhook = { version = "0.1", default-features = false, features = ["plt"] }

# Inline hooks only.
omhook = { version = "0.1", default-features = false, features = ["inline"] }
```

Enabling neither is a compile error. The `inline` feature pulls in `iced-x86`
on x86 targets and `yaxpeax-arch`/`yaxpeax-arm` on arm32; `plt` pulls in
nothing beyond `libc`, `log`, and `syscalls`.

## A first hook

```rust
# extern crate omhook;
use omhook::{Hook, HookHandle, Target, install_hook};

unsafe extern "C" {
    fn getpid() -> i32;
}

extern "C" fn replacement_getpid() -> i32 {
    1
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
    let mut installed = unsafe { install_hook(hook)? };

    // SAFETY: getpid takes no arguments and has no caller-side preconditions.
    assert_eq!(unsafe { getpid() }, 1);

    // SAFETY: the installation guarantees above still hold during removal.
    unsafe { installed.unhook()? };
    Ok(())
}
```

Three things in that snippet are load-bearing.

**Resolve the slot first.** A lazy PLT slot still points at the dynamic
linker's resolver until the symbol is first called. Installing over an
unresolved slot is refused with `InspectionStatus::UnresolvedLazy` rather than
silently replacing the resolver.

**`require_non_null_previous`.** Without it, a successful install may report a
null previous pointer, which is legal but useless if the replacement wants to
call through to the original.

**`unhook` is explicit.** Dropping `installed` leaves the hook in place. This is
deliberate: the library cannot know when your callers have drained, so it never
guesses at destructor time.

## Reading process maps

`read_self_maps` and `read_process_maps` are entirely safe and install nothing.
They are the fastest way to sanity-check what the library sees:

```rust
# extern crate omhook;
fn main() -> omhook::Result<()> {
    for map in omhook::read_self_maps()? {
        println!("{:#x}-{:#x} {:?} {:?}", map.start, map.end, map.perms, map.path);
    }
    Ok(())
}
```

## Next steps

- [PLT/GOT Hooks](plt-hooks.md) for selection, batching, groups, and budgets.
- [Inline Hooks](inline-hooks.md) for trampolines and the prepare/commit
  protocol.
- [Safety Model](safety.md) before shipping any of it. The inline engine in
  particular carries an obligation that is easy to miss and hard to satisfy.

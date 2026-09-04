# Loader Lifecycle

Every unsafe entry point requires that the images it selected are not unloaded,
remapped, or reprotected for the duration of the call, and — for an installed
hook — until it is removed and all affected calls have drained.

The library cannot verify this. It has no way to observe a `dlopen` or
`dlclose` performed by other code in the process, and a fresh `/proc/self/maps`
check cannot rule out same-address ABA replacement: a library unloaded and
another mapped at the same address looks identical to one that never moved.

## `LifecycleReadLease`

`LifecycleReadLease` is how a caller discharges the obligation. It is a
cooperative protocol, and it only works if every participant follows it.

```rust
# extern crate omhook;
use omhook::{Hook, LifecycleReadLease};

static LOADER: std::sync::RwLock<()> = std::sync::RwLock::new(());

// Every loader transition takes the write side, for the complete transition,
// after all hook work for the old generation has finished. It must not call
// into Oh My Hook while holding it.
fn load_plugin() {
    let _guard = LOADER.write().unwrap();
    // dlopen / dlclose here.
}

fn main() -> omhook::Result<()> {
    let hooks: Vec<Hook> = Vec::new();

    // SAFETY: `LOADER` is the single lock every cooperating loader transition
    // takes for writing.
    let lease = unsafe { LifecycleReadLease::acquire(&LOADER) }.unwrap();

    // SAFETY: the installer contract applies; the lease keeps the image
    // generation alive across the call.
    let _report = unsafe { lease.install_hooks(&hooks) }?;
    Ok(())
}
```

The lease mirrors the free functions — `install_hooks`, `install_inline_hooks`,
`prepare_inline_hooks`, `find_loaded_images`, `inspect_hooks`, `unhook`,
`unhook_inline_hooks` — and its type keeps the read guard alive for the whole
call.

## What it proves, and what it does not

It proves exactly one thing: that a specific caller-chosen `RwLock` read guard
was alive across the operation.

It does **not** prove that any loader transition actually takes that lock. If
some other code in the process calls `dlclose` without cooperating, the lease
changes nothing. It is a discipline you opt into, made checkable by the type
system, not a runtime guarantee.

Outside its reach:

- A second copy of this crate compiled into the same process, with its own
  internal lock.
- Any foreign hooking library, JIT, or loader wrapper.
- The dynamic linker's own lazy binding, which writes PLT slots without asking
  anyone.

## Lock order

The required order is the lifecycle read lease first, then this library's
internal process lock. The library takes its own lock inside the operation, so
following the API gives you the right order automatically.

The rule that matters for callers: **a loader transition holding the lifecycle
write lock must not call into Oh My Hook.** Doing so inverts the order and
deadlocks.

## If you do not use it

Nothing forces you to. A single-threaded program that loads everything at
startup and never calls `dlclose` satisfies the requirement without any lock.
The lease exists for programs where that is not obviously true, and for making
the assumption explicit in code review rather than in a comment.

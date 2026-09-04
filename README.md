# Oh My Hook

Oh My Hook is a pure Rust PLT/GOT and inline hook engine for little-endian Linux
and Android on i386, amd64, arm32, and arm64. On arm32, inline hooks require an
armv7 or thumbv7neon target.

## Documentation

- Guide: <https://qwq233.github.io/OhMyHook/>
- API reference: <https://docs.rs/omhook>
- Runnable examples: `cargo run --example <name>`, listed in the guide.

## Quick Start

Start with the [Getting Started](https://qwq233.github.io/OhMyHook/getting-started.html)
guide. It contains the smallest complete PLT example and links to the inline
and batch flows.

## Safety

PLT hooks replace supported ELF relocation slots; inline hooks patch a function
entry and expose its trampoline through `HookHandle::original`. Both return
explicit handles and remain installed if those handles are dropped.

Three obligations are easy to miss and are covered in the guide:

- Installing or removing an **inline** hook writes through
  `/proc/self/mem` while the target page stays executable; every function
  sharing that page must therefore be quiescent — not just the patched entry.
  If forced access is unavailable, the fallback adds `PROT_WRITE` while keeping
  `PROT_EXEC`; only an explicitly pinned `DropExec` request removes it.
  The installer itself cannot run from a target page in its own mutation-code
  span, so that target is rejected on both paths. PLT hooks carry no page
  requirement.
- The library **terminates the process** when an in-progress mutation cannot be
  rolled back, or when its internal lock is found poisoned *inside* the
  mutation window. A lock poisoned outside that window is recovered: the
  library owns no half-written state there, and removal must stay usable.
- Callers are responsible for excluding concurrent `dlopen`/`dlclose`/remap of
  the selected images. `LifecycleReadLease` makes that discipline checkable.

Read each unsafe API's complete contract before installing or removing a hook.

## Features

Both engines are enabled by default. To select one, disable default features
and enable either `plt` or `inline` on the `omhook` dependency.

## License

This library uses `LGPL-3.0-or-later`.

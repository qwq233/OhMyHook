# Examples

The repository ships runnable examples. On a compatible Linux host:

```sh
cargo run --example maps
```

Cross-compiled Android builds must be deployed and run separately.

| Example | What it demonstrates |
| --- | --- |
| `maps` | Safe process-map inspection without installing a hook |
| `inline_hook` | One inline hook, its original trampoline, and removal |
| `inline_batch` | Transactional inline batch installation and removal |
| `getpid` | One PLT hook with an `OriginalPointerCell` and explicit removal |
| `batch_getpid` | Aligned results from independent PLT hook installation |
| `inspect_getpid` | Loaded-image, map, relocation, and selector inspection |
| `strict_getpid` | Strict relocation selection with a mutation budget |
| `grouped_getpid` | Required and optional PLT groups |

## Suggested reading order

1. **`maps`** — no hooking at all. Confirms the library can read your process
   and shows what `MapInfo` contains.
2. **`inspect_getpid`** — the complete PLT preflight with nothing written. If a
   hook is going to be rejected, this is where you find out why.
3. **`getpid`** — the smallest complete install/call/remove cycle, including
   publishing the original through an `OriginalPointerCell` before installation.
4. **`strict_getpid`** — the same thing with every fail-closed assertion turned
   on and a `MutationBudget` capping what may be touched.
5. **`batch_getpid`** and **`grouped_getpid`** — batch semantics and the
   required/optional group policy. `grouped_getpid` intentionally leaves its
   hooks installed and exits with the process instead of demonstrating
   removal; `batch_getpid` shows the complete remove cycle.
6. **`inline_hook`** and **`inline_batch`** — the inline engine. Note that both
   are single-threaded, which is what makes their
   [quiescence](safety-quiescence.md) claim true.

## A note on `inline_batch`

Its target functions call `std::hint::black_box` to leave room for the normal
5-byte x86 jump. Shorter entries need a replacement or relay within short-jump
range. See
[Inline Hooks](inline-hooks.md#how-an-entry-is-analyzed).

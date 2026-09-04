# Inline Hooks

An inline hook overwrites the first instructions of a function entry with a
jump to your replacement, and copies the displaced instructions into a
generated trampoline so the original remains callable.

Read [Whole-Page Quiescence](safety-quiescence.md) before using this engine.
It carries an obligation that PLT hooks do not, and it is not optional.

## Installing

```rust
# extern crate omhook;
use omhook::{HookHandle, install_inline_hook};

#[inline(never)]
extern "C" fn target(value: i32) -> i32 {
    std::hint::black_box(value) + 1
}

#[inline(never)]
extern "C" fn replacement(value: i32) -> i32 {
    std::hint::black_box(value) + 2
}

fn main() -> omhook::Result<()> {
    // SAFETY: this single-threaded process keeps the whole target page
    // quiescent, and both functions stay live with the same ABI.
    let (mut hook, completion) = unsafe {
        install_inline_hook(target as *const (), replacement as *const ())?.into_parts()
    };
    assert!(matches!(completion, omhook::InlineInstallCompletion::Complete));

    let original = hook.original().expect("trampoline");
    assert!(!original.is_null());

    // SAFETY: all calls through the target and trampoline have drained.
    unsafe { hook.unhook()? };
    Ok(())
}
```

## How an entry is analyzed

The installer decodes the target's first instructions until it has enough bytes
to hold the patch jump, then re-encodes any that are position-dependent at the
trampoline's address.

An entry is **refused**, not patched, when:

- An instruction cannot be relocated. Calls, exceptions, system transitions,
  and x87 instructions with observable PC semantics all have meaning tied to
  their original address.
- A PC-relative access would read or write the bytes being stolen.
- A PC-relative address computation (RIP-relative `lea`, `adr`, `adrp`)
  produces a value that addresses the stolen bytes.
- A branch elsewhere in the function targets the middle of a stolen
  instruction.
- The target page contains this crate's own page-mutation code: the default
  path would make the installer non-executable, while the forced path cannot
  satisfy whole-page quiescence while the installer is running there.
- **The entry ends before the patch fits.** Execution cannot fall out of a
  `ret`, an unconditional jump, or an indirect branch, so the bytes after one
  belong to whatever the toolchain placed next. The analyzer stops there. If
  fewer bytes were collected than the patch needs, installation fails rather
  than overwriting the following function.

That last case is the common surprise. An optimized leaf function such as
`fn(i32) -> i32 { value + 1 }` can compile to as little as `endbr64; lea; ret`,
which leaves too little room on x86_64. Hooking it requires a longer entry;
`std::hint::black_box` in the body is enough for a test or example.

The engine never consults symbol sizes, and there is no reliable way for it to
learn where a function ends. Refusing is the only safe response.

## The trampoline

`HookHandle::original` returns the trampoline while the hook is installed, and
`None` afterwards. It is an untyped pointer: converting, calling, or
dereferencing it requires you to prove its ABI, provenance, and lifetime.

The trampoline lives in an executable arena the library allocates near the
target, close enough for the architecture's branch range. It is released when
the hook is removed. If a thread is still executing inside a trampoline when
its arena is unmapped, that thread crashes — draining calls before `unhook` is
part of the contract, not a suggestion.

## Batches

`install_inline_hooks` prepares the whole batch before changing any byte, then
commits it under one lock. Overlapping target ranges are rejected, as is a
batch where one member's replacement lies inside another member's patch range.

`unhook_inline_hooks` removes a batch the same way.

## Prepare and commit

For coordinated work, the expensive analysis can be separated from the moment
of mutation:

```rust
# extern crate omhook;
use omhook::{InlineHook, LifecycleReadLease};

#[inline(never)]
extern "C" fn target(value: i32) -> i32 {
    std::hint::black_box(value) + 1
}

#[inline(never)]
extern "C" fn replacement(value: i32) -> i32 {
    std::hint::black_box(value) + 2
}
fn main() -> omhook::Result<()> {
    let lifecycle = std::sync::RwLock::new(());
    // SAFETY: every cooperating loader transition takes this same lock for
    // writing, for the complete transition.
    let lease = unsafe { LifecycleReadLease::acquire(&lifecycle) }.unwrap();

    let request = InlineHook::new(target as *const (), replacement as *const ());
    // SAFETY: the installer contract applies from here until commit or
    // explicit discard.
    let prepared = unsafe { lease.prepare_inline_hooks(&[request]) }?;

    // Trampoline addresses are known before anything is patched.
    let trampoline = prepared.trampoline(0);

    // SAFETY: the target page is quiescent for the serialized commit.
    let mut installed = match unsafe { prepared.commit() } {
        Ok(outcome) => outcome.into_parts().0,
        Err(failure) => {
            // The batch rolled back and kept its arenas. Split the error,
            // report it, and release the arenas explicitly: dropping the
            // prepared value would leak them.
            let (error, prepared) = failure.into_parts();
            eprintln!("commit failed: {error}");
            // SAFETY: no trampoline was published, so nothing can enter it.
            // A discard error means an executable arena stayed mapped; no
            // target byte is wrong, so report it and carry on.
            if let Err(cleanup) = unsafe { prepared.discard() } {
                eprintln!("arena cleanup failed: {cleanup}");
            }
            return Ok(());
        }
    };

    // SAFETY: all calls have drained and the lease is still held.
    unsafe { lease.unhook_inline_hooks(&mut installed) }?;
    Ok(())
}
```

Preparation runs concurrently with other preparations; only commit serializes
target mutation, and commit revalidates mappings and expected bytes before
writing. Two prepared batches for the same target can coexist — the second
commit fails with `Error::Conflict` and *retains* its arenas, so it stays
retryable after the first is removed.

Publishing a trampoline pointer before commit is the point of this API: a
replacement that needs the original can be fully wired up before the target
ever redirects to it.

## Cleanup-pending removal

If the target is restored but an arena cannot be unmapped, `unhook` returns
`Error::InlineCleanupPending`. This is not a failed removal:

- The target is already restored.
- `is_installed` reports `false` and `original` returns `None`.
- Retrying `unhook` releases only the remaining arenas.

Treat it as "the hook is gone, memory is still held". `InlineCommitError` and
this state are why inline handles must not be discarded on the error path —
dropping one leaks its executable arena.

Do not confuse it with `Error::ForcedDescriptorLeaked`, which says the opposite:
that removal was **undone**, so the target is still patched, `is_installed`
still reports `true`, and the call should be retried. Only a file descriptor
leaked there.

## Data references into the overwritten bytes

Inline hooking replaces the entry's first instruction bytes with the branch.
Code that later reads those exact bytes as data ? typically self-checksumming
or anti-tamper checks ? therefore observes different bytes no matter which
engine it uses.

The analyzer follows the destination register of a stolen ADR or ADRP through
register moves and constant offsets for up to 32 following instructions. When
an access is *proven* to land inside the overwritten bytes, installation fails
with `Error::InlineDataReference` instead of silently corrupting that check.
Unrecognized uses do not reject the target; a data reference that leaves the
analyzed window remains part of the caller's safety contract, exactly like a
control-flow edge that enters the overwritten range.

`AppliedInlineHook::sync_core` reports whether the kernel's sync-core
membarrier is active. When it reports `false`, other cores are synchronized
only by your quiescence discipline; `instruction_stream_sync_capability()`
answers the same question before installing.

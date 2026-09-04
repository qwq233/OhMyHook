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
    let mut hook =
        unsafe { install_inline_hook(target as *const (), replacement as *const ())? };
    assert!(matches!(hook.install_cleanup_status(), omhook::InlineInstallCleanupStatus::Complete));

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

- An instruction cannot be relocated. This includes ARM/AArch64 calls,
  x86 indirect calls and call-to-next-instruction PC discovery, exceptions,
  system transitions, and x87 instructions with observable PC semantics.
  Ordinary x86 direct calls are relocated; recognized i686 PC-thunks preserve
  the original return-address value.
- A PC-relative access would read or write the bytes being stolen.
- A PC-relative address computation (RIP-relative `lea`, `adr`, `adrp`)
  produces a value that addresses the stolen bytes.
- A branch in the decoded entry targets the middle of a stolen
  instruction.
- The target page contains this crate's own page-mutation code: the pinned
  drop-exec path must make the installer non-executable, while the forced path cannot
  satisfy whole-page quiescence while the installer is running there.
- **The entry ends before the patch fits.** Execution cannot fall out of a
  `ret`, an unconditional jump, or an indirect branch, so the bytes after one
  belong to whatever the toolchain placed next. The analyzer stops there. If
  fewer bytes were collected than the patch needs, installation fails rather
  than overwriting the following function.

An optimized leaf function such as
`fn(i32) -> i32 { value + 1 }` can compile to as little as `endbr64; lea; ret`,
which can leave too little room for the normal 5-byte x86_64 jump. An entry
with at least two complete instruction bytes can use a short jump when the
replacement or relay fits its signed 8-bit displacement. A longer entry,
such as the examples using `std::hint::black_box`, avoids that layout constraint.

The engine never consults symbol sizes, and there is no reliable way for it to
learn where a function ends. Refusing is the only safe response. The caller
must exclude branches from outside the overwritten range into it, except for
calls or tail calls to the exact target entry; the analyzer does not scan the
whole function to prove this.

## The trampoline

`HookHandle::original` returns the trampoline while the hook is installed, and
`None` afterwards. It is an untyped pointer: converting, calling, or
dereferencing it requires you to prove its ABI, provenance, and lifetime.

The trampoline lives in an executable arena the library allocates. Short hooks
place it within the architecture's branch range. AArch64 uses an in-place far
form when that placement fails: 28 bytes on a guarded page, 12 bytes when an
unguarded page and a replacement within `B` range leave room for a landing, or
16 bytes when an unguarded page has four instructions and the final one ends
control flow; an unguarded fall-through window uses the 28-byte landing form.
Stolen literals and branches within the stolen window use local sequences.
Branches leaving that window retain direct branch semantics; arena placement
searches the intersection of their reachable ranges. Without those external
branches, the far arena has no target-distance requirement.

Batch preparation first tries one shared pool. If that placement fails, each
hook is prepared individually and can use the AArch64 far form.

The allocator uses a process-wide near-target code pool mapped with
`MAP_FIXED_NOREPLACE`. On a kernel without that flag, it retries the selected
address as an `mmap` hint and accepts the mapping only if the kernel returns
that address. Pool pages are reused after removal. The arena is released when
the hook is removed; a thread still executing in the trampoline crashes if it
is unmapped first, so calls must drain before `unhook`.

`Error::NoNearbyMemory` is deterministic for one address-space layout. Do not
retry the same refused target in the same process unless the relevant mappings
have changed. `Error::InlineArenaPlacement` reports a failed deterministic pool
reservation.

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
use omhook::{InlineHookRequest, LifecycleReadLease};

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

    let request = InlineHookRequest::new(target as *const (), replacement as *const ());
    // SAFETY: the installer contract applies from here until commit or
    // explicit discard.
    let prepared = unsafe { lease.prepare_inline_hooks(&[request]) }?;

    // Trampoline addresses are known before anything is patched.
    let trampoline = prepared.trampoline(0);

    // SAFETY: the target page is quiescent for the serialized commit.
    let mut installed = match unsafe { prepared.commit() } {
        Ok(installed) => installed,
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

Publishing a trampoline pointer before commit lets a replacement that needs
the original finish wiring before the target redirects to it.

## Validated target pages

PrivateFileValidation is opt-in. `InlineHookRequest::require_private_file_pages` requires a private, readable,
file-backed target page; the write stays a private copy and never touches the
backing file. Requests that cannot satisfy that contract fail closed. See
[Safety Model](safety.md) for the exact checks and observable COW effects.

## Choosing the mutation path

The default uses `MutationPath::ForcedWrite` and falls back to
`MutationPath::KeepExec` when `/proc/self/mem` is unavailable. Pin a path with
`InlineHookRequest::with_mutation_path`; the installed handle reports which path ran.
See [Mutation Quiescence](safety-quiescence.md) for the safety and failure
semantics.

## Cleanup-pending removal

If `unhook` restores the target but cannot unmap the arena, it returns
`Error::InlineCleanupPending`; retrying releases only the arena.
`Error::ForcedMutationRolledBackWithCloseError` means the removal was undone and the hook is
still installed. See [Safety Model](safety.md).

## Data references into the overwritten bytes

The analyzer follows a stolen ADR or ADRP through register moves and constant
offsets for up to 32 instructions, and rejects a proven read into the stolen
bytes with `Error::InlineDataReference`. Unrecognized uses remain part of the
caller's safety contract.

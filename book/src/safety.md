# Safety Model

Almost every entry point in this library is `unsafe`, and every `# Safety`
section is part of the contract. This chapter describes what the library
checks, what it cannot check, and what it does when a check fails too late.

## What the library validates

Before any byte changes, an operation:

- reads `/proc/self/maps` and confirms every page it intends to touch is
  mapped, private, and not executable (for PLT slots);
- parses the ELF metadata of each selected image with bounds checks against
  `PT_LOAD` ranges, rejecting malformed tables rather than trusting them;
- confirms every relocation slot still holds the value the preflight observed;
- for inline hooks, decodes the entry and refuses anything it cannot relocate.

After a failure it rolls back every pointer it wrote and attempts to restore
every protection it changed. A failed final restore is reported with a typed
error or install_cleanup_status state rather than as a clean rollback; see
[Termination and Poisoning](safety-termination.md).

Every successful PLT installation restores an elevated relocation page before
returning. Pages which were already writable are never changed by `mprotect`.

## What the library cannot validate

These are your obligations. The library states them and then trusts you.

**ABI compatibility.** Nothing checks that your replacement has the same
signature as the target. A mismatch is undefined behavior with no diagnostic.

**Lifetime.** The replacement, and everything it reaches, must stay valid until
the hook is removed *and* every call that could have loaded it has finished.
A replacement can start executing before the installer returns.

**Foreign writers.** Another hooking library, a JIT, or the dynamic linker
performing lazy binding can write the same slot or page. The library's internal
lock excludes only its own callers.

**Loader transitions.** A concurrent `dlopen`, `dlclose`, remap, or reprotect
of a selected image invalidates everything the preflight established. See
[Loader Lifecycle](safety-loader-lifecycle.md).

**Execution during mutation.** For inline hooks this is the primary hazard; see
[Whole-Page Quiescence](safety-quiescence.md).

**Re-entrancy.** A replacement, signal handler, or logger callback must not
call back into this library while an operation holds its lock.

**`fork`/`vfork` during an operation.** A child created mid-transaction can
inherit transient writes, transient page permissions, and a locked mutex.

## Handles do not restore on drop

Dropping a `PltHookHandle` or `InlineHookHandle` leaves the target hooked. This
is deliberate. The library cannot know at destructor time whether your callers
have drained, and unhooking too early is worse than leaking. Removal is always
an explicit `unhook`, `unhook_hooks`, or `unhook_inline_hooks`.

For inline handles, dropping also leaks the executable arena.

## Safe surface

These are safe and validate their own inputs:

- `read_self_maps`, `read_process_maps`
- `ElfImageSelector` construction, `PltHookRequest` construction and its builder methods
- `SymbolQuery` constructors
- `HookInspection` accessors, `SlotSnapshot::selector`

`PltHookRequest::new` deliberately accepts a raw replacement pointer without checking it:
constructing a hook only records an address. Every pointer obligation is
attached to the installer's unsafe contract instead.

## Failure that cannot be represented

Some rollback failures leave memory in a state no `Result` can describe. The
library terminates the process for those cases. See
[Process Termination](safety-termination.md) for the complete list of causes.

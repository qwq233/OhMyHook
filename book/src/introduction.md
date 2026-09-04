# Introduction

Oh My Hook (`omhook`) is a pure Rust function-hooking engine for little-endian
Linux and Android. It ships two independent engines:

- **PLT/GOT hooks** rewrite the relocation slot a caller jumps through. They
  change *who a caller reaches*, not the callee itself.
- **Inline hooks** rewrite the first instructions of a function entry and
  relocate the displaced instructions into a generated trampoline. They change
  *the callee*, for every caller at once.

Both engines operate on the current process only. Neither uses `ptrace`, spawns
a helper process, links a C shim, or writes anything to disk.

## Which engine do I want?

|  | PLT/GOT | Inline |
| --- | --- | --- |
| Intercepts | Calls that go through a relocation slot | All calls, including intra-library ones |
| Writes to | A data page | An executable page |
| Requires quiescent threads | No | [Yes, page-wide](safety-quiescence.md) |
| Can hook a static or local function | No | Yes |
| Needs instruction decoding | No | Yes, and can refuse an entry |
| Failure mode on an unsupported target | Reports a rejected relocation | Reports an unrelocatable instruction |

Prefer PLT hooks when the call you care about crosses a library boundary. They
are the cheaper and far more forgiving mechanism: a slot write is one naturally
aligned atomic store to a page that is never executable, so no thread has to be
stopped. Reach for inline hooks only when interception must cover callers the
relocation slot never sees.

## Design

Normal failures are transactional and explicit.

- **Preflight before mutation.** Images are discovered, ELF metadata parsed,
  slots selected, and pages validated before a single byte changes. A batch
  that cannot be fully prepared changes nothing.
- **Rollback on failure.** A partial batch is undone, including page
  protections. Some completed commits carry a resource warning instead of being
  misreported as failure, and rollback failure is [terminal](safety-termination.md).
- **Handles, not globals.** Installation returns a handle carrying the previous
  pointer or trampoline. Dropping it does *not* restore the target; removal is
  always an explicit `unhook`.
- **No hidden validation.** Every unsafe entry point documents the complete set
  of obligations it cannot check, and the library states plainly which of them
  it never verifies.

## Scope

`omhook` grants no privilege the calling process does not already have. It
modifies the memory of the process it is linked into, which that process could
modify itself. It is a mechanism for instrumentation, testing, compatibility
shims, and research inside your own process.

## Status

Version 0.1.0. The public API is not yet stable; `0.x` releases may break it.
Report vulnerabilities through GitHub's private vulnerability reporting, as
described in `SECURITY.md`.

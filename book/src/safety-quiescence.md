# Mutation Quiescence

This page describes the single hardest obligation in the library. It applies to
inline hooks only.

## The mechanism

The default mutation path writes through `/proc/self/mem` while the target page
keeps its captured `r-x` protection. If this process cannot use that file at
all -- SELinux, a seccomp filter, or descriptor exhaustion -- the fallback calls
`mprotect` with `PROT_READ | PROT_WRITE | PROT_EXEC`, writes the patch, and
restores the captured protection. Which path ran is reported by
`InlineHookHandle::install_mutation_path`, and `InlineHookRequest::with_mutation_path` pins
one of them when the caller already knows which this process can use.

Only an explicitly pinned `MutationPath::DropExec` request drops `PROT_EXEC`.
During that window, **every function on the page is unrunnable**, not only the
one being patched, and a thread entering any of them dies with `SIGSEGV`. The
forced and keeping-exec paths leave the page executable, so they do not turn a
contract violation into a fault; no thread may enter the overwritten
instruction range while a multi-instruction patch is partly published.

The same choice exists during `unhook`. The forced path never makes the page
non-executable, but a multi-instruction patch is still not safe to fetch while
only part of it is present, so the quiescence obligation below applies to both
paths.

## Why it is hard to satisfy

Page granularity belongs to the kernel, not to this library. A 4 KiB page holds
dozens of unrelated functions on a typical target, 16 KiB and 64 KiB pages hold
proportionally more, and nothing tells you which ones. You cannot enumerate the
functions you must keep quiet.

So the obligation cannot be discharged by reasoning about call sites. It has to
be discharged by controlling threads:

- A single-threaded process satisfies it only if signal handlers cannot enter
  any function sharing a target page; ordinary application code running on that
  one thread is quiescent.
- A process with a known set of worker threads and a barrier or safepoint can
  satisfy it by stopping them across the install and the removal.
- A process hooking an entry in a hot shared library while arbitrary threads
  run **cannot** satisfy it. Hooking `libc` in that state will eventually
  crash.

Rarity is not safety here. The failure is a genuine race: it may not reproduce
in testing and still fire in production under load.

## What the library does and does not do

It does not stop your threads and has no signal-based safepoint or thread
enumeration. On kernels that support
`MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE`, it registers and issues that
barrier after publishing instruction changes. This is a context-synchronizing
event, not a replacement for caller quiescence: a thread already executing
inside the patched range is still unsafe, and the page is still yours to keep
quiet.

The automatic fallback does use a short `RWX` window. Dropping `PROT_EXEC`
first would make restoration depend on `execmod`, which Android app domains
commonly deny; adding `PROT_WRITE` without removing `PROT_EXEC` avoids that
denial. The page returns to its captured protection before the call reports
success, but W^X is temporarily false and a maps poller can observe the window.
If the final restore fails, the caller receives `PagesMayBeWritable` (install)
or `Error::TargetPagesMayBeWritable`. The report includes every page involved
in the mutation and its captured protection, including pages already restored.
Verify or repair every listed page under the same lifetime and quiescence
contract. The error's `rolled_back` field distinguishes an undone operation
from a completed removal.

One page the caller can never keep quiet is the one holding this library's own
page-mutation code: the installer must run it to complete the window. Such
targets are therefore rejected with `Error::InvalidInlineTarget` before any
byte changes instead of crashing mid-mutation. The rejected set is the
complete page span between the lowest and highest address of the installer's
closed mutation-window function set plus two trailing pages, so functions that
cross page boundaries and identical-code clones are covered too. This is
deliberately conservative: an unrelated function placed inside that span is
rejected even though the installer never executes it.

## The alternative

PLT hooks carry none of this. A relocation slot lives on a data page that is
never executable, and the update is a single naturally aligned pointer-sized
atomic store. Concurrent readers observe either the old or the new value and
nothing else, and no thread has to be stopped.

That is the default in-place path. Validated mutations do **not** swap pages:
they validate that every selected file-backed GOT page is private, then let the
normal write path copy-on-write it. The mapping keeps its address, bounds,
permissions, and path; only the backing file stays untouched. A concurrent
reader still observes either the old or the new pointer, so the normal
writer-exclusion contract is enough and no extra page-quiescence obligation is
introduced.

If the calls you want to intercept cross a library boundary, use a PLT hook.
Reserve inline hooks for the cases where nothing else reaches the caller, and
pay for them with a real quiescence mechanism.

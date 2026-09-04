# Whole-Page Quiescence

This page describes the single hardest obligation in the library. It applies to
inline hooks only.

## The mechanism

The default mutation path writes through `/proc/self/mem` while the target page
keeps its captured `r-x` protection. If that descriptor is unavailable, the
fallback calls `mprotect` with `PROT_READ | PROT_WRITE`, writes the patch, and
restores the original protection.

During the default `mprotect` window, **every function on that page is
unrunnable**, not only the one being patched. A thread that is executing, or
that enters, any function sharing the page takes an instruction-fetch fault
and the process dies with `SIGSEGV`.

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
  run **cannot** satisfy it. Hooking `libc` from a live multi-threaded Android
  application is the canonical example of a program that will crash eventually
  rather than immediately.

Rarity is not safety here. The failure is a genuine race: it may not reproduce
in testing and still fire in production under load. This library's own test
suite demonstrated exactly that — a test that patched an entry while sibling
test threads ran on the same page crashed roughly 60% of runs at 16 threads and
0% at 4, which is why those tests now run in a dedicated process.

## What the library does and does not do

It does not stop your threads. It has no signal-based safepoint, no
`membarrier` dance, and no thread enumeration. It performs the complete
protection change or the forced retry, and the contract says the page is yours
to keep quiet.

It does not use `PROT_READ | PROT_WRITE | PROT_EXEC`. A permanently RWX code
page would remove this window at the cost of defeating W^X, and SELinux denies
that transition on file-backed executable mappings on Android anyway.

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

If the calls you want to intercept cross a library boundary, use a PLT hook.
Reserve inline hooks for the cases where nothing else reaches the caller, and
pay for them with a real quiescence mechanism.

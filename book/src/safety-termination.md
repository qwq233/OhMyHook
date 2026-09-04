# Process Termination

This library can terminate the calling process. It is documented behavior, not
a bug, and you should know the causes before linking it.

## How

Termination goes through a fallback chain, none of which unwinds or runs
destructors:

1. `exit_group(134)`.
2. If that is blocked, `kill(getpid(), SIGKILL)`.
3. If that is blocked, `tgkill(getpid(), gettid(), SIGKILL)`.
4. Finally a trapping instruction (`ud2` on x86, `udf #0` on ARM) in a loop, so
   a `SIGILL` handler that returns cannot resume execution.

Each syscall in the chain is attempted at most once. Every process identifier
is range-checked before being passed to a signal syscall, so a raw negative
errno can never be reinterpreted as a process-group target.

## Why

The library terminates only where returning an error would be a lie about the
state of memory:

- **A rollback that fails.** If a partially applied batch cannot be undone — a
  pointer cannot be restored, or a page cannot be reopened to restore its bytes
  — no `Result` can describe the resulting state.
- **A poisoned process lock during a mutation.** Described below.
- **A violated internal invariant.** Cases the code's own structure makes
  unreachable, kept as fail-closed assertions rather than `unwrap()`.

These cases are narrower than the states that merely went wrong. Anything that
leaves every target byte accounted for is reported instead:

- **An arena that cannot be unmapped after a successful removal** returns
  `Error::InlineCleanupPending`. The hook is gone; an executable mapping leaked.
- **An unpublished arena that cannot be unmapped** returns the same error. No
  target was written; an executable mapping leaked.
- **A forced-access descriptor that cannot be closed** returns
  `Error::ForcedDescriptorLeaked`. The operation was undone, so every target
  holds the bytes it held before the call — for a *removal* that means it is
  still patched and its handle is still installed. This is deliberately a
  different error from the one above, which promises the opposite.
- **A target page whose protection cannot be restored** returns
  `Error::TargetPageProtectionLost` after the rollback has put the bytes back.
  The page is left non-executable, so no retry can succeed; the error asks the
  caller to abort, but it is the caller's decision, not this library's. A policy
  that refuses this cannot be recognised before the first write, so one
  installation is lost to learning it; the refusal is then remembered and every
  later installation writes through the forced channel instead.

Note the asymmetry with removal: a *removal* failure normally returns an error
and leaves the handle retryable. Termination is reserved for states that cannot
be described.

## Lock poisoning, and how to avoid it

The library serializes its operations on one internal `RwLock`. `std` poisons
such a lock when a panic escapes while it is held **exclusively**.

A poisoned lock only proves that some caller unwound while holding it. What
matters is *where*. The library marks the window in which target bytes or
relocation slots are only partly written, and:

- Poisoned **outside** that window: the lock is recovered and the call proceeds.
  Every invariant this library owns is still intact, and removal in particular
  must stay usable after something else in the process went wrong.
- Poisoned **inside** that window: the process still terminates. A panic with a
  half-written target leaves state no later call can reason about.

The window flag is deliberately not cleared while unwinding, so a panic escaping
the window keeps the fail-stop behaviour for every later acquisition.

The library emits no log record while any internal guard is held, so a panic
under the guard can only come from a defect in this library, not from your
logger. Two caller-side rules follow, because records are emitted through the
caller-configured `log` facade once the guard is released:

- **Your logger must not panic.** Not on a full buffer, not on a poisoned mutex
  of its own, not on a failed write.
- **Your logger must not re-enter Oh My Hook.** A logger that calls a hooked
  function which calls back into the library deadlocks on a non-reentrant lock.

## If you cannot accept this

There is no feature flag to convert the remaining cases into errors, because the
states they describe are not representable as errors. If your process cannot
tolerate termination, the mitigation is to constrain what you hook and to keep
the logger trivial — not to catch anything.

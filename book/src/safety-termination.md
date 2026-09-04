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
  `Error::ForcedMutationRolledBackWithCloseError`. The operation was undone, so every target
  holds the bytes it held before the call — for a *removal* that means it is
  still patched and its handle is still installed. This is deliberately a
  different error from the one above, which promises the opposite.
- **A target page whose protection cannot be restored** returns
  `Error::TargetPageProtectionLost` after the rollback has put the bytes back.
  This is reachable only from an explicitly pinned `MutationPath::DropExec` request. The
  page is left non-executable, so no retry can succeed; stop using the target
  for the rest of this process or terminate. The automatic fallback keeps
  `PROT_EXEC`, so it cannot create this state.
- **A keeping-exec page whose write bit cannot be removed** reports
  `PagesMayBeWritable` on install or `Error::TargetPagesMayBeWritable`.
  The report covers every page involved in the mutation, not only the first
  failed restore. The targets remain callable; verify or repair every listed
  page using its captured protection. If `rolled_back` is true, the operation
  was undone and removal handles remain installed; otherwise removal completed.

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

The library keeps the byte-mutation window free of log records, so a panic
inside that window can only come from a defect in this library. Outside that
window the guarantees differ by engine: PLT install and removal emit their
entry records before taking the process lock and every failure, install_cleanup_status,
and descriptor-cleanup record after releasing it, while inline preparation —
including the one-shot install — emits records while the lock is held. A panic
in a caller logger during inline preparation is therefore possible and follows
the lock-poison rules above. Two caller-side rules follow, because records are
emitted through the caller-configured `log` facade:

- **Your logger must not panic.** Not on a full buffer, not on a poisoned mutex
  of its own, not on a failed write.
- **Your logger must not re-enter Oh My Hook.** A logger that calls a hooked
  function which calls back into the library deadlocks on a non-reentrant lock.

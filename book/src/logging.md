# Logging

Oh My Hook emits records through the [`log`](https://docs.rs/log) facade and
installs no logger of its own. The application chooses the backend and the
level filter.

## Levels

| Level | Used for |
| --- | --- |
| `debug` | Lifecycle boundaries, batch rejection reasons, descriptor cleanup |
| `trace` | No-op removals and empty batches, entry normalization adjustments |
| `warn` | A hook request or private-file validation rejected, a preparation stage failed with nothing installed, cross-core instruction-stream sync unavailable |
| `error` | A commit failure, a preflight failure that aborts the operation |

Records include the counts and indices needed to correlate a failure with an
input, for example `PLT hook group rejected: group_index=1, hook_index=0`. They
do not log symbol names. Error records may contain addresses already present in
the error returned to the caller; no separate address scan is emitted.

The library emits no `info` records at all. Lifecycle records are deliberately
at `debug`: on Android another
component in the same process can read its own logcat identity. A deployment
that does not need diagnostics should install no logger or filter to `warn`;
`info` does not select any library records.

## Two hard rules for your logger

**It must not panic.** A logger is caller code running inside this library's
call stack. A panic escaping while the internal process lock is held
exclusively poisons that lock. Outside the byte-mutation window the lock is
recovered; inside that window later acquisitions [terminate the
process](safety-termination.md). PLT install and removal emit lifecycle records
outside the process lock. Inline preparation emits records while that lock is
held, so a panicking logger there follows the documented lock-poison rules.

**It must not re-enter Oh My Hook.** A logger that ends up calling a hooked
function which calls back into the library deadlocks on a non-reentrant lock.
Be especially careful with a logger that writes through a hooked I/O function.

## Cost when disabled

The `log` macros check the level filter before formatting, so a disabled level
costs an atomic load. The byte-mutation window contains no records.

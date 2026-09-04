# Logging

Oh My Hook emits records through the [`log`](https://docs.rs/log) facade and
installs no logger of its own. The application chooses the backend and the
level filter.

## Levels

| Level | Used for |
| --- | --- |
| `info` | Lifecycle boundaries: a batch requested, an install or unhook completed |
| `debug` | Selection and validation detail, rejection reasons |
| `trace` | Per-slot decisions, no-op removals |
| `warn` | A hook rejected, a preflight stage failed with nothing installed |
| `error` | A commit failure, a preflight failure that aborts the operation |

Records include the counts and indices needed to correlate a failure with an
input, for example `PLT hook group rejected: group_index=1, hook_index=0`. They
do not include symbol names or addresses beyond what the API already returns.

## Two hard rules for your logger

**It must not panic.** A logger is caller code running inside this library's
call stack. A panic escaping while the internal process lock is held
exclusively poisons that lock permanently, and every later call into the
library then [terminates the process](safety-termination.md). Install paths now
emit their records after releasing the guard, which removes the known trigger,
but a panicking logger remains a hazard you own.

**It must not re-enter Oh My Hook.** A logger that ends up calling a hooked
function which calls back into the library deadlocks on a non-reentrant lock.
Be especially careful with a logger that writes through a hooked I/O function.

## Cost when disabled

The `log` macros check the level filter before formatting, so a disabled level
costs an atomic load. The library additionally keeps its serialized commit path
free of logging entirely: no record is emitted between the first and last
target byte change.

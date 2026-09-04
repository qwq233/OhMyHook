# PLT/GOT Hooks

A PLT hook replaces the pointer a caller loads before jumping. The callee's own
code is never touched, so no thread has to be stopped and no executable page is
ever made writable.

## Selecting a target

A `Target` names which loaded images to search:

```rust
# extern crate omhook;
use omhook::Target;

# fn main() -> omhook::Result<()> {
let exe = Target::current_executable()?;
// Use a path that exists on every test host; replace it with a loaded library
// path when selecting a different image in a deployed process.
let lib = Target::from_path(std::env::current_exe()?)?;
# Ok(())
# }
```

A `Hook` pairs a target with a symbol and a replacement:

```rust
# extern crate omhook;
use omhook::{Hook, RelocationKinds, SymbolQuery, Target};

# extern "C" fn replacement() {}
# fn main() -> omhook::Result<()> {
# let target = Target::current_executable()?;
let hook = Hook::new(&target, c"open", replacement as *const ())?
    // Narrow to jump slots only; the default is every supported kind.
    .with_relocation_kinds(RelocationKinds::JUMP_SLOT)
    // Fail closed if the target or symbol is ambiguous.
    .require_unique_match()
    // Fail closed if the previous pointer would be null.
    .require_non_null_previous();
# Ok(())
# }
```

### Relocation kinds

`RelocationKind` covers the three semantic forms this library understands:

| Kind | Typical origin |
| --- | --- |
| `JumpSlot` | An ordinary PLT call, `R_*_JUMP_SLOT` |
| `GlobalData` | A `-fno-plt` call or a taken function address, `R_*_GLOB_DAT` |
| `Absolute` | An absolute pointer relocation |

`RelocationKinds::ALL` is the default and preserves traditional behavior.
Narrowing is a deliberate act: excluding `GlobalData` silently misses every
`-fno-plt` call site, which is the default codegen on some distributions.

### Replacement landing pads

The stored pointer is reached by indirect branches, so the replacement entry
must be a legal landing pad for every caller of the slot.

On AArch64 the library validates this itself: when BTI hardware is present and
the replacement's page is BTI-guarded, an entry that does not begin with
`bti jc` is rejected at install time. Plain `bti`, `bti c`, `bti j`, and PAC
prologues are not universal landings, and a slot is reachable through the
`br x17` of a PLT stub, the `blr` of no-PLT callers, or another indirect
branch.

On x86-64 the library cannot cheaply detect CET IBT enforcement, so the caller
must ensure the replacement is a valid indirect-branch target (`endbr64` at
the entry) whenever enforcement is enabled for the process.

### Symbol versions

`Hook::new` matches by name only. For versioned symbols, build the query
explicitly:

```rust
# extern crate omhook;
use omhook::SymbolQuery;

# fn main() -> omhook::Result<()> {
let any = SymbolQuery::any_version(c"open")?;
let bare = SymbolQuery::unversioned(c"open")?;
let exact = SymbolQuery::exact_version(c"open", c"GLIBC_2.2.5")?;
# Ok(())
# }
```

Version-aware matching reads `VERDEF` for defined symbols and `VERNEED` for
undefined ones. The hidden/default bit does not affect matching.

## Inspecting before installing

`inspect_hooks` runs the complete preflight and changes nothing:

```rust
# extern crate omhook;
use omhook::{InspectionStatus, inspect_hooks};

# fn main() -> omhook::Result<()> {
# let hooks: Vec<omhook::Hook> = Vec::new();
// SAFETY: the process keeps the selected images and their relocation metadata
// stable and unremapped for the read-only scan.
let report = unsafe { inspect_hooks(&hooks) }?;
for inspected in &report {
    if let Some(error) = inspected.error() {
        println!("rejected: {error}");
    }
    for image in inspected.images() {
        for slot in &image.slots {
            println!("{:p} {:?} {:?}", slot.address, slot.kind, slot.status);
        }
    }
}
# Ok(())
# }
```

`InspectionStatus` reports exactly why a slot was not eligible:

| Status | Meaning |
| --- | --- |
| `Eligible` | The complete inspected batch could install this slot |
| `Conflict` | Another hook claimed it, or it already holds the replacement |
| `UnresolvedLazy` | Still pointing at the lazy-binding resolver |
| `AmbiguousIfunc` | A GNU IFUNC with no matching resolved hint |
| `AmbiguousPreviousPointer` | The hook's slots disagree on the original |
| `OriginalSlotConflict` | A shared `OriginalSlot` disagrees |
| `Aarch64PacPlt` | The stored PAC-PLT value failed verification |
| `ImplicitAddend` | The relocation needs an implicit addend read from the slot |
| `UnsupportedAddend` | The relocation's explicit addend cannot be preserved |
| `Rejected` | Another hook-level preflight error rejected the slot |

An inspection result is a snapshot. Installation repeats every check against a
fresh one, so acting on a stale report fails closed rather than writing to the
wrong slot.

## Batches

`install_hooks` takes a slice and returns a report aligned with it. Per-hook
failures are independent: one rejected hook is rolled back on its own while the
rest stay installed. An outer `Err` means the whole batch was undone.

Batching is also the fast path. A batch performs one `/proc/self/maps` read,
one ELF traversal, and one `mprotect` pair per unique page for the entire set,
regardless of how many hooks it contains.

Removal has the same shape:

```rust
# extern crate omhook;
use omhook::{install_hooks, unhook_hooks};

# fn main() -> omhook::Result<()> {
# let hooks: Vec<omhook::Hook> = Vec::new();
// SAFETY: see the installer contract.
let report = unsafe { install_hooks(&hooks) }?;
let mut installed: Vec<_> = report.into_iter().flatten().collect();

// SAFETY: all replacement and original calls have drained.
unsafe { unhook_hooks(&mut installed) }?;
# Ok(())
# }
```

`unhook_hooks` merges every handle's ledger into a single transaction, so a
shared relocation page is elevated and restored once instead of once per
handle. `HookHandle::unhook` is the one-element case of it.

## Groups

A `HookGroup` is an all-or-none rollback unit with an absence policy:

```rust
# extern crate omhook;
use omhook::{HookGroup, install_hook_groups};

# fn main() {
# let primary: Vec<omhook::Hook> = Vec::new();
# let fallback: Vec<omhook::Hook> = Vec::new();
let groups = [
    // At least one candidate must end up installed.
    HookGroup::required(&primary),
    // A group whose candidates are all absent is accepted.
    HookGroup::optional(&fallback),
];
// SAFETY: see the installer contract.
match unsafe { install_hook_groups(&groups) } {
    // One InstallReport per group, aligned with `groups`.
    Ok(report) => println!("installed {} groups", report.len()),
    // The failure carries the group and hook index that caused the rollback.
    Err(failure) => println!("{failure}"),
}
# }
```

Group installation is all-or-none across every group, so it reports a
`GroupInstallError` rather than the per-hook report `install_hooks` returns.
This is the right tool for "hook whichever of these symbol spellings this
platform actually has, but fail if none of them exist".

## Mutation budgets

A budget caps how much the operation may touch, and is enforced *before* any
original is published or any page protection changes:

```rust
# extern crate omhook;
use omhook::{MutationBudget, install_hooks_with_budget};

# fn main() -> omhook::Result<()> {
# let hooks: Vec<omhook::Hook> = Vec::new();
let budget = MutationBudget {
    max_images: 1,
    max_slots: 4,
    max_pages: 2,
};
// SAFETY: see the installer contract.
let report = unsafe { install_hooks_with_budget(&hooks, budget) }?;
# Ok(())
# }
```

Use it when a wildcard target could match far more than you intended: exceeding
the budget returns `Error::MutationBudgetExceeded` with nothing written.

## Calling the original

`AppliedHook::previous` returns the untyped pointer every selected slot held
before installation. Converting it to a function pointer and calling it is
entirely on the caller: the library proves nothing about its ABI, provenance,
or lifetime.

For a replacement that must reach the original, publish it through an
`OriginalSlot` *before* installation rather than reading the handle afterwards.
A replacement can execute the moment the first slot changes, which is before
`install_hooks` returns.

## AArch64 PAC-PLT

On AArch64 with pointer authentication, a PLT slot may hold a signed value.
The library verifies the stored PAC before treating a slot as eligible and
returns the previous pointer with its PAC stripped. Every thread that can
execute a hooked entry must keep the same IA key for as long as the hook is
installed: `PR_PAC_RESET_KEYS`, debugger key replacement, and any other key
change are forbidden from inspection through removal and call drainage.

## Concealed relocation pages

Concealment is disabled in this release. `concealed_mutations_supported()` returns `Ok(false)` without probing or mutating. `Hook::enforce_concealed_mutations` and `set_enforce_concealed_mutations(true)` fail with `Error::UnsupportedFeature` before any target mutation, and `restore_concealed_mutations()` returns `Ok(0)`.

#![allow(clippy::expect_used, clippy::unreachable)]

use omhook::{
    Hook, HookHandle, MutationBudget, OriginalSlot, RelocationKinds, SymbolQuery, Target,
    inspect_hooks, install_hook_with_budget,
};
use std::mem;

type Getpid = unsafe extern "C" fn() -> i32;
static ORIGINAL_GETPID: OriginalSlot = OriginalSlot::new();

unsafe extern "C" {
    fn getpid() -> i32;
}

#[inline(never)]
fn call_getpid() -> i32 {
    // SAFETY: getpid has no arguments or caller-side preconditions.
    unsafe { getpid() }
}

extern "C" fn replacement_getpid() -> i32 {
    let original = ORIGINAL_GETPID.get().expect("original was pre-published");
    // SAFETY: strict preflight rejects null and publishes getpid's exact ABI.
    let original = unsafe { mem::transmute::<*const (), Getpid>(original) };
    // SAFETY: getpid has no arguments or caller-side preconditions.
    (unsafe { original() }) + 100_000
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Resolve a lazy Linux PLT slot before inspection.
    let before = call_getpid();
    let source = Target::current_executable()?;
    let query = SymbolQuery::any_version(c"getpid")?;
    assert_eq!(query.name(), c"getpid");
    let function_relocations = RelocationKinds::GLOBAL_DATA | RelocationKinds::JUMP_SLOT;
    let broad = Hook::new_query(&source, query, replacement_getpid as *const ())?
        .with_relocation_kinds(function_relocations);

    // SAFETY: this single-threaded process keeps the executable and its resolved
    // getpid relocation stable throughout inspection and installation.
    let inspected = unsafe { inspect_hooks(&[broad]) }?
        .pop()
        .unwrap_or_else(|| unreachable!("one Hook produces one inspection result"));
    let expected_previous = inspected.previous();
    let (image, slot) = inspected.into_unique_eligible()?;
    let expected_previous =
        expected_previous.unwrap_or_else(|| unreachable!("eligible Hook has a previous pointer"));
    assert!(function_relocations.contains(slot.kind));
    let target = image.exact_target();
    let hook = Hook::new(&target, c"getpid", replacement_getpid as *const ())?
        .with_slot_selector(slot.selector())?
        .require_exactly_one_slot()?
        .require_non_null_previous()
        .with_original_slot(&ORIGINAL_GETPID);

    // SAFETY: the exact inspected slot remains stable and writer-exclusive, the
    // replacement remains live and ABI-compatible, and the budget is one slot.
    let mut applied = unsafe {
        install_hook_with_budget(
            hook,
            MutationBudget {
                max_images: 1,
                max_slots: 1,
                max_pages: 1,
            },
        )?
    };
    assert_eq!(applied.slots.get(), 1);
    assert_eq!(applied.previous(), expected_previous);
    assert_eq!(ORIGINAL_GETPID.get(), Some(applied.previous()));

    let hooked = call_getpid();
    assert_eq!(hooked, before + 100_000);
    // SAFETY: this single-threaded process has drained every getpid call.
    unsafe { applied.unhook()? };
    assert_eq!(call_getpid(), before);
    println!("strict getpid hook succeeded: before={before}, hooked={hooked}");
    Ok(())
}

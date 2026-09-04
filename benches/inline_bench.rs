use omhook::{
    HookHandle, InlineHookRequest, MutationPath, install_inline_hook, install_inline_hooks,
    unhook_inline_hooks,
};
use std::hint::black_box;
use std::mem;
use std::time::{Duration, Instant};

type Unary = extern "C" fn(i32) -> i32;

#[inline(never)]
extern "C" fn target(value: i32) -> i32 {
    black_box(value).wrapping_mul(3)
}

#[inline(never)]
extern "C" fn replacement(value: i32) -> i32 {
    black_box(value.wrapping_mul(3))
}

#[inline(never)]
extern "C" fn verification_target(value: i32) -> i32 {
    black_box(value).wrapping_mul(4)
}

extern "C" fn verification_replacement(value: i32) -> i32 {
    black_box(value).wrapping_mul(6)
}

#[inline(never)]
extern "C" fn call_target(value: i32) -> i32 {
    target(value)
}

#[inline(never)]
extern "C" fn call_replacement(value: i32) -> i32 {
    replacement(value)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    const CYCLES: usize = 10_000;
    assert_eq!(verification_target(black_box(7)), 28);

    let mut hook = unsafe {
        install_inline_hook(
            verification_target as *const (),
            verification_replacement as *const (),
        )
    }?;
    assert_eq!(verification_target(black_box(7)), 42);
    let original = hook.original().expect("missing original trampoline");
    // SAFETY: the installed hook published the target's exact C ABI pointer.
    let original = unsafe { mem::transmute::<*const (), Unary>(original) };
    assert_eq!(original(black_box(7)), 28);
    // SAFETY: the verification calls above drained the replacement.
    unsafe { hook.unhook()? };
    assert_eq!(verification_target(black_box(7)), 28);

    time_unary("unhooked", call_target);

    let mut hook = unsafe { install_inline_hook(target as *const (), replacement as *const ()) }?;
    time_unary("hooked", call_target);

    let original = hook.original().expect("missing original trampoline");
    // SAFETY: the installed hook published the target's exact C ABI pointer.
    let original = unsafe { mem::transmute::<*const (), Unary>(original) };
    time_unary("original", original);
    time_unary("replacement", call_replacement);
    // SAFETY: the timing calls above drained the replacement.
    unsafe { hook.unhook()? };
    assert_eq!(call_target(black_box(7)), 21);

    let mut install_samples = Vec::with_capacity(CYCLES);
    let mut unhook_samples = Vec::with_capacity(CYCLES);
    for _ in 0..CYCLES {
        let start = Instant::now();
        let mut hook =
            unsafe { install_inline_hook(target as *const (), replacement as *const ()) }?;
        install_samples.push(start.elapsed().as_secs_f64() * 1_000_000_000.0);
        let _ = call_target(black_box(7));
        let start = Instant::now();
        // SAFETY: the call above drained the replacement.
        unsafe { hook.unhook()? };
        unhook_samples.push(start.elapsed().as_secs_f64() * 1_000_000_000.0);
        if call_target(black_box(7)) != 21 {
            return Err("restored call failed".into());
        }
    }
    report_cycle("install", &mut install_samples);
    report_cycle("unhook", &mut unhook_samples);

    for (name, path, count) in [
        ("keep_exec", Some(MutationPath::KeepExec), 1),
        ("batch", None, 2),
        ("keep_exec_batch", Some(MutationPath::KeepExec), 2),
    ] {
        let requests = [
            InlineHookRequest::new(target as *const (), replacement as *const ()),
            InlineHookRequest::new(
                verification_target as *const (),
                verification_replacement as *const (),
            ),
        ]
        .map(|request| match path {
            Some(path) => request.with_mutation_path(path),
            None => request,
        });
        install_samples.clear();
        unhook_samples.clear();
        for _ in 0..CYCLES {
            let start = Instant::now();
            // SAFETY: this single thread owns the targets and drains every call.
            let mut hooks = unsafe { install_inline_hooks(&requests[..count]) }?;
            install_samples.push(start.elapsed().as_secs_f64() * 1_000_000_000.0);
            assert_eq!(call_target(black_box(7)), 21);
            assert_eq!(
                verification_target(black_box(7)),
                if count == 2 { 42 } else { 28 }
            );
            for (index, hook) in hooks.iter().enumerate() {
                // SAFETY: both originals have the declared C ABI and remain live.
                let original =
                    unsafe { mem::transmute::<*const (), Unary>(hook.original().unwrap()) };
                assert_eq!(original(black_box(7)), if index == 0 { 21 } else { 28 });
            }
            let start = Instant::now();
            // SAFETY: all target, replacement and original calls have drained.
            unsafe { unhook_inline_hooks(&mut hooks) }?;
            unhook_samples.push(start.elapsed().as_secs_f64() * 1_000_000_000.0);
            assert_eq!(call_target(black_box(7)), 21);
            assert_eq!(verification_target(black_box(7)), 28);
        }
        report_cycle(&format!("{name}_install"), &mut install_samples);
        report_cycle(&format!("{name}_unhook"), &mut unhook_samples);
    }

    Ok(())
}

fn time_unary(name: &str, entry: Unary) {
    const WARMUP_CALLS: usize = 10_000;
    const CALLS_PER_SAMPLE: usize = 1_000;
    const SAMPLES: usize = 201;
    // Nanosecond-scale calls need sustained warmup to outlast startup transients.
    let warmup = Instant::now();
    while warmup.elapsed() < Duration::from_millis(200) {
        for _ in 0..WARMUP_CALLS {
            let _ = entry(black_box(7));
        }
    }
    let mut samples = Vec::with_capacity(SAMPLES);
    let mut sink = 0_i64;
    for _ in 0..SAMPLES {
        let start = Instant::now();
        for _ in 0..CALLS_PER_SAMPLE {
            sink = sink.wrapping_add(i64::from(entry(black_box(7))));
        }
        samples.push(start.elapsed().as_secs_f64() * 1_000_000_000.0 / CALLS_PER_SAMPLE as f64);
    }
    samples.sort_by(|left, right| left.partial_cmp(right).expect("sample NaN"));
    println!(
        "engine=omhook_inline,scenario=per_call_{name}_batch_mean,median_ns={:.3},p95_ns={:.3}",
        samples[samples.len() / 2],
        samples[samples.len() * 95 / 100]
    );
    black_box(sink);
}

fn report_cycle(name: &str, samples: &mut [f64]) {
    samples.sort_by(|left, right| left.partial_cmp(right).expect("sample NaN"));
    println!(
        "engine=omhook_inline,scenario={name},median_ns={:.3},p95_ns={:.3}",
        samples[samples.len() / 2],
        samples[samples.len() * 95 / 100]
    );
}

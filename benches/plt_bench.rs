use omhook::{ElfImageSelector, HookHandle, OriginalPointerCell, PltHookRequest, install_hook};
use std::hint::black_box;
use std::mem;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

type Getpid = extern "C" fn() -> i32;

static ORIGINAL_GETPID: OriginalPointerCell = OriginalPointerCell::new();
static CALLER: OnceLock<Getpid> = OnceLock::new();

extern "C" fn replacement_getpid() -> i32 {
    ORIGINAL_GETPID.get().map_or_else(
        || 0,
        |original| unsafe {
            let original = mem::transmute::<*const (), Getpid>(original);
            original()
        },
    )
}

extern "C" fn verification_getpid() -> i32 {
    #[cfg(target_arch = "aarch64")]
    {
        unsafe {
            std::arch::asm!("bti jc", options(nomem, nostack));
        }
        std::hint::black_box(());
    }
    42
}

extern "C" fn bench_caller() -> i32 {
    unsafe { libc::getpid() }
}

#[inline(never)]
extern "C" fn call_getpid() -> i32 {
    CALLER.get().expect("missing caller")()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    const CYCLES: usize = 1_000;
    let (caller, image_selector, unbound_image_selector) = benchmark_executable_selectors()?;
    CALLER.set(caller).expect("caller already initialized");

    time_getpid("unhooked", call_getpid);

    let request =
        PltHookRequest::new(&image_selector, c"getpid", verification_getpid as *const ())?
            .require_non_null_previous();
    let mut applied = unsafe { install_hook(request)? };
    if call_getpid() != 42 {
        return Err("hooked call failed".into());
    }
    unsafe { applied.unhook()? };
    if call_getpid() == 42 {
        return Err("restored call failed".into());
    }

    let request = PltHookRequest::new(&image_selector, c"getpid", replacement_getpid as *const ())?
        .require_non_null_previous()
        .with_original_pointer_cell(&ORIGINAL_GETPID);
    let mut applied = unsafe { install_hook(request)? };
    time_getpid("hooked", call_getpid);

    let original = applied
        .original()
        .expect("missing original function pointer");
    let original = unsafe { mem::transmute::<*const (), Getpid>(original) };
    time_getpid("original", original);
    time_getpid("replacement", replacement_getpid);
    unsafe { applied.unhook()? };
    if call_getpid() == 42 {
        return Err("restored call failed".into());
    }

    let mut install_samples = Vec::with_capacity(CYCLES);
    let mut unhook_samples = Vec::with_capacity(CYCLES);
    let mut cycles = Vec::with_capacity(CYCLES);
    for _ in 0..CYCLES {
        let cycle_start = Instant::now();
        let start = Instant::now();
        let request =
            PltHookRequest::new(&image_selector, c"getpid", verification_getpid as *const ())?
                .require_non_null_previous();
        let mut applied = unsafe { install_hook(request)? };
        install_samples.push(start.elapsed().as_secs_f64() * 1_000_000_000.0);
        if call_getpid() != 42 {
            return Err("hooked call failed".into());
        }
        let start = Instant::now();
        unsafe { applied.unhook()? };
        unhook_samples.push(start.elapsed().as_secs_f64() * 1_000_000_000.0);
        if call_getpid() == 42 {
            return Err("restored call failed".into());
        }
        cycles.push(cycle_start.elapsed().as_secs_f64() * 1_000_000_000.0);
    }
    report_cycle("install", &mut install_samples);
    report_cycle("unhook", &mut unhook_samples);
    report_cycle("install_unhook_cycle", &mut cycles);

    let mut unbound_selector_install_samples = Vec::with_capacity(CYCLES);
    let mut unbound_selector_unhook_samples = Vec::with_capacity(CYCLES);
    let mut unbound_selector_cycles = Vec::with_capacity(CYCLES);
    for _ in 0..CYCLES {
        let cycle_start = Instant::now();
        let start = Instant::now();
        let request = PltHookRequest::new(
            &unbound_image_selector,
            c"getpid",
            verification_getpid as *const (),
        )?
        .require_non_null_previous();
        let mut applied = unsafe { install_hook(request)? };
        unbound_selector_install_samples.push(start.elapsed().as_secs_f64() * 1_000_000_000.0);
        if call_getpid() != 42 {
            return Err("unbound-selector hooked call failed".into());
        }
        let start = Instant::now();
        unsafe { applied.unhook()? };
        unbound_selector_unhook_samples.push(start.elapsed().as_secs_f64() * 1_000_000_000.0);
        if call_getpid() == 42 {
            return Err("unbound-selector restored call failed".into());
        }
        unbound_selector_cycles.push(cycle_start.elapsed().as_secs_f64() * 1_000_000_000.0);
    }
    report_cycle(
        "unbound_selector_install",
        &mut unbound_selector_install_samples,
    );
    report_cycle(
        "unbound_selector_unhook",
        &mut unbound_selector_unhook_samples,
    );
    report_cycle(
        "unbound_selector_install_unhook_cycle",
        &mut unbound_selector_cycles,
    );

    let mut private_file_validated_install_samples = Vec::with_capacity(CYCLES);
    let mut private_file_validated_unhook_samples = Vec::with_capacity(CYCLES);
    let mut private_file_validated_cycles = Vec::with_capacity(CYCLES);
    for _ in 0..CYCLES {
        let cycle_start = Instant::now();
        let start = Instant::now();
        let request =
            PltHookRequest::new(&image_selector, c"getpid", verification_getpid as *const ())?
                .require_non_null_previous()
                .require_private_file_pages();
        let mut applied = unsafe { install_hook(request)? };
        private_file_validated_install_samples
            .push(start.elapsed().as_secs_f64() * 1_000_000_000.0);
        if call_getpid() != 42 {
            return Err("hooked call failed".into());
        }
        let start = Instant::now();
        unsafe { applied.unhook()? };
        private_file_validated_unhook_samples.push(start.elapsed().as_secs_f64() * 1_000_000_000.0);
        if call_getpid() == 42 {
            return Err("validated restored call failed".into());
        }
        private_file_validated_cycles.push(cycle_start.elapsed().as_secs_f64() * 1_000_000_000.0);
    }
    report_cycle(
        "private_file_validated_install",
        &mut private_file_validated_install_samples,
    );
    report_cycle(
        "private_file_validated_unhook",
        &mut private_file_validated_unhook_samples,
    );
    report_cycle(
        "private_file_validated_install_unhook_cycle",
        &mut private_file_validated_cycles,
    );

    black_box(caller);
    Ok(())
}

fn benchmark_executable_selectors()
-> Result<(Getpid, ElfImageSelector, ElfImageSelector), Box<dyn std::error::Error>> {
    let path = std::env::current_exe()?;
    let unbound_image_selector = ElfImageSelector::from_path(&path)?;
    let image_selector = ElfImageSelector::current_executable()?;
    Ok((bench_caller, image_selector, unbound_image_selector))
}

fn time_getpid(name: &str, entry: Getpid) {
    const WARMUP_CALLS: usize = 10_000;
    const CALLS_PER_SAMPLE: usize = 1_000;
    const SAMPLES: usize = 201;
    // Nanosecond-scale calls need sustained warmup to outlast startup transients.
    let warmup = Instant::now();
    while warmup.elapsed() < Duration::from_millis(200) {
        for _ in 0..WARMUP_CALLS {
            let _ = entry();
        }
    }
    let mut samples = Vec::with_capacity(SAMPLES);
    let mut sink = 0_i64;
    for _ in 0..SAMPLES {
        let start = Instant::now();
        for _ in 0..CALLS_PER_SAMPLE {
            sink = sink.wrapping_add(i64::from(entry()));
        }
        samples.push(start.elapsed().as_secs_f64() * 1_000_000_000.0 / CALLS_PER_SAMPLE as f64);
    }
    samples.sort_by(|left, right| left.partial_cmp(right).expect("sample NaN"));
    println!(
        "engine=omhook_plt,scenario=per_call_{name}_batch_mean,median_ns={:.3},p95_ns={:.3}",
        samples[samples.len() / 2],
        samples[samples.len() * 95 / 100]
    );
    black_box(sink);
}

fn report_cycle(name: &str, samples: &mut [f64]) {
    samples.sort_by(|left, right| left.partial_cmp(right).expect("sample NaN"));
    println!(
        "engine=omhook_plt,scenario={name},median_ns={:.3},p95_ns={:.3}",
        samples[samples.len() / 2],
        samples[samples.len() * 95 / 100]
    );
}

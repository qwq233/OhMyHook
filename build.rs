fn main() -> Result<(), std::env::VarError> {
    println!("cargo::rustc-check-cfg=cfg(omhook_arm_v6t2)");

    let target = std::env::var("TARGET")?;
    if target.starts_with("armv7-") || target.starts_with("thumbv7neon-") {
        println!("cargo::rustc-cfg=omhook_arm_v6t2");
    }
    Ok(())
}

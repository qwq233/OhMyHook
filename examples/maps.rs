use omhook::{MapPerms, read_process_maps, read_self_maps};

fn main() -> omhook::Result<()> {
    let main_address = main as *const () as usize;
    let maps = read_self_maps()?;
    let code = maps
        .iter()
        .find(|map| map.contains(main_address))
        .expect("main is missing from the process map");
    assert!(code.perms.contains(MapPerms::EXEC));

    let current = read_process_maps(std::process::id())?;
    assert!(current.iter().any(|map| map.contains(main_address)));

    println!(
        "main is in {:#x}-{:#x}; self maps={}, pid maps={}",
        code.start,
        code.end,
        maps.len(),
        current.len()
    );
    Ok(())
}

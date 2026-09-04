use omhook::{
    ElfImageSelector, InspectionStatus, MapPerms, PltHookRequest, find_loaded_images,
    inspect_hooks, read_self_maps,
};

unsafe extern "C" {
    fn getpid() -> i32;
}

extern "C" fn replacement_getpid() -> i32 {
    0
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Resolve a lazy Linux PLT slot before inspection.
    // SAFETY: getpid has no arguments or caller-side preconditions.
    let _ = unsafe { getpid() };

    let image_selector = ElfImageSelector::from_path("/proc/self/exe")?;
    let maps = read_self_maps()?;

    // SAFETY: this single-threaded process keeps the executable and loader
    // metadata stable for the read-only discovery.
    for image in unsafe { find_loaded_images(&image_selector)? } {
        let source = image.source_selector();
        let header = image.elf_header().expose_provenance();
        let header_map = maps
            .iter()
            .find(|map| map.start == header)
            .expect("missing ELF header map");
        assert!(header_map.contains(header));
        assert!(header_map.perms.contains(MapPerms::READ));
        assert_eq!(
            ElfImageSelector::from_elf_header_map(header_map)?,
            image_selector
        );
        println!(
            "image={:p} base={:p} build-id-bytes={} device={}:{} inode={} offset={}",
            image.elf_header(),
            image.loader_base(),
            image.build_id().map_or(0, <[u8]>::len),
            source.device().major,
            source.device().minor,
            source.inode(),
            source.elf_header_offset(),
        );
    }

    let request = PltHookRequest::new(&image_selector, c"getpid", replacement_getpid as *const ())?;

    // SAFETY: this single-threaded process keeps the executable and relocation
    // metadata stable for the read-only scan.
    let report = unsafe { inspect_hooks(&[request]) }?;
    for inspected in report {
        if let Some(error) = inspected.error() {
            println!("PLT hook rejected: {error}");
        }
        for image in inspected.images() {
            for slot in &image.slots {
                println!(
                    "address={:p} kind={:?} current={:p} status={:?}",
                    slot.address, slot.kind, slot.current, slot.status
                );
                if slot.status == InspectionStatus::SelectionEligible {
                    let _selector = slot.selector();
                }
            }
        }
    }
    Ok(())
}

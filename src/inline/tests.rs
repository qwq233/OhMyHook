use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

unsafe extern "C" {
    fn isdigit(value: libc::c_int) -> libc::c_int;
    fn lgammaf(value: libc::c_float) -> libc::c_float;
}

type Unary = unsafe extern "C" fn(libc::c_int) -> libc::c_int;
type Padded = unsafe extern "C" fn(libc::c_float) -> libc::c_float;
static ORIGINAL: AtomicUsize = AtomicUsize::new(0);
static PADDED_ORIGINAL: AtomicUsize = AtomicUsize::new(0);
static PREPARED_ORIGINAL: AtomicUsize = AtomicUsize::new(0);

#[test]
fn prepared_private_file_validation_follows_the_final_patch_window() {
    let request = PreparedInlineHook {
        target_address: 0x1000,
        patch_address: 0x1ff0,
        original_bytes: vec![0; 28],
        patch_bytes: vec![0; 28],
        trampoline: 0x3000,
        pages: Vec::new(),
        arenas: Vec::new(),
        path_request: None,
        require_private_file_pages: true,
    };

    let hooks = [request];
    assert!(!private_file_validation_is_complete(&hooks, &[0x1000], 4096).unwrap());
    assert!(private_file_validation_is_complete(&hooks, &[0x1000, 0x2000], 4096).unwrap());

    let mut maps = [MapInfo {
        start: 0x1000,
        end: 0x3000,
        perms: crate::MapPerms::READ | crate::MapPerms::EXEC,
        is_private: true,
        offset: 0,
        device: crate::DeviceId::new(0, 1),
        inode: 1,
        path: None,
    }];
    let windows = || {
        hooks.iter().map(|request| {
            (
                request.patch_address,
                request.patch_bytes.len(),
                request.require_private_file_pages,
            )
        })
    };
    let pages = inline_private_file_validation_pages(windows(), &maps, 4096, &[]).unwrap();
    assert_eq!(
        pages.iter().map(|(page, _)| *page).collect::<Vec<_>>(),
        [0x1000, 0x2000]
    );
    let smaps = [SmapInfo {
        map: maps[0].clone(),
        vm_flags: Default::default(),
        protection_key: 0,
    }];
    let validated = validate_inline_private_file_pages(&pages, &smaps, 4096).unwrap();
    assert!(private_file_validation_is_complete(&hooks, &validated, 4096).unwrap());
    assert!(inline_private_file_validation_pages(windows(), &maps, 4096, &[0x2000]).is_err());
    maps[0].end = 0x2000;
    assert!(inline_private_file_validation_pages(windows(), &maps, 4096, &[]).is_err());
    maps[0].end = 0x3000;
    maps[0].is_private = false;
    assert!(inline_private_file_validation_pages(windows(), &maps, 4096, &[]).is_err());
}

#[cfg(target_arch = "x86")]
#[test]
fn distant_pc_thunk_preserves_original_return_address_through_hook_lifecycle() {
    serialized(|| {
        for thunk_code in [
            &[0x8b, 0x04, 0x24, 0xc3][..], // mov eax, [esp]; ret
            &[0xf3, 0x0f, 0x1e, 0xfb, 0x8b, 0x04, 0x24, 0xc3][..], // endbr32; mov eax, [esp]; ret
        ] {
            let page_size = crate::sys::page_size().unwrap();
            let thunk_offset = 3 * 1024 * 1024;
            let length = thunk_offset + page_size;
            // SAFETY: reserve separate code pages outside the initial lookup window.
            let mapping = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    length,
                    libc::PROT_NONE,
                    libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                    -1,
                    0,
                )
            };
            assert_ne!(mapping, libc::MAP_FAILED);
            let target = mapping as usize;
            let thunk = target + thunk_offset;
            let replacement = target + 0x100;
            let expected = (target + 9) as i32;
            let mut source = vec![0xf3, 0x0f, 0x1e, 0xfb, 0xe8]; // endbr32; call
            source.extend_from_slice(&((thunk_offset - 9) as u32).to_le_bytes());
            source.push(0xc3); // ret
            // SAFETY: only these two owned pages are writable while code is emitted.
            unsafe {
                for page in [target, thunk] {
                    assert_eq!(
                        libc::mprotect(
                            page as *mut _,
                            page_size,
                            libc::PROT_READ | libc::PROT_WRITE
                        ),
                        0
                    );
                }
                for (address, bytes) in [
                    (target, source.as_slice()),
                    (thunk, thunk_code),
                    (replacement, &[0xb8, 11, 0, 0, 0, 0xc3]), // mov eax, 11; ret
                ] {
                    std::ptr::copy_nonoverlapping(bytes.as_ptr(), address as *mut u8, bytes.len());
                }
                for page in [target, thunk] {
                    assert_eq!(
                        libc::mprotect(
                            page as *mut _,
                            page_size,
                            libc::PROT_READ | libc::PROT_EXEC
                        ),
                        0
                    );
                }
            }
            let entry = std::ptr::with_exposed_provenance::<()>(target);
            assert_eq!(call(entry, 0), expected);
            let request =
                InlineHookRequest::new(entry, std::ptr::with_exposed_provenance(replacement));
            let mut installed = install_one(&request).unwrap();
            assert_eq!(call(entry, 0), 11);
            let original_result = call(installed.original().unwrap(), 0);
            unhook_one(&mut installed).unwrap();
            assert_eq!(call(entry, 0), expected);
            // SAFETY: all calls and the hook's trampoline have been drained.
            assert_eq!(unsafe { libc::munmap(mapping, length) }, 0);
            assert_eq!(original_result, expected);
        }
    });
}

#[cfg(target_arch = "arm")]
#[test]
fn thumb_compare_branches_preserve_both_paths_at_each_halfword_alignment() {
    serialized(|| {
        let page_size = crate::sys::page_size().unwrap();
        // SAFETY: this test exclusively owns the page and all calls into it.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        let base = mapping as usize;
        let cases = [(0xb108_u16, 0), (0xb108, 2), (0xb908, 0), (0xb908, 2)];
        let replacement = base + 0x100;
        // SAFETY: all instruction sequences fit in the owned writable page.
        unsafe {
            for (index, &(branch, alignment)) in cases.iter().enumerate() {
                let target = base + index * 0x40 + alignment;
                // cbz/cbnz r0, .+6; movs r0,#1; bx lr; movs r0,#2; bx lr
                let words = [branch, 0x2001, 0x4770, 0x2002, 0x4770];
                std::ptr::copy_nonoverlapping(words.as_ptr(), target as *mut u16, words.len());
            }
            let words = [0x200b_u16, 0x4770]; // movs r0,#11; bx lr
            std::ptr::copy_nonoverlapping(words.as_ptr(), replacement as *mut u16, words.len());
            assert_eq!(
                libc::mprotect(mapping, page_size, libc::PROT_READ | libc::PROT_EXEC),
                0
            );
            assert!(
                crate::sys::flush_instruction_cache_ranges_checked(
                    &[(base, base + page_size)],
                    true,
                    &mut false
                )
                .is_none()
            );
        }
        for (index, &(branch, alignment)) in cases.iter().enumerate() {
            let target = base + index * 0x40 + alignment;
            let entry = std::ptr::with_exposed_provenance::<()>(target | 1);
            let nonzero = branch & 0x800 != 0;
            let expected = [if nonzero { 1 } else { 2 }, if nonzero { 2 } else { 1 }];
            assert_eq!([call(entry, 0), call(entry, 1)], expected);
            let request =
                InlineHookRequest::new(entry, std::ptr::with_exposed_provenance(replacement | 1));
            let mut installed = install_one(&request).unwrap();
            let original = installed.original().unwrap();
            assert_eq!([call(entry, 0), call(entry, 1)], [11, 11]);
            assert_eq!([call(original, 0), call(original, 1)], expected);
            unhook_one(&mut installed).unwrap();
            assert_eq!([call(entry, 0), call(entry, 1)], expected);
        }
        // SAFETY: every hook is removed and all calls have drained.
        assert_eq!(unsafe { libc::munmap(mapping, page_size) }, 0);
    });
}

#[cfg(target_arch = "aarch64")]
#[test]
fn far_variant_falls_back_to_the_landing_form_for_fallthrough_windows() {
    const NOP: u32 = 0xd503_201f;
    const RET: u32 = 0xd65f_03c0;
    let sequential = [NOP; 7];
    let code = sequential
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<_>>();
    let analysis =
        analyze_inplace_far_variant(0x1000, &code, false, false).expect("28-byte fallback");
    assert_eq!(analysis.original.len(), 28);

    let terminal = [NOP, NOP, NOP, RET];
    let code = terminal
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<_>>();
    let analysis = analyze_inplace_far_variant(0x1000, &code, false, false).expect("compact far");
    assert_eq!(analysis.original.len(), 16);

    let guarded_code = sequential
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<_>>();
    let guarded =
        analyze_inplace_far_variant(0x1000, &guarded_code, true, false).expect("guarded far");
    assert_eq!(guarded.original.len(), 28);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn far_batch_windows_keep_page_offsets_and_empty_intersections() {
    let page_size = crate::sys::page_size().unwrap();
    let request = |target| {
        let words = [
            0x5400_8000_u32,
            0xd503_201f,
            0xd503_201f,
            0xd503_201f,
            0xd503_201f,
            0xd503_201f,
            0xd503_201f,
        ];
        let code = words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        AnalyzedInlineHook {
            analysis: arch::analyze_inplace_far(target, &code).unwrap(),
            code_address: target,
            replacement: target + 0x100,
            pages: Vec::new(),
            require_private_file_pages: false,
            path_request: None,
            guarded: true,
            replacement_bti: arch::ReplacementBti {
                hint: false,
                cache: std::cell::Cell::new(None),
            },
        }
    };
    let mut hooks = [request(0x2000_0000), request(0x2001_0000)];
    let first = arch::far_branch_window(&hooks[0].analysis, true).unwrap();
    let second = arch::far_branch_window(&hooks[1].analysis, true).unwrap();
    let expected = Some((
        first.0.max(second.0 - page_size),
        first.1.min(second.1 - page_size),
    ));
    assert_eq!(
        arena_candidate_window(&hooks, page_size, false).unwrap(),
        expected
    );
    assert_eq!(
        arena_candidate_window(&hooks, page_size, true).unwrap(),
        expected
    );
    hooks[1] = request(0x5000_0000);
    let (low, high) = arena_candidate_window(&hooks, page_size, false)
        .unwrap()
        .unwrap();
    assert!(low > high);
}

#[cfg(target_arch = "aarch64")]
#[test]
fn far_fallback_hooks_an_external_conditional_without_near_arena_space() {
    serialized(|| {
        let page_size = crate::sys::page_size().unwrap();
        let radius = 1 << 27;
        let far_space = 0x80000;
        let length = 2 * radius + page_size;
        // SAFETY: reserve address space without committing physical pages.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length + far_space,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        let reservation_start = mapping as usize + far_space;
        let arena_page = mapping as usize + far_space / 2;
        let target = reservation_start + radius;
        let destination = target - far_space;
        let replacement = target + 0x100;
        for (address, words) in [
            (
                target,
                vec![0x34c0_0000_u32, 0x5280_0020, 0xd503_201f, 0xd65f_03c0],
            ),
            (destination, vec![0x5280_0040, 0xd65f_03c0]),
            (replacement, vec![0x5280_0160, 0xd65f_03c0]),
        ] {
            let page = crate::sys::page_start(address, page_size);
            // SAFETY: this test owns each complete page and has no live calls.
            unsafe {
                assert_eq!(
                    libc::mprotect(
                        page as *mut _,
                        page_size,
                        libc::PROT_READ | libc::PROT_WRITE
                    ),
                    0
                );
                std::ptr::copy_nonoverlapping(words.as_ptr(), address as *mut u32, words.len());
                assert_eq!(
                    libc::mprotect(page as *mut _, page_size, libc::PROT_READ | libc::PROT_EXEC),
                    0
                );
                assert!(
                    crate::sys::flush_instruction_cache_ranges_checked(
                        &[(address, address + words.len() * 4)],
                        true,
                        &mut false
                    )
                    .is_none()
                );
            }
        }
        let entry = std::ptr::with_exposed_provenance::<()>(target);
        assert_eq!(call(entry, 0), 2);
        assert_eq!(call(entry, 1), 1);
        // Keep both sides reserved so larger allocator/stack mappings cannot
        // consume the far slot while installation allocates its working data.
        // SAFETY: this page belongs to the reservation and contains no code.
        assert_eq!(unsafe { libc::munmap(arena_page as *mut _, page_size) }, 0);
        let request = InlineHookRequest::new(entry, std::ptr::with_exposed_provenance(replacement));
        let mut installed = install_one(&request).unwrap_or_else(|error| {
            let maps =
                crate::maps::read_self_maps_for_ranges(&[(arena_page, arena_page + page_size)])
                    .unwrap();
            let ranges = maps
                .iter()
                .map(|map| (map.start, map.end, map.perms))
                .collect::<Vec<_>>();
            panic!("far fallback failed: {error:?}; arena_page={arena_page:#x}, maps={ranges:x?}");
        });
        let original = installed.original().unwrap();
        assert!(original.expose_provenance().abs_diff(target) >= radius);
        assert_eq!(call(entry, 0), 11);
        assert_eq!(call(entry, 1), 11);
        assert_eq!(call(original, 0), 2);
        assert_eq!(call(original, 1), 1);
        unhook_one(&mut installed).unwrap();
        assert_eq!(call(entry, 0), 2);
        assert_eq!(call(entry, 1), 1);
        for (start, size) in [
            (mapping as usize, far_space / 2),
            (arena_page + page_size, length + far_space / 2 - page_size),
        ] {
            // SAFETY: only the two still-owned segments are released; the arena
            // page between them was handed to the allocator and has been drained.
            assert_eq!(unsafe { libc::munmap(start as *mut _, size) }, 0);
        }
    });
}

#[cfg(target_arch = "aarch64")]
#[test]
fn same_page_adrp_only_rejects_actual_stolen_byte_accesses() {
    #[repr(align(4096))]
    struct Code([u32; 64]);
    let mut code = Code([0xd503_201f; 64]);
    let target = code.0.as_ptr() as usize;
    code.0[0] = 0x9000_0000; // adrp x0, current page
    code.0[7] = 0xd65f_03c0; // ret, beyond either stolen window
    let maps = [crate::maps::MapInfo {
        start: target,
        end: target + std::mem::size_of_val(&code.0),
        perms: crate::MapPerms::READ | crate::MapPerms::EXEC,
        is_private: true,
        offset: 0,
        device: crate::DeviceId::new(0, 0),
        inode: 0,
        path: None,
    }];
    for (offset, overlaps) in [(0x100, false), (0, true)] {
        code.0[1] = 0x9100_0000 | (offset << 10); // add x0, x0, #offset
        for access in [
            0xb940_0000,
            0xb87f_6800,
            0x88df_fc00,
            0x885f_7c00,
            0x4c40_7000,
        ] {
            code.0[2] = access;
            let bytes = code
                .0
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect::<Vec<_>>();
            for analysis in [
                super::aarch64::analyze(target, &bytes).unwrap(),
                super::aarch64::analyze_inplace_far(target, &bytes).unwrap(),
            ] {
                let result = scan_inline_data_references(&analysis, &maps);
                if overlaps {
                    assert!(matches!(result, Err(Error::InlineDataReference { .. })));
                } else {
                    result.unwrap();
                }
            }
        }
    }
}

#[cfg(target_arch = "aarch64")]
#[test]
fn data_reference_scan_starts_at_the_address_definition() {
    const NOP: u32 = 0xd503_201f;
    let mut code_words = [NOP; 7];
    let target = code_words.as_ptr() as usize;
    code_words[0] = super::aarch64::encode_adr_reg(target, target + 32, 0).unwrap();
    code_words[1] = 0x381f_8001; // ldurb w1, [x0, #-8]
    let code = code_words
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<_>>();
    assert_eq!(
        u32::from_le_bytes(code[..4].try_into().unwrap()),
        0x1000_0100
    );
    let analysis = super::aarch64::analyze_inplace_far(target, &code).unwrap();
    assert_eq!(analysis.address_references.len(), 1);
    let maps = [crate::maps::MapInfo {
        start: target,
        end: target + code.len(),
        perms: crate::maps::MapPerms::READ | crate::maps::MapPerms::EXEC,
        is_private: true,
        offset: 0,
        device: crate::maps::DeviceId::new(0, 0),
        inode: 0,
        path: None,
    }];

    let error = scan_inline_data_references(&analysis, &maps).unwrap_err();
    assert!(
        matches!(error, Error::InlineDataReference { .. }),
        "unexpected error: {error:?}"
    );
}

#[cfg(target_arch = "aarch64")]
#[test]
fn data_reference_scan_continues_past_the_initial_window() {
    const NOP: u32 = 0xd503_201f;
    const RET: u32 = 0xd65f_03c0;
    for access_index in [32, 33, 64, 65, 129] {
        let mut code_words = [NOP; 136];
        let target = code_words.as_ptr() as usize;
        code_words[0] = super::aarch64::encode_adr_reg(target, target + 32, 0).unwrap();
        code_words[access_index] = 0x385e_0001; // ldurb w1, [x0, #-32]
        code_words[135] = RET;
        let code = code_words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        let analysis = super::aarch64::analyze_inplace_far(target, &code).unwrap();
        let maps = [crate::maps::MapInfo {
            start: target,
            end: target + code.len(),
            perms: crate::maps::MapPerms::READ | crate::maps::MapPerms::EXEC,
            is_private: true,
            offset: 0,
            device: crate::maps::DeviceId::new(0, 0),
            inode: 0,
            path: None,
        }];

        let error = scan_inline_data_references(&analysis, &maps).unwrap_err();
        assert!(
            matches!(error, Error::InlineDataReference { instruction, address }
                if instruction == target + access_index * 4 && address == target),
            "access index {access_index}: unexpected error: {error:?}"
        );
    }
}

#[cfg(target_arch = "aarch64")]
#[test]
fn data_reference_scan_stops_after_a_terminal_instruction() {
    const NOP: u32 = 0xd503_201f;
    const RET: u32 = 0xd65f_03c0;
    let mut code_words = [NOP; 72];
    let target = code_words.as_ptr() as usize;
    code_words[0] = super::aarch64::encode_adr_reg(target, target + 32, 0).unwrap();
    code_words[31] = RET;
    code_words[33] = 0x385e_0001; // ldurb w1, [x0, #-32], after RET
    let code = code_words
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<_>>();
    let analysis = super::aarch64::analyze_inplace_far(target, &code).unwrap();
    let maps = [crate::maps::MapInfo {
        start: target,
        end: target + code.len(),
        perms: crate::maps::MapPerms::READ | crate::maps::MapPerms::EXEC,
        is_private: true,
        offset: 0,
        device: crate::maps::DeviceId::new(0, 0),
        inode: 0,
        path: None,
    }];

    assert!(scan_inline_data_references(&analysis, &maps).is_ok());
}

#[cfg(target_arch = "aarch64")]
#[test]
fn data_reference_scan_preserves_aliases_past_the_initial_window() {
    const NOP: u32 = 0xd503_201f;
    const RET: u32 = 0xd65f_03c0;
    for overwrite_alias in [false, true] {
        let mut code_words = [NOP; 40];
        let target = code_words.as_ptr() as usize;
        code_words[0] = super::aarch64::encode_adr_reg(target, target + 0x100, 0).unwrap();
        code_words[1] = 0xaa00_03e1; // mov x1, x0
        code_words[2] = 0xd280_0000; // mov x0, #0; x1 retains the reference
        if overwrite_alias {
            code_words[32] = 0xaa03_03e1; // mov x1, x3; overwrite the last alias
        }
        code_words[33] = 0x3850_0022; // ldurb w2, [x1, #-256]
        code_words[39] = RET;
        let code = code_words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        let analysis = super::aarch64::analyze_inplace_far(target, &code).unwrap();
        let maps = [crate::maps::MapInfo {
            start: target,
            end: target + code.len(),
            perms: crate::maps::MapPerms::READ | crate::maps::MapPerms::EXEC,
            is_private: true,
            offset: 0,
            device: crate::maps::DeviceId::new(0, 0),
            inode: 0,
            path: None,
        }];

        let result = scan_inline_data_references(&analysis, &maps);
        if overwrite_alias {
            result.unwrap();
        } else {
            assert!(
                matches!(result, Err(Error::InlineDataReference { .. })),
                "unexpected result: {result:?}"
            );
        }
    }
}

#[cfg(target_arch = "aarch64")]
#[test]
fn fixed_point_conversion_preserves_hook_and_original_calls() {
    serialized(|| {
        type FloatInput = unsafe extern "C" fn(f64) -> u32;
        let data = 42_u8;
        let address = std::ptr::from_ref(&data).addr() + 16;
        let argument = address as f64 / 2.0;
        assert_eq!((argument * 2.0) as usize, address);
        for conversion in [0x9e58_fc00_u32, 0x9e59_fc00_u32] {
            let page = PrivateExecPage::new().expect("private executable page");
            let words = [
                super::aarch64::encode_adr_reg(page.address, page.address + 16, 0).unwrap(),
                conversion,  // fcvtzs/fcvtzu x0, d0, #1
                0x385f_0000, // ldurb w0, [x0, #-16]
                0xd65f_03c0, // ret
            ];
            let bytes = words
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect::<Vec<_>>();
            assert_eq!(
                // SAFETY: this owned file and its executable page are unused so far.
                unsafe { libc::pwrite(page.fd, bytes.as_ptr().cast(), bytes.len(), 0) },
                bytes.len() as isize
            );
            assert!(
                // SAFETY: the range is the owned executable mapping, with no calls in flight.
                unsafe {
                    crate::sys::flush_instruction_cache_ranges_checked(
                        &[(page.address, page.address + bytes.len())],
                        true,
                        &mut false,
                    )
                }
                .is_none()
            );
            // SAFETY: the emitted entry accepts d0 and returns an unsigned value in w0.
            let target = unsafe { std::mem::transmute::<*const (), FloatInput>(page.entry()) };
            // SAFETY: argument converts exactly to the live data address plus 16.
            assert_eq!(unsafe { target(argument) }, u32::from(data));
            let request = InlineHookRequest::new(
                page.entry(),
                std::ptr::with_exposed_provenance(page.address + 64),
            );
            let mut hook = install_one(&request).expect("fixed-point conversion installation");
            // SAFETY: the trampoline preserves the emitted entry's ABI and stays live.
            let original =
                unsafe { std::mem::transmute::<*const (), FloatInput>(hook.original().unwrap()) };
            // SAFETY: both calls use the same valid argument and complete before removal.
            unsafe {
                assert_eq!(target(argument), 1);
                assert_eq!(original(argument), u32::from(data));
            }
            unhook_one(&mut hook).unwrap();
            // SAFETY: removal restored the owned entry, and the data remains live.
            assert_eq!(unsafe { target(argument) }, u32::from(data));
        }
    });
}

// INLINE_TEST_LOCK lives at module level: the patch-module symbol audit
// shares it, because it reads pages these tests swap.

/// Runs `body` with the module's exclusive inline-mutation lock held.
///
/// Panics release the lock through unwinding, so a failing test cannot
/// poison the suite for its siblings.
fn serialized(body: impl FnOnce()) {
    let _guard = crate::sys::recover_lock(INLINE_TEST_LOCK.lock());
    assert!(
        crate::sys::recover_lock(ACTIVE_INLINE_TARGETS.lock()).is_empty(),
        "an earlier inline test leaked an installed target"
    );
    let _syscall_injections =
        crate::sys::recover_lock(crate::sys::tests::SYSCALL_INJECTION_LOCK.lock());
    #[cfg(feature = "plt")]
    let _process_guard = crate::sys::recover_lock(crate::plt::tests::PROCESS_TEST_LOCK.lock());
    arena::clear_pool_for_tests();
    reset_test_state();
    ORIGINAL.store(0, Ordering::Release);
    PADDED_ORIGINAL.store(0, Ordering::Release);
    PREPARED_ORIGINAL.store(0, Ordering::Release);
    let _injections = DisarmedInjections;
    body();
}

#[test]
fn active_target_registry_uses_sorted_binary_search() {
    serialized(|| {
        let targets = [0x3000, 0x1000, 0x2000];
        assert!(!inline_targets_installed(&targets));
        reserve_inline_targets(targets.len());
        register_inline_targets(&targets);
        assert!(inline_targets_installed(&[0x1000, 0x3000]));

        let mut encoded = targets
            .iter()
            .map(|target| crate::sys::encode_usize(*target))
            .collect::<Vec<_>>();
        encoded.sort_unstable();
        assert_eq!(
            *crate::sys::recover_lock(ACTIVE_INLINE_TARGETS.lock()),
            encoded
        );

        unregister_inline_targets(&[0x2000]);
        assert!(inline_targets_installed(&[0x1000, 0x3000]));
        assert!(!inline_targets_installed(&[0x2000]));
        unregister_inline_targets(&[0x1000, 0x3000]);
        assert!(crate::sys::recover_lock(ACTIVE_INLINE_TARGETS.lock()).is_empty());
    });
}

/// Installs one request through the batch entry point and returns the handle.
///
/// The per-request builder choices only exist on [`InlineHookRequest`], so the
/// single-target convenience entry point cannot reach them.
fn install_one(request: &InlineHookRequest) -> Result<InlineHookHandle> {
    // SAFETY: forwarded from the calling test's complete contract.
    let mut hooks = install_batch(std::slice::from_ref(request))?;
    hooks.pop().ok_or(Error::InvalidInlineTarget(
        "single inline request produced no handle",
    ))
}

/// Removes one test-owned handle under the shared inline test lock.
fn unhook_one(request: &mut InlineHookHandle) -> Result<()> {
    // SAFETY: every calling test holds the inline test lock and has
    // drained calls through the target and trampoline.
    unsafe { request.unhook() }
}

/// Installs a test-owned batch under the shared inline test lock.
fn install_batch(requests: &[InlineHookRequest]) -> Result<Vec<InlineHookHandle>> {
    // SAFETY: every calling test holds the inline test lock and upholds
    // the complete installation contract.
    unsafe { install_inline_hooks(requests) }.map(InlineHookBatch::into_handles)
}

// Forced-write capability probe shared with the plt tests.
use crate::sys::tests::forced_writes_supported;

/// Whether the real security policy of this process allows restoring
/// `PROT_EXEC` on a private file page after it has been written.
///
/// The probe uses a throwaway private mapping of a temporary file, so a
/// permanent refusal never damages a page another test or the harness
/// still executes. Such a domain cannot run the elevation-fallback
/// assertions at all: the first real refusal inside those tests would
/// leave a shared libc page non-executable for the rest of the process.
fn real_exec_restore_denied() -> bool {
    use std::ffi::CString;
    use std::io::Write;
    use std::sync::OnceLock;
    static DENIED: OnceLock<bool> = OnceLock::new();
    *DENIED.get_or_init(|| {
        let Ok(page_size) = crate::sys::page_size() else {
            return true;
        };
        let path = std::env::temp_dir().join(format!(
            "omhook-exec-restore-probe-{}.bin",
            std::process::id()
        ));
        let Ok(mut file) = std::fs::File::create(&path) else {
            return true;
        };
        if file.write_all(&vec![0x90_u8; page_size]).is_err() {
            let _ = std::fs::remove_file(&path);
            return true;
        }
        drop(file);
        let Ok(cpath) = CString::new(path.as_os_str().as_encoded_bytes()) else {
            let _ = std::fs::remove_file(&path);
            return true;
        };
        // SAFETY: cpath is NUL-terminated and names the probe file.
        let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            let _ = std::fs::remove_file(&path);
            return true;
        }
        // SAFETY: the probe owns this complete temporary mapping.
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page_size,
                libc::PROT_READ | libc::PROT_EXEC,
                libc::MAP_PRIVATE,
                fd,
                0,
            )
        };
        if address == libc::MAP_FAILED {
            // SAFETY: the descriptor was opened by this probe.
            unsafe { libc::close(fd) };
            let _ = std::fs::remove_file(&path);
            return true;
        }
        let exec = libc::PROT_READ | libc::PROT_EXEC;
        let writable = libc::PROT_READ | libc::PROT_WRITE;
        // SAFETY: this probe owns the complete temporary mapping and each
        // protection change names exactly that mapping.
        let denied = unsafe {
            crate::sys::protect_checked(address as usize, page_size, writable).is_some()
                || crate::sys::protect_checked(address as usize, page_size, exec).is_some()
        };
        // SAFETY: the mapping belongs to this probe and is no longer used.
        unsafe { libc::munmap(address, page_size) };
        // SAFETY: the descriptor belongs to this probe.
        unsafe { libc::close(fd) };
        let _ = std::fs::remove_file(&path);
        denied
    })
}

/// A private executable page backed by a temporary file, plus a callable
/// `mov w0, #1; ret` (A32: `mov r0, #1; bx lr`) entries at offsets 0 and 64.
///
/// Elevation-fallback tests deliberately strand their target page
/// non-executable on kernels whose policy refuses `execmod`. Doing that
/// to a shared libc page poisons every later test in this process, so
/// those tests drive this throwaway page instead.
struct PrivateExecPage {
    address: usize,
    length: usize,
    fd: i32,
    path: std::path::PathBuf,
}

impl PrivateExecPage {
    #[cfg(target_arch = "aarch64")]
    const CODE: [u8; 8] = [
        0x20, 0x00, 0x80, 0x52, // mov w0, #1
        0xc0, 0x03, 0x5f, 0xd6, // ret
    ];

    #[cfg(target_arch = "arm")]
    const CODE: [u8; 8] = [
        0x01, 0x00, 0xa0, 0xe3, // mov r0, #1
        0x1e, 0xff, 0x2f, 0xe1, // bx lr
    ];

    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    const CODE: [u8; 8] = [
        0xb8, 0x01, 0x00, 0x00, 0x00, // mov eax, 1
        0xc3, 0x66, 0x90, // ret; nop
    ];

    fn new() -> Option<Self> {
        use std::ffi::CString;
        use std::io::Write;
        let page_size = crate::sys::page_size().ok()?;
        let path =
            std::env::temp_dir().join(format!("omhook-private-exec-{}.bin", std::process::id()));
        let mut file = std::fs::File::create(&path).ok()?;
        let mut code = vec![0xcc_u8; page_size];
        code[..Self::CODE.len()].copy_from_slice(&Self::CODE);
        code[64..64 + Self::CODE.len()].copy_from_slice(&Self::CODE);
        file.write_all(&code).ok()?;
        drop(file);
        let cpath = CString::new(path.as_os_str().as_encoded_bytes()).ok()?;
        // SAFETY: cpath is NUL-terminated and names the probe file.
        let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            let _ = std::fs::remove_file(&path);
            return None;
        }
        // SAFETY: this page owns the complete fresh mapping.
        let address = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page_size,
                libc::PROT_READ | libc::PROT_EXEC,
                libc::MAP_PRIVATE,
                fd,
                0,
            )
        };
        if address == libc::MAP_FAILED {
            // SAFETY: the descriptor belongs to this page.
            unsafe { libc::close(fd) };
            let _ = std::fs::remove_file(&path);
            return None;
        }
        Some(Self {
            address: address as usize,
            length: page_size,
            fd,
            path,
        })
    }

    fn entry(&self) -> *const () {
        std::ptr::with_exposed_provenance(self.address)
    }
}

impl Drop for PrivateExecPage {
    fn drop(&mut self) {
        // SAFETY: this page owns the mapping, descriptor, and file, and
        // no test uses them after dropping the page.
        unsafe {
            libc::munmap(self.address as *mut _, self.length);
            libc::close(self.fd);
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Disarms every process-global syscall injection switch.
///
/// The module lock cannot cover a test that deliberately arms a switch
/// before entering it; this reset closes that window without weakening
/// the injections themselves.
struct DisarmedInjections;

impl Drop for DisarmedInjections {
    fn drop(&mut self) {
        crate::sys::tests::restore_next_protect();
        crate::sys::tests::restore_next_unmap();
        crate::sys::tests::restore_next_map();
        crate::sys::tests::FAIL_NEXT_SYNC.store(false, Ordering::Release);
        crate::sys::tests::restore_exec_regrant();
        crate::sys::tests::restore_next_self_mem_open();
        patch::tests::restore_forced_close_failure();
        patch::tests::restore_forced_write_failure();
        patch::tests::restore_forced_unavailable_failure();
        crate::sys::tests::deny_exec_protect_page(0);
    }
}

#[inline(never)]
extern "C" fn replacement(value: libc::c_int) -> i32 {
    let original = std::ptr::with_exposed_provenance(ORIGINAL.load(Ordering::Acquire));
    // SAFETY: the test publishes this request's live trampoline and drains
    // the call before removal.
    let original = unsafe { std::mem::transmute::<*const (), Unary>(original) };
    // SAFETY: the caller passes an `int` in the target's valid domain.
    unsafe { original(value) + 10 }
}

#[inline(never)]
extern "C" fn prepared_replacement(value: libc::c_int) -> i32 {
    let original = std::ptr::with_exposed_provenance(PREPARED_ORIGINAL.load(Ordering::Acquire));
    // SAFETY: the test publishes this request's live trampoline and drains
    // every call before removal.
    let original = unsafe { std::mem::transmute::<*const (), Unary>(original) };
    // SAFETY: the caller passes an `int` in the target's valid domain.
    unsafe { original(value) + 10 }
}

#[inline(never)]
extern "C" fn padded_replacement(value: libc::c_float) -> libc::c_float {
    let original = std::ptr::with_exposed_provenance(PADDED_ORIGINAL.load(Ordering::Acquire));
    // SAFETY: the test publishes this request's live trampoline and drains
    // the call before removal.
    let original = unsafe { std::mem::transmute::<*const (), Padded>(original) };
    // SAFETY: the caller passes a finite float.
    unsafe { original(value) + 1.0 }
}

fn call(entry: *const (), value: i32) -> i32 {
    // SAFETY: the entry accepts this `int`.
    let entry = unsafe { std::mem::transmute::<*const (), Unary>(entry) };
    unsafe {
        // SAFETY: the entry accepts this `int`.
        std::hint::black_box(entry)(std::hint::black_box(value))
    }
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64", target_arch = "aarch64"))]
#[test]
fn protection_keys_preserve_inline_lifecycle_and_forced_access() {
    serialized(|| {
        let Some(rights) = crate::sys::PkeyTestRights::new() else {
            return;
        };
        for path in [
            MutationPath::KeepExec,
            MutationPath::DropExec,
            MutationPath::ForcedWrite,
        ] {
            if path == MutationPath::ForcedWrite && !forced_writes_supported() {
                continue;
            }
            let page = PrivateExecPage::new().expect("private executable page");
            rights.set_writable(false);
            // SAFETY: this test owns the mapping and key, and no call is in flight.
            unsafe {
                syscalls::syscall!(
                    syscalls::Sysno::pkey_mprotect,
                    page.address,
                    page.length,
                    libc::PROT_READ | libc::PROT_EXEC,
                    rights.key
                )
                .unwrap();
            }
            let request = InlineHookRequest::new(page.entry(), replacement as *const ())
                .with_mutation_path(path);
            if path != MutationPath::ForcedWrite {
                let error = install_batch(std::slice::from_ref(&request))
                    .err()
                    .expect("write denial must be detected before mutation");
                assert!(matches!(
                    error,
                    Error::SystemCall {
                        operation: "pkey write access",
                        source: syscalls::Errno::EACCES,
                    }
                ));
                assert_eq!(call(page.entry(), 0), 1);
                rights.set_writable(true);
            }
            let mut hooks = install_batch(std::slice::from_ref(&request)).unwrap();
            let mut handle = hooks.pop().unwrap();
            let original = handle.original().unwrap();
            ORIGINAL.store(original.expose_provenance(), Ordering::Release);
            assert_eq!(call(original, 0), 1);
            assert_eq!(call(page.entry(), 0), 11);
            rights.set_writable(false);
            if path != MutationPath::ForcedWrite {
                let error = unhook_one(&mut handle).expect_err("write denial must retain the hook");
                assert!(matches!(
                    error,
                    Error::SystemCall {
                        operation: "pkey write access",
                        source: syscalls::Errno::EACCES,
                    }
                ));
                assert!(handle.is_installed());
                assert_eq!(call(page.entry(), 0), 11);
                rights.set_writable(true);
            }
            unhook_one(&mut handle).unwrap();
            assert_eq!(call(page.entry(), 0), 1);
        }
    });
}

#[test]
fn cleanup_pending_retains_arenas_for_retry() {
    serialized(|| {
        if !forced_writes_supported() {
            return;
        }
        // The request explicitly opts out so this test exercises the
        // plain in-place path rather than PrivateFileValidation.
        let request = InlineHookRequest::new(isdigit as *const (), replacement as *const ());
        {
            // SAFETY: the inline test lock excludes target execution and
            // competing mutation.
            let mut hooks = install_batch(&[request]).expect("inline request installation failed");
            let mut request = hooks.pop().expect("one installed inline handle");
            let trampoline = request.original().unwrap().expose_provenance();
            crate::sys::tests::fail_next_protect();

            // SAFETY: no target, replacement, original, or trampoline call
            // is in flight.
            let error = unhook_one(&mut request).expect_err("cleanup failure was not reported");
            crate::sys::tests::restore_next_protect();
            assert!(matches!(error, Error::InlineCleanupPending(_)));
            assert!(!request.is_installed());
            assert!(request.original().is_none());
            assert!(
                crate::read_self_maps()
                    .unwrap()
                    .iter()
                    .any(|map| map.start <= trampoline && trampoline < map.end)
            );

            // SAFETY: the target is already restored; this retries only
            // pending cleanup.
            unhook_one(&mut request).expect("cleanup retry failed");
            assert!(
                arena::reserved_pool_ranges_for_tests()
                    .iter()
                    .any(|&(start, end)| start <= trampoline && trampoline < end)
            );
        }
    });
}

#[test]
fn install_rollback_reports_protection_failure_for_pool_arena() {
    // Placement may reject a candidate before its executable transition;
    // returning that pool page also needs mprotect and must report cleanup.
    serialized(|| {
        if !forced_writes_supported() {
            return;
        }
        let target = isdigit as *const ();
        let before = [call(target, -1), call(target, i32::from(b'7'))];
        // Both failed self-mem opens force the RW pool path; the next
        // protection change fails during generation cleanup or publication.
        crate::sys::tests::fail_next_self_mem_open_times(2);
        crate::sys::tests::fail_next_protect();
        let error = {
            // SAFETY: both entries are live and ABI-compatible; the arena
            // cannot become executable.
            let request = InlineHookRequest::new(isdigit as *const (), replacement as *const ());
            // SAFETY: the same complete test contract covers this batch.
            install_batch(std::slice::from_ref(&request))
                .err()
                .expect("installation cannot succeed with every mutation syscall denied")
        };
        crate::sys::tests::restore_next_protect();
        crate::sys::tests::restore_next_self_mem_open();
        assert!(
            matches!(
                error,
                Error::SystemCall {
                    operation: "mprotect",
                    source: syscalls::Errno::EPERM,
                } | Error::InlineCleanupPending(syscalls::Errno::EPERM)
            ),
            "unexpected error: {error:?}"
        );
        assert_eq!([call(target, -1), call(target, i32::from(b'7'))], before);
    });
}

#[test]
fn executable_replacement_permissions_preserve_hook_lifecycle() {
    serialized(|| {
        if !forced_writes_supported() {
            return;
        }
        let page = PrivateExecPage::new().expect("replacement page allocation failed");
        let target = isdigit as *const ();
        for protection in [
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            libc::PROT_EXEC,
        ] {
            assert_eq!(
                // SAFETY: this test owns the entire unused replacement mapping.
                unsafe { libc::mprotect(page.address as *mut _, page.length, protection) },
                0
            );
            assert_eq!(call(target, -1), 0);
            // SAFETY: the lock excludes mutation and target execution; the
            // ABI-compatible replacement stays mapped through removal.
            let mut hook = unsafe { install_inline_hook(target, page.entry()) }
                .expect("executable replacement installation failed");
            assert_eq!(
                hook.private_file_validation(),
                crate::PrivateFileValidation::Unvalidated
            );
            assert_eq!(call(target, -1), 1);
            assert_eq!(call(hook.original().expect("missing original"), -1), 0);
            // SAFETY: all calls completed while the test still owns the lock.
            unhook_one(&mut hook).expect("executable replacement removal failed");
            assert_eq!(call(target, -1), 0);
        }
    });
}

#[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
#[test]
fn short_entry_uses_an_adjacent_relay_for_a_far_replacement() {
    serialized(|| {
        let page_size = crate::sys::page_size().unwrap();
        // SAFETY: this test owns both fresh pages until the second is released
        // for the installer's relay allocation.
        let base = unsafe { crate::sys::map_rw_anonymous(0, page_size * 2, 0) }.unwrap();
        let target = base + page_size - 32;
        let landing = [
            0xf3,
            0x0f,
            0x1e,
            if cfg!(target_arch = "x86_64") {
                0xfa
            } else {
                0xfb
            },
        ];
        // SAFETY: both entries lie in the writable page owned by this test.
        unsafe {
            let bytes = std::slice::from_raw_parts_mut(base as *mut u8, page_size);
            bytes[..4].copy_from_slice(&landing);
            bytes[4..10].copy_from_slice(&[0xb8, 42, 0, 0, 0, 0xc3]);
            bytes[page_size - 32..page_size - 28].copy_from_slice(&landing);
            bytes[page_size - 28..page_size - 25].copy_from_slice(&[0x31, 0xc0, 0xc3]);
            crate::sys::protect(base, page_size, libc::PROT_READ | libc::PROT_EXEC).unwrap();
            crate::sys::unmap(base + page_size, page_size).unwrap();
        }
        let target = std::ptr::with_exposed_provenance(target);
        assert_eq!(call(target, 0), 0);
        // SAFETY: the test lock keeps the complete target page quiescent; both
        // entries implement the same unary ABI and remain mapped until removal.
        let installed =
            unsafe { install_inline_hook(target, std::ptr::with_exposed_provenance(base)) };
        if let Err(error) = installed {
            // SAFETY: a failed installation did not publish a target branch.
            unsafe { crate::sys::unmap(base, page_size) }.unwrap();
            panic!("short entry installation failed: {error}");
        }
        let mut hook = installed.unwrap();
        assert_eq!(
            hook.private_file_validation(),
            crate::PrivateFileValidation::Unvalidated
        );
        assert_eq!(call(target, 0), 42);
        assert_eq!(call(hook.original().unwrap(), 0), 0);
        unhook_one(&mut hook).unwrap();
        assert_eq!(call(target, 0), 0);
        // SAFETY: the hook is removed and no call remains in flight.
        unsafe { crate::sys::unmap(base, page_size) }.unwrap();
    });
}

#[test]
fn installs_calls_original_and_removes_inline_hook() {
    serialized(|| {
        let forced = forced_writes_supported();
        // A private page stays quiescent even if the fallback drops PROT_EXEC.
        let fixture = PrivateExecPage::new().expect("private executable page");
        let target_entry = fixture.entry();
        // SAFETY: installation is rejected before mutating code because
        // the replacement overlaps the analyzed target entry.
        assert!(matches!(
            unsafe {
                // SAFETY: installation is rejected before mutation.
                install_inline_hook(target_entry, target_entry)
            },
            Err(Error::Conflict)
        ));
        // SAFETY: the lock excludes target execution and competing
        // mutation while installing and removing ABI-compatible functions.
        let request = InlineHookRequest::new(target_entry, replacement as *const ());
        // SAFETY: the same complete test contract covers this batch.
        let mut hooks = unsafe {
            // SAFETY: the same complete test contract covers this batch.
            install_inline_hooks(std::slice::from_ref(&request))
        }
        .expect("inline request installation failed")
        .into_handles();
        let mut request = hooks.pop().expect("one installed inline handle");
        assert_eq!(
            request.install_mutation_path() == MutationPath::ForcedWrite,
            forced
        );
        // SAFETY: the first handle still owns the exact installed
        // redirection; a second installation must fail without changing it.
        assert!(matches!(
            unsafe {
                // SAFETY: the first handle owns the installed target.
                install_inline_hook(target_entry, replacement as *const ())
            },
            Err(Error::Conflict)
        ));
        let original = request.original().expect("missing original trampoline");
        ORIGINAL.store(original.expose_provenance(), Ordering::Release);

        assert!(request.is_installed());
        assert_eq!(call(target_entry, -1), 11);
        assert_eq!(call(original, -1), 1);

        // SAFETY: all calls above completed and the lock still holds.
        unhook_one(&mut request).expect("inline request removal failed");
        assert!(!request.is_installed());
        assert!(request.original().is_none());
        assert_eq!(call(target_entry, -1), 1);
        // SAFETY: successful removal is explicitly idempotent.
        unhook_one(&mut request).expect("repeated removal failed");
    });
}

#[cfg(target_arch = "aarch64")]
#[test]
fn batch_rejects_a_replacement_inside_another_target_patch_window() {
    const NOP: u32 = 0xd503_201f;
    const RET: u32 = 0xd65f_03c0;
    let mut words = [NOP; 7];
    words[6] = RET;
    let code = words
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<_>>();
    let analysis = super::aarch64::analyze_inplace_far(0x1000, &code).unwrap();
    let replacement = analysis.patch_address + 4;
    let hook = AnalyzedInlineHook {
        code_address: analysis.patch_address,
        analysis,
        replacement,
        pages: Vec::new(),
        require_private_file_pages: false,
        path_request: None,
        guarded: false,
        replacement_bti: arch::ReplacementBti {
            hint: false,
            cache: std::cell::Cell::new(None),
        },
    };

    assert!(matches!(
        validate_analyzed_hooks(std::slice::from_ref(&hook), &[]),
        Err(Error::Conflict)
    ));

    // A second hook can use code just after the first hook's near patch.
    // Far fallback expands that window, even though its own replacement is
    // elsewhere and the two target windows do not overlap.
    let replacements = [0x3000, 0x1004];
    assert!(
        validate_replacement_windows(
            [(0x1000, 4), (0x2000, 4)].into_iter(),
            replacements.into_iter(),
        )
        .is_ok()
    );
    assert!(matches!(
        validate_replacement_windows(
            [
                (hook.analysis.patch_address, hook.analysis.original.len()),
                (0x2000, 4)
            ]
            .into_iter(),
            replacements.into_iter(),
        ),
        Err(Error::Conflict)
    ));
    let patch_end = hook.analysis.patch_address + hook.analysis.original.len();
    assert!(
        validate_replacement_windows(
            [
                (hook.analysis.patch_address, hook.analysis.original.len()),
                (0x2000, 4)
            ]
            .into_iter(),
            [0x3000, patch_end].into_iter(),
        )
        .is_ok()
    );
}

/// PrivateFileValidation keeps libc's `isdigit` text page inside its original private
/// file mapping for the complete install and removal.
#[test]
fn inline_private_file_validation_keeps_the_target_page_mapping_unchanged() {
    serialized(|| {
        if !forced_writes_supported() {
            return;
        }
        let target_entry = isdigit as *const ();
        let before = crate::read_self_maps().expect("maps");
        let page_size = crate::sys::page_size().unwrap();
        let page = target_entry as usize & !(page_size - 1);
        let file_map = before
            .iter()
            .find(|map| page >= map.start && page < map.end)
            .expect("libc text mapping");
        assert_ne!(
            file_map.inode, 0,
            "isdigit must start on a file-backed page"
        );
        let original_perms = file_map.perms;
        let published_page = read_backing_page(page).expect("readable libc page");

        let request = InlineHookRequest::new(target_entry, replacement as *const ())
            .require_private_file_pages();
        // SAFETY: the inline test lock keeps the complete target page
        // quiescent while installing and removing ABI-compatible functions.
        let mut hooks = install_batch(&[request]).expect("Validated inline installation failed");
        assert_eq!(hooks.len(), 1);
        let mut request = hooks.pop().expect("one installed inline handle");
        assert_eq!(
            request.private_file_validation(),
            crate::PrivateFileValidation::Validated
        );

        let during = crate::read_self_maps().expect("maps");
        let live = during
            .iter()
            .find(|map| page >= map.start && page < map.end)
            .expect("live target mapping");
        // The Validated page must keep its original file identity and
        // permissions for the complete install: PrivateFileValidation validates the
        // mapping and the patch write stays a private copy of it.
        assert!(
            live.perms
                .contains(crate::MapPerms::READ | crate::MapPerms::EXEC)
        );
        assert!(!live.perms.contains(crate::MapPerms::WRITE));
        assert_eq!(live.inode, file_map.inode);
        assert_eq!(live.device, file_map.device);
        let trampoline = request.original().expect("missing original trampoline");
        ORIGINAL.store(trampoline.expose_provenance(), Ordering::Release);
        assert_eq!(call(target_entry, -1), 10);
        assert_eq!(call(trampoline, -1), 0);

        // SAFETY: the calls above drained and the lock still holds.
        unhook_one(&mut request).expect("Validated inline removal failed");
        let after = crate::read_self_maps().expect("maps");
        let restored = after
            .iter()
            .find(|map| page >= map.start && page < map.end)
            .expect("restored target mapping");
        assert_eq!(restored.inode, file_map.inode);
        assert_eq!(restored.device, file_map.device);
        assert_eq!(restored.perms, original_perms);
        ORIGINAL.store(0, Ordering::Release);
        assert_eq!(call(target_entry, -1), 0);

        // PrivateFileValidation is a promise about the backing file, so the on-disk
        // bytes have to survive the complete install and removal window.
        let file_page = read_backing_page(page).expect("readable libc page");
        assert_ne!(
            file_page, [0_u8; 4],
            "the backing-file check did not read executable bytes"
        );
        assert_ne!(
            file_page, [0_u8; 4],
            "the libc text page should hold executable code"
        );
        assert_eq!(
            file_page, published_page,
            "the install changed the backing file's bytes"
        );
    });
}

/// Android marks some 4 KiB executable mappings with page-size-migration
/// padding metadata. PrivateFileValidation must recognize that metadata as ordinary
/// rather than rejecting the mapping as unknown.
#[test]
fn inline_private_file_validation_accepts_android_padding_metadata() {
    serialized(|| {
        if !forced_writes_supported() {
            return;
        }
        // The lgammaf page contains only Bessel and gamma functions, so
        // the parallel test harness does not execute it while this test
        // holds the inline mutation lock.
        let target_entry = lgammaf as *const ();
        let request = InlineHookRequest::new(target_entry, padded_replacement as *const ())
            .require_private_file_pages();
        // SAFETY: the inline test lock keeps the complete target page
        // quiescent while installing and removing ABI-compatible functions.
        let mut hooks = install_batch(std::slice::from_ref(&request))
            .expect("padded PrivateFileValidation failed");
        let mut request = hooks.pop().expect("one installed inline handle");
        assert_eq!(
            request.private_file_validation(),
            crate::PrivateFileValidation::Validated
        );
        let original = request.original().expect("missing original trampoline");
        PADDED_ORIGINAL.store(original.expose_provenance(), Ordering::Release);

        // SAFETY: the hook is installed and the test owns lgammaf's ABI.
        assert_eq!(unsafe { lgammaf(2.0) }, 1.0);
        // SAFETY: the trampoline has lgammaf's ABI and the input is
        // finite.
        let original = unsafe { std::mem::transmute::<*const (), Padded>(original) };
        // SAFETY: the trampoline accepts a finite float.
        assert_eq!(unsafe { original(2.0) }, 0.0);

        // SAFETY: the calls above drained and the lock still holds.
        unhook_one(&mut request).expect("padded PrivateFileValidation removal failed");
        PADDED_ORIGINAL.store(0, Ordering::Release);
        // SAFETY: the hook is removed and the test owns lgammaf's ABI.
        assert_eq!(unsafe { lgammaf(2.0) }, 0.0);
    });
}

#[test]
fn a_leaked_descriptor_after_a_published_mutation_still_reports_success() {
    // The forced path wrote, verified and flushed every byte before its
    // descriptor failed to close. The hooks are live at that point, so the
    // call must succeed: reporting failure makes the one-shot entry point
    // discard the batch and unmap the arenas the new entries branch into,
    // which turns a leaked descriptor into a crash at the next call.
    serialized(|| {
        if !forced_writes_supported() {
            return;
        }
        let target_entry = isdigit as *const ();
        patch::tests::fail_next_forced_close();
        // SAFETY: the inline test lock keeps this page quiescent and
        // excludes competing writers while the injection is armed.
        let request = InlineHookRequest::new(target_entry, replacement as *const ());
        let mut hooks = unsafe {
            // SAFETY: the inline test lock keeps this page quiescent
            // and excludes competing writers.
            install_inline_hooks(std::slice::from_ref(&request))
        }
        .expect("a descriptor close failure must not fail a published mutation")
        .into_handles();
        let mut request = hooks.pop().expect("one installed inline handle");
        let install_cleanup_status = request.install_cleanup_status();
        patch::tests::restore_forced_close_failure();
        assert!(matches!(
            install_cleanup_status,
            InlineInstallCleanupStatus::ForcedDescriptorCloseFailed(_)
        ));
        assert_eq!(request.install_mutation_path(), MutationPath::ForcedWrite);
        ORIGINAL.store(
            request
                .original()
                .expect("missing trampoline")
                .expose_provenance(),
            Ordering::Release,
        );
        // The hook is live, which is the whole point: the arenas it
        // branches into were not discarded.
        assert_eq!(call(target_entry, -5), 10);
        // SAFETY: the call above completed and no sibling inline test runs.
        unhook_one(&mut request).expect("removal failed");
        assert_eq!(call(target_entry, -5), 0);
    });
}

/// Reads the first four bytes the backing file holds for one mapped page.
///
/// This is the only view that can prove a Validated mutation never reached
/// the file: the mapping's own contents are the private copy by design.
/// Returns `None` when the mapping is anonymous or its file is unreadable,
/// so a caller can skip rather than assert on an unprovable page.
fn read_backing_page(page: usize) -> Option<[u8; 4]> {
    let maps = crate::read_self_maps().ok()?;
    let map = maps
        .iter()
        .find(|map| page >= map.start && page < map.end)?;
    if map.inode == 0 || map.device == crate::DeviceId::new(0, 0) {
        return None;
    }
    let path = map.path.as_deref()?;
    let offset = map
        .offset
        .checked_add(u64::try_from(page - map.start).ok()?)?;
    let mut file = std::fs::File::open(path).ok()?;
    use std::io::{Read, Seek, SeekFrom};
    file.seek(SeekFrom::Start(offset)).ok()?;
    let mut bytes = [0_u8; 4];
    file.read_exact(&mut bytes).ok()?;
    Some(bytes)
}

extern "C" fn same_page_first_replacement(_: i32) -> i32 {
    0x1111
}

extern "C" fn same_page_second_replacement(_: i32) -> i32 {
    0x2222
}

/// The installer's own patch has to reach instruction fetch: the entry must
/// hold the published branch and a call through the target must land in the
/// replacement. This is the acceptance test for whichever mutation channel
/// the platform allows.
#[test]
fn the_installed_entry_branch_is_executed() {
    serialized(|| {
        let fixture = PrivateExecPage::new().expect("private executable page");
        let target_entry = fixture.entry();
        let address = target_entry.expose_provenance();
        let request = InlineHookRequest::new(target_entry, replacement as *const ());
        // SAFETY: the inline test lock keeps the page quiescent.
        let mut hooks = install_batch(std::slice::from_ref(&request)).expect("installation failed");
        let mut request = hooks.pop().expect("one handle");
        let trampoline = request.original().expect("trampoline").expose_provenance();
        let code_address = arch::mapped_target(address).expect("mapped target");
        let trampoline_address = arch::mapped_target(trampoline).expect("mapped trampoline");
        let patch_address = crate::sys::decode_usize(request.patch_address);
        let expected = crate::sys::decode_bytes(&request.patch_bytes);
        // SAFETY: the entry and trampoline are live and readable.
        let (landing, published, trampoline_head) = unsafe {
            (
                std::ptr::read_unaligned(code_address as *const u32),
                std::slice::from_raw_parts(patch_address as *const u8, expected.len()).to_vec(),
                std::slice::from_raw_parts(trampoline_address as *const u8, 8).to_vec(),
            )
        };
        ORIGINAL.store(trampoline, Ordering::Release);
        let called = call(target_entry, -1);
        let observed = format!(
            "address={address:#x} landing={landing:#x} patch_address={patch_address:#x} expected={expected:02x?} published={published:02x?} trampoline={trampoline:#x} head={trampoline_head:x?} path={:?} called={called}",
            request.install_mutation_path()
        );
        // SAFETY: no call is in flight.
        let removal = unhook_one(&mut request);
        assert_eq!(
            called, 11,
            "the published entry branch was not executed: {observed} removal={removal:?}"
        );
        removal.expect("entry-branch removal failed");
        assert_eq!(call(target_entry, -1), 1);
    });
}

#[test]
fn a_degraded_install_leaves_another_hook_on_the_same_page_intact() {
    // A failed permission restore must preserve both published hooks.
    serialized(|| {
        let fixture = PrivateExecPage::new().expect("private executable page");
        let page = fixture.address;
        let page_size = fixture.length;
        let first_entry = fixture.entry();
        let second_entry = std::ptr::with_exposed_provenance(page + 64);

        // SAFETY: the inline test lock keeps the shared page quiescent
        // and excludes competing writers.
        let first_request =
            InlineHookRequest::new(first_entry, same_page_first_replacement as *const ());
        // SAFETY: the inline test lock keeps the shared page quiescent.
        let mut firsts =
            install_batch(std::slice::from_ref(&first_request)).expect("first installation failed");
        let mut first = firsts.pop().expect("one installed inline handle");
        assert_eq!(
            first.private_file_validation(),
            crate::PrivateFileValidation::Unvalidated
        );
        let first_installed = call(first_entry, 7);
        assert_eq!(first_installed, 0x1111);

        patch::tests::fail_next_forced_unavailable();
        // The forced-unavailable fallback keeps the shared page
        // executable and opens it writable; refuse only the restore that
        // would close that window.
        crate::sys::tests::deny_protect_restore_pages([page, 0]);
        let second_request =
            InlineHookRequest::new(second_entry, same_page_second_replacement as *const ());
        let result = unsafe {
            // SAFETY: the shared page is quiescent under the test lock.
            install_inline_hooks(std::slice::from_ref(&second_request))
        };
        crate::sys::tests::deny_protect_restore_pages([0, 0]);
        // Read the one-shot injection state before restoring it: the
        // restore clears the flag, so checking afterwards proves nothing.
        let injection_reached = !patch::tests::forced_unavailable_failure_pending();
        patch::tests::restore_forced_unavailable_failure();
        assert!(
            injection_reached,
            "the unavailable injection was never reached; the injection point moved"
        );
        let mut seconds = result
            .expect("the executable hook remains installed")
            .into_handles();
        let mut second = seconds.pop().expect("one installed inline handle");
        assert!(matches!(
            second.install_cleanup_status(),
            InlineInstallCleanupStatus::PagesMayBeWritable { pages, .. }
                if pages.len() == 1 && pages[0].address == page
        ));
        // SAFETY: this test owns the page and no target is executing under the lock.
        unsafe { crate::sys::protect(page, page_size, libc::PROT_READ | libc::PROT_EXEC) }
            .expect("restore executable page protection");

        assert!(first.is_installed());
        assert_eq!(
            call(first_entry, 7),
            0x1111,
            "the degraded installation reverted the first request's bytes"
        );
        assert!(second.is_installed());
        assert_eq!(call(second_entry, 7), 0x2222);

        // SAFETY: every call above completed and the lock still holds.
        unsafe {
            second.unhook().expect("second removal failed");
            first.unhook().expect("first removal failed");
        }
        assert_eq!(call(first_entry, 7), 1);
        assert_eq!(call(second_entry, 7), 1);
    });
}

#[test]
fn a_refused_protection_restore_does_not_reject_other_live_pages() {
    serialized(|| {
        if real_exec_restore_denied() {
            return;
        }
        let page_size = crate::sys::page_size().unwrap();
        let first = PrivateExecPage::new().expect("first executable page");
        let second = PrivateExecPage::new().expect("second executable page");
        crate::sys::tests::deny_exec_protect_page(first.address);
        let refused_request =
            InlineHookRequest::new(first.entry(), same_page_first_replacement as *const ())
                .with_mutation_path(MutationPath::DropExec);
        let refused = install_one(&refused_request);
        crate::sys::tests::deny_exec_protect_page(0);
        assert!(
            matches!(refused, Err(Error::TargetPageProtectionLost { address, .. }) if address == first.address),
            "unexpected first installation result"
        );
        assert!(install_one(&refused_request).is_err());

        let pinned_request =
            InlineHookRequest::new(second.entry(), same_page_first_replacement as *const ())
                .with_mutation_path(MutationPath::DropExec);
        let mut hook = install_one(&pinned_request).expect("independent page installation");
        assert_eq!(hook.install_mutation_path(), MutationPath::DropExec);
        assert_eq!(call(second.entry(), 7), 0x1111);
        assert_eq!(call(hook.original().unwrap(), 7), 1);
        unhook_one(&mut hook).unwrap();
        assert_eq!(call(second.entry(), 7), 1);

        // SAFETY: the first fixture owns the complete quiescent page.
        unsafe { crate::sys::protect(first.address, page_size, libc::PROT_READ | libc::PROT_EXEC) }
            .unwrap();
        let mut repaired = install_one(&refused_request).expect("repaired page installation");
        assert_eq!(call(first.entry(), 7), 0x1111);
        assert_eq!(call(repaired.original().unwrap(), 7), 1);
        unhook_one(&mut repaired).unwrap();
        assert_eq!(call(first.entry(), 7), 1);
    });
}

#[test]
fn an_undone_removal_does_not_claim_the_target_was_restored() {
    // A forced removal whose write fails is rolled back by writing the
    // patch bytes again -- the hook is still installed. If the descriptor
    // then fails to close, the error must not be `InlineCleanupPending`:
    // that variant is documented as "the target is restored, only arenas
    // remain", and a caller acting on it would drop a live request believing
    // it was gone.
    serialized(|| {
        if !forced_writes_supported() {
            return;
        }
        let target_entry = isdigit as *const ();
        // SAFETY: the inline test lock keeps the complete target page
        // quiescent and excludes competing writers.
        let mut request = (unsafe { install_inline_hook(target_entry, replacement as *const ()) })
            .expect("forced installation failed");
        assert_eq!(request.install_mutation_path(), MutationPath::ForcedWrite);
        ORIGINAL.store(
            request
                .original()
                .expect("missing trampoline")
                .expose_provenance(),
            Ordering::Release,
        );
        assert_eq!(call(target_entry, -5), 10);

        patch::tests::fail_next_forced_write();
        patch::tests::fail_next_forced_close();
        // SAFETY: the call above completed and the lock still holds.
        let error =
            unhook_one(&mut request).expect_err("the injected write failure aborts removal");
        patch::tests::restore_forced_write_failure();
        patch::tests::restore_forced_close_failure();
        assert!(
            matches!(error, Error::ForcedMutationRolledBackWithCloseError),
            "an undone removal must not report a restored target: {error:?}"
        );

        // The rollback put the patch bytes back, so the hook is still live
        // and the handle says so. Both must agree.
        assert!(request.is_installed());
        assert_eq!(call(target_entry, -5), 10);

        // And the removal is genuinely retryable.
        // SAFETY: the call above completed and the lock still holds.
        unhook_one(&mut request).expect("retrying the removal failed");
        assert!(!request.is_installed());
        assert_eq!(call(target_entry, -5), 0);
    });
}

#[test]
fn stuck_page_protection_is_reported_instead_of_terminating() {
    // A policy that lets a page drop PROT_EXEC but refuses to grant it back
    // once the page has been written -- an SELinux domain without
    // `execmod` -- used to terminate the process from the rollback path on
    // every inline installation. The rollback now puts the bytes back and
    // reports the page it could not close, as an error the caller can act
    // on. The target page is left non-executable until this test puts it
    // back.
    serialized(|| {
        if !forced_writes_supported() {
            return;
        }
        let Some(page) = PrivateExecPage::new() else {
            return;
        };
        let target_entry = page.entry();
        let page_size = crate::sys::page_size().unwrap();
        let page = crate::sys::page_start(target_entry.expose_provenance(), page_size);

        patch::tests::fail_next_forced_unavailable();
        crate::sys::tests::deny_exec_protect_page(page);
        // SAFETY: the inline test lock keeps the complete target page
        // quiescent and excludes competing writers and loader changes.
        let request = InlineHookRequest::new(target_entry, replacement as *const ())
            .with_mutation_path(MutationPath::DropExec);
        let result = install_batch(std::slice::from_ref(&request));
        crate::sys::tests::deny_exec_protect_page(0);
        patch::tests::restore_forced_unavailable_failure();
        let Err(error) = result else {
            panic!("installation succeeded while PROT_EXEC was refused");
        };

        match error {
            Error::TargetPageProtectionLost {
                address, length, ..
            } => {
                assert_eq!(address, page);
                assert_eq!(length, page_size);
            }
            other => panic!("unexpected error: {other:?}"),
        }

        // Real kernels can enforce the same policy the injection models:
        // once the target page has been written, restoring PROT_EXEC is
        // refused for good. If this process cannot re-elevate the page,
        // the assertions above already covered the reported error; stop
        // before an instruction fetch would fault.
        let restored = unsafe {
            // SAFETY: this test owns the stuck page and no target is
            // executing while the lock is held.
            crate::sys::protect_checked(page, page_size, libc::PROT_READ | libc::PROT_EXEC)
        };
        if restored.is_some() {
            reset_test_state();
            return;
        }
        assert_eq!(call(target_entry, -1), 1);
    });
}

#[test]
fn installs_and_removes_without_any_mprotect() {
    // The forced-access pipeline maps arenas with their final protection
    // and writes target bytes through /proc/self/mem, so a process that
    // rejects every mprotect on the target page can still install and
    // remove an inline request.
    // The whole target page stays quiescent under the inline test lock.
    serialized(|| {
        if !forced_writes_supported() {
            return;
        }
        let target_entry = isdigit as *const ();
        fn omhook_descriptors() -> usize {
            std::fs::read_dir("/proc/self/fd")
                .map(|entries| {
                    entries
                        .filter_map(|entry| entry.ok())
                        .filter(|entry| {
                            std::fs::read_link(entry.path()).is_ok_and(|path| {
                                let path = path.to_string_lossy();
                                path.starts_with("/proc/") && path.ends_with("/mem")
                            })
                        })
                        .count()
                })
                .unwrap_or_else(|_| crate::sys::fail_stop())
        }
        fn mapping_count() -> usize {
            crate::read_self_maps()
                .map(|maps| {
                    maps.iter()
                        // Count only anonymous executable mappings: every
                        // arena this lifecycle maps is anonymous and
                        // executable, while the process allocator freely
                        // splits and extends its own named heap VMAs.
                        .filter(|map| {
                            map.perms.contains(crate::maps::MapPerms::EXEC) && map.path.is_none()
                        })
                        .count()
                })
                .unwrap_or_else(|_| crate::sys::fail_stop())
        }
        // The first forced placement can split an existing anonymous VMA
        // when its arena merges with a neighbor; that bounded split is not
        // a leak. Warm it up before taking the stable resource baseline.
        let warmup_request = InlineHookRequest::new(target_entry, replacement as *const ());
        let mut warmups = install_batch(std::slice::from_ref(&warmup_request))
            .expect("forced inline installation requires no mprotect");
        let mut warmup = warmups.pop().expect("one installed inline handle");
        // The caller can tell that the target page kept PROT_EXEC for the
        // whole write, so the fault that normally catches a thread entering
        // the range never existed for this installation.
        assert_eq!(warmup.install_mutation_path(), MutationPath::ForcedWrite);
        ORIGINAL.store(
            warmup
                .original()
                .expect("missing forced warm-up trampoline")
                .expose_provenance(),
            Ordering::Release,
        );
        assert_eq!(call(target_entry, -5), 10);
        // SAFETY: the warm-up call completed and the lock still holds.
        unsafe { warmup.unhook().expect("forced warm-up removal failed") };
        assert_eq!(call(target_entry, -5), 0);
        let fds_baseline = omhook_descriptors();
        let mappings_before = mapping_count();
        for _ in 0..32 {
            // SAFETY: the lock excludes target execution and competing
            // writers for every complete lifecycle.
            let mut hooks = install_batch(std::slice::from_ref(&warmup_request))
                .expect("forced inline installation requires no mprotect");
            let mut request = hooks.pop().expect("one installed inline handle");
            ORIGINAL.store(
                request
                    .original()
                    .expect("missing forced trampoline")
                    .expose_provenance(),
                Ordering::Release,
            );
            assert_eq!(call(target_entry, -5), 10);

            // SAFETY: the forced call completed and the lock still holds.
            unhook_one(&mut request).expect("forced removal requires no mprotect");
            assert_eq!(call(target_entry, -5), 0);
        }
        let fds_after = omhook_descriptors();
        let mappings_after = mapping_count();
        assert!(
            fds_after <= fds_baseline,
            "forced lifecycle leaked descriptors: {fds_baseline} -> {fds_after}"
        );
        assert!(
            mappings_after <= mappings_before,
            "forced lifecycle leaked mappings: {mappings_before} -> {mappings_after}"
        );
    });
}

#[test]
fn installs_and_removes_when_forced_writes_are_denied() {
    // The permission-changing path is independent of `/proc/self/mem`, so
    // rejecting writes to that file cannot affect a normal installation.
    serialized(|| {
        if real_exec_restore_denied() {
            // The fallback would strand the shared page.
            return;
        }
        let target_entry = isdigit as *const ();
        // Refuse the forced channel for this install only. The default
        // request must degrade to page elevation instead of failing, which
        // is what a process whose own policy blocks /proc/self/mem sees.
        patch::tests::fail_next_forced_unavailable();
        // SAFETY: the inline test lock excludes target execution and
        // competing writers for the complete lifecycle.
        let mut request = unsafe { install_inline_hook(target_entry, replacement as *const ()) }
            .expect("denied forced writes must fall back to page elevation");
        assert_eq!(request.install_mutation_path(), MutationPath::KeepExec);
        ORIGINAL.store(
            request
                .original()
                .expect("missing fallback trampoline")
                .expose_provenance(),
            Ordering::Release,
        );
        assert_eq!(call(target_entry, -6), 10);

        // SAFETY: the fallback call completed and the lock still holds.
        unhook_one(&mut request).expect("fallback removal failed");
        assert_eq!(call(target_entry, -6), 0);
    });
}

#[test]
fn execmod_denial_uses_the_executable_fallback() {
    // The reported Android failure: `/proc/self/mem` is unavailable and a
    // file-backed private page that drops `PROT_EXEC` cannot get it back.
    // Adding `PROT_WRITE` without removing `PROT_EXEC` never requests that
    // re-grant, so the target page stays callable throughout.
    serialized(|| {
        if !forced_writes_supported() {
            return;
        }
        let target_entry = isdigit as *const ();
        let page_size = crate::sys::page_size().unwrap();
        let page = crate::sys::page_start(target_entry as usize, page_size);
        crate::sys::tests::deny_exec_regrant(page, libc::PROT_READ | libc::PROT_EXEC);
        patch::tests::fail_next_forced_unavailable();
        // SAFETY: the inline test lock keeps this page quiescent and
        // excludes competing writers for the complete lifecycle.
        let mut request = unsafe { install_inline_hook(target_entry, replacement as *const ()) }
            .expect("execmod denial must not strand the target page");
        crate::sys::tests::restore_exec_regrant();
        patch::tests::restore_forced_unavailable_failure();
        assert_eq!(request.install_mutation_path(), MutationPath::KeepExec);
        ORIGINAL.store(
            request
                .original()
                .expect("missing trampoline")
                .expose_provenance(),
            Ordering::Release,
        );
        assert_eq!(call(target_entry, -6), 10);

        // SAFETY: the call above completed and the lock still holds.
        unhook_one(&mut request).expect("fallback removal failed");
        assert_eq!(call(target_entry, -6), 0);
    });
}

#[test]
fn a_restore_failure_reports_live_writable_pages() {
    serialized(|| {
        if !forced_writes_supported() {
            return;
        }
        let target_entry = isdigit as *const ();
        let page_size = crate::sys::page_size().unwrap();
        let page = crate::sys::page_start(target_entry as usize, page_size);
        crate::sys::tests::deny_protect_restore_pages([page, 0]);
        let request = InlineHookRequest::new(target_entry, replacement as *const ())
            .with_mutation_path(MutationPath::KeepExec);
        // SAFETY: the inline test lock keeps this page quiescent and
        // excludes competing writers for the complete lifecycle.
        let mut hooks = install_batch(std::slice::from_ref(&request))
            .expect("a live request must not be discarded for a restore failure");
        let mut request = hooks.pop().expect("one installed inline handle");
        let install_cleanup_status = request.install_cleanup_status();
        assert_eq!(request.install_mutation_path(), MutationPath::KeepExec);
        assert!(
            matches!(
                &install_cleanup_status,
                InlineInstallCleanupStatus::PagesMayBeWritable {
                    pages,
                    source,
                } if pages.len() == 1
                    && pages[0].address == page
                    && pages[0].length == page_size
                    && pages[0].protection & (libc::PROT_READ | libc::PROT_EXEC | libc::PROT_WRITE)
                        == libc::PROT_READ | libc::PROT_EXEC
                    && *source == syscalls::Errno::EACCES
            ),
            "unexpected install_cleanup_status"
        );
        ORIGINAL.store(
            request
                .original()
                .expect("missing trampoline")
                .expose_provenance(),
            Ordering::Release,
        );
        assert_eq!(call(target_entry, -6), 10);

        // SAFETY: the call above completed and the lock still holds.
        let error = unhook_one(&mut request).expect_err("the page remains writable");
        assert!(
            matches!(
                &error,
                Error::TargetPagesMayBeWritable {
                    pages,
                    rolled_back: false,
                    source,
                } if pages.len() == 1
                    && pages[0].address == page
                    && pages[0].length == page_size
                    && pages[0].protection & (libc::PROT_READ | libc::PROT_EXEC | libc::PROT_WRITE)
                        == libc::PROT_READ | libc::PROT_EXEC
                    && *source == syscalls::Errno::EACCES
            ),
            "unexpected error: {error:?}"
        );
        assert!(!request.is_installed());
        assert_eq!(call(target_entry, -6), 0);

        crate::sys::tests::restore_next_protect();
        // SAFETY: this test owns the still-live page and the target is
        // restored; put its protection back before releasing the lock.
        assert!(
            unsafe {
                // SAFETY: this test owns the page and the target is
                // restored.
                crate::sys::protect_checked(page, page_size, libc::PROT_READ | libc::PROT_EXEC)
            }
            .is_none()
        );
    });
}

#[cfg(target_arch = "aarch64")]
#[test]
fn successful_forced_mutations_validate_relay_bti_once() {
    serialized(|| {
        if !forced_writes_supported() {
            return;
        }
        crate::maps::reset_smaps_reads();
        let target_entry = isdigit as *const ();
        // SAFETY: the inline test lock keeps this page quiescent and
        // excludes competing writers for the complete lifecycle.
        let mut request = unsafe { install_inline_hook(target_entry, replacement as *const ()) }
            .expect("forced installation failed");
        assert_eq!(request.install_mutation_path(), MutationPath::ForcedWrite);
        ORIGINAL.store(
            request
                .original()
                .expect("missing trampoline")
                .expose_provenance(),
            Ordering::Release,
        );
        assert_eq!(call(target_entry, -6), 10);
        // SAFETY: the call above completed and the lock still holds.
        unhook_one(&mut request).expect("forced removal failed");
        assert_eq!(crate::maps::smaps_reads(), 1);
        assert_eq!(call(target_entry, -6), 0);
    });
}

#[cfg(target_arch = "aarch64")]
#[test]
fn direct_forced_hooks_do_not_read_smaps() {
    serialized(|| {
        if !forced_writes_supported() {
            return;
        }
        let target_entry = isdigit as *const ();
        crate::maps::reset_smaps_reads();
        let request = InlineHookRequest::new(target_entry, replacement as *const ());
        let mut request = install_one(&request).expect("direct forced installation failed");
        let trampoline = request.original().expect("missing original trampoline");
        ORIGINAL.store(trampoline.expose_provenance(), Ordering::Release);
        assert_eq!(call(target_entry, -1), 10);
        ORIGINAL.store(0, Ordering::Release);
        // SAFETY: the call above drained and the test still owns the page.
        unhook_one(&mut request).expect("direct forced removal failed");
        assert_eq!(call(target_entry, -1), 0);
        // A guarded libc entry needs its target flags before generation.
        // The invariant is that the direct path never reopens smaps after
        // that preflight.
        assert!(crate::maps::smaps_reads() <= 1);
    });
}

#[test]
fn default_installs_use_direct_arenas_when_forced_writes_work() {
    serialized(|| {
        if !forced_writes_supported() {
            return;
        }
        let target_entry = isdigit as *const ();
        // SAFETY: the inline test lock keeps this page quiescent and
        // excludes competing writers for the complete lifecycle.
        let mut request = unsafe { install_inline_hook(target_entry, replacement as *const ()) }
            .expect("default forced installation failed");
        assert!(request.arenas_direct());
        ORIGINAL.store(
            request
                .original()
                .expect("missing original trampoline")
                .expose_provenance(),
            Ordering::Release,
        );
        assert_eq!(call(target_entry, -6), 10);
        // SAFETY: the target and trampoline calls above have drained.
        unhook_one(&mut request).expect("direct arena removal failed");
        assert_eq!(call(target_entry, -6), 0);
    });
}

#[test]
fn reserved_arena_is_consumed_by_direct_forced_hooks() {
    serialized(|| {
        if !forced_writes_supported() {
            return;
        }
        let target_entry = isdigit as *const ();
        let page_size = crate::sys::page_size().unwrap();
        reserve_inline_arena_near(target_entry as usize, page_size)
            .expect("arena reservation failed");
        let ranges = arena::reserved_pool_ranges_for_tests();
        assert_eq!(ranges.len(), 1);
        let (pool_start, pool_end) = ranges[0];

        // SAFETY: the inline test lock keeps this page quiescent and
        // excludes competing writers for the complete lifecycle.
        let mut request = unsafe { install_inline_hook(target_entry, replacement as *const ()) }
            .expect("reserved direct installation failed");
        assert!(request.arenas_direct());
        let trampoline = request
            .original()
            .expect("missing reserved original trampoline");
        assert!((pool_start..pool_end).contains(&(trampoline as usize)));
        ORIGINAL.store(trampoline.expose_provenance(), Ordering::Release);
        assert_eq!(call(target_entry, -6), 10);

        // SAFETY: the target and trampoline calls above have drained.
        unhook_one(&mut request).expect("reserved direct removal failed");
        assert_eq!(call(target_entry, -6), 0);
    });
}

#[test]
fn an_unopenable_self_mem_falls_back_to_elevation() {
    // The reported failure: a process that cannot open /proc/self/mem at
    // all. The old code only recognised one `pwrite64` errno, so this
    // process got `UnsupportedFeature("forced-access mutation is
    // unavailable")` even though the elevation path was available and
    // permitted.
    serialized(|| {
        if real_exec_restore_denied() {
            return;
        }
        let target_entry = isdigit as *const ();
        // The direct arena and the target mutation each probe the file.
        crate::sys::tests::fail_next_self_mem_open_times(2);
        // SAFETY: the inline test lock excludes target execution and
        // competing writers for the complete lifecycle.
        let mut request = unsafe { install_inline_hook(target_entry, replacement as *const ()) }
            .expect("an unopenable /proc/self/mem must not fail the install");
        assert_eq!(request.install_mutation_path(), MutationPath::KeepExec);
        assert!(
            !crate::sys::tests::self_mem_open_failure_pending(),
            "the forced channel was never attempted, so the injection must stay armed"
        );
        ORIGINAL.store(
            request
                .original()
                .expect("missing fallback trampoline")
                .expose_provenance(),
            Ordering::Release,
        );
        assert_eq!(call(target_entry, -7), 10);
        // SAFETY: the fallback call completed and the lock still holds.
        unhook_one(&mut request).expect("fallback removal failed");
        assert_eq!(call(target_entry, -7), 0);
    });
}

#[cfg(target_arch = "aarch64")]
#[test]
fn executable_fallback_reads_protection_flags_once() {
    serialized(|| {
        if !crate::sys::aarch64_bti_supported() || real_exec_restore_denied() {
            return;
        }
        let target_entry = isdigit as *const ();
        crate::maps::reset_smaps_reads();
        patch::tests::fail_next_forced_unavailable();
        // SAFETY: the inline test lock keeps this page quiescent and
        // excludes competing writers for the complete lifecycle.
        let mut request = unsafe { install_inline_hook(target_entry, replacement as *const ()) }
            .expect("forced refusal must reach the executable fallback");
        assert_eq!(request.install_mutation_path(), MutationPath::KeepExec);
        assert_eq!(crate::maps::smaps_reads(), 1);
        ORIGINAL.store(
            request
                .original()
                .expect("missing trampoline")
                .expose_provenance(),
            Ordering::Release,
        );
        assert_eq!(call(target_entry, -7), 10);
        // SAFETY: the call above completed and the lock still holds.
        unhook_one(&mut request).expect("fallback removal failed");
        assert_eq!(call(target_entry, -7), 0);
    });
}

#[test]
fn a_protection_pinned_request_never_opens_self_mem() {
    serialized(|| {
        if real_exec_restore_denied() {
            return;
        }
        let Some(page) = PrivateExecPage::new() else {
            return;
        };
        let target_entry = page.entry();
        crate::sys::tests::fail_next_self_mem_open();
        let request = InlineHookRequest::new(target_entry, replacement as *const ())
            .with_mutation_path(MutationPath::DropExec);
        // SAFETY: the inline test lock excludes target execution and
        // competing writers for the complete lifecycle.
        let mut request = install_one(&request)
            .expect("a pinned elevation request must not depend on /proc/self/mem");
        assert_eq!(request.install_mutation_path(), MutationPath::DropExec);
        assert!(!request.arenas_direct());
        assert!(
            crate::sys::tests::self_mem_open_failure_pending(),
            "the pinned elevation path opened /proc/self/mem"
        );
        crate::sys::tests::restore_next_self_mem_open();
        ORIGINAL.store(
            request
                .original()
                .expect("missing trampoline")
                .expose_provenance(),
            Ordering::Release,
        );
        assert_eq!(call(target_entry, -8), 11);
        // SAFETY: the call above completed and the lock still holds.
        unhook_one(&mut request).expect("removal failed");
        assert_eq!(call(target_entry, -8), 1);
    });
}

#[test]
fn a_forced_pinned_request_reports_why_the_channel_is_unusable() {
    serialized(|| {
        let target_entry = isdigit as *const ();
        crate::sys::tests::fail_next_self_mem_open_times(2);
        let request = InlineHookRequest::new(target_entry, replacement as *const ())
            .with_mutation_path(MutationPath::ForcedWrite);
        // SAFETY: the inline test lock excludes target execution and
        // competing writers for the complete lifecycle.
        let error = install_one(&request)
            .err()
            .expect("a pinned forced path must not silently degrade");
        crate::sys::tests::restore_next_self_mem_open();
        match error {
            Error::MutationPathUnavailable {
                forced_access: Some(source),
                protection_keeping_exec: None,
                protection: None,
            } => {
                assert_eq!(crate::errno_code(source), libc::EPERM);
            }
            other => panic!("unexpected error: {other:?}"),
        }
        // The failing install left the target untouched.
        assert_eq!(call(target_entry, -9), 0);
    });
}

#[test]
fn default_forced_open_errno_is_preserved_for_fallback_reporting() {
    serialized(|| {
        crate::sys::tests::fail_next_self_mem_open();
        let (mem, errno) = forced_access_descriptor(None).expect("default request retries");
        assert_eq!(mem, None);
        assert_eq!(errno, Some(syscalls::Errno::EPERM));
    });
}

#[test]
fn conflicting_path_constraints_are_rejected_before_mutation() {
    serialized(|| {
        // A batch is mutated as one unit on one path, so it cannot honour both
        // constraints; the request is refused before any target byte changes.
        let first = InlineHookRequest::new(isdigit as *const (), replacement as *const ())
            .with_mutation_path(MutationPath::DropExec);
        let second =
            InlineHookRequest::new(prepared_replacement as *const (), replacement as *const ())
                .with_mutation_path(MutationPath::ForcedWrite);
        // SAFETY: the batch is rejected during preflight, so neither target is
        // analysed, patched, or called.
        let error = install_batch(&[first, second])
            .err()
            .expect("a batch that pins both paths cannot be satisfied");
        assert!(
            matches!(
                error,
                Error::InvalidInlineTarget("conflicting mutation path constraints")
            ),
            "unexpected error: {error:?}"
        );
        assert_eq!(call(isdigit as *const (), -3), 0);
    });
}

#[test]
fn removal_honours_the_pinned_path() {
    // A handle that forbade the non-executable window must not take it on
    // the way out either.
    serialized(|| {
        if !forced_writes_supported() {
            return;
        }
        let target_entry = isdigit as *const ();
        let request = InlineHookRequest::new(target_entry, replacement as *const ())
            .with_mutation_path(MutationPath::ForcedWrite);
        // SAFETY: the inline test lock excludes target execution and
        // competing writers for the complete lifecycle.
        let mut request =
            install_one(&request).expect("the forced channel is available in this process");
        assert_eq!(request.install_mutation_path(), MutationPath::ForcedWrite);
        ORIGINAL.store(
            request
                .original()
                .expect("missing trampoline")
                .expose_provenance(),
            Ordering::Release,
        );
        assert_eq!(call(target_entry, -4), 10);

        crate::sys::tests::fail_next_self_mem_open();
        // SAFETY: the call above completed and the lock still holds.
        let error = unhook_one(&mut request).expect_err("the pinned path is unusable");
        crate::sys::tests::restore_next_self_mem_open();
        assert!(
            matches!(
                error,
                Error::MutationPathUnavailable {
                    forced_access: Some(_),
                    ..
                }
            ),
            "unexpected error: {error:?}"
        );
        assert!(
            request.is_installed(),
            "a refused removal must leave the request"
        );
        assert_eq!(call(target_entry, -4), 10);

        // SAFETY: the pinned path is usable again and no call is in flight.
        unhook_one(&mut request).expect("retried removal failed");
        assert_eq!(call(target_entry, -4), 0);
    });
}

#[test]
fn unhook_falls_back_to_elevation_when_forced_access_is_unavailable() {
    // A process can lose /proc/self/mem access between installation and
    // removal (seccomp, domain transition). Removal must then take the
    // page-elevation path rather than leaving an installed request that can
    // never be removed.
    serialized(|| {
        if !forced_writes_supported() {
            return;
        }
        if real_exec_restore_denied() {
            // A domain that refuses to re-elevate a written page cannot
            // exercise the fallback end to end.
            return;
        }
        let target_entry = isdigit as *const ();
        // SAFETY: the inline test lock excludes target execution and
        // competing writers for the complete lifecycle.
        let mut request = unsafe { install_inline_hook(target_entry, replacement as *const ()) }
            .expect("installation on the forced path");
        assert_eq!(request.install_mutation_path(), MutationPath::ForcedWrite);
        ORIGINAL.store(
            request
                .original()
                .expect("missing original trampoline")
                .expose_provenance(),
            Ordering::Release,
        );
        assert_eq!(call(target_entry, -6), 10);

        // SAFETY: the fallback call completed and the lock still holds.
        patch::tests::fail_next_forced_unavailable();
        unhook_one(&mut request).expect("unhook must fall back to page elevation");
        assert!(!patch::tests::forced_unavailable_failure_pending());
        assert_eq!(call(target_entry, -6), 0);
    });
}

#[test]
fn rejects_chained_hooks_and_allows_removal_then_reinstall() {
    // The inline test lock provides whole-page quiescence.
    serialized(|| {
        if !forced_writes_supported() {
            return;
        }
        let target_entry = isdigit as *const ();
        // SAFETY: the lock excludes target execution and competing
        // mutation while installing and removing ABI-compatible functions.
        let mut first = unsafe { install_inline_hook(target_entry, replacement as *const ()) }
            .expect("first inline request installation failed");
        ORIGINAL.store(
            first
                .original()
                .expect("missing original trampoline")
                .expose_provenance(),
            Ordering::Release,
        );

        // SAFETY: the second request names the same target with a
        // different replacement; the registry must reject chaining before
        // any change.
        assert!(matches!(
            unsafe {
                // SAFETY: the second request is rejected before mutation.
                install_inline_hook(target_entry, prepared_replacement as *const ())
            },
            Err(Error::Conflict)
        ));
        assert!(first.is_installed());
        assert_eq!(call(target_entry, -3), 10);

        // SAFETY: all calls above completed and the lock still holds.
        unhook_one(&mut first).expect("first removal failed");
        assert_eq!(call(target_entry, -3), 0);

        // SAFETY: removal restored the entry bytes, so the target is
        // hookable again through an independent handle.
        let mut second =
            unsafe { install_inline_hook(target_entry, prepared_replacement as *const ()) }
                .expect("reinstalling the removed target failed");
        PREPARED_ORIGINAL.store(
            second
                .original()
                .expect("missing retry trampoline")
                .expose_provenance(),
            Ordering::Release,
        );
        assert_eq!(call(target_entry, -4), 10);

        // SAFETY: the retried request's calls have drained.
        unsafe { second.unhook().expect("second removal failed") };
        assert_eq!(call(target_entry, -4), 0);
    });
}

#[test]
fn prepared_trampolines_sync_before_publication_and_retry_after_failure() {
    serialized(|| {
        let page = PrivateExecPage::new().expect("target page allocation failed");
        let lifecycle = std::sync::RwLock::new(());
        // SAFETY: the test owns the target mapping and excludes loader changes.
        let lease = unsafe { crate::LifecycleReadLease::acquire(&lifecycle) }.unwrap();
        let requests = [
            InlineHookRequest::new(page.entry(), prepared_replacement as *const ()),
            InlineHookRequest::new(
                std::ptr::with_exposed_provenance(page.address + 64),
                prepared_replacement as *const (),
            ),
        ];
        for count in [1, 2] {
            assert!(!crate::sys::tests::FAIL_NEXT_SYNC.swap(true, Ordering::AcqRel));
            // SAFETY: all entries remain mapped, ABI-compatible and quiescent.
            let error = match unsafe { lease.prepare_inline_hooks(&requests[..count]) } {
                Ok(prepared) => {
                    // SAFETY: no trampoline has been published or called.
                    unsafe { prepared.discard() }.unwrap();
                    panic!("preparation ignored an instruction synchronization failure");
                }
                Err(error) => error,
            };
            assert!(matches!(
                error,
                Error::SystemCall {
                    operation: "membarrier",
                    source: syscalls::Errno::ENOMEM,
                }
            ));
            for offset in [0, 64] {
                // SAFETY: preparation never modifies this owned readable page.
                let bytes = unsafe {
                    std::slice::from_raw_parts(
                        (page.address + offset) as *const u8,
                        PrivateExecPage::CODE.len(),
                    )
                };
                assert_eq!(bytes, PrivateExecPage::CODE);
            }
            // SAFETY: failed preparation left the same live target unchanged.
            let prepared = unsafe { lease.prepare_inline_hooks(&requests[..count]) }.unwrap();
            for index in 0..count {
                assert_eq!(call(prepared.trampoline(index).unwrap(), 7), 1);
            }
            // SAFETY: every pre-commit trampoline call has completed.
            unsafe { prepared.discard() }.unwrap();
            assert_eq!(call(page.entry(), 7), 1);
        }
    });
}

#[test]
fn prepared_batches_serialize_commit_and_retain_retryable_ownership() {
    // The commit and both removals drop PROT_EXEC from libc's complete isdigit
    // page; the inline test lock supplies the required quiescence. The
    // libc target page also cannot contain this crate's mutation code,
    // which would make the installer fault on its own pages.
    serialized(|| {
        if !forced_writes_supported() {
            return;
        }
        let lifecycle = std::sync::RwLock::new(());
        // SAFETY: this test uses the same lock for its complete synthetic
        // lifecycle and performs no loader transition while the lease is
        // live.
        let lease = unsafe { crate::LifecycleReadLease::acquire(&lifecycle) }.unwrap();
        let request =
            InlineHookRequest::new(isdigit as *const (), prepared_replacement as *const ());
        // SAFETY: the target is quiescent and both entries remain live and
        // ABI-compatible through commit, calls, and removal.
        let first = unsafe { lease.prepare_inline_hooks(std::slice::from_ref(&request)) }.unwrap();
        // SAFETY: a shared prepare phase changes no target bytes, so a
        // second prepared candidate can coexist under the same lifecycle
        // generation.
        let second = unsafe { lease.prepare_inline_hooks(std::slice::from_ref(&request)) }.unwrap();
        let first_original = first.trampoline(0).unwrap();
        let second_original = second.trampoline(0).unwrap();

        // SAFETY: the target remains quiescent for serialized commit.
        let mut installed = unsafe { first.commit() }.unwrap().into_handles();
        let mut request = installed.pop().unwrap();
        assert!(installed.is_empty());
        // SAFETY: the first commit changed the expected target bytes, so
        // the second commit must roll back and retain its unpublished
        // arenas.
        let error = match unsafe { second.commit() } {
            Ok(_) => panic!("second prepared commit unexpectedly succeeded"),
            Err(error) => error,
        };
        assert!(matches!(error.error(), Error::Conflict));
        let (_, second) = error.into_parts();

        PREPARED_ORIGINAL.store(first_original.expose_provenance(), Ordering::Release);
        assert_eq!(call(isdigit as *const (), -2), 10);
        // SAFETY: all calls drained and the same lifecycle lease remains
        // live.
        unsafe { lease.unhook(&mut request) }.unwrap();
        assert_eq!(call(isdigit as *const (), -2), 0);

        // SAFETY: removal restored the expected bytes and the same
        // lifecycle generation remains stable and quiescent for retry.
        let mut retried = unsafe { second.commit() }.unwrap().into_handles();
        let mut retried = retried.pop().unwrap();
        PREPARED_ORIGINAL.store(second_original.expose_provenance(), Ordering::Release);
        assert_eq!(call(isdigit as *const (), -2), 10);
        // SAFETY: the retried target and trampoline calls have drained.
        unsafe { lease.unhook(&mut retried) }.unwrap();
        PREPARED_ORIGINAL.store(0, Ordering::Release);
        assert_eq!(call(isdigit as *const (), -2), 0);
    });
}

#[test]
fn writable_batch_reports_every_involved_page_without_stale_handles() {
    serialized(|| {
        let fixtures: [PrivateExecPage; 4] =
            std::array::from_fn(|_| PrivateExecPage::new().expect("private executable page"));
        let inactive_request = InlineHookRequest::new(
            fixtures[3].entry(),
            same_page_first_replacement as *const (),
        )
        .with_mutation_path(MutationPath::KeepExec);
        let mut inactive = install_one(&inactive_request).unwrap();
        unhook_one(&mut inactive).unwrap();
        let targets = [
            fixtures[0].entry(),
            std::ptr::with_exposed_provenance(fixtures[0].address + 64),
            fixtures[1].entry(),
            fixtures[2].entry(),
        ];
        let requests = targets.map(|target| {
            InlineHookRequest::new(target, same_page_first_replacement as *const ())
                .with_mutation_path(MutationPath::KeepExec)
        });
        crate::sys::tests::deny_protect_restore_pages([fixtures[0].address, fixtures[2].address]);
        let mut hooks = install_batch(&requests).unwrap();
        let InlineInstallCleanupStatus::PagesMayBeWritable { pages, source } =
            hooks[0].install_cleanup_status()
        else {
            panic!("batch restore failure was not reported");
        };
        assert_eq!(source, syscalls::Errno::EACCES);
        assert_eq!(pages.len(), 3);
        for fixture in &fixtures[..3] {
            let page = pages
                .iter()
                .find(|page| page.address == fixture.address)
                .unwrap();
            assert_eq!(page.length, fixture.length);
            assert_eq!(page.protection, libc::PROT_READ | libc::PROT_EXEC);
        }
        for (hook, target) in hooks.iter().zip(targets) {
            let InlineInstallCleanupStatus::PagesMayBeWritable { pages: shared, .. } =
                hook.install_cleanup_status()
            else {
                panic!("a batch handle lost the complete report");
            };
            assert!(Arc::ptr_eq(&pages, &shared));
            assert_eq!(call(target, 7), 0x1111);
            assert_eq!(call(hook.original().unwrap(), 7), 1);
        }
        let maps = crate::read_self_maps().unwrap();
        for (index, fixture) in fixtures[..3].iter().enumerate() {
            let map =
                crate::maps::find_map_containing(&maps, fixture.address, fixture.length).unwrap();
            assert_eq!(map.perms.contains(crate::MapPerms::WRITE), index != 1);
        }
        hooks.push(inactive);
        // SAFETY: the fixtures remain live and every target call has drained.
        let error = unsafe { unhook_inline_hooks(&mut hooks) }.unwrap_err();
        let Error::TargetPagesMayBeWritable {
            pages: removal_pages,
            rolled_back: false,
            source: syscalls::Errno::EACCES,
        } = error
        else {
            panic!("completed removal lost its protection report");
        };
        assert_eq!(removal_pages, pages);
        assert!(hooks.iter().all(|hook| !hook.is_installed()));
        for target in targets {
            assert_eq!(call(target, 7), 1);
        }
        crate::sys::tests::restore_next_protect();
        for page in pages.iter() {
            // SAFETY: the report names only the owned, quiescent fixture pages.
            unsafe { crate::sys::protect(page.address, page.length, page.protection) }.unwrap();
        }
        let maps = crate::read_self_maps().unwrap();
        for page in pages.iter() {
            assert!(
                !crate::maps::find_map_containing(&maps, page.address, page.length)
                    .unwrap()
                    .perms
                    .contains(crate::MapPerms::WRITE)
            );
        }
        // SAFETY: all calls drained; these handles now require no further mutation.
        unsafe { unhook_inline_hooks(&mut hooks) }.unwrap();
    });
}

#[test]
fn keeping_exec_rollback_retains_complete_protection_and_retry_state() {
    serialized(|| {
        let fixtures: [PrivateExecPage; 2] =
            std::array::from_fn(|_| PrivateExecPage::new().expect("private executable page"));
        let lifecycle = std::sync::RwLock::new(());
        // SAFETY: the test owns both mappings and excludes loader changes.
        let lease = unsafe { crate::LifecycleReadLease::acquire(&lifecycle) }.unwrap();
        for pinned in [true, false] {
            let requests = fixtures.each_ref().map(|fixture| {
                let request = InlineHookRequest::new(
                    fixture.entry(),
                    same_page_first_replacement as *const (),
                );
                if pinned {
                    request.with_mutation_path(MutationPath::KeepExec)
                } else {
                    request
                }
            });
            // SAFETY: the owned entries remain live, ABI-compatible and quiescent.
            let prepared = unsafe { lease.prepare_inline_hooks(&requests) }.unwrap();
            crate::sys::tests::deny_protect_restore_pages([
                fixtures[0].address,
                fixtures[1].address,
            ]);
            if !pinned {
                patch::tests::fail_next_forced_unavailable();
            }
            assert!(!crate::sys::tests::FAIL_NEXT_SYNC.swap(true, Ordering::AcqRel));
            // SAFETY: the same complete contract covers this attempted commit.
            let failure = match unsafe { prepared.commit() } {
                Ok(_) => panic!("commit ignored the synchronization failure"),
                Err(failure) => failure,
            };
            let (error, prepared) = failure.into_parts();
            let Error::TargetPagesMayBeWritable {
                pages,
                rolled_back: true,
                source: syscalls::Errno::EACCES,
            } = error
            else {
                panic!("commit rollback lost its page or operation state");
            };
            assert_eq!(pages.len(), 2);
            for (index, fixture) in fixtures.iter().enumerate() {
                assert!(pages.iter().any(|page| page.address == fixture.address));
                assert_eq!(call(fixture.entry(), 7), 1);
                assert_eq!(call(prepared.trampoline(index).unwrap(), 7), 1);
            }
            crate::sys::tests::restore_next_protect();
            for page in pages.iter() {
                // SAFETY: both report entries belong to live, quiescent fixtures.
                unsafe { crate::sys::protect(page.address, page.length, page.protection) }.unwrap();
            }
            // SAFETY: rollback retained the prepared arenas and unchanged targets.
            let mut hooks = unsafe { prepared.commit() }.unwrap();
            crate::sys::tests::deny_protect_restore_pages([
                fixtures[0].address,
                fixtures[1].address,
            ]);
            if !pinned {
                patch::tests::fail_next_forced_unavailable();
            }
            assert!(!crate::sys::tests::FAIL_NEXT_SYNC.swap(true, Ordering::AcqRel));
            // SAFETY: no target or trampoline call is in flight.
            let error = unsafe { unhook_inline_hooks(&mut hooks) }.unwrap_err();
            let Error::TargetPagesMayBeWritable {
                pages,
                rolled_back: true,
                source: syscalls::Errno::EACCES,
            } = error
            else {
                panic!("removal rollback lost its page or operation state");
            };
            assert_eq!(pages.len(), 2);
            for (fixture, hook) in fixtures.iter().zip(hooks.iter()) {
                assert!(pages.iter().any(|page| page.address == fixture.address));
                assert!(hook.is_installed());
                assert_eq!(call(fixture.entry(), 7), 0x1111);
                assert_eq!(call(hook.original().unwrap(), 7), 1);
            }
            crate::sys::tests::restore_next_protect();
            for page in pages.iter() {
                // SAFETY: the live hooks and mappings remain stable and quiescent.
                unsafe { crate::sys::protect(page.address, page.length, page.protection) }.unwrap();
            }
            // SAFETY: every earlier call drained and rollback retained installed handles.
            unsafe { unhook_inline_hooks(&mut hooks) }.unwrap();
            assert!(hooks.iter().all(|hook| !hook.is_installed()));
            for fixture in &fixtures {
                assert_eq!(call(fixture.entry(), 7), 1);
            }
            if !real_exec_restore_denied() {
                let request = InlineHookRequest::new(
                    fixtures[0].entry(),
                    same_page_first_replacement as *const (),
                )
                .with_mutation_path(MutationPath::DropExec);
                let mut hook = install_one(&request).expect("DropExec after KeepExec rollback");
                assert_eq!(hook.install_mutation_path(), MutationPath::DropExec);
                assert_eq!(call(fixtures[0].entry(), 7), 0x1111);
                assert_eq!(call(hook.original().unwrap(), 7), 1);
                unhook_one(&mut hook).unwrap();
                assert_eq!(call(fixtures[0].entry(), 7), 1);
            }
        }
    });
}

#[test]
fn installed_handles_report_the_single_publication_barrier() {
    serialized(|| {
        let page = PrivateExecPage::new().expect("private executable page");
        let targets = [
            page.entry(),
            std::ptr::with_exposed_provenance(page.address + 64),
        ];
        for path in [None, Some(MutationPath::KeepExec)] {
            let requests = targets.map(|target| {
                let request =
                    InlineHookRequest::new(target, same_page_first_replacement as *const ());
                match path {
                    Some(path) => request.with_mutation_path(path),
                    None => request,
                }
            });
            for count in [1, 2] {
                let ready = ensure_sync_core_registered();
                let before = crate::sys::tests::SYNC_CORE_ISSUES.load(Ordering::Relaxed);
                // SAFETY: the test owns the mappings and all calls are quiescent.
                let mut hooks = unsafe { install_inline_hooks(&requests[..count]) }.unwrap();
                let issued = crate::sys::tests::SYNC_CORE_ISSUES.load(Ordering::Relaxed) - before;
                for (target, hook) in targets.iter().zip(hooks.iter()) {
                    assert_eq!(hook.sync_core(), ready);
                    assert_eq!(call(*target, 7), 0x1111);
                    assert_eq!(call(hook.original().unwrap(), 7), 1);
                }
                // SAFETY: every target and trampoline call has completed.
                unsafe { unhook_inline_hooks(&mut hooks) }.unwrap();
                for target in targets {
                    assert_eq!(call(target, 7), 1);
                }
                assert!(
                    issued <= 1,
                    "installation issued a redundant publication barrier"
                );
                if ready {
                    assert_eq!(issued, 1, "installation omitted the publication barrier");
                }
            }
        }
    });
}

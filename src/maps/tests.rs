use super::smaps::SmapVmFlags;
use super::smaps::read_smaps_for_ranges_with;
use super::smaps::tests::{parse_smaps, read_smaps_for_ranges};
use super::*;

fn maps_line(column: usize, inode: &str, path: &[u8]) -> Vec<u8> {
    let mut line = format!("7f1000-7f3000 r-xp 00001000 08:02 {inode}").into_bytes();
    if line.len() < column {
        line.resize(column, b' ');
    } else {
        line.extend_from_slice(b"  ");
    }
    line.extend_from_slice(path);
    line
}

fn smaps_snapshot(column: usize, line: Vec<u8>, flags: &[u8]) -> Vec<u8> {
    let mut contents = maps_line(column, "0", b"[stack]");
    contents.extend_from_slice(b"\nVmFlags: rd wr\n");
    contents.extend(line);
    contents.extend_from_slice(b"\nVmFlags:");
    contents.extend_from_slice(flags);
    contents.push(b'\n');
    contents
}

#[test]
fn parses_variable_padding_and_path_bytes_without_stack_probe() {
    use std::os::unix::ffi::OsStrExt;

    for column in [47, 49, 73, 81] {
        let mut path = b"/tmp/a  library.so (deleted)".to_vec();
        path.push(0xff);
        let mut maps = parse_maps(&maps_line(column, "42", &path)).unwrap();
        let map = maps.pop().unwrap();

        assert_eq!(map.start, 0x7f1000);
        assert_eq!(map.end, 0x7f3000);
        assert_eq!(map.offset, 0x1000);
        assert_eq!(map.device, DeviceId::new(8, 2));
        assert_eq!(map.inode, 42);
        assert!(map.perms.contains(MapPerms::READ));
        assert!(map.perms.contains(MapPerms::EXEC));
        assert!(!map.perms.contains(MapPerms::WRITE));
        assert!(map.is_private);
        assert_eq!(map.path.unwrap().as_os_str().as_bytes(), path);
    }
}

#[test]
fn parses_mapping_without_pathname() {
    let maps = parse_maps(b"7f1000-7f3000 rw-p 00000000 00:00 0\n").unwrap();
    assert_eq!(maps.len(), 1);
    assert_eq!(maps[0].path, None);
}

#[test]
fn permission_field_keeps_exact_width_and_whitespace_boundaries() {
    for separator in [b' ', b'\t', b'\r', 0x0c] {
        let mut line = b"1000-2000\t r-xp".to_vec();
        line.push(separator);
        line.extend_from_slice(b"00000000 00:00 0");
        let maps = parse_maps(&line).unwrap();
        assert_eq!(maps[0].perms, MapPerms::READ | MapPerms::EXEC);
        assert!(maps[0].is_private);
    }
    for permissions in ["r-x", "r-xpx", "r-xp0", "q-xp", "rwyp", "rw-z", "rwx"] {
        let line = format!("1000-2000 {permissions} 00000000 00:00 0");
        assert!(matches!(
            parse_maps(line.as_bytes()),
            Err(Error::InvalidMapsLine(_))
        ));
    }
    assert!(matches!(
        parse_maps(b"1000-2000 r-xp"),
        Err(Error::InvalidMapsLine(_))
    ));
}

#[test]
fn full_snapshot_tolerates_gki_empty_padding_entries() {
    let contents = b"1000-2000 r-xp 00001000 08:02 42 /system/lib64/liblog.so\n\
2000-2000 r-xp 00013000 08:02 42 /system/lib64/liblog.so\n\
2000-3000 ---p 00000000 00:00 0\n\
7f0000-7f1000 rw-p 00000000 00:00 0\n";
    let maps = parse_maps(contents).unwrap();

    assert_eq!(
        maps.iter()
            .map(|map| (map.start, map.end))
            .collect::<Vec<_>>(),
        vec![(0x1000, 0x2000), (0x2000, 0x3000), (0x7f0000, 0x7f1000)]
    );
    assert!(
        maps.iter()
            .all(|map| map.contains(map.start) || map.start == map.end)
    );
    let found = find_map_containing(&maps, 0x2000, 1).unwrap();
    assert_eq!(found.perms, MapPerms::empty());
    assert_eq!(found.path, None);
    assert_eq!(
        find_map_containing(&maps, 0x1000, 0x1000).unwrap().start,
        0x1000
    );
    assert!(find_map_containing(&maps, 0x1fff, 2).is_none());
    assert!(find_map_containing(&maps, 0x0fff, 1).is_none());
    assert!(find_map_containing(&maps, 0x3000, 1).is_none());
    assert!(find_map_containing(&maps, 0x1000, usize::MAX).is_none());
    assert!(find_map_containing(&[], 0x1000, 1).is_none());
}

#[test]
fn full_snapshot_orders_empty_and_real_entries_sharing_one_start() {
    for contents in [
        b"1000-1000 r-xp 00013000 08:02 42 /system/lib64/liblog.so\n\
1000-2000 ---p 00000000 00:00 0\n"
            .as_slice(),
        b"1000-2000 ---p 00000000 00:00 0\n\
1000-1000 r-xp 00013000 08:02 42 /system/lib64/liblog.so\n"
            .as_slice(),
    ] {
        let maps = parse_maps_with_paths(contents, true).unwrap();

        assert_eq!(
            maps.iter()
                .map(|map| (map.start, map.end))
                .collect::<Vec<_>>(),
            vec![(0x1000, 0x2000)]
        );
        assert!(find_map_containing(&maps, 0x1000, 1).is_some());
    }
}

#[test]
fn targeted_maps_skip_gki_empty_padding_entries() {
    let contents = b"1000-1000 r-xp 00013000 08:02 42 /system/lib64/liblog.so\n\
1000-2000 ---p 00000000 00:00 0\n\
2000-3000 r-xp 00002000 08:02 43 /system/lib64/libc++.so\n";
    let maps =
        read_maps_for_ranges(std::io::Cursor::new(contents), &[(0x0f00, 0x2800)], false).unwrap();

    assert_eq!(
        maps.iter()
            .map(|map| (map.start, map.end))
            .collect::<Vec<_>>(),
        vec![(0x1000, 0x2000), (0x2000, 0x3000)]
    );
}

#[test]
fn targeted_smaps_skip_gki_empty_padding_headers() {
    let contents = b"1000-1000 r-xp 00013000 08:02 42 /system/lib64/liblog.so\n\
VmFlags: rd ex\n\
1000-2000 ---p 00000000 00:00 0\n\
VmFlags: \n\
2000-3000 r-xp 00002000 08:02 43 /system/lib64/libc++.so\n\
VmFlags: rd ex\n";
    let entries =
        read_smaps_for_ranges(std::io::Cursor::new(contents), &[(0x0f00, 0x2800)]).unwrap();

    assert_eq!(entries.len(), 2);
    assert_eq!((entries[0].map.start, entries[0].map.end), (0x1000, 0x2000));
    assert_eq!((entries[1].map.start, entries[1].map.end), (0x2000, 0x3000));
    // The empty VmFlags entry for the zero-length header is skipped entirely.
    assert!(!entries.iter().any(|entry| entry.map.start == entry.map.end));
}

#[test]
fn full_snapshot_rejects_out_of_order_mappings() {
    let ordered =
        b"1000-2000 r-xp 00000000 08:02 42 /tmp/a.so\n7f0000-7f1000 rw-p 00000000 00:00 0\n";
    assert_eq!(parse_maps(ordered).unwrap().len(), 2);

    let backwards =
        b"7f0000-7f1000 rw-p 00000000 00:00 0\n1000-2000 r-xp 00000000 08:02 42 /tmp/a.so\n";
    assert!(matches!(
        parse_maps(backwards),
        Err(Error::InvalidMapsLine(_))
    ));
}

#[test]
fn parser_rejects_non_ascii_digits_and_numeric_overflow() {
    for line in [
        b"g000-2000 r--p 00000000 00:00 0\n".as_slice(),
        b"1000 2000 r--p 00000000 00:00 0\n".as_slice(),
        b"-2000 r--p 00000000 00:00 0\n".as_slice(),
        b"1000- r--p 00000000 00:00 0\n".as_slice(),
        b"1000- 2000 r--p 00000000 00:00 0\n".as_slice(),
        b"10000000000000000-10000000000000001 r--p 00000000 00:00 0\n".as_slice(),
        b"1000-2000 r--p 10000000000000000 00:00 0\n".as_slice(),
        b"1000-2000 r--p 00000000 00: 00 0\n".as_slice(),
        b"1000-2000 r--p 00000000 100000000:00 0\n".as_slice(),
        b"1000-2000 r--p 00000000 00:00 18446744073709551616\n".as_slice(),
    ] {
        assert!(matches!(parse_maps(line), Err(Error::InvalidMapsLine(_))));
    }
}

#[test]
fn pathless_parser_keeps_mapping_identity_without_allocating_paths() {
    let map = parse_maps_with_paths(b"1000-3000 r-xp 00001000 08:02 42 /tmp/library.so\n", false)
        .unwrap()
        .pop()
        .unwrap();

    assert_eq!(map.start, 0x1000);
    assert_eq!(map.end, 0x3000);
    assert_eq!(map.offset, 0x1000);
    assert_eq!(map.device, DeviceId::new(8, 2));
    assert_eq!(map.inode, 42);
    assert!(map.perms.contains(MapPerms::READ | MapPerms::EXEC));
    assert!(!map.perms.contains(MapPerms::WRITE));
    assert!(map.is_private);
    assert_eq!(map.path, None);
}

#[test]
fn targeted_maps_keep_complete_vmas_once_and_in_procfs_order() {
    let contents = b"0800-1000 malformed suffix is ignored\n\
1000-2000 r--p 00000000 00:00 0 /first\n\
2000-3000 r-xp 00001000 08:02 42 /second\n\
invalid sentinel must not be read\n";
    let maps = read_maps_for_ranges(
        std::io::BufReader::with_capacity(7, std::io::Cursor::new(contents)),
        &[(0x1800, 0x1900), (0x1a00, 0x1b00), (0x2800, 0x2900)],
        false,
    )
    .unwrap();

    assert_eq!(maps.len(), 2);
    assert_eq!((maps[0].start, maps[0].end), (0x1000, 0x2000));
    assert_eq!((maps[1].start, maps[1].end), (0x2000, 0x3000));
    assert_eq!(maps[0].path, None);
    assert_eq!(maps[1].path, None);

    let pathful = read_maps_for_ranges(
        std::io::Cursor::new(contents),
        &[(0x1800, 0x1900), (0x2800, 0x2900)],
        true,
    )
    .unwrap();
    assert_eq!(
        pathful[0].path.as_deref(),
        Some(std::path::Path::new("/first"))
    );
    assert_eq!(
        pathful[1].path.as_deref(),
        Some(std::path::Path::new("/second"))
    );
}

#[test]
fn targeted_maps_strictly_validate_consumed_prefixes_and_targets() {
    for successor in [
        b"2000-zzzz r--p 00000000 00:00 0\n".as_slice(),
        b"2000-10000000000000000 r--p 00000000 00:00 0\n".as_slice(),
        b"3000-2000 r--p 00000000 00:00 0\n".as_slice(),
    ] {
        let mut contents = b"1000-2000 r--p 00000000 00:00 0\n".to_vec();
        contents.extend_from_slice(successor);
        assert!(matches!(
            read_maps_for_ranges(std::io::Cursor::new(contents), &[(0x1800, 0x2800)], false),
            Err(Error::InvalidMapsLine(_))
        ));
    }

    assert!(matches!(
        read_maps_for_ranges(
            std::io::Cursor::new(
                b"1000-2000 r--p 00000000 00:00 0\n0fff-3000 r--p 00000000 00:00 0\n"
            ),
            &[(0x1800, 0x2800)],
            false,
        ),
        Err(Error::InvalidMapsLine(_))
    ));
    assert!(matches!(
        read_maps_for_ranges(
            std::io::Cursor::new(b"1000-2000 malformed ElfImageSelector suffix\n"),
            &[(0x1800, 0x1900)],
            false,
        ),
        Err(Error::InvalidMapsLine(_))
    ));
}

#[test]
fn targeted_maps_use_half_open_boundaries() {
    let contents = b"1000-2000 r--p 00000000 00:00 0\n\
2000-3000 r-xp 00000000 00:00 0\n";

    let before =
        read_maps_for_ranges(std::io::Cursor::new(contents), &[(0x800, 0x1000)], false).unwrap();
    assert!(before.is_empty());

    let adjacent =
        read_maps_for_ranges(std::io::Cursor::new(contents), &[(0x2000, 0x2100)], false).unwrap();
    assert_eq!(adjacent.len(), 1);
    assert_eq!(adjacent[0].start, 0x2000);
}

#[test]
fn targeted_readers_handle_lines_split_across_input_buffers() {
    let maps_contents = b"1000-2000 r--p 00000000 00:00 0\r\n\
2000-3000 r-xp 00001000 08:02 42 /second";

    let maps = read_maps_for_ranges(
        std::io::BufReader::with_capacity(7, std::io::Cursor::new(maps_contents)),
        &[(0x2800, 0x2900)],
        false,
    )
    .unwrap();
    assert_eq!((maps[0].start, maps[0].end), (0x2000, 0x3000));

    let smaps_contents = b"1000-2000 r--p 00000000 00:00 0\r\n\
VmFlags: rd\r\n\
2000-3000 r-xp 00001000 08:02 42 /second\r\n\
VmFlags: rd ex bt mt";
    let smaps = read_smaps_for_ranges(
        std::io::BufReader::with_capacity(7, std::io::Cursor::new(smaps_contents)),
        &[(0x2800, 0x2900)],
    )
    .unwrap();
    assert_eq!((smaps[0].map.start, smaps[0].map.end), (0x2000, 0x3000));
    assert!(smaps[0].vm_flags.bti);
    assert!(smaps[0].vm_flags.mte);
}

#[test]
fn page_ranges_sort_deduplicate_coalesce_and_check_overflow() {
    let page_size = crate::sys::page_size().unwrap();
    let base = page_size.checked_mul(4).unwrap();
    let ranges = page_ranges([
        base + page_size + 1,
        base + 1,
        base + 1,
        base + page_size * 3 + 1,
    ])
    .unwrap();

    assert_eq!(
        ranges,
        vec![
            (base, base + page_size * 2),
            (base + page_size * 3, base + page_size * 4),
        ]
    );
    assert!(matches!(
        page_ranges([usize::MAX]),
        Err(Error::ArithmeticOverflow)
    ));
}

#[test]
fn smaps_preserves_bti_mte_and_unknown_vm_flags() {
    for column in [47, 81] {
        let line = maps_line(column, "42", b"/tmp/library.so");
        let entries = parse_smaps(&smaps_snapshot(column, line, b" rd bt future mt ")).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[1].vm_flags,
            SmapVmFlags {
                bti: true,
                mte: true,
                unknown: true,
                ..SmapVmFlags::default()
            }
        );
    }
}

#[test]
fn smaps_denywrite_is_not_special_for_private_replacement() {
    let line = maps_line(81, "42", b"/tmp/library.so");
    let snapshot = smaps_snapshot(81, line, b" rd mr mw me dw ");
    let entries = parse_smaps(&snapshot).unwrap();

    assert_eq!(entries[1].vm_flags, SmapVmFlags::default());
}

#[test]
fn smaps_android_padding_metadata_is_not_special() {
    let line = maps_line(81, "42", b"/apex/com.android.runtime/lib64/bionic/libm.so");
    let valid = smaps_snapshot(81, line.clone(), b" rd ex mr mw me bt pad=8kB ");
    let entries = parse_smaps(&valid).unwrap();

    assert!(entries[1].vm_flags.bti);
    assert!(!entries[1].vm_flags.unknown);

    for token in [
        b" rd ex mr mw me bt pad=kB ".as_slice(),
        b" rd ex mr mw me bt pad=xkB ".as_slice(),
    ] {
        let invalid = smaps_snapshot(81, line.clone(), token);
        let entries = parse_smaps(&invalid).unwrap();
        assert!(
            entries[1].vm_flags.unknown,
            "invalid padding token {token:?} was accepted"
        );
    }
}

#[test]
fn smaps_preserves_flags_that_prevent_safe_mapping_replacement() {
    let line = maps_line(81, "42", b"/tmp/library.so");
    let mut snapshot = smaps_snapshot(81, line, b" lo dd df wf hg nh mm io lf sr ");
    snapshot.extend_from_slice(b"ProtectionKey: 7\n");
    let entries = parse_smaps(&snapshot).unwrap();
    let flags = &entries[1].vm_flags;
    assert!(flags.locked);
    assert!(flags.dont_dump);
    assert!(flags.dont_fork);
    assert!(flags.wipe_on_fork);
    assert!(flags.hugepage);
    assert!(flags.non_hugepage);
    assert!(flags.mixed_map);
    assert!(flags.io_map);
    assert!(flags.lock_on_fault);
    assert!(flags.sync);
    assert_eq!(entries[1].protection_key, 7);
}

#[test]
fn smaps_lock_on_fault_is_lf_and_unknown_flags_stay_distinct() {
    let line = maps_line(81, "42", b"/tmp/library.so");
    let snapshot = smaps_snapshot(81, line, b" lf zz ");
    let entries = parse_smaps(&snapshot).unwrap();
    let flags = &entries[1].vm_flags;
    assert!(flags.lock_on_fault);
    assert!(!flags.locked);
    assert!(flags.unknown);
}

#[test]
fn targeted_smaps_reader_can_retain_backing_paths() {
    let contents = b"1000-2000 r--p 00001000 08:02 42 /tmp/library.so\n\
                     ProtectionKey: 0\n\
                     VmFlags: rd mr mw me sd\n";
    let entries =
        read_smaps_for_ranges_with(std::io::Cursor::new(contents), &[(0x1800, 0x1900)], true)
            .unwrap();

    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].map.path.as_deref(),
        Some("/tmp/library.so".as_ref())
    );
    assert_eq!(entries[0].protection_key, 0);
}

#[test]
fn smaps_header_detection_rejects_properties_and_keeps_strict_parsing() {
    let entries = parse_smaps(
        b" 1000-2000 r-xp 00000000 00:00 0\n\
AnonHugePages:         0 kB\n\
FilePmdMapped:         0 kB\n\
VmFlags: rd ex bt\n",
    )
    .unwrap();
    assert_eq!(entries.len(), 1);
    assert!(entries[0].vm_flags.bti);

    assert!(matches!(
        parse_smaps(b"1000-zzzz r--p 00000000 00:00 0\nVmFlags: rd\n"),
        Err(Error::InvalidMapsLine(_))
    ));
}

#[test]
fn smaps_requires_exactly_one_vm_flags_line_per_mapping() {
    let line = maps_line(81, "42", b"/tmp/library.so");
    let mut missing = maps_line(81, "0", b"[stack]");
    missing.extend_from_slice(b"\nVmFlags: rd\n");
    missing.extend_from_slice(&line);
    missing.push(b'\n');
    assert!(matches!(
        parse_smaps(&missing),
        Err(Error::InvalidSmaps("mapping has no VmFlags"))
    ));

    let mut duplicate = smaps_snapshot(81, line, b" rd");
    duplicate.extend_from_slice(b"VmFlags: rd\n");
    assert!(matches!(
        parse_smaps(&duplicate),
        Err(Error::InvalidSmaps("duplicate VmFlags for one mapping"))
    ));
}

#[test]
fn merged_range_scan_covers_window_and_targets_in_one_pass() {
    let contents = b"1000-2000 r-xp 00000000 08:02 42 /lib/a.so\n\
2000-3000 r--p 00000000 00:00 0\n\
5000-6000 r-xp 00000000 08:02 43 /lib/b.so\n\
9000-a000 r-xp 00000000 08:02 44 /lib/c.so\n";
    // ElfImageSelector inside /lib/a.so plus a distant allocation window around
    // /lib/b.so: one scan must return both complete VMAs, in procfs order,
    // without duplicating either when the ranges coalesce.
    let ranges = [(0x1800, 0x1900), (0x4000, 0x7000)];
    let merged = read_maps_for_ranges(std::io::Cursor::new(contents), &ranges, false).unwrap();
    assert_eq!(merged.len(), 2);
    assert_eq!((merged[0].start, merged[0].end), (0x1000, 0x2000));
    assert_eq!((merged[1].start, merged[1].end), (0x5000, 0x6000));
    assert!(merged[0].perms.contains(crate::MapPerms::EXEC));
}

#[test]
fn page_ranges_normalize_descending_target_and_replacement_pages() {
    let page_size = crate::sys::page_size().unwrap();
    let replacement_page = page_size;
    let replacement_end = replacement_page + page_size;
    let slot_page = page_size * 5;
    let slot_end = slot_page + page_size;
    let contents = format!(
        "{replacement_page:x}-{replacement_end:x} r-xp 00000000 08:02 42 /lib/a.so\n\
{slot_page:x}-{slot_end:x} r--p 00000000 08:02 43 /lib/b.so\n"
    );
    let ranges = page_ranges([slot_page, replacement_page]).unwrap();

    assert_eq!(
        ranges,
        [(replacement_page, replacement_end), (slot_page, slot_end)]
    );
    let maps =
        read_maps_for_ranges(std::io::Cursor::new(contents.as_bytes()), &ranges, false).unwrap();
    assert_eq!(
        (maps[0].start, maps[0].end),
        (replacement_page, replacement_end)
    );
    assert_eq!((maps[1].start, maps[1].end), (slot_page, slot_end));
}

#[test]
fn newline_scan_matches_the_byte_loop_on_every_boundary() {
    assert_eq!(super::find_newline(b""), None);
    assert_eq!(super::find_newline(b"abcdef"), None);
    for position in [0, 1, 7, 8, 9, 15, 16, 31, 63, 64] {
        let mut buffer = vec![b'x'; position];
        buffer.push(b'\n');
        buffer.extend_from_slice(&[b'x'; 40]);
        assert_eq!(super::find_newline(&buffer), Some(position));
    }
    // Bytes carrying a set bit above 0x0a must not alias to a newline.
    let mut alias = [0x2a_u8; 128];
    alias[127] = b'\n';
    assert_eq!(super::find_newline(&alias), Some(127));
}

#[test]
fn targeted_smaps_reader_keeps_only_intersections() {
    let contents = b"0800-1000 malformed non-ElfImageSelector suffix\n\
1000-2000 r--p 00000000 00:00 0\n\
VmFlags: rd\n\
2000-3000 r-xp 00001000 08:02 42 /tmp/library.so\n\
VmFlags: rd ex bt mt\n\
3000-4000 malformed successor suffix\n\
4000-zzzz sentinel must not be read\n";
    let entries =
        read_smaps_for_ranges(std::io::Cursor::new(contents), &[(0x2800, 0x2900)]).unwrap();

    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].map.start, 0x2000);
    assert_eq!(entries[0].map.end, 0x3000);
    assert_eq!(entries[0].map.path, None);
    assert!(entries[0].vm_flags.bti);
    assert!(entries[0].vm_flags.mte);

    let before =
        read_smaps_for_ranges(std::io::Cursor::new(contents), &[(0x1800, 0x2000)]).unwrap();
    assert_eq!(before.len(), 1);
    assert_eq!(before[0].map.start, 0x1000);

    let adjacent =
        read_smaps_for_ranges(std::io::Cursor::new(contents), &[(0x2000, 0x2100)]).unwrap();
    assert_eq!(adjacent.len(), 1);
    assert_eq!(adjacent[0].map.start, 0x2000);
}

#[test]
fn targeted_smaps_strictly_validate_header_prefixes_and_targets() {
    for successor in [
        b"2000-zzzz r--p 00000000 00:00 0\n".as_slice(),
        b"2000-10000000000000000 r--p 00000000 00:00 0\n".as_slice(),
        b"3000-2000 r--p 00000000 00:00 0\n".as_slice(),
    ] {
        let mut contents = b"1000-2000 r--p 00000000 00:00 0\nVmFlags: rd\n".to_vec();
        contents.extend_from_slice(successor);
        assert!(matches!(
            read_smaps_for_ranges(std::io::Cursor::new(contents), &[(0x1800, 0x1900)]),
            Err(Error::InvalidMapsLine(_))
        ));
    }

    assert!(matches!(
        read_smaps_for_ranges(
            std::io::Cursor::new(
                b"1000-2000 r--p 00000000 00:00 0\nVmFlags: rd\n0fff-3000 r--p 00000000 00:00 0\n"
            ),
            &[(0x1800, 0x1900)],
        ),
        Err(Error::InvalidSmaps("mappings are not ordered"))
    ));
    assert!(matches!(
        read_smaps_for_ranges(
            std::io::Cursor::new(b"1000-2000 malformed ElfImageSelector suffix\nVmFlags: rd\n"),
            &[(0x1800, 0x1900)],
        ),
        Err(Error::InvalidMapsLine(_))
    ));
}

#[test]
fn targeted_smaps_require_exactly_one_target_vm_flags() {
    assert!(matches!(
        read_smaps_for_ranges(
            std::io::Cursor::new(
                b"1000-2000 r--p 00000000 00:00 0\n2000-3000 r--p 00000000 00:00 0\nVmFlags: rd\n"
            ),
            &[(0x1800, 0x1900)],
        ),
        Err(Error::InvalidSmaps("mapping has no VmFlags"))
    ));
    assert!(matches!(
        read_smaps_for_ranges(
            std::io::Cursor::new(b"1000-2000 r--p 00000000 00:00 0\nVmFlags: rd\nVmFlags: bt\n"),
            &[(0x1800, 0x1900)],
        ),
        Err(Error::InvalidSmaps("duplicate VmFlags for one mapping"))
    ));
}

#[test]
fn targeted_smaps_ranges_survive_gaps_and_reuse_one_mapping() {
    let contents = b"1000-2000 r--p 00000000 00:00 0\n\
VmFlags: rd\n\
3000-4000 r-xp 00000000 00:00 0\n\
VmFlags: rd ex\n\
5000-6000 r--p 00000000 00:00 0\n\
VmFlags: rd\n";
    let contents = std::io::Cursor::new(contents);

    let gap = read_smaps_for_ranges(contents.clone(), &[(0x2400, 0x2800)]).unwrap();
    assert!(gap.is_empty());

    let spanning = read_smaps_for_ranges(
        contents.clone(),
        &[(0x1800, 0x1900), (0x2400, 0x2800), (0x3200, 0x3300)],
    )
    .unwrap();
    assert_eq!(
        spanning
            .iter()
            .map(|entry| (entry.map.start, entry.map.end))
            .collect::<Vec<_>>(),
        vec![(0x1000, 0x2000), (0x3000, 0x4000)]
    );

    let reused = read_smaps_for_ranges(
        contents,
        &[(0x1200, 0x1300), (0x1800, 0x1900), (0x1c00, 0x1d00)],
    )
    .unwrap();
    assert_eq!(reused.len(), 1);
    assert_eq!((reused[0].map.start, reused[0].map.end), (0x1000, 0x2000));
}

#[test]
fn full_maps_snapshot_fits_small_stack_threads() {
    let thread = std::thread::Builder::new()
        .stack_size(32 * 1024)
        .spawn(read_self_maps_pathless)
        .unwrap();
    let maps = thread.join().unwrap().unwrap();
    assert!(!maps.is_empty());
}

#[cfg(all(feature = "plt", target_pointer_width = "64"))]
#[test]
fn image_scan_expands_from_a_live_header_and_preserves_gaps_and_permissions() {
    let contents = b"0800-1000 ignored suffix\n\
1000-2000 r--p 00000000 08:02 42 /image\n\
3000-4000 ---p 00002000 08:02 42 /image\n\
4000-5000 rw-p 00003000 08:02 42 /image\n\
5000-6000 ignored suffix\n\
invalid sentinel must not be read\n";
    let mut calls = 0;
    let maps = read_maps_for_image(
        std::io::BufReader::with_capacity(7, std::io::Cursor::new(contents)),
        0x1800,
        &mut |first| {
            calls += 1;
            assert_eq!((first.start, first.end), (0x1000, 0x2000));
            assert!(first.perms.contains(MapPerms::READ));
            Ok(0x4800)
        },
    )
    .unwrap();
    assert_eq!(calls, 1);
    assert_eq!(maps.len(), 3);
    assert!(find_map_containing(&maps, 0x2800, 1).is_none());
    assert!(!maps[1].perms.contains(MapPerms::READ));
    assert_eq!((maps[2].start, maps[2].end), (0x4000, 0x5000));
    assert!(matches!(
        read_maps_for_image(std::io::Cursor::new(contents), 0x2800, &mut |_| {
            panic!("missing header must not reach the extent callback")
        }),
        Err(Error::UnmappedRead { .. })
    ));
    assert!(matches!(
        read_maps_for_image(std::io::Cursor::new(contents), 0x1800, &mut |_| {
            Ok(0x1800)
        }),
        Err(Error::ArithmeticOverflow)
    ));
}

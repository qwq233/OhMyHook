use super::*;

fn image_with_notes(notes: &[u8]) -> Image {
    let base = notes.as_ptr() as usize;
    Image {
        id: ImageId {
            device: crate::DeviceId::new(1, 2),
            inode: 3,
            header: base,
            load_bias: base,
            elf_header_offset: 0,
            loader_base: None,
        },
        header: ElfHeader {
            class: native_class(),
            machine: arch::MACHINE,
            phoff: 0,
            phentsize: native_class().phdr_size() as u16,
            phnum: 1,
        },
        dynamic: DynamicInfo::default(),
        load_ranges: vec![(base, base + notes.len())],
        notes: vec![ProgramHeader {
            kind: PT_NOTE,
            flags: 0,
            offset: 0,
            vaddr: 0,
            filesz: notes.len() as u64,
            memsz: notes.len() as u64,
        }],
    }
}

#[test]
fn parses_raw_gnu_build_id_with_four_byte_note_alignment() {
    for class in [ElfClass::Elf32, ElfClass::Elf64] {
        let mut fixture = Fixture::new();
        let mut notes = Vec::new();
        push_note(&mut notes, b"X", b"abc", 99);
        push_note(
            &mut notes,
            b"GNU\0",
            b"\x01\x23\x45\x67\x89",
            NT_GNU_BUILD_ID,
        );
        fixture.write(NOTE_OFFSET, &notes);
        let mut image = image_for(&fixture, class, arch::MACHINE, false);
        image.notes.push(ProgramHeader {
            kind: PT_NOTE,
            flags: 0,
            offset: NOTE_OFFSET as u64,
            vaddr: NOTE_OFFSET as u64,
            filesz: notes.len() as u64,
            memsz: notes.len() as u64,
        });
        let maps = [map_for(&fixture.0)];
        assert_eq!(
            image.gnu_build_id(&memory(&maps)).unwrap().as_deref(),
            Some(b"\x01\x23\x45\x67\x89".as_slice())
        );
    }
}

#[test]
fn accepts_identical_and_rejects_conflicting_build_id_notes() {
    let mut fixture = Fixture::new();
    let mut notes = Vec::new();
    push_note(&mut notes, b"GNU\0", b"same", NT_GNU_BUILD_ID);
    push_note(&mut notes, b"GNU\0", b"same", NT_GNU_BUILD_ID);
    fixture.write(NOTE_OFFSET, &notes);
    let mut image = image_for(&fixture, native_class(), arch::MACHINE, false);
    image.notes.push(ProgramHeader {
        kind: PT_NOTE,
        flags: 0,
        offset: NOTE_OFFSET as u64,
        vaddr: NOTE_OFFSET as u64,
        filesz: notes.len() as u64,
        memsz: notes.len() as u64,
    });
    let maps = [map_for(&fixture.0)];
    assert_eq!(
        image.gnu_build_id(&memory(&maps)).unwrap().as_deref(),
        Some(b"same".as_slice())
    );

    let mut conflicting = Vec::new();
    push_note(&mut conflicting, b"GNU\0", b"first", NT_GNU_BUILD_ID);
    push_note(&mut conflicting, b"GNU\0", b"second", NT_GNU_BUILD_ID);
    fixture.write(NOTE_OFFSET, &conflicting);
    image.notes[0].filesz = conflicting.len() as u64;
    let maps = [map_for(&fixture.0)];
    assert!(matches!(
        image.gnu_build_id(&memory(&maps)),
        Err(Error::InvalidElf("conflicting GNU build-id notes"))
    ));
}

#[test]
fn rejects_truncated_accessible_build_id_note_segments() {
    let fixture = Fixture::new();
    let mut image = image_for(&fixture, native_class(), arch::MACHINE, false);
    image.notes.push(ProgramHeader {
        kind: PT_NOTE,
        flags: 0,
        offset: NOTE_OFFSET as u64,
        vaddr: NOTE_OFFSET as u64,
        filesz: 11,
        memsz: 11,
    });
    let maps = [map_for(&fixture.0)];
    assert!(matches!(
        image.gnu_build_id(&memory(&maps)),
        Err(Error::InvalidElf("truncated ELF note header"))
    ));
}

#[test]
fn rejects_oversized_build_id_before_allocating_it() {
    let mut notes = Vec::new();
    push_note(
        &mut notes,
        b"GNU\0",
        &vec![0; MAX_BUILD_ID_SIZE + 1],
        NT_GNU_BUILD_ID,
    );
    let image = image_with_notes(&notes);
    let maps = [map_for(&notes)];

    assert!(matches!(
        image.gnu_build_id(&memory(&maps)),
        Err(Error::InvalidElf("GNU build-id is too large"))
    ));
}

#[test]
fn rejects_excessive_total_build_id_bytes() {
    let description = vec![0; MAX_BUILD_ID_SIZE];
    let mut notes = Vec::new();
    for _ in 0..=(MAX_BUILD_ID_BYTES / MAX_BUILD_ID_SIZE) {
        push_note(&mut notes, b"GNU\0", &description, NT_GNU_BUILD_ID);
    }
    let image = image_with_notes(&notes);
    let maps = [map_for(&notes)];

    assert!(matches!(
        image.gnu_build_id(&memory(&maps)),
        Err(Error::InvalidElf("too many GNU build-id bytes"))
    ));
}

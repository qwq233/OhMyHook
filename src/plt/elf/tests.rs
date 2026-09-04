use super::discover::*;
use super::parse::*;
use super::relocation::{PackedReader, RelocationTable};
use super::version::validate_dynamic_string;
use super::*;
use std::ffi::CStr;

impl ImageMappingKey {
    pub(crate) const fn for_test(device: crate::DeviceId, inode: u64, header: usize) -> Self {
        Self {
            device,
            inode,
            header,
            load_bias: header,
            elf_header_offset: 0,
            loader_base: None,
        }
    }
}

impl FoundRelocation {
    pub(crate) const fn for_test(
        address: usize,
        image: ImageMappingKey,
        kind: RelocationKind,
        addend: i64,
        jump_slot_state: JumpSlotState,
    ) -> Self {
        Self {
            address,
            image,
            kind,
            addend,
            jump_slot_state,
            aarch64_pac_plt: false,
            function_symbol: false,
            _validated_mapping: (),
        }
    }
}

impl<T> RelocationSet<T> {
    #[cfg(test)]
    fn get(&self, address: &usize) -> Option<&T> {
        self.first
            .as_ref()
            .and_then(|(first, value)| (first == address).then_some(value))
            .or_else(|| self.rest.get(address))
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        usize::from(self.first.is_some()) + self.rest.len()
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.first.is_none() && self.rest.is_empty()
    }

    #[cfg(test)]
    fn keys(&self) -> impl Iterator<Item = &usize> {
        self.first
            .iter()
            .map(|(address, _)| address)
            .chain(self.rest.keys())
    }

    #[cfg(test)]
    fn values(&self) -> impl Iterator<Item = &T> {
        self.first
            .iter()
            .map(|(_, value)| value)
            .chain(self.rest.values())
    }
}

#[cfg(test)]
impl<T> std::ops::Index<&usize> for RelocationSet<T> {
    type Output = T;

    fn index(&self, address: &usize) -> &Self::Output {
        self.get(address).expect("missing relocation address")
    }
}

const STRTAB_OFFSET: usize = 128;
const SYMTAB_OFFSET: usize = 160;
const VERSYM_OFFSET: usize = 224;
const TABLE_OFFSET: usize = 256;
const SLOT_OFFSET: usize = 512;
const VERDEF_OFFSET: usize = 600;
const VERNEED_OFFSET: usize = 700;
const NOTE_OFFSET: usize = 800;
const GNU_HASH_OFFSET: usize = 848;

fn any_query(name: &CStr) -> SymbolQuery<'_> {
    SymbolQuery::any_version(name).unwrap()
}

/// Builds a real single-bucket GNU hash table covering symbol index 1.
///
/// Layout: header (nbuckets, symoffset, bloom_count, bloom[1]), one bucket
/// pointing at `first_symbol`, and one chain word per covered symbol holding
/// the symbol's GNU hash with the chain-terminator bit set, exactly as a
/// linker emits for a single-symbol GNU-only image.
fn install_gnu_hash(fixture: &mut Fixture, class: ElfClass, name: &[u8], first_symbol: u32) {
    let hash = Hashes::for_name(name).gnu;
    fixture.write_u32(GNU_HASH_OFFSET, 1); // nbuckets
    fixture.write_u32(GNU_HASH_OFFSET + 4, first_symbol); // symoffset
    fixture.write_u32(GNU_HASH_OFFSET + 8, 1); // bloom_count
    fixture.write_u64(GNU_HASH_OFFSET + 16, u64::from(hash)); // bloom word
    let bucket = GNU_HASH_OFFSET + 16 + class.pointer_size();
    fixture.write_u32(bucket, first_symbol);
    // Chain word: the covered symbol's hash with bit 0 set as the chain
    // terminator, exactly as a linker marks the last bucket entry.
    fixture.write_u32(bucket + 4, hash | 1);
}

#[repr(align(8))]
struct Fixture([u8; 1024]);

impl Fixture {
    fn new() -> Self {
        Self([0; 1024])
    }

    fn base(&self) -> usize {
        self.0.as_ptr() as usize
    }

    fn write(&mut self, offset: usize, bytes: &[u8]) {
        self.0[offset..offset + bytes.len()].copy_from_slice(bytes);
    }

    fn write_u16(&mut self, offset: usize, value: u16) {
        self.write(offset, &value.to_le_bytes());
    }

    fn write_u32(&mut self, offset: usize, value: u32) {
        self.write(offset, &value.to_le_bytes());
    }

    fn write_u64(&mut self, offset: usize, value: u64) {
        self.write(offset, &value.to_le_bytes());
    }
}

fn map_for(bytes: &[u8]) -> MapInfo {
    MapInfo {
        start: bytes.as_ptr() as usize,
        end: bytes.as_ptr() as usize + bytes.len(),
        perms: MapPerms::READ,
        is_private: true,
        offset: 0,
        device: crate::DeviceId::new(0, 0),
        inode: 0,
        path: None,
    }
}

fn memory(maps: &[MapInfo]) -> Memory<'_> {
    // SAFETY: every test map is built from a live backing slice which
    // outlives the returned view and is not moved while the view is used.
    unsafe { Memory::new(maps) }
}

fn image_for(fixture: &Fixture, class: ElfClass, machine: u16, pac_plt: bool) -> Image {
    let base = fixture.base();
    Image {
        id: ImageMappingKey {
            device: crate::DeviceId::new(1, 2),
            inode: 3,
            header: base,
            load_bias: base,
            elf_header_offset: 0,
            loader_base: None,
        },
        header: ElfHeader {
            class,
            machine,
            phoff: 0,
            phentsize: class.phdr_size() as u16,
            phnum: 1,
        },
        dynamic: DynamicInfo {
            aarch64_pac_plt: pac_plt,
            ..DynamicInfo::default()
        },
        load_ranges: vec![(base, base + fixture.0.len())],
        notes: Vec::new(),
    }
}

fn install_symbol(fixture: &mut Fixture, class: ElfClass) -> (u64, u64, u64) {
    fixture.write(STRTAB_OFFSET, b"\0getpid\0");
    fixture.write_u32(SYMTAB_OFFSET + class.sym_size(), 1);
    (
        (fixture.base() + STRTAB_OFFSET) as u64,
        8,
        (fixture.base() + SYMTAB_OFFSET) as u64,
    )
}

fn install_version_tables(fixture: &mut Fixture, image: &mut Image) -> (u64, u64, u64) {
    let strings = b"\0foo\0VER_DEF\0lib.so\0VER_NEED\0";
    fixture.write(STRTAB_OFFSET, strings);

    fixture.write_u16(VERDEF_OFFSET, VER_DEF_CURRENT);
    fixture.write_u16(VERDEF_OFFSET + 4, 2);
    fixture.write_u16(VERDEF_OFFSET + 6, 1);
    fixture.write_u32(VERDEF_OFFSET + 12, 20);
    fixture.write_u32(VERDEF_OFFSET + 16, 0);
    fixture.write_u32(VERDEF_OFFSET + 20, 5);
    fixture.write_u32(VERDEF_OFFSET + 24, 0);

    fixture.write_u16(VERNEED_OFFSET, VER_NEED_CURRENT);
    fixture.write_u16(VERNEED_OFFSET + 2, 1);
    fixture.write_u32(VERNEED_OFFSET + 4, 13);
    fixture.write_u32(VERNEED_OFFSET + 8, 16);
    fixture.write_u32(VERNEED_OFFSET + 12, 0);
    fixture.write_u16(VERNEED_OFFSET + 16 + 6, 3);
    fixture.write_u32(VERNEED_OFFSET + 16 + 8, 20);
    fixture.write_u32(VERNEED_OFFSET + 16 + 12, 0);

    image.dynamic.versym = Some(VERSYM_OFFSET as u64);
    image.dynamic.verdef = Some(VERDEF_OFFSET as u64);
    image.dynamic.verdefnum = Some(1);
    image.dynamic.verneed = Some(VERNEED_OFFSET as u64);
    image.dynamic.verneednum = Some(1);
    (
        (fixture.base() + STRTAB_OFFSET) as u64,
        strings.len() as u64,
        (fixture.base() + SYMTAB_OFFSET) as u64,
    )
}

fn push_sleb128(output: &mut Vec<u8>, mut value: i64) {
    loop {
        let byte = (value as u8) & 0x7f;
        let sign = byte & 0x40 != 0;
        value >>= 7;
        let done = (value == 0 && !sign) || (value == -1 && sign);
        output.push(if done { byte } else { byte | 0x80 });
        if done {
            break;
        }
    }
}

fn push_note(output: &mut Vec<u8>, name: &[u8], description: &[u8], kind: u32) {
    output.extend_from_slice(&(name.len() as u32).to_le_bytes());
    output.extend_from_slice(&(description.len() as u32).to_le_bytes());
    output.extend_from_slice(&kind.to_le_bytes());
    output.extend_from_slice(name);
    output.resize(output.len().next_multiple_of(4), 0);
    output.extend_from_slice(description);
    output.resize(output.len().next_multiple_of(4), 0);
}

fn read_sleb128(bytes: &[u8]) -> Result<i64> {
    let mut packed = b"APS2".to_vec();
    packed.extend_from_slice(bytes);
    let maps = [map_for(&packed)];
    let memory = memory(&maps);
    let mut reader = PackedReader::new(&memory, packed.as_ptr() as usize, packed.len())?;
    reader.read_sleb128()
}

fn write_header(fixture: &mut Fixture, class: ElfClass, machine: u16, phoff: u64, phnum: u16) {
    fixture.write(0, ELF_MAGIC);
    fixture.0[4] = class.value();
    fixture.0[5] = ELFDATA2LSB;
    fixture.write_u16(18, machine);
    match class {
        ElfClass::Elf32 => {
            fixture.write_u32(28, phoff as u32);
            fixture.write_u16(42, class.phdr_size() as u16);
            fixture.write_u16(44, phnum);
        }
        ElfClass::Elf64 => {
            fixture.write_u64(32, phoff);
            fixture.write_u16(54, class.phdr_size() as u16);
            fixture.write_u16(56, phnum);
        }
    }
}

fn native_class() -> ElfClass {
    match arch::ELF_CLASS {
        arch::ELFCLASS32 => ElfClass::Elf32,
        arch::ELFCLASS64 => ElfClass::Elf64,
        _ => panic!("unsupported test architecture"),
    }
}

mod build_id;
mod parsing;
mod relocations;
mod symbols;
mod validation;

#[test]
fn hash_functions_match_reference_values() {
    let hashes = |name: &[u8]| super::Hashes::for_name(name);
    assert_eq!(hashes(b"").sysv & 0x0fff_ffff, 0);
    assert_eq!(hashes(b"getpid").sysv, 0x06dc_b6f4);
    assert_eq!(hashes(b"").gnu, 5381);
    assert_eq!(hashes(b"getpid").gnu, 0xff87_8ec2);
}

#[test]
fn gnu_hash_prefilter_matches_exported_symbols_and_hash_collisions() {
    for class in [ElfClass::Elf32, ElfClass::Elf64] {
        let mut fixture = Fixture::new();
        let (strtab, strsz, symtab) = install_symbol(&mut fixture, class);
        install_gnu_hash(&mut fixture, class, b"getpid", 1);
        let mut image = image_for(&fixture, class, arch::MACHINE, false);
        image.dynamic.gnu_hash = Some((fixture.base() + 848) as u64);
        image.dynamic.strtab = Some(strtab);
        image.dynamic.strsz = Some(strsz);
        image.dynamic.symtab = Some(symtab);
        image.dynamic.syment = Some(class.sym_size() as u64);
        let maps = [map_for(&fixture.0)];
        let view = memory(&maps);
        let filter = SymbolHashPrefilter::new(&image, &view);
        let query = ResolvedSymbolQuery {
            output: 0,
            name: b"getpid",
            version: SymbolVersion::Any,
            strtab,
            strsz,
            symtab,
            symbol_count: Some(2),
            versions: None,
        };

        // Symbol 1 lives at or above the GNU hash floor: the chain stores
        // `hash & !1`, so the query hash must match without a shift. A miss
        // here silently drops the relocation as NoMatchingRelocation.
        assert!(filter.may_match(1, Hashes::for_name(query.name)));
        // A query whose 31-bit hash does not appear in the chain is still
        // rejected by the walk; the prefilter must not become a pass-through.
        let other = ResolvedSymbolQuery {
            name: b"a-different-name",
            ..query
        };
        assert!(
            !filter.may_match(1, Hashes::for_name(other.name))
                || Hashes::for_name(other.name).gnu & !1 == Hashes::for_name(b"getpid").gnu & !1
        );
        // Below the GNU hash floor lies the imported-symbol region, which no
        // hash table covers; those indexes must always stay candidates.
        assert!(filter.may_match(0, Hashes::for_name(query.name)));

        // Some aarch64 linkers emit an empty GNU hash table beside a larger
        // dynsym. An all-zero bucket set must not turn exported symbols into
        // prefilter rejections.
        fixture.write_u32(GNU_HASH_OFFSET + 16 + class.pointer_size(), 0);
        let filter = SymbolHashPrefilter::new(&image, &view);
        assert!(filter.may_match(1, Hashes::for_name(query.name)));
    }
}

#[test]
fn sysv_hash_misses_keep_imported_symbols_as_candidates() {
    for class in [ElfClass::Elf32, ElfClass::Elf64] {
        let mut fixture = Fixture::new();
        let (strtab, strsz, symtab) = install_symbol(&mut fixture, class);
        let mut image = image_for(&fixture, class, arch::MACHINE, false);
        image.dynamic.hash = Some((fixture.base() + TABLE_OFFSET) as u64);
        image.dynamic.strtab = Some(strtab);
        image.dynamic.strsz = Some(strsz);
        image.dynamic.symtab = Some(symtab);
        image.dynamic.syment = Some(class.sym_size() as u64);

        fixture.write_u32(TABLE_OFFSET, 1); // nbuckets
        fixture.write_u32(TABLE_OFFSET + 4, 2); // nchain
        fixture.write_u32(TABLE_OFFSET + 8, 1); // bucket
        fixture.write_u32(TABLE_OFFSET + 12, 0); // chain[0]
        fixture.write_u32(TABLE_OFFSET + 16, 0); // chain[1]

        let maps = [map_for(&fixture.0)];
        let view = memory(&maps);
        let filter = SymbolHashPrefilter::new(&image, &view);
        let query = ResolvedSymbolQuery {
            output: 0,
            name: b"getpid",
            version: SymbolVersion::Any,
            strtab,
            strsz,
            symtab,
            symbol_count: Some(2),
            versions: None,
        };

        assert!(filter.may_match(1, Hashes::for_name(query.name)));
        assert!(
            filter.may_match(0, Hashes::for_name(query.name)),
            "an uncovered SysV symbol must stay an import candidate"
        );
    }
}

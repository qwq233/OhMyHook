//! Bounds-checked parsing of loaded ELF images and their dynamic relocations.
//!
//! This module only reads the live address space described by a captured maps
//! snapshot. REL, RELA, and Android APS2 tables all converge on one relocation
//! filter, so a target image is traversed once for the complete symbol batch.

use super::arch::{self, RelocationKind};
use super::target::{Target, loader_image_base};
use super::{SymbolQuery, SymbolVersion};
use crate::maps::{MapInfo, MapPerms, find_map_containing};
use crate::{Error, Result};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::ptr;
use std::sync::Arc;

const ELF_MAGIC: &[u8; 4] = b"\x7fELF";
const ELFDATA2LSB: u8 = 1;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_NOTE: u32 = 4;
const PF_X: u32 = 1;
const SHN_UNDEF: u16 = 0;
const SHN_ABS: u16 = 0xfff1;
const STT_GNU_IFUNC: u8 = 10;
const NT_GNU_BUILD_ID: u32 = 3;

const DT_NULL: i64 = 0;
const DT_PLTRELSZ: i64 = 2;
const DT_HASH: i64 = 4;
const DT_STRTAB: i64 = 5;
const DT_SYMTAB: i64 = 6;
const DT_RELA: i64 = 7;
const DT_RELASZ: i64 = 8;
const DT_RELAENT: i64 = 9;
const DT_STRSZ: i64 = 10;
const DT_SYMENT: i64 = 11;
const DT_REL: i64 = 17;
const DT_RELSZ: i64 = 18;
const DT_RELENT: i64 = 19;
const DT_PLTREL: i64 = 20;
const DT_JMPREL: i64 = 23;
const DT_SYMTABSZ: i64 = 39;
const DT_GNU_HASH: i64 = 0x6fff_fef5;
const DT_VERSYM: i64 = 0x6fff_fff0;
const DT_VERDEF: i64 = 0x6fff_fffc;
const DT_VERDEFNUM: i64 = 0x6fff_fffd;
const DT_VERNEED: i64 = 0x6fff_fffe;
const DT_VERNEEDNUM: i64 = 0x6fff_ffff;

const DT_ANDROID_REL: i64 = 0x6000_000f;
const DT_ANDROID_RELSZ: i64 = 0x6000_0010;
const DT_ANDROID_RELA: i64 = 0x6000_0011;
const DT_ANDROID_RELASZ: i64 = 0x6000_0012;
const DT_AARCH64_PAC_PLT: i64 = 0x7000_0003;

const RELOCATION_GROUPED_BY_INFO: i64 = 1;
const RELOCATION_GROUPED_BY_OFFSET_DELTA: i64 = 2;
const RELOCATION_GROUPED_BY_ADDEND: i64 = 4;
const RELOCATION_GROUP_HAS_ADDEND: i64 = 8;
const KNOWN_GROUP_FLAGS: i64 = RELOCATION_GROUPED_BY_INFO
    | RELOCATION_GROUPED_BY_OFFSET_DELTA
    | RELOCATION_GROUPED_BY_ADDEND
    | RELOCATION_GROUP_HAS_ADDEND;

const MAX_TABLE_SIZE: usize = 128 * 1024 * 1024;
const MAX_PROGRAM_HEADERS: usize = 4 * 1024;
const MAX_DYNAMIC_ENTRIES: usize = 64 * 1024;
const MAX_RELOCATIONS: usize = 16 * 1024 * 1024;
const MAX_VERSION_ENTRIES: usize = 1024 * 1024;
const MAX_BUILD_ID_SIZE: usize = 4 * 1024;
const MAX_BUILD_ID_BYTES: usize = 64 * 1024;
const VER_NDX_MASK: u16 = 0x7fff;
const VER_NDX_GLOBAL: u16 = 1;
const VER_DEF_CURRENT: u16 = 1;
const VER_NEED_CURRENT: u16 = 1;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct ImageId {
    pub(crate) device: crate::DeviceId,
    pub(crate) inode: u64,
    pub(crate) header: usize,
    pub(crate) load_bias: usize,
    pub(crate) elf_header_offset: u64,
    pub(crate) loader_base: Option<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FoundRelocation {
    pub(crate) address: usize,
    pub(crate) image: ImageId,
    pub(crate) kind: RelocationKind,
    pub(crate) addend: i64,
    pub(crate) jump_slot_state: JumpSlotState,
    pub(crate) aarch64_pac_plt: bool,
    _validated_mapping: (),
}

pub(crate) struct FoundRelocations {
    pub(crate) by_symbol: Vec<FoundSymbolRelocations>,
    pub(crate) images: Vec<FoundImage>,
}

pub(crate) struct FoundSymbolRelocations {
    pub(crate) relocations: Vec<FoundRelocation>,
    pub(crate) rejected: Vec<RejectedRelocation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RejectedRelocation {
    pub(crate) address: usize,
    pub(crate) image: ImageId,
    pub(crate) kind: RelocationKind,
    pub(crate) addend: Option<i64>,
    pub(crate) reason: RelocationRejection,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RelocationRejection {
    Aarch64PacPlt,
    ImplicitAddend,
    UnsupportedAddend,
}

pub(crate) struct FoundImage {
    pub(crate) id: ImageId,
    pub(crate) load_ranges: Vec<(usize, usize)>,
    pub(crate) build_id: Option<Arc<[u8]>>,
}

struct DiscoveredImage {
    image: Image,
    maps: Vec<MapInfo>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum JumpSlotState {
    Resolved,
    Lazy(usize),
    AmbiguousIfunc,
}

#[derive(Clone, Copy)]
enum ElfClass {
    Elf32,
    Elf64,
}

impl ElfClass {
    fn from_ident(value: u8) -> Result<Self> {
        match value {
            arch::ELFCLASS32 => Ok(Self::Elf32),
            arch::ELFCLASS64 => Ok(Self::Elf64),
            other => Err(Error::UnsupportedElfClass(other)),
        }
    }

    const fn value(self) -> u8 {
        match self {
            Self::Elf32 => arch::ELFCLASS32,
            Self::Elf64 => arch::ELFCLASS64,
        }
    }

    const fn ehdr_size(self) -> usize {
        match self {
            Self::Elf32 => 52,
            Self::Elf64 => 64,
        }
    }

    const fn phdr_size(self) -> usize {
        match self {
            Self::Elf32 => 32,
            Self::Elf64 => 56,
        }
    }

    const fn dyn_size(self) -> usize {
        match self {
            Self::Elf32 => 8,
            Self::Elf64 => 16,
        }
    }

    const fn sym_size(self) -> usize {
        match self {
            Self::Elf32 => 16,
            Self::Elf64 => 24,
        }
    }

    const fn sym_shndx_offset(self) -> usize {
        match self {
            Self::Elf32 => 14,
            Self::Elf64 => 6,
        }
    }

    const fn sym_info_offset(self) -> usize {
        match self {
            Self::Elf32 => 12,
            Self::Elf64 => 4,
        }
    }

    const fn pointer_size(self) -> usize {
        match self {
            Self::Elf32 => 4,
            Self::Elf64 => 8,
        }
    }

    const fn rel_size(self, format: RelFormat) -> usize {
        match (self, format) {
            (Self::Elf32, RelFormat::Rel) => 8,
            (Self::Elf32, RelFormat::Rela) => 12,
            (Self::Elf64, RelFormat::Rel) => 16,
            (Self::Elf64, RelFormat::Rela) => 24,
        }
    }

    fn decode_info(self, info: u64) -> Result<(u32, u32)> {
        match self {
            Self::Elf32 => {
                let info = u32::try_from(info).map_err(|_| Error::InvalidElf("ELF32 r_info"))?;
                Ok((info >> 8, info & 0xff))
            }
            Self::Elf64 => Ok(((info >> 32) as u32, info as u32)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RelFormat {
    Rel,
    Rela,
}

#[derive(Clone, Copy)]
struct ElfHeader {
    class: ElfClass,
    machine: u16,
    phoff: u64,
    phentsize: u16,
    phnum: u16,
}

#[derive(Clone, Copy)]
struct ProgramHeader {
    kind: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
}

#[derive(Default)]
struct DynamicInfo {
    hash: Option<u64>,
    strtab: Option<u64>,
    strsz: Option<u64>,
    symtab: Option<u64>,
    syment: Option<u64>,
    symtabsz: Option<u64>,
    gnu_hash: Option<u64>,
    rel: Option<u64>,
    relsz: Option<u64>,
    relent: Option<u64>,
    rela: Option<u64>,
    relasz: Option<u64>,
    relaent: Option<u64>,
    jmprel: Option<u64>,
    pltrelsz: Option<u64>,
    pltrel: Option<u64>,
    android_rel: Option<u64>,
    android_relsz: Option<u64>,
    android_rela: Option<u64>,
    android_relasz: Option<u64>,
    versym: Option<u64>,
    verdef: Option<u64>,
    verdefnum: Option<u64>,
    verneed: Option<u64>,
    verneednum: Option<u64>,
    duplicate_versym: bool,
    duplicate_version_tag: bool,
    aarch64_pac_plt: bool,
}

#[derive(Default)]
struct VersionMetadata {
    versym: Option<usize>,
    definitions: BTreeMap<u16, u32>,
    requirements: BTreeMap<u16, u32>,
}

struct RelocationSet<T> {
    first: Option<(usize, T)>,
    rest: BTreeMap<usize, T>,
}

impl<T> Default for RelocationSet<T> {
    fn default() -> Self {
        Self {
            first: None,
            rest: BTreeMap::new(),
        }
    }
}

impl<T> RelocationSet<T> {
    fn contains_key(&self, address: &usize) -> bool {
        self.first
            .as_ref()
            .is_some_and(|(first, _)| first == address)
            || self.rest.contains_key(address)
    }

    fn into_values(self) -> impl Iterator<Item = T> {
        self.first
            .into_iter()
            .map(|(_, value)| value)
            .chain(self.rest.into_values())
    }
}

impl<T: PartialEq> RelocationSet<T> {
    fn insert(&mut self, address: usize, value: T) -> Result<()> {
        if let Some((first_address, first_value)) = self.first.as_ref() {
            if *first_address == address {
                return if *first_value == value {
                    Ok(())
                } else {
                    Err(Error::InvalidElf("conflicting relocations for one slot"))
                };
            }
            if let Some(first) = self.first.take() {
                self.rest.insert(first.0, first.1);
            }
            self.rest.insert(address, value);
            return Ok(());
        }
        if self.rest.is_empty() {
            self.first = Some((address, value));
            return Ok(());
        }
        match self.rest.entry(address) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(value);
                Ok(())
            }
            std::collections::btree_map::Entry::Occupied(entry) if entry.get() != &value => {
                Err(Error::InvalidElf("conflicting relocations for one slot"))
            }
            std::collections::btree_map::Entry::Occupied(_) => Ok(()),
        }
    }
}

#[derive(Default)]
struct RelocationScan {
    matches: RelocationSet<FoundRelocation>,
    rejected: RelocationSet<RejectedRelocation>,
    unsupported_implicit_addend: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SymbolMatch {
    Mismatch,
    Match {
        undefined: bool,
        definition: Option<usize>,
        ifunc: bool,
    },
}

struct Memory<'a> {
    maps: &'a [MapInfo],
}

impl<'a> Memory<'a> {
    unsafe fn new(maps: &'a [MapInfo]) -> Self {
        Self { maps }
    }

    fn read_array<const N: usize>(&self, address: usize) -> Result<[u8; N]> {
        if self.is_readable(address, N) {
            // SAFETY: the complete scalar is inside one live readable mapping
            // and the Memory invariant keeps it stable for this read.
            return Ok(unsafe {
                ptr::read_unaligned(ptr::with_exposed_provenance::<[u8; N]>(address))
            });
        }
        let mut bytes = [0_u8; N];
        self.read_into(address, &mut bytes)?;
        Ok(bytes)
    }

    fn read_into(&self, mut address: usize, output: &mut [u8]) -> Result<()> {
        let mut written = 0;
        while written < output.len() {
            let map = self
                .readable_map(address)
                .ok_or_else(|| Error::UnmappedRead {
                    address,
                    length: output.len() - written,
                })?;
            let available = map
                .end
                .checked_sub(address)
                .ok_or(Error::ArithmeticOverflow)?;
            let length = available.min(output.len() - written);
            if length == 0 {
                return Err(Error::UnmappedRead {
                    address,
                    length: output.len() - written,
                });
            }
            // SAFETY: the Memory invariant keeps this exact source range live,
            // readable, and stable. `ptr::copy` also permits overlap with the
            // caller-provided destination.
            unsafe {
                ptr::copy(
                    ptr::with_exposed_provenance(address),
                    output.as_mut_ptr().add(written),
                    length,
                );
            }
            address = address
                .checked_add(length)
                .ok_or(Error::ArithmeticOverflow)?;
            written += length;
        }
        Ok(())
    }

    fn read_u8(&self, address: usize) -> Result<u8> {
        Ok(self.read_array::<1>(address)?[0])
    }

    fn read_u16(&self, address: usize) -> Result<u16> {
        Ok(u16::from_le_bytes(self.read_array(address)?))
    }

    fn read_u32(&self, address: usize) -> Result<u32> {
        Ok(u32::from_le_bytes(self.read_array(address)?))
    }

    fn read_i32(&self, address: usize) -> Result<i32> {
        Ok(i32::from_le_bytes(self.read_array(address)?))
    }

    fn read_u64(&self, address: usize) -> Result<u64> {
        Ok(u64::from_le_bytes(self.read_array(address)?))
    }

    fn read_i64(&self, address: usize) -> Result<i64> {
        Ok(i64::from_le_bytes(self.read_array(address)?))
    }

    fn matches_c_string(
        &self,
        mut address: usize,
        available: usize,
        expected: &[u8],
    ) -> Result<bool> {
        let required = expected
            .len()
            .checked_add(1)
            .ok_or(Error::ArithmeticOverflow)?;
        if required > available {
            return Ok(false);
        }
        let mut matched = 0;
        while matched < expected.len() {
            let map = self
                .readable_map(address)
                .ok_or_else(|| Error::UnmappedRead {
                    address,
                    length: expected.len() - matched,
                })?;
            let length = (map.end - address).min(expected.len() - matched);
            // SAFETY: `readable_map` proves this exact source range is live and
            // readable for the Memory lifetime.
            let actual: &[u8] = unsafe {
                std::slice::from_raw_parts(ptr::with_exposed_provenance(address), length)
            };
            if actual != &expected[matched..matched + length] {
                return Ok(false);
            }
            address = address
                .checked_add(length)
                .ok_or(Error::ArithmeticOverflow)?;
            matched += length;
        }
        Ok(self.read_u8(address)? == 0)
    }

    fn compare_c_string(
        &self,
        mut address: usize,
        available: usize,
        expected: &[u8],
    ) -> Result<Ordering> {
        let mut compared = 0;
        while compared < available {
            let map = self
                .readable_map(address)
                .ok_or(Error::UnmappedRead { address, length: 1 })?;
            let length = (map.end - address).min(available - compared);
            // SAFETY: `readable_map` proves this exact source range is live and
            // readable for the Memory lifetime.
            let actual: &[u8] = unsafe {
                std::slice::from_raw_parts(ptr::with_exposed_provenance(address), length)
            };
            let common = length.min(expected.len().saturating_sub(compared));
            match actual[..common].cmp(&expected[compared..compared + common]) {
                Ordering::Equal => {}
                ordering => return Ok(ordering),
            }
            if common < length {
                return Ok(if actual[common] == 0 {
                    Ordering::Equal
                } else {
                    Ordering::Greater
                });
            }
            address = address
                .checked_add(length)
                .ok_or(Error::ArithmeticOverflow)?;
            compared += length;
        }
        Ok(Ordering::Less)
    }

    fn is_readable(&self, address: usize, length: usize) -> bool {
        self.readable_map(address)
            .is_some_and(|map| map.contains_range(address, length))
    }

    fn is_fully_readable(&self, mut address: usize, length: usize) -> bool {
        let Some(end) = address.checked_add(length) else {
            return false;
        };
        while address < end {
            let Some(map) = self.readable_map(address) else {
                return false;
            };
            address = map.end.min(end);
        }
        true
    }

    fn readable_map(&self, address: usize) -> Option<&MapInfo> {
        find_map_containing(self.maps, address, 1).filter(|map| map.perms.contains(MapPerms::READ))
    }
}

struct Image {
    id: ImageId,
    header: ElfHeader,
    dynamic: DynamicInfo,
    load_ranges: Vec<(usize, usize)>,
    notes: Vec<ProgramHeader>,
}

struct ResolvedSymbolQuery<'a> {
    output: usize,
    name: &'a [u8],
    version: SymbolVersion<'a>,
    strtab: u64,
    strsz: u64,
    symtab: u64,
    symbol_count: u32,
    versions: Option<&'a VersionMetadata>,
}

struct SymbolTables<'a> {
    symtab: Option<(usize, &'a [u8])>,
    strtab: Option<(usize, &'a [u8])>,
}

impl<'a> SymbolTables<'a> {
    fn new(
        memory: &'a Memory<'_>,
        queries: &[ResolvedSymbolQuery<'_>],
        class: ElfClass,
        load_ranges: &[(usize, usize)],
    ) -> Self {
        let Some(first) = queries.first() else {
            return Self {
                symtab: None,
                strtab: None,
            };
        };
        if queries.iter().any(|query| {
            query.symtab != first.symtab
                || query.symbol_count != first.symbol_count
                || query.strtab != first.strtab
                || query.strsz != first.strsz
        }) {
            return Self {
                symtab: None,
                strtab: None,
            };
        }

        let symtab = u64::from(first.symbol_count)
            .checked_mul(class.sym_size() as u64)
            .and_then(|size| usize::try_from(size).ok())
            .filter(|size| *size != 0 && *size <= MAX_TABLE_SIZE)
            .and_then(|size| {
                let address = absolute_address(first.symtab).ok()?;
                (range_in_ranges(address, size, load_ranges) && memory.is_readable(address, size))
                    .then(|| {
                        // SAFETY: the complete table is inside one live readable
                        // mapping and this Image's PT_LOAD for the Memory lifetime.
                        let bytes = unsafe {
                            std::slice::from_raw_parts(ptr::with_exposed_provenance(address), size)
                        };
                        (address, bytes)
                    })
            });
        let strtab = usize::try_from(first.strsz)
            .ok()
            .filter(|size| *size != 0 && *size <= MAX_TABLE_SIZE)
            .and_then(|size| {
                let address = absolute_address(first.strtab).ok()?;
                (range_in_ranges(address, size, load_ranges) && memory.is_readable(address, size))
                    .then(|| {
                        // SAFETY: the complete table is inside one live readable
                        // mapping and this Image's PT_LOAD for the Memory lifetime.
                        let bytes = unsafe {
                            std::slice::from_raw_parts(ptr::with_exposed_provenance(address), size)
                        };
                        (address, bytes)
                    })
            });
        Self { symtab, strtab }
    }

    fn symbol(&self, address: usize, size: usize) -> Option<&'a [u8]> {
        let (start, bytes) = self.symtab?;
        let offset = address.checked_sub(start)?;
        let end = offset.checked_add(size)?;
        bytes.get(offset..end)
    }

    fn compare_c_string(
        &self,
        address: usize,
        available: usize,
        expected: &[u8],
    ) -> Option<Ordering> {
        let (start, bytes) = self.strtab?;
        let offset = address.checked_sub(start)?;
        let end = offset.checked_add(available)?;
        let actual = bytes.get(offset..end)?;
        let common = actual.len().min(expected.len());
        match actual[..common].cmp(&expected[..common]) {
            Ordering::Equal => {}
            ordering => return Some(ordering),
        }
        Some(if common == actual.len() {
            Ordering::Less
        } else if actual[common] == 0 {
            Ordering::Equal
        } else {
            Ordering::Greater
        })
    }

    fn matches_c_string(&self, address: usize, available: usize, expected: &[u8]) -> Option<bool> {
        let required = expected.len().checked_add(1)?;
        if required > available {
            return Some(false);
        }
        let (start, bytes) = self.strtab?;
        let offset = address.checked_sub(start)?;
        let end = offset.checked_add(required)?;
        let actual = bytes.get(offset..end)?;
        Some(actual[..expected.len()] == *expected && actual[expected.len()] == 0)
    }
}

impl Image {
    fn gnu_build_id(&self, memory: &Memory<'_>) -> Result<Option<Arc<[u8]>>> {
        let mut found: Option<Arc<[u8]>> = None;
        let mut build_id_bytes = 0_usize;
        for note in &self.notes {
            let size = usize::try_from(note.filesz).map_err(|_| Error::ArithmeticOverflow)?;
            if size == 0 {
                continue;
            }
            let start = runtime_address(self.id.load_bias, note.vaddr)?;
            if !address_in_ranges(start, &self.load_ranges) || memory.readable_map(start).is_none()
            {
                continue;
            }
            if size > MAX_TABLE_SIZE
                || !range_in_ranges(start, size, &self.load_ranges)
                || !memory.is_fully_readable(start, size)
            {
                return Err(Error::InvalidElf("PT_NOTE exceeds readable PT_LOAD"));
            }
            let end = checked_add(start, size)?;
            let mut cursor = start;
            while cursor < end {
                if end - cursor < 12 {
                    return Err(Error::InvalidElf("truncated ELF note header"));
                }
                let name_size = usize::try_from(memory.read_u32(cursor)?)
                    .map_err(|_| Error::ArithmeticOverflow)?;
                let description_size = usize::try_from(memory.read_u32(checked_add(cursor, 4)?)?)
                    .map_err(|_| Error::ArithmeticOverflow)?;
                let kind = memory.read_u32(checked_add(cursor, 8)?)?;
                let name = checked_add(cursor, 12)?;
                let description = checked_add(name, align_note_size(name_size)?)?;
                let next = checked_add(description, align_note_size(description_size)?)?;
                if checked_add(name, name_size)? > end
                    || checked_add(description, description_size)? > end
                    || next > end
                {
                    return Err(Error::InvalidElf("ELF note payload exceeds PT_NOTE"));
                }

                if kind == NT_GNU_BUILD_ID
                    && name_size == 4
                    && memory.read_array::<4>(name)? == *b"GNU\0"
                {
                    if description_size > MAX_BUILD_ID_SIZE {
                        return Err(Error::InvalidElf("GNU build-id is too large"));
                    }
                    build_id_bytes = build_id_bytes
                        .checked_add(description_size)
                        .ok_or(Error::ArithmeticOverflow)?;
                    if build_id_bytes > MAX_BUILD_ID_BYTES {
                        return Err(Error::InvalidElf("too many GNU build-id bytes"));
                    }
                    let mut identifier = vec![0_u8; description_size];
                    memory.read_into(description, &mut identifier)?;
                    match &found {
                        None => found = Some(Arc::<[u8]>::from(identifier)),
                        Some(existing) if existing.as_ref() == identifier => {}
                        Some(_) => {
                            return Err(Error::InvalidElf("conflicting GNU build-id notes"));
                        }
                    }
                }
                cursor = next;
            }
        }
        Ok(found)
    }
}

fn align_note_size(size: usize) -> Result<usize> {
    size.checked_add(3)
        .map(|value| value & !3)
        .ok_or(Error::ArithmeticOverflow)
}

fn runtime_address(load_bias: usize, virtual_address: u64) -> Result<usize> {
    checked_add_u64(load_bias, virtual_address)
}

fn absolute_address(address: u64) -> Result<usize> {
    usize::try_from(address).map_err(|_| Error::ArithmeticOverflow)
}

fn checked_add_u64(base: usize, offset: u64) -> Result<usize> {
    let offset = usize::try_from(offset).map_err(|_| Error::ArithmeticOverflow)?;
    checked_add(base, offset)
}

fn checked_add(base: usize, offset: usize) -> Result<usize> {
    base.checked_add(offset).ok_or(Error::ArithmeticOverflow)
}

mod discover;
mod parse;
mod relocation;
mod scan;
mod version;
pub(crate) use discover::find_loaded_images;
use discover::{discover_images, maps_in_ranges, merge_ranges};
pub(crate) use parse::range_in_ranges;
use parse::{address_in_ranges, parse_image, resolve_dynamic_pointer};
pub(crate) use scan::find_symbol_relocations;

#[cfg(test)]
mod tests;

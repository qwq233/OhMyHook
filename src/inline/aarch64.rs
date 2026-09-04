use super::{Generated, TransientBytes, patch};
use crate::maps::{MapInfo, MappingSnapshot, find_map_containing, read_self_smaps_for_ranges};
use crate::{Error, Result};
use std::cell::Cell;

const BTI_J: u32 = 0xd503_249f;
const BTI_JC: u32 = 0xd503_24df;
const BTI_C: u32 = 0xd503_245f;
const BTI: u32 = 0xd503_241f;
const NOP: u32 = 0xd503_201f;
const BR_X16: u32 = 0xd61f_0200;
const MAX_DISTANCE: usize = (128 * 1024 * 1024) - 4;

/// Per-hook replacement BTI state, cached for the current preparation call.
pub(super) struct ReplacementBti {
    pub(super) hint: bool,
    pub(super) cache: Cell<Option<bool>>,
}

/// Returns whether the replacement page is actually BTI-guarded.
///
/// The instruction hint is only a fast path; an indirect relay must use the
/// VMA's real protection state.
fn replacement_bti_guarded(
    maps: &[MapInfo],
    replacement: usize,
    state: &ReplacementBti,
) -> Result<bool> {
    if let Some(cached) = state.cache.get() {
        return Ok(cached);
    }
    if maps.is_empty() {
        return Ok(state.hint);
    }
    let guarded = page_bti_guarded(maps, replacement)?;
    state.cache.set(Some(guarded));
    Ok(guarded)
}

pub(super) fn page_bti_guarded(maps: &[MapInfo], address: usize) -> Result<bool> {
    let page_size = crate::sys::page_size()?;
    let start = crate::sys::page_start(address, page_size);
    let end = start
        .checked_add(page_size)
        .ok_or(Error::ArithmeticOverflow)?;
    let map = find_map_containing(maps, address, 4)
        .filter(|map| map.perms.contains(crate::maps::MapPerms::EXEC))
        .ok_or(Error::MappingChanged)?;
    let identity = MappingSnapshot::from_map(map);
    let smaps = read_self_smaps_for_ranges(&[(start, end)])?;
    let entry = smaps
        .iter()
        .find(|entry| entry.map.contains_range(start, page_size))
        .filter(|entry| identity.matches(&entry.map))
        .ok_or(Error::MappingChanged)?;
    Ok(entry.vm_flags.bti)
}
/// The page size `ADR`/`ADRP` and the literal forms name in their encodings.
///
/// This is the architectural 4 KiB granule, not the runtime page size: the
/// instruction set defines these displacements against this granule even when
/// the kernel maps the page larger.
const ARCH_PAGE: usize = 4096;
const ARCH_PAGE_MASK: usize = ARCH_PAGE - 1;
pub(super) const WINDOW_LENGTH: usize = 20;
pub(super) const FAR_READ_LENGTH: usize = 32;
const FAR_PATCH_LENGTH: usize = 28;
const NEAR_FAR_PATCH_LENGTH: usize = 12;
const COMPACT_FAR_PATCH_LENGTH: usize = 16;

pub(super) struct Analysis {
    pub(super) patch_address: usize,
    pub(super) original: Vec<u8>,
    pac_landing: bool,
    relocations: Vec<Relocation>,
    pub(super) address_references: Vec<AddressReference>,
    pub(super) far: bool,
    pub(super) near_far: bool,
}

/// An ADR or ADRP destination whose value later instructions may consume.
pub(super) struct AddressReference {
    pub(super) address: usize,
    pub(super) register: u32,
    pub(super) target: usize,
}

impl Drop for Analysis {
    fn drop(&mut self) {
        crate::sys::erase_bytes(&mut self.original);
    }
}

enum Relocation {
    Copy(u32),
    Terminal(u32),
    Branch(usize),
    Conditional {
        instruction: u32,
        target: usize,
    },
    Adr {
        register: u32,
        target: usize,
    },
    Literal {
        instruction: u32,
        target: usize,
        width: usize,
    },
}

pub(super) fn analyze(target: usize, code: &[u8]) -> Result<Analysis> {
    if !target.is_multiple_of(4) {
        return Err(Error::InvalidInlineTarget(
            "AArch64 entry is not 4-byte aligned",
        ));
    }
    let first = read_word(code, 0)?;
    if is_pac_landing(first) {
        let mut analysis = analyze_inplace_variant(
            target,
            code,
            InplaceVariant {
                patch_length: 8,
                minimum_terminal_index: 1,
                near_far: false,
                require_final_control_flow: false,
                length_reason: "AArch64 PAC entry needs a landing and branch",
                terminal_reason: "AArch64 PAC entry ends before its branch fits",
            },
        )?;
        analysis.far = false;
        return Ok(analysis);
    }
    let landing = usize::from(is_bti(first)) * 4;
    let patch_address = target
        .checked_add(landing)
        .ok_or(Error::ArithmeticOverflow)?;
    let instruction = read_word(code, landing)?;
    let relocation = classify(instruction, patch_address)?;
    let address_references = match &relocation {
        Relocation::Adr { register, target } if *register <= 30 => vec![AddressReference {
            address: patch_address,
            register: *register,
            target: *target,
        }],
        _ => Vec::new(),
    };
    let patch_end = patch_address
        .checked_add(4)
        .ok_or(Error::ArithmeticOverflow)?;
    if let Relocation::Literal { target, width, .. } = &relocation {
        let literal_end = target
            .checked_add(*width)
            .ok_or(Error::ArithmeticOverflow)?;
        if *target < patch_end && patch_address < literal_end {
            return Err(unsupported(
                patch_address,
                "PC-relative data overlaps stolen instruction",
            ));
        }
    }
    if let Relocation::Adr { target, .. } = &relocation {
        // ADRP consumers are checked by the data-reference scan after analysis.
        let overlaps =
            instruction & 0x9f00_0000 != 0x9000_0000 && (patch_address..patch_end).contains(target);
        if overlaps {
            return Err(unsupported(
                patch_address,
                "PC-relative address overlaps stolen instruction",
            ));
        }
    }
    Ok(Analysis {
        patch_address,
        original: instruction.to_le_bytes().to_vec(),
        pac_landing: landing == 0 && is_pac_landing(first),
        relocations: vec![relocation],
        address_references,
        far: false,
        near_far: false,
    })
}

pub(super) fn max_distance(analysis: &Analysis, _replacement: usize) -> usize {
    if analysis.far {
        // External branches constrain placement separately from the entry.
        usize::MAX
    } else {
        MAX_DISTANCE
    }
}

pub(super) fn far_branch_window(analysis: &Analysis, guarded: bool) -> Option<(usize, usize)> {
    if !analysis.far {
        return None;
    }
    let original_end = analysis
        .patch_address
        .saturating_add(analysis.original.len());
    let mut offset_min = usize::from(guarded) * 4;
    let mut offset_max = offset_min;
    let mut window = None;
    for relocation in &analysis.relocations {
        let branch = match relocation {
            Relocation::Branch(target) => Some((*target, 0)),
            Relocation::Conditional { target, .. } => Some((*target, 4)),
            _ => None,
        };
        if let Some((target, extra)) = branch
            && !(analysis.patch_address..original_end).contains(&target)
        {
            // Keep every possible layout; allocation retries adjacent pages
            // when compact ADR expansion makes a boundary candidate unusable.
            let low = target.saturating_sub(MAX_DISTANCE + offset_max + extra);
            let high = target.saturating_add(MAX_DISTANCE + 4 - offset_min - extra);
            let (previous_low, previous_high) = window.unwrap_or((0, usize::MAX));
            window = Some((previous_low.max(low), previous_high.min(high)));
        }
        match relocation {
            Relocation::Adr { .. } => {
                offset_min += 4;
                offset_max += 16;
            }
            Relocation::Literal { width, .. } => {
                offset_min = (offset_min + 8).next_multiple_of(*width) + width;
                offset_max = (offset_max + 8).next_multiple_of(*width) + width;
            }
            Relocation::Conditional { .. } => {
                offset_min += 8;
                offset_max += 8;
            }
            _ => {
                offset_min += 4;
                offset_max += 4;
            }
        }
    }
    // At most eight stolen instructions expand to fewer than 256 bytes, so
    // only one page at either end can depend on the compact-address layout.
    debug_assert!(offset_max < ARCH_PAGE);
    window
}

pub(super) const fn mapped_target(target: usize) -> Result<usize> {
    if !target.is_multiple_of(4) {
        return Err(Error::InvalidInlineTarget(
            "AArch64 target is not 4-byte aligned",
        ));
    }
    Ok(target)
}

pub(super) const fn mapped_replacement(replacement: usize) -> Result<usize> {
    if !replacement.is_multiple_of(4) {
        return Err(Error::InvalidInlineTarget(
            "AArch64 replacement is not 4-byte aligned",
        ));
    }
    Ok(replacement)
}

pub(super) fn entry_needs_page_flags(instruction: u32) -> bool {
    is_bti(instruction) || is_pac_landing(instruction)
}

pub(super) fn redirects_to(
    analysis: &Analysis,
    replacement: usize,
    maps: &[MapInfo],
) -> Result<bool> {
    let patch_length = analysis.original.len();
    if patch::validate_executable_entry(maps, analysis.patch_address, patch_length).is_ok() {
        // SAFETY: validation covers the complete in-place far patch.
        let live = unsafe {
            std::slice::from_raw_parts(
                std::ptr::with_exposed_provenance::<u8>(analysis.patch_address),
                patch_length,
            )
        };
        if is_ldr_x16_br(live, replacement) {
            return Ok(true);
        }
        if page_relative_literal_matches(live, analysis.patch_address, replacement, maps) {
            return Ok(true);
        }
    }
    let Some(instruction) = analysis
        .original
        .get(..4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
    else {
        return Ok(false);
    };
    let Some(destination) = unconditional_branch_target(analysis.patch_address, instruction) else {
        return Ok(false);
    };
    if destination == replacement {
        return Ok(true);
    }
    if trampoline_redirects_to(analysis, replacement, maps)? {
        return Ok(true);
    }
    let probe = patch::probe_maps(maps, destination, 16)?;
    let validation_maps = probe.as_deref().unwrap_or(maps);
    if patch::validate_executable_entry(validation_maps, destination, 16).is_err() {
        return Ok(false);
    }
    // SAFETY: validation covers the complete relay sequence.
    let relay = unsafe {
        std::slice::from_raw_parts(std::ptr::with_exposed_provenance::<u8>(destination), 16)
    };
    let first = u32::from_le_bytes([relay[0], relay[1], relay[2], relay[3]]);
    if unconditional_branch_target(destination, first) == Some(replacement) {
        return Ok(true);
    }
    if is_ldr_x16_br(relay, replacement) {
        return Ok(true);
    }
    if page_relative_literal_matches(relay, destination, replacement, validation_maps) {
        return Ok(true);
    }
    if patch::validate_executable_entry(validation_maps, destination, 20).is_err() {
        return Ok(false);
    }
    // SAFETY: the 20-byte MOVZ/MOVK + BR sequence was just validated.
    let relay = unsafe {
        std::slice::from_raw_parts(std::ptr::with_exposed_provenance::<u8>(destination), 20)
    };
    Ok(is_movk_x16_relay(relay, replacement))
}

/// Reports whether a live entry branch leads into this entry's own trampoline.
///
/// The installer publishes the trampoline with one direct branch, so auditing
/// an already-installed entry has to follow that branch into the arena and
/// recognise its absolute branch to the replacement, not only a redirected
/// first instruction.
fn trampoline_redirects_to(
    analysis: &Analysis,
    replacement: usize,
    maps: &[MapInfo],
) -> Result<bool> {
    if analysis.original.len() < 4 {
        return Ok(false);
    }
    if patch::validate_executable_entry(maps, analysis.patch_address, 4).is_err() {
        return Ok(false);
    }
    // SAFETY: validation just proved the live entry readable for one word.
    let entry = unsafe {
        u32::from_le(std::ptr::read_unaligned(std::ptr::with_exposed_provenance(
            analysis.patch_address,
        )))
    };
    let Some(arena) = decoded_branch_target(analysis.patch_address, entry) else {
        return Ok(false);
    };
    // A far replacement puts the relay at the arena head, so the relocated
    // block is found by its landing instead of by a fixed offset.
    let scan = analysis
        .original
        .len()
        .checked_add(32)
        .ok_or(Error::ArithmeticOverflow)?;
    if patch::validate_executable_entry(maps, arena, scan).is_err() {
        return Ok(false);
    }
    // SAFETY: validation covers the complete scanned span, and the caller keeps
    // the arena live and writer-exclusive.
    let words = unsafe {
        std::slice::from_raw_parts(std::ptr::with_exposed_provenance::<u32>(arena), scan / 4)
    };
    let Some(index) = words.iter().position(|word| is_bti(*word)) else {
        return Ok(false);
    };
    let Some(first) = arena
        .checked_add(index * 4)
        .and_then(|landing| landing.checked_add(4))
    else {
        return Err(Error::ArithmeticOverflow);
    };
    if patch::validate_executable_entry(maps, first, analysis.original.len() + 4).is_err() {
        return Ok(false);
    }
    // SAFETY: the relocated window and its back edge were just validated.
    let relocated = unsafe {
        u32::from_le(std::ptr::read_unaligned(std::ptr::with_exposed_provenance(
            first,
        )))
    };
    let captured = u32::from_le_bytes([
        analysis.original[0],
        analysis.original[1],
        analysis.original[2],
        analysis.original[3],
    ]);
    if relocated != captured {
        return Ok(false);
    }
    let Some(back_edge) = first.checked_add(analysis.original.len()) else {
        return Err(Error::ArithmeticOverflow);
    };
    if patch::validate_executable_entry(maps, back_edge, 4).is_err() {
        return Ok(false);
    }
    // SAFETY: validation covers the back edge word, and the caller keeps the
    // trampoline live and writer-exclusive.
    let back = unsafe {
        u32::from_le(std::ptr::read_unaligned(std::ptr::with_exposed_provenance(
            back_edge,
        )))
    };
    // A trampoline belongs to this entry when its back edge returns to the
    // instruction the patch replaced and its relay reaches the replacement.
    let continuation = analysis
        .patch_address
        .checked_add(analysis.original.len())
        .ok_or(Error::ArithmeticOverflow)?;
    if decoded_branch_target(back_edge, back) != Some(continuation) {
        return Ok(false);
    }
    let mut relay = [0_u8; 16];
    for (index, &word) in words.iter().take(4).enumerate() {
        relay[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    Ok(decoded_branch_target(arena, words[0]) == Some(replacement)
        || is_ldr_x16_br(&relay, replacement)
        || page_relative_literal_matches(&relay, arena, replacement, maps))
}

/// Decodes an unconditional `B` without the branch-depth bookkeeping the
/// analysis walker applies while it steps through a target entry.
fn decoded_branch_target(from: usize, instruction: u32) -> Option<usize> {
    if instruction & 0xfc00_0000 != 0x1400_0000 {
        return None;
    }
    let immediate = sign_extend(u64::from(instruction & 0x03ff_ffff), 26).checked_mul(4)?;
    add_signed(from, immediate).ok()
}

/// Reports whether the `adrp`/`ldr`/`br x16` sequence at `address` loads
/// exactly `replacement` from its page-relative literal.
fn page_relative_literal_matches(
    bytes: &[u8],
    address: usize,
    replacement: usize,
    maps: &[MapInfo],
) -> bool {
    let Some(literal) = page_relative_literal(bytes, address) else {
        return false;
    };
    let probe = patch::probe_maps(maps, literal, 8).ok().flatten();
    let validation_maps = probe.as_deref().unwrap_or(maps);
    if patch::validate_executable_entry(validation_maps, literal, 8).is_err() {
        return false;
    }
    // SAFETY: the literal address was validated as a live readable mapping
    // and no writer may change it under the caller's contract.
    let value = unsafe {
        u64::from_le(std::ptr::read_unaligned(std::ptr::with_exposed_provenance(
            literal,
        )))
    };
    value as usize == replacement
}

pub(super) fn branch_reaches(from: usize, to: usize) -> bool {
    encode_b(from, to).is_ok()
}

struct InplaceVariant {
    patch_length: usize,
    minimum_terminal_index: usize,
    near_far: bool,
    require_final_control_flow: bool,
    length_reason: &'static str,
    terminal_reason: &'static str,
}

/// Analyzes the 28-byte far-patch window and its relocations, extended for PAC prefixes.
pub(super) fn analyze_inplace_far(target: usize, code: &[u8]) -> Result<Analysis> {
    analyze_inplace_variant(
        target,
        code,
        InplaceVariant {
            patch_length: FAR_PATCH_LENGTH,
            minimum_terminal_index: 6,
            near_far: false,
            require_final_control_flow: false,
            length_reason: "AArch64 in-place far jump needs 28 bytes",
            terminal_reason: "AArch64 in-place far jump ends before the following instruction",
        },
    )
}

pub(super) fn analyze_inplace_near_far(target: usize, code: &[u8]) -> Result<Analysis> {
    analyze_inplace_variant(
        target,
        code,
        InplaceVariant {
            patch_length: NEAR_FAR_PATCH_LENGTH,
            minimum_terminal_index: 2,
            near_far: true,
            require_final_control_flow: false,
            length_reason: "AArch64 in-place near-far jump needs 12 bytes",
            terminal_reason: "AArch64 in-place near-far jump ends before the following instruction",
        },
    )
}

pub(super) fn analyze_inplace_compact_far(target: usize, code: &[u8]) -> Result<Analysis> {
    analyze_inplace_variant(
        target,
        code,
        InplaceVariant {
            patch_length: COMPACT_FAR_PATCH_LENGTH,
            minimum_terminal_index: 3,
            near_far: false,
            require_final_control_flow: true,
            length_reason: "AArch64 in-place compact-far jump needs 16 bytes",
            terminal_reason: "AArch64 in-place compact-far jump ends before the following instruction",
        },
    )
}

fn analyze_inplace_variant(
    target: usize,
    code: &[u8],
    variant: InplaceVariant,
) -> Result<Analysis> {
    let InplaceVariant {
        patch_length,
        minimum_terminal_index,
        near_far,
        require_final_control_flow,
        length_reason,
        terminal_reason,
    } = variant;
    if !target.is_multiple_of(4) {
        return Err(Error::InvalidInlineTarget(
            "AArch64 entry is not 4-byte aligned",
        ));
    }
    let first = read_word(code, 0)?;
    let pac_landing = is_pac_landing(first);
    let prefix = usize::from(pac_landing) * 4;
    let patch_length = patch_length + if patch_length == 8 { 0 } else { prefix };
    let minimum_terminal_index =
        minimum_terminal_index + if patch_length == 8 { 0 } else { prefix / 4 };
    let landing = usize::from(is_bti(first)) * 4;
    let patch_address = target
        .checked_add(landing)
        .ok_or(Error::ArithmeticOverflow)?;
    if code.len() < landing + patch_length {
        return Err(unsupported(patch_address, length_reason));
    }
    let mut relocations = Vec::with_capacity(patch_length / 4);
    let mut address_references = Vec::new();
    for index in 0..patch_length / 4 {
        let instruction = read_word(code, landing + index * 4)?;
        let address = patch_address
            .checked_add(index * 4)
            .ok_or(Error::ArithmeticOverflow)?;
        let relocation = classify(instruction, address)?;
        let patch_end = patch_address
            .checked_add(patch_length)
            .ok_or(Error::ArithmeticOverflow)?;
        let exits_patch_window = matches!(
            &relocation,
            Relocation::Branch(target)
                if *target < patch_address || *target >= patch_end
        );
        if (matches!(relocation, Relocation::Terminal(_)) || exits_patch_window)
            && index < minimum_terminal_index
        {
            return Err(unsupported(address, terminal_reason));
        }
        match &relocation {
            Relocation::Literal { target, width, .. } => {
                let literal_end = target
                    .checked_add(*width)
                    .ok_or(Error::ArithmeticOverflow)?;
                if *target < patch_end && patch_address < literal_end {
                    return Err(unsupported(
                        address,
                        "PC-relative data overlaps stolen instruction",
                    ));
                }
            }
            Relocation::Adr { register, target } => {
                if *register <= 30 {
                    address_references.push(AddressReference {
                        address,
                        register: *register,
                        target: *target,
                    });
                }
                let overlaps = instruction & 0x9f00_0000 != 0x9000_0000
                    && (patch_address..patch_end).contains(target);
                if overlaps {
                    return Err(unsupported(
                        address,
                        "PC-relative address overlaps stolen instruction",
                    ));
                }
            }
            _ => {}
        }
        relocations.push(relocation);
    }
    if require_final_control_flow
        && !matches!(
            relocations.last(),
            Some(Relocation::Terminal(_)) | Some(Relocation::Branch(_))
        )
    {
        let address = patch_address
            .checked_add(patch_length - 4)
            .ok_or(Error::ArithmeticOverflow)?;
        return Err(unsupported(
            address,
            "AArch64 compact-far jump needs a final terminal or branch",
        ));
    }
    Ok(Analysis {
        patch_address,
        original: code[landing..landing + patch_length].to_vec(),
        pac_landing,
        relocations,
        address_references,
        far: true,
        near_far,
    })
}

fn unconditional_branch_target(from: usize, instruction: u32) -> Option<usize> {
    if instruction & 0xfc00_0000 != 0x1400_0000 {
        return None;
    }
    let immediate = sign_extend(u64::from(instruction & 0x03ff_ffff), 26).checked_mul(4)?;
    add_signed(from, immediate).ok()
}

pub(super) fn generate(
    analysis: &Analysis,
    arena: usize,
    replacement: usize,
    maps: &[MapInfo],
    guarded: bool,
    replacement_bti: &ReplacementBti,
    _: bool,
) -> Result<Generated> {
    if analysis.far {
        return generate_inplace_far(analysis, arena, replacement, maps, guarded, replacement_bti);
    }
    let branch_address = analysis.patch_address + usize::from(analysis.pac_landing) * 4;
    let direct_patch = match encode_b(branch_address, replacement) {
        Ok(patch) => Some(patch),
        Err(Error::NoNearbyMemory) => None,
        Err(error) => return Err(error),
    };
    // A far replacement is reached through the relay at the arena head; the
    // trampoline follows it and holds the relocated entry. When the arena is
    // also within branch range of the replacement, that relay is one direct
    // branch and needs neither a literal nor a BTI landing.
    let bytes = if direct_patch.is_some() {
        Vec::new()
    } else if let Ok(branch) = encode_b(arena, replacement) {
        branch.to_le_bytes().to_vec()
    } else {
        let replacement_guarded = replacement_bti_guarded(maps, replacement, replacement_bti)?;
        relay(arena, replacement, maps, replacement_guarded)?
    };
    let mut bytes = TransientBytes::from(bytes);
    align_code(&mut bytes, 16);
    let trampoline_offset = bytes.len();
    if guarded {
        push_word(&mut bytes, BTI_JC);
    }
    let relocated_address = arena
        .checked_add(bytes.len())
        .ok_or(Error::ArithmeticOverflow)?;
    let original_end = analysis
        .patch_address
        .checked_add(analysis.original.len())
        .ok_or(Error::ArithmeticOverflow)?;
    let mut falls_through = true;
    for (index, relocation) in analysis.relocations.iter().enumerate() {
        let instruction_address = analysis
            .patch_address
            .checked_add(index * 4)
            .ok_or(Error::ArithmeticOverflow)?;
        let relocated_instruction = arena
            .checked_add(bytes.len())
            .ok_or(Error::ArithmeticOverflow)?;
        falls_through = append_relocated_instruction(
            &mut bytes,
            relocation,
            analysis.patch_address..original_end,
            relocated_address,
            relocated_instruction,
            instruction_address,
            maps,
        )?;
        if !falls_through {
            break;
        }
    }
    if falls_through {
        let branch_address = arena
            .checked_add(bytes.len())
            .ok_or(Error::ArithmeticOverflow)?;
        push_word(&mut bytes, encode_b(branch_address, original_end)?);
    }
    let branch = match direct_patch {
        Some(patch) => patch,
        None => encode_b(branch_address, arena)?,
    }
    .to_le_bytes();
    let mut patch = TransientBytes::from(Vec::new());
    if analysis.pac_landing {
        // Replacement receives the caller's unsigned LR; only original runs PAC.
        push_word(&mut patch, BTI_C);
    }
    patch.extend_from_slice(&branch);
    let original = arena
        .checked_add(trampoline_offset)
        .ok_or(Error::ArithmeticOverflow)?;
    Ok(Generated {
        bytes: bytes.into_vec(),
        patch: patch.into_vec(),
        original,
        auxiliary: None,
    })
}

fn append_relocated_instruction(
    bytes: &mut TransientBytes,
    relocation: &Relocation,
    original: std::ops::Range<usize>,
    relocated_start: usize,
    relocated_address: usize,
    instruction_address: usize,
    maps: &[MapInfo],
) -> Result<bool> {
    match relocation {
        Relocation::Copy(instruction) => {
            push_word(bytes, *instruction);
            Ok(true)
        }
        Relocation::Terminal(instruction) => {
            push_word(bytes, *instruction);
            Ok(false)
        }
        Relocation::Branch(target) => {
            let target =
                remap_window_target(*target, original.start, original.end, relocated_start)?;
            match encode_b(relocated_address, target) {
                Ok(branch) => push_word(bytes, branch),
                Err(Error::NoNearbyMemory) => return Err(Error::NoNearbyMemory),
                Err(error) => {
                    return Err(relocation_range(error, instruction_address, MAX_DISTANCE));
                }
            }
            Ok(false)
        }
        Relocation::Conditional {
            instruction,
            target,
        } => {
            let target =
                remap_window_target(*target, original.start, original.end, relocated_start)?;
            let branch_address = relocated_address
                .checked_add(4)
                .ok_or(Error::ArithmeticOverflow)?;
            match encode_b(branch_address, target) {
                Ok(branch) => {
                    push_word(bytes, invert_conditional_to_skip(*instruction, 2));
                    push_word(bytes, branch);
                }
                Err(Error::NoNearbyMemory) => {
                    return Err(Error::NoNearbyMemory);
                }
                Err(error) => {
                    return Err(relocation_range(error, instruction_address, MAX_DISTANCE));
                }
            }
            Ok(true)
        }
        Relocation::Adr { register, target } => {
            if !emit_compact_address(bytes, *register, relocated_address, *target) {
                emit_address(bytes, *register, *target as u64);
            }
            Ok(true)
        }
        Relocation::Literal {
            instruction,
            target,
            width,
        } => {
            let literal = read_literal_bytes(*target, *width, maps)?;
            let load_offset = bytes.len();
            push_word(bytes, *instruction);
            let branch_offset = bytes.len();
            push_word(bytes, 0);
            align_code(bytes, *width);
            let data_offset = bytes.len();
            bytes.extend_from_slice(&literal[..*width]);
            let load_immediate = u32::try_from((data_offset - load_offset) / 4)
                .map_err(|_| Error::ArithmeticOverflow)?;
            let load = (*instruction & !0x00ff_ffe0) | (load_immediate << 5);
            bytes[load_offset..load_offset + 4].copy_from_slice(&load.to_le_bytes());
            let skip = u32::try_from((bytes.len() - branch_offset) / 4)
                .map_err(|_| Error::ArithmeticOverflow)?;
            let branch = 0x1400_0000 | (skip & 0x03ff_ffff);
            bytes[branch_offset..branch_offset + 4].copy_from_slice(&branch.to_le_bytes());
            Ok(true)
        }
    }
}

fn relocation_range(error: Error, instruction: usize, distance: usize) -> Error {
    match error {
        Error::NoNearbyMemory => Error::InlineRelocationRange {
            instruction,
            distance,
        },
        other => other,
    }
}

fn read_literal_bytes(address: usize, width: usize, maps: &[MapInfo]) -> Result<[u8; 16]> {
    if width == 0 || width > 16 || !width.is_multiple_of(4) {
        return Err(unsupported(address, "unsupported AArch64 literal width"));
    }
    let mut literal = [0_u8; 16];
    let probe = patch::probe_maps(maps, address, width)?;
    let validation_maps = probe.as_deref().unwrap_or(maps);
    let map = find_map_containing(validation_maps, address, width)
        .filter(|map| {
            map.perms.contains(crate::maps::MapPerms::READ)
                && !map.perms.contains(crate::maps::MapPerms::WRITE)
                && map.is_private
        })
        .ok_or(Error::MappingChanged)?;
    if map.end.saturating_sub(address) < width {
        return Err(Error::MappingChanged);
    }
    // SAFETY: the captured mapping is readable and covers the literal.
    unsafe {
        std::ptr::copy_nonoverlapping(
            std::ptr::with_exposed_provenance::<u8>(address),
            literal.as_mut_ptr(),
            width,
        );
    }
    Ok(literal)
}

fn remap_window_target(
    target: usize,
    original_start: usize,
    original_end: usize,
    relocated_start: usize,
) -> Result<usize> {
    if !(original_start..original_end).contains(&target) {
        return Ok(target);
    }
    if !target.is_multiple_of(4) {
        return Err(unsupported(
            original_start,
            "branch enters the middle of a stolen instruction",
        ));
    }
    relocated_start
        .checked_add(target - original_start)
        .ok_or(Error::ArithmeticOverflow)
}

fn classify(instruction: u32, address: usize) -> Result<Relocation> {
    if is_call(instruction) {
        let disassembly = if instruction & 0xfc00_0000 == 0x9400_0000 {
            "BL"
        } else {
            "BLR"
        };
        log::warn!("AArch64 instruction rejected: {disassembly}");
        return Err(unsupported(address, "stolen BL/BLR is not relocatable"));
    }
    if instruction & 0xfc00_0000 == 0x1400_0000 {
        return Ok(Relocation::Branch(add_signed(
            address,
            sign_extend(((instruction & 0x03ff_ffff) as u64) << 2, 28),
        )?));
    }
    if instruction & 0xff00_0000 == 0x5400_0000 {
        let target = add_signed(
            address,
            sign_extend((((instruction >> 5) & 0x7ffff) as u64) << 2, 21),
        )?;
        if instruction & 0xf >= 14 {
            return Ok(Relocation::Branch(target));
        }
        return Ok(Relocation::Conditional {
            instruction,
            target,
        });
    }
    if matches!(instruction & 0x7e00_0000, 0x3400_0000 | 0x3600_0000) {
        let (immediate, bits) = if instruction & 0x7e00_0000 == 0x3400_0000 {
            (((instruction >> 5) & 0x7ffff) as u64, 21)
        } else {
            // TBZ/TBNZ carry imm14 in bits 18..5; after scaling by four the
            // signed displacement is sixteen bits wide.
            (((instruction >> 5) & 0x3fff) as u64, 16)
        };
        return Ok(Relocation::Conditional {
            instruction,
            target: add_signed(address, sign_extend(immediate << 2, bits))?,
        });
    }
    match instruction & 0x9f00_0000 {
        0x1000_0000 => {
            let register = instruction & 0x1f;
            if register == 31 {
                return Ok(Relocation::Copy(instruction));
            }
            let immediate = (((instruction >> 29) & 3) | ((instruction >> 3) & 0x1f_fffc)) as u64;
            return Ok(Relocation::Adr {
                register,
                target: add_signed(address, sign_extend(immediate, 21))?,
            });
        }
        0x9000_0000 => {
            let register = instruction & 0x1f;
            if register == 31 {
                return Ok(Relocation::Copy(instruction));
            }
            let immediate = (((instruction >> 29) & 3) | ((instruction >> 3) & 0x1f_fffc)) as u64;
            let page = address & !ARCH_PAGE_MASK;
            return Ok(Relocation::Adr {
                register,
                target: add_signed(page, sign_extend(immediate << 12, 33))?,
            });
        }
        _ => {}
    }
    if instruction & 0x3b00_0000 == 0x1800_0000 {
        let vector = instruction >> 26 & 1;
        let opc = instruction >> 30;
        let width = match (vector, opc) {
            (0, 0 | 2) | (1, 0) => 4,
            (_, 1) => 8,
            (1, 2) => 16,
            _ => return Err(unsupported(address, "unsupported AArch64 literal load")),
        };
        let target = add_signed(
            address,
            sign_extend((((instruction >> 5) & 0x7ffff) as u64) << 2, 21),
        )?;
        return Ok(Relocation::Literal {
            instruction,
            target,
            width,
        });
    }

    if instruction & 0xffff_fc1f == 0xd61f_0000
        || instruction & 0xffff_fc1f == 0xd65f_0000
        || matches!(instruction, 0xd65f_0bff | 0xd65f_0fff)
    {
        return Ok(Relocation::Terminal(instruction));
    }
    if instruction & 0xfe00_0000 == 0xd600_0000 {
        return Err(unsupported(
            address,
            "unsupported AArch64 branch-register instruction",
        ));
    }

    let major = instruction >> 25 & 0xf;
    if instruction & 0xff00_0000 == 0xd400_0000 {
        return Err(unsupported(
            address,
            "AArch64 exception-generation instruction is not relocatable",
        ));
    }
    if matches!(major, 4 | 5 | 6 | 7 | 8 | 9 | 12 | 13 | 14 | 15)
        || instruction & 0xff00_0000 == 0xd500_0000
    {
        return Ok(Relocation::Copy(instruction));
    }
    Err(unsupported(address, "unknown AArch64 PC semantics"))
}

/// Detects a following instruction that provably reads the overwritten bytes
/// through the destination register of a stolen ADR or ADRP.
///
/// `words[i]` is the instruction at `base + i * 4`. The tracker follows the
/// referenced register through register moves and constant add/sub offsets.
/// Only accesses whose effective address provably intersect
/// `stolen_start..stolen_end` are reported; unrecognized uses drop tracking
/// instead of rejecting, so legitimate entries never lose hookability.
///
/// Returns the accessing instruction address and the first intersecting
/// effective address.
#[cfg(test)]
pub(super) fn detect_data_reference(
    words: &[u32],
    base: usize,
    register: u32,
    target: usize,
    stolen_start: usize,
    stolen_end: usize,
) -> Option<(usize, usize)> {
    if register > 30 {
        return None;
    }
    let mut offsets = [None; 32];
    offsets[register as usize] = Some(0_isize);
    detect_data_reference_with_offsets(words, base, &mut offsets, target, stolen_start, stolen_end)
}

/// Continues data-reference detection with register state from a prior window.
pub(super) fn detect_data_reference_with_offsets(
    words: &[u32],
    base: usize,
    offsets: &mut [Option<isize>; 32],
    target: usize,
    stolen_start: usize,
    stolen_end: usize,
) -> Option<(usize, usize)> {
    let mut instruction = base;
    for &word in words {
        if terminates_analysis(word) {
            return None;
        }
        if let Some((address, effective)) =
            memory_access(word, instruction, offsets, target, stolen_start, stolen_end)
        {
            return Some((address, effective));
        }
        update_tracking(word, offsets);
        instruction += 4;
    }
    None
}

/// Returns whether one of the scanned words ends linear execution.
pub(super) fn linear_flow_terminated(words: &[u32]) -> bool {
    words.iter().any(|&word| terminates_analysis(word))
}

/// Returns whether control flow cannot reach the next instruction linearly.
fn terminates_analysis(word: u32) -> bool {
    if word & 0xFC00_0000 == 0x1400_0000 {
        return true; // B
    }
    if word & 0xFC00_0000 == 0x9400_0000 {
        return true; // BL
    }
    if word & 0xFF00_0000 == 0x5400_0000 && (word & 0xF) >= 14 {
        return true; // B.AL/B.NV are unconditional in this relocation model
    }
    if word & 0xFE00_0000 == 0xD600_0000 {
        return true; // BR, BLR, RET, RETAA/RETAB
    }
    // Exception generation ends linear execution; hints such as NOP, BTI, and
    // PAC continue to the next instruction.
    word & 0xFF00_0000 == 0xD400_0000
}

/// Reports a tracked-base access whose effective address hits the stolen
/// bytes, if this word has a provable effective address.
fn memory_access(
    word: u32,
    instruction: usize,
    offsets: &[Option<isize>; 32],
    target: usize,
    stolen_start: usize,
    stolen_end: usize,
) -> Option<(usize, usize)> {
    if let Some((width, _, _)) = base_memory_access(word) {
        let delta = offsets[((word >> 5) & 31) as usize]?;
        let effective = (target as isize).checked_add(delta)? as usize;
        return effective
            .checked_add(width)
            .filter(|&end| effective < stolen_end && end > stolen_start)
            .map(|_| (instruction, effective));
    }
    if let Some((base_register, element_width, immediate, _, _, offset_applies, _)) =
        pair_access(word)
    {
        let delta = offsets[base_register as usize]?;
        let immediate = if offset_applies { immediate } else { 0 };
        let effective = (target as isize)
            .checked_add(delta)?
            .checked_add(immediate)? as usize;
        if effective
            .checked_add(element_width * 2)
            .is_some_and(|end| effective < stolen_end && end > stolen_start)
        {
            return Some((instruction, effective));
        }
        return None;
    }

    let unsigned = word & 0x3B00_0000 == 0x3900_0000;
    let unscaled = word & 0x3B20_0000 == 0x3800_0000 || word & 0x3F20_0C00 == 0x1900_0000; // LDAPUR/STLUR
    let register_offset = word & 0x3B20_0C00 == 0x3820_0800 && (word >> 13) & 2 != 0;
    if !unsigned && !unscaled && !register_offset {
        return None;
    }
    let vector = (word >> 26) & 1 == 1;
    let size = (word >> 30) & 3;
    let opcode = (word >> 22) & 3;
    let base_register = (word >> 5) & 31;
    let delta = offsets[base_register as usize]?;
    let (immediate, width) = if unsigned || register_offset {
        // Integer prefetches do not read or write the target bytes. The other
        // integer opcodes include signed loads such as LDRSB/LDRSH.
        if !vector && size == 3 && opcode == 2 {
            return None;
        }
        // Q is the only width whose scale is not encoded directly in `size`;
        // scalar bytes are the only one-byte access with an unscaled scale.
        let (scale, width) = if vector && size == 0 && opcode >= 2 {
            (4_usize, 16_usize)
        } else {
            (if size == 0 { 0 } else { size as usize }, 1_usize << size)
        };
        let immediate = if register_offset {
            // XZR/WZR is a known zero index; other indices are runtime inputs.
            if (word >> 16) & 31 != 31 {
                return None;
            }
            0
        } else {
            (((word >> 10) & 0xFFF) << scale) as isize
        };
        (immediate, width)
    } else {
        // Sign-extend the 9-bit immediate through a 32-bit value first: a
        // direct isize shift would keep the top bit far below bit 63.
        let raw = (((word >> 12) & 0x1FF) << 23) as i32;
        let signed = (raw >> 23) as isize;
        let mode = (word >> 10) & 3;
        // Integer prefetches do not read or write the target bytes. The other
        // integer opcodes include signed loads such as LDRSB/LDRSH.
        if !vector && size == 3 && opcode == 2 {
            return None;
        }
        let width = if vector {
            if size == 0 && opcode >= 2 {
                16
            } else {
                1_usize << size
            }
        } else {
            1_usize << size
        };
        (if mode == 1 { 0 } else { signed }, width)
    };
    let effective = (target as isize)
        .checked_add(delta)?
        .checked_add(immediate)? as usize;
    if effective
        .checked_add(width)
        .is_some_and(|end| effective < stolen_end && end > stolen_start)
    {
        return Some((instruction, effective));
    }
    None
}

/// Decodes base-only accesses: byte width, overwritten GPR mask, and known writeback.
fn base_memory_access(word: u32) -> Option<(usize, u32, Option<isize>)> {
    let register_mask = |register: u32| if register >= 31 { 0 } else { 1_u32 << register };
    let size = word >> 30;
    let load = word & (1 << 22) != 0;
    if word & 0x3F00_0000 == 0x0800_0000 {
        let ordered = word & (1 << 23) != 0;
        let pair = word & (1 << 21) != 0 && !ordered;
        let source = (word >> 16) & 31;
        let destination = word & 31;
        let (width, written) = if pair && size < 2 {
            // CASP returns the old pair in Rs/Rs+1.
            (8 << size, register_mask(source) | register_mask(source + 1))
        } else if ordered && word & (1 << 21) != 0 {
            (1 << size, register_mask(source)) // CAS
        } else {
            let written = if load {
                register_mask(destination)
                    | if pair {
                        register_mask((word >> 10) & 31)
                    } else {
                        0
                    }
            } else if !ordered {
                register_mask(source) // STXR/STXP status
            } else {
                0
            };
            ((1 << size) * if pair { 2 } else { 1 }, written)
        };
        return Some((width, written, None));
    }
    if word & 0x3F20_0C00 == 0x3820_0000 && matches!((word >> 12) & 15, 0..=8 | 12) {
        return Some((1 << size, register_mask(word & 31), None));
    }
    let width = if word & 0xBF20_0000 == 0x0C00_0000 {
        let registers = match (word >> 12) & 15 {
            0 | 2 => 4,
            4 | 6 => 3,
            8 | 10 => 2,
            7 => 1,
            _ => return None,
        };
        registers * if word & (1 << 30) != 0 { 16 } else { 8 }
    } else if word & 0xBF00_0000 == 0x0D00_0000 {
        let opcode = (word >> 13) & 7;
        let element_size = (word >> 10) & 3;
        let lane_bit = word & (1 << 12) != 0;
        let width = match opcode >> 1 {
            0 => 1,
            1 if element_size & 1 == 0 => 2,
            2 if element_size & 2 == 0 && (element_size & 1 == 0 || !lane_bit) => {
                4 << (element_size & 1)
            }
            3 if load && !lane_bit => 1 << element_size,
            _ => return None,
        };
        (((opcode & 1) << 1) + ((word >> 21) & 1) + 1) as usize * width
    } else {
        return None;
    };
    // SIMD structure transfers write V registers; only post-index affects a GPR.
    if word & (1 << 23) == 0 {
        Some((width, 0, None))
    } else if (word >> 16) & 31 == 31 {
        Some((width, 0, Some(width as isize)))
    } else {
        Some((width, 1 << ((word >> 5) & 31), None))
    }
}

fn pair_access(word: u32) -> Option<(u32, usize, isize, bool, bool, bool, bool)> {
    let vector = (word >> 26) & 1 == 1;
    if word & 0x3800_0000 != 0x2800_0000 || (word >> 25) & 1 != 0 {
        return None;
    }
    let size = (word >> 30) & 3;
    if size == 3 {
        return None;
    }
    let load = (word >> 22) & 1 == 1;
    let element_width = if vector {
        4_usize << size
    } else if size == 0 || (size == 1 && load) {
        // LDPSW has size=1 but sign-extends two 32-bit words into X
        // registers. Its immediate is scaled by the 4-byte element width.
        4
    } else if size == 1 {
        // STGP has size=1 and stores two 64-bit granules. Its immediate is
        // scaled by the 16-byte pair width.
        8
    } else {
        8
    };
    let raw = (((word >> 15) & 0x7F) << 25) as i32;
    let immediate_scale = if !vector && size == 1 && !load {
        16
    } else {
        element_width
    };
    let immediate = ((raw >> 25) as isize) * immediate_scale as isize;
    let base_register = (word >> 5) & 31;
    let addressing_mode = (word >> 23) & 3;
    let writeback = matches!(addressing_mode, 1 | 3);
    let offset_applies = addressing_mode != 1;
    Some((
        base_register,
        element_width,
        immediate,
        writeback,
        load,
        offset_applies,
        vector,
    ))
}

fn scalar_memory_access(word: u32) -> Option<(u32, u32, bool, Option<isize>, bool)> {
    let unsigned = word & 0x3B00_0000 == 0x3900_0000;
    let unscaled = word & 0x3B20_0000 == 0x3800_0000 || word & 0x3F20_0C00 == 0x1900_0000; // LDAPUR/STLUR
    let register_offset = word & 0x3B20_0C00 == 0x3820_0800 && (word >> 13) & 2 != 0;
    if !unsigned && !unscaled && !register_offset {
        return None;
    }
    let vector = (word >> 26) & 1 == 1;
    let size = (word >> 30) & 3;
    let opcode = (word >> 22) & 3;
    let integer_prefetch = !vector && size == 3 && opcode == 2;
    let load = if integer_prefetch {
        false
    } else if vector {
        opcode & 1 != 0
    } else {
        opcode != 0
    };
    let writeback = if unscaled {
        matches!((word >> 10) & 3, 1 | 3)
    } else {
        false
    };
    let immediate = if unscaled {
        let raw = (((word >> 12) & 0x1FF) << 23) as i32;
        Some((raw >> 23) as isize)
    } else {
        None
    };
    Some((
        (word >> 5) & 31,
        word & 31,
        load,
        writeback.then_some(immediate.unwrap_or(0)),
        vector,
    ))
}

/// Returns whether an instruction writes only an SIMD/FP register (or no
/// general-purpose register). Such instructions use the same low five-bit
/// destination field as GPR operations, but must not erase GPR offset state.
fn writes_simd_or_fp_register(word: u32) -> bool {
    match (word >> 25) & 0xf {
        // SIMD&FP vector data-processing. UMOV/SMOV are the extraction forms
        // in this class that write a GPR instead of a V register.
        7 => {
            let extraction = ((word >> 21) & 7) == 0 && matches!((word >> 10) & 0x3f, 0x0b | 0x0f);
            !extraction
        }
        // Fixed-point conversions encode scale where ordinary conversions use
        // a zero sub-op; SCVTF/UCVTF and FMOV-from-GPR still write FP.
        15 => {
            let opcode = (word >> 16) & 0x1f;
            let sub_op = (word >> 10) & 0x3f;
            let fixed_point_conversion = word & 0x7f3e_0000 == 0x1e18_0000;
            !fixed_point_conversion && (sub_op != 0 || matches!(opcode, 2 | 3 | 7))
        }
        _ => false,
    }
}

/// Moves constant-offset knowledge through recognized register writes.
fn update_tracking(word: u32, offsets: &mut [Option<isize>; 32]) {
    if let Some((_, written, writeback)) = base_memory_access(word) {
        for (register, offset) in offsets.iter_mut().enumerate() {
            if written & (1 << register) != 0 {
                *offset = None;
            }
        }
        if let Some(immediate) = writeback {
            let base = ((word >> 5) & 31) as usize;
            offsets[base] = offsets[base].and_then(|delta| delta.checked_add(immediate));
        }
        return;
    }
    if let Some((base_register, _, immediate, writeback, load, _, vector)) = pair_access(word) {
        let first = word & 31;
        let second = (word >> 10) & 31;
        if load && !vector {
            // Rt/Rt2 == 31 names XZR/WZR in scalar pair transfers, not SP.
            if first != 31 {
                offsets[first as usize] = None;
            }
            if second != 31 {
                offsets[second as usize] = None;
            }
        }
        if writeback {
            // Scalar pair writeback with a source/destination overlapping the
            // base register is constrained-unpredictable. Do not retain a
            // supposedly precise offset in that case.
            let overlap = !vector
                && base_register != 31
                && (base_register == first || base_register == second);
            offsets[base_register as usize] = if overlap {
                None
            } else {
                offsets[base_register as usize].and_then(|delta| delta.checked_add(immediate))
            };
        }
        return;
    }
    if let Some((base_register, destination, load, writeback, vector)) = scalar_memory_access(word)
    {
        let base_offset = offsets[base_register as usize];
        if load && !vector && destination != 31 {
            offsets[destination as usize] = None;
        }
        if let Some(immediate) = writeback {
            let overlap =
                !vector && base_register != 31 && destination != 31 && base_register == destination;
            offsets[base_register as usize] = if overlap {
                None
            } else {
                base_offset.and_then(|delta| delta.checked_add(immediate))
            };
        }
        return;
    }
    if writes_simd_or_fp_register(word) {
        return;
    }
    if word & 0xFF00_0000 == 0x5400_0000
        || word & 0x7E00_0000 == 0x3400_0000
        || word & 0x7E00_0000 == 0x3600_0000
    {
        return;
    }

    let destination = word & 31;
    // MOV register: ORR Xd, XZR, Xm, with no shift.
    if word & 0xFFE0_FFE0 == 0xAA00_03E0 {
        let source = (word >> 16) & 31;
        // Register 31 is XZR in this instruction, unlike the SP form used by
        // ADD/SUB and memory addressing. Keep the SP slot untouched.
        if destination != 31 {
            offsets[destination as usize] = if source == 31 {
                None
            } else {
                offsets[source as usize]
            };
        }
        return;
    }
    // ADD/SUB immediate, 64-bit, flags-preserving, unshifted.
    let add = word & 0xFF40_0000 == 0x9100_0000;
    let sub = word & 0xFF40_0000 == 0xD100_0000;
    if add || sub {
        let base_register = (word >> 5) & 31;
        let immediate = ((word >> 10) & 0xFFF) as isize;
        let Some(delta) = offsets[base_register as usize] else {
            offsets[destination as usize] = None;
            return;
        };
        offsets[destination as usize] = if add {
            delta.checked_add(immediate)
        } else {
            delta.checked_sub(immediate)
        };
        return;
    }
    // An unrecognized instruction that writes the tracked register cannot
    // keep its proven constant offset.
    // Most unrecognised writes use XZR when Rd == 31. Do not let those writes
    // erase a tracked SP value in the shared slot.
    if destination != 31 && offsets[destination as usize].is_some() {
        offsets[destination as usize] = None;
    }
}

fn generate_inplace_far(
    analysis: &Analysis,
    arena: usize,
    replacement: usize,
    maps: &[MapInfo],
    guarded: bool,
    replacement_bti: &ReplacementBti,
) -> Result<Generated> {
    let replacement_guarded = replacement_bti_guarded(maps, replacement, replacement_bti)?;
    let prefix = usize::from(analysis.pac_landing) * 4;
    let patch_length = analysis.original.len() - prefix;
    if analysis.near_far && patch_length != NEAR_FAR_PATCH_LENGTH {
        return Err(unsupported(
            analysis.patch_address,
            "AArch64 in-place near-far jump needs 12 bytes",
        ));
    }
    if !analysis.near_far
        && patch_length != FAR_PATCH_LENGTH
        && patch_length != COMPACT_FAR_PATCH_LENGTH
    {
        return Err(unsupported(
            analysis.patch_address,
            "AArch64 in-place far jump needs 16 or 28 bytes",
        ));
    }
    if replacement_guarded && !analysis.near_far {
        patch::validate_executable_entry(maps, replacement, 4)?;
        // SAFETY: the executable mapping is readable for one instruction.
        let landing = unsafe {
            u32::from_le(std::ptr::read_unaligned(std::ptr::with_exposed_provenance(
                replacement,
            )))
        };
        if !is_br_x16_landing(landing) {
            return Err(Error::InvalidInlineTarget(
                "guarded AArch64 replacement lacks a BR x16 landing",
            ));
        }
    }
    let mut bytes = TransientBytes::from(Vec::new());
    let trampoline_offset = bytes.len();
    if guarded {
        push_word(&mut bytes, BTI_JC);
    }
    let original_start = analysis.patch_address;
    let original_end = original_start
        .checked_add(analysis.original.len())
        .ok_or(Error::ArithmeticOverflow)?;
    let mut relocated_offsets = vec![None; analysis.relocations.len()];
    let mut branch_patches = Vec::<(usize, usize, bool, u32)>::new();
    let mut falls_through = true;
    for (index, relocation) in analysis.relocations.iter().enumerate() {
        let instruction_address = original_start
            .checked_add(index * 4)
            .ok_or(Error::ArithmeticOverflow)?;
        let relocated_address = arena
            .checked_add(bytes.len())
            .ok_or(Error::ArithmeticOverflow)?;
        relocated_offsets[index] = Some(bytes.len());
        match relocation {
            Relocation::Branch(target) => {
                branch_patches.push((bytes.len(), *target, false, 0));
            }
            Relocation::Conditional {
                target,
                instruction,
            } => {
                branch_patches.push((bytes.len(), *target, true, *instruction));
            }
            _ => {}
        }
        falls_through = append_relocated_instruction(
            &mut bytes,
            relocation,
            original_start..original_end,
            arena + usize::from(guarded) * 4,
            relocated_address,
            instruction_address,
            maps,
        )?;
    }
    for (offset, target, conditional, instruction) in branch_patches {
        if !(original_start..original_end).contains(&target) {
            continue;
        }
        let index = (target - original_start) / 4;
        let relocated_offset =
            relocated_offsets
                .get(index)
                .copied()
                .flatten()
                .ok_or_else(|| {
                    unsupported(
                        analysis.patch_address,
                        "AArch64 far branch target was not relocated",
                    )
                })?;
        let relocated_target = arena
            .checked_add(relocated_offset)
            .ok_or(Error::ArithmeticOverflow)?;
        let branch_address = arena + offset + usize::from(conditional) * 4;
        let branch = encode_b(branch_address, relocated_target)?;
        if conditional {
            bytes[offset..offset + 4]
                .copy_from_slice(&invert_conditional_to_skip(instruction, 2).to_le_bytes());
            bytes[offset + 4..offset + 8].copy_from_slice(&branch.to_le_bytes());
        } else {
            bytes[offset..offset + 4].copy_from_slice(&branch.to_le_bytes());
        }
    }
    if falls_through {
        let landing = original_start
            .checked_add(prefix + if analysis.near_far { 4 } else { 16 })
            .ok_or(Error::ArithmeticOverflow)?;
        push_word(&mut bytes, 0xa9bf_47f0); // stp x16, x17, [sp, #-16]!
        push_word(&mut bytes, 0x5800_0050); // ldr x16, #8
        push_word(&mut bytes, BR_X16);
        bytes.extend_from_slice(&(landing as u64).to_le_bytes());
    }
    let mut patch = TransientBytes::from(Vec::with_capacity(analysis.original.len()));
    if analysis.pac_landing {
        push_word(&mut patch, BTI_C);
    }
    if analysis.near_far {
        // The replacement is already within `B` range, so the entry stays one
        // word and leaves room for an 8-byte landing in a 12-byte window.
        push_word(
            &mut patch,
            encode_b(analysis.patch_address + prefix, replacement)?,
        );
        push_word(&mut patch, 0xa8c1_47f0); // ldp x16, x17, [sp], #16
        push_word(&mut patch, 0x1400_0001); // b .+4
    } else if patch_length == COMPACT_FAR_PATCH_LENGTH {
        // The replacement is out of range and the target page is unguarded, so
        // the entry needs only a self-contained literal branch.
        push_word(&mut patch, 0x5800_0050); // ldr x16, #8
        push_word(&mut patch, BR_X16);
        patch.extend_from_slice(&(replacement as u64).to_le_bytes());
    } else {
        // The first 16 bytes enter the replacement. The remaining 12 bytes are
        // a guarded landing that restores the scratch pair and stack pointer.
        push_word(&mut patch, 0x5800_0050); // ldr x16, #8
        push_word(&mut patch, BR_X16);
        patch.extend_from_slice(&(replacement as u64).to_le_bytes());
        push_word(&mut patch, BTI_JC);
        push_word(&mut patch, 0xa8c1_47f0); // ldp x16, x17, [sp], #16
        push_word(&mut patch, 0x1400_0001); // b .+4
    }
    let original = arena
        .checked_add(trampoline_offset)
        .ok_or(Error::ArithmeticOverflow)?;
    Ok(Generated {
        bytes: bytes.into_vec(),
        patch: patch.into_vec(),
        original,
        auxiliary: None,
    })
}

/// Emits the absolute branch the installer uses when a replacement is beyond
/// the entry's branch range: a page-relative load of the destination in `x16`
/// followed by the indirect branch, with the destination as the only literal.
///
/// This is the shape compilers emit for an ordinary indirect branch, and the
/// one [`redirects_to`] recognises when it audits a live entry.
fn relay(
    address: usize,
    replacement: usize,
    maps: &[MapInfo],
    replacement_guarded: bool,
) -> Result<Vec<u8>> {
    if replacement_guarded {
        patch::validate_executable_entry(maps, replacement, 4)?;
        // SAFETY: the executable mapping is readable for one instruction.
        let landing = unsafe {
            u32::from_le(std::ptr::read_unaligned(std::ptr::with_exposed_provenance(
                replacement,
            )))
        };
        if !is_br_x16_landing(landing) {
            return Err(Error::InvalidInlineTarget(
                "guarded AArch64 replacement lacks a BR x16 landing",
            ));
        }
    }
    let literal = address.checked_add(16).ok_or(Error::ArithmeticOverflow)?;
    if (literal & !ARCH_PAGE_MASK) != (address & !ARCH_PAGE_MASK)
        || (literal.wrapping_add(7) & !ARCH_PAGE_MASK) != (address & !ARCH_PAGE_MASK)
    {
        return Err(Error::NoNearbyMemory);
    }
    let mut relay = TransientBytes::from(Vec::with_capacity(24));
    push_word(&mut relay, encode_adrp(address, address)?);
    push_word(
        &mut relay,
        encode_ldr_x16_page_offset(literal & ARCH_PAGE_MASK)?,
    );
    push_word(&mut relay, BR_X16);
    push_word(&mut relay, NOP);
    relay.extend_from_slice(&(replacement as u64).to_le_bytes());
    Ok(relay.into_vec())
}

fn is_call(instruction: u32) -> bool {
    instruction & 0xfc00_0000 == 0x9400_0000
        || matches!(
            instruction & 0xffff_fc1f,
            0xd63f_0000 | 0xd63f_081f | 0xd63f_0c1f
        )
        || matches!(instruction & 0xffff_fc00, 0xd73f_0800 | 0xd73f_0c00)
}

fn is_bti(instruction: u32) -> bool {
    matches!(instruction, BTI_J | BTI_JC | BTI_C | BTI)
}

fn is_pac_landing(instruction: u32) -> bool {
    matches!(instruction, 0xd503_233f | 0xd503_237f)
}

/// Reports whether any instruction in `code` (starting at `base`) branches into
/// `(start, end)`. A branch to `start` itself is the hooked entry and is allowed.
#[cfg(test)]
fn branch_enters_window(code: &[u8], base: usize, start: usize, end: usize) -> bool {
    let mut offset = 0;
    let mut pc = base;
    while offset + 4 <= code.len() {
        let word = u32::from_le_bytes([
            code[offset],
            code[offset + 1],
            code[offset + 2],
            code[offset + 3],
        ]);
        if let Ok(relocation) = classify(word, pc) {
            let target = match relocation {
                Relocation::Branch(target) => Some(target),
                Relocation::Conditional { target, .. } => Some(target),
                _ => None,
            };
            if target.is_some_and(|target| target > start && target < end) {
                return true;
            }
        }
        if terminates_analysis(word) {
            break;
        }
        offset += 4;
        pc += 4;
    }
    false
}

fn is_ldr_x16_br(bytes: &[u8], replacement: usize) -> bool {
    let Some(head) = bytes.get(..16) else {
        return false;
    };
    u32::from_le_bytes([head[0], head[1], head[2], head[3]]) == 0x5800_0050
        && u32::from_le_bytes([head[4], head[5], head[6], head[7]]) == 0xd61f_0200
        && u64::from_le_bytes([
            head[8], head[9], head[10], head[11], head[12], head[13], head[14], head[15],
        ]) as usize
            == replacement
}

fn is_br_x16_landing(instruction: u32) -> bool {
    // BR through x16 preserves unsigned LR and uses BTYPE=01, accepted by J and C.
    matches!(instruction, BTI_J | BTI_JC | BTI_C) || is_pac_landing(instruction)
}

fn invert_conditional_to_skip(instruction: u32, offset_words: u32) -> u32 {
    if instruction & 0xff00_0000 == 0x5400_0000 {
        ((instruction ^ 1) & !0x00ff_ffe0) | (offset_words << 5)
    } else if instruction & 0x7e00_0000 == 0x3400_0000 {
        ((instruction ^ 0x0100_0000) & !0x00ff_ffe0) | (offset_words << 5)
    } else {
        ((instruction ^ 0x0100_0000) & !0x0007_ffe0) | (offset_words << 5)
    }
}

fn emit_address(bytes: &mut TransientBytes, register: u32, address: u64) {
    for halfword in 0..4_u32 {
        let opcode = if halfword == 0 {
            0xd280_0000
        } else {
            0xf280_0000
        };
        let immediate = ((address >> (halfword * 16)) & 0xffff) as u32;
        push_word(
            bytes,
            opcode | (halfword << 21) | (immediate << 5) | register,
        );
    }
}

fn is_movk_x16_relay(bytes: &[u8], replacement: usize) -> bool {
    let mut expected = TransientBytes::from(Vec::with_capacity(20));
    emit_address(&mut expected, 16, replacement as u64);
    push_word(&mut expected, 0xd61f_0200);
    bytes.starts_with(&expected.into_vec())
}

fn encode_b(from: usize, to: usize) -> Result<u32> {
    let immediate = scaled_signed(to, from, 4, 26)?;
    Ok(0x1400_0000 | (immediate as u32 & 0x03ff_ffff))
}

/// Encodes `adrp x16, <page of to>` relative to the page of `from`.
fn encode_adrp(from: usize, to: usize) -> Result<u32> {
    encode_adrp_reg(from, to, 16)
}

pub(super) fn encode_adr_reg(from: usize, to: usize, register: u32) -> Result<u32> {
    let immediate = scaled_signed(to, from, 1, 21)? as u32;
    Ok(0x1000_0000 | (immediate & 3) << 29 | ((immediate >> 2) & 0x7_ffff) << 5 | register)
}

fn encode_adrp_reg(from: usize, to: usize, register: u32) -> Result<u32> {
    let pages = scaled_signed(to & !ARCH_PAGE_MASK, from & !ARCH_PAGE_MASK, ARCH_PAGE, 21)?;
    let immediate = (pages as u32) & 0x1f_ffff;
    Ok(0x9000_0000 | (immediate & 3) << 29 | ((immediate >> 2) & 0x7_ffff) << 5 | register)
}

/// Writes `target` into `register` with ADR or ADRP+ADD when the trampoline
/// can express it. Returns false when the distance needs the MOVZ/MOVK form.
fn emit_compact_address(
    bytes: &mut TransientBytes,
    register: u32,
    from: usize,
    target: usize,
) -> bool {
    if register > 30 {
        return false;
    }
    if let Ok(word) = encode_adr_reg(from, target, register) {
        push_word(bytes, word);
        return true;
    }
    if let Ok(word) = encode_adrp_reg(from, target, register) {
        push_word(bytes, word);
        let low = (target & ARCH_PAGE_MASK) as u32;
        if low != 0 {
            push_word(
                bytes,
                0x9100_0000 | (low << 10) | (register << 5) | register,
            );
        }
        return true;
    }
    false
}

/// Encodes `ldr x16, [x16, #offset]` for an 8-byte literal in `x16`'s page.
fn encode_ldr_x16_page_offset(offset: usize) -> Result<u32> {
    if !offset.is_multiple_of(8) || offset >= 0x8000 {
        return Err(Error::NoNearbyMemory);
    }
    Ok(0xf940_0000 | (((offset / 8) as u32) << 10) | (16 << 5) | 16)
}

/// Decodes the literal address of an `adrp`/`ldr`/`br x16` sequence.
///
/// Returns `None` when the bytes at `address` are not exactly that sequence.
fn page_relative_literal(bytes: &[u8], address: usize) -> Option<usize> {
    let page = read_word(bytes, 0).ok()?;
    let load = read_word(bytes, 4).ok()?;
    let branch = read_word(bytes, 8).ok()?;
    if page & 0x9f00_0000 != 0x9000_0000 || page & 0x1f != 16 {
        return None;
    }
    if load & 0xffc0_0000 != 0xf940_0000 || (load >> 5) & 0x1f != 16 || load & 0x1f != 16 {
        return None;
    }
    if branch != BR_X16 {
        return None;
    }
    let immediate = (((page >> 29) & 3) as u64) | ((((page >> 5) & 0x7_ffff) as u64) << 2);
    let signed = sign_extend(immediate, 21);
    let target_page = (address as i64).checked_add(signed << 12)? as usize & !ARCH_PAGE_MASK;
    target_page.checked_add(((load >> 10) & 0xfff) as usize * 8)
}

fn scaled_signed(to: usize, from: usize, scale: usize, bits: u32) -> Result<i64> {
    let difference = (to as i128) - (from as i128);
    if difference % scale as i128 != 0 {
        return Err(Error::InvalidInlineTarget(
            "unaligned branch or literal target",
        ));
    }
    let value = difference / scale as i128;
    let minimum = -(1_i128 << (bits - 1));
    let maximum = (1_i128 << (bits - 1)) - 1;
    if !(minimum..=maximum).contains(&value) {
        return Err(Error::NoNearbyMemory);
    }
    i64::try_from(value).map_err(|_| Error::ArithmeticOverflow)
}

fn add_signed(base: usize, displacement: i64) -> Result<usize> {
    if displacement >= 0 {
        base.checked_add(displacement as usize)
    } else {
        base.checked_sub(displacement.unsigned_abs() as usize)
    }
    .ok_or(Error::ArithmeticOverflow)
}

fn sign_extend(value: u64, bits: u32) -> i64 {
    ((value << (64 - bits)) as i64) >> (64 - bits)
}

fn read_word(code: &[u8], offset: usize) -> Result<u32> {
    code.get(offset..offset + 4)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(Error::InvalidInlineTarget("truncated AArch64 entry"))
}

fn push_word(bytes: &mut TransientBytes, instruction: u32) {
    bytes.extend_from_slice(&instruction.to_le_bytes());
}

fn align_code(bytes: &mut TransientBytes, alignment: usize) {
    let padding = bytes.len().wrapping_neg() & (alignment - 1);
    bytes.resize(bytes.len() + padding, 0);
}

fn unsupported(address: usize, reason: &'static str) -> Error {
    Error::UnsupportedInstruction { address, reason }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn replacement_bti(hint: bool) -> ReplacementBti {
        ReplacementBti {
            hint,
            cache: Cell::new(None),
        }
    }

    fn decode_branch(from: usize, patch: &[u8]) -> usize {
        let instruction = u32::from_le_bytes(patch.try_into().unwrap());
        let Relocation::Branch(target) = classify(instruction, from).unwrap() else {
            panic!("expected unconditional branch")
        };
        target
    }

    #[test]
    fn detects_direct_offset_readback_of_stolen_bytes() {
        // Entry at 0x1000 is `adr x0, . + 16`; the next instruction reads
        // back through a negative offset that lands inside the stolen word.
        let words = [0x381f_0001_u32]; // ldurb w1, [x0, #-16]
        assert_eq!(
            detect_data_reference(&words, 0x1004, 0, 0x1010, 0x1000, 0x1004),
            Some((0x1004, 0x1000))
        );
        // A read that stops before the stolen bytes stays hookable.
        let words = [0x381f_8001_u32]; // ldurb w1, [x0, #-8]
        assert_eq!(
            detect_data_reference(&words, 0x1004, 0, 0x1010, 0x1000, 0x1004),
            None
        );
    }

    #[test]
    fn signed_loads_are_reads_but_integer_prefetches_are_not() {
        // LDRSB W0, [X0, #1] shares the prefetch opcode field but still reads
        // one byte; the size field distinguishes it from PRFM.
        assert_eq!(
            detect_data_reference(&[0x39c0_0400], 0x1004, 0, 0xfff, 0x1000, 0x1004),
            Some((0x1004, 0x1000))
        );

        // PRFM and PRFUM use size=3, opcode=2, but do not access the target
        // bytes and must not clobber tracked register state.
        for word in [0xf980_0400_u32, 0xf89f_8000_u32, 0xf8bf_6800] {
            assert_eq!(
                detect_data_reference(&[word], 0x1004, 0, 0xff8, 0x1000, 0x1004),
                None,
                "prefetch {word:#x} was treated as a data access"
            );
            let mut offsets = [None; 32];
            offsets[0] = Some(0);
            update_tracking(word, &mut offsets);
            assert_eq!(offsets[0], Some(0), "prefetch {word:#x} clobbered tracking");
        }
    }

    #[test]
    fn detects_register_offset_and_base_only_accesses_with_exact_widths() {
        for (word, width) in [
            (0xb87f_6800, 4),  // ldr w0, [x0, xzr]
            (0x3cff_6800, 16), // ldr q0, [x0, xzr]
            (0x387f_6801, 1),  // ldrb w1, [x0, xzr]
            (0xb8bf_6801, 4),  // ldrsw x1, [x0, xzr]
            (0xb83f_6801, 4),  // str w1, [x0, xzr]
            (0x88df_fc01, 4),  // ldar w1, [x0]
            (0x889f_fc01, 4),  // stlr w1, [x0]
            (0x885f_7c01, 4),  // ldxr w1, [x0]
            (0x8802_7c01, 4),  // stxr w2, w1, [x0]
            (0x887f_0801, 8),  // ldxp w1, w2, [x0]
            (0xc87f_0801, 16), // ldxp x1, x2, [x0]
            (0x8823_0801, 8),  // stxp w3, w1, w2, [x0]
            (0x88a1_7c02, 4),  // cas w1, w2, [x0]
            (0x0822_7c04, 8),  // casp w2, w3, w4, w5, [x0]
            (0x4822_7c04, 16), // casp x2, x3, x4, x5, [x0]
            (0xb821_0002, 4),  // ldadd w1, w2, [x0]
            (0xf821_8002, 8),  // swp x1, x2, [x0]
            (0xb8bf_c001, 4),  // ldapr w1, [x0]
            (0xd940_0001, 8),  // ldapur x1, [x0]
            (0x4c40_7000, 16), // ld1 {v0.16b}, [x0]
            (0x0c40_7000, 8),  // ld1 {v0.8b}, [x0]
            (0x0d40_0000, 1),  // ld1 {v0.b}[0], [x0]
            (0x4d40_c000, 1),  // ld1r {v0.16b}, [x0]
        ] {
            for (target, hit) in [
                (0x1000 - width, false),
                (0x1001 - width, true),
                (0x1100, false),
            ] {
                assert_eq!(
                    detect_data_reference(&[word], 0x1004, 0, target, 0x1000, 0x1004),
                    hit.then_some((0x1004, target)),
                    "access {word:#x} at {target:#x} with width {width}",
                );
            }
        }
        // Every legal extension and scale of XZR/WZR still denotes zero.
        for option in [2, 3, 6, 7] {
            for scaled in [0, 1] {
                let word = (0xb87f_6800 & !0xf000) | (option << 13) | (scaled << 12);
                assert_eq!(
                    detect_data_reference(&[word], 0x1004, 0, 0x1000, 0x1000, 0x1004),
                    Some((0x1004, 0x1000))
                );
            }
        }
    }

    #[test]
    fn base_only_and_register_offset_accesses_preserve_register_semantics() {
        for word in [
            0xb83f_6820,
            0x889f_fc20,
            0x4c40_7020,
            0x3cff_6820,
            0xd900_8020,
        ] {
            // Stores and SIMD loads through untracked X1 must not erase X0.
            assert_eq!(
                detect_data_reference(&[word, 0x3940_0002], 0x1004, 0, 0x1000, 0x1000, 0x1004),
                Some((0x1008, 0x1000)),
                "access {word:#x} clobbered X0",
            );
        }
        for (word, cleared) in [
            (0x885f_7c01, &[1][..]),
            (0x8802_7c01, &[2][..]),
            (0x887f_0801, &[1, 2][..]),
            (0x88a1_7c02, &[1][..]),
            (0x0822_7c04, &[2, 3][..]),
            (0xb821_0002, &[2][..]),
            (0xb862_6801, &[1][..]), // ldr w1, [x0, x2]
            (0xd940_8001, &[1][..]), // ldapur x1, [x0, #8]
        ] {
            let mut offsets = [Some(0); 32];
            update_tracking(word, &mut offsets);
            for (register, offset) in offsets.iter().enumerate() {
                assert_eq!(
                    offset.is_none(),
                    cleared.contains(&register),
                    "access {word:#x}, register {register}"
                );
            }
        }
        let mut offsets = [None; 32];
        offsets[0] = Some(-16);
        update_tracking(0x4cdf_7000, &mut offsets); // ld1 {v0.16b}, [x0], #16
        assert_eq!(offsets[0], Some(0));
        update_tracking(0x4cc1_7000, &mut offsets); // ld1 {v0.16b}, [x0], x1
        assert_eq!(offsets[0], None);
    }

    #[test]
    fn detects_pair_readback_of_stolen_bytes() {
        // ldp x1, x2, [x0] and stp x1, x2, [x0] each transfer sixteen bytes.
        for word in [0xa940_0801_u32, 0xa900_0801_u32] {
            assert_eq!(
                detect_data_reference(&[word], 0x1004, 0, 0xff8, 0x1000, 0x1004),
                Some((0x1004, 0xff8)),
                "pair instruction {word:#x} missed readback"
            );
        }
        // SIMD&FP pair transfers use the same effective-address tracking;
        // Q-register pairs transfer thirty-two bytes as one access.
        for word in [0xad7f_8801_u32, 0xad3f_8801_u32] {
            assert_eq!(
                detect_data_reference(&[word], 0x1004, 0, 0x1010, 0x1000, 0x1004),
                Some((0x1004, 0x1000)),
                "vector pair instruction {word:#x} missed readback"
            );
        }
        // Loading through x0 makes both destination registers unknown.
        let words = [0xa940_0801_u32, 0xf940_0023]; // ldp; ldr x3, [x1]
        assert_eq!(
            detect_data_reference(&words, 0x1004, 0, 0x2000, 0x1000, 0x1004),
            None
        );
        // A store pair reads its source registers; it must not clear a
        // tracked source just because that register is encoded as Rt.
        let words = [0xa900_0820_u32, 0x3900_0002]; // stp x0, x2, [x1]; ldrb w2, [x0]
        assert_eq!(
            detect_data_reference(&words, 0x1004, 0, 0x1000, 0x1000, 0x1004),
            Some((0x1008, 0x1000))
        );

        // LDPSW transfers two 32-bit words even though each destination is
        // an X register; its pair width is eight bytes, not sixteen.
        assert_eq!(
            detect_data_reference(
                &[0x6940_0440], // ldpsw x0, x1, [x2]
                0x1004,
                2,
                0xffc,
                0x1000,
                0x1004,
            ),
            Some((0x1004, 0xffc))
        );
        assert_eq!(
            detect_data_reference(&[0x6940_0440], 0x1004, 2, 0xff8, 0x1000, 0x1004,),
            None
        );
    }

    #[test]
    fn pair_addressing_modes_use_their_effective_addresses() {
        for (word, target, effective) in [
            (0xa941_0801_u32, 0xff0, 0x1000),  // [x0, #16]
            (0xa9c1_0801_u32, 0xff0, 0x1000),  // [x0, #16]!
            (0xa8c1_0801_u32, 0x1000, 0x1000), // [x0], #16
            (0xa8bf_0801_u32, 0x1000, 0x1000), // [x0], #-16 (store)
        ] {
            assert_eq!(
                detect_data_reference(&[word], 0x1004, 0, target, 0x1000, 0x1004),
                Some((0x1004, effective)),
                "pair mode {word:#x} used the wrong address"
            );
        }
    }

    #[test]
    fn pair_pre_index_writeback_updates_tracking() {
        let mut offsets = [None; 32];
        offsets[0] = Some(0);
        update_tracking(0xa9c1_0801, &mut offsets); // ldp x1, x2, [x0, #16]!
        assert_eq!(offsets[0], Some(16));
        assert_eq!(offsets[1], None);
        assert_eq!(offsets[2], None);
    }

    #[test]
    fn non_temporal_pairs_do_not_write_back() {
        for word in [0xa841_0801_u32, 0xa83f_0801_u32] {
            let mut offsets = [None; 32];
            offsets[0] = Some(0);
            update_tracking(word, &mut offsets);
            assert_eq!(
                offsets[0],
                Some(0),
                "pair {word:#x} unexpectedly wrote back"
            );
        }
    }

    #[test]
    fn pair_width_and_scale_match_ldpsw_and_stgp() {
        assert_eq!(
            detect_data_reference(
                &[0x697f_0801], // ldpsw x1, x2, [x0, #-8]
                0x1004,
                0,
                0x1008,
                0x1000,
                0x1004,
            ),
            Some((0x1004, 0x1000))
        );
        assert_eq!(
            detect_data_reference(
                &[0x6900_8801], // stgp x1, x2, [x0, #16]
                0x1004,
                0,
                0xff0,
                0x1000,
                0x1004,
            ),
            Some((0x1004, 0x1000))
        );
    }

    #[test]
    fn pair_writeback_overlap_drops_base_tracking() {
        let mut offsets = [None; 32];
        offsets[0] = Some(0);
        update_tracking(0xa9c1_0800, &mut offsets); // ldp x0, x2, [x0, #16]!
        assert_eq!(offsets[0], None);
    }

    #[test]
    fn detects_readback_through_register_and_constant_aliases() {
        // mov x5, x0; ldur w2, [x5, #-16]
        let words = [0xaa00_03e5, 0xb85f_00a2];
        assert_eq!(
            detect_data_reference(&words, 0x1004, 0, 0x1010, 0x1000, 0x1004),
            Some((0x1008, 0x1000))
        );
        // sub x6, x0, #16; ldrb w3, [x6]
        let words = [0xd100_4006, 0x3900_00c3];
        assert_eq!(
            detect_data_reference(&words, 0x1004, 0, 0x1010, 0x1000, 0x1004),
            Some((0x1008, 0x1000))
        );
    }

    #[test]
    fn data_reference_tracking_survives_window_boundaries() {
        // The first window aliases x0 into x1. The next window reads through
        // x1, so its state must retain the alias established earlier.
        let mut offsets = [None; 32];
        offsets[0] = Some(0);
        assert_eq!(
            detect_data_reference_with_offsets(
                &[0xaa00_03e1], // mov x1, x0
                0x1004,
                &mut offsets,
                0x1100,
                0x1000,
                0x1004,
            ),
            None
        );
        assert_eq!(offsets[1], Some(0));
        assert_eq!(
            detect_data_reference_with_offsets(
                &[0x3810_0022], // ldurb w2, [x1, #-256]
                0x1084,
                &mut offsets,
                0x1100,
                0x1000,
                0x1004,
            ),
            Some((0x1084, 0x1000))
        );
    }

    #[test]
    fn readback_analysis_continues_through_hints() {
        // NOP, BTI, and PAC hints do not end the linear window, so tracking
        // must survive them and still reject a later stolen-byte readback.
        for hint in [NOP, BTI_C, 0xd503_233f] {
            let words = [0xaa00_03e5, hint, 0xb85f_00a2];
            assert_eq!(
                detect_data_reference(&words, 0x1004, 0, 0x1010, 0x1000, 0x1004),
                Some((0x100c, 0x1000)),
                "hint {hint:#x} stopped readback tracking"
            );
        }
    }

    #[test]
    fn detects_upper_half_and_correctly_scaled_unsigned_offsets() {
        // ldr x4, [x0, #2048]; ldrsh x1, [x0, #8]
        let words = [0xf944_0004_u32];
        assert_eq!(
            detect_data_reference(&words, 0x1004, 0, 0x800, 0x1000, 0x1004),
            Some((0x1004, 0x1000))
        );
        let words = [0x7980_1001_u32];
        assert_eq!(
            detect_data_reference(&words, 0x1004, 0, 0xff8, 0x1000, 0x1002),
            Some((0x1004, 0x1000))
        );
    }

    #[test]
    fn vector_byte_width_does_not_use_quadword_width() {
        // ldr b2, [x0] one byte before the stolen word cannot reach it.
        let words = [0x3d40_0002_u32];
        assert_eq!(
            detect_data_reference(&words, 0x1004, 0, 0xffc, 0x1000, 0x1004),
            None
        );
        // ldr q2, [x0] starting sixteen bytes before it does reach it.
        let words = [0x3dc0_0002_u32];
        assert_eq!(
            detect_data_reference(&words, 0x1004, 0, 0xff1, 0x1000, 0x1004),
            Some((0x1004, 0xff1))
        );
    }

    #[test]
    fn vector_loads_do_not_clobber_gpr_tracking() {
        // V registers are separate from X registers. A vector load into V0
        // must leave an X0 address established by ADR/ADRP available to a
        // later scalar access.
        for vector_load in [0x3dc0_0020_u32, 0xad40_0021_u32] {
            let words = [vector_load, 0x3900_0002_u32];
            assert_eq!(
                detect_data_reference(&words, 0x1004, 0, 0x1000, 0x1000, 0x1004),
                Some((0x1008, 0x1000)),
                "vector load {vector_load:#x} clobbered GPR tracking"
            );
        }
    }

    #[test]
    fn simd_and_fp_alu_do_not_clobber_gpr_tracking() {
        for word in [
            0x1e20_2800_u32, // fadd s0, s0, s0
            0x4e20_8400_u32, // add v0.16b, v0.16b, v0.16b
            0x9e67_0000_u32, // fmov d0, x0
            0x1e27_0000_u32, // fmov s0, w0
            0x9e42_fc00_u32, // scvtf d0, x0, #1
            0x1e03_fc00_u32, // ucvtf s0, w0, #1
            0x1f58_0820_u32, // fmadd d0, d1, d24, d2
            0x1f19_8820_u32, // fmsub s0, s1, s25, s2
            0x5f7f_fc00_u32, // fcvtzs d0, d0, #1
        ] {
            let mut offsets = [None; 32];
            offsets[0] = Some(0);
            update_tracking(word, &mut offsets);
            assert_eq!(offsets[0], Some(0), "SIMD/FP op {word:#x} clobbered x0");
        }
        let mut offsets = [None; 32];
        offsets[0] = Some(0);
        update_tracking(0x9e38_0000, &mut offsets); // fcvtzs x0, s0
        assert_eq!(offsets[0], None);
        for word in [
            0x9e58_fc00_u32, // fcvtzs x0, d0, #1
            0x9e59_fc00_u32, // fcvtzu x0, d0, #1
            0x1e18_fc00_u32, // fcvtzs w0, s0, #1
            0x9ed9_0000_u32, // fcvtzu x0, h0, #64
        ] {
            let mut offsets = [None; 32];
            offsets[0] = Some(0);
            offsets[1] = Some(8);
            update_tracking(word, &mut offsets);
            assert_eq!(
                offsets[0], None,
                "fixed-point conversion {word:#x} retained x0"
            );
            assert_eq!(offsets[1], Some(8));
            assert_eq!(
                detect_data_reference(&[word, 0x385f_0001], 0x1004, 0, 0x1010, 0x1000, 0x1004),
                None,
                "fixed-point conversion {word:#x} caused a stale-address readback"
            );
        }
    }

    #[test]
    fn indexed_and_unscaled_memory_accesses_keep_their_real_widths() {
        for (word, target) in [
            (0xb85f_0c01_u32, 0x1010), // ldr w1, [x0, #-16]!
            (0xb85f_0401_u32, 0x1000), // ldr w1, [x0], #-16
            (0x3cdf_0001_u32, 0x1010), // ldur q1, [x0, #-16]
            (0xd95f_8001_u32, 0x1008), // ldapur x1, [x0, #-8]
            (0x19df_f001_u32, 0x1001), // ldapursb w1, [x0, #-1]
            (0xd91f_8001_u32, 0x1008), // stlur x1, [x0, #-8]
        ] {
            assert_eq!(
                detect_data_reference(&[word], 0x1004, 0, target, 0x1000, 0x1004),
                Some((0x1004, 0x1000)),
                "indexed access {word:#x} missed readback"
            );
        }
        // A byte load ending at the stolen range must not be widened to Q.
        assert_eq!(
            detect_data_reference(&[0x3c5f_f001], 0x1004, 0, 0xfff, 0x1000, 0x1004),
            None
        );
        let mut offsets = [None; 32];
        offsets[0] = Some(0);
        update_tracking(0xb81f_0401, &mut offsets); // str w1, [x0], #-16
        assert_eq!(offsets[0], Some(-16));
        // A store whose source register is the tracked base must not clear
        // that base as if it were a load destination.
        assert_eq!(
            detect_data_reference(
                &[0xb900_0020, 0x3900_0002], // str w0, [x1]; ldrb w2, [x0]
                0x1004,
                0,
                0x1000,
                0x1000,
                0x1004,
            ),
            Some((0x1008, 0x1000))
        );
    }

    #[test]
    fn unknown_rewrites_and_terminators_stop_tracking() {
        // movz x0, #0 overwrites the tracked register, so a following read
        // of x0 is not provably inside the stolen bytes.
        let words = [0xd280_0000, 0x3900_0001]; // movz x0, #0; ldrb w1, [x0]
        assert_eq!(
            detect_data_reference(&words, 0x1004, 0, 0x1010, 0x1000, 0x1004),
            None
        );
        // An unconditional branch ends the linear window before the read.
        let words = [0x1400_0002, 0x381f_0001];
        assert_eq!(
            detect_data_reference(&words, 0x1004, 0, 0x1010, 0x1000, 0x1004),
            None
        );
        for branch in [0x5400_0000_u32, 0x3400_0000, 0x3600_0000] {
            let words = [branch, 0x3900_0001];
            assert_eq!(
                detect_data_reference(&words, 0x1004, 0, 0x1000, 0x1000, 0x1004),
                Some((0x1008, 0x1000)),
                "conditional branch {branch:#x} cleared the tracked base"
            );
        }
        // B.AL and B.NV are treated as unconditional by relocation.
        assert!(linear_flow_terminated(&[0x5400_004e]));
        assert!(linear_flow_terminated(&[0x5400_004f]));
    }

    #[test]
    fn direct_patch_targets_replacement_and_arena_starts_with_trampoline() {
        let analysis = analyze(0x1000, &0xd503_201f_u32.to_le_bytes()).unwrap();
        let generated = generate(
            &analysis,
            0x2000,
            0x3000,
            &[],
            false,
            &replacement_bti(true),
            false,
        )
        .unwrap();

        assert_eq!(
            decode_branch(analysis.patch_address, &generated.patch),
            0x3000
        );
        assert_eq!(generated.original, 0x2000);
        assert_eq!(
            u32::from_le_bytes(generated.bytes[..4].try_into().unwrap()),
            0xd503_201f
        );
        let guarded = generate(
            &analysis,
            0x2000,
            0x3000,
            &[],
            true,
            &replacement_bti(true),
            false,
        )
        .unwrap();
        assert_eq!(
            u32::from_le_bytes(guarded.bytes[..4].try_into().unwrap()),
            BTI_JC
        );
        assert!(generated.auxiliary.is_none());
    }

    /// Reconstructs the 64-bit value a MOVZ/MOVK chain writes into `x0`.
    fn rematerialised_x0(bytes: &[u8]) -> Option<u64> {
        let mut value = 0_u64;
        let mut seen = false;
        for chunk in bytes.as_chunks::<4>().0 {
            let word = u32::from_le_bytes(*chunk);
            // 64-bit MOVZ is 1_10_100101 and MOVK is 1_11_100101 in bits 31:23.
            let opcode = word >> 23;
            let movz = opcode == 0x1a5;
            let movk = opcode == 0x1e5;
            if (!movz && !movk) || word & 0x1f != 0 {
                continue;
            }
            let shift = ((word >> 21) & 3) * 16;
            let immediate = u64::from((word >> 5) & 0xffff) << shift;
            // MOVZ clears the register; MOVK merges into it.
            value = if movz { immediate } else { value | immediate };
            seen = true;
        }
        seen.then_some(value)
    }

    #[test]
    fn adrp_is_rematerialised_to_the_same_page_address() {
        // ADRP adds its scaled immediate to the 4 KiB page of its own address,
        // so what it computes depends on where the instruction sits. Relocating
        // one into an arena must not re-encode that field: the same encoding at
        // the new address would name a different page. The backend writes the
        // resolved address out with MOVZ/MOVK instead, and this pins that the
        // chain resolves to what the original instruction computed.
        //
        // `adrp x0, #0x2000` is immlo=2, immhi=0, Rd=0. At 0x1000 it selects
        // page 0x1000 + 2 * 4096 = 0x3000.
        const ADRP_X0_TWO_PAGES: u32 = 0xd000_0000;
        let target = 0x1000_usize;
        let arena = 0x50_0000_usize;
        let analysis = analyze(target, &ADRP_X0_TWO_PAGES.to_le_bytes()).unwrap();
        let generated = generate(
            &analysis,
            arena,
            target + 0x40,
            &[],
            false,
            &replacement_bti(true),
            false,
        )
        .unwrap();

        let word = u32::from_le_bytes(generated.bytes[..4].try_into().unwrap());
        assert_eq!(
            word & 0x9f00_001f,
            0x9000_0000,
            "expected ADRP x0, got {word:#x}"
        );
        assert_eq!(adrp_page(word, generated.original), 0x3000);
        assert!(rematerialised_x0(&generated.bytes).is_none());
    }

    #[test]
    fn adr_xzr_does_not_create_a_data_reference() {
        for word in [0x1000_001f_u32, 0x9000_001f_u32] {
            let analysis = analyze(0x1000, &word.to_le_bytes()).unwrap();
            assert!(analysis.address_references.is_empty(), "ADR/ADRP {word:#x}");
        }
    }

    #[test]
    fn rejects_pc_relative_addresses_into_the_stolen_instruction() {
        // adr x0, .: the produced address is the patched entry itself.
        assert!(matches!(
            analyze(0x1000, &0x1000_0000_u32.to_le_bytes()),
            Err(Error::UnsupportedInstruction { .. })
        ));
        // ADRP names a page; its consumers determine whether bytes overlap.
        let analysis = analyze(0x1000, &0x9000_0000_u32.to_le_bytes()).unwrap();
        assert_eq!(analysis.address_references.len(), 1);
        assert_eq!(analysis.address_references[0].target, 0x1000);
        // adr x0, . + 16 addresses bytes outside the overwritten span.
        assert!(analyze(0x1000, &0x1000_0080_u32.to_le_bytes()).is_ok());
    }

    #[test]
    fn far_patch_targets_the_relay_at_the_arena_head() {
        let analysis = analyze(0x1000, &0xd503_201f_u32.to_le_bytes()).unwrap();
        let arena = 0x2000;
        let replacement = arena + (1 << 27);
        let generated = generate(
            &analysis,
            arena,
            replacement,
            &[],
            false,
            &replacement_bti(false),
            false,
        )
        .unwrap();

        // A far replacement is reached through the relay at the arena head, so
        // the entry patch targets that relay, not the trampoline behind it.
        assert_eq!(generated.patch.len(), analysis.original.len());
        assert_eq!(
            decode_branch(analysis.patch_address, &generated.patch),
            arena
        );
        // The relay reaches its destination through a page-relative literal.
        assert_eq!(
            u64::from_le_bytes(generated.bytes[16..24].try_into().unwrap()) as usize,
            replacement
        );
        // The trampoline follows the relay. An unguarded page does not spend
        // an instruction on BTI.
        assert_ne!(generated.original, arena);
        let landing = generated.original - arena;
        assert_ne!(
            u32::from_le_bytes(generated.bytes[landing..landing + 4].try_into().unwrap()),
            BTI_JC
        );
        // The relocated entry returns to the instruction the patch replaced.
        let back_edge = landing + analysis.original.len();
        assert_eq!(
            decode_branch(
                arena + back_edge,
                &generated.bytes[back_edge..back_edge + 4]
            ),
            0x1004
        );
    }

    #[test]
    fn far_patch_uses_a_direct_relay_when_the_arena_reaches_the_replacement() {
        let analysis = analyze(0x1000, &0xd503_201f_u32.to_le_bytes()).unwrap();
        let replacement = 0x1000 + (1 << 27) + 0x1000;
        let arena = replacement - (1 << 26);
        let generated = generate(
            &analysis,
            arena,
            replacement,
            &[],
            false,
            &replacement_bti(false),
            false,
        )
        .unwrap();

        assert_eq!(generated.patch.len(), analysis.original.len());
        assert_eq!(
            decode_branch(analysis.patch_address, &generated.patch),
            arena
        );
        assert_eq!(decode_branch(arena, &generated.bytes[..4]), replacement);
        assert_ne!(generated.original, arena);
    }

    #[test]
    fn inplace_far_rejects_a_non_landing_replacement() {
        // The in-place far form ends in `br x16`, which BTI type-checks, so a
        // replacement without a matching landing must fail closed.
        let mut window = Vec::new();
        for _ in 0..7 {
            window.extend_from_slice(&0xd503_201f_u32.to_le_bytes());
        }
        let analysis = analyze_inplace_far(0x4000, &window).unwrap();
        assert!(matches!(
            generate(
                &analysis,
                0x2000,
                0x2000 + (1 << 27),
                &[],
                false,
                &replacement_bti(true),
                false
            ),
            Err(Error::MappingChanged)
        ));
    }

    /// One captured private `r-x` range, as a stubbed mapping snapshot.
    fn executable_range(start: usize, length: usize) -> MapInfo {
        MapInfo {
            start,
            end: start + length,
            perms: crate::maps::MapPerms::READ | crate::maps::MapPerms::EXEC,
            is_private: true,
            offset: 0,
            device: crate::maps::DeviceId::new(0, 0),
            inode: 0,
            path: None,
        }
    }

    #[test]
    fn redirects_to_waits_for_the_complete_generated_hook() {
        let page_size = crate::sys::page_size().unwrap();
        // Page 0 holds one untouched entry, page 1 a live one, page 2 the
        // arena and page 3 the replacement: `redirects_to` validates every word
        // through the capture, so all of them have to live inside it.
        // SAFETY: this test owns the fresh anonymous mapping.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page_size * 4,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        let base = mapping as usize;
        let arena = base + page_size * 2;
        let replacement = base + page_size * 3;
        // Seven stolen instructions cover the complete self-contained patch.
        let code = [NOP.to_le_bytes(); 7].concat();
        let maps = [executable_range(base, page_size * 4)];

        // An entry that has not been patched yet redirects nowhere, so a second
        // installation of the same triple must still be allowed.
        let idle = analyze_inplace_far(base, &code).unwrap();
        assert!(!redirects_to(&idle, replacement, &maps).unwrap());

        // A published entry carries exactly what the installer writes: the
        // branch into the arena, the relocated window, and the branch back.
        let patch_address = base + page_size;
        // The captured window has to cover the complete stolen span so the
        // trampoline back edge is validated at the address generation uses.
        let live = analyze_inplace_far(patch_address, &code).unwrap();
        assert_eq!(live.original.len(), code.len());
        let generated = generate(
            &live,
            arena,
            replacement,
            &[],
            false,
            &replacement_bti(false),
            false,
        )
        .unwrap();
        assert_eq!(generated.patch.len(), code.len());
        assert_eq!(generated.original, arena);
        // SAFETY: every range belongs to the mapping this test owns.
        unsafe {
            std::ptr::copy_nonoverlapping(
                generated.patch.as_ptr(),
                std::ptr::with_exposed_provenance_mut::<u8>(patch_address),
                generated.patch.len(),
            );
            std::ptr::copy_nonoverlapping(
                generated.bytes.as_ptr(),
                arena as *mut u8,
                generated.bytes.len(),
            );
        }
        assert!(redirects_to(&live, replacement, &maps).unwrap());
        assert!(!redirects_to(&live, replacement + 0x40, &maps).unwrap());

        // A guarded far hook reaches the replacement through a direct relay at
        // the arena head. The trampoline audit must follow that relay too, not
        // merely recognize the relocated original bytes and back edge.
        let short = analyze(patch_address, &0xd503_201f_u32.to_le_bytes()).unwrap();
        let far_replacement = patch_address + 0x0800_0000;
        let generated = generate(
            &short,
            arena,
            far_replacement,
            &[],
            true,
            &replacement_bti(false),
            false,
        )
        .unwrap();
        // SAFETY: every range belongs to the mapping this test owns.
        unsafe {
            std::ptr::copy_nonoverlapping(
                generated.patch.as_ptr(),
                std::ptr::with_exposed_provenance_mut::<u8>(patch_address),
                generated.patch.len(),
            );
            std::ptr::copy_nonoverlapping(
                generated.bytes.as_ptr(),
                arena as *mut u8,
                generated.bytes.len(),
            );
        }
        assert!(trampoline_redirects_to(&short, far_replacement, &maps).unwrap());
        assert!(!trampoline_redirects_to(&short, far_replacement + 0x40, &maps).unwrap());
        // SAFETY: the mapping is live and this test owns it.
        assert_eq!(unsafe { libc::munmap(mapping, page_size * 4) }, 0);
    }

    #[test]
    fn inplace_far_patch_is_self_contained_and_copies_the_window() {
        let mut code = Vec::new();
        for _ in 0..7 {
            code.extend_from_slice(&0xd503_201f_u32.to_le_bytes());
        }
        let analysis = analyze_inplace_far(0x1000, &code).unwrap();
        let arena = 0x2000_usize;
        let replacement = arena + (1 << 27);
        let generated = generate(
            &analysis,
            arena,
            replacement,
            &[],
            false,
            &replacement_bti(false),
            false,
        )
        .unwrap();
        assert_eq!(generated.patch.len(), code.len());
        assert!(is_ldr_x16_br(&generated.patch, replacement));
        assert_eq!(
            u64::from_le_bytes(generated.bytes[40..48].try_into().unwrap()) as usize,
            0x1010
        );
        assert_eq!(&generated.bytes[..28], code.as_slice());
        assert_eq!(generated.original, arena);
        let guarded = generate(
            &analysis,
            arena,
            replacement,
            &[],
            true,
            &replacement_bti(false),
            false,
        )
        .unwrap();
        assert_eq!(
            u32::from_le_bytes(guarded.bytes[..4].try_into().unwrap()),
            BTI_JC
        );
        assert_eq!(
            u32::from_le_bytes(guarded.patch[16..20].try_into().unwrap()),
            BTI_JC
        );
        assert_eq!(
            u32::from_le_bytes(guarded.patch[20..24].try_into().unwrap()),
            0xa8c1_47f0
        );
    }

    #[test]
    fn inplace_far_relocates_pc_relative_instructions() {
        static LITERAL: u64 = 0x1234_5678_9abc_def0;
        let literal_address = (&raw const LITERAL).expose_provenance();
        let target = literal_address - 0x100;
        let literal = 0x5800_0000 | (((literal_address - target) / 4) as u32) << 5;
        let words: [u32; 7] = [
            0x1000_0400, // adr x0, #0x80
            NOP,
            0x5400_0040, // b.eq .+8
            literal,
            NOP,
            NOP,
            NOP,
        ];
        let code = words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        let analysis = analyze_inplace_far(target, &code).unwrap();
        assert_eq!(analysis.address_references.len(), 1);
        assert_eq!(max_distance(&analysis, 0), usize::MAX);
        let generated = generate(
            &analysis,
            target.wrapping_add(0x4000_0000),
            target + 0x100,
            &[],
            false,
            &replacement_bti(false),
            false,
        )
        .unwrap();

        assert_eq!(generated.patch.len(), 28);
        assert!(generated.bytes.len() > 28);
        assert_eq!(
            u32::from_le_bytes(generated.patch[16..20].try_into().unwrap()),
            BTI_JC
        );
    }

    #[test]
    fn inplace_far_preserves_stack_prologue_across_branch_range() {
        let page_size = crate::sys::page_size().unwrap();
        let arena_offset = (MAX_DISTANCE / page_size + 2) * page_size;
        let length = arena_offset
            .checked_add(page_size)
            .expect("test mapping length overflow");
        // SAFETY: this test owns the complete anonymous mapping.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        let base = mapping as usize;
        let arena = base + arena_offset;
        let words: [u32; 10] = [
            0xf81a_0ffa, // str x26, [sp, #-0x60]!
            0xa900_6ffc, // stp x28, x27, [sp]
            0xa901_63f9, // stp x25, x24, [sp, #0x10]
            0xa902_5bf7, // stp x23, x22, [sp, #0x20]
            0xa903_53f5, // stp x21, x20, [sp, #0x30]
            NOP,
            NOP,
            0x9101_83ff, // add sp, sp, #0x60
            0xd280_0020, // mov x0, #1
            0xd65f_03c0, // ret
        ];
        let code = words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        let analysis = analyze_inplace_far(base, &code).unwrap();
        let generated = generate(
            &analysis,
            arena,
            arena + 0x1000,
            &[],
            false,
            &replacement_bti(false),
            false,
        )
        .unwrap();
        // SAFETY: both pages belong to the mapping this test owns.
        let (protected, result, unmapped) = unsafe {
            std::ptr::copy_nonoverlapping(
                code.as_ptr(),
                std::ptr::with_exposed_provenance_mut::<u8>(base),
                code.len(),
            );
            std::ptr::copy_nonoverlapping(
                generated.patch.as_ptr(),
                std::ptr::with_exposed_provenance_mut::<u8>(base),
                generated.patch.len(),
            );
            std::ptr::copy_nonoverlapping(
                generated.bytes.as_ptr(),
                std::ptr::with_exposed_provenance_mut::<u8>(arena),
                generated.bytes.len(),
            );
            let protected = libc::mprotect(mapping, page_size, libc::PROT_READ | libc::PROT_EXEC)
                == 0
                && libc::mprotect(
                    arena as *mut libc::c_void,
                    page_size,
                    libc::PROT_READ | libc::PROT_EXEC,
                ) == 0;
            let original = std::mem::transmute::<*const (), unsafe extern "C" fn() -> usize>(
                std::ptr::with_exposed_provenance(generated.original),
            );
            let mut called = 0;
            if protected {
                called = original();
            }
            let result = std::hint::black_box(called);
            let unmapped = libc::munmap(mapping, length) == 0;
            (protected, result, unmapped)
        };
        assert!(protected, "test pages could not be made executable");
        assert_eq!(result, 1);
        assert!(unmapped, "test mapping could not be released");
    }

    #[test]
    fn inplace_far_skips_a_leading_bti_landing() {
        let mut code = BTI_C.to_le_bytes().to_vec();
        for _ in 0..7 {
            code.extend_from_slice(&0xd503_201f_u32.to_le_bytes());
        }
        let analysis = analyze_inplace_far(0x1000, &code).unwrap();
        assert_eq!(analysis.patch_address, 0x1004);
        let generated = generate(
            &analysis,
            0x2000,
            0x2000 + (1 << 27),
            &[],
            true,
            &replacement_bti(false),
            false,
        )
        .unwrap();
        assert_eq!(generated.patch.len(), 28);
        assert!(is_ldr_x16_br(&generated.patch, 0x2000 + (1 << 27)));
    }

    #[test]
    fn inplace_far_preserves_a_pac_landing_without_signing_replacement_lr() {
        let mut code = 0xd503_233f_u32.to_le_bytes().to_vec();
        for _ in 0..7 {
            code.extend_from_slice(&0xd503_201f_u32.to_le_bytes());
        }
        let analysis = analyze_inplace_far(0x1000, &code).unwrap();
        let generated = generate(
            &analysis,
            0x2000,
            0x3000,
            &[],
            true,
            &replacement_bti(false),
            false,
        )
        .unwrap();
        assert_eq!(generated.patch.len(), 32);
        assert_eq!(&generated.patch[..4], &BTI_C.to_le_bytes());
        assert_eq!(
            &generated.bytes[..8],
            &[BTI_JC.to_le_bytes(), 0xd503_233f_u32.to_le_bytes()].concat()
        );
    }

    #[test]
    fn preserves_bti_and_rejects_call_families() {
        let mut code = BTI_C.to_le_bytes().to_vec();
        code.extend_from_slice(&0xd503_201f_u32.to_le_bytes());
        assert_eq!(analyze(0x1000, &code).unwrap().patch_address, 0x1004);
        for instruction in [0x9400_0000, 0xd63f_0000, 0xd73f_0800] {
            assert!(matches!(
                classify(instruction, 0x1000),
                Err(Error::UnsupportedInstruction { .. })
            ));
        }
    }

    #[test]
    fn rejects_exception_generation() {
        for instruction in [0xd400_0001, 0xd420_0000] {
            assert!(matches!(
                classify(instruction, 0x1000),
                Err(Error::UnsupportedInstruction { .. })
            ));
        }
    }

    #[test]
    fn treats_al_and_nv_conditional_branches_as_unconditional() {
        for condition in [14, 15] {
            assert!(matches!(
                classify(0x5400_0040 | condition, 0x1000),
                Ok(Relocation::Branch(0x1008))
            ));
        }
    }

    #[test]
    fn decodes_test_bit_branches_with_nonzero_bit_numbers() {
        for (instruction, address, target) in [
            (0x36f8_0040_u32, 0x1000, 0x1008), // tbz x0, #31, .+8
            (0x36ff_ffc0_u32, 0x1000, 0x0ff8), // tbz x0, #31, .-8
            (0x3700_0041_u32, 0x1000, 0x1008), // tbnz x1, #0, .+8
        ] {
            assert!(
                matches!(
                    classify(instruction, address),
                    Ok(Relocation::Conditional { target: decoded, .. }) if decoded == target
                ),
                "test-bit branch {instruction:#x} decoded to the wrong target"
            );
        }
    }

    #[test]
    fn literal_relocation_loads_a_local_copy() {
        static LITERAL: u64 = 0x1234_5678_9abc_def0;
        let literal_address = (&raw const LITERAL).expose_provenance();
        let target = literal_address - 0x100;
        let immediate = ((literal_address - target) / 4) as u32;
        let instruction = 0x5800_0000 | (immediate << 5);
        let analysis = analyze(target, &instruction.to_le_bytes()).unwrap();
        let generated = generate(
            &analysis,
            target + 0x1000,
            target + 0x100,
            &[],
            false,
            &replacement_bti(false),
            false,
        )
        .unwrap();
        let relocated_address = generated.original;
        let offset = relocated_address - (target + 0x1000);
        let instruction =
            u32::from_le_bytes(generated.bytes[offset..offset + 4].try_into().unwrap());
        assert_eq!(instruction & 0x00ff_ffe0, 2 << 5);
        let copy = u64::from_le_bytes(generated.bytes[offset + 8..offset + 16].try_into().unwrap());
        assert_eq!(copy, LITERAL);
    }

    #[test]
    fn far_window_branches_and_literals_remain_aligned() {
        #[repr(align(16))]
        struct AlignedLiteral([u8; 16]);
        static LITERAL: AlignedLiteral = AlignedLiteral([
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
            0x1e, 0x1f,
        ]);
        let literal_address = &LITERAL.0 as *const u8 as usize;
        let target = literal_address - 0x100;
        let load = 0x9c00_0000 | ((0x100 / 4) << 5);
        let words = [load, NOP, 0x5400_0080, NOP, NOP, NOP, 0xd65f_03c0];
        let code = words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        let analysis = analyze_inplace_far(target, &code).unwrap();
        let arena = 0x8000_0000;
        assert!(!branch_reaches(analysis.patch_address, arena));
        let generated = generate(
            &analysis,
            arena,
            target + 0x100,
            &[],
            false,
            &replacement_bti(false),
            false,
        )
        .unwrap();

        let ret_offset = generated
            .bytes
            .windows(4)
            .position(|bytes| bytes == 0xd65f_03c0_u32.to_le_bytes())
            .expect("missing relocated terminal");
        let ret_address = arena + ret_offset;
        let mut branch_address = None;
        for offset in (0..generated.bytes.len()).step_by(4) {
            let word = u32::from_le_bytes(generated.bytes[offset..offset + 4].try_into().unwrap());
            if let Ok(Relocation::Branch(target)) = classify(word, arena + offset)
                && target == ret_address
            {
                branch_address = Some(arena + offset);
                break;
            }
        }
        assert!(
            branch_address.is_some(),
            "conditional branch did not reach the terminal"
        );

        let data_offset = generated
            .bytes
            .windows(LITERAL.0.len())
            .position(|bytes| bytes == LITERAL.0)
            .expect("missing copied literal");
        assert_eq!(data_offset % 16, 0);
        let mut literal_target = None;
        for offset in (0..data_offset).step_by(4) {
            let word = u32::from_le_bytes(generated.bytes[offset..offset + 4].try_into().unwrap());
            if let Ok(Relocation::Literal { target, .. }) = classify(word, arena + offset) {
                literal_target = Some(target);
                break;
            }
        }
        assert_eq!(literal_target, Some(arena + data_offset));
    }

    #[test]
    fn far_branch_to_a_late_window_target_is_relocated() {
        let words = [NOP, 0x5400_0080, NOP, NOP, NOP, NOP, 0xd65f_03c0];
        let code = words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        let analysis = analyze_inplace_far(0x1000, &code).unwrap();
        let generated = generate(
            &analysis,
            0x8000_0000,
            0x3000,
            &[],
            false,
            &replacement_bti(false),
            false,
        )
        .expect("a late in-window target must be relocated");
        assert!(generated.bytes.len() > analysis.original.len());
    }

    #[test]
    fn far_unconditional_branch_ends_entry() {
        let target = 0x1000 + MAX_DISTANCE;
        let words = [
            encode_b(0x1000, target).unwrap(),
            NOP,
            NOP,
            NOP,
            NOP,
            NOP,
            NOP,
        ];
        let code = words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        let error = analyze_inplace_far(0x1000, &code)
            .err()
            .expect("an unconditional branch unexpectedly remained inside the window");

        assert!(
            matches!(error, Error::UnsupportedInstruction { .. }),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn far_conditional_needs_a_reachable_arena() {
        let conditional = 0x5400_8000; // b.eq .+0x1000
        let words = [conditional, NOP, NOP, NOP, NOP, NOP, NOP];
        let code = words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        let analysis = analyze_inplace_far(0x1000, &code).unwrap();
        let error = generate(
            &analysis,
            0x8000_0000,
            0x3000,
            &[],
            false,
            &replacement_bti(false),
            false,
        )
        .err()
        .expect("an out-of-range conditional branch unexpectedly succeeded");

        assert!(
            matches!(error, Error::NoNearbyMemory),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn far_branch_window_keeps_usable_boundary_pages_after_expansion() {
        #[repr(align(16))]
        struct Literal([u8; 16]);
        static LITERAL: Literal = Literal([0x35; 16]);
        let literal = LITERAL.0.as_ptr() as usize;
        let target = literal - 0x100;
        let page_size = crate::sys::page_size().unwrap();
        for opcode in [
            0x5400_0000,
            0xb400_0000,
            0xb500_0000,
            0x3600_0000,
            0x3700_0000,
            0,
        ] {
            for backwards in [false, true] {
                let mut words = [NOP; 7];
                words[0] = encode_adr_reg(target, target + 0x200, 0).unwrap();
                words[1] = 0x9c00_0000 | (((literal - (target + 4)) / 4) as u32) << 5;
                if opcode == 0 {
                    let from = target + 24;
                    let destination = if backwards {
                        from - MAX_DISTANCE
                    } else {
                        from + MAX_DISTANCE
                    };
                    words[6] = encode_b(from, destination).unwrap();
                } else {
                    let mask = if opcode & 0x7e00_0000 == 0x3600_0000 {
                        0x3fff
                    } else {
                        0x7ffff
                    };
                    let immediate = if backwards {
                        (-0x400_i32) as u32
                    } else {
                        0x400
                    };
                    words[2] = opcode | ((immediate & mask) << 5);
                }
                let code = words
                    .iter()
                    .flat_map(|word| word.to_le_bytes())
                    .collect::<Vec<_>>();
                let analysis = analyze_inplace_far(target, &code).unwrap();
                for guarded in [false, true] {
                    let (low, high) = far_branch_window(&analysis, guarded).unwrap();
                    let first = low.next_multiple_of(page_size);
                    let last = crate::sys::page_start(high, page_size);
                    let generate_at = |address| {
                        generate(
                            &analysis,
                            address,
                            target + 0x100,
                            &[],
                            guarded,
                            &replacement_bti(false),
                            false,
                        )
                    };
                    assert!(
                        [first, first + page_size]
                            .into_iter()
                            .any(|address| generate_at(address).is_ok())
                    );
                    assert!(
                        [last, last - page_size]
                            .into_iter()
                            .any(|address| generate_at(address).is_ok())
                    );
                    for address in [first - 2 * page_size, last + 2 * page_size] {
                        assert!(matches!(generate_at(address), Err(Error::NoNearbyMemory)));
                    }
                }
            }
        }
    }

    #[test]
    fn literal_relocation_rejects_writable_literals() {
        let page_size = crate::sys::page_size().unwrap();
        // SAFETY: this test owns the complete anonymous mapping.
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
        let maps = crate::read_self_maps().unwrap();
        let error = read_literal_bytes(mapping as usize, 8, &maps);
        assert!(matches!(error, Err(Error::MappingChanged)));
        // SAFETY: the mapping is owned by this test.
        assert_eq!(unsafe { libc::munmap(mapping, page_size) }, 0);
    }

    #[test]
    fn rejects_literal_data_overlapping_stolen_instruction() {
        for instruction in [0x1800_0000_u32, 0x58ff_ffe0, 0x9cff_ffa0] {
            assert!(matches!(
                analyze(0x1000, &instruction.to_le_bytes()),
                Err(Error::UnsupportedInstruction { .. })
            ));
        }
    }

    #[test]
    fn accepts_literal_ending_at_preserved_bti() {
        let mut code = BTI_C.to_le_bytes().to_vec();
        code.extend_from_slice(&0x18ff_ffe0_u32.to_le_bytes());
        assert!(analyze(0x1000, &code).is_ok());

        code[4..].copy_from_slice(&0x58ff_ffe0_u32.to_le_bytes());
        assert!(matches!(
            analyze(0x1000, &code),
            Err(Error::UnsupportedInstruction { .. })
        ));
    }

    #[test]
    fn guarded_pac_target_relocates_signing_and_preserves_a_call_landing() {
        for instruction in [0xd503_233f_u32, 0xd503_237f] {
            let code = [instruction, 0x5280_0540, 0xd503_23bf, 0xd65f_03c0]
                .into_iter()
                .flat_map(u32::to_le_bytes)
                .collect::<Vec<_>>();
            let analysis = analyze(0x1000, &code).unwrap();
            let generated = generate(
                &analysis,
                0x2000,
                0x3000,
                &[],
                true,
                &replacement_bti(false),
                false,
            )
            .unwrap();
            assert_eq!(generated.patch.len(), 8);
            assert_eq!(&generated.patch[..4], &BTI_C.to_le_bytes());
            assert_eq!(decode_branch(0x1004, &generated.patch[4..]), 0x3000);
            let offset = generated.original - 0x2000;
            assert_eq!(&generated.bytes[offset..offset + 4], &BTI_JC.to_le_bytes());
            assert_eq!(&generated.bytes[offset + 4..offset + 12], &code[..8]);
            assert_eq!(
                decode_branch(generated.original + 12, &generated.bytes[offset + 12..]),
                0x1008
            );
            assert!(is_pac_landing(instruction));
            assert!(is_br_x16_landing(instruction));
        }
    }

    #[test]
    fn paired_pac_and_authenticated_return_remain_hookable() {
        for (pac, ret) in [
            (0xd503_233f_u32, 0xd65f_0bff_u32),
            (0xd503_237f_u32, 0xd65f_0fff_u32),
        ] {
            let code = [pac.to_le_bytes(), ret.to_le_bytes()].concat();
            let analysis = analyze(0x1000, &code).unwrap();
            assert_eq!(analysis.original, code);
            for guarded in [false, true] {
                let generated = generate(
                    &analysis,
                    0x2000,
                    0x3000,
                    &[],
                    guarded,
                    &replacement_bti(false),
                    false,
                )
                .unwrap();
                assert_eq!(&generated.patch[..4], &BTI_C.to_le_bytes());
                assert_eq!(decode_branch(0x1004, &generated.patch[4..]), 0x3000);
                let offset = generated.original - 0x2000 + usize::from(guarded) * 4;
                assert_eq!(&generated.bytes[offset..], &code);
            }
            let mut window = code;
            window.resize(FAR_READ_LENGTH, 0);
            assert!(analyze_inplace_far(0x1000, &window).is_err());
            assert!(analyze_inplace_near_far(0x1000, &window).is_err());
            assert!(analyze_inplace_compact_far(0x1000, &window).is_err());
        }
    }

    #[test]
    fn guarded_far_relay_landing_matrix_matches_br_x16_semantics() {
        for (instruction, accepted) in [
            (BTI, false),
            (BTI_C, true),
            (BTI_J, true),
            (BTI_JC, true),
            (0xd503_233f, true),
            (0xd503_237f, true),
            (0xd503_201f, false),
        ] {
            assert_eq!(is_br_x16_landing(instruction), accepted);

            let landing = instruction;
            let replacement = (&raw const landing).expose_provenance();
            let map = MapInfo {
                start: replacement,
                end: replacement + 4,
                perms: crate::maps::MapPerms::READ | crate::maps::MapPerms::EXEC,
                is_private: true,
                offset: 0,
                device: crate::maps::DeviceId::new(0, 0),
                inode: 0,
                path: None,
            };
            assert_eq!(
                relay(replacement & !ARCH_PAGE_MASK, replacement, &[map], true).is_ok(),
                accepted
            );
        }
    }

    #[test]
    fn page_bti_guarded_detects_live_guarded_pages() {
        let page_size = crate::sys::page_size().unwrap();
        // SAFETY: this test owns the complete anonymous mapping.
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
        // SAFETY: the writable mapping owns these four bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(BTI_JC.to_le_bytes().as_ptr(), mapping.cast::<u8>(), 4);
        }
        // SAFETY: this test owns the complete page and only changes its own
        // protection. PROT_BTI is the architecture's bit 0x10.
        let guarded = unsafe {
            libc::mprotect(mapping, page_size, libc::PROT_READ | libc::PROT_EXEC | 0x10) == 0
        };
        if guarded {
            let maps = crate::read_self_maps().unwrap();
            assert!(page_bti_guarded(&maps, mapping as usize).unwrap());
        }
        // SAFETY: the mapping is owned by this test and no code remains live.
        assert_eq!(unsafe { libc::munmap(mapping, page_size) }, 0);
    }

    #[test]
    fn far_patch_and_relay_execute_a_guarded_bti_j_replacement() {
        if !crate::sys::aarch64_bti_supported() {
            return;
        }
        let page_size = crate::sys::page_size().unwrap();
        // SAFETY: this test owns both pages and keeps all calls on this thread.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                2 * page_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        let target = mapping as usize;
        let arena = target + 0x100;
        let relay_address = target + 0x200;
        let replacement = target + page_size;
        let source = [NOP, NOP, 0xd280_0020, 0xd65f_03c0]
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect::<Vec<_>>();
        let replacement_code = [BTI_J, 0xd280_0160, 0xd65f_03c0];
        // SAFETY: only the replacement page becomes executable here.
        unsafe {
            std::ptr::copy_nonoverlapping(
                replacement_code.as_ptr(),
                replacement as *mut u32,
                replacement_code.len(),
            );
            assert_eq!(
                libc::mprotect(
                    replacement as *mut _,
                    page_size,
                    libc::PROT_READ | libc::PROT_EXEC | 0x10,
                ),
                0
            );
        }
        let maps = crate::read_self_maps().unwrap();
        assert!(page_bti_guarded(&maps, replacement).unwrap());
        let analysis = analyze_inplace_compact_far(target, &source).unwrap();
        let generated = generate(
            &analysis,
            arena,
            replacement,
            &maps,
            false,
            &replacement_bti(false),
            false,
        )
        .unwrap();
        assert_eq!(
            u32::from_le_bytes(generated.patch[4..8].try_into().unwrap()),
            BR_X16
        );
        let relay_bytes = relay(relay_address, replacement, &maps, true).unwrap();
        // SAFETY: all generated code fits in the first owned page; only its
        // BR x16 paths enter the guarded BTI_J replacement, never a BLR call.
        unsafe {
            for (address, bytes) in [
                (target, generated.patch.as_slice()),
                (arena, generated.bytes.as_slice()),
                (relay_address, relay_bytes.as_slice()),
            ] {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), address as *mut u8, bytes.len());
            }
            assert_eq!(
                libc::mprotect(mapping, page_size, libc::PROT_READ | libc::PROT_EXEC),
                0
            );
            assert!(
                crate::sys::flush_instruction_cache_ranges_checked(
                    &[(target, replacement + replacement_code.len() * 4)],
                    true,
                    &mut false,
                )
                .is_none()
            );
            for (address, expected) in [(target, 11), (generated.original, 1), (relay_address, 11)]
            {
                let function =
                    std::mem::transmute::<usize, unsafe extern "C" fn() -> usize>(address);
                assert_eq!(function(), expected);
            }
            assert_eq!(
                libc::mprotect(mapping, page_size, libc::PROT_READ | libc::PROT_WRITE),
                0
            );
            std::ptr::copy_nonoverlapping(source.as_ptr(), mapping.cast::<u8>(), source.len());
            assert_eq!(
                libc::mprotect(mapping, page_size, libc::PROT_READ | libc::PROT_EXEC),
                0
            );
            assert!(
                crate::sys::flush_instruction_cache_ranges_checked(
                    &[(target, target + source.len())],
                    true,
                    &mut false,
                )
                .is_none()
            );
            let restored = std::mem::transmute::<usize, unsafe extern "C" fn() -> usize>(target);
            assert_eq!(restored(), 1);
            assert_eq!(libc::munmap(mapping, 2 * page_size), 0);
        }
    }

    #[test]
    fn branch_range_boundaries_are_exact() {
        assert!(encode_b(0x1000, 0x1000 + (1 << 27) - 4).is_ok());
        assert!(encode_b(0x1000, 0x1000 + (1 << 27)).is_err());
        assert!(encode_b(0x1000 + (1 << 27), 0x1000).is_ok());
    }

    #[test]
    fn in_place_far_has_unconstrained_distance() {
        let words = [
            0x5400_8000, // b.eq .+0x1000
            NOP,
            NOP,
            NOP,
            NOP,
            NOP,
            NOP,
        ];
        let code = words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        let far = analyze_inplace_far(0x1000, &code).unwrap();
        assert_eq!(max_distance(&far, 0), usize::MAX);
        assert!(far_branch_window(&far, false).is_some());
        let short = analyze(0x1000, &code).unwrap();
        assert_eq!(max_distance(&short, 0), MAX_DISTANCE);
        assert!(far_branch_window(&short, false).is_none());
        let local = [NOP, 0x5400_0040, NOP, NOP, NOP, NOP, NOP]
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        assert!(far_branch_window(&analyze_inplace_far(0x1000, &local).unwrap(), false).is_none());
    }

    #[test]
    fn near_far_accepts_a_three_instruction_function() {
        let words: [u32; 3] = [NOP, 0xd280_0020, 0xd65f_03c0];
        let code = words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        let analysis = analyze_inplace_near_far(0x1000, &code).unwrap();
        let generated = generate(
            &analysis,
            0x2000,
            0x3000,
            &[],
            false,
            &replacement_bti(false),
            false,
        )
        .unwrap();

        assert_eq!(analysis.original.len(), 12);
        assert_eq!(generated.patch.len(), 12);
        assert_eq!(
            decode_branch(analysis.patch_address, &generated.patch[..4]),
            0x3000
        );
        assert_eq!(
            u32::from_le_bytes(generated.patch[4..8].try_into().unwrap()),
            0xa8c1_47f0
        );
    }

    #[test]
    fn near_far_does_not_require_an_indirect_landing() {
        let words: [u32; 3] = [NOP, 0xd280_0020, 0xd65f_03c0];
        let code = words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        let analysis = analyze_inplace_near_far(0x1000, &code).unwrap();
        let generated = generate(
            &analysis,
            0x2000,
            0x3000,
            &[],
            false,
            &replacement_bti(true),
            false,
        )
        .expect("near-far uses a direct branch and needs no BR landing");

        assert_eq!(generated.patch.len(), 12);
    }

    #[test]
    fn sign_extension_handles_negative_adrp_immediate() {
        assert_eq!(sign_extend(0x1f_ffff, 21), -1);
    }

    #[test]
    fn compact_far_accepts_a_four_instruction_function() {
        let words: [u32; 4] = [NOP, NOP, NOP, 0xd65f_03c0];
        let code = words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        let analysis = analyze_inplace_compact_far(0x1000, &code).unwrap();
        let replacement = 0x1000 + (1 << 27);
        let generated = generate(
            &analysis,
            0x2000,
            replacement,
            &[],
            false,
            &replacement_bti(false),
            false,
        )
        .unwrap();

        assert_eq!(analysis.original.len(), 16);
        assert_eq!(generated.patch.len(), 16);
        assert!(is_ldr_x16_br(&generated.patch, replacement));
    }

    #[test]
    fn compact_far_rejects_a_fall_through_window() {
        let words = [NOP, NOP, NOP, NOP];
        let code = words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        assert!(matches!(
            analyze_inplace_compact_far(0x1000, &code),
            Err(Error::UnsupportedInstruction { .. })
        ));
    }

    #[test]
    fn decodes_adrp_with_architectural_four_kib_page() {
        let Relocation::Adr { target, .. } = classify(0x9000_0000, 0x1234_5678).unwrap() else {
            panic!("expected ADRP")
        };
        assert_eq!(target, 0x1234_5000);
    }

    fn adrp_page(instruction: u32, pc: usize) -> usize {
        let immediate =
            (((instruction >> 29) & 3) as i64) | ((((instruction >> 5) & 0x7ffff) as i64) << 2);
        let signed = (immediate << 43) >> 43;
        (pc & !ARCH_PAGE_MASK).wrapping_add((signed << 12) as usize)
    }

    #[test]
    fn inplace_far_rejects_a_terminal_before_the_final_instruction() {
        let ret = 0xd65f_03c0_u32.to_le_bytes();
        let nop = NOP.to_le_bytes();
        let mut early = ret.to_vec();
        for _ in 0..6 {
            early.extend_from_slice(&nop);
        }
        assert!(analyze_inplace_far(0x1000, &early).is_err());
        let mut middle = nop.to_vec();
        middle.extend_from_slice(&ret);
        for _ in 0..5 {
            middle.extend_from_slice(&nop);
        }
        assert!(analyze_inplace_far(0x1000, &middle).is_err());
        let mut late = Vec::new();
        for _ in 0..4 {
            late.extend_from_slice(&nop);
        }
        late.extend_from_slice(&ret);
        for _ in 0..2 {
            late.extend_from_slice(&nop);
        }
        assert!(analyze_inplace_far(0x1000, &late).is_err());
        let mut later = Vec::new();
        for _ in 0..5 {
            later.extend_from_slice(&nop);
        }
        later.extend_from_slice(&ret);
        later.extend_from_slice(&nop);
        assert!(analyze_inplace_far(0x1000, &later).is_err());
        let mut tail = Vec::new();
        for _ in 0..6 {
            tail.extend_from_slice(&nop);
        }
        tail.extend_from_slice(&ret);
        assert!(analyze_inplace_far(0x1000, &tail).is_ok());
    }

    #[test]
    fn inplace_far_tracks_an_adrp_page_crossed_by_the_patch() {
        let words = [
            0xb000_0000_u32, // adrp x0, next 4 KiB page
            NOP,
            NOP,
            NOP,
            NOP,
            NOP,
            NOP,
        ];
        let code = words
            .iter()
            .flat_map(|word| word.to_le_bytes())
            .collect::<Vec<_>>();
        let analysis = analyze_inplace_far(0x1ff0, &code).unwrap();
        assert_eq!(analysis.address_references.len(), 1);
        assert_eq!(analysis.address_references[0].target, 0x2000);
    }

    #[test]
    fn adr_in_range_is_one_instruction() {
        let analysis = analyze(0x1000, &0x1000_0080_u32.to_le_bytes()).unwrap();
        let generated = generate(
            &analysis,
            0x2000,
            0x3000,
            &[],
            false,
            &replacement_bti(false),
            false,
        )
        .unwrap();
        let word = u32::from_le_bytes(generated.bytes[..4].try_into().unwrap());
        assert_eq!(
            word & 0x9f00_0000,
            0x1000_0000,
            "expected ADR, got {word:#x}"
        );
        assert!(rematerialised_x0(&generated.bytes).is_none());
    }

    #[test]
    fn branch_into_the_stolen_window_is_detected() {
        // B from 0x1010 to 0x1004, which is inside (0x1000, 0x1010).
        let word = encode_b(0x1010, 0x1004).unwrap().to_le_bytes();
        assert!(branch_enters_window(&word, 0x1010, 0x1000, 0x1010));
        let outside = encode_b(0x1010, 0x2000).unwrap().to_le_bytes();
        assert!(!branch_enters_window(&outside, 0x1010, 0x1000, 0x1010));
    }
}

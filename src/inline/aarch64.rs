use super::{Generated, TransientBytes, patch};
use crate::maps::MapInfo;
use crate::{Error, Result};

const BTI_J: u32 = 0xd503_249f;
const BTI_JC: u32 = 0xd503_24df;
const MAX_DISTANCE: usize = (128 * 1024 * 1024) - 4;
pub(super) const WINDOW_LENGTH: usize = 8;

pub(super) struct Analysis {
    pub(super) patch_address: usize,
    pub(super) original: Vec<u8>,
    pac_landing: bool,
    relocation: Relocation,
    pub(super) address_reference: Option<AddressReference>,
}

/// An ADR or ADRP destination whose value later instructions may consume.
pub(super) struct AddressReference {
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
    let landing = usize::from(is_bti(first)) * 4;
    let patch_address = target
        .checked_add(landing)
        .ok_or(Error::ArithmeticOverflow)?;
    let instruction = read_word(code, landing)?;
    let relocation = classify(instruction, patch_address)?;
    let address_reference = match &relocation {
        Relocation::Adr { register, target } => Some(AddressReference {
            register: *register,
            target: *target,
        }),
        _ => None,
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
        // ADR is relocated to its original absolute address and ADRP to its
        // original page. A value addressing the overwritten bytes is not
        // recoverable: a following instruction can consume any offset inside
        // an ADRP page, so that complete page is rejected.
        let overlaps = if instruction & 0x9f00_0000 == 0x9000_0000 {
            crate::sys::page_start(*target, 4096) == crate::sys::page_start(patch_address, 4096)
        } else {
            (patch_address..patch_end).contains(target)
        };
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
        relocation,
        address_reference,
    })
}

pub(super) const fn max_distance(_: &Analysis) -> usize {
    MAX_DISTANCE
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

pub(super) fn redirects_to(
    analysis: &Analysis,
    replacement: usize,
    maps: &[MapInfo],
) -> Result<bool> {
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
    Ok(first == 0x5800_0050
        && u32::from_le_bytes([relay[4], relay[5], relay[6], relay[7]]) == 0xd61f_0200
        && u64::from_le_bytes([
            relay[8], relay[9], relay[10], relay[11], relay[12], relay[13], relay[14], relay[15],
        ]) as usize
            == replacement)
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
    replacement_guarded: bool,
    _: bool,
) -> Result<Generated> {
    if guarded && analysis.pac_landing {
        return Err(Error::InvalidInlineTarget(
            "guarded PAC entry cannot preserve its landing semantics",
        ));
    }
    let direct_patch = match encode_b(analysis.patch_address, replacement) {
        Ok(patch) => Some(patch),
        Err(Error::NoNearbyMemory) => None,
        Err(error) => return Err(error),
    };
    let bytes = if direct_patch.is_some() {
        Vec::new()
    } else {
        relay(arena, replacement, maps, replacement_guarded)?
    };
    let mut bytes = TransientBytes::from(bytes);
    align_code(&mut bytes, 16);
    let trampoline_offset = bytes.len();
    push_word(&mut bytes, BTI_JC);
    let relocated_address = arena
        .checked_add(bytes.len())
        .ok_or(Error::ArithmeticOverflow)?;
    let stolen_end = analysis
        .patch_address
        .checked_add(4)
        .ok_or(Error::ArithmeticOverflow)?;
    let falls_through = match analysis.relocation {
        Relocation::Copy(instruction) => {
            push_word(&mut bytes, instruction);
            true
        }
        Relocation::Terminal(instruction) => {
            push_word(&mut bytes, instruction);
            false
        }
        Relocation::Branch(target) => {
            let target = remap_internal(
                target,
                analysis.patch_address..stolen_end,
                relocated_address,
            )?;
            push_word(&mut bytes, encode_b(relocated_address, target)?);
            false
        }
        Relocation::Conditional {
            instruction,
            target,
        } => {
            let target = remap_internal(
                target,
                analysis.patch_address..stolen_end,
                relocated_address,
            )?;
            push_word(&mut bytes, invert_conditional_to_skip(instruction));
            push_word(
                &mut bytes,
                encode_b(
                    relocated_address
                        .checked_add(4)
                        .ok_or(Error::ArithmeticOverflow)?,
                    target,
                )?,
            );
            true
        }
        Relocation::Adr { register, target } => {
            emit_address(&mut bytes, register, target as u64);
            true
        }
        Relocation::Literal {
            instruction,
            target,
            ..
        } => {
            let immediate = scaled_signed(target, relocated_address, 4, 19)?;
            push_word(
                &mut bytes,
                (instruction & !0x00ff_ffe0) | ((immediate as u32 & 0x7ffff) << 5),
            );
            true
        }
    };

    if falls_through {
        let branch_address = arena
            .checked_add(bytes.len())
            .ok_or(Error::ArithmeticOverflow)?;
        push_word(&mut bytes, encode_b(branch_address, stolen_end)?);
    }
    let patch = match direct_patch {
        Some(patch) => patch,
        None => encode_b(analysis.patch_address, arena)?,
    }
    .to_le_bytes()
    .to_vec();
    let patch = TransientBytes::from(patch);
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

fn classify(instruction: u32, address: usize) -> Result<Relocation> {
    if is_call(instruction) {
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
            (((instruction >> 5) & 0x3fff) as u64, 16)
        };
        return Ok(Relocation::Conditional {
            instruction,
            target: add_signed(address, sign_extend(immediate << 2, bits))?,
        });
    }
    match instruction & 0x9f00_0000 {
        0x1000_0000 => {
            let immediate = (((instruction >> 29) & 3) | ((instruction >> 3) & 0x1f_fffc)) as u64;
            return Ok(Relocation::Adr {
                register: instruction & 0x1f,
                target: add_signed(address, sign_extend(immediate, 21))?,
            });
        }
        0x9000_0000 => {
            let immediate = (((instruction >> 29) & 3) | ((instruction >> 3) & 0x1f_fffc)) as u64;
            let page = address & !0xfff;
            return Ok(Relocation::Adr {
                register: instruction & 0x1f,
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

    if instruction & 0xffff_fc1f == 0xd61f_0000 || instruction & 0xffff_fc1f == 0xd65f_0000 {
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
pub(super) fn detect_data_reference(
    words: &[u32],
    base: usize,
    register: u32,
    target: usize,
    stolen_start: usize,
    stolen_end: usize,
) -> Option<(usize, usize)> {
    let mut offsets = [None; 31];
    offsets[register as usize] = Some(0_isize);
    let mut instruction = base;
    for &word in words {
        if terminates_analysis(word) {
            return None;
        }
        if let Some((address, effective)) = memory_access(
            word,
            instruction,
            &offsets,
            target,
            stolen_start,
            stolen_end,
        ) {
            return Some((address, effective));
        }
        update_tracking(word, &mut offsets);
        instruction += 4;
    }
    None
}

/// Returns whether control flow cannot reach the next instruction linearly.
fn terminates_analysis(word: u32) -> bool {
    if word & 0xFC00_0000 == 0x1400_0000 {
        return true; // B
    }
    if word & 0xFC00_0000 == 0x9400_0000 {
        return true; // BL
    }
    if word & 0xFE00_0000 == 0xD600_0000 {
        return true; // BR, BLR, RET, RETAA/RETAB
    }
    word & 0xFF00_0000 == 0xD400_0000 // exception generation and system hints
}

/// Reports a tracked-base access whose effective address hits the stolen
/// bytes, if this word is a decodable unscaled or unsigned-offset access.
fn memory_access(
    word: u32,
    instruction: usize,
    offsets: &[Option<isize>; 31],
    target: usize,
    stolen_start: usize,
    stolen_end: usize,
) -> Option<(usize, usize)> {
    let unsigned = word & 0x3B00_0000 == 0x3900_0000;
    let unscaled = word & 0x3B20_0C00 == 0x3800_0000 && !unsigned;
    if !unsigned && !unscaled {
        return None;
    }
    let vector = (word >> 26) & 1 == 1;
    let size = (word >> 30) & 3;
    let opcode = (word >> 22) & 3;
    let base_register = (word >> 5) & 31;
    let delta = offsets[base_register as usize]?;
    let (immediate, width) = if unsigned {
        // Integer prefetches do not read or write the target bytes.
        if !vector && opcode == 3 {
            return None;
        }
        // Q is the only width whose scale is not encoded directly in `size`;
        // scalar bytes are the only one-byte access with an unscaled scale.
        let (scale, width) = if vector && size == 0 && opcode >= 2 {
            (4_usize, 16_usize)
        } else {
            (if size == 0 { 0 } else { size as usize }, 1_usize << size)
        };
        ((((word >> 10) & 0xFFF) << scale) as isize, width)
    } else {
        // Sign-extend the 9-bit immediate through a 32-bit value first: a
        // direct isize shift would keep the top bit far below bit 63.
        let raw = (((word >> 12) & 0x1FF) << 23) as i32;
        let signed = (raw >> 23) as isize;
        // Integer prefetches do not read or write the target bytes.
        if !vector && opcode == 3 {
            return None;
        }
        let width = if vector {
            match size {
                0 => 16_usize,
                1 => 2,
                2 => 4,
                _ => 8,
            }
        } else {
            1_usize << size
        };
        (signed, width)
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

/// Moves constant-offset knowledge through recognized register writes.
fn update_tracking(word: u32, offsets: &mut [Option<isize>; 31]) {
    let destination = word & 31;
    // MOV register: ORR Xd, XZR, Xm, with no shift.
    if word & 0xFFE0_FFE0 == 0xAA00_03E0 {
        let source = (word >> 16) & 31;
        offsets[destination as usize] = offsets[source as usize];
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
    if offsets[destination as usize].is_some() {
        offsets[destination as usize] = None;
    }
}

fn relay(
    address: usize,
    replacement: usize,
    maps: &[MapInfo],
    replacement_guarded: bool,
) -> Result<Vec<u8>> {
    if let Ok(branch) = encode_b(address, replacement) {
        return Ok(branch.to_le_bytes().to_vec());
    }
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
    let mut relay = TransientBytes::from(Vec::with_capacity(16));
    push_word(&mut relay, 0x5800_0050); // ldr x16, #8
    push_word(&mut relay, 0xd61f_0200); // br x16
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
    instruction & 0xffff_ff3f == 0xd503_241f
}

fn is_pac_landing(instruction: u32) -> bool {
    matches!(instruction, 0xd503_233f | 0xd503_237f)
}

fn is_br_x16_landing(instruction: u32) -> bool {
    // BR through x16 sets BTYPE=01 on a guarded page. Only `bti j` and
    // `bti jc` accept that branch type; PAC prologues act as `bti c` here.
    matches!(instruction, BTI_J | BTI_JC)
}

fn invert_conditional_to_skip(instruction: u32) -> u32 {
    if instruction & 0xff00_0000 == 0x5400_0000 {
        ((instruction ^ 1) & !0x00ff_ffe0) | (2 << 5)
    } else if instruction & 0x7e00_0000 == 0x3400_0000 {
        ((instruction ^ 0x0100_0000) & !0x00ff_ffe0) | (2 << 5)
    } else {
        ((instruction ^ 0x0100_0000) & !0x0007_ffe0) | (2 << 5)
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

fn encode_b(from: usize, to: usize) -> Result<u32> {
    let immediate = scaled_signed(to, from, 4, 26)?;
    Ok(0x1400_0000 | (immediate as u32 & 0x03ff_ffff))
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

fn remap_internal(
    target: usize,
    stolen: std::ops::Range<usize>,
    relocated: usize,
) -> Result<usize> {
    if !stolen.contains(&target) {
        return Ok(target);
    }
    if target == stolen.start {
        Ok(relocated)
    } else {
        Err(unsupported(
            stolen.start,
            "branch enters the middle of a stolen instruction",
        ))
    }
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

    const BTI: u32 = 0xd503_241f;
    const BTI_C: u32 = 0xd503_245f;

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
    }

    #[test]
    fn direct_patch_targets_replacement_and_arena_starts_with_trampoline() {
        let analysis = analyze(0x1000, &0xd503_201f_u32.to_le_bytes()).unwrap();
        let generated = generate(&analysis, 0x2000, 0x3000, &[], false, true, false).unwrap();

        assert_eq!(
            decode_branch(analysis.patch_address, &generated.patch),
            0x3000
        );
        assert_eq!(generated.original, 0x2000);
        assert_eq!(
            u32::from_le_bytes(generated.bytes[..4].try_into().unwrap()),
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
        let generated = generate(&analysis, arena, target + 0x40, &[], false, true, false).unwrap();

        let resolved = rematerialised_x0(&generated.bytes)
            .expect("the trampoline must rematerialise the ADRP result");
        assert_eq!(resolved as usize, 0x3000);
    }

    #[test]
    fn rejects_pc_relative_addresses_into_the_stolen_instruction() {
        // adr x0, .: the produced address is the patched entry itself.
        assert!(matches!(
            analyze(0x1000, &0x1000_0000_u32.to_le_bytes()),
            Err(Error::UnsupportedInstruction { .. })
        ));
        // adrp x0, .: a following ADD can select the patched bytes.
        assert!(matches!(
            analyze(0x1000, &0x9000_0000_u32.to_le_bytes()),
            Err(Error::UnsupportedInstruction { .. })
        ));
        // adr x0, . + 16 addresses bytes outside the overwritten span.
        assert!(analyze(0x1000, &0x1000_0080_u32.to_le_bytes()).is_ok());
    }

    #[test]
    fn far_patch_targets_relay_and_keeps_guarded_landing_check() {
        let analysis = analyze(0x1000, &0xd503_201f_u32.to_le_bytes()).unwrap();
        let arena = 0x2000;
        let replacement = arena + (1 << 27);
        let generated = generate(&analysis, arena, replacement, &[], false, false, false).unwrap();

        assert_eq!(
            decode_branch(analysis.patch_address, &generated.patch),
            arena
        );
        assert_eq!(generated.original, arena + 16);
        assert_eq!(
            u32::from_le_bytes(generated.bytes[..4].try_into().unwrap()),
            0x5800_0050
        );
        assert_eq!(
            u32::from_le_bytes(generated.bytes[4..8].try_into().unwrap()),
            0xd61f_0200
        );
        assert_eq!(
            u64::from_le_bytes(generated.bytes[8..16].try_into().unwrap()) as usize,
            replacement
        );
        assert_eq!(
            u32::from_le_bytes(generated.bytes[16..20].try_into().unwrap()),
            BTI_JC
        );
        assert!(matches!(
            generate(&analysis, arena, replacement, &[], false, true, false),
            Err(Error::MappingChanged)
        ));
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
    fn literal_relocation_keeps_loading_from_the_original_address() {
        let analysis = analyze(0x1000, &0x5800_4000_u32.to_le_bytes()).unwrap();
        let generated = generate(&analysis, 0x2000, 0x3000, &[], false, false, false).unwrap();
        let relocated_address = generated.original + 4;
        let offset = relocated_address - 0x2000;
        let instruction =
            u32::from_le_bytes(generated.bytes[offset..offset + 4].try_into().unwrap());
        assert!(matches!(
            classify(instruction, relocated_address),
            Ok(Relocation::Literal { target: 0x1800, .. })
        ));
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
    fn guarded_pac_target_fails_closed_and_pac_is_not_a_br_x16_landing() {
        for instruction in [0xd503_233f_u32, 0xd503_237f] {
            let analysis = analyze(0x1000, &instruction.to_le_bytes()).unwrap();
            assert!(matches!(
                generate(&analysis, 0x2000, 0x3000, &[], true, false, false),
                Err(Error::InvalidInlineTarget(_))
            ));
            assert!(is_pac_landing(instruction));
            assert!(!is_br_x16_landing(instruction));
        }
    }

    #[test]
    fn guarded_far_relay_landing_matrix_matches_br_x16_semantics() {
        for (instruction, accepted) in [
            (BTI, false),
            (BTI_C, false),
            (BTI_J, true),
            (BTI_JC, true),
            (0xd503_233f, false),
            (0xd503_237f, false),
            (0xd503_201f, false),
        ] {
            assert_eq!(is_br_x16_landing(instruction), accepted);

            let landing = instruction;
            let replacement = (&landing as *const u32).expose_provenance();
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
            let relay_address = replacement
                .checked_add(1 << 28)
                .unwrap_or_else(|| replacement - (1 << 28));
            assert_eq!(
                relay(relay_address, replacement, &[map], true).is_ok(),
                accepted
            );
        }
    }

    #[test]
    fn branch_range_boundaries_are_exact() {
        assert!(encode_b(0x1000, 0x1000 + (1 << 27) - 4).is_ok());
        assert!(encode_b(0x1000, 0x1000 + (1 << 27)).is_err());
        assert!(encode_b(0x1000 + (1 << 27), 0x1000).is_ok());
    }

    #[test]
    fn decodes_adrp_with_architectural_four_kib_page() {
        let Relocation::Adr { target, .. } = classify(0x9000_0000, 0x1234_5678).unwrap() else {
            panic!("expected ADRP")
        };
        assert_eq!(target, 0x1234_5000);
    }
}

use super::{Generated, TransientBytes, patch};
use crate::maps::MapInfo;
use crate::{Error, Result};
use yaxpeax_arch::{Decoder, U8Reader};
use yaxpeax_arm::armv7::InstDecoder;

const A32_MAX_DISTANCE: usize = (32 * 1024 * 1024) - 8;
const THUMB_MAX_DISTANCE: usize = (16 * 1024 * 1024) - 4;
/// Worst case: a 32-bit Thumb instruction completing the four-byte minimum,
/// then `it` (2 bytes) and four governed 32-bit Thumb instructions.
pub(super) const WINDOW_LENGTH: usize = 24;

pub(super) struct Analysis {
    pub(super) patch_address: usize,
    pub(super) original: Vec<u8>,
    thumb: bool,
    instructions: Vec<RelocatedInstruction>,
}

impl Drop for Analysis {
    fn drop(&mut self) {
        crate::sys::erase_bytes(&mut self.original);
    }
}

struct RelocatedInstruction {
    address: usize,
    kind: Relocation,
}

enum Relocation {
    Copy {
        bytes: Vec<u8>,
        terminal: bool,
    },
    Branch {
        target: usize,
        mode: BranchMode,
    },
    Adr {
        target: usize,
        register: u8,
        condition: Option<u8>,
    },
    Literal {
        target: usize,
        size: usize,
        mode: LiteralMode,
    },
}

enum BranchMode {
    A32(u8),
    Thumb,
    ThumbConditional(u16),
}

enum LiteralMode {
    A32(u32),
    Thumb(u8),
}

struct PoolFixup {
    instruction_offset: usize,
    instruction_address: usize,
    encoding: PoolEncoding,
    value: Vec<u8>,
}

impl Drop for Relocation {
    fn drop(&mut self) {
        if let Self::Copy { bytes, .. } = self {
            crate::sys::erase_bytes(bytes);
        }
    }
}

impl Drop for PoolFixup {
    fn drop(&mut self) {
        crate::sys::erase_bytes(&mut self.value);
    }
}

#[derive(Clone, Copy)]
enum PoolEncoding {
    A32(u32),
    Thumb(u8),
}

pub(super) fn analyze(target: usize, code: &[u8]) -> Result<Analysis> {
    let thumb = target & 1 != 0;
    let patch_address = target & !1;
    if (thumb && !patch_address.is_multiple_of(2)) || (!thumb && !patch_address.is_multiple_of(4)) {
        return Err(Error::InvalidInlineTarget("misaligned ARM entry"));
    }

    let mut instructions = Vec::new();
    let mut stolen = 0;
    // Number of IT-governed instructions still to steal. An `it` makes the
    // next instructions conditional by position, so the complete block must
    // move to the trampoline together; stealing only part of it would execute
    // the remainder without its predicate.
    let mut it_governed = 0_usize;
    while stolen < 4 || it_governed > 0 {
        let length = if thumb {
            thumb_instruction_length(code, stolen)?
        } else {
            4
        };
        let bytes = code
            .get(stolen..stolen + length)
            .ok_or(Error::InvalidInlineTarget("truncated ARM instruction"))?;
        validate_decode(bytes, thumb, patch_address + stolen)?;
        if thumb && bytes.len() == 2 && is_thumb_it(bytes) {
            if it_governed > 0 {
                return Err(unsupported(
                    patch_address + stolen,
                    "nested Thumb IT block is not relocatable",
                ));
            }
            it_governed = it_governed_instructions(bytes)
                .ok_or_else(|| unsupported(patch_address + stolen, "invalid Thumb IT mask"))?;
            instructions.push(RelocatedInstruction {
                address: patch_address + stolen,
                kind: Relocation::Copy {
                    bytes: bytes.to_vec(),
                    terminal: false,
                },
            });
            stolen += length;
            continue;
        }
        let kind = if thumb {
            classify_thumb(bytes, patch_address + stolen)?
        } else {
            classify_a32(bytes, patch_address + stolen)?
        };
        if it_governed > 0 && !kind.relocatable_inside_it() {
            return Err(unsupported(
                patch_address + stolen,
                "IT-governed Thumb instruction is not relocatable",
            ));
        }
        let falls_through = kind.falls_through();
        instructions.push(RelocatedInstruction {
            address: patch_address + stolen,
            kind,
        });
        stolen += length;
        if it_governed > 0 {
            it_governed -= 1;
            // A terminal inside the block still leaves governed instructions
            // that other paths could observe, so the block is never cut.
            continue;
        }
        // Execution cannot continue past a terminal instruction, so the bytes
        // after it belong to whatever the toolchain placed next rather than to
        // this entry. Stealing them would overwrite an unrelated function.
        if !falls_through {
            break;
        }
    }
    if stolen < 4 {
        return Err(unsupported(
            patch_address,
            "ARM entry ends before the patch branch fits",
        ));
    }

    let end = patch_address
        .checked_add(stolen)
        .ok_or(Error::ArithmeticOverflow)?;
    let boundaries = instructions
        .iter()
        .map(|instruction| instruction.address)
        .collect::<Vec<_>>();
    for instruction in &instructions {
        if let Some(target) = instruction.kind.branch_target()
            && (patch_address..end).contains(&target)
            && !boundaries.contains(&target)
        {
            return Err(unsupported(
                instruction.address,
                "branch enters the middle of a stolen instruction",
            ));
        }
        if let Relocation::Adr { target, .. } = &instruction.kind
            && (patch_address..end).contains(target)
        {
            return Err(unsupported(
                instruction.address,
                "PC-relative address overlaps stolen instruction",
            ));
        }
    }

    Ok(Analysis {
        patch_address,
        original: code[..stolen].to_vec(),
        thumb,
        instructions,
    })
}

pub(super) const fn max_distance(analysis: &Analysis) -> usize {
    if analysis.thumb {
        THUMB_MAX_DISTANCE
    } else {
        A32_MAX_DISTANCE
    }
}

pub(super) const fn mapped_target(target: usize) -> Result<usize> {
    let address = target & !1;
    if target & 1 == 0 && !address.is_multiple_of(4) {
        return Err(Error::InvalidInlineTarget(
            "A32 target is not 4-byte aligned",
        ));
    }
    Ok(address)
}

pub(super) const fn mapped_replacement(replacement: usize) -> Result<usize> {
    let address = replacement & !1;
    if replacement & 1 == 0 && !address.is_multiple_of(4) {
        return Err(Error::InvalidInlineTarget(
            "A32 replacement is not 4-byte aligned",
        ));
    }
    if replacement & 1 != 0 && !address.is_multiple_of(2) {
        return Err(Error::InvalidInlineTarget(
            "Thumb replacement is not 2-byte aligned",
        ));
    }
    Ok(address)
}

pub(super) fn redirects_to(
    analysis: &Analysis,
    replacement: usize,
    maps: &[MapInfo],
) -> Result<bool> {
    let Some(destination) = analysis
        .instructions
        .first()
        .and_then(|instruction| instruction.kind.branch_target())
    else {
        return Ok(false);
    };
    if destination == replacement & !1 {
        return Ok(true);
    }
    let Ok(expected) = relay(destination, replacement, analysis.thumb) else {
        return Ok(false);
    };
    let expected = TransientBytes::from(expected);
    let probe = patch::probe_maps(maps, destination, expected.len())?;
    let validation_maps = probe.as_deref().unwrap_or(maps);
    if patch::validate_executable_entry(validation_maps, destination, expected.len()).is_err() {
        return Ok(false);
    }
    // SAFETY: validation covers the complete relay sequence.
    let current = unsafe {
        std::slice::from_raw_parts(
            std::ptr::with_exposed_provenance::<u8>(destination),
            expected.len(),
        )
    };
    Ok(current == &*expected)
}

pub(super) fn generate(
    analysis: &Analysis,
    arena: usize,
    replacement: usize,
    maps: &[MapInfo],
    _: bool,
    _mem: Option<usize>,
) -> Result<Generated> {
    let bytes = relay(arena, replacement, analysis.thumb)?;
    let mut bytes = TransientBytes::from(bytes);
    align_code(&mut bytes, 4);
    let trampoline_offset = bytes.len();
    let mut relocated_addresses = Vec::with_capacity(analysis.instructions.len());
    let mut offset = trampoline_offset;
    for instruction in &analysis.instructions {
        relocated_addresses.push((instruction.address, arena + offset));
        offset = offset
            .checked_add(instruction.kind.emitted_length())
            .ok_or(Error::ArithmeticOverflow)?;
    }

    let stolen = analysis.patch_address
        ..analysis
            .patch_address
            .checked_add(analysis.original.len())
            .ok_or(Error::ArithmeticOverflow)?;
    let mut fixups = Vec::new();
    for (index, instruction) in analysis.instructions.iter().enumerate() {
        let relocated = relocated_addresses[index].1;
        emit_instruction(
            &mut bytes,
            &mut fixups,
            instruction,
            relocated,
            &relocated_addresses,
            stolen.clone(),
            maps,
        )?;
    }

    if analysis
        .instructions
        .last()
        .is_some_and(|instruction| instruction.kind.falls_through())
    {
        let branch_address = arena
            .checked_add(bytes.len())
            .ok_or(Error::ArithmeticOverflow)?;
        emit_pool_branch(
            &mut bytes,
            &mut fixups,
            branch_address,
            stolen.end,
            analysis.thumb,
            None,
        )?;
    }
    apply_pool_fixups(&mut bytes, &fixups, arena)?;

    let patch = if analysis.thumb {
        let mut patch =
            TransientBytes::from(encode_thumb_b_w(analysis.patch_address, arena)?.to_vec());
        while patch.len() < analysis.original.len() {
            patch.extend_from_slice(&0xbf00_u16.to_le_bytes());
        }
        patch.into_vec()
    } else {
        encode_a32_b(14, analysis.patch_address, arena)?
            .to_le_bytes()
            .to_vec()
    };
    let patch = TransientBytes::from(patch);
    let original = arena
        .checked_add(trampoline_offset)
        .ok_or(Error::ArithmeticOverflow)?
        | usize::from(analysis.thumb);
    Ok(Generated {
        bytes: bytes.into_vec(),
        patch: patch.into_vec(),
        original,
        auxiliary: None,
    })
}

impl Relocation {
    fn branch_target(&self) -> Option<usize> {
        match self {
            Self::Branch { target, .. } => Some(*target),
            _ => None,
        }
    }

    fn emitted_length(&self) -> usize {
        match self {
            Self::Copy { bytes, .. } => bytes.len(),
            Self::Branch {
                mode: BranchMode::ThumbConditional(_),
                ..
            } => 6,
            Self::Branch { .. } | Self::Literal { .. } => 4,
            Self::Adr {
                condition: Some(_), ..
            } => 8,
            Self::Adr {
                condition: None, ..
            } => 4,
        }
    }

    fn falls_through(&self) -> bool {
        match self {
            Self::Copy { terminal, .. } => !terminal,
            Self::Branch {
                mode: BranchMode::A32(condition),
                ..
            } => *condition != 14,
            Self::Branch {
                mode: BranchMode::Thumb,
                ..
            } => false,
            Self::Branch {
                mode: BranchMode::ThumbConditional(_),
                ..
            }
            | Self::Adr { .. }
            | Self::Literal { .. } => true,
        }
    }

    /// Returns whether one IT-governed slot can keep this relocation.
    ///
    /// Verbatim copies and pool-based address materializations stay exactly
    /// one instruction in the block, so positional predication survives.
    /// Branches change control-flow semantics and conditional Thumb branches
    /// expand to two instructions, so either would discard or shift the
    /// predicate the `it` word applies to that slot.
    fn relocatable_inside_it(&self) -> bool {
        matches!(
            self,
            Self::Copy { .. }
                | Self::Adr {
                    condition: None,
                    ..
                }
                | Self::Literal { .. }
        )
    }
}

/// Returns whether two bytes encode a Thumb `it` instruction.
fn is_thumb_it(bytes: &[u8]) -> bool {
    let first = u16::from_le_bytes([bytes[0], bytes[1]]);
    first & 0xff00 == 0xbf00 && first & 0x000f != 0
}

/// Decodes how many instructions one `it` word governs.
///
/// The mask's lowest set bit selects the block length: `1000` governs one,
/// `x100` two, `xy10` three, and `xyz1` four instructions. A first condition
/// of `111x` (NV) is UNPREDICTABLE and rejected.
fn it_governed_instructions(bytes: &[u8]) -> Option<usize> {
    let instruction = u16::from_le_bytes([bytes[0], bytes[1]]);
    if (instruction >> 4) & 0xf >= 14 {
        return None;
    }
    match instruction & 0xf {
        mask if mask.trailing_zeros() == 3 => Some(1),
        mask if mask.trailing_zeros() == 2 => Some(2),
        mask if mask.trailing_zeros() == 1 => Some(3),
        mask if mask.trailing_zeros() == 0 => Some(4),
        _ => None,
    }
}

fn emit_instruction(
    bytes: &mut TransientBytes,
    fixups: &mut Vec<PoolFixup>,
    instruction: &RelocatedInstruction,
    relocated: usize,
    relocated_addresses: &[(usize, usize)],
    stolen: std::ops::Range<usize>,
    maps: &[MapInfo],
) -> Result<()> {
    match &instruction.kind {
        Relocation::Copy { bytes: raw, .. } => bytes.extend_from_slice(raw),
        Relocation::Branch { target, mode } => {
            let target = remap_branch(*target, &stolen, relocated_addresses)?;
            match mode {
                BranchMode::A32(condition) => {
                    emit_pool_branch(bytes, fixups, relocated, target, false, Some(*condition))?
                }
                BranchMode::Thumb => {
                    emit_pool_branch(bytes, fixups, relocated, target, true, None)?
                }
                BranchMode::ThumbConditional(skip) => {
                    bytes.extend_from_slice(&skip.to_le_bytes());
                    emit_pool_branch(bytes, fixups, relocated + 2, target, true, None)?;
                }
            }
        }
        Relocation::Adr {
            target,
            register,
            condition,
        } => {
            if let Some(condition) = condition {
                emit_a32_address(bytes, *condition, *register, *target as u32);
            } else {
                emit_thumb_pool_load(
                    bytes,
                    fixups,
                    relocated,
                    *register,
                    (*target as u32).to_le_bytes().to_vec(),
                );
            }
        }
        Relocation::Literal { target, size, mode } => {
            let value = patch::copy_literal(maps, *target, *size, stolen)?;
            match mode {
                LiteralMode::A32(base) => {
                    let instruction_offset = bytes.len();
                    bytes.extend_from_slice(&base.to_le_bytes());
                    fixups.push(PoolFixup {
                        instruction_offset,
                        instruction_address: relocated,
                        encoding: PoolEncoding::A32(*base),
                        value,
                    });
                }
                LiteralMode::Thumb(register) => {
                    emit_thumb_pool_load(bytes, fixups, relocated, *register, value)
                }
            }
        }
    }
    Ok(())
}

fn emit_pool_branch(
    bytes: &mut TransientBytes,
    fixups: &mut Vec<PoolFixup>,
    address: usize,
    target: usize,
    thumb: bool,
    condition: Option<u8>,
) -> Result<()> {
    let instruction_offset = bytes.len();
    if thumb {
        bytes.extend_from_slice(&0xf8df_u16.to_le_bytes());
        bytes.extend_from_slice(&0xf000_u16.to_le_bytes());
        fixups.push(PoolFixup {
            instruction_offset,
            instruction_address: address,
            encoding: PoolEncoding::Thumb(15),
            value: ((target | 1) as u32).to_le_bytes().to_vec(),
        });
    } else {
        let base = (u32::from(condition.unwrap_or(14)) << 28) | 0x059f_f000;
        bytes.extend_from_slice(&base.to_le_bytes());
        fixups.push(PoolFixup {
            instruction_offset,
            instruction_address: address,
            encoding: PoolEncoding::A32(base),
            value: (target as u32).to_le_bytes().to_vec(),
        });
    }
    Ok(())
}

fn emit_thumb_pool_load(
    bytes: &mut TransientBytes,
    fixups: &mut Vec<PoolFixup>,
    address: usize,
    register: u8,
    value: Vec<u8>,
) {
    let instruction_offset = bytes.len();
    bytes.extend_from_slice(&0xf8df_u16.to_le_bytes());
    bytes.extend_from_slice(&(u16::from(register) << 12).to_le_bytes());
    fixups.push(PoolFixup {
        instruction_offset,
        instruction_address: address,
        encoding: PoolEncoding::Thumb(register),
        value,
    });
}

fn apply_pool_fixups(bytes: &mut TransientBytes, fixups: &[PoolFixup], arena: usize) -> Result<()> {
    for fixup in fixups {
        align_code(bytes, 4);
        let pool = arena
            .checked_add(bytes.len())
            .ok_or(Error::ArithmeticOverflow)?;
        match fixup.encoding {
            PoolEncoding::A32(base) => {
                let pc = fixup
                    .instruction_address
                    .checked_add(8)
                    .ok_or(Error::ArithmeticOverflow)?;
                // A32 reads PC as the instruction address plus 8, but the pool
                // starts immediately after the last emitted instruction. A load
                // in one of the final two words therefore addresses its entry
                // backwards, so the sign is encoded in U instead of assumed.
                let (up, distance) = if pool >= pc {
                    (0x0080_0000, pool - pc)
                } else {
                    (0, pc - pool)
                };
                if distance > 0xfff {
                    return Err(Error::NoNearbyMemory);
                }
                let encoded = (base & !0x0080_0fff) | up | distance as u32;
                bytes[fixup.instruction_offset..fixup.instruction_offset + 4]
                    .copy_from_slice(&encoded.to_le_bytes());
            }
            PoolEncoding::Thumb(register) => {
                let pc = crate::sys::page_start(
                    fixup
                        .instruction_address
                        .checked_add(4)
                        .ok_or(Error::ArithmeticOverflow)?,
                    4,
                );
                let distance = pool.checked_sub(pc).ok_or(Error::NoNearbyMemory)?;
                if distance > 0xfff {
                    return Err(Error::NoNearbyMemory);
                }
                let second = (u16::from(register) << 12) | distance as u16;
                bytes[fixup.instruction_offset + 2..fixup.instruction_offset + 4]
                    .copy_from_slice(&second.to_le_bytes());
            }
        }
        bytes.extend_from_slice(&fixup.value);
    }
    Ok(())
}

fn classify_a32(bytes: &[u8], address: usize) -> Result<Relocation> {
    let instruction = u32::from_le_bytes(
        bytes
            .try_into()
            .map_err(|_| Error::InvalidInlineTarget("truncated A32 instruction"))?,
    );
    let condition = (instruction >> 28) as u8;
    if instruction & 0x0e00_0000 == 0x0a00_0000 {
        if condition == 15 || instruction & 0x0100_0000 != 0 {
            return Err(unsupported(address, "stolen BL/BLX is not relocatable"));
        }
        let displacement = sign_extend(u64::from(instruction & 0x00ff_ffff) << 2, 26);
        return Ok(Relocation::Branch {
            target: add_signed(address + 8, displacement)?,
            mode: BranchMode::A32(condition),
        });
    }
    if instruction & 0x0fff_fff0 == 0x012f_ff30 {
        return Err(unsupported(address, "stolen BLX is not relocatable"));
    }
    if instruction & 0x0fff_fff0 == 0x012f_ff10 {
        if condition != 14 || instruction & 0xf == 15 {
            return Err(unsupported(
                address,
                "conditional or PC-based BX is not relocatable",
            ));
        }
        return Ok(Relocation::Copy {
            bytes: bytes.to_vec(),
            terminal: true,
        });
    }

    let immediate_data = instruction & 0x0e00_0000 == 0x0200_0000;
    let opcode = (instruction >> 21) & 0xf;
    if immediate_data
        && matches!(opcode, 2 | 4)
        && instruction & (1 << 20) == 0
        && (instruction >> 16) & 0xf == 15
        && (instruction >> 12) & 0xf != 15
        && condition != 15
    {
        let immediate = rotated_immediate(instruction);
        let pc = address.checked_add(8).ok_or(Error::ArithmeticOverflow)?;
        let target = if opcode == 4 {
            pc.checked_add(immediate)
        } else {
            pc.checked_sub(immediate)
        }
        .ok_or(Error::ArithmeticOverflow)?;
        return Ok(Relocation::Adr {
            target,
            register: ((instruction >> 12) & 0xf) as u8,
            condition: Some(condition),
        });
    }

    let single_transfer = instruction & 0x0c00_0000 == 0x0400_0000;
    if single_transfer
        && instruction & (1 << 25) == 0
        && instruction & (1 << 24) != 0
        && instruction & (1 << 21) == 0
        && instruction & (1 << 20) != 0
        && (instruction >> 16) & 0xf == 15
        && (instruction >> 12) & 0xf != 15
        && condition != 15
    {
        let pc = address.checked_add(8).ok_or(Error::ArithmeticOverflow)?;
        let immediate = (instruction & 0xfff) as usize;
        let target = if instruction & (1 << 23) != 0 {
            pc.checked_add(immediate)
        } else {
            pc.checked_sub(immediate)
        }
        .ok_or(Error::ArithmeticOverflow)?;
        return Ok(Relocation::Literal {
            target,
            size: if instruction & (1 << 22) != 0 { 1 } else { 4 },
            mode: LiteralMode::A32(instruction & !0x0080_0fff),
        });
    }

    if condition != 15 && is_safe_a32(instruction) {
        return Ok(Relocation::Copy {
            bytes: bytes.to_vec(),
            terminal: false,
        });
    }
    Err(unsupported(address, "unknown A32 PC semantics"))
}

fn classify_thumb(bytes: &[u8], address: usize) -> Result<Relocation> {
    let first = u16::from_le_bytes([bytes[0], bytes[1]]);
    if bytes.len() == 2 {
        if first & 0xff00 == 0xbf00 && first & 0xf != 0 {
            return Err(unsupported(address, "Thumb IT block is not relocatable"));
        }
        if first & 0xf800 == 0xe000 {
            let displacement = sign_extend(u64::from(first & 0x7ff) << 1, 12);
            return Ok(Relocation::Branch {
                target: add_signed(address + 4, displacement)?,
                mode: BranchMode::Thumb,
            });
        }
        if first & 0xf000 == 0xd000 && (first >> 8) & 0xf < 14 {
            let displacement = sign_extend(u64::from(first & 0xff) << 1, 9);
            return Ok(Relocation::Branch {
                target: add_signed(address + 4, displacement)?,
                mode: BranchMode::ThumbConditional(invert_thumb_condition(first, false)),
            });
        }
        if first & 0xf500 == 0xb100 {
            let immediate = usize::from(((first >> 9) & 1) << 5 | ((first >> 3) & 0x1f)) << 1;
            return Ok(Relocation::Branch {
                target: address
                    .checked_add(4 + immediate)
                    .ok_or(Error::ArithmeticOverflow)?,
                mode: BranchMode::ThumbConditional(invert_thumb_cb(first)),
            });
        }
        if first & 0xff87 == 0x4780 {
            return Err(unsupported(address, "stolen BLX is not relocatable"));
        }
        if first & 0xff87 == 0x4700 {
            if (first >> 3) & 0xf == 15 {
                return Err(unsupported(address, "PC-based Thumb BX is not relocatable"));
            }
            return Ok(Relocation::Copy {
                bytes: bytes.to_vec(),
                terminal: true,
            });
        }
        if first & 0xf800 == 0xa000 {
            let target = crate::sys::page_start(address + 4, 4)
                .checked_add(usize::from(first & 0xff) << 2)
                .ok_or(Error::ArithmeticOverflow)?;
            return Ok(Relocation::Adr {
                target,
                register: ((first >> 8) & 7) as u8,
                condition: None,
            });
        }
        if first & 0xf800 == 0x4800 {
            let target = crate::sys::page_start(address + 4, 4)
                .checked_add(usize::from(first & 0xff) << 2)
                .ok_or(Error::ArithmeticOverflow)?;
            return Ok(Relocation::Literal {
                target,
                size: 4,
                mode: LiteralMode::Thumb(((first >> 8) & 7) as u8),
            });
        }
        if is_safe_thumb16(first) {
            return Ok(Relocation::Copy {
                bytes: bytes.to_vec(),
                terminal: false,
            });
        }
        return Err(unsupported(address, "unknown Thumb-16 PC semantics"));
    }

    let second = u16::from_le_bytes([bytes[2], bytes[3]]);
    if first & 0xf800 == 0xf000 {
        match second & 0xd000 {
            0xd000 | 0xc000 => {
                return Err(unsupported(address, "stolen BL/BLX is not relocatable"));
            }
            0x9000 => {
                return Ok(Relocation::Branch {
                    target: decode_thumb_wide_branch(first, second, address, false)?,
                    mode: BranchMode::Thumb,
                });
            }
            0x8000 if (first >> 6) & 0xf < 14 => {
                return Ok(Relocation::Branch {
                    target: decode_thumb_wide_branch(first, second, address, true)?,
                    mode: BranchMode::ThumbConditional(invert_thumb_condition(first >> 6, true)),
                });
            }
            _ => {}
        }
    }
    if first & 0xff7f == 0xf85f && (second >> 12) != 15 {
        let pc = crate::sys::page_start(address + 4, 4);
        let immediate = usize::from(second & 0xfff);
        let target = if first & 0x80 != 0 {
            pc.checked_add(immediate)
        } else {
            pc.checked_sub(immediate)
        }
        .ok_or(Error::ArithmeticOverflow)?;
        return Ok(Relocation::Literal {
            target,
            size: 4,
            mode: LiteralMode::Thumb((second >> 12) as u8),
        });
    }
    if is_safe_thumb32(first, second) {
        return Ok(Relocation::Copy {
            bytes: bytes.to_vec(),
            terminal: false,
        });
    }
    Err(unsupported(address, "unknown Thumb-32 PC semantics"))
}

fn validate_decode(bytes: &[u8], thumb: bool, address: usize) -> Result<()> {
    let decoder = if thumb {
        InstDecoder::default_thumb()
    } else {
        InstDecoder::default()
    };
    let mut reader = U8Reader::new(bytes);
    decoder
        .decode(&mut reader)
        .map(|_| ())
        .map_err(|_| unsupported(address, "ARM decoder rejected instruction"))
}

fn thumb_instruction_length(code: &[u8], offset: usize) -> Result<usize> {
    let first = code
        .get(offset..offset + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_le_bytes)
        .ok_or(Error::InvalidInlineTarget("truncated Thumb instruction"))?;
    Ok(if first & 0xf800 >= 0xe800 { 4 } else { 2 })
}

fn is_safe_a32(instruction: u32) -> bool {
    let rn = (instruction >> 16) & 0xf;
    let rd = (instruction >> 12) & 0xf;
    if instruction & 0x0e00_0000 == 0x0800_0000 {
        return rn != 15 && instruction & (1 << 15) == 0;
    }
    if instruction & 0x0c00_0000 == 0x0400_0000 {
        return rn != 15 && rd != 15 && (instruction & (1 << 25) == 0 || instruction & 0xf != 15);
    }
    if instruction & 0x0c00_0000 != 0 {
        return false;
    }
    if instruction & 0x0fc0_00f0 == 0x0000_0090 {
        return false;
    }
    let opcode = (instruction >> 21) & 0xf;
    let s = instruction & (1 << 20) != 0;
    let rn_used = !matches!(opcode, 13 | 15);
    let rd_used = !matches!(opcode, 8..=11) || !s;
    if (rn_used && rn == 15) || (rd_used && rd == 15) {
        return false;
    }
    if instruction & (1 << 25) == 0 {
        if instruction & 0xf == 15 {
            return false;
        }
        if instruction & (1 << 4) != 0 && (instruction >> 8) & 0xf == 15 {
            return false;
        }
    }
    !matches!(opcode, 8..=11) || s
}

fn is_safe_thumb16(instruction: u16) -> bool {
    let top = instruction >> 12;
    if top <= 4 || matches!(top, 5..=9 | 12) {
        if instruction & 0xfc00 == 0x4400 {
            let rm = (instruction >> 3) & 0xf;
            let rd = (instruction & 7) | ((instruction >> 4) & 8);
            return rm != 15 && rd != 15 && (instruction >> 8) & 3 != 3;
        }
        return true;
    }
    instruction & 0xfe00 == 0xb400
        || instruction & 0xff00 == 0xb000
        || instruction & 0xff0f == 0xbf00
        || (instruction & 0xfe00 == 0xbc00 && instruction & 0x0100 == 0)
        || instruction & 0xf800 == 0xa800
}

fn is_safe_thumb32(first: u16, second: u16) -> bool {
    ((first == 0xe92d || first == 0xe8bd) && second & 0x8000 == 0)
        || (first == 0xf3af && second & 0xd000 == 0x8000)
}

fn relay(address: usize, replacement: usize, thumb: bool) -> Result<Vec<u8>> {
    let replacement_address = replacement & !1;
    if thumb && replacement & 1 != 0 {
        if let Ok(branch) = encode_thumb_b_w(address, replacement_address) {
            return Ok(branch.to_vec());
        }
    } else if !thumb
        && replacement & 1 == 0
        && let Ok(branch) = encode_a32_b(14, address, replacement_address)
    {
        return Ok(branch.to_le_bytes().to_vec());
    }
    let mut relay = TransientBytes::from(Vec::with_capacity(8));
    if thumb {
        relay.extend_from_slice(&0xf8df_u16.to_le_bytes());
        relay.extend_from_slice(&0xf000_u16.to_le_bytes());
    } else {
        relay.extend_from_slice(&0xe51f_f004_u32.to_le_bytes());
    }
    relay.extend_from_slice(&(replacement as u32).to_le_bytes());
    Ok(relay.into_vec())
}

fn remap_branch(
    target: usize,
    stolen: &std::ops::Range<usize>,
    relocated: &[(usize, usize)],
) -> Result<usize> {
    if !stolen.contains(&target) {
        return Ok(target);
    }
    relocated
        .iter()
        .find(|(original, _)| *original == target)
        .map(|(_, relocated)| *relocated)
        .ok_or_else(|| unsupported(stolen.start, "branch enters stolen instruction middle"))
}

fn encode_a32_b(condition: u8, from: usize, to: usize) -> Result<u32> {
    let pc = from.checked_add(8).ok_or(Error::ArithmeticOverflow)?;
    let difference = (to as i128) - (pc as i128);
    if difference % 4 != 0 {
        return Err(Error::InvalidInlineTarget("unaligned A32 branch target"));
    }
    let immediate = difference / 4;
    if !(-(1_i128 << 23)..=(1_i128 << 23) - 1).contains(&immediate) {
        return Err(Error::NoNearbyMemory);
    }
    Ok((u32::from(condition) << 28) | 0x0a00_0000 | (immediate as u32 & 0x00ff_ffff))
}

fn encode_thumb_b_w(from: usize, to: usize) -> Result<[u8; 4]> {
    let pc = from.checked_add(4).ok_or(Error::ArithmeticOverflow)?;
    let difference = (to as i128) - (pc as i128);
    if difference % 2 != 0 {
        return Err(Error::InvalidInlineTarget("unaligned Thumb branch target"));
    }
    if !(-(1_i128 << 24)..=(1_i128 << 24) - 2).contains(&difference) {
        return Err(Error::NoNearbyMemory);
    }
    let immediate = difference as i32 as u32 & 0x01ff_ffff;
    let s = immediate >> 24 & 1;
    let i1 = immediate >> 23 & 1;
    let i2 = immediate >> 22 & 1;
    let j1 = (!(i1 ^ s)) & 1;
    let j2 = (!(i2 ^ s)) & 1;
    let first = 0xf000 | (s << 10) as u16 | ((immediate >> 12) & 0x3ff) as u16;
    let second = 0x9000 | (j1 << 13) as u16 | (j2 << 11) as u16 | ((immediate >> 1) & 0x7ff) as u16;
    let mut bytes = [0_u8; 4];
    bytes[..2].copy_from_slice(&first.to_le_bytes());
    bytes[2..].copy_from_slice(&second.to_le_bytes());
    Ok(bytes)
}

fn decode_thumb_wide_branch(
    first: u16,
    second: u16,
    address: usize,
    conditional: bool,
) -> Result<usize> {
    let s = u64::from((first >> 10) & 1);
    let j1 = u64::from((second >> 13) & 1);
    let j2 = u64::from((second >> 11) & 1);
    let immediate = if conditional {
        (s << 20)
            | (j2 << 19)
            | (j1 << 18)
            | (u64::from(first & 0x3f) << 12)
            | (u64::from(second & 0x7ff) << 1)
    } else {
        let i1 = (!(j1 ^ s)) & 1;
        let i2 = (!(j2 ^ s)) & 1;
        (s << 24)
            | (i1 << 23)
            | (i2 << 22)
            | (u64::from(first & 0x3ff) << 12)
            | (u64::from(second & 0x7ff) << 1)
    };
    add_signed(
        address.checked_add(4).ok_or(Error::ArithmeticOverflow)?,
        sign_extend(immediate, if conditional { 21 } else { 25 }),
    )
}

fn invert_thumb_condition(instruction: u16, wide: bool) -> u16 {
    let condition = if wide {
        instruction & 0xf
    } else {
        (instruction >> 8) & 0xf
    };
    0xd001 | ((condition ^ 1) << 8)
}

fn invert_thumb_cb(instruction: u16) -> u16 {
    ((instruction ^ 0x0800) & !0x02f8) | 0x0008
}

fn rotated_immediate(instruction: u32) -> usize {
    (instruction & 0xff).rotate_right(((instruction >> 8) & 0xf) * 2) as usize
}

fn emit_a32_address(bytes: &mut TransientBytes, condition: u8, register: u8, address: u32) {
    for (top, immediate) in [
        (0x0300_0000, address as u16),
        (0x0340_0000, (address >> 16) as u16),
    ] {
        let immediate = u32::from(immediate);
        let instruction = (u32::from(condition) << 28)
            | top
            | ((immediate & 0xf000) << 4)
            | (u32::from(register) << 12)
            | (immediate & 0x0fff);
        bytes.extend_from_slice(&instruction.to_le_bytes());
    }
}

fn align_code(bytes: &mut TransientBytes, alignment: usize) {
    let padding = bytes.len().wrapping_neg() & (alignment - 1);
    bytes.resize(bytes.len() + padding, 0);
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

fn unsupported(address: usize, reason: &'static str) -> Error {
    Error::UnsupportedInstruction { address, reason }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thumb_branch_round_trips_boundaries() {
        for difference in [-(1_i32 << 24), -2, 0, (1_i32 << 24) - 2] {
            let from = 0x0200_0000_usize;
            let to = (from as i64 + 4 + i64::from(difference)) as usize;
            let bytes = encode_thumb_b_w(from, to).unwrap();
            let first = u16::from_le_bytes(bytes[..2].try_into().unwrap());
            let second = u16::from_le_bytes(bytes[2..].try_into().unwrap());
            assert_eq!(
                decode_thumb_wide_branch(first, second, from, false).unwrap(),
                to
            );
        }
    }

    #[test]
    fn rejects_thumb_it_and_calls() {
        assert!(matches!(
            classify_thumb(&0xbf08_u16.to_le_bytes(), 0x1000),
            Err(Error::UnsupportedInstruction { .. })
        ));
        let mut call = Vec::new();
        call.extend_from_slice(&0xf000_u16.to_le_bytes());
        call.extend_from_slice(&0xd000_u16.to_le_bytes());
        assert!(matches!(
            classify_thumb(&call, 0x1000),
            Err(Error::UnsupportedInstruction { .. })
        ));
    }

    #[test]
    fn steals_a_complete_thumb32_instruction_after_thumb16() {
        let mut code = 0xbf00_u16.to_le_bytes().to_vec();
        code.extend_from_slice(&0xf3af_u16.to_le_bytes());
        code.extend_from_slice(&0x8000_u16.to_le_bytes());
        assert_eq!(analyze(0x1001, &code).unwrap().original.len(), 6);
    }

    #[test]
    fn steals_a_complete_bionic_thumb_it_block() {
        // bionic arm32 `abs`: cmp r0,#0; it mi; rsbmi r0,r0,#0; bx lr.
        let code: [u8; 8] = [0x00, 0x28, 0x48, 0xbf, 0x40, 0x42, 0x70, 0x47];
        let analysis = analyze(0x8efb3, &code).unwrap();
        assert_eq!(analysis.original.len(), 6);
        assert_eq!(&analysis.original[..4], &[0x00, 0x28, 0x48, 0xbf]);

        let generated = generate(&analysis, 0x2000, 0x3001, &[], false, None).unwrap();
        assert_eq!(generated.patch.len(), 6);
        let offset = generated.original & !1;
        let trampoline = &generated.bytes[offset - 0x2000..];
        assert_eq!(&trampoline[..6], &code[..6]);
    }

    #[test]
    fn steals_every_instruction_of_a_four_slot_it_block() {
        // it eq, mask 1111: movs r0,#1 under every slot, then bx lr.
        let mut code = 0xbf0f_u16.to_le_bytes().to_vec();
        for _ in 0..4 {
            code.extend_from_slice(&0x2001_u16.to_le_bytes());
        }
        code.extend_from_slice(&0x4770_u16.to_le_bytes());
        assert_eq!(analyze(0x1001, &code).unwrap().original.len(), 10);
    }

    #[test]
    fn rejects_a_branch_inside_an_it_block() {
        // cmp r0,#0; it mi; bne .+8 — the governed branch cannot keep its
        // predicate through the two-instruction conditional relocation.
        let mut code = [0x00_u8, 0x28, 0x48, 0xbf, 0x02, 0xd1, 0x70, 0x47];
        assert!(matches!(
            analyze(0x1001, &code),
            Err(Error::UnsupportedInstruction { .. })
        ));
        // Replacing the it word with a nop keeps the four-byte window clear
        // of the block, and the branch stays outside the stolen range.
        code[2] = 0x00;
        code[3] = 0xbf;
        let analysis = analyze(0x1001, &code).unwrap();
        assert_eq!(analysis.original.len(), 4);
    }

    #[test]
    fn rejects_nested_and_unpredictable_it_words() {
        // it eq inside a governed slot is UNPREDICTABLE.
        let nested: [u8; 8] = [0x08, 0xbf, 0x08, 0xbf, 0x01, 0x20, 0x01, 0x20];
        assert!(matches!(
            analyze(0x1001, &nested),
            Err(Error::UnsupportedInstruction { .. })
        ));
        assert!(it_governed_instructions(&0xbf08_u16.to_le_bytes()).is_some());
        // firstcond NV (1110) is UNPREDICTABLE.
        assert!(it_governed_instructions(&0xbfe8_u16.to_le_bytes()).is_none());
        for (instruction, expected) in [(0xbf08_u16, 1), (0xbf04, 2), (0xbf0a, 3), (0xbf0f, 4)] {
            assert_eq!(
                it_governed_instructions(&instruction.to_le_bytes()),
                Some(expected)
            );
        }
    }

    #[test]
    fn a32_branch_range_boundaries_are_exact() {
        assert!(encode_a32_b(14, 0x0200_0000, 0x0400_0004).is_ok());
        assert!(encode_a32_b(14, 0x0200_0000, 0x0400_0008).is_err());
        assert!(encode_a32_b(14, 0x0400_0000, 0x0200_0008).is_ok());
        assert_eq!(A32_MAX_DISTANCE, (32 * 1024 * 1024) - 8);
        assert_eq!(THUMB_MAX_DISTANCE, (16 * 1024 * 1024) - 4);
    }

    #[test]
    fn rejects_a32_adr_into_stolen_code() {
        // adr r0, . - 5: the produced address is entry + 3.
        let mut code = 0xe24f_0005_u32.to_le_bytes().to_vec();
        code.extend_from_slice(&0xe1a0_0000_u32.to_le_bytes());
        assert!(matches!(
            analyze(0x1000, &code),
            Err(Error::UnsupportedInstruction { .. })
        ));
        // adr r0, . + 8 addresses the instruction after the stolen one.
        let mut code = 0xe28f_0008_u32.to_le_bytes().to_vec();
        code.extend_from_slice(&0xe1a0_0000_u32.to_le_bytes());
        assert!(analyze(0x1000, &code).is_ok());
    }
}

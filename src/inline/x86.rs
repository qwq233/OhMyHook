use super::patch;
use super::{Arena, ArenaPlacement, Generated, TransientBytes};
use crate::maps::MapInfo;
use crate::{Error, Result};
use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Decoder, DecoderOptions, FlowControl, Instruction,
    InstructionBlock, InstructionInfoFactory, Mnemonic, OpKind,
};

#[cfg(target_arch = "x86")]
const BITNESS: u32 = 32;
#[cfg(target_arch = "x86_64")]
const BITNESS: u32 = 64;
const PATCH_LENGTH: usize = 5;
#[cfg(target_arch = "x86")]
const MAX_DISTANCE: usize = usize::MAX;
#[cfg(target_arch = "x86_64")]
const MAX_DISTANCE: usize = i32::MAX as usize;
pub(super) const WINDOW_LENGTH: usize = 23;

pub(super) struct Analysis {
    pub(super) patch_address: usize,
    pub(super) original: Vec<u8>,
    instructions: Vec<Instruction>,
    requires_encoding: bool,
}

impl Drop for Analysis {
    fn drop(&mut self) {
        crate::sys::erase_bytes(&mut self.original);
    }
}

pub(super) fn analyze(target: usize, code: &[u8], _maps: &[MapInfo]) -> Result<Analysis> {
    let landing = if code.starts_with(expected_endbr()) {
        expected_endbr().len()
    } else {
        0
    };
    let patch_address = target
        .checked_add(landing)
        .ok_or(Error::ArithmeticOverflow)?;
    let bytes = code
        .get(landing..)
        .ok_or(Error::InvalidInlineTarget("truncated x86 entry"))?;
    let mut decoder = Decoder::with_ip(BITNESS, bytes, patch_address as u64, DecoderOptions::NONE);
    let mut instructions = Vec::with_capacity(PATCH_LENGTH);
    #[cfg(target_arch = "x86")]
    let mut requires_encoding = false;
    #[cfg(not(target_arch = "x86"))]
    let requires_encoding = false;
    while decoder.position() < PATCH_LENGTH {
        if !decoder.can_decode() {
            return Err(Error::InvalidInlineTarget("truncated x86 instruction"));
        }
        let start = decoder.position();
        let instruction = decoder.decode();
        if instruction.is_invalid() {
            return Err(unsupported(
                instruction.ip() as usize,
                "invalid x86 instruction",
            ));
        }
        let flow = instruction.flow_control();
        #[cfg(target_arch = "x86")]
        if flow == FlowControl::Call
            && let Some(relocated) = try_relocate_pc_thunk(&instruction, _maps)?
        {
            instructions.push(relocated);
            requires_encoding = true;
            continue;
        }
        if matches!(
            flow,
            FlowControl::IndirectCall | FlowControl::Interrupt | FlowControl::Exception
        ) || (flow == FlowControl::Call
            && (near_branch_target(&instruction).is_none()
                || instruction.near_branch_target() == instruction.next_ip()))
            || (flow == FlowControl::Return && instruction.mnemonic() != Mnemonic::Ret)
        {
            return Err(unsupported(
                instruction.ip() as usize,
                // On 32-bit this is most often a position-independent entry
                // opening with `call __x86.get_pc_thunk.*`, whose return
                // address is the value the rest of the function depends on.
                "x86 call, exception, or system transition is not relocatable",
            ));
        }
        if is_x87(&bytes[start..decoder.position()]) {
            return Err(unsupported(
                instruction.ip() as usize,
                "stolen x87 instruction has observable PC semantics",
            ));
        }
        instructions.push(instruction);
        // Execution cannot fall out of these, so the bytes after them belong to
        // whatever the toolchain placed next rather than to this entry. The
        // decoder has no function bounds, so continuing would silently steal
        // and overwrite the beginning of an unrelated function.
        if matches!(
            flow,
            FlowControl::Return | FlowControl::UnconditionalBranch | FlowControl::IndirectBranch
        ) {
            break;
        }
    }
    let stolen = decoder.position();
    if stolen < 2 {
        return Err(unsupported(
            patch_address,
            "x86 entry ends before a relative jump fits",
        ));
    }
    let end = patch_address
        .checked_add(stolen)
        .ok_or(Error::ArithmeticOverflow)?;
    let mut info_factory = None;
    for instruction in &instructions {
        // With ENDBR the block starts at patch_address while the entry keeps
        // its landing instruction: a branch back onto the ENDBR itself sits
        // outside the encoded block, so no relocation can redirect it, and
        // after installation it would re-enter the hook. Without ENDBR the
        // entry equals the first stolen instruction, whose ip-exemption below
        // still lets the encoder relocate that back edge.
        if let Some(branch) = near_branch_target(instruction)
            && (target..end).contains(&branch)
            && !instructions
                .iter()
                .any(|instruction| instruction.ip() as usize == branch)
        {
            return Err(unsupported(
                instruction.ip() as usize,
                "branch enters the middle of a stolen instruction",
            ));
        }
        if instruction.is_ip_rel_memory_operand() {
            let info_factory = info_factory.get_or_insert_with(InstructionInfoFactory::new);
            let target = instruction.ip_rel_memory_address() as usize;
            if info_factory.info(instruction).used_memory().is_empty() {
                // An address-only operand such as RIP-relative LEA is
                // relocated value-preservingly, but a target inside the
                // overwritten span would point into patched bytes.
                if (patch_address..end).contains(&target) {
                    return Err(unsupported(
                        instruction.ip() as usize,
                        "PC-relative address points into stolen instructions",
                    ));
                }
                continue;
            }
            let width = instruction.memory_size().size();
            let overlaps = if width == 0 {
                target < end
            } else {
                target < end
                    && patch_address < target.checked_add(width).ok_or(Error::ArithmeticOverflow)?
            };
            if overlaps {
                return Err(unsupported(
                    instruction.ip() as usize,
                    "PC-relative data overlaps stolen instructions",
                ));
            }
        }
    }
    Ok(Analysis {
        patch_address,
        original: bytes[..stolen].to_vec(),
        instructions,
        requires_encoding,
    })
}

pub(super) fn max_distance(analysis: &Analysis, replacement: usize) -> usize {
    if analysis.original.len() < PATCH_LENGTH
        && short_relative_jump(analysis.patch_address, replacement).is_err()
    {
        i8::MAX as usize + 2
    } else {
        MAX_DISTANCE
    }
}

pub(super) const fn mapped_target(target: usize) -> Result<usize> {
    Ok(target)
}

pub(super) const fn mapped_replacement(replacement: usize) -> Result<usize> {
    Ok(replacement)
}

pub(super) fn redirects_to(
    analysis: &Analysis,
    replacement: usize,
    maps: &[MapInfo],
) -> Result<bool> {
    let Some(destination) = relative_jump_target(analysis.patch_address, &analysis.original) else {
        return Ok(false);
    };
    if destination == replacement {
        return Ok(true);
    }
    // `relay` emits a plain relative jump whenever the replacement is in range
    // of the arena, which on i386 is unconditional. Recognize that shape before
    // the absolute forms, otherwise a repeated installation is not detected.
    if relay_jump_target(maps, destination)? == Some(replacement) {
        return Ok(true);
    }

    #[cfg(target_arch = "x86_64")]
    {
        let probe = patch::probe_maps(maps, destination, 14)?;
        let validation_maps = probe.as_deref().unwrap_or(maps);
        if patch::validate_executable_entry(validation_maps, destination, 14).is_err() {
            return Ok(false);
        }
        // SAFETY: validation covers the complete relay bytes.
        let relay = unsafe {
            std::slice::from_raw_parts(std::ptr::with_exposed_provenance::<u8>(destination), 14)
        };
        if relay[..6] != [0xff, 0x25, 0, 0, 0, 0] {
            return Ok(false);
        }
        let Ok(relay_destination) = relay[6..14].try_into() else {
            return Ok(false);
        };
        let relay_destination = u64::from_le_bytes(relay_destination) as usize;
        if relay_destination == replacement {
            return Ok(true);
        }
        let bridge_maps = patch::probe_maps(validation_maps, relay_destination, 9)?;
        let bridge_maps = bridge_maps.as_deref().unwrap_or(validation_maps);
        if patch::validate_executable_entry(bridge_maps, relay_destination, 9).is_err() {
            return Ok(false);
        }
        // SAFETY: validation covers ENDBR plus one relative jump.
        let bridge = unsafe {
            std::slice::from_raw_parts(
                std::ptr::with_exposed_provenance::<u8>(relay_destination),
                9,
            )
        };
        Ok(bridge.starts_with(expected_endbr())
            && relative_jump_target(relay_destination + expected_endbr().len(), &bridge[4..])
                == Some(replacement))
    }
    #[cfg(target_arch = "x86")]
    {
        let probe = patch::probe_maps(maps, destination, 10)?;
        let validation_maps = probe.as_deref().unwrap_or(maps);
        if patch::validate_executable_entry(validation_maps, destination, 10).is_err() {
            return Ok(false);
        }
        // SAFETY: validation covers the complete absolute relay.
        let relay = unsafe {
            std::slice::from_raw_parts(std::ptr::with_exposed_provenance::<u8>(destination), 10)
        };
        let low = u32::from_le_bytes([relay[2], relay[3], relay[4], relay[5]]);
        let high = u32::from_le_bytes([relay[6], relay[7], relay[8], relay[9]]);
        if relay[..2] != [0xff, 0x25] || low as usize != destination.saturating_add(6) {
            return Ok(false);
        }
        if high as usize == replacement {
            return Ok(true);
        }
        let bridge_maps = patch::probe_maps(validation_maps, high as usize, 9)?;
        let bridge_maps = bridge_maps.as_deref().unwrap_or(validation_maps);
        if patch::validate_executable_entry(bridge_maps, high as usize, 9).is_err() {
            return Ok(false);
        }
        // SAFETY: validation covers ENDBR32 plus one relative jump.
        let bridge = unsafe {
            std::slice::from_raw_parts(std::ptr::with_exposed_provenance::<u8>(high as usize), 9)
        };
        Ok(bridge.starts_with(expected_endbr())
            && relative_jump_target(high as usize + expected_endbr().len(), &bridge[4..])
                == Some(replacement))
    }
}

fn relay_jump_target(maps: &[MapInfo], destination: usize) -> Result<Option<usize>> {
    let probe = patch::probe_maps(maps, destination, PATCH_LENGTH)?;
    let validation_maps = probe.as_deref().unwrap_or(maps);
    if patch::validate_executable_entry(validation_maps, destination, PATCH_LENGTH).is_err() {
        return Ok(None);
    }
    // SAFETY: validation covers the complete relative jump.
    let relay = unsafe {
        std::slice::from_raw_parts(
            std::ptr::with_exposed_provenance::<u8>(destination),
            PATCH_LENGTH,
        )
    };
    Ok(relative_jump_target(destination, relay))
}

fn relative_jump_target(from: usize, bytes: &[u8]) -> Option<usize> {
    if bytes.first() == Some(&0xeb) {
        return from
            .checked_add(2)?
            .checked_add_signed(*bytes.get(1)? as i8 as isize);
    }
    if bytes.first() != Some(&0xe9) {
        return None;
    }
    let displacement = i32::from_le_bytes(bytes.get(1..5)?.try_into().ok()?);
    from.checked_add(PATCH_LENGTH)?
        .checked_add_signed(displacement as isize)
}

pub(super) fn generate(
    analysis: &Analysis,
    arena: usize,
    replacement: usize,
    validation_maps: &[MapInfo],
    allocation_maps: &[MapInfo],
    allow_auxiliary: bool,
    mem: Option<usize>,
) -> Result<Generated> {
    let short_entry = analysis.original.len() < PATCH_LENGTH;
    let direct_patch = if short_entry {
        short_relative_jump(analysis.patch_address, replacement).map(|patch| patch.to_vec())
    } else {
        #[cfg(target_arch = "x86_64")]
        {
            relative_jump(analysis.patch_address, replacement).map(|patch| patch.to_vec())
        }
        #[cfg(target_arch = "x86")]
        {
            Err(Error::NoNearbyMemory)
        }
    };
    let direct_patch = match direct_patch {
        Ok(patch) => Some(patch),
        Err(Error::NoNearbyMemory) => None,
        Err(error) => return Err(error),
    };
    let short_relay_patch = if short_entry && direct_patch.is_none() {
        Some(short_relative_jump(analysis.patch_address, arena)?)
    } else {
        None
    };
    let (bytes, mut auxiliary) = if direct_patch.is_some() {
        (Vec::new(), None)
    } else {
        relay(
            arena,
            replacement,
            validation_maps,
            allocation_maps,
            allow_auxiliary,
            mem,
        )?
    };
    let mut bytes = TransientBytes::from(bytes);
    let generated = (|| {
        align_code(&mut bytes, 16);
        let trampoline_offset = bytes.len();
        bytes.extend_from_slice(expected_endbr());
        let relocated_ip = arena
            .checked_add(bytes.len())
            .ok_or(Error::ArithmeticOverflow)?;
        if !analysis.requires_encoding
            && analysis.instructions.iter().all(|instruction| {
                near_branch_target(instruction).is_none() && !instruction.is_ip_rel_memory_operand()
            })
        {
            bytes.extend_from_slice(&analysis.original);
        } else {
            let encoded = BlockEncoder::encode(
                BITNESS,
                InstructionBlock::new(&analysis.instructions, relocated_ip as u64),
                BlockEncoderOptions::RETURN_RELOC_INFOS
                    | BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS,
            )
            .map_err(|_| Error::NoNearbyMemory)?;
            let unsupported = !encoded.reloc_infos.is_empty()
                || encoded.new_instruction_offsets.contains(&u32::MAX);
            let mut code_buffer = encoded.code_buffer;
            if unsupported {
                crate::sys::erase_bytes(&mut code_buffer);
                return Err(Error::NoNearbyMemory);
            }
            bytes.extend_from_slice(&code_buffer);
            crate::sys::erase_bytes(&mut code_buffer);
        }
        let continuation = analysis
            .patch_address
            .checked_add(analysis.original.len())
            .ok_or(Error::ArithmeticOverflow)?;
        let jump_address = arena
            .checked_add(bytes.len())
            .ok_or(Error::ArithmeticOverflow)?;
        bytes.extend_from_slice(&relative_jump(jump_address, continuation)?);

        let mut patch = TransientBytes::from(match direct_patch {
            Some(patch) => patch,
            None if short_entry => short_relay_patch
                .unwrap_or_else(|| crate::sys::fail_stop())
                .to_vec(),
            None => relative_jump(analysis.patch_address, arena)?.to_vec(),
        });
        patch.resize(analysis.original.len(), 0x90);
        let original = arena
            .checked_add(trampoline_offset)
            .ok_or(Error::ArithmeticOverflow)?;
        Ok(Generated {
            bytes: bytes.into_vec(),
            patch: patch.into_vec(),
            original,
            auxiliary: auxiliary.take(),
        })
    })();
    if generated.is_err()
        && let Some(bridge) = auxiliary
    {
        // SAFETY: generation failed before any entry could reach the bridge.
        // No handle exists through which failed cleanup could be retried, so
        // the bridge leaks. Nothing was written to the target, so report the
        // leak instead of taking the host process down.
        if let Err(error) = unsafe { bridge.release() } {
            return Err(super::cleanup_pending(error));
        }
    }
    generated
}

fn relay(
    address: usize,
    replacement: usize,
    _validation_maps: &[MapInfo],
    _allocation_maps: &[MapInfo],
    allow_bridge: bool,
    _mem: Option<usize>,
) -> Result<(Vec<u8>, Option<Arena>)> {
    if let Ok(jump) = relative_jump(address, replacement) {
        return Ok((jump.to_vec(), None));
    }

    #[cfg(target_arch = "x86_64")]
    {
        let landing = patch::validate_executable_entry(
            _validation_maps,
            replacement,
            expected_endbr().len(),
        )
        .is_ok()
            // SAFETY: successful validation covers the complete instruction.
            && unsafe {
                std::slice::from_raw_parts(
                    std::ptr::with_exposed_provenance::<u8>(replacement),
                    expected_endbr().len(),
                ) == expected_endbr()
            };
        let bridge = if landing {
            None
        } else if !allow_bridge {
            // The strict placement pass prefers an arena from which a plain
            // relative jump reaches the replacement, which needs no landing
            // pad and no second mapping.
            return Err(Error::NoNearbyMemory);
        } else {
            let page_size = crate::sys::page_size()?;
            // SAFETY: candidates come from captured gaps and installation
            // excludes concurrent mapping changes.
            let (bridge, bytes) = unsafe {
                Arena::allocate_near(
                    _allocation_maps,
                    replacement,
                    MAX_DISTANCE,
                    page_size,
                    page_size,
                    ArenaPlacement {
                        direct: _mem.map(|fd| (libc::PROT_READ | libc::PROT_EXEC, fd)),
                        allowed: None,
                    },
                    |bridge| {
                        let mut bytes = TransientBytes::from(expected_endbr().to_vec());
                        let jump = bridge
                            .checked_add(bytes.len())
                            .ok_or(Error::ArithmeticOverflow)?;
                        bytes.extend_from_slice(&relative_jump(jump, replacement)?);
                        Ok(bytes.into_vec())
                    },
                )?
            };
            let bytes = TransientBytes::from(bytes);
            let prepared = (|| {
                // SAFETY: the bridge is caller-owned private memory.
                unsafe { bridge.write(&bytes, _mem)? };
                // SAFETY: RW bridges receive their sole RW-to-executable
                // transition; direct bridges already have final protection.
                unsafe { bridge.make_executable(libc::PROT_READ | libc::PROT_EXEC)? };
                Ok(())
            })();
            if let Err(error) = prepared {
                // SAFETY: no generated entry can reach this unpublished bridge.
                // No handle exists through which failed cleanup could be
                // retried, so the bridge leaks. Report the leak in preference
                // to the preparation error: the caller can retry preparation,
                // but only it can decide what an unreleasable executable
                // mapping is worth.
                if let Err(unmap_error) = unsafe { bridge.release() } {
                    return Err(super::cleanup_pending(unmap_error));
                }
                return Err(error);
            }
            Some(bridge)
        };
        let destination = bridge.as_ref().map_or(replacement, Arena::address);
        let mut relay = TransientBytes::from(vec![0xff, 0x25, 0, 0, 0, 0]);
        relay.extend_from_slice(&(destination as u64).to_le_bytes());
        Ok((relay.into_vec(), bridge))
    }
    #[cfg(target_arch = "x86")]
    {
        let landing = patch::validate_executable_entry(
            _validation_maps,
            replacement,
            expected_endbr().len(),
        )
        .is_ok()
            // SAFETY: successful validation covers the complete instruction.
            && unsafe {
                std::slice::from_raw_parts(
                    std::ptr::with_exposed_provenance::<u8>(replacement),
                    expected_endbr().len(),
                ) == expected_endbr()
            };
        if !landing && !allow_bridge {
            // Without an ENDBR32 landing the absolute indirect jump would
            // fault under CET IBT, so the strict pass keeps looking for a
            // directly reachable arena instead of building one.
            return Err(Error::NoNearbyMemory);
        }
        let bridge = if landing {
            None
        } else {
            let page_size = crate::sys::page_size()?;
            // SAFETY: candidates come from captured gaps and installation
            // excludes concurrent mapping changes.
            let (bridge, bytes) = unsafe {
                Arena::allocate_near(
                    _allocation_maps,
                    replacement,
                    MAX_DISTANCE,
                    page_size,
                    page_size,
                    ArenaPlacement {
                        direct: _mem.map(|fd| (libc::PROT_READ | libc::PROT_EXEC, fd)),
                        allowed: None,
                    },
                    |bridge| {
                        let mut bytes = TransientBytes::from(expected_endbr().to_vec());
                        let jump = bridge
                            .checked_add(bytes.len())
                            .ok_or(Error::ArithmeticOverflow)?;
                        bytes.extend_from_slice(&relative_jump(jump, replacement)?);
                        Ok(bytes.into_vec())
                    },
                )?
            };
            let bytes = TransientBytes::from(bytes);
            let prepared = (|| {
                // SAFETY: the bridge is caller-owned private memory.
                unsafe { bridge.write(&bytes, _mem)? };
                // SAFETY: RW bridges receive their sole RW-to-executable
                // transition; direct bridges already have final protection.
                unsafe { bridge.make_executable(libc::PROT_READ | libc::PROT_EXEC)? };
                Ok(())
            })();
            if let Err(error) = prepared {
                // SAFETY: no generated entry can reach this unpublished
                // bridge, and no handle exists through which failed cleanup
                // could be retried, so the bridge leaks.
                if let Err(unmap_error) = unsafe { bridge.release() } {
                    return Err(super::cleanup_pending(unmap_error));
                }
                return Err(error);
            }
            Some(bridge)
        };
        let destination = bridge.as_ref().map_or(replacement, Arena::address);
        let literal = address.checked_add(6).ok_or(Error::ArithmeticOverflow)?;
        let mut relay = TransientBytes::from(vec![0xff, 0x25]);
        relay.extend_from_slice(&(literal as u32).to_le_bytes());
        relay.extend_from_slice(&(destination as u32).to_le_bytes());
        Ok((relay.into_vec(), bridge))
    }
}

fn short_relative_jump(from: usize, to: usize) -> Result<[u8; 2]> {
    let next = from.checked_add(2).ok_or(Error::ArithmeticOverflow)?;
    let displacement =
        i8::try_from(to as i128 - next as i128).map_err(|_| Error::NoNearbyMemory)?;
    Ok([0xeb, displacement as u8])
}

fn relative_jump(from: usize, to: usize) -> Result<[u8; PATCH_LENGTH]> {
    let next = from
        .checked_add(PATCH_LENGTH)
        .ok_or(Error::ArithmeticOverflow)?;
    #[cfg(target_arch = "x86_64")]
    let displacement =
        i32::try_from((to as i128) - (next as i128)).map_err(|_| Error::NoNearbyMemory)?;
    #[cfg(target_arch = "x86")]
    let displacement = (to as u32).wrapping_sub(next as u32) as i32;
    let mut jump = [0_u8; PATCH_LENGTH];
    jump[0] = 0xe9;
    jump[1..].copy_from_slice(&displacement.to_le_bytes());
    Ok(jump)
}

#[cfg(target_arch = "x86")]
fn try_relocate_pc_thunk(
    instruction: &Instruction,
    _maps: &[MapInfo],
) -> Result<Option<Instruction>> {
    use iced_x86::{Code, Register};

    let Some(target) = near_branch_target(instruction) else {
        return Ok(None);
    };
    let mut thunk = [0_u8; 8];
    let probe = patch::probe_maps(_maps, target, thunk.len())?;
    let maps = probe.as_deref().unwrap_or(_maps);
    let Ok(length) = patch::copy_executable_window(maps, target, &mut thunk) else {
        return Ok(None);
    };
    let thunk = &thunk[..length];
    let thunk = thunk.strip_prefix(expected_endbr()).unwrap_or(thunk);
    if thunk.len() < 4
        || thunk[0] != 0x8b
        || thunk[2] != 0x24
        || thunk[3] != 0xc3
        || (thunk[1] & 0xc7) != 0x04
    {
        return Ok(None);
    }
    let register = match (thunk[1] >> 3) & 0x7 {
        0 => Register::EAX,
        1 => Register::ECX,
        2 => Register::EDX,
        3 => Register::EBX,
        4 => Register::ESP,
        5 => Register::EBP,
        6 => Register::ESI,
        _ => Register::EDI,
    };
    let next_ip = instruction
        .ip()
        .checked_add(u64::from(instruction.len() as u32))
        .ok_or(Error::ArithmeticOverflow)?;
    let immediate = u32::try_from(next_ip).map_err(|_| Error::ArithmeticOverflow)?;
    let mut mov = Instruction::with2(Code::Mov_r32_imm32, register, immediate).map_err(|_| {
        unsupported(
            instruction.ip() as usize,
            "x86 PC-thunk relocation creation failed",
        )
    })?;
    mov.set_ip(instruction.ip());
    Ok(Some(mov))
}

fn near_branch_target(instruction: &Instruction) -> Option<usize> {
    matches!(
        instruction.op0_kind(),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
    )
    .then(|| instruction.near_branch_target() as usize)
}

fn is_x87(bytes: &[u8]) -> bool {
    let mut index = 0;
    let mut skipped_wait = false;
    while let Some(&byte) = bytes.get(index) {
        let legacy = matches!(
            byte,
            0xf0 | 0xf2 | 0xf3 | 0x2e | 0x36 | 0x3e | 0x26 | 0x64 | 0x65 | 0x66 | 0x67
        );
        let rex = BITNESS == 64 && (0x40..=0x4f).contains(&byte);
        if legacy || rex {
            index += 1;
        } else if byte == 0x9b && !skipped_wait {
            skipped_wait = true;
            index += 1;
        } else {
            return (0xd8..=0xdf).contains(&byte);
        }
    }
    false
}

fn expected_endbr() -> &'static [u8; 4] {
    #[cfg(target_arch = "x86")]
    {
        b"\xf3\x0f\x1e\xfb"
    }
    #[cfg(target_arch = "x86_64")]
    {
        b"\xf3\x0f\x1e\xfa"
    }
}

fn align_code(bytes: &mut TransientBytes, alignment: usize) {
    let padding = bytes.len().wrapping_neg() & (alignment - 1);
    bytes.resize(bytes.len() + padding, 0x90);
}

fn unsupported(address: usize, reason: &'static str) -> Error {
    Error::UnsupportedInstruction { address, reason }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_arch = "x86_64")]
    use crate::maps::{DeviceId, MapPerms};

    #[test]
    fn relocates_a_direct_call_and_preserves_its_destination() {
        let analysis = analyze(0x1000, &[0xe8, 0xfb, 0, 0, 0], &[]).unwrap();
        let generated = generate(&analysis, 0x2000, 0x1080, &[], &[], false, None).unwrap();
        let offset = generated.original - 0x2000 + expected_endbr().len();
        let mut decoder = Decoder::with_ip(
            BITNESS,
            &generated.bytes[offset..],
            (0x2000 + offset) as u64,
            DecoderOptions::NONE,
        );
        let call = decoder.decode();
        assert_eq!(call.flow_control(), FlowControl::Call);
        assert_eq!(call.near_branch_target(), 0x1100);
    }

    #[test]
    fn short_entry_uses_only_its_own_bytes_for_a_nearby_replacement() {
        let analysis = analyze(0x1000, &[0x31, 0xc0, 0xc3, 0xb8, 42, 0, 0, 0, 0xc3], &[]).unwrap();
        assert_eq!(analysis.original, [0x31, 0xc0, 0xc3]);
        assert_eq!(max_distance(&analysis, 0x1040), MAX_DISTANCE);
        assert_eq!(max_distance(&analysis, 0x3000), 129);
        let generated = generate(&analysis, 0x2000, 0x1040, &[], &[], false, None).unwrap();
        assert_eq!(generated.patch, [0xeb, 0x3e, 0x90]);
        assert_eq!(relative_jump_target(0x1000, &generated.patch), Some(0x1040));
        assert!(matches!(
            generate(&analysis, 0x2000, 0x3000, &[], &[], false, None),
            Err(Error::NoNearbyMemory)
        ));
        let relayed = generate(&analysis, 0x1040, 0x3000, &[], &[], false, None).unwrap();
        assert_eq!(relayed.patch, [0xeb, 0x3e, 0x90]);
        assert_eq!(relative_jump_target(0x1040, &relayed.bytes), Some(0x3000));
        assert!(relayed.original > 0x1040);
    }

    #[cfg(target_arch = "x86")]
    #[test]
    fn redirects_to_follows_endbr32_bridge() {
        const PAGE: usize = 0x1000;
        // SAFETY: the test owns this anonymous executable mapping.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                PAGE,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        let base = mapping as usize;
        let patch_address = base + 0x100;
        let relay = base + 0x200;
        let bridge = base + 0x300;
        let replacement = base + 0x400;

        // SAFETY: the test owns the complete mapping.
        unsafe {
            let bytes = std::slice::from_raw_parts_mut(mapping.cast::<u8>(), PAGE);
            bytes[0x100..0x105].copy_from_slice(&relative_jump(patch_address, relay).unwrap());
            bytes[0x200..0x202].copy_from_slice(&[0xff, 0x25]);
            bytes[0x202..0x206].copy_from_slice(&((relay + 6) as u32).to_le_bytes());
            bytes[0x206..0x20a].copy_from_slice(&(bridge as u32).to_le_bytes());
            bytes[0x300..0x304].copy_from_slice(expected_endbr());
            bytes[0x304..0x309].copy_from_slice(&relative_jump(bridge + 4, replacement).unwrap());
        }

        let maps = [crate::maps::MapInfo {
            start: base,
            end: base + PAGE,
            perms: crate::maps::MapPerms::READ | crate::maps::MapPerms::EXEC,
            is_private: true,
            offset: 0,
            device: crate::maps::DeviceId::new(0, 0),
            inode: 0,
            path: None,
        }];
        let analysis = Analysis {
            patch_address,
            original: relative_jump(patch_address, relay).unwrap().to_vec(),
            instructions: Vec::new(),
            requires_encoding: false,
        };

        assert!(redirects_to(&analysis, replacement, &maps).unwrap());

        // SAFETY: the test still owns the complete mapping.
        unsafe {
            let bytes = std::slice::from_raw_parts_mut(mapping.cast::<u8>(), PAGE);
            bytes[0x304] ^= 1;
        }
        assert!(!redirects_to(&analysis, replacement, &maps).unwrap());

        // SAFETY: the test owns the complete mapping.
        unsafe {
            assert_eq!(libc::munmap(mapping, PAGE), 0);
        }
    }

    #[cfg(target_arch = "x86")]
    #[test]
    fn relocates_a_pc_thunk_call_to_the_original_return_address() {
        use iced_x86::{Code, Register};

        const PAGE: usize = 0x1000;
        const TARGET: usize = 0x1000;

        // SAFETY: the test owns this anonymous executable mapping.
        let mapping = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                2 * PAGE,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(mapping, libc::MAP_FAILED);
        let thunk_address = mapping as usize;

        // SAFETY: the test owns the complete mapping.
        unsafe {
            assert_eq!(
                libc::mprotect(mapping, PAGE, libc::PROT_READ | libc::PROT_WRITE),
                0
            );
            let bytes = std::slice::from_raw_parts_mut(mapping.cast::<u8>(), PAGE);
            bytes[..4].copy_from_slice(&[0x8b, 0x1c, 0x24, 0xc3]);
            bytes[16..22].copy_from_slice(&[0xb8, 11, 0, 0, 0, 0xc3]);
            bytes[32..40].copy_from_slice(&[0xf3, 0x0f, 0x1e, 0xfb, 0x8b, 0x1c, 0x24, 0xc3]);
            bytes[64..74].copy_from_slice(&[0xf3, 0x0f, 0x1e, 0xfb, 0xb8, 11, 0, 0, 0, 0xc3]);
            bytes[PAGE - 8..].copy_from_slice(&[0xf3, 0x0f, 0x1e, 0xfb, 0x8b, 0x1c, 0x24, 0xc3]);
            assert_eq!(
                libc::mprotect(mapping, PAGE, libc::PROT_READ | libc::PROT_EXEC),
                0
            );
        }

        let maps = [crate::maps::MapInfo {
            start: thunk_address,
            end: thunk_address + PAGE,
            perms: crate::maps::MapPerms::READ | crate::maps::MapPerms::EXEC,
            is_private: true,
            offset: 0,
            device: crate::maps::DeviceId::new(0, 0),
            inode: 0,
            path: None,
        }];

        for offset in [0, 32, PAGE - 8, PAGE - 4] {
            let displacement = ((thunk_address + offset) as u32).wrapping_sub(TARGET as u32 + 5);
            let entry = [0xe8]
                .into_iter()
                .chain(displacement.to_le_bytes())
                .collect::<Vec<_>>();
            for snapshot in [maps.as_slice(), &[]] {
                let analysis = analyze(TARGET, &entry, snapshot).unwrap();
                assert_eq!(analysis.original.len(), 5);
                assert_eq!(analysis.instructions.len(), 1);
                assert_eq!(analysis.instructions[0].code(), Code::Mov_r32_imm32);
                assert_eq!(analysis.instructions[0].op0_register(), Register::EBX);
                assert_eq!(analysis.instructions[0].immediate32(), TARGET as u32 + 5);
                assert!(analysis.requires_encoding);
            }
        }

        for offset in [16, 64] {
            let displacement = ((thunk_address + offset) as u32).wrapping_sub(TARGET as u32 + 5);
            let ordinary_call = [0xe8]
                .into_iter()
                .chain(displacement.to_le_bytes())
                .collect::<Vec<_>>();
            let analysis = analyze(TARGET, &ordinary_call, &[]).unwrap();
            assert_eq!(analysis.instructions[0].code(), Code::Call_rel32_32);
            assert_eq!(
                analysis.instructions[0].near_branch_target(),
                (thunk_address + offset) as u64
            );
        }

        // SAFETY: the test still owns the complete mapping.
        unsafe {
            assert_eq!(libc::munmap(mapping, 2 * PAGE), 0);
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn decode_relative_jump(from: usize, patch: &[u8]) -> usize {
        assert_eq!(patch[0], 0xe9);
        let displacement = i32::from_le_bytes(patch[1..PATCH_LENGTH].try_into().unwrap());
        from.checked_add(PATCH_LENGTH)
            .unwrap()
            .checked_add_signed(displacement as isize)
            .unwrap()
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn direct_patch_targets_replacement_and_pads_the_stolen_span() {
        let analysis = analyze(0x1000, &[0x48, 0x8d, 0x05, 0, 0, 0, 0], &[]).unwrap();
        let generated = generate(&analysis, 0x2000, 0x3000, &[], &[], false, None).unwrap();

        assert_eq!(
            decode_relative_jump(analysis.patch_address, &generated.patch),
            0x3000
        );
        assert_eq!(generated.patch.len(), analysis.original.len());
        assert_eq!(&generated.patch[PATCH_LENGTH..], &[0x90, 0x90]);
        assert_eq!(generated.original, 0x2000);
        assert_eq!(&generated.bytes[..expected_endbr().len()], expected_endbr());
        assert!(generated.auxiliary.is_none());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn far_patch_targets_relay_and_preserves_endbr_layout() {
        let replacement = expected_endbr().as_ptr().expose_provenance();
        let arena = replacement ^ (1_usize << 32);
        let target = arena.checked_sub(0x1000).unwrap();
        let maps = [MapInfo {
            start: replacement,
            end: replacement.checked_add(expected_endbr().len()).unwrap(),
            perms: MapPerms::READ | MapPerms::EXEC,
            is_private: true,
            offset: 0,
            device: DeviceId::new(0, 0),
            inode: 0,
            path: None,
        }];
        let analysis = analyze(target, &[0x55, 0x48, 0x89, 0xe5, 0x90], &[]).unwrap();
        let generated = generate(&analysis, arena, replacement, &maps, &maps, false, None).unwrap();

        assert!(relative_jump(arena, replacement).is_err());
        assert_eq!(decode_relative_jump(target, &generated.patch), arena);
        assert_eq!(&generated.bytes[..6], &[0xff, 0x25, 0, 0, 0, 0]);
        assert_eq!(
            u64::from_le_bytes(generated.bytes[6..14].try_into().unwrap()) as usize,
            replacement
        );
        assert_eq!(&generated.bytes[14..16], &[0x90, 0x90]);
        assert_eq!(generated.original, arena + 16);
        assert_eq!(&generated.bytes[16..20], expected_endbr());
        assert!(generated.auxiliary.is_none());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn a_relocated_branch_that_cannot_reach_its_target_is_rejected() {
        // The stolen span conditionally branches to 0x1022, outside itself, and
        // a conditional branch does not terminate the entry. Relocating it
        // into an arena four gibibytes away leaves that target unreachable with
        // a rel32, and the block encoder answers with relocation entries rather
        // than a self-contained block. The guard on those entries is what stops
        // the trampoline's tail jump from being emitted after an eight-byte
        // pointer blob, where execution would fall straight into data.
        let target = 0x1000_usize;
        let arena = target + (1_usize << 32);
        let analysis = analyze(target, &[0x74, 0x20, 0x90, 0x90, 0x90], &[]).unwrap();
        assert!(matches!(
            generate(&analysis, arena, target + 0x40, &[], &[], false, None),
            Err(Error::NoNearbyMemory)
        ));

        // The same prologue relocates cleanly when the arena is in range, so
        // the rejection above is about reach and not about the instruction.
        let near = generate(
            &analysis,
            target + 0x2000,
            target + 0x40,
            &[],
            &[],
            false,
            None,
        )
        .expect("a reachable arena keeps the branch encodable");
        assert_eq!(near.patch.len(), analysis.original.len());
    }

    #[test]
    fn preserves_endbr_and_rejects_stolen_call() {
        let mut entry = expected_endbr().to_vec();
        entry.extend_from_slice(&[0x55, 0x48, 0x89, 0xe5, 0x90]);
        let analysis = analyze(0x1000, &entry, &[]).unwrap();
        assert_eq!(analysis.patch_address, 0x1004);
        assert!(matches!(
            analyze(0x1000, &[0xe8, 0, 0, 0, 0], &[]),
            Err(Error::UnsupportedInstruction { .. })
        ));
    }

    #[test]
    fn entry_window_covers_endbr_and_a_maximum_length_instruction() {
        let mut entry = expected_endbr().to_vec();
        entry.extend_from_slice(&[0x90; 4]);
        entry.extend_from_slice(&[0x66; 14]);
        entry.push(0x90);
        assert_eq!(entry.len(), WINDOW_LENGTH);
        assert_eq!(analyze(0x1000, &entry, &[]).unwrap().original.len(), 19);
    }

    #[test]
    fn rejects_x87_with_and_without_wait() {
        for entry in [
            &[0xd9, 0xee, 0x90, 0x90, 0x90][..],
            &[0x9b, 0xdb, 0xe3, 0x90, 0x90][..],
        ] {
            assert!(matches!(
                analyze(0x1000, entry, &[]),
                Err(Error::UnsupportedInstruction { .. })
            ));
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn rejects_rip_relative_access_crossing_stolen_code() {
        assert!(matches!(
            analyze(0x1000, &[0x48, 0x8b, 0x05, 0xf5, 0xff, 0xff, 0xff], &[],),
            Err(Error::UnsupportedInstruction { .. })
        ));
        assert!(matches!(
            analyze(0x1000, &[0x0f, 0xae, 0x25, 0xf5, 0xff, 0xff, 0xff], &[],),
            Err(Error::UnsupportedInstruction { .. })
        ));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn accepts_rip_relative_operands_that_do_not_access_memory() {
        assert!(analyze(0x1000, &[0x48, 0x8d, 0x05, 0xf5, 0xff, 0xff, 0xff], &[]).is_ok());
        assert!(analyze(0x1000, &[0x0f, 0x1f, 0x05, 0xf6, 0xff, 0xff, 0xff], &[]).is_ok());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn rejects_rip_relative_address_into_stolen_code() {
        // lea rax, [rip - 2]: the produced address is entry + 5.
        assert!(matches!(
            analyze(0x1000, &[0x48, 0x8d, 0x05, 0xfe, 0xff, 0xff, 0xff], &[],),
            Err(Error::UnsupportedInstruction { .. })
        ));
    }

    #[test]
    fn rejects_system_transitions_and_traps() {
        for entry in [
            &[0x0f, 0x05, 0x90, 0x90, 0x90][..],
            &[0xff, 0xd0, 0x90, 0x90, 0x90][..],
            &[0x0f, 0x01, 0xc1, 0x90, 0x90][..],
            &[0xcc, 0x90, 0x90, 0x90, 0x90][..],
            &[0x0f, 0x0b, 0x90, 0x90, 0x90][..],
            &[0xcf, 0x90, 0x90, 0x90, 0x90][..],
            &[0x0f, 0xaa, 0x90, 0x90, 0x90][..],
            &[0xcb, 0x90, 0x90, 0x90, 0x90][..],
        ] {
            assert!(
                matches!(
                    analyze(0x1000, entry, &[]),
                    Err(Error::UnsupportedInstruction { .. })
                ),
                "accepted {entry:02x?}"
            );
        }
        // A near `ret` is relocatable, unlike `retf`/`iret`, but only when the
        // entry is long enough to hold the patch without stealing past it.
        assert!(analyze(0x1000, &[0x55, 0x48, 0x89, 0xe5, 0xc3], &[]).is_ok());
        assert!(matches!(
            analyze(0x1000, &[0xc3, 0x90, 0x90, 0x90, 0x90], &[]),
            Err(Error::UnsupportedInstruction { .. })
        ));
    }

    #[test]
    fn trampoline_starts_with_endbr_and_patch_covers_whole_instructions() {
        let analysis = analyze(0x1000, &[0x55, 0x48, 0x89, 0xe5, 0x90], &[]).unwrap();
        let generated = generate(&analysis, 0x2000, 0x3000, &[], &[], false, None).unwrap();
        assert_eq!(generated.patch.len(), analysis.original.len());
        assert_eq!(
            &generated.bytes[generated.original - 0x2000..][..4],
            expected_endbr()
        );
        assert_eq!(
            &generated.bytes[generated.original - 0x2000 + expected_endbr().len()..]
                [..analysis.original.len()],
            analysis.original
        );
    }
}

use super::patch;
use super::{Arena, Generated, TransientBytes};
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
}

impl Drop for Analysis {
    fn drop(&mut self) {
        crate::sys::erase_bytes(&mut self.original);
    }
}

pub(super) fn analyze(target: usize, code: &[u8]) -> Result<Analysis> {
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
        if matches!(
            flow,
            FlowControl::Call
                | FlowControl::IndirectCall
                | FlowControl::Interrupt
                | FlowControl::Exception
        ) || (flow == FlowControl::Return && instruction.mnemonic() != Mnemonic::Ret)
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
    if stolen < PATCH_LENGTH {
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
        if let Some(target) = near_branch_target(instruction)
            && (patch_address..end).contains(&target)
            && !instructions
                .iter()
                .any(|instruction| instruction.ip() as usize == target)
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
    })
}

pub(super) const fn max_distance(_: &Analysis) -> usize {
    MAX_DISTANCE
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
        let relay_destination = u64::from_le_bytes(relay[6..14].try_into().unwrap()) as usize;
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
        Ok(relay[..2] == [0xff, 0x25]
            && u32::from_le_bytes(relay[2..6].try_into().unwrap()) as usize
                == destination.saturating_add(6)
            && u32::from_le_bytes(relay[6..10].try_into().unwrap()) as usize == replacement)
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
    #[cfg(target_arch = "x86_64")]
    let direct_patch = match relative_jump(analysis.patch_address, replacement) {
        Ok(patch) => Some(patch),
        Err(Error::NoNearbyMemory) => None,
        Err(error) => return Err(error),
    };
    #[cfg(target_arch = "x86")]
    let direct_patch: Option<[u8; PATCH_LENGTH]> = None;
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
        if analysis.instructions.iter().all(|instruction| {
            near_branch_target(instruction).is_none() && !instruction.is_ip_rel_memory_operand()
        }) {
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
            Some(patch) => patch.to_vec(),
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
        if let Err(error) = unsafe { bridge.unmap() } {
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
    _allow_bridge: bool,
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
        } else if !_allow_bridge {
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
                    _mem.map(|fd| (libc::PROT_READ | libc::PROT_EXEC, fd)),
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
                if let Err(unmap_error) = unsafe { bridge.unmap() } {
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
        if !landing && !_allow_bridge {
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
                    _mem.map(|fd| (libc::PROT_READ | libc::PROT_EXEC, fd)),
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
                if let Err(unmap_error) = unsafe { bridge.unmap() } {
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
        let analysis = analyze(0x1000, &[0x48, 0x8d, 0x05, 0, 0, 0, 0]).unwrap();
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
        let analysis = analyze(target, &[0x55, 0x48, 0x89, 0xe5, 0x90]).unwrap();
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
        let analysis = analyze(target, &[0x74, 0x20, 0x90, 0x90, 0x90]).unwrap();
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
        let analysis = analyze(0x1000, &entry).unwrap();
        assert_eq!(analysis.patch_address, 0x1004);
        assert!(matches!(
            analyze(0x1000, &[0xe8, 0, 0, 0, 0]),
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
        assert_eq!(analyze(0x1000, &entry).unwrap().original.len(), 19);
    }

    #[test]
    fn rejects_x87_with_and_without_wait() {
        for entry in [
            &[0xd9, 0xee, 0x90, 0x90, 0x90][..],
            &[0x9b, 0xdb, 0xe3, 0x90, 0x90][..],
        ] {
            assert!(matches!(
                analyze(0x1000, entry),
                Err(Error::UnsupportedInstruction { .. })
            ));
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn rejects_rip_relative_access_crossing_stolen_code() {
        assert!(matches!(
            analyze(0x1000, &[0x48, 0x8b, 0x05, 0xf5, 0xff, 0xff, 0xff]),
            Err(Error::UnsupportedInstruction { .. })
        ));
        assert!(matches!(
            analyze(0x1000, &[0x0f, 0xae, 0x25, 0xf5, 0xff, 0xff, 0xff]),
            Err(Error::UnsupportedInstruction { .. })
        ));
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn accepts_rip_relative_operands_that_do_not_access_memory() {
        assert!(analyze(0x1000, &[0x48, 0x8d, 0x05, 0xf5, 0xff, 0xff, 0xff]).is_ok());
        assert!(analyze(0x1000, &[0x0f, 0x1f, 0x05, 0xf6, 0xff, 0xff, 0xff]).is_ok());
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn rejects_rip_relative_address_into_stolen_code() {
        // lea rax, [rip - 2]: the produced address is entry + 5.
        assert!(matches!(
            analyze(0x1000, &[0x48, 0x8d, 0x05, 0xfe, 0xff, 0xff, 0xff]),
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
                    analyze(0x1000, entry),
                    Err(Error::UnsupportedInstruction { .. })
                ),
                "accepted {entry:02x?}"
            );
        }
        // A near `ret` is relocatable, unlike `retf`/`iret`, but only when the
        // entry is long enough to hold the patch without stealing past it.
        assert!(analyze(0x1000, &[0x55, 0x48, 0x89, 0xe5, 0xc3]).is_ok());
        for entry in [
            &[0xc3, 0x90, 0x90, 0x90, 0x90][..],
            &[0xeb, 0x0e, 0x90, 0x90, 0x90][..],
            &[0xff, 0xe0, 0x90, 0x90, 0x90][..],
        ] {
            assert!(
                matches!(
                    analyze(0x1000, entry),
                    Err(Error::UnsupportedInstruction { .. })
                ),
                "stole past the terminator in {entry:02x?}"
            );
        }
    }

    #[test]
    fn trampoline_starts_with_endbr_and_patch_covers_whole_instructions() {
        let analysis = analyze(0x1000, &[0x55, 0x48, 0x89, 0xe5, 0x90]).unwrap();
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

# Platform Support

## Operating systems

Linux and Android only. Any other target fails at compile time:

```text
error: Oh My Hook supports only Linux and Android
```

The compatibility envelope is Android 12 through 17, common Linux
distributions, and Linux kernels 4.14 through 6.18 and newer LTS kernels.
Reaching outside that envelope is unsupported, not merely untested.

## Architectures

| Architecture | PLT hooks | Inline hooks |
| --- | --- | --- |
| `x86_64` | Yes | Yes |
| `i686` | Yes | Yes |
| `aarch64` | Yes | Yes |
| `arm` (armv7+) | Yes | Yes |
| `arm` (pre-armv7) | Yes | No — disable the `inline` feature |

Little-endian only, and the pointer width must match the architecture. Both
constraints are compile-time errors rather than runtime surprises.

On arm32, inline hooks need `MOVW`/`MOVT`, so an `armv7` or `thumbv7neon`
target is required. This is enforced by target-triple prefix (`armv7-*` or
`thumbv7neon-*`), not by `target_feature`, so a custom `arm-*` triple is
rejected even when it enables `+v7`. The build script detects this and emits a
clear error for older targets:

```text
error: ARM inline hooks require an armv7 or thumbv7neon target;
       disable the `inline` feature on older ARM targets
```

## Architecture-specific behavior

**x86 / x86_64.** Entries are decoded with `iced-x86`. RIP-relative operands
are re-encoded at the trampoline address, and an entry is refused if the
displacement will not fit. `ENDBR64` landing pads are preserved so a patched
entry stays a valid indirect-branch target under CET. On x86-64, `GLOB_DAT`
and `JUMP_SLOT` relocations with a non-zero explicit addend are rejected: the
ABI stores `S + A`, and an exact hook replacement cannot silently drop `A`.
For PLT hooks, a replacement's own landing-pad validity under CET IBT remains
the caller's responsibility.

**AArch64.** One instruction is stolen, exactly matching the patch size, so
over-stealing is structurally impossible. `ADRP`/`ADR` page-relative immediates
are recomputed for the trampoline's page, and branch range limits are checked.
PAC-PLT slots are verified before selection and returned with the PAC stripped.
BTI is detected through `AT_HWCAP2` and preserved. A PLT replacement on a
BTI-guarded page must begin with `bti jc`: the slot can be reached through
`br x17`, `blr`, or another indirect branch. Plain `bti` rejects all non-zero
branch types, `bti c` rejects a guarded-page `br` through another register,
and `bti j` rejects `blr`; other entries are rejected.

**arm32.** Both A32 and Thumb-2 are handled, including the mode bit in target
and replacement addresses. PC-relative reads use the correct architectural bias
(instruction + 8 for A32, aligned instruction + 4 for Thumb), and literal pools
are emitted after the relocated code with correctly signed offsets.

After a successful inline removal, a restored private file-backed page keeps
its private copy. This avoids validating a stale pathname and silently skipping
file-read or `madvise` failures.

## Page size

Page size is read from `sysconf(_SC_PAGESIZE)` at runtime and required to be a
power of two; no runtime page-size decision hardcodes 4096. AArch64 systems
with 16 KiB or 64 KiB pages work, and the larger page only widens the
[quiescence window](safety-quiescence.md) for inline hooks.

One fixed 4096 remains by architecture, not by choice: the AArch64 `ADRP`
instruction's immediate encodes a 4 KiB architectural page regardless of the
kernel's page size. Relocating `ADRP` uses that ISA granularity, which is
correct on 4 KiB, 16 KiB, and 64 KiB systems alike.

## Android specifics

**Packed relocations.** `DT_ANDROID_REL` and `DT_ANDROID_RELA` (APS2) tables
are decoded, including the trailing zero padding `lld` appends so a packed
section never shrinks between layout iterations. Plain `DT_RELR` /
`SHT_ANDROID_RELR` tables are intentionally not decoded: they encode only
relative relocations without a symbol index, so they never name a slot this
library can hook.

**Symbol-table size tag.** The dynamic symbol-count fallback accepts the
generic `DT_SYMTABSZ` tag `39`, which is a linker proposal rather than an
Android or glibc standard assignment. When the tag is absent, SysV and GNU
hash tables remain the authoritative sources.

**Static executables.** PLT discovery requires a `PT_DYNAMIC` segment and a
loader-registered image, so fully static executables without dynamic metadata
report a target or ELF error rather than a distinct diagnostic. Inline hooks
do not depend on `Target` or the loader and still work on such binaries.

**Executable memory.** Inline hooks allocate an anonymous executable arena.
SELinux policy can deny this in some domains; allocation failure is reported as
a system-call error rather than being papered over.

**PIE.** Bionic has required position-independent executables since API 21, so
image discovery assumes ELF images the platform can actually load.

## Verification status

Non-tag CI runs formatting, clippy, unit tests, and doctests on x86_64 and
arm64 Linux. Tags also run tests on i686 and armv7 Linux via qemu-system, and
clippy on the four Android ABIs.

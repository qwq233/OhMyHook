use std::fmt;
use std::io;
use syscalls::Errno;

/// Error returned by this crate.
///
/// PLT hook installers return operation-wide failures directly. Batch PLT
/// installation, when enabled, keeps hook-specific errors in its aligned
/// report.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// An operating-system I/O operation failed.
    Io(io::Error),
    /// `/proc/<pid>/maps` contained an entry that could not be parsed.
    InvalidMapsLine(Vec<u8>),
    /// `/proc/self/smaps` did not describe mapping protection state
    /// unambiguously.
    ///
    /// The message is diagnostic text, not a stable matching key.
    InvalidSmaps(&'static str),
    /// A target mapping is not backed by a file inode.
    #[cfg(feature = "plt")]
    TargetNotFileBacked,
    /// An archive member has a zero byte size.
    #[cfg(feature = "plt")]
    EmptyArchiveMember,
    /// A requested dynamic symbol name is empty.
    #[cfg(feature = "plt")]
    EmptySymbol,
    /// A requested GNU symbol version name is empty.
    #[cfg(feature = "plt")]
    EmptySymbolVersion,
    /// A replacement pointer is null.
    NullReplacement,
    /// An inline target pointer is null.
    #[cfg(feature = "inline")]
    NullTarget,
    /// An inline request or replacement violates an ABI entry constraint.
    ///
    /// The message is diagnostic text, not a stable matching key.
    #[cfg(feature = "inline")]
    InvalidInlineTarget(&'static str),
    /// An instruction cannot be relocated without changing observable
    /// behavior.
    #[cfg(feature = "inline")]
    UnsupportedInstruction {
        /// Address of the rejected instruction.
        address: usize,
        /// Diagnostic rejection reason.
        reason: &'static str,
    },
    /// No usable executable arena was found within branch range.
    ///
    /// This covers two causes that the search cannot tell apart, because both
    /// depend on the address an arena lands at: no free page was reachable at
    /// all, and every reachable page left some relocated prologue branch out of
    /// range. Widening the search cannot distinguish them either, so the report
    /// names the outcome rather than guessing the cause. The result is
    /// deterministic for one address-space layout: retrying the same target in
    /// the same process is useful only after the caller changes that layout.
    #[cfg(feature = "inline")]
    NoNearbyMemory,
    /// A deterministic near-target arena could not be reserved.
    #[cfg(feature = "inline")]
    InlineArenaPlacement {
        /// target whose nearby window was searched.
        target: usize,
        /// Maximum distance that was considered.
        distance: usize,
    },
    /// A relocated instruction needs a larger range than the arena provides.
    #[cfg(feature = "inline")]
    InlineRelocationRange {
        /// Address of the instruction that could not be re-encoded.
        instruction: usize,
        /// Range limit that was exceeded.
        distance: usize,
    },
    /// A requested exact slot count is zero.
    #[cfg(feature = "plt")]
    InvalidSlotCount,
    /// An internal installation result violated its validated batch shape.
    #[cfg(feature = "plt")]
    InternalInstallState(&'static str),
    /// A request required its image selector bound to one exact loaded image.
    #[cfg(feature = "plt")]
    BoundImageRequired,
    /// An inspected slot selector's image or relocation metadata does not
    /// match the request or the fresh ELF scan. A changed slot value is
    /// [`Error::Conflict`].
    #[cfg(feature = "plt")]
    SlotSelectorMismatch,
    /// An ELF structure was malformed or inconsistent.
    ///
    /// The message is diagnostic text, not a stable matching key.
    #[cfg(feature = "plt")]
    InvalidElf(&'static str),
    /// An address, offset, table size, or index overflowed.
    ArithmeticOverflow,
    /// The loaded ELF class is not supported.
    #[cfg(feature = "plt")]
    UnsupportedElfClass(u8),
    /// The loaded ELF byte order is not supported.
    #[cfg(feature = "plt")]
    UnsupportedEndian(u8),
    /// The ELF machine does not match the current process ABI.
    #[cfg(feature = "plt")]
    MachineMismatch {
        /// Machine identifier required by the current Rust target.
        expected: u16,
        /// Machine identifier read from the loaded ELF image.
        actual: u16,
    },
    /// A platform or ELF feature cannot be hooked safely.
    ///
    /// The feature description is diagnostic text, not a stable matching key.
    UnsupportedFeature(&'static str),
    /// A mutation path failed, with the errno of every path this call tried.
    ///
    /// `Some` means that path was attempted and failed with that error; `None`
    /// means it was not attempted, typically because the request pinned another
    /// path. This is the only stable way to tell a policy denial
    /// (`EPERM`/`EACCES`) from a resource failure (`EMFILE`/`ENFILE`).
    #[non_exhaustive]
    MutationPathUnavailable {
        /// `/proc/self/mem` open, write, or verification error.
        forced_access: Option<Errno>,
        /// Error from adding `PROT_WRITE` while keeping `PROT_EXEC`.
        protection_keeping_exec: Option<Errno>,
        /// Error from the path that removes `PROT_EXEC` before writing.
        protection: Option<Errno>,
    },
    /// A stolen instruction's address result is dereferenced back into the
    /// overwritten entry bytes, which an inline hook cannot preserve.
    #[cfg(feature = "inline")]
    InlineDataReference {
        /// Address of the instruction that reads the overwritten bytes.
        instruction: usize,
        /// Effective address it reads inside the overwritten range.
        address: usize,
    },
    /// No currently loaded image matches the selector.
    #[cfg(feature = "plt")]
    TargetNotLoaded,
    /// A request requiring a unique match selected multiple loaded images.
    #[cfg(feature = "plt")]
    MultipleLoadedImages {
        /// Number of loaded images selected by the image selector.
        actual: usize,
    },
    /// The requested query produced no supported dynamic relocation.
    #[cfg(feature = "plt")]
    NoMatchingRelocation,
    /// A request selected a different non-zero slot count than the caller required.
    #[cfg(feature = "plt")]
    UnexpectedSlotCount {
        /// Required exact slot count.
        expected: usize,
        /// Selected slot count found during preflight.
        actual: usize,
    },
    /// One request's matching relocation slots have different previous pointers.
    #[cfg(feature = "plt")]
    AmbiguousPreviousPointer,
    /// Hooks overlap, a target already contains its replacement, or a
    /// competing writer changed memory after preflight.
    Conflict,
    /// A request required a non-null previous pointer but resolved null.
    #[cfg(feature = "plt")]
    NullPreviousPointer,
    /// Hooks sharing an `OriginalPointerCell` resolved different originals,
    /// or disagreed with its already published value.
    #[cfg(feature = "plt")]
    OriginalPointerCellConflict,
    /// A required hook group had no present installable candidate.
    #[cfg(feature = "plt")]
    RequiredGroupMissing,
    /// The target mapping changed while it was being inspected or modified.
    MappingChanged,
    /// The final selected mutation exceeded an operation-wide hard limit.
    #[cfg(feature = "plt")]
    MutationBudgetExceeded {
        /// Loaded images containing at least one selected slot.
        images: usize,
        /// Unique selected relocation slots.
        slots: usize,
        /// Unique pages containing selected slots, including writable pages.
        pages: usize,
        /// Maximum permitted image count.
        max_images: usize,
        /// Maximum permitted slot count.
        max_slots: usize,
        /// Maximum permitted page count.
        max_pages: usize,
    },
    /// An ELF read fell outside the readable mappings captured for the image.
    #[cfg(feature = "plt")]
    UnmappedRead {
        /// First address that could not be read safely.
        address: usize,
        /// Number of bytes requested from that address.
        length: usize,
    },
    /// A Linux or Android memory-management operation failed.
    SystemCall {
        /// Name of the failed operation.
        operation: &'static str,
        /// Operating-system error returned by the kernel.
        source: Errno,
    },
    /// Cleanup after an inline operation could not release an executable arena.
    ///
    /// For a removal, the target is restored, its handle is no longer
    /// installed, and retrying removal releases only the remaining arenas.
    /// An unpublished prepared batch whose arena could not be unmapped reports
    /// this error with no target changed; that path consumes the only ownership
    /// record, so the mapping stays live for the rest of the process. This is
    /// not the only inline error that can report a restored removal target:
    /// see [`Error::InlineCleanupComposite`] and
    /// [`Error::TargetPagesMayBeWritable`].
    #[cfg(feature = "inline")]
    InlineCleanupPending(Errno),
    /// An inline operation encountered multiple failures.
    ///
    /// `source` is the primary failure; `cleanup` is the later executable-arena
    /// or descriptor cleanup failure. Preparation and discard leave target
    /// bytes unchanged; a completed removal restores them and marks its handles
    /// removed. Consult `source` and the handle state for any remaining page
    /// protection failure.
    #[cfg(feature = "inline")]
    InlineCleanupComposite {
        /// Primary operation failure.
        source: Box<Error>,
        /// Additional executable-arena or descriptor cleanup failure.
        cleanup: Box<Error>,
    },
    /// An operation was undone, and its forced-access descriptor could not be
    /// closed afterwards.
    ///
    /// Every target holds exactly the bytes it held before the call: an
    /// installation left them unpatched, a removal left them **patched**. The
    /// handle's state is therefore unchanged and the call can be retried. Only
    /// a file descriptor leaked.
    ///
    /// This is deliberately not [`Error::InlineCleanupPending`], which reports
    /// completed cleanup-only work after a removal.
    #[cfg(feature = "inline")]
    ForcedMutationRolledBackWithCloseError,
    /// A rollback puts every target byte back, but could not return a target
    /// page to its captured protection.
    ///
    /// "Back" means the state from before the call: an installation leaves the
    /// request unpatched, a removal leaves it **patched** and its handle still
    /// installed.
    ///
    /// The page is left writable and **not executable**, so every function on
    /// it faults when called, including functions this crate never touched.
    /// Nothing in this process can repair it, and no retry can succeed while
    /// the page stays non-executable. Stop using that hook for the rest of
    /// this process or terminate: the fault surfaces at an arbitrary later
    /// call, and no retry can repair the page.
    ///
    /// Only the first such page is named. If the operation covered several
    /// pages, any other page that failed the same way is in the same state.
    #[cfg(feature = "inline")]
    TargetPageProtectionLost {
        /// First address of the page whose protection could not be restored.
        address: usize,
        /// Length in bytes of that page.
        length: usize,
        /// Operating-system error from the final restore attempt.
        source: Errno,
    },
    /// At least one target page stayed executable and writable because its
    /// captured protection could not be restored.
    ///
    /// Verify or restore every listed page while upholding the operation's
    /// mapping lifetime, whole-page quiescence and writer-exclusion contract.
    /// Some listed pages may already have their original protection.
    /// A successful installation reports this state through
    /// `InlineInstallCleanupStatus::PagesMayBeWritable` instead.
    #[cfg(feature = "inline")]
    TargetPagesMayBeWritable {
        /// Complete, deduplicated set of pages involved in this mutation.
        pages: std::sync::Arc<[crate::InlinePageProtection]>,
        /// Whether target bytes returned to their pre-call state. When true,
        /// removal handles remain installed and a commit remains prepared.
        /// When false, removal completed and handles are no longer installed.
        rolled_back: bool,
        /// Operating-system error from the first failed protection restore.
        source: Errno,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::InvalidMapsLine(line) => {
                write!(
                    f,
                    "invalid /proc maps line: {}",
                    String::from_utf8_lossy(line)
                )
            }
            Self::InvalidSmaps(message) => write!(f, "invalid /proc/self/smaps: {message}"),
            #[cfg(feature = "plt")]
            Self::TargetNotFileBacked => f.write_str("target is not backed by a file inode"),
            #[cfg(feature = "plt")]
            Self::EmptyArchiveMember => f.write_str("archive member size is zero"),
            #[cfg(feature = "plt")]
            Self::EmptySymbol => f.write_str("symbol name is empty"),
            #[cfg(feature = "plt")]
            Self::EmptySymbolVersion => f.write_str("symbol version name is empty"),
            Self::NullReplacement => f.write_str("replacement pointer is null"),
            #[cfg(feature = "inline")]
            Self::NullTarget => f.write_str("inline target pointer is null"),
            #[cfg(feature = "inline")]
            Self::InvalidInlineTarget(message) => {
                write!(f, "invalid inline request: {message}")
            }
            #[cfg(feature = "inline")]
            Self::UnsupportedInstruction { address, reason } => {
                write!(f, "unsupported instruction at {address:#x}: {reason}")
            }
            #[cfg(feature = "inline")]
            Self::NoNearbyMemory => f.write_str(
                "no reachable executable arena could host the relocated entry within branch range",
            ),
            #[cfg(feature = "inline")]
            Self::InlineArenaPlacement { target, distance } => write!(
                f,
                "inline arena placement failed near {target:#x} within {distance} bytes"
            ),
            #[cfg(feature = "inline")]
            Self::InlineRelocationRange {
                instruction,
                distance,
            } => write!(
                f,
                "inline relocation at {instruction:#x} exceeds {distance} bytes"
            ),
            #[cfg(feature = "plt")]
            Self::InvalidSlotCount => f.write_str("expected slot count is zero"),
            #[cfg(feature = "plt")]
            Self::InternalInstallState(reason) => {
                write!(f, "internal install state error: {reason}")
            }
            #[cfg(feature = "plt")]
            Self::BoundImageRequired => f.write_str("request requires a bound loaded image"),
            #[cfg(feature = "plt")]
            Self::SlotSelectorMismatch => f.write_str(
                "inspected slot selector does not match the request or the current image",
            ),
            #[cfg(feature = "plt")]
            Self::InvalidElf(message) => write!(f, "invalid ELF image: {message}"),
            Self::ArithmeticOverflow => f.write_str("address or size arithmetic overflow"),
            #[cfg(feature = "plt")]
            Self::UnsupportedElfClass(class) => write!(f, "unsupported ELF class: {class}"),
            #[cfg(feature = "plt")]
            Self::UnsupportedEndian(endian) => write!(f, "unsupported ELF byte order: {endian}"),
            #[cfg(feature = "plt")]
            Self::MachineMismatch { expected, actual } => {
                write!(
                    f,
                    "ELF machine mismatch: expected {expected}, found {actual}"
                )
            }
            Self::UnsupportedFeature(feature) => write!(f, "unsupported feature: {feature}"),
            Self::MutationPathUnavailable {
                forced_access,
                protection_keeping_exec,
                protection,
            } => {
                write!(f, "mutation path unavailable")?;
                if let Some(error) = forced_access {
                    write!(f, "; forced_access: {error}")?;
                }
                if let Some(error) = protection_keeping_exec {
                    write!(f, "; protection_keeping_exec: {error}")?;
                }
                if let Some(error) = protection {
                    write!(f, "; protection: {error}")?;
                }
                Ok(())
            }
            #[cfg(feature = "inline")]
            Self::InlineDataReference {
                instruction,
                address,
            } => write!(
                f,
                "instruction at {instruction:#x} reads the overwritten bytes at {address:#x}"
            ),
            #[cfg(feature = "plt")]
            Self::TargetNotLoaded => f.write_str("request has no currently loaded image"),
            #[cfg(feature = "plt")]
            Self::MultipleLoadedImages { actual } => write!(
                f,
                "request selected {actual} loaded images, expected exactly one"
            ),
            #[cfg(feature = "plt")]
            Self::NoMatchingRelocation => f.write_str("query has no supported dynamic relocation"),
            #[cfg(feature = "plt")]
            Self::UnexpectedSlotCount { expected, actual } => write!(
                f,
                "request selected {actual} relocation slot(s), expected exactly {expected}"
            ),
            #[cfg(feature = "plt")]
            Self::AmbiguousPreviousPointer => {
                f.write_str("hooked relocation slots have different previous pointers")
            }
            #[cfg(feature = "plt")]
            Self::NullPreviousPointer => {
                f.write_str("hooked relocation slots have a null previous pointer")
            }
            Self::Conflict => f.write_str("hook request conflicts with another hook or writer"),
            #[cfg(feature = "plt")]
            Self::OriginalPointerCellConflict => {
                f.write_str("shared original slot has conflicting resolved pointers")
            }
            #[cfg(feature = "plt")]
            Self::RequiredGroupMissing => {
                f.write_str("required hook group has no installable candidate")
            }
            Self::MappingChanged => f.write_str("target mapping changed during the operation"),
            #[cfg(feature = "plt")]
            Self::MutationBudgetExceeded {
                images,
                slots,
                pages,
                max_images,
                max_slots,
                max_pages,
            } => write!(
                f,
                "mutation budget exceeded: images={images}/{max_images}, slots={slots}/{max_slots}, pages={pages}/{max_pages}"
            ),
            #[cfg(feature = "plt")]
            Self::UnmappedRead { address, length } => write!(
                f,
                "ELF read at {address:#x} for {length} byte(s) is not mapped readable"
            ),
            Self::SystemCall { operation, source } => {
                write!(f, "{operation} failed: {source}")
            }
            #[cfg(feature = "inline")]
            Self::InlineCleanupPending(source) => {
                write!(f, "inline cleanup left executable arenas mapped: {source}")
            }
            #[cfg(feature = "inline")]
            Self::InlineCleanupComposite { source, cleanup } => write!(
                f,
                "inline operation and cleanup failed: {source}; cleanup: {cleanup}"
            ),
            #[cfg(feature = "inline")]
            Self::ForcedMutationRolledBackWithCloseError => f.write_str(
                "inline operation undone, but the forced-access descriptor could not be closed",
            ),
            #[cfg(feature = "inline")]
            Self::TargetPageProtectionLost {
                address,
                length,
                source,
            } => write!(
                f,
                "target bytes restored but page {address:#x}+{length:#x} is non-executable and must not be used again: {source}"
            ),
            #[cfg(feature = "inline")]
            Self::TargetPagesMayBeWritable {
                pages,
                rolled_back,
                source,
            } => write!(
                f,
                "inline mutation {} but {} target pages require protection verification or repair: {source}",
                if *rolled_back {
                    "rolled back"
                } else {
                    "completed"
                },
                pages.len()
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::SystemCall { source: error, .. } => Some(error),
            Self::MutationPathUnavailable {
                forced_access,
                protection_keeping_exec,
                protection,
            } => forced_access
                .as_ref()
                .or(protection_keeping_exec.as_ref())
                .or(protection.as_ref())
                .map(|error| error as &(dyn std::error::Error + 'static)),
            #[cfg(feature = "inline")]
            Self::InlineCleanupPending(error) => Some(error),
            #[cfg(feature = "inline")]
            Self::InlineCleanupComposite { source, .. } => Some(source),
            #[cfg(feature = "inline")]
            Self::TargetPageProtectionLost { source, .. } => Some(source),
            #[cfg(feature = "inline")]
            Self::TargetPagesMayBeWritable { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl Error {
    /// Builds a system-call error.
    ///
    /// Mutation-window callers capture the failing operation and errno as
    /// `Copy` values first and construct this error only after every page
    /// protection has been restored.
    pub(crate) fn system_call(operation: &'static str, errno: Errno) -> Self {
        Self::SystemCall {
            operation,
            source: errno,
        }
    }
}

/// Returns the raw error code represented by an [`Errno`].
///
/// `Errno` is re-exported by this crate, so callers never need to add or import
/// the `syscalls` crate to inspect a public error field.
pub fn errno_code(errno: Errno) -> i32 {
    errno.into_raw()
}

/// Result type used by this crate.
pub type Result<T> = std::result::Result<T, Error>;

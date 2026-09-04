use std::fmt;
use std::io;

/// Error returned by this crate.
///
/// Hook installers return operation-wide failures directly. Batch PLT
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
    /// An inline-hook target pointer is null.
    #[cfg(feature = "inline")]
    NullTarget,
    /// An inline-hook target or replacement violates an ABI entry constraint.
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
    /// names the outcome rather than guessing the cause.
    #[cfg(feature = "inline")]
    NoNearbyMemory,
    /// A requested exact slot count is zero.
    #[cfg(feature = "plt")]
    InvalidSlotCount,
    /// An internal installation result violated its validated batch shape.
    #[cfg(feature = "plt")]
    InternalInstallState(&'static str),
    /// A Hook required a selector bound to one exact loaded image.
    #[cfg(feature = "plt")]
    ExactImageRequired,
    /// An inspected slot selector's image or relocation metadata does not
    /// match the Hook or current ELF scan. A changed slot value is
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
    /// A stolen instruction's address result is dereferenced back into the
    /// overwritten entry bytes, which an inline hook cannot preserve.
    #[cfg(feature = "inline")]
    InlineDataReference {
        /// Address of the instruction that reads the overwritten bytes.
        instruction: usize,
        /// Effective address it reads inside the overwritten range.
        address: usize,
    },
    /// No currently loaded image matches the requested target selector.
    #[cfg(feature = "plt")]
    TargetNotLoaded,
    /// A Hook requiring a unique match selected multiple loaded images.
    #[cfg(feature = "plt")]
    MultipleLoadedImages {
        /// Number of loaded images selected by the Target.
        actual: usize,
    },
    /// The requested symbol has no supported dynamic relocation in the target.
    #[cfg(feature = "plt")]
    SymbolNotFound,
    /// A Hook selected a different non-zero slot count than the caller required.
    #[cfg(feature = "plt")]
    UnexpectedSlotCount {
        /// Required exact slot count.
        expected: usize,
        /// Selected slot count found during preflight.
        actual: usize,
    },
    /// One Hook's matching relocation slots have different previous pointers.
    #[cfg(feature = "plt")]
    AmbiguousPreviousPointer,
    /// Hooks overlap, a target already contains its replacement, or a
    /// competing writer changed memory after preflight.
    Conflict,
    /// A Hook required a non-null previous pointer but resolved null.
    #[cfg(feature = "plt")]
    NullPreviousPointer,
    /// Hooks sharing an `OriginalSlot` resolved different originals,
    /// or disagreed with its already published value.
    #[cfg(feature = "plt")]
    OriginalSlotConflict,
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
        source: io::Error,
    },
    /// A removal restored its target, but the arenas it owned are still mapped.
    ///
    /// The hook is gone; only an executable mapping leaked. Retrying removal
    /// retries that cleanup and nothing else. This is the one inline error that
    /// reports a target as already restored, which is why it must never be used
    /// for an operation that was undone — see
    /// [`Error::ForcedDescriptorLeaked`].
    #[cfg(feature = "inline")]
    InlineCleanupPending(io::Error),
    /// A completed inline operation encountered more than one cleanup failure.
    ///
    /// `source` is the primary failure; `cleanup` is the later executable-arena
    /// cleanup failure. Every target is already restored.
    #[cfg(feature = "inline")]
    InlineCleanupComposite {
        /// Primary operation failure.
        source: Box<Error>,
        /// Executable-arena cleanup failure.
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
    /// This is deliberately not [`Error::InlineCleanupPending`], which promises
    /// the opposite about a removal.
    #[cfg(feature = "inline")]
    ForcedDescriptorLeaked,
    /// A rollback put every target byte back, but could not return a target
    /// page to its captured protection.
    ///
    /// "Back" means the state from before the call: an installation leaves the
    /// target unpatched, a removal leaves it **patched** and its handle still
    /// installed.
    ///
    /// The page is left writable and **not executable**, so every function on
    /// it faults when called, including functions this crate never touched.
    /// Nothing in this process can repair it, and no retry can succeed while
    /// the page stays non-executable. Abort the process instead of continuing:
    /// letting the fault surface at an arbitrary later call is strictly worse
    /// than stopping here.
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
        source: io::Error,
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
            Self::InvalidInlineTarget(message) => write!(f, "invalid inline target: {message}"),
            #[cfg(feature = "inline")]
            Self::UnsupportedInstruction { address, reason } => {
                write!(f, "unsupported instruction at {address:#x}: {reason}")
            }
            #[cfg(feature = "inline")]
            Self::NoNearbyMemory => f.write_str(
                "no reachable executable arena could host the relocated entry within branch range",
            ),
            #[cfg(feature = "plt")]
            Self::InvalidSlotCount => f.write_str("expected slot count is zero"),
            #[cfg(feature = "plt")]
            Self::InternalInstallState(reason) => {
                write!(f, "internal install state error: {reason}")
            }
            #[cfg(feature = "plt")]
            Self::ExactImageRequired => f.write_str("Hook requires an exact loaded image target"),
            #[cfg(feature = "plt")]
            Self::SlotSelectorMismatch => {
                f.write_str("inspected slot selector does not match the Hook or current image")
            }
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
            #[cfg(feature = "inline")]
            Self::InlineDataReference {
                instruction,
                address,
            } => write!(
                f,
                "instruction at {instruction:#x} reads the overwritten bytes at {address:#x}"
            ),
            #[cfg(feature = "plt")]
            Self::TargetNotLoaded => f.write_str("target has no currently loaded image"),
            #[cfg(feature = "plt")]
            Self::MultipleLoadedImages { actual } => write!(
                f,
                "Hook selected {actual} loaded images, expected exactly one"
            ),
            #[cfg(feature = "plt")]
            Self::SymbolNotFound => f.write_str("symbol has no supported dynamic relocation"),
            #[cfg(feature = "plt")]
            Self::UnexpectedSlotCount { expected, actual } => write!(
                f,
                "Hook selected {actual} relocation slot(s), expected exactly {expected}"
            ),
            #[cfg(feature = "plt")]
            Self::AmbiguousPreviousPointer => {
                f.write_str("hooked relocation slots have different previous pointers")
            }
            #[cfg(feature = "plt")]
            Self::NullPreviousPointer => {
                f.write_str("hooked relocation slots have a null previous pointer")
            }
            Self::Conflict => f.write_str("hook target conflicts with another hook or writer"),
            #[cfg(feature = "plt")]
            Self::OriginalSlotConflict => {
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
                write!(
                    f,
                    "inline target restored but arena cleanup failed: {source}"
                )
            }
            #[cfg(feature = "inline")]
            Self::InlineCleanupComposite { source, cleanup } => write!(
                f,
                "inline target restored but operation and cleanup failed: {source}; cleanup: {cleanup}"
            ),
            #[cfg(feature = "inline")]
            Self::ForcedDescriptorLeaked => f.write_str(
                "inline operation undone, but the forced-access descriptor could not be closed",
            ),
            #[cfg(feature = "inline")]
            Self::TargetPageProtectionLost {
                address,
                length,
                source,
            } => write!(
                f,
                "target bytes restored but page {address:#x}+{length:#x} is stuck non-executable, abort the process: {source}"
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            Self::SystemCall { source: error, .. } => Some(error),
            #[cfg(feature = "inline")]
            Self::InlineCleanupPending(error) => Some(error),
            #[cfg(feature = "inline")]
            Self::InlineCleanupComposite { source, .. } => Some(source),
            #[cfg(feature = "inline")]
            Self::TargetPageProtectionLost { source, .. } => Some(source),
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
    /// Builds a system-call error from a raw errno.
    ///
    /// Mutation-window callers capture the failing operation and errno as
    /// `Copy` values first and construct this error only after every page
    /// protection has been restored.
    pub(crate) fn system_call(operation: &'static str, errno: i32) -> Self {
        Self::SystemCall {
            operation,
            source: io::Error::from_raw_os_error(errno),
        }
    }
}

/// Result type used by this crate.
pub type Result<T> = std::result::Result<T, Error>;

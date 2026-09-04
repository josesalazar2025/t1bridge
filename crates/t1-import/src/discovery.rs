//! Read-only discovery planning for user-controlled Apple machine data.
//!
//! This module separates discovery policy from filesystem and container
//! mechanisms. Callers inspect candidate paths without following links, probe
//! their readers, and describe only the FDR objects and records they found.
//! The resulting plan refers to opaque caller-assigned identifiers, so paths
//! and hardware associations cannot leak through diagnostics or previews.

use std::fmt;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Component, Path};

use crate::archive::{PbzxEncoding, PbzxReader};

/// Maximum number of source candidates considered in one discovery pass.
pub const MAX_CANDIDATES: usize = 64;
/// Maximum supported regular source size.
pub const MAX_SOURCE_SIZE: u64 = 128 * 1024 * 1024 * 1024;
/// Maximum supported `FDRData` object size.
pub const MAX_FDR_DATA_SIZE: u64 = 64 * 1024 * 1024;
/// Maximum supported encoded calibration-record size.
pub const MAX_CALIBRATION_RECORD_SIZE: u64 = 16 * 1024 * 1024;
/// Maximum number of relevant records described for one `FDRData` object.
pub const MAX_RECORDS_PER_FDR: usize = 4_096;
/// Length of the sensor-module association returned by Mesa.
pub const HARDWARE_ASSOCIATION_SIZE: usize = 18;

const BPLIST_MAGIC: &[u8; 8] = b"bplist00";
const XML_MAGIC: &[u8; 5] = b"<?xml";
const PBZX_MAGIC: &[u8; 4] = b"pbzx";
const UDIF_TRAILER_MAGIC: &[u8; 4] = b"koly";
const UDIF_TRAILER_SIZE: u64 = 512;

/// Stable, non-sensitive identifier assigned by the caller to a source.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CandidateId(pub u32);

/// Stable, non-sensitive identifier assigned by the caller to an FDR object.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct FdrId(pub u32);

/// Stable, non-sensitive identifier assigned by the caller to an FDR record.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RecordId(pub u32);

/// How a user obtained a local candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceOrigin {
    /// An existing or preserved Apple EFI filesystem.
    PreservedEfi,
    /// A user-created backup containing `FDRData`.
    Backup,
    /// One local PBZX installer or recovery payload.
    InstallerPayload,
    /// A mounted local Apple disk image.
    MountedDiskImage,
    /// A local Apple disk-image file exposed through a caller-supplied reader.
    DiskImage,
}

impl fmt::Display for SourceOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PreservedEfi => "preserved EFI",
            Self::Backup => "backup",
            Self::InstallerPayload => "installer payload",
            Self::MountedDiskImage => "mounted disk image",
            Self::DiskImage => "disk image",
        })
    }
}

/// File type observed without following the final path component.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntryType {
    RegularFile,
    Directory,
    Symlink,
    Other,
}

/// Read-only security metadata supplied by the filesystem mechanism.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidateMetadata {
    /// Type observed without following the final component.
    pub entry_type: EntryType,
    /// Byte length for a regular file, or zero for a directory.
    pub byte_len: u64,
    /// Whether the invoking process can read/search the candidate.
    pub readable: bool,
    /// Whether ownership was verified as root or the invoking user.
    pub trusted_owner: bool,
    /// Whether any component in the resolved path is a symbolic link.
    pub path_has_symlink: bool,
    /// Unix permission bits, excluding the file-type bits.
    pub mode: u32,
}

/// Content identified by probing a candidate reader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceContent {
    /// A binary or canonical Apple XML property-list `FDRData` object.
    FdrData,
    /// A PBZX installer payload whose relevant chunks are raw.
    InstallerPayloadRaw,
    /// A PBZX installer payload containing at least one XZ chunk.
    InstallerPayloadXz,
    /// An Apple UDIF disk image.
    AppleDiskImage,
    /// A mounted directory; its contents were inventoried by the caller.
    MountedDirectory,
    /// A format this importer does not understand.
    Unknown,
}

/// Probe a bounded regular-file reader for a supported top-level format.
///
/// This recognizes direct binary- or canonical Apple XML-plist `FDRData`, PBZX
/// installer payloads, and
/// Apple UDIF disk images. PBZX streams are fully walked without expanding
/// them so an XZ chunk at any position is classified accurately.
///
/// # Errors
///
/// Returns a redaction-safe error when the declared size is out of bounds or
/// the reader cannot be sought or read. The reader's final position is
/// unspecified.
pub fn probe_reader<R: Read + Seek>(reader: &mut R, byte_len: u64) -> Result<SourceContent, Error> {
    if byte_len == 0 || byte_len > MAX_SOURCE_SIZE {
        return Err(Error::SourceSize {
            candidate: None,
            size: byte_len,
        });
    }

    reader
        .seek(SeekFrom::Start(0))
        .map_err(|error| Error::Reader(error.kind()))?;
    let mut prefix = [0_u8; 8];
    let prefix_len = usize::try_from(byte_len.min(prefix.len() as u64))
        .map_err(|_| Error::Reader(io::ErrorKind::InvalidData))?;
    read_exact_redacted(reader, &mut prefix[..prefix_len])?;

    if (prefix_len >= BPLIST_MAGIC.len() && &prefix == BPLIST_MAGIC)
        || (prefix_len >= XML_MAGIC.len() && &prefix[..XML_MAGIC.len()] == XML_MAGIC)
    {
        return Ok(SourceContent::FdrData);
    }
    if prefix_len >= PBZX_MAGIC.len() && &prefix[..PBZX_MAGIC.len()] == PBZX_MAGIC {
        reader
            .seek(SeekFrom::Start(0))
            .map_err(|error| Error::Reader(error.kind()))?;
        let mut pbzx = PbzxReader::new(reader.take(byte_len)).map_err(|_| Error::MalformedPbzx)?;
        let mut contains_xz = false;
        while let Some(chunk) = pbzx.next_chunk().map_err(|_| Error::MalformedPbzx)? {
            contains_xz |= chunk.header().encoding == PbzxEncoding::Xz;
            chunk.drain().map_err(|_| Error::MalformedPbzx)?;
        }
        return Ok(if contains_xz {
            SourceContent::InstallerPayloadXz
        } else {
            SourceContent::InstallerPayloadRaw
        });
    }
    if byte_len >= UDIF_TRAILER_SIZE {
        reader
            .seek(SeekFrom::Start(byte_len - UDIF_TRAILER_SIZE))
            .map_err(|error| Error::Reader(error.kind()))?;
        let mut trailer_magic = [0_u8; 4];
        read_exact_redacted(reader, &mut trailer_magic)?;
        if trailer_magic == *UDIF_TRAILER_MAGIC {
            return Ok(SourceContent::AppleDiskImage);
        }
    }
    Ok(SourceContent::Unknown)
}

fn read_exact_redacted(reader: &mut impl Read, buffer: &mut [u8]) -> Result<(), Error> {
    reader
        .read_exact(buffer)
        .map_err(|error| Error::Reader(error.kind()))
}

/// One structurally inspected calibration record.
pub struct RecordMetadata<'a> {
    pub id: RecordId,
    /// Association copied from the validated record, never rendered.
    pub hardware_association: &'a [u8],
    pub encoded_size: u64,
    /// Whether the format-specific parser accepted the complete record.
    pub structurally_valid: bool,
}

impl fmt::Debug for RecordMetadata<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordMetadata")
            .field("id", &self.id)
            .field("hardware_association", &"<redacted>")
            .field("encoded_size", &self.encoded_size)
            .field("structurally_valid", &self.structurally_valid)
            .finish()
    }
}

/// One `FDRData` object found directly or inside a container.
pub struct FdrMetadata<'a> {
    pub id: FdrId,
    pub encoded_size: u64,
    /// Whether the property list and Combined-record inventory were valid.
    pub structurally_valid: bool,
    /// Relevant `FSCl` records only; unrelated records need not be retained.
    pub calibration_records: &'a [RecordMetadata<'a>],
}

impl fmt::Debug for FdrMetadata<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FdrMetadata")
            .field("id", &self.id)
            .field("encoded_size", &self.encoded_size)
            .field("structurally_valid", &self.structurally_valid)
            .field("calibration_record_count", &self.calibration_records.len())
            .finish()
    }
}

/// One caller-inspected local source candidate.
pub struct Candidate<'a> {
    pub id: CandidateId,
    /// Raw path used only for safety validation; never retained in a plan.
    pub path: &'a Path,
    pub origin: SourceOrigin,
    pub metadata: CandidateMetadata,
    pub content: SourceContent,
    /// FDR objects found by the caller's direct, archive, mount, or image
    /// reader. Entries are opaque and are not copied during planning.
    pub fdr_objects: &'a [FdrMetadata<'a>],
}

impl fmt::Debug for Candidate<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Candidate")
            .field("id", &self.id)
            .field("path", &"<redacted>")
            .field("origin", &self.origin)
            .field("metadata", &self.metadata)
            .field("content", &self.content)
            .field("fdr_object_count", &self.fdr_objects.len())
            .finish()
    }
}

/// Sensitive hardware association supplied from the live sensor.
pub struct HardwareAssociation<'a>(&'a [u8]);

impl<'a> HardwareAssociation<'a> {
    /// Wrap a live association without copying or rendering it.
    #[must_use]
    pub const fn new(value: &'a [u8]) -> Self {
        Self(value)
    }
}

impl fmt::Debug for HardwareAssociation<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HardwareAssociation(<redacted>)")
    }
}

/// Exact logical access performed by a later importer execution step.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessStep {
    /// Inspect the selected source's already-validated container metadata.
    InspectSource { maximum_bytes: u64 },
    /// Read exactly one selected `FDRData` object.
    ReadFdrData { fdr: FdrId, bytes: u64 },
    /// Copy exactly one selected factory calibration record.
    CopyCalibration { record: RecordId, bytes: u64 },
}

/// A redaction-safe preview suitable for confirmation output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Preview {
    pub candidate: CandidateId,
    pub origin: SourceOrigin,
    pub accesses: [AccessStep; 3],
}

impl fmt::Display for Preview {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [
            AccessStep::InspectSource { maximum_bytes },
            AccessStep::ReadFdrData {
                fdr,
                bytes: fdr_bytes,
            },
            AccessStep::CopyCalibration {
                record,
                bytes: record_bytes,
            },
        ] = self.accesses
        else {
            return formatter.write_str("invalid import preview");
        };
        write!(
            formatter,
            "candidate {} ({}): inspect at most {} source bytes; read FDR object {} ({} bytes); copy calibration record {} ({} bytes); access no other records; use no network",
            self.candidate.0, self.origin, maximum_bytes, fdr.0, fdr_bytes, record.0, record_bytes
        )
    }
}

/// Selected read-only source and minimum associated record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportPlan {
    pub candidate: CandidateId,
    pub origin: SourceOrigin,
    pub fdr: FdrId,
    pub record: RecordId,
    pub source_bytes: u64,
    pub fdr_bytes: u64,
    pub record_bytes: u64,
}

impl ImportPlan {
    /// Return the exact logical accesses without exposing path or association.
    #[must_use]
    pub const fn preview(&self) -> Preview {
        Preview {
            candidate: self.candidate,
            origin: self.origin,
            accesses: [
                AccessStep::InspectSource {
                    maximum_bytes: self.source_bytes,
                },
                AccessStep::ReadFdrData {
                    fdr: self.fdr,
                    bytes: self.fdr_bytes,
                },
                AccessStep::CopyCalibration {
                    record: self.record,
                    bytes: self.record_bytes,
                },
            ],
        }
    }
}

/// Redaction-safe discovery or validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    TooManyCandidates {
        count: usize,
    },
    DuplicateCandidateId {
        candidate: CandidateId,
    },
    UnsafePath {
        candidate: CandidateId,
    },
    SymlinkPath {
        candidate: CandidateId,
    },
    WrongEntryType {
        candidate: CandidateId,
    },
    Unreadable {
        candidate: CandidateId,
    },
    UntrustedOwner {
        candidate: CandidateId,
    },
    WritableByUntrustedUser {
        candidate: CandidateId,
    },
    SourceSize {
        candidate: Option<CandidateId>,
        size: u64,
    },
    UnsupportedSource {
        candidate: CandidateId,
    },
    MissingFdrData {
        candidate: CandidateId,
    },
    InvalidFdrData {
        candidate: CandidateId,
        fdr: FdrId,
    },
    FdrDataSize {
        candidate: CandidateId,
        fdr: FdrId,
        size: u64,
    },
    TooManyRecords {
        candidate: CandidateId,
        fdr: FdrId,
        count: usize,
    },
    InvalidRecord {
        candidate: CandidateId,
        fdr: FdrId,
        record: RecordId,
    },
    RecordSize {
        candidate: CandidateId,
        fdr: FdrId,
        record: RecordId,
        size: u64,
    },
    InvalidHardwareAssociation,
    AssociationMismatch {
        candidate: CandidateId,
    },
    DuplicateAssociatedRecord {
        candidate: CandidateId,
    },
    AmbiguousFdrData {
        candidate: CandidateId,
    },
    NoUsableSource,
    AmbiguousSources {
        count: usize,
    },
    MalformedPbzx,
    Reader(io::ErrorKind),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyCandidates { .. }
            | Self::DuplicateCandidateId { .. }
            | Self::UnsafePath { .. }
            | Self::SymlinkPath { .. }
            | Self::WrongEntryType { .. }
            | Self::Unreadable { .. }
            | Self::UntrustedOwner { .. }
            | Self::WritableByUntrustedUser { .. }
            | Self::SourceSize { .. }
            | Self::UnsupportedSource { .. } => self.fmt_source(formatter),
            Self::MissingFdrData { .. }
            | Self::InvalidFdrData { .. }
            | Self::FdrDataSize { .. }
            | Self::TooManyRecords { .. }
            | Self::InvalidRecord { .. }
            | Self::RecordSize { .. }
            | Self::AssociationMismatch { .. }
            | Self::DuplicateAssociatedRecord { .. }
            | Self::AmbiguousFdrData { .. } => self.fmt_inventory(formatter),
            Self::InvalidHardwareAssociation => {
                formatter.write_str("live hardware association has an invalid length")
            }
            Self::NoUsableSource => formatter.write_str("no usable local machine-data source"),
            Self::AmbiguousSources { count } => {
                write!(
                    formatter,
                    "{count} usable local machine-data sources are ambiguous"
                )
            }
            Self::MalformedPbzx => formatter.write_str("malformed PBZX installer payload"),
            Self::Reader(kind) => write!(formatter, "source reader failed with {kind:?}"),
        }
    }
}

impl Error {
    fn fmt_source(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyCandidates { count } => {
                write!(
                    formatter,
                    "candidate count {count} exceeds {MAX_CANDIDATES}"
                )
            }
            Self::DuplicateCandidateId { candidate } => {
                write!(
                    formatter,
                    "candidate {} has a duplicate identifier",
                    candidate.0
                )
            }
            Self::UnsafePath { candidate } => {
                write!(formatter, "candidate {} has an unsafe path", candidate.0)
            }
            Self::SymlinkPath { candidate } => {
                write!(
                    formatter,
                    "candidate {} contains a symbolic link",
                    candidate.0
                )
            }
            Self::WrongEntryType { candidate } => {
                write!(
                    formatter,
                    "candidate {} has the wrong entry type",
                    candidate.0
                )
            }
            Self::Unreadable { candidate } => {
                write!(formatter, "candidate {} is not readable", candidate.0)
            }
            Self::UntrustedOwner { candidate } => {
                write!(
                    formatter,
                    "candidate {} has an untrusted owner",
                    candidate.0
                )
            }
            Self::WritableByUntrustedUser { candidate } => write!(
                formatter,
                "candidate {} is writable by an untrusted user",
                candidate.0
            ),
            Self::SourceSize { candidate, size } => match candidate {
                Some(candidate) => write!(
                    formatter,
                    "candidate {} source size {size} is outside the supported bound",
                    candidate.0
                ),
                None => write!(
                    formatter,
                    "source size {size} is outside the supported bound"
                ),
            },
            Self::UnsupportedSource { candidate } => {
                write!(
                    formatter,
                    "candidate {} is not a supported local source",
                    candidate.0
                )
            }
            _ => unreachable!("only source errors are delegated here"),
        }
    }

    fn fmt_inventory(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingFdrData { candidate } => {
                write!(formatter, "candidate {} contains no FDRData", candidate.0)
            }
            Self::InvalidFdrData { candidate, fdr } => write!(
                formatter,
                "candidate {} FDR object {} is invalid",
                candidate.0, fdr.0
            ),
            Self::FdrDataSize {
                candidate,
                fdr,
                size,
            } => write!(
                formatter,
                "candidate {} FDR object {} size {size} is outside the supported bound",
                candidate.0, fdr.0
            ),
            Self::TooManyRecords {
                candidate,
                fdr,
                count,
            } => write!(
                formatter,
                "candidate {} FDR object {} record count {count} exceeds {MAX_RECORDS_PER_FDR}",
                candidate.0, fdr.0
            ),
            Self::InvalidRecord {
                candidate,
                fdr,
                record,
            } => write!(
                formatter,
                "candidate {} FDR object {} record {} is invalid",
                candidate.0, fdr.0, record.0
            ),
            Self::RecordSize {
                candidate,
                fdr,
                record,
                size,
            } => write!(
                formatter,
                "candidate {} FDR object {} record {} size {size} is outside the supported bound",
                candidate.0, fdr.0, record.0
            ),
            Self::AssociationMismatch { candidate } => write!(
                formatter,
                "candidate {} is associated with different hardware",
                candidate.0
            ),
            Self::DuplicateAssociatedRecord { candidate } => write!(
                formatter,
                "candidate {} contains duplicate associated calibration records",
                candidate.0
            ),
            Self::AmbiguousFdrData { candidate } => write!(
                formatter,
                "candidate {} contains multiple associated FDR objects",
                candidate.0
            ),
            _ => unreachable!("only inventory errors are delegated here"),
        }
    }
}

impl std::error::Error for Error {}

/// Validate and plan one candidate.
///
/// # Errors
///
/// Returns a redaction-safe error when the path, metadata, format, bounds,
/// minimum record set, or live-hardware association is invalid or ambiguous.
pub fn plan_candidate(
    candidate: &Candidate<'_>,
    hardware: &HardwareAssociation<'_>,
) -> Result<ImportPlan, Error> {
    validate_candidate_path(candidate)?;
    validate_candidate_metadata(candidate)?;
    validate_origin_and_content(candidate)?;
    if hardware.0.len() != HARDWARE_ASSOCIATION_SIZE {
        return Err(Error::InvalidHardwareAssociation);
    }
    if candidate.fdr_objects.is_empty() {
        return Err(Error::MissingFdrData {
            candidate: candidate.id,
        });
    }

    let mut selected: Option<(FdrId, RecordId, u64, u64)> = None;
    for fdr in candidate.fdr_objects {
        let associated = validate_fdr(candidate.id, fdr, hardware)?;
        if let Some(record) = associated {
            if selected.is_some() {
                return Err(Error::AmbiguousFdrData {
                    candidate: candidate.id,
                });
            }
            selected = Some((fdr.id, record.id, fdr.encoded_size, record.encoded_size));
        }
    }

    let Some((fdr, record, fdr_bytes, record_bytes)) = selected else {
        return Err(Error::AssociationMismatch {
            candidate: candidate.id,
        });
    };
    Ok(ImportPlan {
        candidate: candidate.id,
        origin: candidate.origin,
        fdr,
        record,
        source_bytes: candidate.metadata.byte_len,
        fdr_bytes,
        record_bytes,
    })
}

fn validate_candidate_path(candidate: &Candidate<'_>) -> Result<(), Error> {
    if !candidate.path.is_absolute()
        || candidate.path == Path::new("/")
        || candidate.path.as_os_str().as_encoded_bytes().len() > 4_096
        || candidate.path.components().any(|component| {
            matches!(
                component,
                Component::ParentDir | Component::CurDir | Component::Prefix(_)
            )
        })
    {
        return Err(Error::UnsafePath {
            candidate: candidate.id,
        });
    }
    if candidate.metadata.path_has_symlink || candidate.metadata.entry_type == EntryType::Symlink {
        return Err(Error::SymlinkPath {
            candidate: candidate.id,
        });
    }
    Ok(())
}

fn validate_candidate_metadata(candidate: &Candidate<'_>) -> Result<(), Error> {
    if !candidate.metadata.readable {
        return Err(Error::Unreadable {
            candidate: candidate.id,
        });
    }
    if !candidate.metadata.trusted_owner {
        return Err(Error::UntrustedOwner {
            candidate: candidate.id,
        });
    }
    if candidate.metadata.mode & 0o022 != 0 {
        return Err(Error::WritableByUntrustedUser {
            candidate: candidate.id,
        });
    }
    let expected_type = if candidate.origin == SourceOrigin::MountedDiskImage {
        EntryType::Directory
    } else {
        EntryType::RegularFile
    };
    if candidate.metadata.entry_type != expected_type {
        return Err(Error::WrongEntryType {
            candidate: candidate.id,
        });
    }
    if expected_type == EntryType::RegularFile
        && (candidate.metadata.byte_len == 0 || candidate.metadata.byte_len > MAX_SOURCE_SIZE)
    {
        return Err(Error::SourceSize {
            candidate: Some(candidate.id),
            size: candidate.metadata.byte_len,
        });
    }
    Ok(())
}

fn validate_origin_and_content(candidate: &Candidate<'_>) -> Result<(), Error> {
    let supported = matches!(
        (candidate.origin, candidate.content),
        (
            SourceOrigin::PreservedEfi | SourceOrigin::Backup,
            SourceContent::FdrData
        ) | (
            SourceOrigin::InstallerPayload,
            SourceContent::InstallerPayloadRaw | SourceContent::InstallerPayloadXz
        ) | (
            SourceOrigin::MountedDiskImage,
            SourceContent::MountedDirectory
        ) | (SourceOrigin::DiskImage, SourceContent::AppleDiskImage)
    );
    if !supported {
        return Err(Error::UnsupportedSource {
            candidate: candidate.id,
        });
    }
    Ok(())
}

fn validate_fdr<'a>(
    candidate: CandidateId,
    fdr: &'a FdrMetadata<'a>,
    hardware: &HardwareAssociation<'_>,
) -> Result<Option<&'a RecordMetadata<'a>>, Error> {
    if !fdr.structurally_valid {
        return Err(Error::InvalidFdrData {
            candidate,
            fdr: fdr.id,
        });
    }
    if fdr.encoded_size == 0 || fdr.encoded_size > MAX_FDR_DATA_SIZE {
        return Err(Error::FdrDataSize {
            candidate,
            fdr: fdr.id,
            size: fdr.encoded_size,
        });
    }
    if fdr.calibration_records.len() > MAX_RECORDS_PER_FDR {
        return Err(Error::TooManyRecords {
            candidate,
            fdr: fdr.id,
            count: fdr.calibration_records.len(),
        });
    }

    let mut selected = None;
    for record in fdr.calibration_records {
        if !record.structurally_valid
            || record.hardware_association.len() != HARDWARE_ASSOCIATION_SIZE
        {
            return Err(Error::InvalidRecord {
                candidate,
                fdr: fdr.id,
                record: record.id,
            });
        }
        if record.encoded_size == 0 || record.encoded_size > MAX_CALIBRATION_RECORD_SIZE {
            return Err(Error::RecordSize {
                candidate,
                fdr: fdr.id,
                record: record.id,
                size: record.encoded_size,
            });
        }
        if record.hardware_association == hardware.0 {
            if selected.is_some() {
                return Err(Error::DuplicateAssociatedRecord { candidate });
            }
            selected = Some(record);
        }
    }
    Ok(selected)
}

/// Plan every usable candidate from a caller-provided set.
///
/// Unsupported, unsafe, malformed, and differently associated candidates are
/// ignored. The returned plans retain caller order and contain no paths or
/// hardware associations. Duplicate matching records are compared only after
/// their bytes are read; see [`crate::fdr::select_matching_record`].
///
/// # Errors
///
/// Returns an error for too many candidates, duplicate opaque identifiers, an
/// invalid live hardware association, or no usable candidate.
pub fn discover_all(
    candidates: &[Candidate<'_>],
    hardware: &HardwareAssociation<'_>,
) -> Result<Vec<ImportPlan>, Error> {
    if hardware.0.len() != HARDWARE_ASSOCIATION_SIZE {
        return Err(Error::InvalidHardwareAssociation);
    }
    if candidates.len() > MAX_CANDIDATES {
        return Err(Error::TooManyCandidates {
            count: candidates.len(),
        });
    }
    for (index, candidate) in candidates.iter().enumerate() {
        if candidates[..index]
            .iter()
            .any(|prior| prior.id == candidate.id)
        {
            return Err(Error::DuplicateCandidateId {
                candidate: candidate.id,
            });
        }
    }

    let plans = candidates
        .iter()
        .filter_map(|candidate| plan_candidate(candidate, hardware).ok())
        .collect::<Vec<_>>();
    if plans.is_empty() {
        Err(Error::NoUsableSource)
    } else {
        Ok(plans)
    }
}

/// Select exactly one usable candidate from a caller-provided set.
///
/// Unsupported, unsafe, malformed, and differently associated candidates are
/// ignored. Call [`plan_candidate`] when the caller needs the precise reason
/// one explicitly selected source was rejected.
///
/// # Errors
///
/// Returns an error for too many candidates, duplicate opaque identifiers, no
/// usable candidate, or more than one usable candidate.
pub fn discover(
    candidates: &[Candidate<'_>],
    hardware: &HardwareAssociation<'_>,
) -> Result<ImportPlan, Error> {
    let mut plans = discover_all(candidates, hardware)?;
    match plans.len() {
        1 => Ok(plans.remove(0)),
        count => Err(Error::AmbiguousSources { count }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    const ASSOCIATION: [u8; HARDWARE_ASSOCIATION_SIZE] = [0xA5; HARDWARE_ASSOCIATION_SIZE];
    const OTHER_ASSOCIATION: [u8; HARDWARE_ASSOCIATION_SIZE] = [0x5A; HARDWARE_ASSOCIATION_SIZE];

    fn metadata(entry_type: EntryType, byte_len: u64) -> CandidateMetadata {
        CandidateMetadata {
            entry_type,
            byte_len,
            readable: true,
            trusted_owner: true,
            path_has_symlink: false,
            mode: if entry_type == EntryType::Directory {
                0o755
            } else {
                0o644
            },
        }
    }

    fn record(id: u32, association: &[u8]) -> RecordMetadata<'_> {
        RecordMetadata {
            id: RecordId(id),
            hardware_association: association,
            encoded_size: 4_096,
            structurally_valid: true,
        }
    }

    fn direct_candidate<'a>(
        id: u32,
        path: &'a Path,
        records: &'a [RecordMetadata<'a>],
        fdr_storage: &'a mut [FdrMetadata<'a>; 1],
    ) -> Candidate<'a> {
        fdr_storage[0] = FdrMetadata {
            id: FdrId(9),
            encoded_size: 32_768,
            structurally_valid: true,
            calibration_records: records,
        };
        Candidate {
            id: CandidateId(id),
            path,
            origin: SourceOrigin::Backup,
            metadata: metadata(EntryType::RegularFile, 32_768),
            content: SourceContent::FdrData,
            fdr_objects: fdr_storage,
        }
    }

    fn pbzx(chunks: &[(u64, &[u8])]) -> Vec<u8> {
        let mut bytes = Vec::from(*PBZX_MAGIC);
        bytes.extend_from_slice(&1_024_u64.to_be_bytes());
        for (expanded_size, payload) in chunks {
            bytes.extend_from_slice(&expanded_size.to_be_bytes());
            bytes.extend_from_slice(
                &u64::try_from(payload.len())
                    .expect("bounded synthetic payload")
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(payload);
        }
        bytes
    }

    #[test]
    fn probes_supported_stream_formats() {
        let mut fdr = Cursor::new(b"bplist00synthetic".to_vec());
        let fdr_len = u64::try_from(fdr.get_ref().len()).unwrap();
        assert_eq!(
            probe_reader(&mut fdr, fdr_len).unwrap(),
            SourceContent::FdrData
        );

        let mut xml_fdr = Cursor::new(b"<?xml synthetic".to_vec());
        let xml_fdr_len = u64::try_from(xml_fdr.get_ref().len()).unwrap();
        assert_eq!(
            probe_reader(&mut xml_fdr, xml_fdr_len).unwrap(),
            SourceContent::FdrData
        );

        let mut payload = Cursor::new(pbzx(&[(2, b"ok"), (128, b"\xfd7zXZ\0")]));
        let payload_len = u64::try_from(payload.get_ref().len()).unwrap();
        assert_eq!(
            probe_reader(&mut payload, payload_len).unwrap(),
            SourceContent::InstallerPayloadXz
        );

        let mut raw_payload = Cursor::new(pbzx(&[(2, b"ok"), (3, b"raw")]));
        let raw_len = u64::try_from(raw_payload.get_ref().len()).unwrap();
        assert_eq!(
            probe_reader(&mut raw_payload, raw_len).unwrap(),
            SourceContent::InstallerPayloadRaw
        );

        let mut image_bytes =
            vec![0_u8; usize::try_from(UDIF_TRAILER_SIZE).expect("synthetic fixture size")];
        image_bytes[..4].copy_from_slice(UDIF_TRAILER_MAGIC);
        let mut image = Cursor::new(image_bytes);
        assert_eq!(
            probe_reader(&mut image, UDIF_TRAILER_SIZE).unwrap(),
            SourceContent::AppleDiskImage
        );
    }

    #[test]
    fn probe_is_bounded_and_redacts_reader_errors() {
        assert_eq!(
            probe_reader(&mut Cursor::new(Vec::new()), 0),
            Err(Error::SourceSize {
                candidate: None,
                size: 0
            })
        );
        let error = probe_reader(&mut Cursor::new(vec![0_u8; 1]), 8).unwrap_err();
        assert_eq!(error, Error::Reader(io::ErrorKind::UnexpectedEof));
        assert!(!error.to_string().contains("source-secret"));

        let mut malformed = Cursor::new(Vec::from(*PBZX_MAGIC));
        assert_eq!(probe_reader(&mut malformed, 4), Err(Error::MalformedPbzx));
    }

    #[test]
    fn plans_minimum_associated_record_and_safe_preview() {
        let records = [record(4, &ASSOCIATION)];
        let mut fdrs = [FdrMetadata {
            id: FdrId(0),
            encoded_size: 0,
            structurally_valid: false,
            calibration_records: &[],
        }];
        let candidate = direct_candidate(
            3,
            Path::new("/media/source-secret/FDRData"),
            &records,
            &mut fdrs,
        );
        let plan = plan_candidate(&candidate, &HardwareAssociation::new(&ASSOCIATION)).unwrap();
        assert_eq!(plan.fdr, FdrId(9));
        assert_eq!(plan.record, RecordId(4));
        let preview = plan.preview().to_string();
        assert_eq!(
            preview,
            "candidate 3 (backup): inspect at most 32768 source bytes; read FDR object 9 (32768 bytes); copy calibration record 4 (4096 bytes); access no other records; use no network"
        );
        assert!(!preview.contains("source-secret"));
        assert!(!format!("{candidate:?}").contains("source-secret"));
        assert!(!format!("{:?}", records[0]).contains("A5"));
    }

    #[test]
    fn rejects_missing_and_differently_associated_records() {
        let mut no_fdr = Candidate {
            id: CandidateId(1),
            path: Path::new("/media/source/FDRData"),
            origin: SourceOrigin::Backup,
            metadata: metadata(EntryType::RegularFile, 1),
            content: SourceContent::FdrData,
            fdr_objects: &[],
        };
        assert_eq!(
            plan_candidate(&no_fdr, &HardwareAssociation::new(&ASSOCIATION)),
            Err(Error::MissingFdrData {
                candidate: CandidateId(1)
            })
        );

        let records = [record(1, &OTHER_ASSOCIATION)];
        let fdrs = [FdrMetadata {
            id: FdrId(1),
            encoded_size: 1_024,
            structurally_valid: true,
            calibration_records: &records,
        }];
        no_fdr.fdr_objects = &fdrs;
        assert_eq!(
            plan_candidate(&no_fdr, &HardwareAssociation::new(&ASSOCIATION)),
            Err(Error::AssociationMismatch {
                candidate: CandidateId(1)
            })
        );
        assert!(!format!("{:?}", HardwareAssociation::new(&ASSOCIATION)).contains("A5"));
    }

    #[test]
    fn rejects_unsafe_paths_symlinks_and_permissions() {
        let records = [record(1, &ASSOCIATION)];
        let fdrs = [FdrMetadata {
            id: FdrId(1),
            encoded_size: 1_024,
            structurally_valid: true,
            calibration_records: &records,
        }];
        let hardware = HardwareAssociation::new(&ASSOCIATION);
        let mut candidate = Candidate {
            id: CandidateId(2),
            path: Path::new("relative/FDRData"),
            origin: SourceOrigin::Backup,
            metadata: metadata(EntryType::RegularFile, 1_024),
            content: SourceContent::FdrData,
            fdr_objects: &fdrs,
        };
        assert!(matches!(
            plan_candidate(&candidate, &hardware),
            Err(Error::UnsafePath { .. })
        ));

        candidate.path = Path::new("/media/source/FDRData");
        candidate.metadata.path_has_symlink = true;
        assert!(matches!(
            plan_candidate(&candidate, &hardware),
            Err(Error::SymlinkPath { .. })
        ));

        candidate.metadata.path_has_symlink = false;
        candidate.metadata.readable = false;
        assert!(matches!(
            plan_candidate(&candidate, &hardware),
            Err(Error::Unreadable { .. })
        ));

        candidate.metadata.readable = true;
        candidate.metadata.trusted_owner = false;
        assert!(matches!(
            plan_candidate(&candidate, &hardware),
            Err(Error::UntrustedOwner { .. })
        ));

        candidate.metadata.trusted_owner = true;
        candidate.metadata.mode = 0o666;
        assert!(matches!(
            plan_candidate(&candidate, &hardware),
            Err(Error::WritableByUntrustedUser { .. })
        ));
    }

    #[test]
    fn rejects_duplicate_records_and_fdr_objects() {
        let records = [record(1, &ASSOCIATION), record(2, &ASSOCIATION)];
        let fdrs = [FdrMetadata {
            id: FdrId(1),
            encoded_size: 1_024,
            structurally_valid: true,
            calibration_records: &records,
        }];
        let candidate = Candidate {
            id: CandidateId(4),
            path: Path::new("/media/source/FDRData"),
            origin: SourceOrigin::Backup,
            metadata: metadata(EntryType::RegularFile, 1_024),
            content: SourceContent::FdrData,
            fdr_objects: &fdrs,
        };
        assert_eq!(
            plan_candidate(&candidate, &HardwareAssociation::new(&ASSOCIATION)),
            Err(Error::DuplicateAssociatedRecord {
                candidate: CandidateId(4)
            })
        );

        let one = [record(1, &ASSOCIATION)];
        let duplicate_fdrs = [
            FdrMetadata {
                id: FdrId(1),
                encoded_size: 1_024,
                structurally_valid: true,
                calibration_records: &one,
            },
            FdrMetadata {
                id: FdrId(2),
                encoded_size: 1_024,
                structurally_valid: true,
                calibration_records: &one,
            },
        ];
        let ambiguous = Candidate {
            fdr_objects: &duplicate_fdrs,
            ..candidate
        };
        assert_eq!(
            plan_candidate(&ambiguous, &HardwareAssociation::new(&ASSOCIATION)),
            Err(Error::AmbiguousFdrData {
                candidate: CandidateId(4)
            })
        );
    }

    #[test]
    fn enforces_source_fdr_record_and_association_bounds() {
        let records = [record(1, &ASSOCIATION)];
        let fdrs = [FdrMetadata {
            id: FdrId(1),
            encoded_size: 1_024,
            structurally_valid: true,
            calibration_records: &records,
        }];
        let hardware = HardwareAssociation::new(&ASSOCIATION);
        let mut candidate = Candidate {
            id: CandidateId(5),
            path: Path::new("/media/source/FDRData"),
            origin: SourceOrigin::Backup,
            metadata: metadata(EntryType::RegularFile, MAX_SOURCE_SIZE + 1),
            content: SourceContent::FdrData,
            fdr_objects: &fdrs,
        };
        assert!(matches!(
            plan_candidate(&candidate, &hardware),
            Err(Error::SourceSize { .. })
        ));

        candidate.metadata.byte_len = 1_024;
        let huge_fdrs = [FdrMetadata {
            id: FdrId(1),
            encoded_size: MAX_FDR_DATA_SIZE + 1,
            structurally_valid: true,
            calibration_records: &records,
        }];
        candidate.fdr_objects = &huge_fdrs;
        assert!(matches!(
            plan_candidate(&candidate, &hardware),
            Err(Error::FdrDataSize { .. })
        ));

        let huge_records = [RecordMetadata {
            encoded_size: MAX_CALIBRATION_RECORD_SIZE + 1,
            ..record(1, &ASSOCIATION)
        }];
        let normal_fdrs = [FdrMetadata {
            id: FdrId(1),
            encoded_size: 1_024,
            structurally_valid: true,
            calibration_records: &huge_records,
        }];
        candidate.fdr_objects = &normal_fdrs;
        assert!(matches!(
            plan_candidate(&candidate, &hardware),
            Err(Error::RecordSize { .. })
        ));

        assert_eq!(
            plan_candidate(&candidate, &HardwareAssociation::new(&[0_u8; 17])),
            Err(Error::InvalidHardwareAssociation)
        );
    }

    #[test]
    fn recognizes_all_supported_origins_including_xz() {
        let records = [record(1, &ASSOCIATION)];
        let fdrs = [FdrMetadata {
            id: FdrId(1),
            encoded_size: 1_024,
            structurally_valid: true,
            calibration_records: &records,
        }];
        let hardware = HardwareAssociation::new(&ASSOCIATION);
        let cases = [
            (
                SourceOrigin::PreservedEfi,
                SourceContent::FdrData,
                EntryType::RegularFile,
            ),
            (
                SourceOrigin::Backup,
                SourceContent::FdrData,
                EntryType::RegularFile,
            ),
            (
                SourceOrigin::InstallerPayload,
                SourceContent::InstallerPayloadRaw,
                EntryType::RegularFile,
            ),
            (
                SourceOrigin::MountedDiskImage,
                SourceContent::MountedDirectory,
                EntryType::Directory,
            ),
            (
                SourceOrigin::DiskImage,
                SourceContent::AppleDiskImage,
                EntryType::RegularFile,
            ),
        ];
        for (index, (origin, content, entry_type)) in cases.into_iter().enumerate() {
            let candidate = Candidate {
                id: CandidateId(u32::try_from(index).expect("bounded synthetic case index")),
                path: Path::new("/media/source/input"),
                origin,
                metadata: metadata(
                    entry_type,
                    if entry_type == EntryType::Directory {
                        0
                    } else {
                        2_048
                    },
                ),
                content,
                fdr_objects: &fdrs,
            };
            assert!(plan_candidate(&candidate, &hardware).is_ok());
        }

        let xz = Candidate {
            id: CandidateId(8),
            path: Path::new("/media/source/payload"),
            origin: SourceOrigin::InstallerPayload,
            metadata: metadata(EntryType::RegularFile, 2_048),
            content: SourceContent::InstallerPayloadXz,
            fdr_objects: &fdrs,
        };
        assert!(plan_candidate(&xz, &hardware).is_ok());
    }

    #[test]
    fn discovery_rejects_missing_ambiguous_and_duplicate_candidates() {
        let records = [record(1, &ASSOCIATION)];
        let fdrs = [FdrMetadata {
            id: FdrId(1),
            encoded_size: 1_024,
            structurally_valid: true,
            calibration_records: &records,
        }];
        let hardware = HardwareAssociation::new(&ASSOCIATION);
        let first = Candidate {
            id: CandidateId(1),
            path: Path::new("/media/source/first"),
            origin: SourceOrigin::Backup,
            metadata: metadata(EntryType::RegularFile, 2_048),
            content: SourceContent::FdrData,
            fdr_objects: &fdrs,
        };
        let second = Candidate {
            id: CandidateId(2),
            path: Path::new("/media/source/second"),
            ..first
        };
        let candidates = [first, second];
        assert_eq!(
            discover(&candidates, &hardware),
            Err(Error::AmbiguousSources { count: 2 })
        );
        let plans = discover_all(&candidates, &hardware).unwrap();
        assert_eq!(plans.len(), 2);
        assert_eq!(plans[0].candidate, CandidateId(1));
        assert_eq!(plans[1].candidate, CandidateId(2));
        assert_eq!(discover(&[], &hardware), Err(Error::NoUsableSource));

        let duplicate = Candidate {
            id: CandidateId(1),
            path: Path::new("/media/source/duplicate"),
            origin: SourceOrigin::Backup,
            metadata: metadata(EntryType::RegularFile, 2_048),
            content: SourceContent::FdrData,
            fdr_objects: &fdrs,
        };
        let original = Candidate {
            id: CandidateId(1),
            path: Path::new("/media/source/original"),
            origin: SourceOrigin::Backup,
            metadata: metadata(EntryType::RegularFile, 2_048),
            content: SourceContent::FdrData,
            fdr_objects: &fdrs,
        };
        assert_eq!(
            discover(&[original, duplicate], &hardware),
            Err(Error::DuplicateCandidateId {
                candidate: CandidateId(1)
            })
        );
    }
}

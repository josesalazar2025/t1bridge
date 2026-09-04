//! Read-only composition of local source walking and device-bound FDR selection.

use std::fmt;
use std::io::{self, Read, Seek, SeekFrom};

use crate::discovery::MAX_SOURCE_SIZE;
use crate::fdr::{self, FdrCalibrationRecord, MAX_FDR_INPUT_SIZE, select_fdr_calibration};
use crate::walk::{WalkError, collect_fdr_object};

const BPLIST_MAGIC: &[u8; 8] = b"bplist00";
const XML_MAGIC: &[u8; 5] = b"<?xml";
const PBZX_MAGIC: &[u8; 4] = b"pbzx";
const YAA_MAGIC: &[u8; 4] = b"YAA1";
const AA_MAGIC: &[u8; 4] = b"AA01";

/// A redaction-safe read-only import failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImportError {
    /// The declared source size is empty or exceeds the importer bound.
    InvalidSourceSize {
        /// Caller-supplied source size.
        actual: u64,
        /// Largest source accepted by the importer.
        maximum: u64,
    },
    /// The seekable stream's actual length differs from the declared size.
    SourceSizeMismatch {
        /// Caller-supplied source size.
        declared: u64,
        /// Length observed by seeking to the stream end.
        actual: u64,
    },
    /// The already-open source could not be read or sought.
    Reader(io::ErrorKind),
    /// Memory for a bounded direct FDR object could not be reserved.
    AllocationFailed,
    /// The source is neither direct `FDRData` nor a reference-proven container.
    UnsupportedSource,
    /// Reference-proven archive walking failed.
    Walk(WalkError),
    /// The selected `FDRData` object or device-bound record was invalid.
    Fdr(fdr::Error),
}

impl fmt::Display for ImportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSourceSize { actual, maximum } => write!(
                formatter,
                "import source size is invalid ({actual} bytes; maximum is {maximum})"
            ),
            Self::SourceSizeMismatch { declared, actual } => write!(
                formatter,
                "import source size differs from its declaration ({actual} bytes; declared {declared})"
            ),
            Self::Reader(_) => formatter.write_str("import source reader failed"),
            Self::AllocationFailed => formatter.write_str("import buffer allocation failed"),
            Self::UnsupportedSource => formatter.write_str("unsupported import source"),
            Self::Walk(error) => error.fmt(formatter),
            Self::Fdr(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ImportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Walk(error) => Some(error),
            Self::Fdr(error) => Some(error),
            Self::InvalidSourceSize { .. }
            | Self::SourceSizeMismatch { .. }
            | Self::Reader(_)
            | Self::AllocationFailed
            | Self::UnsupportedSource => None,
        }
    }
}

impl From<WalkError> for ImportError {
    fn from(error: WalkError) -> Self {
        Self::Walk(error)
    }
}

impl From<fdr::Error> for ImportError {
    fn from(error: fdr::Error) -> Self {
        Self::Fdr(error)
    }
}

/// Reads and validates one device-bound calibration from an already-open source.
///
/// `source_size` must be the exact length of the complete seekable stream. A
/// direct binary or canonical Apple XML plist is treated as the `FDRData`
/// object itself. For AA or
/// PBZX sources, `selector` receives each safe archive path and owns the exact
/// object-selection policy; this layer adds no filename pattern. XZ chunks are
/// decoded locally within their declared PBZX output bounds.
///
/// The operation performs no writes and returns the complete signed outer
/// Combined `FSCl` record. Temporary complete `FDRData` buffers are cleared on
/// every success and failure path.
///
/// # Errors
///
/// Returns a redaction-safe error for invalid or inconsistent source sizes,
/// reader failures, unsupported or malformed containers, invalid XZ chunks,
/// duplicate/missing archive matches, or invalid device association.
pub fn read_fdr_calibration<R, S>(
    source: &mut R,
    source_size: u64,
    selector: S,
    module_serial: &[u8],
) -> Result<FdrCalibrationRecord, ImportError>
where
    R: Read + Seek,
    S: FnMut(&[u8]) -> bool,
{
    validate_exact_size(source, source_size)?;
    let kind = classify(source, source_size)?;
    seek_start(source)?;

    let object = match kind {
        SourceKind::DirectFdr => read_direct(source, source_size)?,
        SourceKind::Archive => {
            TemporaryFdrData::new(collect_fdr_object(source, source_size, selector)?)
        }
    };
    select_fdr_calibration(object.as_bytes(), module_serial).map_err(ImportError::from)
}

/// Reads one direct `FDRData` object from an already-open source.
///
/// Unlike [`read_fdr_calibration`], this operation rejects archive containers
/// immediately. It is intended for preserved EFI `FDRData` files whose paths
/// and readers were already selected by a separate filesystem adapter.
///
/// # Errors
///
/// Returns a redaction-safe error for an invalid or inconsistent source size,
/// reader failure, non-`FDRData` input, or invalid device association.
pub fn read_direct_fdr_calibration<R: Read + Seek>(
    source: &mut R,
    source_size: u64,
    module_serial: &[u8],
) -> Result<FdrCalibrationRecord, ImportError> {
    validate_exact_size(source, source_size)?;
    if !matches!(classify(source, source_size)?, SourceKind::DirectFdr) {
        return Err(ImportError::UnsupportedSource);
    }
    seek_start(source)?;
    let object = read_direct(source, source_size)?;
    select_fdr_calibration(object.as_bytes(), module_serial).map_err(ImportError::from)
}

#[derive(Clone, Copy)]
enum SourceKind {
    DirectFdr,
    Archive,
}

fn validate_exact_size<R: Seek>(source: &mut R, declared: u64) -> Result<(), ImportError> {
    if declared == 0 || declared > MAX_SOURCE_SIZE {
        return Err(ImportError::InvalidSourceSize {
            actual: declared,
            maximum: MAX_SOURCE_SIZE,
        });
    }
    let actual = source
        .seek(SeekFrom::End(0))
        .map_err(|error| ImportError::Reader(error.kind()))?;
    if actual != declared {
        return Err(ImportError::SourceSizeMismatch { declared, actual });
    }
    Ok(())
}

fn classify<R: Read + Seek>(source: &mut R, source_size: u64) -> Result<SourceKind, ImportError> {
    seek_start(source)?;
    let mut prefix = [0_u8; BPLIST_MAGIC.len()];
    let prefix_len =
        usize::try_from(source_size.min(8)).map_err(|_| ImportError::InvalidSourceSize {
            actual: source_size,
            maximum: MAX_SOURCE_SIZE,
        })?;
    source
        .read_exact(&mut prefix[..prefix_len])
        .map_err(|error| ImportError::Reader(error.kind()))?;

    if (prefix_len == BPLIST_MAGIC.len() && prefix == *BPLIST_MAGIC)
        || (prefix_len >= XML_MAGIC.len() && prefix[..XML_MAGIC.len()] == *XML_MAGIC)
    {
        return Ok(SourceKind::DirectFdr);
    }
    if prefix_len >= PBZX_MAGIC.len() {
        let magic = &prefix[..PBZX_MAGIC.len()];
        if magic == PBZX_MAGIC || magic == YAA_MAGIC || magic == AA_MAGIC {
            return Ok(SourceKind::Archive);
        }
    }
    Err(ImportError::UnsupportedSource)
}

fn read_direct<R: Read>(source: &mut R, source_size: u64) -> Result<TemporaryFdrData, ImportError> {
    let maximum = u64::try_from(MAX_FDR_INPUT_SIZE).unwrap_or(u64::MAX);
    if source_size > maximum {
        return Err(ImportError::Fdr(fdr::Error::InputTooLarge {
            actual: usize::try_from(source_size).unwrap_or(usize::MAX),
            maximum: MAX_FDR_INPUT_SIZE,
        }));
    }
    let size = usize::try_from(source_size).map_err(|_| ImportError::AllocationFailed)?;
    let mut object = TemporaryFdrData::with_size(size)?;
    source
        .read_exact(object.as_mut_bytes())
        .map_err(|error| ImportError::Reader(error.kind()))?;
    Ok(object)
}

fn seek_start<R: Seek>(source: &mut R) -> Result<(), ImportError> {
    source
        .seek(SeekFrom::Start(0))
        .map(|_| ())
        .map_err(|error| ImportError::Reader(error.kind()))
}

struct TemporaryFdrData(Vec<u8>);

impl TemporaryFdrData {
    const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    fn with_size(size: usize) -> Result<Self, ImportError> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(size)
            .map_err(|_| ImportError::AllocationFailed)?;
        bytes.resize(size, 0);
        Ok(Self(bytes))
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.0
    }

    fn wipe(&mut self) {
        self.0.fill(0);
    }
}

impl Drop for TemporaryFdrData {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::Cursor;
    use t1_bridge::bplist::{self, Value};
    use t1_bridge::calibration::MODULE_SERIAL_NUMBER_SIZE;

    const MODULE_SERIAL: &[u8; MODULE_SERIAL_NUMBER_SIZE] = b"SYNTHETICMODULE001";
    const OTHER_MODULE: &[u8; MODULE_SERIAL_NUMBER_SIZE] = b"SYNTHETICMODULE002";
    const TARGET: &[u8] = b"usr/share/t1bridge/FDRData";

    fn read(bytes: &[u8]) -> Result<FdrCalibrationRecord, ImportError> {
        read_fdr_calibration(
            &mut Cursor::new(bytes),
            u64::try_from(bytes.len()).unwrap(),
            |path| path == TARGET,
            MODULE_SERIAL,
        )
    }

    fn fdr_data(module_serial: &[u8; MODULE_SERIAL_NUMBER_SIZE]) -> Vec<u8> {
        let key = format!("FSCl-{}", std::str::from_utf8(module_serial).unwrap());
        bplist::encode(&Value::Dictionary(BTreeMap::from([(
            key,
            Value::Data(fdr_record(module_serial)),
        )])))
        .unwrap()
    }

    fn calibration_blob(module_serial: &[u8; MODULE_SERIAL_NUMBER_SIZE]) -> Vec<u8> {
        let mut calibration = vec![0_u8; 96];
        let length = u32::try_from(calibration.len()).unwrap();
        calibration[4..8].copy_from_slice(&length.to_le_bytes());
        calibration[16..20].copy_from_slice(b"CALB");
        calibration[32..50].copy_from_slice(module_serial);
        calibration
    }

    fn fdr_record(module_serial: &[u8; MODULE_SERIAL_NUMBER_SIZE]) -> Vec<u8> {
        let calibration = calibration_blob(module_serial);
        let im4p = der_sequence(&[
            der(0x16, b"IM4P"),
            der(0x16, b"FSCl"),
            der(0x16, b"1.0"),
            der(0x04, &calibration),
        ]);
        let img4 = der_sequence(&[der(0x16, b"IMG4"), im4p]);
        let fdrd = der_sequence(&[der(0x16, b"fdrd"), der(0x04, &img4)]);
        der_sequence(&[der(0x16, b"comb"), fdrd])
    }

    fn der_sequence(children: &[Vec<u8>]) -> Vec<u8> {
        der(0x30, &children.concat())
    }

    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut output = vec![tag];
        if content.len() < 0x80 {
            output.push(u8::try_from(content.len()).unwrap());
        } else {
            output.extend_from_slice(&[0x81, u8::try_from(content.len()).unwrap()]);
        }
        output.extend_from_slice(content);
        output
    }

    fn aa_field_bytes(key: [u8; 3], value: &[u8]) -> Vec<u8> {
        let mut field = key.to_vec();
        field.push(b'P');
        field.extend_from_slice(&u16::try_from(value.len()).unwrap().to_le_bytes());
        field.extend_from_slice(value);
        field
    }

    fn aa_entry(path: &[u8], data: &[u8]) -> Vec<u8> {
        let mut fields = aa_field_bytes(*b"PAT", path);
        fields.extend_from_slice(b"TYP1F");
        fields.extend_from_slice(b"DATB");
        fields.extend_from_slice(&u32::try_from(data.len()).unwrap().to_le_bytes());
        let mut entry = b"YAA1".to_vec();
        entry.extend_from_slice(&u16::try_from(6 + fields.len()).unwrap().to_le_bytes());
        entry.extend_from_slice(&fields);
        entry.extend_from_slice(data);
        entry
    }

    fn pbzx(chunk: &[u8]) -> Vec<u8> {
        let size = u64::try_from(chunk.len()).unwrap();
        let mut bytes = b"pbzx".to_vec();
        bytes.extend_from_slice(&size.to_be_bytes());
        bytes.extend_from_slice(&size.to_be_bytes());
        bytes.extend_from_slice(&size.to_be_bytes());
        bytes.extend_from_slice(chunk);
        bytes
    }

    fn newc_entry(path: &[u8], mode: u32, data: &[u8]) -> Vec<u8> {
        let values = [
            1,
            mode,
            0,
            0,
            1,
            0,
            u32::try_from(data.len()).unwrap(),
            0,
            0,
            0,
            0,
            u32::try_from(path.len() + 1).unwrap(),
            0,
        ];
        let mut bytes = b"070701".to_vec();
        for value in values {
            bytes.extend_from_slice(format!("{value:08x}").as_bytes());
        }
        bytes.extend_from_slice(path);
        bytes.push(0);
        bytes.resize((bytes.len() + 3) & !3, 0);
        bytes.extend_from_slice(data);
        bytes.resize((bytes.len() + 3) & !3, 0);
        bytes
    }

    fn cpio(path: &[u8], data: &[u8]) -> Vec<u8> {
        let mut bytes = newc_entry(path, 0o100_600, data);
        bytes.extend_from_slice(&newc_entry(b"TRAILER!!!", 0, b""));
        bytes
    }

    #[test]
    fn direct_fdr_data_returns_the_validated_outer_record() {
        let source = fdr_data(MODULE_SERIAL);
        let record = read(&source).unwrap();
        assert_eq!(record.as_bytes(), fdr_record(MODULE_SERIAL));
        assert!(!format!("{record:?}").contains("SYNTHETIC"));

        let record = read_direct_fdr_calibration(
            &mut Cursor::new(&source),
            u64::try_from(source.len()).unwrap(),
            MODULE_SERIAL,
        )
        .unwrap();
        assert_eq!(record.as_bytes(), fdr_record(MODULE_SERIAL));
    }

    #[test]
    fn direct_fdr_reader_rejects_archive_containers() {
        let source = aa_entry(TARGET, &fdr_data(MODULE_SERIAL));
        let size = u64::try_from(source.len()).unwrap();

        assert_eq!(
            read_direct_fdr_calibration(&mut Cursor::new(source), size, MODULE_SERIAL),
            Err(ImportError::UnsupportedSource)
        );
    }

    #[test]
    fn archive_selector_composes_aa_and_pbzx_walking() {
        let fdr = fdr_data(MODULE_SERIAL);
        let aa = aa_entry(TARGET, &fdr);
        assert_eq!(read(&aa).unwrap().as_bytes(), fdr_record(MODULE_SERIAL));
        assert_eq!(
            read(&pbzx(&aa)).unwrap().as_bytes(),
            fdr_record(MODULE_SERIAL)
        );
        assert_eq!(
            read(&pbzx(&cpio(TARGET, &fdr))).unwrap().as_bytes(),
            fdr_record(MODULE_SERIAL)
        );

        let size = u64::try_from(aa.len()).unwrap();
        let error =
            read_fdr_calibration(&mut Cursor::new(aa), size, |_| false, MODULE_SERIAL).unwrap_err();
        assert_eq!(error, ImportError::Walk(WalkError::MissingSelectedObject));
    }

    #[test]
    fn rejects_duplicate_missing_invalid_xz_and_malformed_sources() {
        let fdr = fdr_data(MODULE_SERIAL);
        let mut duplicate = aa_entry(TARGET, &fdr);
        duplicate.extend_from_slice(&aa_entry(TARGET, &fdr));
        assert_eq!(
            read(&duplicate),
            Err(ImportError::Walk(WalkError::DuplicateSelectedObject))
        );
        assert_eq!(read(b"unsupported"), Err(ImportError::UnsupportedSource));

        let archived = b"\xfd7zXZ\0synthetic-compressed-data";
        let mut xz = b"pbzx".to_vec();
        xz.extend_from_slice(&64_u64.to_be_bytes());
        xz.extend_from_slice(&64_u64.to_be_bytes());
        xz.extend_from_slice(&u64::try_from(archived.len()).unwrap().to_be_bytes());
        xz.extend_from_slice(archived);
        assert_eq!(
            read(&xz),
            Err(ImportError::Walk(WalkError::XzDecompression))
        );

        assert!(matches!(
            read(b"bplist00"),
            Err(ImportError::Fdr(fdr::Error::InvalidBinaryPlist(_)))
        ));
        assert!(matches!(
            read(b"<?xml"),
            Err(ImportError::Fdr(fdr::Error::InvalidXmlPlist(_)))
        ));
        assert!(matches!(
            read(b"YAA1\x07\0X"),
            Err(ImportError::Walk(WalkError::MalformedContainer))
        ));
    }

    #[test]
    fn validates_module_binding_after_archive_selection() {
        let source = aa_entry(TARGET, &fdr_data(OTHER_MODULE));
        let error = read(&source).unwrap_err();
        assert!(matches!(
            error,
            ImportError::Fdr(fdr::Error::MissingModuleRecord)
        ));

        let source = fdr_data(MODULE_SERIAL);
        let error = read_fdr_calibration(
            &mut Cursor::new(&source),
            u64::try_from(source.len()).unwrap(),
            |_| true,
            b"invalid-module",
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ImportError::Fdr(fdr::Error::InvalidModuleSerialLength { .. })
        ));
    }

    #[test]
    fn enforces_declared_and_actual_source_size_before_reading() {
        let source = fdr_data(MODULE_SERIAL);
        assert_eq!(
            read_fdr_calibration(&mut Cursor::new(&source), 0, |_| true, MODULE_SERIAL,),
            Err(ImportError::InvalidSourceSize {
                actual: 0,
                maximum: MAX_SOURCE_SIZE,
            })
        );
        assert_eq!(
            read_fdr_calibration(
                &mut Cursor::new(&source),
                MAX_SOURCE_SIZE + 1,
                |_| true,
                MODULE_SERIAL,
            ),
            Err(ImportError::InvalidSourceSize {
                actual: MAX_SOURCE_SIZE + 1,
                maximum: MAX_SOURCE_SIZE,
            })
        );
        assert_eq!(
            read_fdr_calibration(
                &mut Cursor::new(&source),
                u64::try_from(source.len() - 1).unwrap(),
                |_| true,
                MODULE_SERIAL,
            ),
            Err(ImportError::SourceSizeMismatch {
                declared: u64::try_from(source.len() - 1).unwrap(),
                actual: u64::try_from(source.len()).unwrap(),
            })
        );
    }

    #[test]
    fn reader_errors_and_sensitive_inputs_are_redacted() {
        struct SensitiveSource(Cursor<Vec<u8>>);

        impl Read for SensitiveSource {
            fn read(&mut self, _bytes: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("private source path and record"))
            }
        }

        impl Seek for SensitiveSource {
            fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
                self.0.seek(position)
            }
        }

        let mut source = SensitiveSource(Cursor::new(vec![0; 8]));
        let error = read_fdr_calibration(&mut source, 8, |_| true, MODULE_SERIAL).unwrap_err();
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("private"));
        assert!(!rendered.contains("SYNTHETIC"));
    }

    #[test]
    fn temporary_fdr_buffer_wipe_clears_every_byte() {
        let mut buffer = TemporaryFdrData::new(vec![0xa5; 32]);
        buffer.wipe();
        assert!(buffer.as_bytes().iter().all(|byte| *byte == 0));
    }
}

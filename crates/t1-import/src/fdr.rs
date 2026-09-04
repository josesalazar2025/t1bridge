//! Selection of one device-bound calibration record from direct `FDRData`.

use std::{fmt, mem};

use t1_bridge::bplist::{self, Value};
use t1_bridge::calibration::{
    CalibrationError, MODULE_SERIAL_NUMBER_SIZE, validate_fdr_calibration_record,
};

use crate::xml_fdr;

/// Largest direct `FDRData` property list accepted by this importer.
pub const MAX_FDR_INPUT_SIZE: usize = bplist::MAX_PLIST_SIZE;
/// Largest Combined `FSCl` record accepted for a Mesa calibration command.
pub const MAX_FDR_RECORD_SIZE: usize = 16 * 1024 * 1024 - 8;

const FSCL_KEY_PREFIX: &str = "FSCl-";

/// A validated Combined `FSCl` record.
///
/// The contents remain opaque and are intentionally omitted from diagnostics.
#[derive(Clone, Eq, PartialEq)]
pub struct FdrCalibrationRecord {
    bytes: Vec<u8>,
}

impl FdrCalibrationRecord {
    /// Returns the complete signed outer record expected by Mesa.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the complete signed outer record expected by Mesa.
    #[must_use]
    pub fn into_bytes(mut self) -> Vec<u8> {
        mem::take(&mut self.bytes)
    }

    /// Returns the encoded outer-record size without exposing its contents.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Reports whether the outer record is empty.
    ///
    /// A successfully constructed record is never empty; this method is
    /// provided alongside [`Self::len`] for collection-like ergonomics.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn from_validated_test_bytes(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
        }
    }
}

impl AsRef<[u8]> for FdrCalibrationRecord {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for FdrCalibrationRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FdrCalibrationRecord")
            .field("len", &self.bytes.len())
            .field("bytes", &"[redacted]")
            .finish()
    }
}

impl Drop for FdrCalibrationRecord {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

/// A redaction-safe result of comparing records selected from multiple local
/// sources against the same live sensor association.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatchingRecordSelectionError {
    /// No local source produced a validated matching record.
    NoMatchingRecord,
    /// Multiple matching sources produced different signed records.
    ConflictingRecords {
        /// Number of matching records compared.
        count: usize,
    },
}

impl fmt::Display for MatchingRecordSelectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoMatchingRecord => formatter.write_str("no matching calibration record"),
            Self::ConflictingRecords { count } => write!(
                formatter,
                "{count} matching local sources contain conflicting calibration records"
            ),
        }
    }
}

impl std::error::Error for MatchingRecordSelectionError {}

/// Select one record from hardware-matched local sources.
///
/// Byte-identical duplicates are one logical source. Different signed records
/// for the same live association are ambiguous and fail without choosing one.
/// All discarded records are cleared when dropped.
///
/// # Errors
///
/// Returns [`MatchingRecordSelectionError::NoMatchingRecord`] for an empty
/// input or [`MatchingRecordSelectionError::ConflictingRecords`] when any
/// matching source differs byte-for-byte.
pub fn select_matching_record(
    records: Vec<FdrCalibrationRecord>,
) -> Result<FdrCalibrationRecord, MatchingRecordSelectionError> {
    let count = records.len();
    let mut records = records.into_iter();
    let Some(selected) = records.next() else {
        return Err(MatchingRecordSelectionError::NoMatchingRecord);
    };
    if records.all(|record| record == selected) {
        Ok(selected)
    } else {
        Err(MatchingRecordSelectionError::ConflictingRecords { count })
    }
}

/// A redaction-safe direct-`FDRData` selection failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The encoded binary plist exceeds [`MAX_FDR_INPUT_SIZE`].
    InputTooLarge {
        /// Observed encoded byte length.
        actual: usize,
        /// Maximum accepted encoded byte length.
        maximum: usize,
    },
    /// The live module serial is not exactly 18 bytes.
    InvalidModuleSerialLength {
        /// Observed byte length.
        actual: usize,
    },
    /// The live module serial is not uppercase ASCII alphanumeric text.
    InvalidModuleSerialCharacter,
    /// The binary plist is malformed or outside the supported value subset.
    InvalidBinaryPlist(bplist::Error),
    /// The XML plist is malformed or outside the supported `FDRData` subset.
    InvalidXmlPlist(xml_fdr::Error),
    /// The binary-plist root is not a dictionary.
    RootNotDictionary,
    /// The exact module key is absent.
    MissingModuleRecord,
    /// The exact module key is present but does not hold opaque data.
    InvalidModuleRecordType,
    /// The selected Combined record exceeds [`MAX_FDR_RECORD_SIZE`].
    RecordTooLarge {
        /// Observed record byte length.
        actual: usize,
        /// Maximum accepted record byte length.
        maximum: usize,
    },
    /// The selected record is malformed or belongs to a different module.
    InvalidCalibration(CalibrationError),
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge { actual, maximum } => write!(
                formatter,
                "FDRData exceeds the input limit ({actual} bytes; maximum is {maximum})"
            ),
            Self::InvalidModuleSerialLength { actual } => write!(
                formatter,
                "invalid module serial length ({actual} bytes; expected {MODULE_SERIAL_NUMBER_SIZE})"
            ),
            Self::InvalidModuleSerialCharacter => {
                formatter.write_str("module serial is not uppercase ASCII alphanumeric text")
            }
            Self::InvalidBinaryPlist(error) => write!(formatter, "invalid FDRData: {error}"),
            Self::InvalidXmlPlist(error) => write!(formatter, "invalid FDRData: {error}"),
            Self::RootNotDictionary => formatter.write_str("FDRData root is not a dictionary"),
            Self::MissingModuleRecord => {
                formatter.write_str("FDRData has no FSCl record for this module")
            }
            Self::InvalidModuleRecordType => {
                formatter.write_str("FDRData FSCl record has an invalid value type")
            }
            Self::RecordTooLarge { actual, maximum } => write!(
                formatter,
                "FDR calibration record exceeds the size limit ({actual} bytes; maximum is {maximum})"
            ),
            Self::InvalidCalibration(error) => {
                write!(formatter, "invalid FDR calibration record: {error}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidBinaryPlist(error) => Some(error),
            Self::InvalidXmlPlist(error) => Some(error),
            Self::InvalidCalibration(error) => Some(error),
            _ => None,
        }
    }
}

/// Selects and validates one module's Combined `FSCl` record.
///
/// `fdr_data` must be one complete binary- or canonical Apple XML-plist
/// dictionary. The lookup uses
/// only the exact `FSCl-<live module serial>` key. The returned bytes are the
/// complete signed outer record, unchanged; the inner `CALB` is validated but
/// is not substituted for it.
///
/// # Errors
///
/// Returns an error for invalid live module serials, malformed or oversized
/// plists, a non-dictionary root, a missing or incorrectly typed module
/// record, or a malformed/differently-bound Combined calibration record.
pub fn select_fdr_calibration(
    fdr_data: &[u8],
    module_serial: &[u8],
) -> Result<FdrCalibrationRecord, Error> {
    validate_module_serial(module_serial)?;
    if fdr_data.len() > MAX_FDR_INPUT_SIZE {
        return Err(Error::InputTooLarge {
            actual: fdr_data.len(),
            maximum: MAX_FDR_INPUT_SIZE,
        });
    }

    let serial =
        std::str::from_utf8(module_serial).map_err(|_| Error::InvalidModuleSerialCharacter)?;
    let key = format!("{FSCL_KEY_PREFIX}{serial}");
    let record = if fdr_data.starts_with(b"<?xml") {
        xml_fdr::select_data(fdr_data, key.as_bytes(), MAX_FDR_RECORD_SIZE)
            .map_err(Error::InvalidXmlPlist)?
            .ok_or(Error::MissingModuleRecord)?
    } else {
        let Value::Dictionary(mut root) =
            bplist::decode(fdr_data).map_err(Error::InvalidBinaryPlist)?
        else {
            return Err(Error::RootNotDictionary);
        };
        let Some(value) = root.remove(&key) else {
            return Err(Error::MissingModuleRecord);
        };
        let Value::Data(record) = value else {
            return Err(Error::InvalidModuleRecordType);
        };
        record
    };

    validate_record(&record, module_serial)?;
    Ok(FdrCalibrationRecord { bytes: record })
}

fn validate_module_serial(module_serial: &[u8]) -> Result<(), Error> {
    if module_serial.len() != MODULE_SERIAL_NUMBER_SIZE {
        return Err(Error::InvalidModuleSerialLength {
            actual: module_serial.len(),
        });
    }
    if !module_serial
        .iter()
        .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return Err(Error::InvalidModuleSerialCharacter);
    }
    Ok(())
}

fn validate_record(record: &[u8], module_serial: &[u8]) -> Result<(), Error> {
    if record.len() > MAX_FDR_RECORD_SIZE {
        return Err(Error::RecordTooLarge {
            actual: record.len(),
            maximum: MAX_FDR_RECORD_SIZE,
        });
    }
    validate_fdr_calibration_record(record, module_serial)
        .map(drop)
        .map_err(Error::InvalidCalibration)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use t1_bridge::bplist;

    const MODULE_SERIAL: &[u8; MODULE_SERIAL_NUMBER_SIZE] = b"SYNTHETICMODULE001";
    const OTHER_MODULE: &[u8; MODULE_SERIAL_NUMBER_SIZE] = b"SYNTHETICMODULE002";

    #[test]
    fn selects_exact_module_record_and_returns_outer_record_unchanged() {
        let outer_record = fdr_record(&calibration_blob(MODULE_SERIAL));
        let input = fdr_data([
            ("FSCl-SYNTHETICMODULE001", Value::Data(outer_record.clone())),
            ("Unrelated", Value::String("ignored".into())),
        ]);

        let selected = select_fdr_calibration(&input, MODULE_SERIAL).unwrap();

        assert_eq!(selected.as_bytes(), outer_record);
        assert!(format!("{selected:?}").contains("[redacted]"));
        assert!(!format!("{selected:?}").contains("SYNTHETIC"));
    }

    #[test]
    fn selects_exact_module_record_from_apple_xml_form() {
        let outer_record = fdr_record(&calibration_blob(MODULE_SERIAL));
        let encoded = encode_base64(&outer_record);
        let input = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
             <plist version=\"1.0\">\n<dict>\n\
             <key>FSCl-SYNTHETICMODULE001</key>\n<data>{encoded}</data>\n\
             </dict>\n</plist>\n"
        );

        let selected = select_fdr_calibration(input.as_bytes(), MODULE_SERIAL).unwrap();

        assert_eq!(selected.as_bytes(), outer_record);
    }

    #[test]
    fn matching_sources_collapse_only_byte_identical_records() {
        let record = FdrCalibrationRecord {
            bytes: vec![1, 2, 3],
        };
        assert_eq!(
            select_matching_record(vec![record.clone(), record.clone()])
                .unwrap()
                .as_bytes(),
            [1, 2, 3]
        );
        assert_eq!(
            select_matching_record(vec![
                record,
                FdrCalibrationRecord {
                    bytes: vec![1, 2, 4],
                },
            ]),
            Err(MatchingRecordSelectionError::ConflictingRecords { count: 2 })
        );
        assert_eq!(
            select_matching_record(Vec::new()),
            Err(MatchingRecordSelectionError::NoMatchingRecord)
        );
    }

    #[test]
    fn matching_source_errors_are_redaction_safe() {
        for error in [
            MatchingRecordSelectionError::NoMatchingRecord,
            MatchingRecordSelectionError::ConflictingRecords { count: 2 },
        ] {
            let diagnostic = format!("{error:?} {error}");
            assert!(!diagnostic.contains("SYNTHETIC"));
        }
    }

    #[test]
    fn different_module_and_missing_key_have_reference_failure() {
        let record = fdr_record(&calibration_blob(MODULE_SERIAL));
        let input = fdr_data([("FSCl-SYNTHETICMODULE001", Value::Data(record))]);

        assert_eq!(
            select_fdr_calibration(&input, OTHER_MODULE),
            Err(Error::MissingModuleRecord)
        );
        assert_eq!(
            select_fdr_calibration(&fdr_data([]), MODULE_SERIAL),
            Err(Error::MissingModuleRecord)
        );
    }

    #[test]
    fn rejects_invalid_live_module_serial_without_disclosing_it() {
        let input = fdr_data([]);
        for serial in [
            &b"TOO-SHORT"[..],
            &b"syntheticmodule001"[..],
            &b"SYNTHETICMODULE-01"[..],
            &b"SYNTHETICMODULE\x801"[..],
        ] {
            let error = select_fdr_calibration(&input, serial).unwrap_err();
            let diagnostic = format!("{error:?} {error}");
            assert!(!diagnostic.contains("synthetic"));
            assert!(!diagnostic.contains("SYNTHETIC"));
        }
    }

    #[test]
    fn rejects_wrong_root_and_selected_value_types() {
        let array = bplist::encode(&Value::Array(Vec::new())).unwrap();
        assert_eq!(
            select_fdr_calibration(&array, MODULE_SERIAL),
            Err(Error::RootNotDictionary)
        );

        for value in [Value::Null, Value::String("opaque?".into())] {
            let input = fdr_data([("FSCl-SYNTHETICMODULE001", value)]);
            assert_eq!(
                select_fdr_calibration(&input, MODULE_SERIAL),
                Err(Error::InvalidModuleRecordType)
            );
        }
    }

    #[test]
    fn rejects_malformed_or_non_plists() {
        for input in [&b"not a plist"[..], &b"bplist00"[..]] {
            assert!(matches!(
                select_fdr_calibration(input, MODULE_SERIAL),
                Err(Error::InvalidBinaryPlist(_))
            ));
        }
    }

    #[test]
    fn rejects_malformed_der_and_calibration() {
        let malformed_der = fdr_data([(
            "FSCl-SYNTHETICMODULE001",
            Value::Data(vec![0x30, 0x02, 0x16]),
        )]);
        assert!(matches!(
            select_fdr_calibration(&malformed_der, MODULE_SERIAL),
            Err(Error::InvalidCalibration(_))
        ));

        let mut malformed_calibration = calibration_blob(MODULE_SERIAL);
        malformed_calibration[16..20].copy_from_slice(b"NOPE");
        let input = fdr_data([(
            "FSCl-SYNTHETICMODULE001",
            Value::Data(fdr_record(&malformed_calibration)),
        )]);
        assert!(matches!(
            select_fdr_calibration(&input, MODULE_SERIAL),
            Err(Error::InvalidCalibration(
                CalibrationError::MissingCalibrationMarker
            ))
        ));
    }

    #[test]
    fn rejects_record_bound_to_a_different_module() {
        let input = fdr_data([(
            "FSCl-SYNTHETICMODULE001",
            Value::Data(fdr_record(&calibration_blob(OTHER_MODULE))),
        )]);

        assert!(matches!(
            select_fdr_calibration(&input, MODULE_SERIAL),
            Err(Error::InvalidCalibration(CalibrationError::DifferentModule))
        ));
    }

    #[test]
    fn enforces_input_and_record_size_bounds() {
        let oversized_input = vec![0; MAX_FDR_INPUT_SIZE + 1];
        assert_eq!(
            select_fdr_calibration(&oversized_input, MODULE_SERIAL),
            Err(Error::InputTooLarge {
                actual: MAX_FDR_INPUT_SIZE + 1,
                maximum: MAX_FDR_INPUT_SIZE,
            })
        );

        let oversized_record = vec![0; MAX_FDR_RECORD_SIZE + 1];
        assert_eq!(
            validate_record(&oversized_record, MODULE_SERIAL),
            Err(Error::RecordTooLarge {
                actual: MAX_FDR_RECORD_SIZE + 1,
                maximum: MAX_FDR_RECORD_SIZE,
            })
        );
    }

    #[test]
    fn error_debug_and_display_do_not_include_serial_or_record_bytes() {
        let mut bad = calibration_blob(MODULE_SERIAL);
        bad[16..20].copy_from_slice(b"NOPE");
        let record = fdr_record(&bad);
        let input = fdr_data([("FSCl-SYNTHETICMODULE001", Value::Data(record.clone()))]);

        let error = select_fdr_calibration(&input, MODULE_SERIAL).unwrap_err();
        let diagnostic = format!("{error:?} {error}");
        assert!(!diagnostic.contains("SYNTHETICMODULE001"));
        assert!(!diagnostic.contains(&format!("{record:?}")));
    }

    fn fdr_data<const N: usize>(entries: [(&str, Value); N]) -> Vec<u8> {
        let values = entries
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect::<BTreeMap<_, _>>();
        bplist::encode(&Value::Dictionary(values)).unwrap()
    }

    fn calibration_blob(module_serial: &[u8; MODULE_SERIAL_NUMBER_SIZE]) -> Vec<u8> {
        let mut calibration = vec![0_u8; 96];
        let size = u32::try_from(calibration.len()).unwrap();
        calibration[4..8].copy_from_slice(&size.to_le_bytes());
        calibration[16..20].copy_from_slice(b"CALB");
        calibration[32..32 + module_serial.len()].copy_from_slice(module_serial);
        calibration
    }

    fn fdr_record(calibration: &[u8]) -> Vec<u8> {
        let im4p = der_sequence(&[
            der(0x16, b"IM4P"),
            der(0x16, b"FSCl"),
            der(0x16, b"1.0"),
            der(0x04, calibration),
        ]);
        let img4 = der_sequence(&[der(0x16, b"IMG4"), im4p]);
        let fdrd = der_sequence(&[der(0x16, b"fdrd"), der(0x04, &img4)]);
        der_sequence(&[der(0x16, b"comb"), fdrd])
    }

    fn encode_base64(input: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut output = String::with_capacity(input.len().div_ceil(3) * 4);
        for chunk in input.chunks(3) {
            let first = chunk[0];
            let second = chunk.get(1).copied().unwrap_or(0);
            let third = chunk.get(2).copied().unwrap_or(0);
            output.push(char::from(ALPHABET[usize::from(first >> 2)]));
            output.push(char::from(
                ALPHABET[usize::from((first & 0x03) << 4 | second >> 4)],
            ));
            output.push(if chunk.len() > 1 {
                char::from(ALPHABET[usize::from((second & 0x0f) << 2 | third >> 6)])
            } else {
                '='
            });
            output.push(if chunk.len() > 2 {
                char::from(ALPHABET[usize::from(third & 0x3f)])
            } else {
                '='
            });
        }
        output
    }

    fn der_sequence(children: &[Vec<u8>]) -> Vec<u8> {
        let content = children.concat();
        der(0x30, &content)
    }

    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut output = vec![tag];
        encode_der_length(content.len(), &mut output);
        output.extend_from_slice(content);
        output
    }

    fn encode_der_length(length: usize, output: &mut Vec<u8>) {
        if length < 0x80 {
            output.push(u8::try_from(length).unwrap());
            return;
        }
        let bytes = length.to_be_bytes();
        let first = bytes.iter().position(|byte| *byte != 0).unwrap();
        let encoded = &bytes[first..];
        output.push(0x80 | u8::try_from(encoded.len()).unwrap());
        output.extend_from_slice(encoded);
    }
}

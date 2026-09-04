//! Validation of device-bound T1 factory calibration records.
//!
//! Calibration contents are opaque. This module validates only the framing,
//! embedded size, format marker, and association with the live sensor module.

use core::fmt;

/// Byte length of the module serial returned by Mesa.
pub const MODULE_SERIAL_NUMBER_SIZE: usize = 18;

const DER_SEQUENCE: u8 = 0x30;
const DER_OCTET_STRING: u8 = 0x04;
const DER_IA5_STRING: u8 = 0x16;
const CALIBRATION_MINIMUM_SIZE: usize = 20;
const CALIBRATION_MARKER_OFFSET: usize = 16;
const CALIBRATION_MARKER: &[u8; 4] = b"CALB";

/// A malformed or incorrectly associated calibration record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CalibrationError {
    /// A DER tag or its first length octet is incomplete.
    TruncatedDerElement,
    /// DER indefinite length or a length wider than four octets was used.
    UnsupportedDerLength,
    /// A declared long-form DER length is incomplete.
    TruncatedDerLength,
    /// A long-form DER length contains a redundant leading zero.
    NonMinimalDerLength,
    /// Long-form DER was used for a value below 128 bytes.
    NonMinimalDerLongLength,
    /// A DER element's content is shorter than its declared length.
    TruncatedDerContent,
    /// A top-level object is not exactly one DER sequence.
    IncompleteDerSequence,
    /// An IMG4 envelope identifier or version is not the expected value.
    UnexpectedImg4Envelope,
    /// The Combined record has no nested `fdrd` sequence.
    MissingFdrdContainer,
    /// The `fdrd` container has no IMG4 octet string.
    MissingImg4Object,
    /// The IMG4 object has no nested IM4P sequence.
    MissingIm4pObject,
    /// The `FSCl` IM4P object has no calibration octet string.
    MissingCalibrationPayload,
    /// The inner calibration blob is too short to contain its header.
    TruncatedCalibrationBlob {
        /// Observed byte length.
        actual: usize,
    },
    /// The calibration header's size does not equal the blob length.
    CalibrationSizeMismatch {
        /// Size declared in the calibration header.
        declared: u32,
        /// Observed byte length.
        actual: usize,
    },
    /// The inner calibration blob does not contain its format marker.
    MissingCalibrationMarker,
    /// The supplied module serial is not exactly 18 bytes.
    InvalidModuleSerialLength {
        /// Observed byte length.
        actual: usize,
    },
    /// The calibration does not contain the supplied module serial.
    DifferentModule,
}

impl fmt::Display for CalibrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TruncatedDerElement => formatter.write_str("truncated FDR DER element"),
            Self::UnsupportedDerLength => formatter.write_str("unsupported FDR DER length"),
            Self::TruncatedDerLength => formatter.write_str("truncated FDR DER length"),
            Self::NonMinimalDerLength => formatter.write_str("non-minimal FDR DER length"),
            Self::NonMinimalDerLongLength => formatter.write_str("non-minimal FDR DER long length"),
            Self::TruncatedDerContent => formatter.write_str("truncated FDR DER content"),
            Self::IncompleteDerSequence => {
                formatter.write_str("FDR object is not one complete DER sequence")
            }
            Self::UnexpectedImg4Envelope => {
                formatter.write_str("FDR calibration has an unexpected IMG4 envelope")
            }
            Self::MissingFdrdContainer => formatter.write_str("FDRData has no fdrd container"),
            Self::MissingImg4Object => formatter.write_str("FDRData has no IMG4 object"),
            Self::MissingIm4pObject => formatter.write_str("FDRData has no IM4P object"),
            Self::MissingCalibrationPayload => {
                formatter.write_str("FDR FSCl object has no calibration payload")
            }
            Self::TruncatedCalibrationBlob { actual } => write!(
                formatter,
                "calibration blob is truncated ({actual} bytes; minimum is {CALIBRATION_MINIMUM_SIZE})"
            ),
            Self::CalibrationSizeMismatch { declared, actual } => write!(
                formatter,
                "calibration blob size does not match its embedded length (declared {declared} bytes; got {actual})"
            ),
            Self::MissingCalibrationMarker => {
                formatter.write_str("calibration blob does not contain a CALB header")
            }
            Self::InvalidModuleSerialLength { actual } => write!(
                formatter,
                "invalid module serial for calibration validation ({actual} bytes; expected {MODULE_SERIAL_NUMBER_SIZE})"
            ),
            Self::DifferentModule => {
                formatter.write_str("calibration blob is bound to a different module")
            }
        }
    }
}

impl std::error::Error for CalibrationError {}

#[derive(Clone, Copy)]
struct DerElement<'a> {
    tag: u8,
    content: &'a [u8],
}

struct DerSequence<'a> {
    content: &'a [u8],
    offset: usize,
}

impl<'a> DerSequence<'a> {
    fn read_exact(data: &'a [u8]) -> Result<Self, CalibrationError> {
        let (element, end) = read_der_element(data, 0)?;
        if element.tag != DER_SEQUENCE || end != data.len() {
            return Err(CalibrationError::IncompleteDerSequence);
        }
        Ok(Self::from_content(element.content))
    }

    const fn from_content(content: &'a [u8]) -> Self {
        Self { content, offset: 0 }
    }

    fn next(&mut self) -> Result<Option<DerElement<'a>>, CalibrationError> {
        if self.offset == self.content.len() {
            return Ok(None);
        }
        let (element, end) = read_der_element(self.content, self.offset)?;
        self.offset = end;
        Ok(Some(element))
    }

    fn validate_remaining(mut self) -> Result<(), CalibrationError> {
        while self.next()?.is_some() {}
        Ok(())
    }
}

/// Validates an inner CALB blob and its association with a sensor module.
///
/// The blob itself remains opaque. Validation checks its minimum header size,
/// embedded little-endian byte length, `CALB` marker, and presence of the
/// exact 18-byte module serial.
///
/// # Errors
///
/// Returns an error when the blob header is malformed, the module serial has
/// the wrong length, or the blob belongs to another module.
pub fn validate_calibration_blob(
    calibration: &[u8],
    module_serial: &[u8],
) -> Result<(), CalibrationError> {
    if calibration.len() < CALIBRATION_MINIMUM_SIZE {
        return Err(CalibrationError::TruncatedCalibrationBlob {
            actual: calibration.len(),
        });
    }

    let declared_size = u32::from_le_bytes([
        calibration[4],
        calibration[5],
        calibration[6],
        calibration[7],
    ]);
    if usize::try_from(declared_size) != Ok(calibration.len()) {
        return Err(CalibrationError::CalibrationSizeMismatch {
            declared: declared_size,
            actual: calibration.len(),
        });
    }

    if &calibration[CALIBRATION_MARKER_OFFSET..CALIBRATION_MARKER_OFFSET + 4] != CALIBRATION_MARKER
    {
        return Err(CalibrationError::MissingCalibrationMarker);
    }
    if module_serial.len() != MODULE_SERIAL_NUMBER_SIZE {
        return Err(CalibrationError::InvalidModuleSerialLength {
            actual: module_serial.len(),
        });
    }
    if !calibration
        .windows(MODULE_SERIAL_NUMBER_SIZE)
        .any(|candidate| candidate == module_serial)
    {
        return Err(CalibrationError::DifferentModule);
    }
    Ok(())
}

/// Validates a Combined `FSCl` FDR record and returns its borrowed inner CALB.
///
/// The required envelope is:
/// `comb` -> `fdrd` -> IMG4 octet string -> `IMG4` -> IM4P sequence ->
/// `IM4P`, `FSCl`, `1.0`, CALB octet string. Additional well-formed elements
/// are tolerated, matching the native record parser, but malformed trailing
/// DER is rejected.
///
/// # Errors
///
/// Returns an error for malformed DER, an unexpected envelope, a malformed
/// CALB header, or a record associated with a different module.
pub fn validate_fdr_calibration_record<'a>(
    record: &'a [u8],
    module_serial: &[u8],
) -> Result<&'a [u8], CalibrationError> {
    let mut container = DerSequence::read_exact(record)?;
    let container_kind = container.next()?;
    let fdrd_container = container.next()?;
    container.validate_remaining()?;

    require_der_value(container_kind, DER_IA5_STRING, b"comb")?;
    let fdrd_container =
        require_tag(fdrd_container, DER_SEQUENCE).ok_or(CalibrationError::MissingFdrdContainer)?;

    let mut fdrd = DerSequence::from_content(fdrd_container.content);
    let fdrd_kind = fdrd.next()?;
    let img4_object = fdrd.next()?;
    fdrd.validate_remaining()?;

    require_der_value(fdrd_kind, DER_IA5_STRING, b"fdrd")?;
    let img4_object =
        require_tag(img4_object, DER_OCTET_STRING).ok_or(CalibrationError::MissingImg4Object)?;

    let mut img4 = DerSequence::read_exact(img4_object.content)?;
    let img4_kind = img4.next()?;
    let im4p_object = img4.next()?;
    img4.validate_remaining()?;

    require_der_value(img4_kind, DER_IA5_STRING, b"IMG4")?;
    let im4p_object =
        require_tag(im4p_object, DER_SEQUENCE).ok_or(CalibrationError::MissingIm4pObject)?;

    let mut im4p = DerSequence::from_content(im4p_object.content);
    let im4p_kind = im4p.next()?;
    let payload_kind = im4p.next()?;
    let version = im4p.next()?;
    let calibration = im4p.next()?;
    im4p.validate_remaining()?;

    require_der_value(im4p_kind, DER_IA5_STRING, b"IM4P")?;
    require_der_value(payload_kind, DER_IA5_STRING, b"FSCl")?;
    require_der_value(version, DER_IA5_STRING, b"1.0")?;
    let calibration = require_tag(calibration, DER_OCTET_STRING)
        .ok_or(CalibrationError::MissingCalibrationPayload)?;

    validate_calibration_blob(calibration.content, module_serial)?;
    Ok(calibration.content)
}

fn require_der_value(
    element: Option<DerElement<'_>>,
    expected_tag: u8,
    expected_value: &[u8],
) -> Result<(), CalibrationError> {
    match element {
        Some(element) if element.tag == expected_tag && element.content == expected_value => Ok(()),
        Some(_) | None => Err(CalibrationError::UnexpectedImg4Envelope),
    }
}

fn require_tag(element: Option<DerElement<'_>>, expected_tag: u8) -> Option<DerElement<'_>> {
    element.filter(|element| element.tag == expected_tag)
}

fn read_der_element(
    data: &[u8],
    offset: usize,
) -> Result<(DerElement<'_>, usize), CalibrationError> {
    let tag = *data
        .get(offset)
        .ok_or(CalibrationError::TruncatedDerElement)?;
    let length_octet_offset = offset
        .checked_add(1)
        .ok_or(CalibrationError::TruncatedDerElement)?;
    let length_octet = *data
        .get(length_octet_offset)
        .ok_or(CalibrationError::TruncatedDerElement)?;

    let (length, header_size) = if length_octet & 0x80 == 0 {
        (usize::from(length_octet), 2_usize)
    } else {
        let length_size = usize::from(length_octet & 0x7f);
        if length_size == 0 || length_size > 4 {
            return Err(CalibrationError::UnsupportedDerLength);
        }
        let length_start = offset
            .checked_add(2)
            .ok_or(CalibrationError::TruncatedDerLength)?;
        let length_end = length_start
            .checked_add(length_size)
            .ok_or(CalibrationError::TruncatedDerLength)?;
        let length_bytes = data
            .get(length_start..length_end)
            .ok_or(CalibrationError::TruncatedDerLength)?;
        if length_bytes[0] == 0 {
            return Err(CalibrationError::NonMinimalDerLength);
        }

        let length = length_bytes
            .iter()
            .fold(0_u32, |value, byte| (value << 8) | u32::from(*byte));
        if length < 0x80 {
            return Err(CalibrationError::NonMinimalDerLongLength);
        }
        (
            usize::try_from(length).map_err(|_| CalibrationError::TruncatedDerContent)?,
            2 + length_size,
        )
    };

    let content_start = offset
        .checked_add(header_size)
        .ok_or(CalibrationError::TruncatedDerContent)?;
    let content_end = content_start
        .checked_add(length)
        .ok_or(CalibrationError::TruncatedDerContent)?;
    let content = data
        .get(content_start..content_end)
        .ok_or(CalibrationError::TruncatedDerContent)?;
    Ok((DerElement { tag, content }, content_end))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MODULE_SERIAL: &[u8; MODULE_SERIAL_NUMBER_SIZE] = b"SYNTHETICMODULE001";
    const OTHER_MODULE: &[u8; MODULE_SERIAL_NUMBER_SIZE] = b"SYNTHETICMODULE002";

    #[test]
    fn accepts_exact_combined_fscl_record_and_returns_inner_blob() {
        let calibration = calibration_blob(96, MODULE_SERIAL);
        let record = fdr_record(&calibration);

        assert_eq!(
            validate_fdr_calibration_record(&record, MODULE_SERIAL),
            Ok(calibration.as_slice())
        );
    }

    #[test]
    fn accepts_well_formed_extra_envelope_elements() {
        let calibration = calibration_blob(96, MODULE_SERIAL);
        let record = fdr_record_with_extra_elements(&calibration);

        assert_eq!(
            validate_fdr_calibration_record(&record, MODULE_SERIAL),
            Ok(calibration.as_slice())
        );
    }

    #[test]
    fn accepts_der_short_and_long_length_boundaries() {
        let short = der(DER_OCTET_STRING, &[0x5a; 127]);
        assert_eq!(short[1], 127);
        assert_eq!(
            read_der_element(&short, 0).map(|(item, end)| (item.content.len(), end)),
            Ok((127, 129))
        );

        let long = der(DER_OCTET_STRING, &[0x5a; 128]);
        assert_eq!(&long[1..3], &[0x81, 0x80]);
        assert_eq!(
            read_der_element(&long, 0).map(|(item, end)| (item.content.len(), end)),
            Ok((128, 131))
        );

        let two_octet = der(DER_OCTET_STRING, &vec![0x5a; 256]);
        assert_eq!(&two_octet[1..4], &[0x82, 0x01, 0x00]);
        assert_eq!(
            read_der_element(&two_octet, 0).map(|(item, _)| item.content.len()),
            Ok(256)
        );
    }

    #[test]
    fn rejects_truncated_der_tag_or_length_octet() {
        assert_eq!(
            DerSequence::read_exact(&[]).map(drop),
            Err(CalibrationError::TruncatedDerElement)
        );
        assert_eq!(
            DerSequence::read_exact(&[DER_SEQUENCE]).map(drop),
            Err(CalibrationError::TruncatedDerElement)
        );
    }

    #[test]
    fn rejects_indefinite_and_wider_than_u32_der_lengths() {
        for bytes in [
            &[DER_SEQUENCE, 0x80][..],
            &[DER_SEQUENCE, 0x85, 1, 0, 0, 0, 0][..],
        ] {
            assert_eq!(
                DerSequence::read_exact(bytes).map(drop),
                Err(CalibrationError::UnsupportedDerLength)
            );
        }
    }

    #[test]
    fn rejects_truncated_long_form_der_length() {
        assert_eq!(
            DerSequence::read_exact(&[DER_SEQUENCE, 0x82, 0x01]).map(drop),
            Err(CalibrationError::TruncatedDerLength)
        );
    }

    #[test]
    fn rejects_non_minimal_der_lengths() {
        assert_eq!(
            DerSequence::read_exact(&[DER_SEQUENCE, 0x82, 0x00, 0x80]).map(drop),
            Err(CalibrationError::NonMinimalDerLength)
        );
        assert_eq!(
            DerSequence::read_exact(&[DER_SEQUENCE, 0x81, 0x7f]).map(drop),
            Err(CalibrationError::NonMinimalDerLongLength)
        );
    }

    #[test]
    fn rejects_truncated_der_content() {
        assert_eq!(
            DerSequence::read_exact(&[DER_SEQUENCE, 3, DER_IA5_STRING, 0]).map(drop),
            Err(CalibrationError::TruncatedDerContent)
        );
    }

    #[test]
    fn rejects_non_sequence_and_top_level_trailing_data() {
        assert_eq!(
            DerSequence::read_exact(&[DER_OCTET_STRING, 0]).map(drop),
            Err(CalibrationError::IncompleteDerSequence)
        );
        assert_eq!(
            DerSequence::read_exact(&[DER_SEQUENCE, 0, 0]).map(drop),
            Err(CalibrationError::IncompleteDerSequence)
        );
    }

    #[test]
    fn rejects_malformed_trailing_child_data() {
        let calibration = calibration_blob(96, MODULE_SERIAL);
        let valid = fdr_record(&calibration);
        let (_, content_end) = read_der_element(&valid, 0).unwrap();
        assert_eq!(content_end, valid.len());

        let mut outer_content = DerSequence::read_exact(&valid).unwrap().content.to_vec();
        outer_content.push(DER_OCTET_STRING);
        let record = der(DER_SEQUENCE, &outer_content);
        assert_eq!(
            validate_fdr_calibration_record(&record, MODULE_SERIAL),
            Err(CalibrationError::TruncatedDerElement)
        );
    }

    #[test]
    fn rejects_wrong_envelope_values_and_tags() {
        let calibration = calibration_blob(96, MODULE_SERIAL);
        let cases = [
            envelope(
                b"wrong",
                b"fdrd",
                b"IMG4",
                b"IM4P",
                b"FSCl",
                b"1.0",
                DER_OCTET_STRING,
                &calibration,
            ),
            envelope(
                b"comb",
                b"wrong",
                b"IMG4",
                b"IM4P",
                b"FSCl",
                b"1.0",
                DER_OCTET_STRING,
                &calibration,
            ),
            envelope(
                b"comb",
                b"fdrd",
                b"wrong",
                b"IM4P",
                b"FSCl",
                b"1.0",
                DER_OCTET_STRING,
                &calibration,
            ),
            envelope(
                b"comb",
                b"fdrd",
                b"IMG4",
                b"wrong",
                b"FSCl",
                b"1.0",
                DER_OCTET_STRING,
                &calibration,
            ),
            envelope(
                b"comb",
                b"fdrd",
                b"IMG4",
                b"IM4P",
                b"wrong",
                b"1.0",
                DER_OCTET_STRING,
                &calibration,
            ),
            envelope(
                b"comb",
                b"fdrd",
                b"IMG4",
                b"IM4P",
                b"FSCl",
                b"2.0",
                DER_OCTET_STRING,
                &calibration,
            ),
        ];
        for record in cases {
            assert_eq!(
                validate_fdr_calibration_record(&record, MODULE_SERIAL),
                Err(CalibrationError::UnexpectedImg4Envelope)
            );
        }

        let wrong_payload_tag = envelope(
            b"comb",
            b"fdrd",
            b"IMG4",
            b"IM4P",
            b"FSCl",
            b"1.0",
            DER_IA5_STRING,
            &calibration,
        );
        assert_eq!(
            validate_fdr_calibration_record(&wrong_payload_tag, MODULE_SERIAL),
            Err(CalibrationError::MissingCalibrationPayload)
        );
    }

    #[test]
    fn rejects_missing_nested_objects() {
        let no_fdrd = der(DER_SEQUENCE, &der(DER_IA5_STRING, b"comb"));
        assert_eq!(
            validate_fdr_calibration_record(&no_fdrd, MODULE_SERIAL),
            Err(CalibrationError::MissingFdrdContainer)
        );

        let fdrd = der(DER_SEQUENCE, &der(DER_IA5_STRING, b"fdrd"));
        let no_img4 = der(DER_SEQUENCE, &[der(DER_IA5_STRING, b"comb"), fdrd].concat());
        assert_eq!(
            validate_fdr_calibration_record(&no_img4, MODULE_SERIAL),
            Err(CalibrationError::MissingImg4Object)
        );

        let img4 = der(DER_SEQUENCE, &der(DER_IA5_STRING, b"IMG4"));
        let no_im4p = wrap_img4(&img4);
        assert_eq!(
            validate_fdr_calibration_record(&no_im4p, MODULE_SERIAL),
            Err(CalibrationError::MissingIm4pObject)
        );

        let im4p = der(
            DER_SEQUENCE,
            &[
                der(DER_IA5_STRING, b"IM4P"),
                der(DER_IA5_STRING, b"FSCl"),
                der(DER_IA5_STRING, b"1.0"),
            ]
            .concat(),
        );
        let no_payload = wrap_img4(&der(
            DER_SEQUENCE,
            &[der(DER_IA5_STRING, b"IMG4"), im4p].concat(),
        ));
        assert_eq!(
            validate_fdr_calibration_record(&no_payload, MODULE_SERIAL),
            Err(CalibrationError::MissingCalibrationPayload)
        );
    }

    #[test]
    fn validates_calibration_minimum_and_embedded_size_boundaries() {
        let too_short = vec![0_u8; CALIBRATION_MINIMUM_SIZE - 1];
        assert_eq!(
            validate_calibration_blob(&too_short, MODULE_SERIAL),
            Err(CalibrationError::TruncatedCalibrationBlob {
                actual: CALIBRATION_MINIMUM_SIZE - 1
            })
        );

        let mut minimum = calibration_blob(
            CALIBRATION_MINIMUM_SIZE + MODULE_SERIAL_NUMBER_SIZE,
            MODULE_SERIAL,
        );
        assert_eq!(validate_calibration_blob(&minimum, MODULE_SERIAL), Ok(()));

        minimum[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            validate_calibration_blob(&minimum, MODULE_SERIAL),
            Err(CalibrationError::CalibrationSizeMismatch {
                declared: u32::MAX,
                actual: CALIBRATION_MINIMUM_SIZE + MODULE_SERIAL_NUMBER_SIZE,
            })
        );
    }

    #[test]
    fn rejects_missing_marker_wrong_serial_length_and_different_module() {
        let mut calibration = calibration_blob(96, MODULE_SERIAL);
        calibration[CALIBRATION_MARKER_OFFSET] ^= 0xff;
        assert_eq!(
            validate_calibration_blob(&calibration, MODULE_SERIAL),
            Err(CalibrationError::MissingCalibrationMarker)
        );

        let calibration = calibration_blob(96, MODULE_SERIAL);
        assert_eq!(
            validate_calibration_blob(&calibration, &MODULE_SERIAL[..17]),
            Err(CalibrationError::InvalidModuleSerialLength { actual: 17 })
        );
        assert_eq!(
            validate_calibration_blob(&calibration, OTHER_MODULE),
            Err(CalibrationError::DifferentModule)
        );
    }

    #[test]
    fn errors_do_not_disclose_payload_or_module_contents() {
        let calibration = calibration_blob(96, MODULE_SERIAL);
        let error = validate_calibration_blob(&calibration, OTHER_MODULE)
            .unwrap_err()
            .to_string();
        assert!(!error.contains("SYNTHETIC"));
        assert!(!error.contains("CALB"));
    }

    fn calibration_blob(size: usize, module_serial: &[u8]) -> Vec<u8> {
        assert!(size >= CALIBRATION_MINIMUM_SIZE + module_serial.len());
        let mut calibration = vec![0_u8; size];
        calibration[4..8].copy_from_slice(&u32::try_from(size).unwrap().to_le_bytes());
        calibration[CALIBRATION_MARKER_OFFSET..CALIBRATION_MARKER_OFFSET + 4]
            .copy_from_slice(CALIBRATION_MARKER);
        let serial_offset = CALIBRATION_MINIMUM_SIZE;
        calibration[serial_offset..serial_offset + module_serial.len()]
            .copy_from_slice(module_serial);
        calibration
    }

    fn fdr_record(calibration: &[u8]) -> Vec<u8> {
        envelope(
            b"comb",
            b"fdrd",
            b"IMG4",
            b"IM4P",
            b"FSCl",
            b"1.0",
            DER_OCTET_STRING,
            calibration,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn envelope(
        container_kind: &[u8],
        fdrd_kind: &[u8],
        img4_kind: &[u8],
        im4p_kind: &[u8],
        payload_kind: &[u8],
        version: &[u8],
        calibration_tag: u8,
        calibration: &[u8],
    ) -> Vec<u8> {
        let im4p = der(
            DER_SEQUENCE,
            &[
                der(DER_IA5_STRING, im4p_kind),
                der(DER_IA5_STRING, payload_kind),
                der(DER_IA5_STRING, version),
                der(calibration_tag, calibration),
            ]
            .concat(),
        );
        let img4 = der(
            DER_SEQUENCE,
            &[der(DER_IA5_STRING, img4_kind), im4p].concat(),
        );
        let fdrd = der(
            DER_SEQUENCE,
            &[der(DER_IA5_STRING, fdrd_kind), der(DER_OCTET_STRING, &img4)].concat(),
        );
        der(
            DER_SEQUENCE,
            &[der(DER_IA5_STRING, container_kind), fdrd].concat(),
        )
    }

    fn wrap_img4(img4: &[u8]) -> Vec<u8> {
        let fdrd = der(
            DER_SEQUENCE,
            &[der(DER_IA5_STRING, b"fdrd"), der(DER_OCTET_STRING, img4)].concat(),
        );
        der(DER_SEQUENCE, &[der(DER_IA5_STRING, b"comb"), fdrd].concat())
    }

    fn fdr_record_with_extra_elements(calibration: &[u8]) -> Vec<u8> {
        let im4p = der(
            DER_SEQUENCE,
            &[
                der(DER_IA5_STRING, b"IM4P"),
                der(DER_IA5_STRING, b"FSCl"),
                der(DER_IA5_STRING, b"1.0"),
                der(DER_OCTET_STRING, calibration),
                der(DER_OCTET_STRING, b"extra-im4p"),
            ]
            .concat(),
        );
        let img4 = der(
            DER_SEQUENCE,
            &[
                der(DER_IA5_STRING, b"IMG4"),
                im4p,
                der(DER_OCTET_STRING, b"extra-img4"),
            ]
            .concat(),
        );
        let fdrd = der(
            DER_SEQUENCE,
            &[
                der(DER_IA5_STRING, b"fdrd"),
                der(DER_OCTET_STRING, &img4),
                der(DER_OCTET_STRING, b"extra-fdrd"),
            ]
            .concat(),
        );
        der(
            DER_SEQUENCE,
            &[
                der(DER_IA5_STRING, b"comb"),
                fdrd,
                der(DER_OCTET_STRING, b"extra-comb"),
            ]
            .concat(),
        )
    }

    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(content.len() + 6);
        encoded.push(tag);
        encode_der_length(content.len(), &mut encoded);
        encoded.extend_from_slice(content);
        encoded
    }

    fn encode_der_length(length: usize, output: &mut Vec<u8>) {
        if length < 0x80 {
            output.push(u8::try_from(length).unwrap());
            return;
        }

        let bytes = length.to_be_bytes();
        let first = bytes.iter().position(|byte| *byte != 0).unwrap();
        let significant = &bytes[first..];
        output.push(0x80 | u8::try_from(significant.len()).unwrap());
        output.extend_from_slice(significant);
    }
}

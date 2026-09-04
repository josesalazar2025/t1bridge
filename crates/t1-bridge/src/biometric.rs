//! `BiometricKit` command headers and small fixed-layout response parsers.

use crate::calibration::MODULE_SERIAL_NUMBER_SIZE;
use core::fmt;

/// Magic at the start of each `BiometricKit` command header.
pub const BIOMETRIC_MAGIC: u16 = 0x4d42;
/// Protocol version used by the T1 `BiometricKit` service.
pub const BIOMETRIC_PROTOCOL_VERSION: u16 = 1;
/// Bridge method ordinal carrying a `BiometricKit` command.
pub const BIOMETRIC_BRIDGE_COMMAND: u64 = 0;
/// Encoded byte length of a `BiometricKit` command header.
pub const COMMAND_HEADER_SIZE: usize = 8;
/// Encoded byte length of the daemon-info response.
pub const DAEMON_INFO_SIZE: usize = 23;
/// Defensive upper bound for catacomb components reported by Mesa.
pub const MAX_CATACOMB_COMPONENTS: u32 = 64;

/// A `BiometricKit` command code.
///
/// The newtype preserves unknown codes for later protocol slices without
/// weakening the type of a command header to an unrelated integer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandCode(u16);

impl CommandCode {
    /// Reads Mesa's calibration status byte.
    pub const GET_CALIBRATION_STATUS: Self = Self(0x1d);
    /// Reads the sensor module's serial used for FDR association.
    pub const GET_MODULE_SERIAL_NUMBER: Self = Self(0x22);
    /// Reads Mesa daemon and catacomb metadata.
    pub const GET_DAEMON_INFO: Self = Self(0x28);
    /// Reads whether the xART service is available.
    pub const IS_XART_AVAILABLE: Self = Self(0x4c);

    /// Creates a command code for another documented `BiometricKit` operation.
    #[must_use]
    pub const fn from_raw(value: u16) -> Self {
        Self(value)
    }

    /// Returns the command's protocol value.
    #[must_use]
    pub const fn as_raw(self) -> u16 {
        self.0
    }
}

/// The fixed header prepended to a `BiometricKit` command payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandHeader {
    command: CommandCode,
    version: u16,
    value: u16,
}

impl CommandHeader {
    /// Creates a version-one command header with a zero value field.
    #[must_use]
    pub const fn new(command: CommandCode) -> Self {
        Self {
            command,
            version: BIOMETRIC_PROTOCOL_VERSION,
            value: 0,
        }
    }

    /// Creates a command header with explicit protocol fields.
    #[must_use]
    pub const fn with_parameters(command: CommandCode, version: u16, value: u16) -> Self {
        Self {
            command,
            version,
            value,
        }
    }

    /// Returns the command code.
    #[must_use]
    pub const fn command(self) -> CommandCode {
        self.command
    }

    /// Returns the protocol version.
    #[must_use]
    pub const fn version(self) -> u16 {
        self.version
    }

    /// Returns the operation-specific value.
    #[must_use]
    pub const fn value(self) -> u16 {
        self.value
    }

    /// Encodes the header in its exact little-endian wire layout.
    #[must_use]
    pub fn encode(self) -> [u8; COMMAND_HEADER_SIZE] {
        let mut bytes = [0_u8; COMMAND_HEADER_SIZE];
        bytes[0..2].copy_from_slice(&BIOMETRIC_MAGIC.to_le_bytes());
        bytes[2..4].copy_from_slice(&self.command.0.to_le_bytes());
        bytes[4..6].copy_from_slice(&self.version.to_le_bytes());
        bytes[6..8].copy_from_slice(&self.value.to_le_bytes());
        bytes
    }
}

/// A validated module serial returned by Mesa.
///
/// Its bytes are intentionally omitted from `Debug` output. Callers may use
/// [`Self::as_bytes`] only where the opaque value is needed for device-bound
/// calibration lookup or validation.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct ModuleSerial([u8; MODULE_SERIAL_NUMBER_SIZE]);

impl ModuleSerial {
    /// Returns the opaque validated serial bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; MODULE_SERIAL_NUMBER_SIZE] {
        &self.0
    }
}

impl fmt::Debug for ModuleSerial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ModuleSerial([redacted])")
    }
}

/// Validated metadata from Mesa's daemon-info response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DaemonInfo {
    /// Number of reported catacomb components.
    pub component_count: u32,
    /// Maximum number of enrolled identities.
    pub identity_capacity: u32,
    /// Whether runtime calibration data has been loaded.
    pub calibration_data_loaded: bool,
}

/// Identifies which fixed-layout response failed validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseKind {
    /// Calibration status byte.
    CalibrationStatus,
    /// xART availability flag.
    XartAvailability,
    /// Sensor module serial.
    ModuleSerial,
    /// Mesa daemon metadata.
    DaemonInfo,
}

impl fmt::Display for ResponseKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CalibrationStatus => formatter.write_str("calibration-status"),
            Self::XartAvailability => formatter.write_str("xART-availability"),
            Self::ModuleSerial => formatter.write_str("module-serial"),
            Self::DaemonInfo => formatter.write_str("daemon-info"),
        }
    }
}

/// A malformed fixed-layout `BiometricKit` response.
///
/// Variants deliberately retain only structural metadata, never response
/// payload bytes or module identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseError {
    /// The response was not the operation's exact fixed length.
    InvalidLength {
        /// Response being parsed.
        response: ResponseKind,
        /// Required byte length.
        expected: usize,
        /// Observed byte length.
        actual: usize,
    },
    /// The xART flag was neither zero nor one.
    InvalidXartAvailability,
    /// The module serial contained bytes outside uppercase ASCII letters and digits.
    InvalidModuleSerial,
    /// Mesa reported more catacomb components than the parser permits.
    ImplausibleComponentCount {
        /// Reported component count.
        actual: u32,
        /// Parser limit.
        maximum: u32,
    },
    /// The daemon-info calibration-loaded flag was neither zero nor one.
    InvalidCalibrationLoadedFlag,
}

impl fmt::Display for ResponseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength {
                response,
                expected,
                actual,
            } => write!(
                formatter,
                "{response} response is {actual} bytes; expected {expected}"
            ),
            Self::InvalidXartAvailability => {
                formatter.write_str("invalid xART-availability response")
            }
            Self::InvalidModuleSerial => {
                formatter.write_str("module serial contains unexpected bytes")
            }
            Self::ImplausibleComponentCount { actual, maximum } => write!(
                formatter,
                "refusing implausible catacomb component count {actual}; maximum is {maximum}"
            ),
            Self::InvalidCalibrationLoadedFlag => {
                formatter.write_str("invalid calibration-loaded flag in daemon-info response")
            }
        }
    }
}

impl std::error::Error for ResponseError {}

/// Parses Mesa's one-byte calibration status.
///
/// # Errors
///
/// Returns [`ResponseError::InvalidLength`] unless `response` is exactly one
/// byte.
pub fn parse_calibration_status(response: &[u8]) -> Result<u8, ResponseError> {
    require_length(response, 1, ResponseKind::CalibrationStatus)?;
    Ok(response[0])
}

/// Parses Mesa's strict zero-or-one xART availability flag.
///
/// # Errors
///
/// Returns an error unless `response` is exactly one byte containing zero or
/// one.
pub fn parse_xart_available(response: &[u8]) -> Result<bool, ResponseError> {
    require_length(response, 1, ResponseKind::XartAvailability)?;
    match response[0] {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(ResponseError::InvalidXartAvailability),
    }
}

/// Parses and validates Mesa's opaque 18-byte module serial.
///
/// # Errors
///
/// Returns an error unless the response is exactly 18 bytes containing only
/// uppercase ASCII letters and digits.
pub fn parse_module_serial(response: &[u8]) -> Result<ModuleSerial, ResponseError> {
    require_length(
        response,
        MODULE_SERIAL_NUMBER_SIZE,
        ResponseKind::ModuleSerial,
    )?;
    if !response
        .iter()
        .all(|byte| byte.is_ascii_digit() || byte.is_ascii_uppercase())
    {
        return Err(ResponseError::InvalidModuleSerial);
    }

    let mut serial = [0_u8; MODULE_SERIAL_NUMBER_SIZE];
    serial.copy_from_slice(response);
    Ok(ModuleSerial(serial))
}

/// Parses and validates Mesa's fixed-size daemon metadata.
///
/// # Errors
///
/// Returns an error for the wrong response length, an implausible catacomb
/// component count, or a calibration-loaded flag other than zero or one.
pub fn parse_daemon_info(response: &[u8]) -> Result<DaemonInfo, ResponseError> {
    require_length(response, DAEMON_INFO_SIZE, ResponseKind::DaemonInfo)?;
    let component_count = read_daemon_u32(response, 0)?;
    if component_count > MAX_CATACOMB_COMPONENTS {
        return Err(ResponseError::ImplausibleComponentCount {
            actual: component_count,
            maximum: MAX_CATACOMB_COMPONENTS,
        });
    }
    let identity_capacity = read_daemon_u32(response, 4)?;
    let calibration_flag = response
        .get(22)
        .copied()
        .ok_or_else(|| daemon_info_length_error(response))?;
    let calibration_data_loaded = match calibration_flag {
        0 => false,
        1 => true,
        _ => return Err(ResponseError::InvalidCalibrationLoadedFlag),
    };

    Ok(DaemonInfo {
        component_count,
        identity_capacity,
        calibration_data_loaded,
    })
}

fn read_daemon_u32(response: &[u8], offset: usize) -> Result<u32, ResponseError> {
    let bytes = response
        .get(offset..offset + 4)
        .and_then(|value| <[u8; 4]>::try_from(value).ok())
        .ok_or_else(|| daemon_info_length_error(response))?;
    Ok(u32::from_le_bytes(bytes))
}

fn daemon_info_length_error(response: &[u8]) -> ResponseError {
    ResponseError::InvalidLength {
        response: ResponseKind::DaemonInfo,
        expected: DAEMON_INFO_SIZE,
        actual: response.len(),
    }
}

fn require_length(
    response: &[u8],
    expected: usize,
    response_kind: ResponseKind,
) -> Result<(), ResponseError> {
    if response.len() != expected {
        return Err(ResponseError::InvalidLength {
            response: response_kind,
            expected,
            actual: response.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SYNTHETIC_SERIAL: &[u8; MODULE_SERIAL_NUMBER_SIZE] = b"SYNTHETICMODULE001";

    #[test]
    fn command_header_matches_the_little_endian_wire_layout() {
        let header = CommandHeader::new(CommandCode::GET_CALIBRATION_STATUS);
        assert_eq!(
            header.encode(),
            [0x42, 0x4d, 0x1d, 0x00, 0x01, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn command_header_preserves_explicit_version_and_value() {
        let command = CommandCode::from_raw(0x20);
        let header = CommandHeader::with_parameters(command, 2, 3);
        assert_eq!(header.command(), command);
        assert_eq!(header.version(), 2);
        assert_eq!(header.value(), 3);
        assert_eq!(
            header.encode(),
            [0x42, 0x4d, 0x20, 0x00, 0x02, 0x00, 0x03, 0x00]
        );
    }

    #[test]
    fn calibration_status_requires_exactly_one_byte() {
        assert_eq!(parse_calibration_status(&[0xa5]), Ok(0xa5));
        assert_eq!(
            parse_calibration_status(&[]),
            Err(ResponseError::InvalidLength {
                response: ResponseKind::CalibrationStatus,
                expected: 1,
                actual: 0,
            })
        );
        assert!(parse_calibration_status(&[0, 1]).is_err());
    }

    #[test]
    fn xart_availability_accepts_only_exact_boolean_encodings() {
        assert_eq!(parse_xart_available(&[0]), Ok(false));
        assert_eq!(parse_xart_available(&[1]), Ok(true));
        assert_eq!(
            parse_xart_available(&[2]),
            Err(ResponseError::InvalidXartAvailability)
        );
        assert!(parse_xart_available(&[]).is_err());
        assert!(parse_xart_available(&[1, 0]).is_err());
    }

    #[test]
    fn module_serial_is_validated_and_debug_redacted() {
        let serial = parse_module_serial(SYNTHETIC_SERIAL).unwrap();
        assert_eq!(serial.as_bytes(), SYNTHETIC_SERIAL);
        assert_eq!(format!("{serial:?}"), "ModuleSerial([redacted])");

        assert_eq!(
            parse_module_serial(b"syntheticmodule001"),
            Err(ResponseError::InvalidModuleSerial)
        );
        assert!(parse_module_serial(b"SYNTHETICMODULE01").is_err());
    }

    #[test]
    fn daemon_info_decodes_metadata_and_runtime_calibration_flag() {
        let mut response = [0_u8; DAEMON_INFO_SIZE];
        response[0..4].copy_from_slice(&2_u32.to_le_bytes());
        response[4..8].copy_from_slice(&5_u32.to_le_bytes());
        response[22] = 1;

        assert_eq!(
            parse_daemon_info(&response),
            Ok(DaemonInfo {
                component_count: 2,
                identity_capacity: 5,
                calibration_data_loaded: true,
            })
        );
    }

    #[test]
    fn daemon_info_rejects_malformed_metadata() {
        assert!(parse_daemon_info(&[0; DAEMON_INFO_SIZE - 1]).is_err());

        let mut response = [0_u8; DAEMON_INFO_SIZE];
        response[0..4].copy_from_slice(&(MAX_CATACOMB_COMPONENTS + 1).to_le_bytes());
        assert_eq!(
            parse_daemon_info(&response),
            Err(ResponseError::ImplausibleComponentCount {
                actual: MAX_CATACOMB_COMPONENTS + 1,
                maximum: MAX_CATACOMB_COMPONENTS,
            })
        );

        response[0..4].copy_from_slice(&0_u32.to_le_bytes());
        response[22] = 2;
        assert_eq!(
            parse_daemon_info(&response),
            Err(ResponseError::InvalidCalibrationLoadedFlag)
        );
    }

    #[test]
    fn errors_do_not_disclose_response_payloads_or_module_identity() {
        let serial_error = parse_module_serial(b"SYNTHETICMODULE00!")
            .unwrap_err()
            .to_string();
        assert!(!serial_error.contains("SYNTHETIC"));
        assert!(!serial_error.contains('!'));

        let xart_error = parse_xart_available(&[0xa5]).unwrap_err().to_string();
        assert!(!xart_error.contains("a5"));
        assert!(!xart_error.contains("165"));
    }
}

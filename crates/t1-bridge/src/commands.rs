//! Exact `BiometricKit` command packets used by the `T1Bridge` control plane.
//!
//! Each explicit builder keeps a request together with the response capacity
//! passed to `BridgeXPC`. Opaque calibration and catacomb bytes are copied
//! unchanged and are never included in diagnostics.

use crate::biometric::{CommandCode, CommandHeader, DAEMON_INFO_SIZE};
use crate::calibration::MODULE_SERIAL_NUMBER_SIZE;
use crate::catacomb::{
    CATACOMB_HASH_RESPONSE_SIZE, CATACOMB_ID_SIZE, SECURE_CATACOMB_SIZE_RESPONSE_SIZE,
    TEMPLATE_LIST_CRC_SIZE, catacomb_state_response_capacity, validate_secure_catacomb,
    validate_secure_catacomb_size,
};
use crate::mesa::{IDENTITY_V1_SIZE, Identity};
use crate::policy::{
    AUTHORIZATION_SIZE, BiometricUserId, PolicyError, SYSTEM_CONFIGURATION_SIZE,
    SystemPolicyTarget, USER_CONFIGURATION_SIZE, encode_authorization, encode_system_update,
    encode_user_update,
};
use core::fmt;
use t1_platform::secret;

/// Maximum number of identity records requested from Mesa.
pub const MAX_IDENTITIES: usize = 5;
/// Maximum byte capacity of an identity-list response.
pub const IDENTITY_LIST_CAPACITY: usize = MAX_IDENTITIES * IDENTITY_V1_SIZE;
/// Calibration-data ceiling enforced by the behavioral reference.
pub const MAX_CALIBRATION_DATA_SIZE: usize = 16 * 1024 * 1024 - 8;

const EMPTY_RESPONSE_CAPACITY: usize = 0;
const BOOLEAN_RESPONSE_CAPACITY: usize = 1;
const SKS_LOCK_STATE_RESPONSE_SIZE: usize = size_of::<u32>();
const START_ENROLLMENT_DESCRIPTOR_SIZE: usize = 2 * size_of::<u32>() + AUTHORIZATION_SIZE;
const START_MATCH_DESCRIPTOR_SIZE: usize = 0x44;

const RESET: CommandCode = CommandCode::from_raw(0x02);
const START_ENROLLMENT: CommandCode = CommandCode::from_raw(0x03);
const START_MATCH: CommandCode = CommandCode::from_raw(0x04);
const CANCEL_OPERATION: CommandCode = CommandCode::from_raw(0x0c);
const REMOVE_IDENTITY: CommandCode = CommandCode::from_raw(0x0d);
const CONTINUE_ENROLLMENT: CommandCode = CommandCode::from_raw(0x0e);
const LOAD_CALIBRATION: CommandCode = CommandCode::from_raw(0x20);
const GET_SKS_LOCK_STATE: CommandCode = CommandCode::from_raw(0x27);
const GET_USER_PROTECTED_CONFIGURATION: CommandCode = CommandCode::from_raw(0x2e);
const SET_USER_PROTECTED_CONFIGURATION: CommandCode = CommandCode::from_raw(0x2f);
const SET_ACTIVE_USER: CommandCode = CommandCode::from_raw(0x31);
const GET_CATACOMB_ID: CommandCode = CommandCode::from_raw(0x38);
const GET_CATACOMB_HASH: CommandCode = CommandCode::from_raw(0x3a);
const GET_CATACOMB_STATE: CommandCode = CommandCode::from_raw(0x3c);
const GET_SECURE_CATACOMB_SIZE: CommandCode = CommandCode::from_raw(0x3d);
const SAVE_SECURE_CATACOMB: CommandCode = CommandCode::from_raw(0x3e);
const FINISH_SAVE_SECURE_CATACOMB: CommandCode = CommandCode::from_raw(0x3f);
const LOAD_SECURE_CATACOMB: CommandCode = CommandCode::from_raw(0x40);
const GET_IDENTITIES: CommandCode = CommandCode::from_raw(0x42);
const GET_SYSTEM_PROTECTED_CONFIGURATION: CommandCode = CommandCode::from_raw(0x43);
const SET_SYSTEM_PROTECTED_CONFIGURATION: CommandCode = CommandCode::from_raw(0x44);
const GET_TEMPLATE_LIST_CRC: CommandCode = CommandCode::from_raw(0x47);
const REMOVE_USER: CommandCode = CommandCode::from_raw(0x48);
const FORCE_BIOLOCKOUT: CommandCode = CommandCode::from_raw(0x49);

/// Source selector placed in Mesa's calibration command header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum CalibrationSource {
    /// System-configuration calibration.
    SystemConfiguration = 1,
    /// Sensor EEPROM calibration.
    Eeprom = 2,
    /// Device-bound FDR calibration record.
    Fdr = 3,
}

/// One encoded command and its exact `BridgeXPC` response allocation.
#[derive(Clone, Eq, PartialEq)]
pub struct CommandPacket {
    request: Vec<u8>,
    response_capacity: usize,
    wipe_on_drop: bool,
}

impl CommandPacket {
    /// Returns the bytes sent to the `BiometricKit` bridge method.
    #[must_use]
    pub fn request(&self) -> &[u8] {
        &self.request
    }

    /// Returns the exact response allocation requested from `BridgeXPC`.
    #[must_use]
    pub const fn response_capacity(&self) -> usize {
        self.response_capacity
    }
}

impl fmt::Debug for CommandPacket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandPacket")
            .field("request_len", &self.request.len())
            .field("request", &"[redacted]")
            .field("response_capacity", &self.response_capacity)
            .finish_non_exhaustive()
    }
}

impl Drop for CommandPacket {
    fn drop(&mut self) {
        if self.wipe_on_drop {
            secret::wipe(&mut self.request);
        }
    }
}

/// Identifies a fixed-layout command response without retaining its bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandResponseKind {
    /// Four-byte Secure Key Store lock state.
    SksLockState,
}

impl fmt::Display for CommandResponseKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SksLockState => formatter.write_str("SKS lock-state"),
        }
    }
}

/// A packet input or response with an invalid structural shape.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommandError {
    /// A calibration record exceeded the behavioral reference's ceiling.
    CalibrationDataTooLarge {
        /// Observed record length.
        actual: usize,
        /// Largest accepted record length.
        maximum: usize,
    },
    /// A no-output command returned data.
    UnexpectedResponseData {
        /// Observed response length.
        actual: usize,
    },
    /// A fixed-size response did not have its exact native length.
    InvalidResponseLength {
        /// Response being decoded.
        response: CommandResponseKind,
        /// Required length.
        expected: usize,
        /// Observed length.
        actual: usize,
    },
    /// The identity list ended partway through a packed record.
    MisalignedIdentityList {
        /// Observed response length.
        actual: usize,
        /// Native identity-record size.
        record_size: usize,
    },
    /// The identity list exceeded Mesa's requested five-record capacity.
    IdentityListExceedsCapacity {
        /// Observed response length.
        actual: usize,
        /// Maximum requested response length.
        capacity: usize,
    },
    /// A policy payload or biometric user ID was invalid.
    Policy(PolicyError),
    /// A secure-catacomb size or payload was invalid.
    Catacomb(crate::catacomb::CatacombError),
}

impl fmt::Display for CommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CalibrationDataTooLarge { actual, maximum } => write!(
                formatter,
                "calibration record is {actual} bytes; maximum is {maximum}"
            ),
            Self::UnexpectedResponseData { actual } => write!(
                formatter,
                "no-output command unexpectedly returned {actual} bytes"
            ),
            Self::InvalidResponseLength {
                response,
                expected,
                actual,
            } => write!(
                formatter,
                "{response} response is {actual} bytes; expected {expected}"
            ),
            Self::MisalignedIdentityList {
                actual,
                record_size,
            } => write!(
                formatter,
                "identity-list response is {actual} bytes; record size is {record_size}"
            ),
            Self::IdentityListExceedsCapacity { actual, capacity } => write!(
                formatter,
                "identity-list response is {actual} bytes; capacity is {capacity}"
            ),
            Self::Policy(error) => error.fmt(formatter),
            Self::Catacomb(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for CommandError {}

impl From<PolicyError> for CommandError {
    fn from(error: PolicyError) -> Self {
        Self::Policy(error)
    }
}

impl From<crate::catacomb::CatacombError> for CommandError {
    fn from(error: crate::catacomb::CatacombError) -> Self {
        Self::Catacomb(error)
    }
}

/// Builds Mesa's read-only calibration-status command.
#[must_use]
pub fn calibration_status_command() -> CommandPacket {
    command(
        CommandCode::GET_CALIBRATION_STATUS,
        BOOLEAN_RESPONSE_CAPACITY,
    )
}

/// Builds Mesa's read-only xART-availability command.
#[must_use]
pub fn xart_available_command() -> CommandPacket {
    command(CommandCode::IS_XART_AVAILABLE, BOOLEAN_RESPONSE_CAPACITY)
}

/// Builds Mesa's read-only module-serial command.
#[must_use]
pub fn module_serial_command() -> CommandPacket {
    command(
        CommandCode::GET_MODULE_SERIAL_NUMBER,
        MODULE_SERIAL_NUMBER_SIZE,
    )
}

/// Builds Mesa's read-only daemon-info command.
#[must_use]
pub fn daemon_info_command() -> CommandPacket {
    command(CommandCode::GET_DAEMON_INFO, DAEMON_INFO_SIZE)
}

/// Builds Mesa's calibration-load command and preserves the record unchanged.
///
/// Validation of the CALB or FDR structure and module association belongs to
/// the calibration parser and must happen before this encoder is called.
///
/// # Errors
///
/// Returns an error when the record exceeds the behavioral reference's bound.
pub fn load_calibration_command(
    source: CalibrationSource,
    calibration: &[u8],
) -> Result<CommandPacket, CommandError> {
    if calibration.len() > MAX_CALIBRATION_DATA_SIZE {
        return Err(CommandError::CalibrationDataTooLarge {
            actual: calibration.len(),
            maximum: MAX_CALIBRATION_DATA_SIZE,
        });
    }
    Ok(command_with_value_and_payload(
        LOAD_CALIBRATION,
        source as u16,
        calibration,
        EMPTY_RESPONSE_CAPACITY,
    ))
}

/// Builds Mesa's live sensor reset command.
#[must_use]
pub fn reset_sensor_command() -> CommandPacket {
    command(RESET, EMPTY_RESPONSE_CAPACITY)
}

/// Builds Mesa's per-user SKS lock-state command.
#[must_use]
pub fn sks_lock_state_command(user_id: BiometricUserId) -> CommandPacket {
    user_command(
        GET_SKS_LOCK_STATE,
        user_id.as_raw(),
        SKS_LOCK_STATE_RESPONSE_SIZE,
    )
}

/// Builds Mesa's read-only system protected-configuration command.
#[must_use]
pub fn system_configuration_command() -> CommandPacket {
    command(
        GET_SYSTEM_PROTECTED_CONFIGURATION,
        SYSTEM_CONFIGURATION_SIZE,
    )
}

/// Builds Mesa's system protected-configuration setter.
///
/// # Errors
///
/// Returns an error when a present ACM credential is not exactly 16 bytes.
pub fn set_system_configuration_command(
    target: SystemPolicyTarget,
    credential_set: Option<&[u8]>,
) -> Result<CommandPacket, CommandError> {
    let mut update = encode_system_update(target, credential_set)?;
    let packet = command_with_sensitive_payload(
        SET_SYSTEM_PROTECTED_CONFIGURATION,
        &update,
        EMPTY_RESPONSE_CAPACITY,
        credential_set.is_some(),
    );
    if credential_set.is_some() {
        secret::wipe(&mut update);
    }
    Ok(packet)
}

/// Builds Mesa's read-only per-user protected-configuration command.
#[must_use]
pub fn user_configuration_command(user_id: BiometricUserId) -> CommandPacket {
    user_command(
        GET_USER_PROTECTED_CONFIGURATION,
        user_id.as_raw(),
        USER_CONFIGURATION_SIZE,
    )
}

/// Builds Mesa's per-user protected-configuration setter.
///
/// # Errors
///
/// Returns an error for an unrecognized policy value or malformed credential.
pub fn set_user_configuration_command(
    user_id: BiometricUserId,
    requested: [i32; 4],
    credential_set: Option<&[u8]>,
) -> Result<CommandPacket, CommandError> {
    let mut update = encode_user_update(user_id, requested, credential_set)?;
    let packet = command_with_sensitive_payload(
        SET_USER_PROTECTED_CONFIGURATION,
        &update,
        EMPTY_RESPONSE_CAPACITY,
        credential_set.is_some(),
    );
    if credential_set.is_some() {
        secret::wipe(&mut update);
    }
    Ok(packet)
}

/// Builds Mesa's bounded identity-list command for one user.
#[must_use]
pub fn identities_command(user_id: BiometricUserId) -> CommandPacket {
    user_command(GET_IDENTITIES, user_id.as_raw(), IDENTITY_LIST_CAPACITY)
}

/// Builds Mesa's per-identity removal command from a validated identity record.
///
/// The caller must persist Mesa's catacomb after the command succeeds.
#[must_use]
pub fn remove_identity_command(identity: Identity) -> CommandPacket {
    let mut descriptor = [0_u8; IDENTITY_V1_SIZE];
    descriptor[..size_of::<u32>()]
        .copy_from_slice(&identity.user_id().cast_unsigned().to_le_bytes());
    descriptor[size_of::<u32>()..].copy_from_slice(&identity.identifier());
    command_with_payload(REMOVE_IDENTITY, &descriptor, EMPTY_RESPONSE_CAPACITY)
}

/// Builds Mesa's active-user selection command.
///
/// `-1` is Mesa's master component. Concrete users occupy the non-negative
/// signed 32-bit range.
///
/// # Errors
///
/// Returns an error outside `-1..=i32::MAX`.
pub fn set_active_user_command(user_id: i64) -> Result<CommandPacket, CommandError> {
    let raw_user = active_user_wire_value(user_id)?;
    Ok(user_command(
        SET_ACTIVE_USER,
        raw_user,
        EMPTY_RESPONSE_CAPACITY,
    ))
}

/// Builds Mesa's guarded biometric-user removal command.
#[must_use]
pub fn remove_user_command(user_id: BiometricUserId) -> CommandPacket {
    user_command(REMOVE_USER, user_id.as_raw(), EMPTY_RESPONSE_CAPACITY)
}

/// Builds Mesa's read-only catacomb-ID command.
#[must_use]
pub fn catacomb_id_command(user_id: BiometricUserId) -> CommandPacket {
    user_command(GET_CATACOMB_ID, user_id.as_raw(), CATACOMB_ID_SIZE)
}

/// Builds Mesa's read-only optional catacomb-hash command.
#[must_use]
pub fn catacomb_hash_command(user_id: BiometricUserId) -> CommandPacket {
    user_command(
        GET_CATACOMB_HASH,
        user_id.as_raw(),
        CATACOMB_HASH_RESPONSE_SIZE,
    )
}

/// Builds Mesa's read-only template-list CRC command.
#[must_use]
pub fn template_list_crc_command(user_id: BiometricUserId) -> CommandPacket {
    user_command(
        GET_TEMPLATE_LIST_CRC,
        user_id.as_raw(),
        TEMPLATE_LIST_CRC_SIZE,
    )
}

/// Builds Mesa's catacomb component-state command.
///
/// # Errors
///
/// Returns an error when the reported component count is implausible or its
/// response allocation overflows.
pub fn catacomb_states_command(component_count: u32) -> Result<CommandPacket, CommandError> {
    let capacity = catacomb_state_response_capacity(component_count)?;
    Ok(command(GET_CATACOMB_STATE, capacity))
}

/// Builds Mesa's secure-catacomb size command for a concrete or master user.
///
/// # Errors
///
/// Returns an error when the user is outside `-1..=i32::MAX`.
pub fn secure_catacomb_size_command(user_id: i64) -> Result<CommandPacket, CommandError> {
    catacomb_user_command(
        GET_SECURE_CATACOMB_SIZE,
        user_id,
        SECURE_CATACOMB_SIZE_RESPONSE_SIZE,
    )
}

/// Builds Mesa's secure-catacomb export command with its preceding size as the
/// exact `BridgeXPC` response allocation.
///
/// # Errors
///
/// Returns an error for an invalid user or export size.
pub fn save_secure_catacomb_command(
    user_id: i64,
    export_size: usize,
) -> Result<CommandPacket, CommandError> {
    validate_secure_catacomb_size(export_size)?;
    catacomb_user_command(SAVE_SECURE_CATACOMB, user_id, export_size)
}

/// Builds Mesa's post-commit secure-catacomb finish command.
///
/// # Errors
///
/// Returns an error when the user is outside `-1..=i32::MAX`.
pub fn finish_save_secure_catacomb_command(user_id: i64) -> Result<CommandPacket, CommandError> {
    catacomb_user_command(
        FINISH_SAVE_SECURE_CATACOMB,
        user_id,
        EMPTY_RESPONSE_CAPACITY,
    )
}

/// Builds Mesa's opaque secure-catacomb load command.
///
/// # Errors
///
/// Returns an error when the opaque payload is empty or above the protocol
/// ceiling.
pub fn load_secure_catacomb_command(data: &[u8]) -> Result<CommandPacket, CommandError> {
    let catacomb = validate_secure_catacomb(data)?;
    Ok(secret_command_with_payload(
        LOAD_SECURE_CATACOMB,
        catacomb.as_bytes(),
        EMPTY_RESPONSE_CAPACITY,
    ))
}

/// Builds the native 56-byte enrollment-start command.
///
/// # Errors
///
/// Returns an error when a present ACM credential is not exactly 16 bytes.
pub fn start_enrollment_command(
    user_id: BiometricUserId,
    credential_set: Option<&[u8]>,
) -> Result<CommandPacket, CommandError> {
    let mut authorization = encode_authorization(credential_set)?;
    let mut descriptor = [0_u8; START_ENROLLMENT_DESCRIPTOR_SIZE];
    descriptor[4..8].copy_from_slice(&user_id.as_raw().to_le_bytes());
    descriptor[8..].copy_from_slice(&authorization);
    let packet = command_with_sensitive_value_and_payload(
        START_ENROLLMENT,
        1,
        &descriptor,
        EMPTY_RESPONSE_CAPACITY,
        credential_set.is_some(),
    );
    if credential_set.is_some() {
        secret::wipe(&mut authorization);
        secret::wipe(&mut descriptor);
    }
    Ok(packet)
}

/// Builds Mesa's enrollment-continue command.
#[must_use]
pub fn continue_enrollment_command() -> CommandPacket {
    command(CONTINUE_ENROLLMENT, EMPTY_RESPONSE_CAPACITY)
}

/// Builds the native 76-byte default match-start command.
#[must_use]
pub fn start_match_command(user_id: BiometricUserId) -> CommandPacket {
    let mut descriptor = [0_u8; START_MATCH_DESCRIPTOR_SIZE];
    descriptor[4..8].copy_from_slice(&user_id.as_raw().to_le_bytes());
    command_with_payload(START_MATCH, &descriptor, EMPTY_RESPONSE_CAPACITY)
}

/// Builds Mesa's operation-cancellation command.
#[must_use]
pub fn cancel_operation_command() -> CommandPacket {
    command(CANCEL_OPERATION, EMPTY_RESPONSE_CAPACITY)
}

/// Builds Mesa's per-user biometric lockout command.
#[must_use]
pub fn force_biolockout_command(user_id: BiometricUserId) -> CommandPacket {
    user_command(FORCE_BIOLOCKOUT, user_id.as_raw(), EMPTY_RESPONSE_CAPACITY)
}

/// Validates the response to any command whose native output capacity is zero.
///
/// # Errors
///
/// Returns an error containing only the unexpected byte count when data was
/// returned.
pub fn validate_empty_response(response: &[u8]) -> Result<(), CommandError> {
    if response.is_empty() {
        Ok(())
    } else {
        Err(CommandError::UnexpectedResponseData {
            actual: response.len(),
        })
    }
}

/// Parses Mesa's exact four-byte little-endian SKS lock state.
///
/// # Errors
///
/// Returns an error unless the response is exactly four bytes.
pub fn parse_sks_lock_state(response: &[u8]) -> Result<u32, CommandError> {
    if response.len() != SKS_LOCK_STATE_RESPONSE_SIZE {
        return Err(CommandError::InvalidResponseLength {
            response: CommandResponseKind::SksLockState,
            expected: SKS_LOCK_STATE_RESPONSE_SIZE,
            actual: response.len(),
        });
    }
    let mut encoded = [0_u8; SKS_LOCK_STATE_RESPONSE_SIZE];
    encoded.copy_from_slice(response);
    Ok(u32::from_le_bytes(encoded))
}

/// Validates a zero-to-five-record packed identity-list response.
///
/// Individual record semantics remain owned by [`crate::mesa::parse_identity`].
///
/// # Errors
///
/// Returns an error for a partial record or a response above the requested
/// five-record capacity.
pub fn validate_identity_list_response(response: &[u8]) -> Result<(), CommandError> {
    if !response.len().is_multiple_of(IDENTITY_V1_SIZE) {
        return Err(CommandError::MisalignedIdentityList {
            actual: response.len(),
            record_size: IDENTITY_V1_SIZE,
        });
    }
    if response.len() > IDENTITY_LIST_CAPACITY {
        return Err(CommandError::IdentityListExceedsCapacity {
            actual: response.len(),
            capacity: IDENTITY_LIST_CAPACITY,
        });
    }
    Ok(())
}

fn command(code: CommandCode, response_capacity: usize) -> CommandPacket {
    command_with_payload(code, &[], response_capacity)
}

fn user_command(code: CommandCode, user_id: u32, response_capacity: usize) -> CommandPacket {
    command_with_payload(code, &user_id.to_le_bytes(), response_capacity)
}

fn catacomb_user_command(
    code: CommandCode,
    user_id: i64,
    response_capacity: usize,
) -> Result<CommandPacket, CommandError> {
    let raw_user = active_user_wire_value(user_id)?;
    Ok(user_command(code, raw_user, response_capacity))
}

fn active_user_wire_value(user_id: i64) -> Result<u32, CommandError> {
    if user_id == -1 {
        return Ok(u32::MAX);
    }
    Ok(BiometricUserId::new(user_id)?.as_raw())
}

fn command_with_payload(
    code: CommandCode,
    payload: &[u8],
    response_capacity: usize,
) -> CommandPacket {
    command_with_sensitive_payload(code, payload, response_capacity, false)
}

fn secret_command_with_payload(
    code: CommandCode,
    payload: &[u8],
    response_capacity: usize,
) -> CommandPacket {
    command_with_sensitive_payload(code, payload, response_capacity, true)
}

fn command_with_sensitive_payload(
    code: CommandCode,
    payload: &[u8],
    response_capacity: usize,
    wipe_on_drop: bool,
) -> CommandPacket {
    command_with_sensitive_value_and_payload(code, 0, payload, response_capacity, wipe_on_drop)
}

fn command_with_value_and_payload(
    code: CommandCode,
    value: u16,
    payload: &[u8],
    response_capacity: usize,
) -> CommandPacket {
    command_with_sensitive_value_and_payload(code, value, payload, response_capacity, false)
}

fn command_with_sensitive_value_and_payload(
    code: CommandCode,
    value: u16,
    payload: &[u8],
    response_capacity: usize,
    wipe_on_drop: bool,
) -> CommandPacket {
    let mut request = Vec::with_capacity(CommandHeader::new(code).encode().len() + payload.len());
    request.extend_from_slice(&CommandHeader::with_parameters(code, 1, value).encode());
    request.extend_from_slice(payload);
    CommandPacket {
        request,
        response_capacity,
        wipe_on_drop,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::biometric::{BIOMETRIC_MAGIC, BIOMETRIC_PROTOCOL_VERSION, MAX_CATACOMB_COMPONENTS};
    use crate::catacomb::MAX_SECURE_CATACOMB_SIZE;
    use crate::policy::ACM_CONTEXT_EXTERNAL_FORM_SIZE;

    fn user() -> BiometricUserId {
        BiometricUserId::new(501).expect("synthetic protocol user is valid")
    }

    fn header(packet: &CommandPacket) -> [u16; 4] {
        let bytes = packet.request();
        [
            u16::from_le_bytes(bytes[0..2].try_into().expect("complete magic")),
            u16::from_le_bytes(bytes[2..4].try_into().expect("complete command")),
            u16::from_le_bytes(bytes[4..6].try_into().expect("complete version")),
            u16::from_le_bytes(bytes[6..8].try_into().expect("complete value")),
        ]
    }

    #[test]
    fn read_only_commands_match_native_headers_and_capacities() {
        let cases = [
            (calibration_status_command(), 0x1d, 1),
            (xart_available_command(), 0x4c, 1),
            (module_serial_command(), 0x22, MODULE_SERIAL_NUMBER_SIZE),
            (daemon_info_command(), 0x28, DAEMON_INFO_SIZE),
            (system_configuration_command(), 0x43, 28),
        ];
        for (packet, code, capacity) in cases {
            assert_eq!(
                header(&packet),
                [BIOMETRIC_MAGIC, code, BIOMETRIC_PROTOCOL_VERSION, 0]
            );
            assert_eq!(packet.request().len(), 8);
            assert_eq!(packet.response_capacity(), capacity);
        }
    }

    #[test]
    fn calibration_load_uses_native_source_three_and_opaque_record() {
        let record = b"synthetic validated FDR record";
        let packet = load_calibration_command(CalibrationSource::Fdr, record).unwrap();
        assert_eq!(header(&packet), [BIOMETRIC_MAGIC, 0x20, 1, 3]);
        assert_eq!(&packet.request()[8..], record);
        assert_eq!(packet.response_capacity(), 0);
        assert!(matches!(
            load_calibration_command(
                CalibrationSource::Fdr,
                &vec![0; MAX_CALIBRATION_DATA_SIZE + 1]
            ),
            Err(CommandError::CalibrationDataTooLarge { .. })
        ));
    }

    #[test]
    fn catacomb_metadata_and_state_packets_have_exact_layouts() {
        let cases = [
            (catacomb_id_command(user()), 0x38, CATACOMB_ID_SIZE),
            (
                catacomb_hash_command(user()),
                0x3a,
                CATACOMB_HASH_RESPONSE_SIZE,
            ),
            (
                template_list_crc_command(user()),
                0x47,
                TEMPLATE_LIST_CRC_SIZE,
            ),
        ];
        for (packet, code, capacity) in cases {
            assert_eq!(header(&packet), [BIOMETRIC_MAGIC, code, 1, 0]);
            assert_eq!(&packet.request()[8..], &501_u32.to_le_bytes());
            assert_eq!(packet.response_capacity(), capacity);
        }

        let states = catacomb_states_command(2).unwrap();
        assert_eq!(header(&states), [BIOMETRIC_MAGIC, 0x3c, 1, 0]);
        assert_eq!(states.response_capacity(), 3 * 8);
        assert!(catacomb_states_command(MAX_CATACOMB_COMPONENTS + 1).is_err());
    }

    #[test]
    fn catacomb_export_packets_preserve_user_size_and_opaque_data() {
        let size = secure_catacomb_size_command(501).unwrap();
        assert_eq!(header(&size), [BIOMETRIC_MAGIC, 0x3d, 1, 0]);
        assert_eq!(&size.request()[8..], &501_u32.to_le_bytes());
        assert_eq!(size.response_capacity(), 4);

        let export = save_secure_catacomb_command(-1, 4096).unwrap();
        assert_eq!(header(&export), [BIOMETRIC_MAGIC, 0x3e, 1, 0]);
        assert_eq!(&export.request()[8..], &u32::MAX.to_le_bytes());
        assert_eq!(export.response_capacity(), 4096);

        let finish = finish_save_secure_catacomb_command(-1).unwrap();
        assert_eq!(header(&finish), [BIOMETRIC_MAGIC, 0x3f, 1, 0]);
        assert_eq!(&finish.request()[8..], &u32::MAX.to_le_bytes());
        assert_eq!(finish.response_capacity(), 0);

        let opaque = b"synthetic opaque catacomb";
        let load = load_secure_catacomb_command(opaque).unwrap();
        assert_eq!(header(&load), [BIOMETRIC_MAGIC, 0x40, 1, 0]);
        assert_eq!(&load.request()[8..], opaque);
        assert!(load_secure_catacomb_command(&[]).is_err());
        assert!(save_secure_catacomb_command(501, MAX_SECURE_CATACOMB_SIZE + 1).is_err());
    }

    #[test]
    fn user_selection_and_recovery_packets_encode_master_sentinel() {
        let concrete = set_active_user_command(501).unwrap();
        assert_eq!(&concrete.request()[8..], &501_u32.to_le_bytes());
        let master = set_active_user_command(-1).unwrap();
        assert_eq!(&master.request()[8..], &u32::MAX.to_le_bytes());
        assert!(set_active_user_command(-2).is_err());
        assert!(set_active_user_command(i64::from(i32::MAX) + 1).is_err());

        let remove = remove_user_command(user());
        assert_eq!(header(&remove), [BIOMETRIC_MAGIC, 0x48, 1, 0]);
        assert_eq!(&remove.request()[8..], &501_u32.to_le_bytes());
    }

    #[test]
    fn enrollment_authorization_and_start_packet_match_native_layout() {
        let credential: Vec<u8> = (0..ACM_CONTEXT_EXTERNAL_FORM_SIZE)
            .map(|value| u8::try_from(value).unwrap())
            .collect();
        let packet = start_enrollment_command(user(), Some(&credential)).unwrap();
        assert_eq!(packet.request().len(), 8 + 48);
        assert_eq!(header(&packet), [BIOMETRIC_MAGIC, 0x03, 1, 1]);
        assert_eq!(&packet.request()[8..12], &0_u32.to_le_bytes());
        assert_eq!(&packet.request()[12..16], &501_u32.to_le_bytes());
        assert_eq!(&packet.request()[16..20], &0_u32.to_le_bytes());
        assert_eq!(&packet.request()[20..24], &16_u32.to_le_bytes());
        assert_eq!(&packet.request()[24..40], credential);
        assert_eq!(&packet.request()[40..], &[0_u8; 16]);
        assert_eq!(packet.response_capacity(), 0);

        let nil_packet = start_enrollment_command(user(), None).unwrap();
        assert_eq!(&nil_packet.request()[16..20], &1_u32.to_le_bytes());
        assert_eq!(&nil_packet.request()[20..], &[0_u8; 36]);
        assert!(start_enrollment_command(user(), Some(&[0; 15])).is_err());
    }

    #[test]
    fn enrollment_continue_match_cancel_and_lockout_are_exact() {
        let reset = reset_sensor_command();
        assert_eq!(header(&reset), [BIOMETRIC_MAGIC, 0x02, 1, 0]);
        assert_eq!(reset.request().len(), 8);
        assert_eq!(reset.response_capacity(), 0);

        let continuation = continue_enrollment_command();
        assert_eq!(header(&continuation), [BIOMETRIC_MAGIC, 0x0e, 1, 0]);
        assert_eq!(continuation.request().len(), 8);

        let start = start_match_command(user());
        assert_eq!(header(&start), [BIOMETRIC_MAGIC, 0x04, 1, 0]);
        assert_eq!(start.request().len(), 8 + 0x44);
        assert_eq!(&start.request()[8..12], &0_u32.to_le_bytes());
        assert_eq!(&start.request()[12..16], &501_u32.to_le_bytes());
        assert_eq!(&start.request()[16..], &[0_u8; 60]);

        assert_eq!(
            header(&cancel_operation_command()),
            [BIOMETRIC_MAGIC, 0x0c, 1, 0]
        );
        let lockout = force_biolockout_command(user());
        assert_eq!(header(&lockout), [BIOMETRIC_MAGIC, 0x49, 1, 0]);
        assert_eq!(&lockout.request()[8..], &501_u32.to_le_bytes());

        let sks = sks_lock_state_command(user());
        assert_eq!(header(&sks), [BIOMETRIC_MAGIC, 0x27, 1, 0]);
        assert_eq!(&sks.request()[8..], &501_u32.to_le_bytes());
        assert_eq!(sks.response_capacity(), 4);
    }

    #[test]
    fn policy_packets_join_exact_headers_and_payloads() {
        let credential = [0x5a; ACM_CONTEXT_EXTERNAL_FORM_SIZE];
        let system = set_system_configuration_command(
            SystemPolicyTarget::TouchIdFeatures,
            Some(&credential),
        )
        .unwrap();
        assert_eq!(header(&system), [BIOMETRIC_MAGIC, 0x44, 1, 0]);
        assert_eq!(system.request().len(), 8 + 68);
        assert_eq!(
            &system.request()[8..36],
            [-1_i32, -1, -1, 1, 1, 1, 1]
                .into_iter()
                .flat_map(i32::to_le_bytes)
                .collect::<Vec<_>>()
        );

        let user_read = user_configuration_command(user());
        assert_eq!(header(&user_read), [BIOMETRIC_MAGIC, 0x2e, 1, 0]);
        assert_eq!(&user_read.request()[8..], &501_u32.to_le_bytes());
        assert_eq!(user_read.response_capacity(), 32);

        let user_set =
            set_user_configuration_command(user(), [1, 0, -1, 1], Some(&credential)).unwrap();
        assert_eq!(header(&user_set), [BIOMETRIC_MAGIC, 0x2f, 1, 0]);
        assert_eq!(user_set.request().len(), 68);
        assert_eq!(&user_set.request()[8..12], &501_u32.to_le_bytes());
        assert_eq!(user_set.response_capacity(), 0);
    }

    #[test]
    fn identity_command_and_response_shape_match_native_contract() {
        let packet = identities_command(user());
        assert_eq!(header(&packet), [BIOMETRIC_MAGIC, 0x42, 1, 0]);
        assert_eq!(&packet.request()[8..], &501_u32.to_le_bytes());
        assert_eq!(packet.response_capacity(), 5 * 20);

        assert_eq!(validate_identity_list_response(&[]), Ok(()));
        assert_eq!(validate_identity_list_response(&[0; 20]), Ok(()));
        assert!(matches!(
            validate_identity_list_response(&[0; 21]),
            Err(CommandError::MisalignedIdentityList { .. })
        ));
        assert!(matches!(
            validate_identity_list_response(&[0; 120]),
            Err(CommandError::IdentityListExceedsCapacity { .. })
        ));
    }

    #[test]
    fn identity_removal_uses_validated_record_and_exact_native_layout() {
        let mut record = [0_u8; IDENTITY_V1_SIZE];
        record[..4].copy_from_slice(&501_i32.to_le_bytes());
        record[4..].copy_from_slice(&[
            0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed,
            0xfe, 0x0f,
        ]);
        let identity = crate::mesa::parse_identity(&record).unwrap();

        let packet = remove_identity_command(identity);
        assert_eq!(header(&packet), [BIOMETRIC_MAGIC, 0x0d, 1, 0]);
        assert_eq!(packet.request().len(), 8 + IDENTITY_V1_SIZE);
        assert_eq!(&packet.request()[8..], &record);
        assert_eq!(packet.response_capacity(), 0);

        record[4..].fill(0);
        assert!(matches!(
            crate::mesa::parse_identity(&record),
            Err(crate::mesa::MesaError::ZeroIdentityIdentifier)
        ));
    }

    #[test]
    fn missing_response_validators_are_exact_and_redacted() {
        assert_eq!(validate_empty_response(&[]), Ok(()));
        let opaque = b"sensitive response bytes";
        let error = validate_empty_response(opaque).unwrap_err();
        assert_eq!(
            error,
            CommandError::UnexpectedResponseData {
                actual: opaque.len()
            }
        );
        assert!(!error.to_string().contains("sensitive"));

        assert_eq!(parse_sks_lock_state(&[0x15, 0, 0, 0]), Ok(0x15));
        assert!(matches!(
            parse_sks_lock_state(&[0x15, 0, 0]),
            Err(CommandError::InvalidResponseLength {
                response: CommandResponseKind::SksLockState,
                expected: 4,
                actual: 3,
            })
        ));
    }

    #[test]
    fn command_debug_never_discloses_opaque_request_bytes() {
        let marker = "opaque-secret-marker";
        let packet = load_secure_catacomb_command(marker.as_bytes()).unwrap();
        let debug = format!("{packet:?}");
        assert!(!debug.contains(marker));
        assert!(debug.contains("[redacted]"));
    }
}

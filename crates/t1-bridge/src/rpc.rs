//! Strict `BridgeXPC` RPC envelopes and method payloads.
//!
//! This module maps the behavioral reference's `call`, `call_dictionary`,
//! `perform_biometric_command`, client-version, calibration, and inbound
//! callback contracts. Request-ID generation and transport loops stay with
//! the caller.

use crate::bplist::{self, Value};
use crate::commands::{CommandPacket, MAX_CALIBRATION_DATA_SIZE};
use crate::mesa::ServiceStatusEvent;
use core::fmt;
use std::collections::BTreeMap;

/// RPC protocol version carried in every request and reply envelope.
pub const RPC_PROTOCOL_VERSION: u64 = 1;
/// Objective-C `nil` as serialized by `BridgeXPC`.
pub const BRIDGEXPC_NIL: &str = "d4161201-daf5-4bbd-ae4f-9bf319fabbe0";

const PERFORM_BIOMETRIC_COMMAND_ORDINAL: u64 = 3;
const BIOMETRIC_BRIDGE_COMMAND: u64 = 0;
const SET_CLIENT_VERSION_ORDINAL: u64 = 1;
const SERVICE_STATUS_ORDINALS: [u64; 2] = [9, 10];
const SUCCESS: i128 = 0;
const UNSUPPORTED_METHOD: i128 = 22;
const UUID_HEX: &[u8; 16] = b"0123456789ABCDEF";

/// A request identifier used to correlate RPC messages.
///
/// [`Self::parse`] constructs canonical outbound identifiers. Decoding may
/// also produce an arbitrary bounded peer string, which replies must echo
/// exactly for compatibility with the behavioral reference.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct RequestId(String);

impl RequestId {
    /// Builds a canonical `UUIDv4` request identifier from caller-supplied
    /// random bytes.
    ///
    /// The caller owns entropy acquisition. This function sets the UUID
    /// version and variant bits and performs no I/O.
    #[must_use]
    pub fn from_uuid_v4_bytes(mut bytes: [u8; 16]) -> Self {
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;

        let mut value = String::with_capacity(36);
        for (index, byte) in bytes.into_iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                value.push('-');
            }
            value.push(char::from(UUID_HEX[usize::from(byte >> 4)]));
            value.push(char::from(UUID_HEX[usize::from(byte & 0x0f)]));
        }
        Self(value)
    }

    /// Validates a canonical uppercase UUID supplied by the request-ID owner.
    ///
    /// Generation intentionally remains outside this crate so the daemon can
    /// choose its entropy source.
    ///
    /// # Errors
    ///
    /// Returns [`RpcError::InvalidRequestId`] unless `value` has the exact
    /// `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX` wire form.
    pub fn parse(value: &str) -> Result<Self, RpcError> {
        if !is_canonical_request_id(value) {
            return Err(RpcError::InvalidRequestId);
        }
        Ok(Self(value.to_owned()))
    }

    fn from_wire(value: String) -> Self {
        Self(value)
    }

    /// Returns the exact wire representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RequestId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RequestId([redacted])")
    }
}

/// One decoded four-element RPC envelope.
#[derive(Clone, Eq, PartialEq)]
pub enum RpcEnvelope {
    /// A request from either peer.
    Request {
        /// Correlation identifier to echo in the reply.
        request_id: RequestId,
        /// Method-specific positional payload.
        payload: Vec<Value>,
    },
    /// A reply to an earlier request.
    Reply {
        /// Correlation identifier copied from the request.
        request_id: RequestId,
        /// Method-specific result array.
        result: Vec<Value>,
    },
}

impl RpcEnvelope {
    /// Returns the result only when this is a reply for `expected`.
    #[must_use]
    pub fn matching_reply(&self, expected: &RequestId) -> Option<&[Value]> {
        match self {
            Self::Reply { request_id, result } if request_id == expected => Some(result),
            Self::Request { .. } | Self::Reply { .. } => None,
        }
    }
}

impl fmt::Debug for RpcEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Request {
                request_id,
                payload,
            } => formatter
                .debug_struct("RpcEnvelope::Request")
                .field("request_id", request_id)
                .field("payload_len", &payload.len())
                .field("payload", &"[redacted]")
                .finish(),
            Self::Reply { request_id, result } => formatter
                .debug_struct("RpcEnvelope::Reply")
                .field("request_id", request_id)
                .field("result_len", &result.len())
                .field("result", &"[redacted]")
                .finish(),
        }
    }
}

/// Source selected by the read-only bridge calibration methods.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BridgeCalibrationSource {
    /// RPC ordinal 5.
    Eeprom,
    /// RPC ordinal 11.
    Fdr,
}

impl BridgeCalibrationSource {
    const fn ordinal(self) -> i128 {
        match self {
            Self::Eeprom => 5,
            Self::Fdr => 11,
        }
    }
}

impl fmt::Display for BridgeCalibrationSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Eeprom => formatter.write_str("EEPROM"),
            Self::Fdr => formatter.write_str("FDR"),
        }
    }
}

/// Result of handling one inbound RPC request.
#[derive(Clone, Eq, PartialEq)]
pub struct InboundRequestResult {
    reply: Vec<Value>,
    service_event: Option<ServiceStatusEvent>,
}

impl InboundRequestResult {
    /// Result array to return in the matching reply envelope.
    #[must_use]
    pub fn reply(&self) -> &[Value] {
        &self.reply
    }

    /// Validated service-status event, if this was callback ordinal 9 or 10.
    #[must_use]
    pub const fn service_event(&self) -> Option<&ServiceStatusEvent> {
        self.service_event.as_ref()
    }

    /// Takes the validated service-status event for queueing by the caller.
    #[must_use]
    pub fn into_service_event(self) -> Option<ServiceStatusEvent> {
        self.service_event
    }
}

impl fmt::Debug for InboundRequestResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InboundRequestResult")
            .field("reply", &self.reply)
            .field("has_service_event", &self.service_event.is_some())
            .field("service_event", &"[redacted]")
            .finish()
    }
}

/// A malformed RPC envelope or method-specific payload.
///
/// Errors retain only protocol metadata. They never retain request, result,
/// callback, calibration, or biometric bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RpcError {
    /// Binary property-list encoding or decoding failed.
    BinaryPlist(bplist::Error),
    /// A request identifier was not a canonical uppercase UUID.
    InvalidRequestId,
    /// The top-level value was not an exact four-element RPC envelope.
    InvalidEnvelope,
    /// The envelope carried a protocol version other than one.
    UnsupportedProtocolVersion,
    /// A raw xART message was not a dictionary.
    InvalidRawDictionary,
    /// The `performBiometricCommand` result was not `[status, data-or-nil]`.
    InvalidBiometricResult,
    /// A biometric status was outside the signed 64-bit wire domain.
    BiometricStatusOutOfRange,
    /// The bridge returned a nonzero signed biometric status.
    BiometricCommandFailed {
        /// Signed status returned by the bridge.
        status: i64,
        /// Command code extracted from the non-sensitive command header.
        command: u16,
    },
    /// The set-client-version result was not exactly `[0, true]`.
    InvalidClientVersionResult,
    /// A read-only calibration result had the wrong positional shape or type.
    InvalidCalibrationResult {
        /// Calibration method being validated.
        source: BridgeCalibrationSource,
    },
    /// The bridge returned an empty calibration record.
    EmptyCalibration {
        /// Calibration method being validated.
        source: BridgeCalibrationSource,
    },
    /// A calibration record exceeded the reference implementation's bound.
    CalibrationTooLarge {
        /// Calibration method being validated.
        source: BridgeCalibrationSource,
        /// Observed opaque byte length.
        actual: usize,
        /// Largest accepted opaque byte length.
        maximum: usize,
    },
    /// A recognized service-status callback had an invalid service field.
    InvalidCallbackService,
    /// A recognized service-status callback had neither data nor native nil.
    InvalidCallbackData,
    /// A recognized service-status callback had invalid timing fields.
    InvalidCallbackTiming,
}

impl fmt::Display for RpcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BinaryPlist(error) => error.fmt(formatter),
            Self::InvalidRequestId => formatter.write_str("invalid RPC request identifier"),
            Self::InvalidEnvelope => formatter.write_str("invalid RPC envelope"),
            Self::UnsupportedProtocolVersion => {
                formatter.write_str("unsupported RPC protocol version")
            }
            Self::InvalidRawDictionary => formatter.write_str("invalid BridgeXPC raw dictionary"),
            Self::InvalidBiometricResult => {
                formatter.write_str("invalid performBiometricCommand result")
            }
            Self::BiometricStatusOutOfRange => {
                formatter.write_str("biometric command status is out of range")
            }
            Self::BiometricCommandFailed { status, command } => write!(
                formatter,
                "T1 biometric command 0x{command:02x} failed with status {status}"
            ),
            Self::InvalidClientVersionResult => {
                formatter.write_str("failed to select bridge client version")
            }
            Self::InvalidCalibrationResult { source } => {
                write!(formatter, "invalid {source} calibration result")
            }
            Self::EmptyCalibration { source } => {
                write!(formatter, "T1 returned empty {source} calibration data")
            }
            Self::CalibrationTooLarge {
                source,
                actual,
                maximum,
            } => write!(
                formatter,
                "refusing {source} calibration data of {actual} bytes; maximum is {maximum}"
            ),
            Self::InvalidCallbackService => {
                formatter.write_str("service-status callback has an invalid service")
            }
            Self::InvalidCallbackData => {
                formatter.write_str("service-status callback has invalid data")
            }
            Self::InvalidCallbackTiming => {
                formatter.write_str("service-status callback has invalid timing data")
            }
        }
    }
}

impl std::error::Error for RpcError {}

impl From<bplist::Error> for RpcError {
    fn from(error: bplist::Error) -> Self {
        Self::BinaryPlist(error)
    }
}

/// Encodes an exact `[1, false, request-id, payload]` envelope.
///
/// # Errors
///
/// Returns an error if the request ID is not a canonical uppercase UUID or the
/// resulting binary plist exceeds codec limits.
pub fn encode_request(request_id: &RequestId, payload: &[Value]) -> Result<Vec<u8>, RpcError> {
    if !is_canonical_request_id(request_id.as_str()) {
        return Err(RpcError::InvalidRequestId);
    }
    encode_envelope(false, request_id, payload)
}

/// Encodes an exact `[1, true, request-id, result]` envelope.
///
/// # Errors
///
/// Returns an error if the resulting binary plist exceeds codec limits.
pub fn encode_reply(request_id: &RequestId, result: &[Value]) -> Result<Vec<u8>, RpcError> {
    encode_envelope(true, request_id, result)
}

fn encode_envelope(
    is_reply: bool,
    request_id: &RequestId,
    payload: &[Value],
) -> Result<Vec<u8>, RpcError> {
    Ok(bplist::encode(&Value::Array(vec![
        integer(RPC_PROTOCOL_VERSION),
        Value::Boolean(is_reply),
        Value::String(request_id.as_str().to_owned()),
        Value::Array(payload.to_vec()),
    ]))?)
}

/// Decodes and validates one exact four-element RPC envelope.
///
/// # Errors
///
/// Returns an error for an invalid binary plist, envelope shape, protocol
/// version, non-string request identifier, or non-array payload/result.
pub fn decode_envelope(data: &[u8]) -> Result<RpcEnvelope, RpcError> {
    let Value::Array(mut fields) = bplist::decode(data)? else {
        return Err(RpcError::InvalidEnvelope);
    };
    if fields.len() != 4 {
        return Err(RpcError::InvalidEnvelope);
    }

    let Value::Array(payload) = fields.pop().ok_or(RpcError::InvalidEnvelope)? else {
        return Err(RpcError::InvalidEnvelope);
    };
    let Value::String(request_id) = fields.pop().ok_or(RpcError::InvalidEnvelope)? else {
        return Err(RpcError::InvalidEnvelope);
    };
    let Value::Boolean(is_reply) = fields.pop().ok_or(RpcError::InvalidEnvelope)? else {
        return Err(RpcError::InvalidEnvelope);
    };
    if fields.pop() != Some(integer(RPC_PROTOCOL_VERSION)) {
        return Err(RpcError::UnsupportedProtocolVersion);
    }
    // The local generator emits canonical uppercase UUIDs, but the behavioral
    // reference accepts any plist string from the peer and echoes it exactly.
    let request_id = RequestId::from_wire(request_id);

    if is_reply {
        Ok(RpcEnvelope::Reply {
            request_id,
            result: payload,
        })
    } else {
        Ok(RpcEnvelope::Request {
            request_id,
            payload,
        })
    }
}

/// Encodes one raw dictionary for the xART message-listener protocol.
///
/// # Errors
///
/// Returns an error if the dictionary exceeds binary-plist codec limits.
pub fn encode_raw_dictionary(dictionary: &BTreeMap<String, Value>) -> Result<Vec<u8>, RpcError> {
    Ok(bplist::encode(&Value::Dictionary(dictionary.clone()))?)
}

/// Decodes one raw xART message and requires a string-keyed dictionary.
///
/// # Errors
///
/// Returns an error for an invalid binary plist or a non-dictionary root.
pub fn decode_raw_dictionary(data: &[u8]) -> Result<BTreeMap<String, Value>, RpcError> {
    match bplist::decode(data)? {
        Value::Dictionary(dictionary) => Ok(dictionary),
        _ => Err(RpcError::InvalidRawDictionary),
    }
}

/// Builds `[3, 0, command-data, response-capacity]` for
/// `performBiometricCommand`.
#[must_use]
pub fn perform_biometric_command_request(packet: &CommandPacket) -> Vec<Value> {
    vec![
        integer(PERFORM_BIOMETRIC_COMMAND_ORDINAL),
        integer(BIOMETRIC_BRIDGE_COMMAND),
        Value::Data(packet.request().to_vec()),
        Value::Integer(packet.response_capacity() as i128),
    ]
}

/// Validates `[signed-status, data-or-native-nil]` from
/// `performBiometricCommand`.
///
/// Native nil maps to an empty byte vector, matching the behavioral reference.
///
/// # Errors
///
/// Returns an error for a malformed result, a status outside signed 64-bit,
/// or any nonzero biometric status.
pub fn parse_biometric_command_result(
    packet: &CommandPacket,
    result: &[Value],
) -> Result<Vec<u8>, RpcError> {
    let [Value::Integer(status), output] = result else {
        return Err(RpcError::InvalidBiometricResult);
    };
    let status = i64::try_from(*status).map_err(|_| RpcError::BiometricStatusOutOfRange)?;
    if status != 0 {
        let command = packet
            .request()
            .get(2..4)
            .and_then(|bytes| bytes.try_into().ok())
            .map_or(0, u16::from_le_bytes);
        return Err(RpcError::BiometricCommandFailed { status, command });
    }

    match output {
        Value::String(value) if value == BRIDGEXPC_NIL => Ok(Vec::new()),
        Value::Data(data) => Ok(data.clone()),
        _ => Err(RpcError::InvalidBiometricResult),
    }
}

/// Builds `[1, version]` for the bridge's set-client-version method.
#[must_use]
pub fn set_client_version_request(version: u64) -> Vec<Value> {
    vec![integer(SET_CLIENT_VERSION_ORDINAL), integer(version)]
}

/// Requires the exact set-client-version result `[0, true]`.
///
/// # Errors
///
/// Returns an error for any other result.
pub fn validate_set_client_version_result(result: &[Value]) -> Result<(), RpcError> {
    if result == [Value::Integer(SUCCESS), Value::Boolean(true)] {
        Ok(())
    } else {
        Err(RpcError::InvalidClientVersionResult)
    }
}

/// Builds the one-element request for read-only calibration retrieval.
#[must_use]
pub fn calibration_request(source: BridgeCalibrationSource) -> Vec<Value> {
    vec![Value::Integer(source.ordinal())]
}

/// Validates one opaque read-only calibration result.
///
/// Native nil means that source is unavailable. Nonempty data is returned
/// unchanged and remains bounded below the maximum `BridgeXPC` frame size.
///
/// # Errors
///
/// Returns an error for the wrong result shape/type, empty data, or oversized
/// data.
pub fn parse_calibration_result(
    source: BridgeCalibrationSource,
    result: &[Value],
) -> Result<Option<Vec<u8>>, RpcError> {
    let [value] = result else {
        return Err(RpcError::InvalidCalibrationResult { source });
    };
    match value {
        Value::String(value) if value == BRIDGEXPC_NIL => Ok(None),
        Value::Data(data) if data.is_empty() => Err(RpcError::EmptyCalibration { source }),
        Value::Data(data) if data.len() > MAX_CALIBRATION_DATA_SIZE => {
            Err(RpcError::CalibrationTooLarge {
                source,
                actual: data.len(),
                maximum: MAX_CALIBRATION_DATA_SIZE,
            })
        }
        Value::Data(data) => Ok(Some(data.clone())),
        _ => Err(RpcError::InvalidCalibrationResult { source }),
    }
}

/// Handles callback ordinals 9 and 10 and builds their synchronous result.
///
/// Recognized callbacks must have exactly five elements:
/// `[ordinal, service, data-or-native-nil, reference-time, continuous-delta]`.
/// They produce `[0]`; all other methods produce the reference implementation's
/// unsupported result `[22]` without inspecting or retaining their arguments.
///
/// # Errors
///
/// Returns an error when a recognized callback has an invalid service, data,
/// or timing field.
pub fn handle_inbound_request(payload: &[Value]) -> Result<InboundRequestResult, RpcError> {
    let [
        Value::Integer(ordinal),
        service,
        data,
        reference_timestamp,
        continuous_time_delta,
    ] = payload
    else {
        return Ok(unsupported_request());
    };
    let Ok(ordinal) = u64::try_from(*ordinal) else {
        return Ok(unsupported_request());
    };
    if !SERVICE_STATUS_ORDINALS.contains(&ordinal) {
        return Ok(unsupported_request());
    }

    let Value::Integer(service) = service else {
        return Err(RpcError::InvalidCallbackService);
    };
    let service = u32::try_from(*service).map_err(|_| RpcError::InvalidCallbackService)?;
    let data = match data {
        Value::String(value) if value == BRIDGEXPC_NIL => Vec::new(),
        Value::Data(data) => data.clone(),
        _ => return Err(RpcError::InvalidCallbackData),
    };
    let Value::Integer(reference_timestamp) = reference_timestamp else {
        return Err(RpcError::InvalidCallbackTiming);
    };
    let Value::Integer(continuous_time_delta) = continuous_time_delta else {
        return Err(RpcError::InvalidCallbackTiming);
    };
    let reference_timestamp =
        u64::try_from(*reference_timestamp).map_err(|_| RpcError::InvalidCallbackTiming)?;
    let continuous_time_delta =
        u64::try_from(*continuous_time_delta).map_err(|_| RpcError::InvalidCallbackTiming)?;

    Ok(InboundRequestResult {
        reply: vec![Value::Integer(SUCCESS)],
        service_event: Some(ServiceStatusEvent {
            service,
            data,
            reference_timestamp,
            continuous_time_delta,
        }),
    })
}

fn unsupported_request() -> InboundRequestResult {
    InboundRequestResult {
        reply: vec![Value::Integer(UNSUPPORTED_METHOD)],
        service_event: None,
    }
}

fn integer(value: u64) -> Value {
    Value::Integer(i128::from(value))
}

fn is_canonical_request_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte)
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::calibration_status_command;

    const REQUEST_ID_TEXT: &str = "01234567-89AB-4CDE-8F01-23456789ABCD";
    const OTHER_REQUEST_ID_TEXT: &str = "11111111-2222-4333-8444-555555555555";

    fn request_id() -> RequestId {
        RequestId::parse(REQUEST_ID_TEXT).unwrap()
    }

    fn integer_i128(value: i128) -> Value {
        Value::Integer(value)
    }

    #[test]
    fn accepts_only_canonical_uppercase_request_ids() {
        assert_eq!(request_id().as_str(), REQUEST_ID_TEXT);
        for invalid in [
            "01234567-89ab-4CDE-8F01-23456789ABCD",
            "0123456789AB4CDE8F0123456789ABCD",
            "01234567-89AB-4CDE-8F01-23456789ABCZ",
        ] {
            assert_eq!(RequestId::parse(invalid), Err(RpcError::InvalidRequestId));
        }
    }

    #[test]
    fn formats_caller_entropy_as_canonical_uuid_v4() {
        let id = RequestId::from_uuid_v4_bytes([
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab,
            0xcd, 0xef,
        ]);
        assert_eq!(id.as_str(), "01234567-89AB-4DEF-8123-456789ABCDEF");
        assert_eq!(RequestId::parse(id.as_str()), Ok(id));
    }

    #[test]
    fn request_and_reply_use_exact_four_element_envelopes() {
        let id = request_id();
        let payload = vec![integer_i128(7), Value::Data(vec![1, 2, 3])];
        let request = encode_request(&id, &payload).unwrap();
        assert_eq!(
            bplist::decode(&request).unwrap(),
            Value::Array(vec![
                integer_i128(1),
                Value::Boolean(false),
                Value::String(REQUEST_ID_TEXT.into()),
                Value::Array(payload.clone()),
            ])
        );
        assert_eq!(
            decode_envelope(&request).unwrap(),
            RpcEnvelope::Request {
                request_id: id.clone(),
                payload: payload.clone(),
            }
        );

        let reply = encode_reply(&id, &payload).unwrap();
        assert_eq!(
            decode_envelope(&reply).unwrap(),
            RpcEnvelope::Reply {
                request_id: id,
                result: payload,
            }
        );
    }

    #[test]
    fn reply_matching_requires_the_exact_request_id() {
        let id = request_id();
        let other = RequestId::parse(OTHER_REQUEST_ID_TEXT).unwrap();
        let reply = RpcEnvelope::Reply {
            request_id: id.clone(),
            result: vec![integer_i128(0)],
        };
        assert_eq!(reply.matching_reply(&id), Some(&[integer_i128(0)][..]));
        assert_eq!(reply.matching_reply(&other), None);
        let request = RpcEnvelope::Request {
            request_id: id.clone(),
            payload: Vec::new(),
        };
        assert_eq!(request.matching_reply(&id), None);
    }

    #[test]
    fn inbound_noncanonical_id_is_preserved_and_echoed_exactly() {
        let wire_id = "peer-callback-id";
        let request = bplist::encode(&Value::Array(vec![
            integer_i128(1),
            Value::Boolean(false),
            Value::String(wire_id.into()),
            Value::Array(vec![integer_i128(9)]),
        ]))
        .unwrap();
        let RpcEnvelope::Request {
            request_id,
            payload,
        } = decode_envelope(&request).unwrap()
        else {
            panic!("expected inbound request");
        };
        assert_eq!(request_id.as_str(), wire_id);
        assert_eq!(payload, vec![integer_i128(9)]);

        let reply = encode_reply(&request_id, &[integer_i128(22)]).unwrap();
        assert_eq!(
            bplist::decode(&reply).unwrap(),
            Value::Array(vec![
                integer_i128(1),
                Value::Boolean(true),
                Value::String(wire_id.into()),
                Value::Array(vec![integer_i128(22)]),
            ])
        );
        assert_eq!(
            encode_request(&request_id, &[]),
            Err(RpcError::InvalidRequestId)
        );
    }

    #[test]
    fn envelope_rejects_wrong_shape_version_and_payload_type() {
        let id = Value::String(REQUEST_ID_TEXT.into());
        let cases = [
            Value::Array(vec![integer_i128(1), Value::Boolean(false), id.clone()]),
            Value::Array(vec![
                integer_i128(2),
                Value::Boolean(false),
                id.clone(),
                Value::Array(Vec::new()),
            ]),
            Value::Array(vec![
                integer_i128(1),
                Value::Boolean(false),
                id,
                Value::Data(Vec::new()),
            ]),
        ];
        assert_eq!(
            decode_envelope(&bplist::encode(&cases[0]).unwrap()),
            Err(RpcError::InvalidEnvelope)
        );
        assert_eq!(
            decode_envelope(&bplist::encode(&cases[1]).unwrap()),
            Err(RpcError::UnsupportedProtocolVersion)
        );
        assert_eq!(
            decode_envelope(&bplist::encode(&cases[2]).unwrap()),
            Err(RpcError::InvalidEnvelope)
        );
    }

    #[test]
    fn xart_messages_are_raw_dictionaries_not_rpc_envelopes() {
        let mut dictionary = BTreeMap::new();
        dictionary.insert("xart-msg.command".into(), integer_i128(200));
        dictionary.insert("xart-msg.version".into(), integer_i128(1));
        let encoded = encode_raw_dictionary(&dictionary).unwrap();
        assert_eq!(decode_raw_dictionary(&encoded).unwrap(), dictionary);
        assert_eq!(
            decode_raw_dictionary(&bplist::encode(&Value::Array(Vec::new())).unwrap()),
            Err(RpcError::InvalidRawDictionary)
        );
    }

    #[test]
    fn perform_biometric_command_shape_and_data_result_match_reference() {
        let packet = calibration_status_command();
        assert_eq!(
            perform_biometric_command_request(&packet),
            vec![
                integer_i128(3),
                integer_i128(0),
                Value::Data(packet.request().to_vec()),
                integer_i128(1),
            ]
        );
        assert_eq!(
            parse_biometric_command_result(&packet, &[integer_i128(0), Value::Data(vec![0x5a])])
                .unwrap(),
            vec![0x5a]
        );
    }

    #[test]
    fn perform_biometric_command_accepts_native_nil() {
        let packet = calibration_status_command();
        assert_eq!(
            parse_biometric_command_result(
                &packet,
                &[integer_i128(0), Value::String(BRIDGEXPC_NIL.into())]
            )
            .unwrap(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn perform_biometric_command_preserves_signed_failure_status() {
        let packet = calibration_status_command();
        assert_eq!(
            parse_biometric_command_result(
                &packet,
                &[integer_i128(-536_870_186), Value::Data(Vec::new())]
            ),
            Err(RpcError::BiometricCommandFailed {
                status: -536_870_186,
                command: 0x1d,
            })
        );
        assert_eq!(
            parse_biometric_command_result(
                &packet,
                &[
                    integer_i128(i128::from(i64::MAX) + 1),
                    Value::Data(Vec::new())
                ]
            ),
            Err(RpcError::BiometricStatusOutOfRange)
        );
    }

    #[test]
    fn set_client_version_shape_and_result_are_exact() {
        assert_eq!(
            set_client_version_request(2),
            vec![integer_i128(1), integer_i128(2)]
        );
        assert_eq!(
            validate_set_client_version_result(&[integer_i128(0), Value::Boolean(true)]),
            Ok(())
        );
        assert_eq!(
            validate_set_client_version_result(&[integer_i128(0), Value::Boolean(false)]),
            Err(RpcError::InvalidClientVersionResult)
        );
    }

    #[test]
    fn calibration_ordinals_and_results_match_reference() {
        assert_eq!(
            calibration_request(BridgeCalibrationSource::Eeprom),
            vec![integer_i128(5)]
        );
        assert_eq!(
            calibration_request(BridgeCalibrationSource::Fdr),
            vec![integer_i128(11)]
        );
        assert_eq!(
            parse_calibration_result(
                BridgeCalibrationSource::Eeprom,
                &[Value::Data(vec![1, 2, 3])]
            )
            .unwrap(),
            Some(vec![1, 2, 3])
        );
        assert_eq!(
            parse_calibration_result(
                BridgeCalibrationSource::Fdr,
                &[Value::String(BRIDGEXPC_NIL.into())]
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn calibration_rejects_invalid_empty_and_oversized_results() {
        let source = BridgeCalibrationSource::Fdr;
        assert_eq!(
            parse_calibration_result(source, &[]),
            Err(RpcError::InvalidCalibrationResult { source })
        );
        assert_eq!(
            parse_calibration_result(source, &[Value::Data(Vec::new())]),
            Err(RpcError::EmptyCalibration { source })
        );
        let oversized = vec![0; MAX_CALIBRATION_DATA_SIZE + 1];
        assert_eq!(
            parse_calibration_result(source, &[Value::Data(oversized)]),
            Err(RpcError::CalibrationTooLarge {
                source,
                actual: MAX_CALIBRATION_DATA_SIZE + 1,
                maximum: MAX_CALIBRATION_DATA_SIZE,
            })
        );
    }

    #[test]
    fn callback_ordinals_nine_and_ten_acknowledge_and_preserve_timing() {
        for ordinal in SERVICE_STATUS_ORDINALS {
            let handled = handle_inbound_request(&[
                integer(ordinal),
                integer_i128(0xe3ff_8000),
                Value::Data(vec![0xaa, 0xbb]),
                integer_i128(123),
                integer_i128(456),
            ])
            .unwrap();
            assert_eq!(handled.reply(), &[integer_i128(0)]);
            assert_eq!(
                handled.service_event(),
                Some(&ServiceStatusEvent {
                    service: 0xe3ff_8000,
                    data: vec![0xaa, 0xbb],
                    reference_timestamp: 123,
                    continuous_time_delta: 456,
                })
            );
        }
    }

    #[test]
    fn callback_native_nil_becomes_empty_data() {
        let handled = handle_inbound_request(&[
            integer_i128(9),
            integer_i128(1),
            Value::String(BRIDGEXPC_NIL.into()),
            integer_i128(0),
            integer_i128(0),
        ])
        .unwrap();
        assert!(handled.service_event().unwrap().data.is_empty());
        assert_eq!(handled.reply(), &[integer_i128(0)]);
    }

    #[test]
    fn unknown_or_misshapen_method_gets_unsupported_reply() {
        for payload in [
            vec![integer_i128(8)],
            vec![integer_i128(9)],
            vec![Value::Boolean(true); 5],
        ] {
            let handled = handle_inbound_request(&payload).unwrap();
            assert_eq!(handled.reply(), &[integer_i128(22)]);
            assert_eq!(handled.service_event(), None);
        }
    }

    #[test]
    fn recognized_callback_rejects_invalid_fields() {
        let base = [
            integer_i128(9),
            integer_i128(1),
            Value::Data(Vec::new()),
            integer_i128(2),
            integer_i128(3),
        ];
        let mut invalid = base.clone();
        invalid[1] = integer_i128(-1);
        assert_eq!(
            handle_inbound_request(&invalid),
            Err(RpcError::InvalidCallbackService)
        );
        invalid = base.clone();
        invalid[2] = Value::String("not nil".into());
        assert_eq!(
            handle_inbound_request(&invalid),
            Err(RpcError::InvalidCallbackData)
        );
        invalid = base;
        invalid[4] = integer_i128(-1);
        assert_eq!(
            handle_inbound_request(&invalid),
            Err(RpcError::InvalidCallbackTiming)
        );
    }

    #[test]
    fn debug_and_errors_do_not_disclose_payloads_or_request_ids() {
        let secret = "SENSITIVE-CALLBACK-CONTENT";
        let envelope = RpcEnvelope::Request {
            request_id: request_id(),
            payload: vec![Value::String(secret.into())],
        };
        let debug = format!("{envelope:?}");
        assert!(!debug.contains(secret));
        assert!(!debug.contains(REQUEST_ID_TEXT));

        let handled = handle_inbound_request(&[
            integer_i128(9),
            integer_i128(1),
            Value::Data(secret.as_bytes().to_vec()),
            integer_i128(2),
            integer_i128(3),
        ])
        .unwrap();
        assert!(!format!("{handled:?}").contains(secret));
        assert!(!RpcError::InvalidCallbackData.to_string().contains(secret));
    }
}

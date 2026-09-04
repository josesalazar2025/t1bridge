//! Safe parsing and evaluation for Mesa service-status messages.

use core::fmt;

pub const IDENTITY_V1_SIZE: usize = 20;
pub const MESA_SERVICE_MESSAGE: u32 = 0xe3ff_8000;
pub const MESA_ENROLLMENT_STATUS: u32 = 0xe3ff_8001;
pub const MESA_MATCH_RESULT: u32 = 0xe3ff_8002;
pub const MESA_ENROLLMENT_COMPLETE: u32 = 0xe3ff_8003;
pub const MESA_MESSAGE_TYPE_V1: u32 = 1;
pub const MESA_MESSAGE_HEADER_SIZE: usize = 40;
pub const MESA_ENROLLMENT_COMPLETE_V1_SIZE: usize = 20;
pub const MESA_ENROLLMENT_CONTINUE_MIN: u64 = 0x64;
pub const MESA_ENROLLMENT_CONTINUE_MAX: u64 = 0x163;
pub const MESA_MATCH_RESULT_V1_SIZE: usize = 0x0c70;

const MESA_MATCH_USER_LIST_COUNT_OFFSET: usize = 0x0c6c;
const MESA_MATCH_USER_LIST_ITEM_SIZE: usize = size_of::<u32>();

/// An opaque 16-byte Mesa identity identifier.
pub type IdentityIdentifier = [u8; 16];

/// One service-status callback received from the bridge.
///
/// Callback data may contain biometric protocol material and must not be
/// logged. [`MesaError`] deliberately reports only structural metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceStatusEvent {
    pub service: u32,
    pub data: Vec<u8>,
    pub reference_timestamp: u64,
    pub continuous_time_delta: u64,
}

/// One decoded Mesa service-status message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MesaMessage {
    pub status: u32,
    pub message_type: u32,
    pub timestamp: u64,
    pub payload: Vec<u8>,
    pub in_value: u64,
}

/// A validated Mesa identity record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    user_id: i32,
    identifier: IdentityIdentifier,
}

impl Identity {
    #[must_use]
    pub const fn user_id(self) -> i32 {
        self.user_id
    }

    #[must_use]
    pub const fn identifier(self) -> IdentityIdentifier {
        self.identifier
    }
}

/// A malformed Mesa record or unsupported Mesa message version.
///
/// Variants contain only lengths, counters, and protocol status values. They
/// never retain or render the associated payload or identity bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MesaError {
    InvalidIdentitySize { actual: usize, expected: usize },
    NegativeIdentityUser,
    ZeroIdentityIdentifier,
    TruncatedMessageHeader { actual: usize, minimum: usize },
    ServiceResultFailed { result: u64 },
    PayloadLengthDoesNotFit { declared: u64 },
    PayloadLengthMismatch { declared: u64, actual: usize },
    UnsupportedEnrollmentCompletionType { actual: u32 },
    TruncatedEnrollmentCompletion { actual: usize, minimum: usize },
    EnrollmentCompletedForWrongUser,
    ZeroEnrollmentIdentifier,
    UnsupportedMatchResultType { actual: u32 },
    TruncatedMatchResult { actual: usize, minimum: usize },
    MatchUserListSizeOverflow { item_count: u32 },
    TruncatedMatchUserList { actual: usize, required: usize },
}

impl fmt::Display for MesaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentitySize { actual, expected } => {
                write!(
                    formatter,
                    "identity record has {actual} bytes; expected {expected}"
                )
            }
            Self::NegativeIdentityUser => {
                formatter.write_str("identity record has a negative user ID")
            }
            Self::ZeroIdentityIdentifier => {
                formatter.write_str("identity record has a zero identifier")
            }
            Self::TruncatedMessageHeader { actual, minimum } => write!(
                formatter,
                "Mesa service-status message has {actual} bytes; header requires {minimum}"
            ),
            Self::ServiceResultFailed { result } => {
                write!(
                    formatter,
                    "Mesa service-status message failed with result {result}"
                )
            }
            Self::PayloadLengthDoesNotFit { declared } => write!(
                formatter,
                "Mesa service-status payload length {declared} cannot be represented"
            ),
            Self::PayloadLengthMismatch { declared, actual } => write!(
                formatter,
                "Mesa service-status payload declares {declared} bytes; received {actual}"
            ),
            Self::UnsupportedEnrollmentCompletionType { actual } => write!(
                formatter,
                "unsupported Mesa enrollment-completion type {actual}"
            ),
            Self::TruncatedEnrollmentCompletion { actual, minimum } => write!(
                formatter,
                "Mesa enrollment completion has {actual} bytes; requires at least {minimum}"
            ),
            Self::EnrollmentCompletedForWrongUser => {
                formatter.write_str("Mesa completed enrollment for the wrong user")
            }
            Self::ZeroEnrollmentIdentifier => {
                formatter.write_str("Mesa enrollment completion has a zero identifier")
            }
            Self::UnsupportedMatchResultType { actual } => {
                write!(formatter, "unsupported Mesa match-result type {actual}")
            }
            Self::TruncatedMatchResult { actual, minimum } => write!(
                formatter,
                "Mesa match result has {actual} bytes; requires at least {minimum}"
            ),
            Self::MatchUserListSizeOverflow { item_count } => write!(
                formatter,
                "Mesa match user-list size overflows for {item_count} items"
            ),
            Self::TruncatedMatchUserList { actual, required } => write!(
                formatter,
                "Mesa match result has {actual} bytes; user list requires {required}"
            ),
        }
    }
}

impl std::error::Error for MesaError {}

/// Parses one exact 20-byte, little-endian Mesa identity record.
///
/// The 16-byte identity identifier is deliberately not interpreted as a UUID.
///
/// # Errors
///
/// Returns an error for a non-exact record size, a negative user ID, or an
/// all-zero identity identifier.
pub fn parse_identity(data: &[u8]) -> Result<Identity, MesaError> {
    if data.len() != IDENTITY_V1_SIZE {
        return Err(MesaError::InvalidIdentitySize {
            actual: data.len(),
            expected: IDENTITY_V1_SIZE,
        });
    }

    let user_id = read_i32(data, 0);
    if user_id < 0 {
        return Err(MesaError::NegativeIdentityUser);
    }

    let mut identifier = [0_u8; 16];
    identifier.copy_from_slice(&data[size_of::<i32>()..IDENTITY_V1_SIZE]);
    if identifier == [0; 16] {
        return Err(MesaError::ZeroIdentityIdentifier);
    }

    Ok(Identity {
        user_id,
        identifier,
    })
}

/// Parses an inline Mesa message from a service-status callback.
///
/// Events for other services are ignored without inspecting their opaque data.
/// Mesa payload size must exactly match the 64-bit length in the header.
///
/// # Errors
///
/// Returns an error for a truncated header, failed service result, payload
/// length that cannot fit this platform, or a payload length mismatch.
pub fn parse_mesa_message(event: &ServiceStatusEvent) -> Result<Option<MesaMessage>, MesaError> {
    if event.service != MESA_SERVICE_MESSAGE {
        return Ok(None);
    }
    if event.data.len() < MESA_MESSAGE_HEADER_SIZE {
        return Err(MesaError::TruncatedMessageHeader {
            actual: event.data.len(),
            minimum: MESA_MESSAGE_HEADER_SIZE,
        });
    }

    let result = read_u64(&event.data, 0);
    if result != 0 {
        return Err(MesaError::ServiceResultFailed { result });
    }

    let declared = read_u64(&event.data, 32);
    let declared_size =
        usize::try_from(declared).map_err(|_| MesaError::PayloadLengthDoesNotFit { declared })?;
    let actual_size = event.data.len() - MESA_MESSAGE_HEADER_SIZE;
    if declared_size != actual_size {
        return Err(MesaError::PayloadLengthMismatch {
            declared,
            actual: actual_size,
        });
    }

    Ok(Some(MesaMessage {
        status: read_u32(&event.data, 8),
        message_type: read_u32(&event.data, 12),
        timestamp: read_u64(&event.data, 16),
        in_value: read_u64(&event.data, 24),
        payload: event.data[MESA_MESSAGE_HEADER_SIZE..].to_vec(),
    }))
}

/// Whether an enrollment-status message requests another enrollment step.
#[must_use]
pub const fn enrollment_needs_continue(message: &MesaMessage) -> bool {
    message.status == MESA_ENROLLMENT_STATUS
        && message.in_value >= MESA_ENROLLMENT_CONTINUE_MIN
        && message.in_value <= MESA_ENROLLMENT_CONTINUE_MAX
}

/// Evaluates an enrollment-completion message.
///
/// Returns `Ok(None)` when the message is not an enrollment completion and the
/// opaque identifier when it is a valid completion for `requested_user_id`.
///
/// # Errors
///
/// Returns an error for an unsupported message type, truncated payload, user
/// mismatch, or zero identity identifier.
pub fn enrollment_completion(
    message: &MesaMessage,
    requested_user_id: i32,
) -> Result<Option<IdentityIdentifier>, MesaError> {
    if message.status != MESA_ENROLLMENT_COMPLETE {
        return Ok(None);
    }
    if message.message_type != MESA_MESSAGE_TYPE_V1 {
        return Err(MesaError::UnsupportedEnrollmentCompletionType {
            actual: message.message_type,
        });
    }
    if message.payload.len() < MESA_ENROLLMENT_COMPLETE_V1_SIZE {
        return Err(MesaError::TruncatedEnrollmentCompletion {
            actual: message.payload.len(),
            minimum: MESA_ENROLLMENT_COMPLETE_V1_SIZE,
        });
    }

    if read_i32(&message.payload, 0) != requested_user_id {
        return Err(MesaError::EnrollmentCompletedForWrongUser);
    }

    let mut identifier = [0_u8; 16];
    identifier.copy_from_slice(&message.payload[4..MESA_ENROLLMENT_COMPLETE_V1_SIZE]);
    if identifier == [0; 16] {
        return Err(MesaError::ZeroEnrollmentIdentifier);
    }
    Ok(Some(identifier))
}

/// Evaluates a Mesa match-result message against validated enrolled identities.
///
/// Returns `Ok(None)` for another status, `Ok(Some(None))` for Mesa's no-match
/// sentinel or an identity/user mismatch, and the opaque enrolled identifier
/// for a valid match.
///
/// # Errors
///
/// Returns an error for an unsupported message type, a truncated fixed result,
/// or an overflowing or truncated variable user list.
pub fn evaluate_matched_identity(
    message: &MesaMessage,
    requested_user_id: i32,
    identities: &[Identity],
) -> Result<Option<Option<IdentityIdentifier>>, MesaError> {
    if message.status != MESA_MATCH_RESULT {
        return Ok(None);
    }
    if message.message_type != MESA_MESSAGE_TYPE_V1 {
        return Err(MesaError::UnsupportedMatchResultType {
            actual: message.message_type,
        });
    }
    if message.payload.len() < MESA_MATCH_RESULT_V1_SIZE {
        return Err(MesaError::TruncatedMatchResult {
            actual: message.payload.len(),
            minimum: MESA_MATCH_RESULT_V1_SIZE,
        });
    }

    let item_count = read_u32(&message.payload, MESA_MATCH_USER_LIST_COUNT_OFFSET);
    let item_bytes = usize::try_from(item_count)
        .ok()
        .and_then(|count| count.checked_mul(MESA_MATCH_USER_LIST_ITEM_SIZE))
        .ok_or(MesaError::MatchUserListSizeOverflow { item_count })?;
    let required = MESA_MATCH_RESULT_V1_SIZE
        .checked_add(item_bytes)
        .ok_or(MesaError::MatchUserListSizeOverflow { item_count })?;
    if message.payload.len() < required {
        return Err(MesaError::TruncatedMatchUserList {
            actual: message.payload.len(),
            required,
        });
    }

    let matched_user_id = read_i32(&message.payload, 0);
    if matched_user_id == -1 {
        return Ok(Some(None));
    }

    let mut matched_identifier = [0_u8; 16];
    matched_identifier.copy_from_slice(&message.payload[4..20]);
    let matched = identities.iter().find(|identity| {
        matched_user_id == requested_user_id
            && identity.user_id == requested_user_id
            && identity.identifier == matched_identifier
    });
    Ok(Some(matched.map(|identity| identity.identifier)))
}

/// Evaluates whether a Mesa match result identifies an enrolled identity.
///
/// This compatibility wrapper preserves the original boolean result while the
/// identity-bearing evaluator remains the single parser and validator.
///
/// # Errors
///
/// Returns the structural errors reported by [`evaluate_matched_identity`].
pub fn evaluate_match_result(
    message: &MesaMessage,
    requested_user_id: i32,
    identities: &[Identity],
) -> Result<Option<bool>, MesaError> {
    evaluate_matched_identity(message, requested_user_id, identities)
        .map(|result| result.map(|identifier| identifier.is_some()))
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        data[offset..offset + 4]
            .try_into()
            .expect("validated slice"),
    )
}

fn read_i32(data: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes(
        data[offset..offset + 4]
            .try_into()
            .expect("validated slice"),
    )
}

fn read_u64(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        data[offset..offset + 8]
            .try_into()
            .expect("validated slice"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: i32 = 501;
    const OTHER_USER: i32 = 502;
    const IDENTIFIER: IdentityIdentifier = [
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe,
        0x0f,
    ];
    const OTHER_IDENTIFIER: IdentityIdentifier = [
        0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e,
        0x0f,
    ];

    fn identity_bytes(user_id: i32, identifier: IdentityIdentifier) -> [u8; IDENTITY_V1_SIZE] {
        let mut data = [0_u8; IDENTITY_V1_SIZE];
        data[..4].copy_from_slice(&user_id.to_le_bytes());
        data[4..].copy_from_slice(&identifier);
        data
    }

    fn mesa_event(
        service: u32,
        result: u64,
        status: u32,
        message_type: u32,
        timestamp: u64,
        in_value: u64,
        payload: &[u8],
    ) -> ServiceStatusEvent {
        let mut data = Vec::with_capacity(MESA_MESSAGE_HEADER_SIZE + payload.len());
        data.extend_from_slice(&result.to_le_bytes());
        data.extend_from_slice(&status.to_le_bytes());
        data.extend_from_slice(&message_type.to_le_bytes());
        data.extend_from_slice(&timestamp.to_le_bytes());
        data.extend_from_slice(&in_value.to_le_bytes());
        data.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        data.extend_from_slice(payload);
        ServiceStatusEvent {
            service,
            data,
            reference_timestamp: 11,
            continuous_time_delta: 12,
        }
    }

    fn message(status: u32, message_type: u32, in_value: u64, payload: Vec<u8>) -> MesaMessage {
        MesaMessage {
            status,
            message_type,
            timestamp: 123,
            payload,
            in_value,
        }
    }

    fn match_message(user_id: i32, identifier: IdentityIdentifier) -> MesaMessage {
        let mut payload = vec![0_u8; MESA_MATCH_RESULT_V1_SIZE];
        payload[..4].copy_from_slice(&user_id.to_le_bytes());
        payload[4..20].copy_from_slice(&identifier);
        message(MESA_MATCH_RESULT, MESA_MESSAGE_TYPE_V1, 0, payload)
    }

    #[test]
    fn identity_parser_preserves_little_endian_user_and_opaque_identifier() {
        let identity = parse_identity(&identity_bytes(USER, IDENTIFIER)).unwrap();
        assert_eq!(identity.user_id(), USER);
        assert_eq!(identity.identifier(), IDENTIFIER);
    }

    #[test]
    fn identity_parser_requires_exact_size_and_valid_fields() {
        for size in [0, IDENTITY_V1_SIZE - 1, IDENTITY_V1_SIZE + 1] {
            assert_eq!(
                parse_identity(&vec![0_u8; size]),
                Err(MesaError::InvalidIdentitySize {
                    actual: size,
                    expected: IDENTITY_V1_SIZE,
                })
            );
        }
        assert_eq!(
            parse_identity(&identity_bytes(-1, IDENTIFIER)),
            Err(MesaError::NegativeIdentityUser)
        );
        assert_eq!(
            parse_identity(&identity_bytes(USER, [0; 16])),
            Err(MesaError::ZeroIdentityIdentifier)
        );
    }

    #[test]
    fn non_mesa_events_are_ignored_without_inspecting_data() {
        let event = ServiceStatusEvent {
            service: MESA_SERVICE_MESSAGE - 1,
            data: vec![0xaa],
            reference_timestamp: 0,
            continuous_time_delta: 0,
        };
        assert_eq!(parse_mesa_message(&event), Ok(None));
    }

    #[test]
    fn mesa_message_parser_decodes_the_exact_little_endian_layout() {
        let event = mesa_event(
            MESA_SERVICE_MESSAGE,
            0,
            MESA_MATCH_RESULT,
            MESA_MESSAGE_TYPE_V1,
            0x0123_4567_89ab_cdef,
            0xfedc_ba98_7654_3210,
            &[0xde, 0xad, 0xbe, 0xef],
        );
        assert_eq!(
            parse_mesa_message(&event),
            Ok(Some(MesaMessage {
                status: MESA_MATCH_RESULT,
                message_type: MESA_MESSAGE_TYPE_V1,
                timestamp: 0x0123_4567_89ab_cdef,
                in_value: 0xfedc_ba98_7654_3210,
                payload: vec![0xde, 0xad, 0xbe, 0xef],
            }))
        );
    }

    #[test]
    fn mesa_message_parser_rejects_every_truncated_header_length() {
        for actual in 0..MESA_MESSAGE_HEADER_SIZE {
            let event = ServiceStatusEvent {
                service: MESA_SERVICE_MESSAGE,
                data: vec![0; actual],
                reference_timestamp: 0,
                continuous_time_delta: 0,
            };
            assert_eq!(
                parse_mesa_message(&event),
                Err(MesaError::TruncatedMessageHeader {
                    actual,
                    minimum: MESA_MESSAGE_HEADER_SIZE,
                })
            );
        }
    }

    #[test]
    fn mesa_message_parser_rejects_failure_and_length_mismatches() {
        let failed = mesa_event(
            MESA_SERVICE_MESSAGE,
            7,
            MESA_MATCH_RESULT,
            MESA_MESSAGE_TYPE_V1,
            0,
            0,
            &[],
        );
        assert_eq!(
            parse_mesa_message(&failed),
            Err(MesaError::ServiceResultFailed { result: 7 })
        );

        let mut short = mesa_event(
            MESA_SERVICE_MESSAGE,
            0,
            MESA_MATCH_RESULT,
            MESA_MESSAGE_TYPE_V1,
            0,
            0,
            &[],
        );
        short.data[32..40].copy_from_slice(&10_u64.to_le_bytes());
        assert_eq!(
            parse_mesa_message(&short),
            Err(MesaError::PayloadLengthMismatch {
                declared: 10,
                actual: 0,
            })
        );

        let mut trailing = mesa_event(
            MESA_SERVICE_MESSAGE,
            0,
            MESA_MATCH_RESULT,
            MESA_MESSAGE_TYPE_V1,
            0,
            0,
            &[0xaa],
        );
        trailing.data[32..40].copy_from_slice(&0_u64.to_le_bytes());
        assert_eq!(
            parse_mesa_message(&trailing),
            Err(MesaError::PayloadLengthMismatch {
                declared: 0,
                actual: 1,
            })
        );
    }

    #[test]
    fn enrollment_continue_range_is_inclusive_and_status_specific() {
        for (in_value, expected) in [
            (MESA_ENROLLMENT_CONTINUE_MIN - 1, false),
            (MESA_ENROLLMENT_CONTINUE_MIN, true),
            (MESA_ENROLLMENT_CONTINUE_MAX, true),
            (MESA_ENROLLMENT_CONTINUE_MAX + 1, false),
        ] {
            let candidate = message(
                MESA_ENROLLMENT_STATUS,
                MESA_MESSAGE_TYPE_V1,
                in_value,
                vec![],
            );
            assert_eq!(enrollment_needs_continue(&candidate), expected);
        }
        assert!(!enrollment_needs_continue(&message(
            MESA_MATCH_RESULT,
            MESA_MESSAGE_TYPE_V1,
            MESA_ENROLLMENT_CONTINUE_MIN,
            vec![],
        )));
    }

    #[test]
    fn enrollment_completion_is_status_specific_and_returns_opaque_identifier() {
        let other = message(0, 99, 0, vec![]);
        assert_eq!(enrollment_completion(&other, USER), Ok(None));

        let mut payload = identity_bytes(USER, IDENTIFIER).to_vec();
        payload.extend_from_slice(&[0xaa, 0xbb]);
        assert_eq!(
            enrollment_completion(
                &message(MESA_ENROLLMENT_COMPLETE, MESA_MESSAGE_TYPE_V1, 0, payload),
                USER,
            ),
            Ok(Some(IDENTIFIER))
        );
    }

    #[test]
    fn enrollment_completion_rejects_type_truncation_user_and_zero_identifier() {
        assert_eq!(
            enrollment_completion(&message(MESA_ENROLLMENT_COMPLETE, 2, 0, vec![]), USER,),
            Err(MesaError::UnsupportedEnrollmentCompletionType { actual: 2 })
        );
        for actual in [0, MESA_ENROLLMENT_COMPLETE_V1_SIZE - 1] {
            assert_eq!(
                enrollment_completion(
                    &message(
                        MESA_ENROLLMENT_COMPLETE,
                        MESA_MESSAGE_TYPE_V1,
                        0,
                        vec![0; actual],
                    ),
                    USER,
                ),
                Err(MesaError::TruncatedEnrollmentCompletion {
                    actual,
                    minimum: MESA_ENROLLMENT_COMPLETE_V1_SIZE,
                })
            );
        }
        assert_eq!(
            enrollment_completion(
                &message(
                    MESA_ENROLLMENT_COMPLETE,
                    MESA_MESSAGE_TYPE_V1,
                    0,
                    identity_bytes(OTHER_USER, IDENTIFIER).to_vec(),
                ),
                USER,
            ),
            Err(MesaError::EnrollmentCompletedForWrongUser)
        );
        assert_eq!(
            enrollment_completion(
                &message(
                    MESA_ENROLLMENT_COMPLETE,
                    MESA_MESSAGE_TYPE_V1,
                    0,
                    identity_bytes(USER, [0; 16]).to_vec(),
                ),
                USER,
            ),
            Err(MesaError::ZeroEnrollmentIdentifier)
        );
    }

    #[test]
    fn match_evaluation_requires_requested_enrolled_identity() {
        let enrolled = parse_identity(&identity_bytes(USER, IDENTIFIER)).unwrap();
        let other_user = parse_identity(&identity_bytes(OTHER_USER, IDENTIFIER)).unwrap();
        let other_identifier = parse_identity(&identity_bytes(USER, OTHER_IDENTIFIER)).unwrap();
        let candidate = match_message(USER, IDENTIFIER);

        assert_eq!(
            evaluate_matched_identity(&candidate, USER, &[enrolled]),
            Ok(Some(Some(IDENTIFIER)))
        );
        assert_eq!(
            evaluate_matched_identity(&candidate, OTHER_USER, &[other_user]),
            Ok(Some(None))
        );
        assert_eq!(
            evaluate_matched_identity(&candidate, USER, &[other_identifier]),
            Ok(Some(None))
        );
        assert_eq!(
            evaluate_match_result(&candidate, USER, &[enrolled]),
            Ok(Some(true))
        );
        assert_eq!(
            evaluate_match_result(&candidate, OTHER_USER, &[other_user]),
            Ok(Some(false))
        );
        assert_eq!(
            evaluate_match_result(&candidate, USER, &[other_identifier]),
            Ok(Some(false))
        );
        assert_eq!(
            evaluate_match_result(&candidate, USER, &[]),
            Ok(Some(false))
        );
    }

    #[test]
    fn match_evaluation_is_status_specific_and_honors_no_match_sentinel() {
        let unrelated = message(MESA_ENROLLMENT_STATUS, 99, 0, vec![]);
        assert_eq!(evaluate_match_result(&unrelated, USER, &[]), Ok(None));

        let no_match = match_message(-1, [0; 16]);
        assert_eq!(evaluate_match_result(&no_match, USER, &[]), Ok(Some(false)));
    }

    #[test]
    fn match_evaluation_rejects_type_and_fixed_result_truncation() {
        assert_eq!(
            evaluate_match_result(&message(MESA_MATCH_RESULT, 2, 0, vec![]), USER, &[]),
            Err(MesaError::UnsupportedMatchResultType { actual: 2 })
        );
        for actual in [0, MESA_MATCH_RESULT_V1_SIZE - 1] {
            assert_eq!(
                evaluate_match_result(
                    &message(MESA_MATCH_RESULT, MESA_MESSAGE_TYPE_V1, 0, vec![0; actual],),
                    USER,
                    &[],
                ),
                Err(MesaError::TruncatedMatchResult {
                    actual,
                    minimum: MESA_MATCH_RESULT_V1_SIZE,
                })
            );
        }
    }

    #[test]
    fn match_evaluation_validates_the_declared_user_list_length() {
        let mut one_missing = match_message(USER, IDENTIFIER);
        one_missing.payload[MESA_MATCH_USER_LIST_COUNT_OFFSET..MESA_MATCH_RESULT_V1_SIZE]
            .copy_from_slice(&1_u32.to_le_bytes());
        assert_eq!(
            evaluate_match_result(&one_missing, USER, &[]),
            Err(MesaError::TruncatedMatchUserList {
                actual: MESA_MATCH_RESULT_V1_SIZE,
                required: MESA_MATCH_RESULT_V1_SIZE + 4,
            })
        );

        let mut complete = one_missing;
        complete
            .payload
            .extend_from_slice(&0x1234_5678_u32.to_le_bytes());
        assert_eq!(evaluate_match_result(&complete, USER, &[]), Ok(Some(false)));

        let mut huge = match_message(USER, IDENTIFIER);
        huge.payload[MESA_MATCH_USER_LIST_COUNT_OFFSET..MESA_MATCH_RESULT_V1_SIZE]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        let error = evaluate_match_result(&huge, USER, &[]).unwrap_err();
        assert!(matches!(
            error,
            MesaError::TruncatedMatchUserList { .. } | MesaError::MatchUserListSizeOverflow { .. }
        ));
    }

    #[test]
    fn typed_errors_do_not_render_payload_or_identifiers() {
        let secret = "102132435465768798a9bacbdcedfe0f";
        let event = mesa_event(
            MESA_SERVICE_MESSAGE,
            0,
            MESA_MATCH_RESULT,
            MESA_MESSAGE_TYPE_V1,
            0,
            0,
            &IDENTIFIER,
        );
        let mut mismatched = event;
        mismatched.data[32..40].copy_from_slice(&0_u64.to_le_bytes());
        let error = parse_mesa_message(&mismatched).unwrap_err();
        assert!(!error.to_string().contains(secret));
        assert!(!format!("{error:?}").contains(secret));
    }
}

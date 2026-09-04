//! Deterministic Mesa fingerprint-match orchestration.

use crate::commands::{
    CommandError, cancel_operation_command, start_match_command, validate_empty_response,
    validate_identity_list_response,
};
use crate::control::BiometricTransport;
use crate::mesa::{
    IDENTITY_V1_SIZE, Identity, IdentityIdentifier, MesaError, ServiceStatusEvent,
    evaluate_matched_identity, parse_identity, parse_mesa_message,
};
use crate::policy::BiometricUserId;
use core::fmt;

/// One caller-owned wait result for an active Mesa match.
pub enum MatchEvent {
    /// A service-status callback already acknowledged by the live transport.
    Callback(ServiceStatusEvent),
    /// The requesting client cancelled the operation.
    Cancelled,
    /// The caller-owned deadline expired.
    TimedOut,
}

impl fmt::Debug for MatchEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Callback(event) => formatter
                .debug_struct("Callback")
                .field("service", &event.service)
                .field("data_len", &event.data.len())
                .finish(),
            Self::Cancelled => formatter.write_str("Cancelled"),
            Self::TimedOut => formatter.write_str("TimedOut"),
        }
    }
}

/// Supplies acknowledged callbacks, cancellation, and timeout decisions.
///
/// Socket polling, clocks, cancellation channels, and callback acquisition
/// remain outside this protocol workflow.
pub trait MatchEventSource {
    /// Caller-owned wait or callback-delivery failure.
    type Error;

    /// Returns the next callback or terminal wait decision.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe caller-owned delivery failure.
    fn next_event(&mut self) -> Result<MatchEvent, Self::Error>;
}

/// Terminal result of one successfully cleaned-up match operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MatchOutcome {
    /// Mesa matched an identity enrolled for the requested user.
    Matched,
    /// Mesa returned its no-match sentinel or an unrecognized identity.
    NoMatch,
    /// The requesting client cancelled before a match result arrived.
    Cancelled,
    /// The caller-owned deadline expired before a match result arrived.
    TimedOut,
}

/// Terminal identity-bearing result of one successfully cleaned-up match.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum IdentityMatchOutcome {
    /// Mesa matched this opaque identity enrolled for the requested user.
    Matched(IdentityIdentifier),
    /// Mesa returned its no-match sentinel or an unrecognized identity.
    NoMatch,
    /// The requesting client cancelled before a match result arrived.
    Cancelled,
    /// The caller-owned deadline expired before a match result arrived.
    TimedOut,
}

impl fmt::Debug for IdentityMatchOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Matched(_) => formatter.write_str("Matched([redacted])"),
            Self::NoMatch => formatter.write_str("NoMatch"),
            Self::Cancelled => formatter.write_str("Cancelled"),
            Self::TimedOut => formatter.write_str("TimedOut"),
        }
    }
}

/// A redaction-safe match setup, wait, parse, or cleanup failure.
pub enum MatchWorkflowError<TransportError, EventError> {
    /// The packed identity response was empty.
    NoEnrolledIdentities,
    /// A valid identity belonged to a user other than the requested user.
    IdentityForWrongUser,
    /// A command packet or fixed response was malformed.
    Command(CommandError),
    /// An identity or callback payload was structurally invalid.
    Mesa(MesaError),
    /// Match-start transport failed.
    Transport(TransportError),
    /// Callback delivery or wait policy failed.
    Event(EventError),
    /// Cancellation transport failed after an otherwise normal outcome.
    CleanupTransport(TransportError),
    /// Cancellation returned malformed data after an otherwise normal outcome.
    CleanupCommand(CommandError),
}

impl<TransportError, EventError> fmt::Debug for MatchWorkflowError<TransportError, EventError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoEnrolledIdentities => formatter.write_str("NoEnrolledIdentities"),
            Self::IdentityForWrongUser => formatter.write_str("IdentityForWrongUser"),
            Self::Command(error) => formatter.debug_tuple("Command").field(error).finish(),
            Self::Mesa(error) => formatter.debug_tuple("Mesa").field(error).finish(),
            Self::Transport(_) => formatter.write_str("Transport([redacted])"),
            Self::Event(_) => formatter.write_str("Event([redacted])"),
            Self::CleanupTransport(_) => formatter.write_str("CleanupTransport([redacted])"),
            Self::CleanupCommand(error) => formatter
                .debug_tuple("CleanupCommand")
                .field(error)
                .finish(),
        }
    }
}

impl<TransportError, EventError> fmt::Display for MatchWorkflowError<TransportError, EventError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoEnrolledIdentities => {
                formatter.write_str("requested biometric user has no enrolled identities")
            }
            Self::IdentityForWrongUser => {
                formatter.write_str("Mesa returned an identity for another user")
            }
            Self::Command(error) | Self::CleanupCommand(error) => error.fmt(formatter),
            Self::Mesa(error) => error.fmt(formatter),
            Self::Transport(_) => formatter.write_str("match-start transport failed"),
            Self::Event(_) => formatter.write_str("match callback delivery failed"),
            Self::CleanupTransport(_) => formatter.write_str("match cancellation transport failed"),
        }
    }
}

impl<TransportError, EventError> std::error::Error
    for MatchWorkflowError<TransportError, EventError>
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Command(error) | Self::CleanupCommand(error) => Some(error),
            Self::Mesa(error) => Some(error),
            Self::NoEnrolledIdentities
            | Self::IdentityForWrongUser
            | Self::Transport(_)
            | Self::Event(_)
            | Self::CleanupTransport(_) => None,
        }
    }
}

enum WaitError<EventError> {
    Event(EventError),
    Mesa(MesaError),
}

enum CleanupError<TransportError> {
    Transport(TransportError),
    Command(CommandError),
}

/// Starts, waits for, and cleans up one Mesa fingerprint match.
///
/// `identity_response` is the packed output of Mesa's identities command or
/// an equivalent already-restored identity list. Every record is parsed and
/// required to belong to `user_id` before match-start is sent.
///
/// A start failure is ambiguous because Mesa may have accepted the request
/// before the reply was lost, so cancellation is attempted best-effort. Once
/// start succeeds, cancellation is always sent. Cleanup failure is returned
/// only after a normal match, no-match, cancellation, or timeout outcome; it
/// never masks callback-delivery or Mesa parsing failures.
///
/// # Errors
///
/// Returns an error for empty, malformed, or cross-user identities; command
/// and transport failures; malformed callbacks; event delivery failures; or
/// cancellation failure following an otherwise normal outcome.
pub fn match_fingerprint<Transport, Events>(
    transport: &mut Transport,
    events: &mut Events,
    user_id: BiometricUserId,
    identity_response: &[u8],
) -> Result<MatchOutcome, MatchWorkflowError<Transport::Error, Events::Error>>
where
    Transport: BiometricTransport,
    Events: MatchEventSource,
{
    match_fingerprint_identified(transport, events, user_id, identity_response).map(|outcome| {
        match outcome {
            IdentityMatchOutcome::Matched(_) => MatchOutcome::Matched,
            IdentityMatchOutcome::NoMatch => MatchOutcome::NoMatch,
            IdentityMatchOutcome::Cancelled => MatchOutcome::Cancelled,
            IdentityMatchOutcome::TimedOut => MatchOutcome::TimedOut,
        }
    })
}

/// Starts, waits for, and cleans up one identity-bearing Mesa fingerprint match.
///
/// This owns the validate, Start, callback wait, and mandatory terminal Cancel
/// sequence used by both match APIs. Its setup and cleanup error behavior is
/// identical to [`match_fingerprint`].
///
/// # Errors
///
/// Returns an error for empty, malformed, or cross-user identities; command
/// and transport failures; malformed callbacks; event delivery failures; or
/// cancellation failure following an otherwise normal outcome.
pub fn match_fingerprint_identified<Transport, Events>(
    transport: &mut Transport,
    events: &mut Events,
    user_id: BiometricUserId,
    identity_response: &[u8],
) -> Result<IdentityMatchOutcome, MatchWorkflowError<Transport::Error, Events::Error>>
where
    Transport: BiometricTransport,
    Events: MatchEventSource,
{
    validate_identity_list_response(identity_response).map_err(MatchWorkflowError::Command)?;
    if identity_response.is_empty() {
        return Err(MatchWorkflowError::NoEnrolledIdentities);
    }

    let requested_user_id = user_id.as_raw().cast_signed();
    let identities = identity_response
        .chunks(IDENTITY_V1_SIZE)
        .map(parse_identity)
        .collect::<Result<Vec<_>, _>>()
        .map_err(MatchWorkflowError::Mesa)?;
    if identities
        .iter()
        .any(|identity| identity.user_id() != requested_user_id)
    {
        return Err(MatchWorkflowError::IdentityForWrongUser);
    }

    let start_result = transport
        .execute(&start_match_command(user_id))
        .map_err(MatchWorkflowError::Transport)
        .and_then(|response| {
            validate_empty_response(&response).map_err(MatchWorkflowError::Command)
        });
    if let Err(error) = start_result {
        let _ = cancel(transport);
        return Err(error);
    }

    let wait_result = wait_for_outcome(events, requested_user_id, &identities);
    let cleanup_result = cancel(transport);
    match wait_result {
        Err(WaitError::Event(error)) => Err(MatchWorkflowError::Event(error)),
        Err(WaitError::Mesa(error)) => Err(MatchWorkflowError::Mesa(error)),
        Ok(outcome) => match cleanup_result {
            Ok(()) => Ok(outcome),
            Err(CleanupError::Transport(error)) => Err(MatchWorkflowError::CleanupTransport(error)),
            Err(CleanupError::Command(error)) => Err(MatchWorkflowError::CleanupCommand(error)),
        },
    }
}

fn wait_for_outcome<Events: MatchEventSource>(
    events: &mut Events,
    requested_user_id: i32,
    identities: &[Identity],
) -> Result<IdentityMatchOutcome, WaitError<Events::Error>> {
    loop {
        match events.next_event().map_err(WaitError::Event)? {
            MatchEvent::Cancelled => return Ok(IdentityMatchOutcome::Cancelled),
            MatchEvent::TimedOut => return Ok(IdentityMatchOutcome::TimedOut),
            MatchEvent::Callback(event) => {
                let Some(message) = parse_mesa_message(&event).map_err(WaitError::Mesa)? else {
                    continue;
                };
                if let Some(identifier) =
                    evaluate_matched_identity(&message, requested_user_id, identities)
                        .map_err(WaitError::Mesa)?
                {
                    return Ok(match identifier {
                        Some(identifier) => IdentityMatchOutcome::Matched(identifier),
                        None => IdentityMatchOutcome::NoMatch,
                    });
                }
            }
        }
    }
}

fn cancel<Transport: BiometricTransport>(
    transport: &mut Transport,
) -> Result<(), CleanupError<Transport::Error>> {
    let response = transport
        .execute(&cancel_operation_command())
        .map_err(CleanupError::Transport)?;
    validate_empty_response(&response).map_err(CleanupError::Command)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesa::{
        MESA_MATCH_RESULT, MESA_MATCH_RESULT_V1_SIZE, MESA_MESSAGE_HEADER_SIZE,
        MESA_MESSAGE_TYPE_V1, MESA_SERVICE_MESSAGE,
    };
    use std::collections::VecDeque;

    const USER: i32 = 501;
    const OTHER_USER: i32 = 502;
    const IDENTIFIER: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    const OTHER_IDENTIFIER: [u8; 16] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
        0x2f,
    ];

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum SyntheticTransportError {
        Start,
        Cancel,
    }

    impl fmt::Display for SyntheticTransportError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("sensitive transport payload")
        }
    }

    impl std::error::Error for SyntheticTransportError {}

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct SyntheticEventError;

    impl fmt::Display for SyntheticEventError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("sensitive callback payload")
        }
    }

    impl std::error::Error for SyntheticEventError {}

    struct FakeTransport {
        responses: VecDeque<Result<Vec<u8>, SyntheticTransportError>>,
        commands: Vec<(u16, Vec<u8>, usize)>,
    }

    impl FakeTransport {
        fn new(
            responses: impl IntoIterator<Item = Result<Vec<u8>, SyntheticTransportError>>,
        ) -> Self {
            Self {
                responses: responses.into_iter().collect(),
                commands: Vec::new(),
            }
        }
    }

    impl BiometricTransport for FakeTransport {
        type Error = SyntheticTransportError;

        fn execute(
            &mut self,
            packet: &crate::commands::CommandPacket,
        ) -> Result<Vec<u8>, Self::Error> {
            let request = packet.request();
            let command = u16::from_le_bytes(request[2..4].try_into().unwrap());
            self.commands
                .push((command, request.to_vec(), packet.response_capacity()));
            self.responses.pop_front().expect("synthetic response")
        }
    }

    struct FakeEvents {
        events: VecDeque<Result<MatchEvent, SyntheticEventError>>,
        calls: usize,
    }

    impl FakeEvents {
        fn new(events: impl IntoIterator<Item = MatchEvent>) -> Self {
            Self {
                events: events.into_iter().map(Ok).collect(),
                calls: 0,
            }
        }

        fn failing() -> Self {
            Self {
                events: [Err(SyntheticEventError)].into_iter().collect(),
                calls: 0,
            }
        }
    }

    impl MatchEventSource for FakeEvents {
        type Error = SyntheticEventError;

        fn next_event(&mut self) -> Result<MatchEvent, Self::Error> {
            self.calls += 1;
            self.events.pop_front().expect("synthetic event")
        }
    }

    fn user() -> BiometricUserId {
        BiometricUserId::new(i64::from(USER)).unwrap()
    }

    fn identity(user_id: i32, identifier: [u8; 16]) -> Vec<u8> {
        let mut record = Vec::with_capacity(IDENTITY_V1_SIZE);
        record.extend_from_slice(&user_id.to_le_bytes());
        record.extend_from_slice(&identifier);
        record
    }

    fn callback(service: u32, data: Vec<u8>) -> MatchEvent {
        MatchEvent::Callback(ServiceStatusEvent {
            service,
            data,
            reference_timestamp: 0,
            continuous_time_delta: 0,
        })
    }

    fn mesa_message(status: u32, message_type: u32, payload: &[u8]) -> MatchEvent {
        let mut data = vec![0_u8; MESA_MESSAGE_HEADER_SIZE];
        data[8..12].copy_from_slice(&status.to_le_bytes());
        data[12..16].copy_from_slice(&message_type.to_le_bytes());
        data[32..40].copy_from_slice(&(payload.len() as u64).to_le_bytes());
        data.extend_from_slice(payload);
        callback(MESA_SERVICE_MESSAGE, data)
    }

    fn match_result(user_id: i32, identifier: [u8; 16]) -> MatchEvent {
        let mut payload = vec![0_u8; MESA_MATCH_RESULT_V1_SIZE];
        payload[..4].copy_from_slice(&user_id.to_le_bytes());
        payload[4..20].copy_from_slice(&identifier);
        mesa_message(MESA_MATCH_RESULT, MESA_MESSAGE_TYPE_V1, &payload)
    }

    fn successful_transport() -> FakeTransport {
        FakeTransport::new([Ok(Vec::new()), Ok(Vec::new())])
    }

    fn command_codes(transport: &FakeTransport) -> Vec<u16> {
        transport
            .commands
            .iter()
            .map(|(command, _, _)| *command)
            .collect()
    }

    #[test]
    fn validates_identity_list_before_mutating_hardware() {
        let cases = [
            (Vec::new(), "empty"),
            (vec![0; IDENTITY_V1_SIZE - 1], "partial"),
            (identity(OTHER_USER, IDENTIFIER), "wrong user"),
            (identity(USER, [0; 16]), "zero identity"),
        ];
        for (records, description) in cases {
            let mut transport = successful_transport();
            let mut events = FakeEvents::new([]);
            let result = match_fingerprint(&mut transport, &mut events, user(), &records);
            assert!(result.is_err(), "{description}");
            assert!(transport.commands.is_empty(), "{description}");
            assert_eq!(events.calls, 0, "{description}");
        }
    }

    #[test]
    fn matches_only_requested_enrolled_identity_and_always_cancels() {
        let records = identity(USER, IDENTIFIER);
        let mut transport = successful_transport();
        let mut events = FakeEvents::new([
            callback(77, b"opaque unrelated callback".to_vec()),
            mesa_message(0x1234, 9, &[]),
            match_result(USER, IDENTIFIER),
        ]);

        let outcome = match_fingerprint(&mut transport, &mut events, user(), &records).unwrap();
        assert_eq!(outcome, MatchOutcome::Matched);
        assert_eq!(command_codes(&transport), vec![0x04, 0x0c]);
        assert_eq!(events.calls, 3);
        let (_, start, capacity) = &transport.commands[0];
        assert_eq!(start.len(), 8 + 0x44);
        assert_eq!(&start[12..16], &user().as_raw().to_le_bytes());
        assert!(start[16..].iter().all(|byte| *byte == 0));
        assert_eq!(*capacity, 0);
    }

    #[test]
    fn identity_bearing_match_preserves_opaque_identifier() {
        let records = identity(USER, IDENTIFIER);
        let mut transport = successful_transport();
        let mut events = FakeEvents::new([match_result(USER, IDENTIFIER)]);

        let outcome =
            match_fingerprint_identified(&mut transport, &mut events, user(), &records).unwrap();
        assert_eq!(outcome, IdentityMatchOutcome::Matched(IDENTIFIER));
        assert_eq!(command_codes(&transport), vec![0x04, 0x0c]);
    }

    #[test]
    fn no_match_sentinel_and_unknown_identity_are_normal_outcomes() {
        let records = identity(USER, IDENTIFIER);
        for event in [
            match_result(-1, [0; 16]),
            match_result(USER, OTHER_IDENTIFIER),
        ] {
            let mut transport = successful_transport();
            let mut events = FakeEvents::new([event]);
            let outcome = match_fingerprint(&mut transport, &mut events, user(), &records).unwrap();
            assert_eq!(outcome, MatchOutcome::NoMatch);
            assert_eq!(command_codes(&transport), vec![0x04, 0x0c]);
        }

        let mut transport = successful_transport();
        let mut events = FakeEvents::new([match_result(USER, OTHER_IDENTIFIER)]);
        let outcome =
            match_fingerprint_identified(&mut transport, &mut events, user(), &records).unwrap();
        assert_eq!(outcome, IdentityMatchOutcome::NoMatch);
        assert_eq!(command_codes(&transport), vec![0x04, 0x0c]);
    }

    #[test]
    fn cancellation_and_timeout_are_distinct_cleaned_up_outcomes() {
        for (event, expected) in [
            (MatchEvent::Cancelled, MatchOutcome::Cancelled),
            (MatchEvent::TimedOut, MatchOutcome::TimedOut),
        ] {
            let mut transport = successful_transport();
            let mut events = FakeEvents::new([event]);
            let outcome = match_fingerprint(
                &mut transport,
                &mut events,
                user(),
                &identity(USER, IDENTIFIER),
            )
            .unwrap();
            assert_eq!(outcome, expected);
            assert_eq!(command_codes(&transport), vec![0x04, 0x0c]);
        }
    }

    #[test]
    fn ambiguous_start_failure_attempts_best_effort_cancel() {
        let mut transport = FakeTransport::new([
            Err(SyntheticTransportError::Start),
            Err(SyntheticTransportError::Cancel),
        ]);
        let mut events = FakeEvents::new([]);

        let error = match_fingerprint(
            &mut transport,
            &mut events,
            user(),
            &identity(USER, IDENTIFIER),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            MatchWorkflowError::Transport(SyntheticTransportError::Start)
        ));
        assert_eq!(command_codes(&transport), vec![0x04, 0x0c]);
        assert_eq!(events.calls, 0);
    }

    #[test]
    fn malformed_start_response_remains_primary_over_cancel_failure() {
        let mut transport =
            FakeTransport::new([Ok(vec![0xaa]), Err(SyntheticTransportError::Cancel)]);
        let mut events = FakeEvents::new([]);

        let error = match_fingerprint(
            &mut transport,
            &mut events,
            user(),
            &identity(USER, IDENTIFIER),
        )
        .unwrap_err();
        assert!(matches!(error, MatchWorkflowError::Command(_)));
        assert_eq!(command_codes(&transport), vec![0x04, 0x0c]);
    }

    #[test]
    fn wait_and_parser_failures_remain_primary_over_cancel_failure() {
        let records = identity(USER, IDENTIFIER);

        let mut transport =
            FakeTransport::new([Ok(Vec::new()), Err(SyntheticTransportError::Cancel)]);
        let mut events = FakeEvents::failing();
        let error = match_fingerprint(&mut transport, &mut events, user(), &records).unwrap_err();
        assert!(matches!(error, MatchWorkflowError::Event(_)));
        assert_eq!(command_codes(&transport), vec![0x04, 0x0c]);

        let mut transport =
            FakeTransport::new([Ok(Vec::new()), Err(SyntheticTransportError::Cancel)]);
        let mut events = FakeEvents::new([callback(MESA_SERVICE_MESSAGE, vec![0; 3])]);
        let error = match_fingerprint(&mut transport, &mut events, user(), &records).unwrap_err();
        assert!(matches!(error, MatchWorkflowError::Mesa(_)));
        assert_eq!(command_codes(&transport), vec![0x04, 0x0c]);
    }

    #[test]
    fn cleanup_failure_after_normal_outcome_is_reported() {
        let records = identity(USER, IDENTIFIER);

        let mut transport =
            FakeTransport::new([Ok(Vec::new()), Err(SyntheticTransportError::Cancel)]);
        let mut events = FakeEvents::new([match_result(USER, IDENTIFIER)]);
        let error = match_fingerprint(&mut transport, &mut events, user(), &records).unwrap_err();
        assert!(matches!(
            error,
            MatchWorkflowError::CleanupTransport(SyntheticTransportError::Cancel)
        ));

        let mut transport = FakeTransport::new([Ok(Vec::new()), Ok(vec![0xbb])]);
        let mut events = FakeEvents::new([MatchEvent::TimedOut]);
        let error = match_fingerprint(&mut transport, &mut events, user(), &records).unwrap_err();
        assert!(matches!(error, MatchWorkflowError::CleanupCommand(_)));
    }

    #[test]
    fn error_and_event_formatting_never_exposes_opaque_details() {
        let transport_error =
            MatchWorkflowError::<_, SyntheticEventError>::Transport(SyntheticTransportError::Start);
        let event_error =
            MatchWorkflowError::<SyntheticTransportError, _>::Event(SyntheticEventError);
        for rendered in [
            format!("{transport_error:?}"),
            transport_error.to_string(),
            format!("{event_error:?}"),
            event_error.to_string(),
        ] {
            assert!(!rendered.contains("sensitive"));
            assert!(!rendered.contains("payload"));
        }
        assert!(std::error::Error::source(&transport_error).is_none());
        assert!(std::error::Error::source(&event_error).is_none());

        let event = callback(77, b"opaque callback secret".to_vec());
        let rendered = format!("{event:?}");
        assert!(!rendered.contains("opaque"));
        assert!(!rendered.contains("secret"));
        assert!(rendered.contains("data_len"));

        let rendered = format!("{:?}", IdentityMatchOutcome::Matched(IDENTIFIER));
        assert_eq!(rendered, "Matched([redacted])");
        assert!(!rendered.contains("16"));
        assert!(!rendered.contains("31"));
    }
}

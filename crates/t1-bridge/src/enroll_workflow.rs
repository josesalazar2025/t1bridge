//! Transport-agnostic Mesa enrollment orchestration.
//!
//! Socket polling and callback timing stay with the caller. This module owns
//! the command sequence, completion postcondition, and cancellation contract.

use crate::commands::{
    CommandError, CommandPacket, cancel_operation_command, continue_enrollment_command,
    identities_command, start_enrollment_command, validate_empty_response,
    validate_identity_list_response,
};
use crate::control::BiometricTransport;
use crate::mesa::{
    IDENTITY_V1_SIZE, IdentityIdentifier, MesaError, ServiceStatusEvent, enrollment_completion,
    enrollment_needs_continue, parse_identity, parse_mesa_message,
};
use crate::policy::BiometricUserId;
use core::fmt;

/// One deterministic input to the enrollment wait loop.
pub enum EnrollmentEvent {
    /// One acknowledged bridge service-status callback.
    ServiceStatus(ServiceStatusEvent),
    /// The caller's enrollment deadline expired without another callback.
    TimedOut,
}

impl fmt::Debug for EnrollmentEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ServiceStatus(event) => formatter
                .debug_struct("ServiceStatus")
                .field("service", &event.service)
                .field("data_len", &event.data.len())
                .field("data", &"[redacted]")
                .field("reference_timestamp", &event.reference_timestamp)
                .field("continuous_time_delta", &event.continuous_time_delta)
                .finish(),
            Self::TimedOut => formatter.write_str("TimedOut"),
        }
    }
}

/// Supplies acknowledged callbacks or the caller-owned timeout decision.
///
/// Implementations may drain callbacks queued during command RPCs before
/// waiting for new stream input. They must return [`EnrollmentEvent::TimedOut`]
/// when their deterministic deadline expires.
pub trait EnrollmentEventSource {
    /// Source-specific failure retained for programmatic handling.
    type Error;

    /// Returns the next acknowledged callback or timeout outcome.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe callback-delivery failure.
    fn next_event(&mut self) -> Result<EnrollmentEvent, Self::Error>;
}

/// Non-biometric enrollment progress reported by Mesa.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnrollmentProgress {
    value: u64,
}

impl EnrollmentProgress {
    /// Returns Mesa's numeric enrollment progress value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.value
    }
}

/// Successful completion or a cleanly cancelled timeout.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum EnrollmentOutcome {
    /// Enrollment completed and the fresh identity list contained this opaque
    /// identifier for the requested user.
    Completed(IdentityIdentifier),
    /// The caller's deadline expired and cancellation succeeded.
    TimedOut,
}

impl fmt::Debug for EnrollmentOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Completed(_) => formatter.write_str("Completed([redacted])"),
            Self::TimedOut => formatter.write_str("TimedOut"),
        }
    }
}

impl EnrollmentOutcome {
    /// Returns the completed opaque identifier, or `None` for timeout.
    #[must_use]
    pub const fn identifier(self) -> Option<IdentityIdentifier> {
        match self {
            Self::Completed(identifier) => Some(identifier),
            Self::TimedOut => None,
        }
    }
}

/// Operation stage associated with a command failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentStage {
    /// Validate and start enrollment.
    Start,
    /// Continue after one qualifying status callback.
    Continue,
    /// Read the post-completion identity list.
    IdentityList,
    /// Cancel the started operation.
    Cancel,
}

impl fmt::Display for EnrollmentStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start => formatter.write_str("start"),
            Self::Continue => formatter.write_str("continue"),
            Self::IdentityList => formatter.write_str("identity-list"),
            Self::Cancel => formatter.write_str("cancel"),
        }
    }
}

/// Redaction-safe enrollment workflow failure.
pub enum EnrollmentError<TransportError, EventError> {
    /// An encoded command or fixed response failed validation.
    Command {
        /// Command stage that failed.
        stage: EnrollmentStage,
        /// Structural packet or response failure.
        error: CommandError,
    },
    /// The biometric command transport failed.
    Transport {
        /// Command stage that failed.
        stage: EnrollmentStage,
        /// Caller-owned transport failure.
        error: TransportError,
    },
    /// Callback delivery failed after enrollment may have started.
    Event(EventError),
    /// A Mesa callback or identity record was malformed.
    Mesa(MesaError),
    /// Mesa's fresh identity list did not contain its completion identifier
    /// for the requested user.
    CompletedIdentityAbsent,
}

impl<TransportError, EventError> fmt::Debug for EnrollmentError<TransportError, EventError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Command { stage, error } => formatter
                .debug_struct("Command")
                .field("stage", stage)
                .field("error", error)
                .finish(),
            Self::Transport { stage, .. } => formatter
                .debug_struct("Transport")
                .field("stage", stage)
                .field("error", &"[redacted]")
                .finish(),
            Self::Event(_) => formatter.write_str("Event([redacted])"),
            Self::Mesa(error) => formatter.debug_tuple("Mesa").field(error).finish(),
            Self::CompletedIdentityAbsent => formatter.write_str("CompletedIdentityAbsent"),
        }
    }
}

impl<TransportError, EventError> fmt::Display for EnrollmentError<TransportError, EventError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Command { stage, error } => {
                write!(formatter, "enrollment {stage} command failed: {error}")
            }
            Self::Transport { stage, .. } => {
                write!(formatter, "enrollment {stage} transport failed")
            }
            Self::Event(_) => formatter.write_str("enrollment callback delivery failed"),
            Self::Mesa(error) => error.fmt(formatter),
            Self::CompletedIdentityAbsent => formatter
                .write_str("completed enrollment is absent from Mesa's fresh identity list"),
        }
    }
}

impl<TransportError, EventError> std::error::Error for EnrollmentError<TransportError, EventError> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Command { error, .. } => Some(error),
            Self::Mesa(error) => Some(error),
            Self::Transport { .. } | Self::Event(_) | Self::CompletedIdentityAbsent => None,
        }
    }
}

/// Starts and drives one Mesa enrollment operation.
///
/// The user and optional ACM credential are fully validated before the start
/// command is sent. Every qualifying status callback causes exactly one
/// continue command. A completion is accepted only after a fresh identity-list
/// command confirms its opaque identifier for the requested user.
///
/// Start transport failures are ambiguous because Mesa may have accepted the
/// operation before the reply was lost. Those and all later primary failures
/// trigger best-effort cancellation without masking the primary failure.
/// Verified completion returns without cancellation, matching the native
/// successful path. Timeout still requires a successful cancellation response.
///
/// # Errors
///
/// Returns a validation, transport, callback, Mesa, postcondition, or required
/// cancellation failure.
pub fn run_enrollment<T, S>(
    transport: &mut T,
    events: &mut S,
    user_id: i64,
    credential_set: Option<&[u8]>,
    mut progress: Option<&mut dyn FnMut(EnrollmentProgress)>,
) -> Result<EnrollmentOutcome, EnrollmentError<T::Error, S::Error>>
where
    T: BiometricTransport,
    S: EnrollmentEventSource,
{
    let user = BiometricUserId::new(user_id).map_err(|error| EnrollmentError::Command {
        stage: EnrollmentStage::Start,
        error: error.into(),
    })?;
    let start = start_enrollment_command(user, credential_set).map_err(|error| {
        EnrollmentError::Command {
            stage: EnrollmentStage::Start,
            error,
        }
    })?;

    let start_result = execute(transport, &start, EnrollmentStage::Start)
        .and_then(|response| validate_response(EnrollmentStage::Start, &response));
    if let Err(primary) = start_result {
        cancel_best_effort(transport);
        return Err(primary);
    }

    let result = wait_for_completion(transport, events, user, &mut progress);
    match result {
        Ok(EnrollmentOutcome::TimedOut) => {
            cancel_required(transport)?;
            Ok(EnrollmentOutcome::TimedOut)
        }
        Ok(completed @ EnrollmentOutcome::Completed(_)) => Ok(completed),
        Err(primary) => {
            cancel_best_effort(transport);
            Err(primary)
        }
    }
}

fn wait_for_completion<T, S>(
    transport: &mut T,
    events: &mut S,
    user: BiometricUserId,
    progress: &mut Option<&mut dyn FnMut(EnrollmentProgress)>,
) -> Result<EnrollmentOutcome, EnrollmentError<T::Error, S::Error>>
where
    T: BiometricTransport,
    S: EnrollmentEventSource,
{
    loop {
        let event = events.next_event().map_err(EnrollmentError::Event)?;
        let EnrollmentEvent::ServiceStatus(event) = event else {
            return Ok(EnrollmentOutcome::TimedOut);
        };
        let Some(message) = parse_mesa_message(&event).map_err(EnrollmentError::Mesa)? else {
            continue;
        };

        if enrollment_needs_continue(&message) {
            if let Some(callback) = progress.as_deref_mut() {
                callback(EnrollmentProgress {
                    value: message.in_value,
                });
            }
            let response = execute(
                transport,
                &continue_enrollment_command(),
                EnrollmentStage::Continue,
            )?;
            validate_response(EnrollmentStage::Continue, &response)?;
            continue;
        }

        let Some(identifier) = enrollment_completion(&message, user.as_raw().cast_signed())
            .map_err(EnrollmentError::Mesa)?
        else {
            continue;
        };
        verify_fresh_identity(transport, user, identifier)?;
        return Ok(EnrollmentOutcome::Completed(identifier));
    }
}

fn verify_fresh_identity<T, EventError>(
    transport: &mut T,
    user: BiometricUserId,
    identifier: IdentityIdentifier,
) -> Result<(), EnrollmentError<T::Error, EventError>>
where
    T: BiometricTransport,
{
    let response = execute(
        transport,
        &identities_command(user),
        EnrollmentStage::IdentityList,
    )?;
    validate_identity_list_response(&response).map_err(|error| EnrollmentError::Command {
        stage: EnrollmentStage::IdentityList,
        error,
    })?;

    let mut found = false;
    for record in response.chunks(IDENTITY_V1_SIZE) {
        let identity = parse_identity(record).map_err(EnrollmentError::Mesa)?;
        if identity.user_id() == user.as_raw().cast_signed() && identity.identifier() == identifier
        {
            found = true;
        }
    }
    if found {
        Ok(())
    } else {
        Err(EnrollmentError::CompletedIdentityAbsent)
    }
}

fn execute<T, EventError>(
    transport: &mut T,
    packet: &CommandPacket,
    stage: EnrollmentStage,
) -> Result<Vec<u8>, EnrollmentError<T::Error, EventError>>
where
    T: BiometricTransport,
{
    transport
        .execute(packet)
        .map_err(|error| EnrollmentError::Transport { stage, error })
}

fn validate_response<TransportError, EventError>(
    stage: EnrollmentStage,
    response: &[u8],
) -> Result<(), EnrollmentError<TransportError, EventError>> {
    validate_empty_response(response).map_err(|error| EnrollmentError::Command { stage, error })
}

fn cancel_required<T, EventError>(
    transport: &mut T,
) -> Result<(), EnrollmentError<T::Error, EventError>>
where
    T: BiometricTransport,
{
    let response = execute(
        transport,
        &cancel_operation_command(),
        EnrollmentStage::Cancel,
    )?;
    validate_response(EnrollmentStage::Cancel, &response)
}

fn cancel_best_effort<T: BiometricTransport>(transport: &mut T) {
    if let Ok(response) = transport.execute(&cancel_operation_command()) {
        let _ = validate_empty_response(&response);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesa::{
        MESA_ENROLLMENT_COMPLETE, MESA_ENROLLMENT_STATUS, MESA_MESSAGE_HEADER_SIZE,
        MESA_MESSAGE_TYPE_V1, MESA_SERVICE_MESSAGE,
    };
    use std::collections::VecDeque;

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

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct SyntheticTransportError;

    impl fmt::Display for SyntheticTransportError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("private transport marker")
        }
    }

    impl std::error::Error for SyntheticTransportError {}

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct SyntheticEventError;

    impl fmt::Display for SyntheticEventError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("private event marker")
        }
    }

    impl std::error::Error for SyntheticEventError {}

    struct FakeTransport {
        responses: VecDeque<Result<Vec<u8>, SyntheticTransportError>>,
        commands: Vec<u16>,
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

        fn execute(&mut self, packet: &CommandPacket) -> Result<Vec<u8>, Self::Error> {
            self.commands.push(u16::from_le_bytes(
                packet.request()[2..4].try_into().expect("command code"),
            ));
            self.responses
                .pop_front()
                .expect("synthetic response for every command")
        }
    }

    struct FakeEvents {
        events: VecDeque<Result<EnrollmentEvent, SyntheticEventError>>,
    }

    impl FakeEvents {
        fn new(
            events: impl IntoIterator<Item = Result<EnrollmentEvent, SyntheticEventError>>,
        ) -> Self {
            Self {
                events: events.into_iter().collect(),
            }
        }
    }

    impl EnrollmentEventSource for FakeEvents {
        type Error = SyntheticEventError;

        fn next_event(&mut self) -> Result<EnrollmentEvent, Self::Error> {
            self.events.pop_front().expect("synthetic enrollment event")
        }
    }

    fn identity(user: i32, identifier: IdentityIdentifier) -> [u8; IDENTITY_V1_SIZE] {
        let mut record = [0_u8; IDENTITY_V1_SIZE];
        record[..4].copy_from_slice(&user.to_le_bytes());
        record[4..].copy_from_slice(&identifier);
        record
    }

    fn event(
        service: u32,
        status: u32,
        message_type: u32,
        in_value: u64,
        payload: &[u8],
    ) -> EnrollmentEvent {
        let mut data = Vec::with_capacity(MESA_MESSAGE_HEADER_SIZE + payload.len());
        data.extend_from_slice(&0_u64.to_le_bytes());
        data.extend_from_slice(&status.to_le_bytes());
        data.extend_from_slice(&message_type.to_le_bytes());
        data.extend_from_slice(&0_u64.to_le_bytes());
        data.extend_from_slice(&in_value.to_le_bytes());
        data.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        data.extend_from_slice(payload);
        EnrollmentEvent::ServiceStatus(ServiceStatusEvent {
            service,
            data,
            reference_timestamp: 0,
            continuous_time_delta: 0,
        })
    }

    fn status_event(value: u64) -> EnrollmentEvent {
        event(
            MESA_SERVICE_MESSAGE,
            MESA_ENROLLMENT_STATUS,
            MESA_MESSAGE_TYPE_V1,
            value,
            &[],
        )
    }

    fn completion_event(user: i32, identifier: IdentityIdentifier) -> EnrollmentEvent {
        event(
            MESA_SERVICE_MESSAGE,
            MESA_ENROLLMENT_COMPLETE,
            MESA_MESSAGE_TYPE_V1,
            0,
            &identity(user, identifier),
        )
    }

    fn empty() -> Vec<u8> {
        Vec::new()
    }

    #[test]
    fn enrollment_continues_at_exact_boundaries_and_verifies_fresh_identity() {
        let mut listed = identity(OTHER_USER, OTHER_IDENTIFIER).to_vec();
        listed.extend_from_slice(&identity(USER, IDENTIFIER));
        let mut transport = FakeTransport::new([Ok(empty()), Ok(empty()), Ok(empty()), Ok(listed)]);
        let mut events = FakeEvents::new([
            Ok(EnrollmentEvent::ServiceStatus(ServiceStatusEvent {
                service: MESA_SERVICE_MESSAGE - 1,
                data: vec![0xff],
                reference_timestamp: 0,
                continuous_time_delta: 0,
            })),
            Ok(status_event(0x63)),
            Ok(status_event(0x64)),
            Ok(status_event(0x163)),
            Ok(status_event(0x164)),
            Ok(completion_event(USER, IDENTIFIER)),
        ]);
        let mut reported = Vec::new();
        let mut report = |progress: EnrollmentProgress| reported.push(progress.value());

        let outcome = run_enrollment(
            &mut transport,
            &mut events,
            i64::from(USER),
            Some(&[0x5a; 16]),
            Some(&mut report),
        )
        .unwrap();

        assert_eq!(outcome.identifier(), Some(IDENTIFIER));
        assert_eq!(reported, [0x64, 0x163]);
        assert_eq!(transport.commands, [0x03, 0x0e, 0x0e, 0x42]);
    }

    #[test]
    fn timeout_is_non_success_and_requires_successful_cancel() {
        let mut transport = FakeTransport::new([Ok(empty()), Ok(empty())]);
        let mut events = FakeEvents::new([Ok(EnrollmentEvent::TimedOut)]);
        let outcome =
            run_enrollment(&mut transport, &mut events, i64::from(USER), None, None).unwrap();
        assert_eq!(outcome, EnrollmentOutcome::TimedOut);
        assert_eq!(transport.commands, [0x03, 0x0c]);

        let mut transport = FakeTransport::new([Ok(empty()), Err(SyntheticTransportError)]);
        let mut events = FakeEvents::new([Ok(EnrollmentEvent::TimedOut)]);
        assert!(matches!(
            run_enrollment(&mut transport, &mut events, i64::from(USER), None, None),
            Err(EnrollmentError::Transport {
                stage: EnrollmentStage::Cancel,
                ..
            })
        ));
    }

    #[test]
    fn verified_completion_never_sends_cancel() {
        let listed = identity(USER, IDENTIFIER).to_vec();
        let mut transport = FakeTransport::new([Ok(empty()), Ok(listed)]);
        let mut events = FakeEvents::new([Ok(completion_event(USER, IDENTIFIER))]);
        assert_eq!(
            run_enrollment(&mut transport, &mut events, i64::from(USER), None, None).unwrap(),
            EnrollmentOutcome::Completed(IDENTIFIER)
        );
        assert_eq!(transport.commands, [0x03, 0x42]);
    }

    #[test]
    fn invalid_user_and_credential_never_start_or_cancel() {
        let mut transport = FakeTransport::new([]);
        let mut events = FakeEvents::new([]);
        assert!(matches!(
            run_enrollment(&mut transport, &mut events, -1, None, None),
            Err(EnrollmentError::Command {
                stage: EnrollmentStage::Start,
                ..
            })
        ));
        assert!(transport.commands.is_empty());

        assert!(matches!(
            run_enrollment(
                &mut transport,
                &mut events,
                i64::from(USER),
                Some(&[0; 15]),
                None
            ),
            Err(EnrollmentError::Command {
                stage: EnrollmentStage::Start,
                ..
            })
        ));
        assert!(transport.commands.is_empty());
    }

    #[test]
    fn ambiguous_start_failures_cancel_without_masking_primary() {
        let mut transport =
            FakeTransport::new([Err(SyntheticTransportError), Err(SyntheticTransportError)]);
        let mut events = FakeEvents::new([]);
        let error =
            run_enrollment(&mut transport, &mut events, i64::from(USER), None, None).unwrap_err();
        assert!(matches!(
            error,
            EnrollmentError::Transport {
                stage: EnrollmentStage::Start,
                ..
            }
        ));
        assert_eq!(transport.commands, [0x03, 0x0c]);

        let mut transport = FakeTransport::new([Ok(vec![0xaa]), Err(SyntheticTransportError)]);
        let mut events = FakeEvents::new([]);
        assert!(matches!(
            run_enrollment(&mut transport, &mut events, i64::from(USER), None, None),
            Err(EnrollmentError::Command {
                stage: EnrollmentStage::Start,
                ..
            })
        ));
        assert_eq!(transport.commands, [0x03, 0x0c]);
    }

    #[test]
    fn started_primary_errors_cancel_without_being_masked() {
        let mut transport = FakeTransport::new([Ok(empty()), Err(SyntheticTransportError)]);
        let mut events = FakeEvents::new([Err(SyntheticEventError)]);
        assert!(matches!(
            run_enrollment(&mut transport, &mut events, i64::from(USER), None, None),
            Err(EnrollmentError::Event(SyntheticEventError))
        ));
        assert_eq!(transport.commands, [0x03, 0x0c]);

        let mut transport = FakeTransport::new([
            Ok(empty()),
            Err(SyntheticTransportError),
            Err(SyntheticTransportError),
        ]);
        let mut events = FakeEvents::new([Ok(status_event(0x64))]);
        assert!(matches!(
            run_enrollment(&mut transport, &mut events, i64::from(USER), None, None),
            Err(EnrollmentError::Transport {
                stage: EnrollmentStage::Continue,
                ..
            })
        ));
        assert_eq!(transport.commands, [0x03, 0x0e, 0x0c]);

        let mut transport =
            FakeTransport::new([Ok(empty()), Ok(vec![0xaa]), Err(SyntheticTransportError)]);
        let mut events = FakeEvents::new([Ok(status_event(0x64))]);
        assert!(matches!(
            run_enrollment(&mut transport, &mut events, i64::from(USER), None, None),
            Err(EnrollmentError::Command {
                stage: EnrollmentStage::Continue,
                ..
            })
        ));
        assert_eq!(transport.commands, [0x03, 0x0e, 0x0c]);
    }

    #[test]
    fn completion_requires_matching_fresh_identity_for_same_user() {
        for listed in [
            Vec::new(),
            identity(USER, OTHER_IDENTIFIER).to_vec(),
            identity(OTHER_USER, IDENTIFIER).to_vec(),
        ] {
            let mut transport =
                FakeTransport::new([Ok(empty()), Ok(listed), Err(SyntheticTransportError)]);
            let mut events = FakeEvents::new([Ok(completion_event(USER, IDENTIFIER))]);
            assert!(matches!(
                run_enrollment(&mut transport, &mut events, i64::from(USER), None, None),
                Err(EnrollmentError::CompletedIdentityAbsent)
            ));
            assert_eq!(transport.commands, [0x03, 0x42, 0x0c]);
        }

        let mut transport =
            FakeTransport::new([Ok(empty()), Ok(vec![0xaa]), Err(SyntheticTransportError)]);
        let mut events = FakeEvents::new([Ok(completion_event(USER, IDENTIFIER))]);
        assert!(matches!(
            run_enrollment(&mut transport, &mut events, i64::from(USER), None, None),
            Err(EnrollmentError::Command {
                stage: EnrollmentStage::IdentityList,
                ..
            })
        ));
        assert_eq!(transport.commands, [0x03, 0x42, 0x0c]);
    }

    #[test]
    fn malformed_callback_and_identity_are_primary_errors() {
        let malformed = EnrollmentEvent::ServiceStatus(ServiceStatusEvent {
            service: MESA_SERVICE_MESSAGE,
            data: vec![0; MESA_MESSAGE_HEADER_SIZE - 1],
            reference_timestamp: 0,
            continuous_time_delta: 0,
        });
        let mut transport = FakeTransport::new([Ok(empty()), Err(SyntheticTransportError)]);
        let mut events = FakeEvents::new([Ok(malformed)]);
        assert!(matches!(
            run_enrollment(&mut transport, &mut events, i64::from(USER), None, None),
            Err(EnrollmentError::Mesa(
                MesaError::TruncatedMessageHeader { .. }
            ))
        ));

        let mut transport = FakeTransport::new([
            Ok(empty()),
            Ok(vec![0; IDENTITY_V1_SIZE]),
            Err(SyntheticTransportError),
        ]);
        let mut events = FakeEvents::new([Ok(completion_event(USER, IDENTIFIER))]);
        assert!(matches!(
            run_enrollment(&mut transport, &mut events, i64::from(USER), None, None),
            Err(EnrollmentError::Mesa(MesaError::ZeroIdentityIdentifier))
        ));

        let mut listed = identity(USER, IDENTIFIER).to_vec();
        listed.extend_from_slice(&[0; IDENTITY_V1_SIZE]);
        let mut transport =
            FakeTransport::new([Ok(empty()), Ok(listed), Err(SyntheticTransportError)]);
        let mut events = FakeEvents::new([Ok(completion_event(USER, IDENTIFIER))]);
        assert!(matches!(
            run_enrollment(&mut transport, &mut events, i64::from(USER), None, None),
            Err(EnrollmentError::Mesa(MesaError::ZeroIdentityIdentifier))
        ));
    }

    #[test]
    fn errors_events_and_outcomes_are_redaction_safe() {
        let transport_error: EnrollmentError<SyntheticTransportError, SyntheticEventError> =
            EnrollmentError::Transport {
                stage: EnrollmentStage::Start,
                error: SyntheticTransportError,
            };
        let event_error: EnrollmentError<SyntheticTransportError, SyntheticEventError> =
            EnrollmentError::Event(SyntheticEventError);
        assert!(std::error::Error::source(&transport_error).is_none());
        assert!(std::error::Error::source(&event_error).is_none());
        for rendered in [
            format!("{transport_error}"),
            format!("{transport_error:?}"),
            format!("{event_error}"),
            format!("{event_error:?}"),
            format!("{:?}", EnrollmentOutcome::Completed(IDENTIFIER)),
            format!(
                "{:?}",
                event(
                    MESA_SERVICE_MESSAGE,
                    MESA_ENROLLMENT_STATUS,
                    MESA_MESSAGE_TYPE_V1,
                    0x64,
                    &[0xde, 0xad, 0xbe, 0xef]
                )
            ),
        ] {
            assert!(!rendered.contains("private transport marker"));
            assert!(!rendered.contains("private event marker"));
            assert!(!rendered.contains("222"));
            assert!(!rendered.contains("173"));
        }
    }
}

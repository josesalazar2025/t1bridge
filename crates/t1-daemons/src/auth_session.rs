//! Transport-independent authentication broker session coordination.
//!
//! Socket activation, peer-credential acquisition, device I/O, clocks, and
//! process lifetimes remain caller-owned. This module joins the existing pure
//! broker state, cancellation delivery, authentication lifecycle, operation,
//! and cosmetic feedback contracts.

use core::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use t1_bridge::control::BiometricTransport;
use t1_bridge::match_workflow::{MatchEvent, MatchEventSource, MatchOutcome};
use t1_bridge::policy::{ACM_CONTEXT_EXTERNAL_FORM_SIZE, BiometricUserId};
use t1_bridge::policy_workflow::UserPolicyRetryRuntime;

use crate::auth_feedback::{
    AuthenticationFeedback, apply_authentication_feedback, initial_overlay_state,
};
use crate::auth_operation::authenticate_user_after_calibration;
use crate::auth_protocol::{
    AccessPolicy, BrokerDecision, BrokerState, EnrollmentOwnerCandidate, Operation,
    OperationResult, OperationToken, PeerMetadata, Purpose, Response,
};
use crate::catacomb_store::CatacombPairStore;
use crate::overlay::{CancellationSlot, OverlayState};
use crate::standard_fingerprint_protocol::{ServerMessage, TerminalOutcome};
use crate::standard_operation_authority::{
    AuthorizedStandardOperation, ResolvedStandardOperation, StandardBrokerDecision,
};

/// Result of dispatching one already-framed peer packet.
pub enum SessionDecision {
    /// A fixed response can be returned immediately.
    Reply(Response),
    /// One authenticated operation may be run outside the coordinator borrow.
    Start(ActiveAuthentication),
}

/// Result of dispatching one resolved standard fingerprint operation.
pub enum StandardSessionDecision {
    /// A typed standard response can be returned immediately.
    Reply(ServerMessage),
    /// One standard operation may run outside the coordinator borrow.
    Start(ActiveStandardOperation),
}

impl fmt::Debug for StandardSessionDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reply(response) => formatter.debug_tuple("Reply").field(response).finish(),
            Self::Start(active) => formatter.debug_tuple("Start").field(active).finish(),
        }
    }
}

impl fmt::Debug for SessionDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reply(response) => formatter.debug_tuple("Reply").field(response).finish(),
            Self::Start(active) => formatter.debug_tuple("Start").field(active).finish(),
        }
    }
}

/// One token-associated operation and its cancellation delivery event.
pub struct ActiveAuthentication {
    operation: Operation,
    event: Arc<AtomicBool>,
    slot: Arc<CancellationSlot>,
}

impl fmt::Debug for ActiveAuthentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActiveAuthentication")
            .field("token", &self.operation.token)
            .field("purpose", &self.operation.purpose)
            .field("cancelled", &self.is_cancelled())
            .finish_non_exhaustive()
    }
}

impl ActiveAuthentication {
    #[cfg(feature = "auth-broker-service")]
    pub(crate) fn clone_for_worker(&self) -> Self {
        Self {
            operation: self.operation,
            event: Arc::clone(&self.event),
            slot: Arc::clone(&self.slot),
        }
    }

    #[cfg(feature = "auth-broker-service")]
    pub(crate) fn completion_for_worker(
        &self,
        result: Result<MatchOutcome, AuthenticationSessionFailure>,
    ) -> AuthenticationCompletion {
        AuthenticationCompletion::new(self, result)
    }

    /// Presentation selected by the authenticated request.
    #[must_use]
    pub const fn purpose(&self) -> Purpose {
        self.operation.purpose
    }

    /// Candidate kernel identity to claim only after successful enrollment.
    #[must_use]
    pub const fn enrollment_owner_candidate(&self) -> Option<EnrollmentOwnerCandidate> {
        self.operation.enrollment_owner_candidate
    }

    /// Initial cosmetic state for this request's presentation.
    #[must_use]
    pub const fn initial_overlay_state(&self) -> OverlayState {
        initial_overlay_state(self.operation.purpose)
    }

    /// Whether token-associated cancellation has reached this worker.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.event.load(Ordering::Acquire)
    }

    /// Closes token-associated cancellation delivery after Mesa has chosen an
    /// authoritative enrollment result but before durable persistence ends.
    ///
    /// `BrokerState` still owns authorization: a later cancel is denied
    /// because delivery cannot succeed, so it is never recorded as accepted.
    #[must_use]
    pub(crate) fn close_cancellation(&self) -> bool {
        self.slot.close(self.operation.token, &self.event)
    }

    fn clear_delivery(&self) {
        self.slot.clear(self.operation.token, &self.event);
    }
}

/// One exact standard operation and its shared cancellation registration.
pub struct ActiveStandardOperation {
    operation: AuthorizedStandardOperation,
    event: Arc<AtomicBool>,
    slot: Arc<CancellationSlot>,
}

impl fmt::Debug for ActiveStandardOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActiveStandardOperation")
            .field("operation", &self.operation)
            .field("cancelled", &self.is_cancelled())
            .finish_non_exhaustive()
    }
}

impl ActiveStandardOperation {
    /// Clones the exact authority and shared cancellation registration for a worker.
    #[must_use]
    pub fn clone_for_worker(&self) -> Self {
        Self {
            operation: self.operation.clone_for_worker(),
            event: Arc::clone(&self.event),
            slot: Arc::clone(&self.slot),
        }
    }

    /// Binds one worker result to this exact operation and cancellation slot.
    #[must_use]
    pub fn completion_for_worker(&self, result: ServerMessage) -> StandardCompletion {
        StandardCompletion::new(self, result)
    }

    /// Exact authority and payload bound at broker admission.
    #[must_use]
    pub const fn operation(&self) -> &AuthorizedStandardOperation {
        &self.operation
    }

    /// Whether token-associated cancellation has reached this worker.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.event.load(Ordering::Acquire)
    }

    /// Closes cancellation delivery at an authoritative mutation cutoff.
    #[must_use]
    pub fn close_cancellation(&self) -> bool {
        self.slot.close(self.operation.token(), &self.event)
    }

    fn clear_delivery(&self) {
        self.slot.clear(self.operation.token(), &self.event);
    }
}

/// Static, payload-free authentication session failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationSessionFailure {
    InvalidOperationUser,
    RelayInactive,
    RelayHealth,
    RelayStop,
    ExclusiveSepAndAcm,
    RelayRecovery,
    InvalidCredential,
    Operation,
}

impl fmt::Display for AuthenticationSessionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidOperationUser => "broker operation user is invalid",
            Self::RelayInactive => "keybag relay is inactive",
            Self::RelayHealth => "keybag relay health check failed",
            Self::RelayStop => "keybag relay stop failed",
            Self::ExclusiveSepAndAcm => "exclusive SEP or ACM lease failed",
            Self::RelayRecovery => "keybag relay recovery failed",
            Self::InvalidCredential => "ACM lease returned an invalid credential",
            Self::Operation => "authentication operation failed",
        })
    }
}

impl std::error::Error for AuthenticationSessionFailure {}

/// Completed product work awaiting an exact token-associated broker response.
pub struct AuthenticationCompletion {
    token: OperationToken,
    event: Arc<AtomicBool>,
    slot: Arc<CancellationSlot>,
    result: Result<MatchOutcome, AuthenticationSessionFailure>,
}

impl fmt::Debug for AuthenticationCompletion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticationCompletion")
            .field("token", &self.token)
            .field("result", &self.result)
            .finish_non_exhaustive()
    }
}

impl AuthenticationCompletion {
    /// Typed biometric outcome or static redacted failure.
    ///
    /// # Errors
    ///
    /// Returns the payload-free failure selected by the completed lifecycle.
    pub const fn result(&self) -> Result<MatchOutcome, AuthenticationSessionFailure> {
        self.result
    }

    pub(crate) fn belongs_to(&self, active: &ActiveAuthentication) -> bool {
        self.token == active.operation.token
            && Arc::ptr_eq(&self.event, &active.event)
            && Arc::ptr_eq(&self.slot, &active.slot)
    }

    #[cfg(test)]
    pub(crate) fn matched_for_test(active: &ActiveAuthentication) -> Self {
        Self::new(active, Ok(MatchOutcome::Matched))
    }

    fn new(
        active: &ActiveAuthentication,
        result: Result<MatchOutcome, AuthenticationSessionFailure>,
    ) -> Self {
        Self {
            token: active.operation.token,
            event: Arc::clone(&active.event),
            slot: Arc::clone(&active.slot),
            result,
        }
    }
}

/// Completed standard work awaiting exact token-associated finalization.
pub struct StandardCompletion {
    token: OperationToken,
    event: Arc<AtomicBool>,
    slot: Arc<CancellationSlot>,
    result: ServerMessage,
}

impl fmt::Debug for StandardCompletion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StandardCompletion")
            .field("token", &self.token)
            .field("result", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl StandardCompletion {
    /// Terminal or identity-list result selected by the standard worker.
    #[must_use]
    pub const fn result(&self) -> &ServerMessage {
        &self.result
    }

    pub(crate) fn belongs_to(&self, active: &ActiveStandardOperation) -> bool {
        self.token == active.operation.token()
            && Arc::ptr_eq(&self.event, &active.event)
            && Arc::ptr_eq(&self.slot, &active.slot)
    }

    fn new(active: &ActiveStandardOperation, result: ServerMessage) -> Self {
        let result = match result {
            ServerMessage::IdentityList { .. } | ServerMessage::Terminal(_) => result,
            ServerMessage::Capabilities(_)
            | ServerMessage::Opened
            | ServerMessage::EnrollProgress(_) => ServerMessage::Terminal(TerminalOutcome::Error),
        };
        Self {
            token: active.operation.token(),
            event: Arc::clone(&active.event),
            slot: Arc::clone(&active.slot),
            result,
        }
    }
}

/// Single-authority broker state plus token-associated cancellation delivery.
#[derive(Debug, Default)]
pub struct BrokerSessionCoordinator {
    state: BrokerState,
    cancellation: Arc<CancellationSlot>,
}

impl BrokerSessionCoordinator {
    /// Authorizes and dispatches one exact packet.
    ///
    /// Unauthorized or malformed requests are denied before an operation is
    /// created. Cancellation is acknowledged only when the active token's
    /// delivery event is set successfully.
    #[must_use]
    pub fn dispatch(
        &mut self,
        peer: PeerMetadata,
        policy: AccessPolicy,
        packet: &[u8],
    ) -> SessionDecision {
        let cancellation = Arc::clone(&self.cancellation);
        let decision =
            self.state
                .handle_packet_with_cancellation(peer, policy, packet, move |token| {
                    cancellation.deliver(token)
                });
        self.install_decision(decision)
    }

    /// Starts an already-decoded enrollment for a validated local non-root peer
    /// only when durable owner state is authoritatively missing.
    #[must_use]
    pub(crate) fn enroll_without_owner(&mut self, peer: PeerMetadata) -> SessionDecision {
        let decision = self.state.enroll_without_owner(peer);
        self.install_decision(decision)
    }

    /// Authorizes and installs one resolved standard operation on the same
    /// broker token and cancellation slot used by legacy requests.
    #[must_use]
    pub fn dispatch_standard(
        &mut self,
        peer: PeerMetadata,
        recorded_owner: Option<AccessPolicy>,
        operation: ResolvedStandardOperation,
    ) -> StandardSessionDecision {
        let decision = self
            .state
            .dispatch_standard(peer, recorded_owner, operation);
        self.install_standard_decision(decision)
    }

    fn install_decision(&mut self, decision: BrokerDecision) -> SessionDecision {
        match decision {
            BrokerDecision::Reply(response) => SessionDecision::Reply(response),
            BrokerDecision::Start(operation) => {
                let event = Arc::new(AtomicBool::new(false));
                if self
                    .cancellation
                    .install(operation.token, Arc::clone(&event))
                    .is_err()
                {
                    let _ = self.state.finish(operation.token, OperationResult::Failed);
                    return SessionDecision::Reply(Response::Failure);
                }
                SessionDecision::Start(ActiveAuthentication {
                    operation,
                    event,
                    slot: Arc::clone(&self.cancellation),
                })
            }
        }
    }

    fn install_standard_decision(
        &mut self,
        decision: StandardBrokerDecision,
    ) -> StandardSessionDecision {
        match decision {
            StandardBrokerDecision::Reply(response) => StandardSessionDecision::Reply(response),
            StandardBrokerDecision::Start(operation) => {
                let event = Arc::new(AtomicBool::new(false));
                if self
                    .cancellation
                    .install(operation.token(), Arc::clone(&event))
                    .is_err()
                {
                    let response = self
                        .state
                        .finish_standard(
                            &operation,
                            ServerMessage::Terminal(TerminalOutcome::Error),
                        )
                        .unwrap_or(ServerMessage::Terminal(TerminalOutcome::Error));
                    return StandardSessionDecision::Reply(response);
                }
                StandardSessionDecision::Start(ActiveStandardOperation {
                    operation,
                    event,
                    slot: Arc::clone(&self.cancellation),
                })
            }
        }
    }

    /// Delivers one root cancellation without requiring enrollment-owner
    /// storage to remain readable after the operation started.
    ///
    /// The transport must have already decoded an exact cancellation packet.
    /// This path cannot construct or start biometric work.
    #[must_use]
    pub(crate) fn cancel_without_owner(&mut self, peer: PeerMetadata) -> Response {
        let cancellation = Arc::clone(&self.cancellation);
        let BrokerDecision::Reply(response) = self
            .state
            .cancel_without_owner(peer, move |token| cancellation.deliver(token))
        else {
            unreachable!("ownerless cancellation cannot start work")
        };
        response
    }

    /// Delivers disconnect cancellation for exactly this active token.
    ///
    /// A stale handle or failed delivery leaves a newer operation untouched.
    pub fn client_disconnected(&mut self, active: &ActiveAuthentication) -> bool {
        if !Arc::ptr_eq(&active.slot, &self.cancellation) {
            return false;
        }
        let cancellation = Arc::clone(&self.cancellation);
        self.state
            .client_disconnected(active.operation.token, move |token| {
                cancellation.deliver(token)
            })
    }

    /// Delivers same-connection cancellation to one exact standard operation.
    pub fn cancel_standard(&mut self, active: &ActiveStandardOperation) -> bool {
        if !Arc::ptr_eq(&active.slot, &self.cancellation) {
            return false;
        }
        let cancellation = Arc::clone(&self.cancellation);
        self.state
            .cancel_standard(&active.operation, move |token| cancellation.deliver(token))
    }

    /// Delivers disconnect cancellation to one exact standard operation.
    pub fn standard_client_disconnected(&mut self, active: &ActiveStandardOperation) -> bool {
        if !Arc::ptr_eq(&active.slot, &self.cancellation) {
            return false;
        }
        let cancellation = Arc::clone(&self.cancellation);
        self.state
            .standard_client_disconnected(&active.operation, move |token| {
                cancellation.deliver(token)
            })
    }

    /// Commits one completed operation to the exact broker response protocol.
    ///
    /// A delivered cancellation wins over a later match. A stale completion
    /// fails closed and cannot finish a newer operation.
    pub fn finish(&mut self, completion: &AuthenticationCompletion) -> Response {
        self.finalize(completion).0
    }

    /// Commits a completion only when it belongs to the named socket session.
    ///
    /// This prevents a caller-owned transport loop from accidentally sending
    /// one connection's result to another connection after a stale wakeup.
    pub fn finish_for(
        &mut self,
        active: &ActiveAuthentication,
        completion: &AuthenticationCompletion,
    ) -> Response {
        if !Arc::ptr_eq(&active.slot, &self.cancellation) || !completion.belongs_to(active) {
            return Response::Failure;
        }
        self.finish(completion)
    }

    /// Finalizes one standard completion only for its exact active connection.
    #[must_use]
    pub fn finish_standard(
        &mut self,
        active: &ActiveStandardOperation,
        completion: &StandardCompletion,
    ) -> ServerMessage {
        if !Arc::ptr_eq(&active.slot, &self.cancellation) || !completion.belongs_to(active) {
            return ServerMessage::Terminal(TerminalOutcome::Error);
        }
        active.clear_delivery();
        self.state
            .finish_standard(&active.operation, completion.result.clone())
            .unwrap_or(ServerMessage::Terminal(TerminalOutcome::Error))
    }

    /// Finalizes one exact token and then applies best-effort cosmetic feedback.
    ///
    /// The delivery registration is removed before broker finalization, so no
    /// cancellation can be accepted after the authoritative result is chosen.
    /// Stale and cancelled completions never emit feedback.
    pub fn finish_with_feedback<Feedback: AuthenticationFeedback>(
        &mut self,
        completion: &AuthenticationCompletion,
        feedback: Option<&mut Feedback>,
    ) -> Response {
        let (response, authoritative) = self.finalize(completion);
        if authoritative {
            let _ = apply_authentication_feedback(completion.result, feedback);
        }
        response
    }

    fn finalize(&mut self, completion: &AuthenticationCompletion) -> (Response, bool) {
        if !Arc::ptr_eq(&completion.slot, &self.cancellation) {
            return (Response::Failure, false);
        }
        self.cancellation.clear(completion.token, &completion.event);
        let cancelled = self.state.is_cancelled(completion.token);
        let result = match completion.result {
            Ok(MatchOutcome::Matched) => OperationResult::Matched,
            Ok(MatchOutcome::NoMatch) => OperationResult::NoMatch,
            Ok(MatchOutcome::Cancelled) => OperationResult::Cancelled,
            Ok(MatchOutcome::TimedOut) => OperationResult::Unavailable,
            Err(_) => OperationResult::Failed,
        };
        let Some(response) = self.state.finish(completion.token, result) else {
            return (Response::Failure, false);
        };
        (response, !cancelled)
    }

    /// Fails and releases an operation that cannot be handed to a worker.
    pub fn abandon(&mut self, active: &ActiveAuthentication) -> Response {
        if !Arc::ptr_eq(&active.slot, &self.cancellation) {
            return Response::Failure;
        }
        active.clear_delivery();
        self.state
            .finish(active.operation.token, OperationResult::Failed)
            .unwrap_or(Response::Failure)
    }

    /// Fails and releases standard work that could not reach a worker.
    #[must_use]
    pub fn abandon_standard(&mut self, active: &ActiveStandardOperation) -> ServerMessage {
        if !Arc::ptr_eq(&active.slot, &self.cancellation) {
            return ServerMessage::Terminal(TerminalOutcome::Error);
        }
        active.clear_delivery();
        self.state
            .finish_standard(
                &active.operation,
                ServerMessage::Terminal(TerminalOutcome::Error),
            )
            .unwrap_or(ServerMessage::Terminal(TerminalOutcome::Error))
    }
}

/// Caller-owned inputs to the complete inner authentication operation.
pub struct AuthenticationProductInputs<'a, Transport, RetryRuntime, Events> {
    pub transport: &'a mut Transport,
    pub retry_runtime: &'a mut RetryRuntime,
    pub events: &'a mut Events,
    pub durable_pair: Option<&'a CatacombPairStore>,
    pub before_match: &'a mut dyn FnMut(),
    pub after_match: &'a mut dyn FnMut(MatchOutcome),
    pub teardown_presentation: &'a mut dyn FnMut(),
}

#[must_use]
pub fn run_authentication_product<Transport, RetryRuntime, Events>(
    active: &ActiveAuthentication,
    credential: &[u8],
    inputs: AuthenticationProductInputs<'_, Transport, RetryRuntime, Events>,
) -> AuthenticationCompletion
where
    Transport: BiometricTransport,
    RetryRuntime: UserPolicyRetryRuntime<Transport::Error>,
    Events: MatchEventSource,
{
    let AuthenticationProductInputs {
        transport,
        retry_runtime,
        events,
        durable_pair,
        before_match,
        after_match,
        teardown_presentation,
    } = inputs;
    let Ok(user) = BiometricUserId::new(i64::from(active.operation.biometric_user_id)) else {
        return AuthenticationCompletion::new(
            active,
            Err(AuthenticationSessionFailure::InvalidOperationUser),
        );
    };

    if credential.len() != ACM_CONTEXT_EXTERNAL_FORM_SIZE {
        return AuthenticationCompletion::new(
            active,
            Err(AuthenticationSessionFailure::InvalidCredential),
        );
    }
    if active.is_cancelled() {
        return AuthenticationCompletion::new(active, Ok(MatchOutcome::Cancelled));
    }
    let result = {
        let _teardown = PresentationTeardown(teardown_presentation);
        let mut events = CancellationEvents {
            inner: events,
            active,
        };
        authenticate_user_after_calibration(
            transport,
            retry_runtime,
            &mut events,
            user,
            durable_pair,
            Some(credential),
            before_match,
            after_match,
        )
        .map_err(|_| AuthenticationSessionFailure::Operation)
    };
    let result = match result {
        Ok(_) if active.is_cancelled() => Ok(MatchOutcome::Cancelled),
        result => result,
    };
    AuthenticationCompletion::new(active, result)
}

struct PresentationTeardown<'a>(&'a mut dyn FnMut());

impl Drop for PresentationTeardown<'_> {
    fn drop(&mut self) {
        (self.0)();
    }
}

struct CancellationEvents<'a, Events> {
    inner: &'a mut Events,
    active: &'a ActiveAuthentication,
}

impl<Events: MatchEventSource> MatchEventSource for CancellationEvents<'_, Events> {
    type Error = Events::Error;

    fn next_event(&mut self) -> Result<MatchEvent, Self::Error> {
        if self.active.is_cancelled() {
            return Ok(MatchEvent::Cancelled);
        }
        let event = self.inner.next_event()?;
        if self.active.is_cancelled() {
            Ok(MatchEvent::Cancelled)
        } else {
            Ok(event)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_feedback::FeedbackAction;
    use crate::auth_protocol::{
        APPROVE_REQUEST, AUTHENTICATE_REQUEST, CANCEL_REQUEST, ENROLL_REQUEST, PeerAddressFamily,
    };
    use crate::standard_fingerprint_protocol::{FingerLabel, IdentityId, Username};
    use crate::standard_operation_authority::{ResolvedStandardAccount, ResolvedStandardOperation};

    const INTERACTIVE_USER: u32 = 42_000;

    fn peer(user_id: u32) -> PeerMetadata {
        PeerMetadata {
            address_family: PeerAddressFamily::Local,
            user_id,
            group_id: 42_001,
        }
    }

    fn policy() -> AccessPolicy {
        AccessPolicy::new(INTERACTIVE_USER).unwrap()
    }

    fn start(coordinator: &mut BrokerSessionCoordinator, packet: &[u8]) -> ActiveAuthentication {
        let SessionDecision::Start(active) =
            coordinator.dispatch(peer(INTERACTIVE_USER), policy(), packet)
        else {
            panic!("synthetic request must start")
        };
        active
    }

    fn account() -> ResolvedStandardAccount {
        let name = Username::new("synthetic-owner").unwrap();
        ResolvedStandardAccount::new(&name, &name, INTERACTIVE_USER).unwrap()
    }

    fn identity(seed: u8) -> IdentityId {
        IdentityId::new([seed; 16]).unwrap()
    }

    fn standard_start(
        coordinator: &mut BrokerSessionCoordinator,
        operation: ResolvedStandardOperation,
    ) -> ActiveStandardOperation {
        let StandardSessionDecision::Start(active) =
            coordinator.dispatch_standard(peer(INTERACTIVE_USER), Some(policy()), operation)
        else {
            panic!("synthetic standard request must start")
        };
        active
    }

    #[test]
    fn standard_and_legacy_requests_share_token_and_cancellation_authority() {
        let mut coordinator = BrokerSessionCoordinator::default();
        let standard = standard_start(
            &mut coordinator,
            ResolvedStandardOperation::Identify { account: account() },
        );
        let worker = standard.clone_for_worker();
        assert!(matches!(
            coordinator.dispatch(peer(INTERACTIVE_USER), policy(), AUTHENTICATE_REQUEST),
            SessionDecision::Reply(Response::Busy)
        ));
        assert!(coordinator.cancel_standard(&standard));
        assert!(worker.is_cancelled());
        let completion =
            worker.completion_for_worker(ServerMessage::Terminal(TerminalOutcome::NoMatch));
        assert_eq!(
            coordinator.finish_standard(&standard, &completion),
            ServerMessage::Terminal(TerminalOutcome::Cancelled)
        );

        let legacy = start(&mut coordinator, AUTHENTICATE_REQUEST);
        assert!(matches!(
            coordinator.dispatch_standard(
                peer(INTERACTIVE_USER),
                Some(policy()),
                ResolvedStandardOperation::Identify { account: account() },
            ),
            StandardSessionDecision::Reply(ServerMessage::Terminal(TerminalOutcome::Busy))
        ));
        assert_eq!(coordinator.abandon(&legacy), Response::Failure);
    }

    #[test]
    fn standard_cancel_disconnect_and_completion_require_the_exact_connection_handle() {
        let mut first = BrokerSessionCoordinator::default();
        let mut second = BrokerSessionCoordinator::default();
        let first_active = standard_start(
            &mut first,
            ResolvedStandardOperation::Verify {
                account: account(),
                identity: identity(0x11),
            },
        );
        let second_active = standard_start(
            &mut second,
            ResolvedStandardOperation::Verify {
                account: account(),
                identity: identity(0x11),
            },
        );
        let foreign = second_active.completion_for_worker(ServerMessage::Terminal(
            TerminalOutcome::Matched(identity(0x11)),
        ));

        assert!(!first.cancel_standard(&second_active));
        assert!(!first.standard_client_disconnected(&second_active));
        assert_eq!(
            first.finish_standard(&first_active, &foreign),
            ServerMessage::Terminal(TerminalOutcome::Error)
        );
        assert!(matches!(
            first.dispatch(peer(INTERACTIVE_USER), policy(), AUTHENTICATE_REQUEST),
            SessionDecision::Reply(Response::Busy)
        ));

        assert!(first.standard_client_disconnected(&first_active));
        let completion = first_active.completion_for_worker(ServerMessage::Terminal(
            TerminalOutcome::Matched(identity(0x11)),
        ));
        assert_eq!(
            first.finish_standard(&first_active, &completion),
            ServerMessage::Terminal(TerminalOutcome::Cancelled)
        );
        assert_eq!(
            second.abandon_standard(&second_active),
            ServerMessage::Terminal(TerminalOutcome::Error)
        );
    }

    #[test]
    fn standard_mutation_cutoff_rejects_late_cancellation() {
        let mut coordinator = BrokerSessionCoordinator::default();
        let enrollment = standard_start(
            &mut coordinator,
            ResolvedStandardOperation::Enroll {
                account: account(),
                finger: FingerLabel::RightIndex,
            },
        );
        assert!(enrollment.close_cancellation());
        assert!(!coordinator.cancel_standard(&enrollment));
        let enrolled = identity(0x21);
        let completion = enrollment
            .completion_for_worker(ServerMessage::Terminal(TerminalOutcome::Enrolled(enrolled)));
        assert_eq!(
            coordinator.finish_standard(&enrollment, &completion),
            ServerMessage::Terminal(TerminalOutcome::Enrolled(enrolled))
        );
    }

    struct FeedbackError(&'static str);

    impl fmt::Debug for FeedbackError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str(self.0)
        }
    }

    struct FakeFeedback {
        calls: Vec<FeedbackAction>,
        fail: bool,
    }

    impl AuthenticationFeedback for FakeFeedback {
        type Error = FeedbackError;

        fn apply(&mut self, action: FeedbackAction) -> Result<(), Self::Error> {
            self.calls.push(action);
            if self.fail {
                Err(FeedbackError("private cosmetic marker"))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn denies_before_start_and_allows_only_one_active_operation() {
        let mut coordinator = BrokerSessionCoordinator::default();
        assert!(matches!(
            coordinator.dispatch(peer(INTERACTIVE_USER + 1), policy(), AUTHENTICATE_REQUEST),
            SessionDecision::Reply(Response::Denied)
        ));
        assert!(matches!(
            coordinator.dispatch(peer(INTERACTIVE_USER), policy(), b"malformed"),
            SessionDecision::Reply(Response::Denied)
        ));

        let active = start(&mut coordinator, AUTHENTICATE_REQUEST);
        assert_eq!(active.purpose(), Purpose::Authenticate);
        assert_eq!(active.initial_overlay_state(), OverlayState::Authenticate);
        assert!(matches!(
            coordinator.dispatch(peer(INTERACTIVE_USER), policy(), APPROVE_REQUEST),
            SessionDecision::Reply(Response::Busy)
        ));
        assert_eq!(coordinator.abandon(&active), Response::Failure);

        let approval = start(&mut coordinator, APPROVE_REQUEST);
        assert_eq!(approval.purpose(), Purpose::Approve);
        assert_eq!(approval.initial_overlay_state(), OverlayState::Approve);
        assert_eq!(coordinator.abandon(&approval), Response::Failure);

        let enrollment = start(&mut coordinator, ENROLL_REQUEST);
        assert_eq!(enrollment.purpose(), Purpose::Enrollment);
        assert_eq!(enrollment.initial_overlay_state(), OverlayState::Enrollment);
        assert_eq!(
            enrollment
                .enrollment_owner_candidate()
                .expect("recorded owner is the re-enrollment candidate")
                .user_id(),
            INTERACTIVE_USER
        );
        assert_eq!(coordinator.abandon(&enrollment), Response::Failure);
    }

    #[test]
    fn missing_owner_enrollment_uses_the_same_busy_and_cancel_authority() {
        let mut coordinator = BrokerSessionCoordinator::default();
        let SessionDecision::Start(enrollment) =
            coordinator.enroll_without_owner(peer(INTERACTIVE_USER))
        else {
            panic!("validated missing-owner candidate starts enrollment")
        };
        assert_eq!(enrollment.purpose(), Purpose::Enrollment);
        assert_eq!(
            enrollment
                .enrollment_owner_candidate()
                .expect("candidate travels with active operation")
                .user_id(),
            INTERACTIVE_USER
        );
        assert!(matches!(
            coordinator.dispatch(peer(INTERACTIVE_USER), policy(), AUTHENTICATE_REQUEST),
            SessionDecision::Reply(Response::Busy)
        ));
        assert_eq!(coordinator.cancel_without_owner(peer(0)), Response::Okay);
        assert!(enrollment.is_cancelled());
        assert_eq!(coordinator.abandon(&enrollment), Response::Failure);
    }

    #[test]
    fn cancellation_requires_authorized_token_associated_delivery() {
        let mut coordinator = BrokerSessionCoordinator::default();
        assert!(matches!(
            coordinator.dispatch(peer(0), policy(), CANCEL_REQUEST),
            SessionDecision::Reply(Response::Denied)
        ));

        let active = start(&mut coordinator, AUTHENTICATE_REQUEST);
        assert!(matches!(
            coordinator.dispatch(peer(INTERACTIVE_USER), policy(), CANCEL_REQUEST),
            SessionDecision::Reply(Response::Denied)
        ));
        assert!(!active.is_cancelled());

        active.clear_delivery();
        assert!(matches!(
            coordinator.dispatch(peer(0), policy(), CANCEL_REQUEST),
            SessionDecision::Reply(Response::Denied)
        ));
        assert!(!active.is_cancelled());
        assert_eq!(coordinator.abandon(&active), Response::Failure);
    }

    #[test]
    fn mesa_completion_cutoff_distinguishes_preexisting_and_late_cancellation() {
        let mut coordinator = BrokerSessionCoordinator::default();
        let completed = start(&mut coordinator, ENROLL_REQUEST);
        assert!(completed.close_cancellation());
        assert!(matches!(
            coordinator.dispatch(peer(0), policy(), CANCEL_REQUEST),
            SessionDecision::Reply(Response::Denied)
        ));
        assert!(!completed.is_cancelled());
        assert_eq!(coordinator.abandon(&completed), Response::Failure);

        let cancelled = start(&mut coordinator, ENROLL_REQUEST);
        assert!(matches!(
            coordinator.dispatch(peer(0), policy(), CANCEL_REQUEST),
            SessionDecision::Reply(Response::Okay)
        ));
        assert!(!cancelled.close_cancellation());
        assert!(cancelled.is_cancelled());
        assert_eq!(coordinator.abandon(&cancelled), Response::Failure);
    }

    #[test]
    fn delivered_cancellation_and_disconnect_beat_later_match() {
        let mut coordinator = BrokerSessionCoordinator::default();
        let cancelled = start(&mut coordinator, AUTHENTICATE_REQUEST);
        assert!(matches!(
            coordinator.dispatch(peer(0), policy(), CANCEL_REQUEST),
            SessionDecision::Reply(Response::Okay)
        ));
        assert!(cancelled.is_cancelled());
        let completion = AuthenticationCompletion::new(&cancelled, Ok(MatchOutcome::Matched));
        assert_eq!(coordinator.finish(&completion), Response::Failure);

        let disconnected = start(&mut coordinator, AUTHENTICATE_REQUEST);
        assert!(coordinator.client_disconnected(&disconnected));
        assert!(disconnected.is_cancelled());
        let completion = AuthenticationCompletion::new(&disconnected, Ok(MatchOutcome::Matched));
        assert_eq!(coordinator.finish(&completion), Response::Failure);
    }

    #[test]
    fn stale_disconnect_and_completion_do_not_touch_newer_operation() {
        let mut coordinator = BrokerSessionCoordinator::default();
        let first = start(&mut coordinator, AUTHENTICATE_REQUEST);
        let first_completion = AuthenticationCompletion::new(&first, Ok(MatchOutcome::Matched));
        assert_eq!(coordinator.finish(&first_completion), Response::Okay);

        let second = start(&mut coordinator, AUTHENTICATE_REQUEST);
        assert!(!coordinator.client_disconnected(&first));
        assert!(!second.is_cancelled());
        let stale = AuthenticationCompletion::new(&first, Ok(MatchOutcome::Matched));
        let mut feedback = FakeFeedback {
            calls: Vec::new(),
            fail: false,
        };
        assert_eq!(
            coordinator.finish_with_feedback(&stale, Some(&mut feedback)),
            Response::Failure
        );
        assert!(feedback.calls.is_empty());
        assert!(!second.is_cancelled());
        let current = AuthenticationCompletion::new(&second, Ok(MatchOutcome::Matched));
        assert_eq!(coordinator.finish(&current), Response::Okay);
    }

    #[test]
    fn connection_bound_finalization_rejects_another_sessions_completion() {
        let mut coordinator = BrokerSessionCoordinator::default();
        let first = start(&mut coordinator, AUTHENTICATE_REQUEST);
        let first_completion = AuthenticationCompletion::new(&first, Ok(MatchOutcome::Matched));
        assert_eq!(coordinator.finish(&first_completion), Response::Okay);

        let second = start(&mut coordinator, AUTHENTICATE_REQUEST);
        let second_completion = AuthenticationCompletion::new(&second, Ok(MatchOutcome::Matched));
        assert_eq!(
            coordinator.finish_for(&first, &second_completion),
            Response::Failure
        );
        assert!(!second.is_cancelled());
        assert_eq!(coordinator.finish(&second_completion), Response::Okay);
    }

    #[test]
    fn connection_bound_finalization_rejects_equal_token_from_other_coordinator() {
        let mut first_coordinator = BrokerSessionCoordinator::default();
        let mut second_coordinator = BrokerSessionCoordinator::default();
        let first = start(&mut first_coordinator, AUTHENTICATE_REQUEST);
        let second = start(&mut second_coordinator, AUTHENTICATE_REQUEST);
        assert_eq!(first.operation.token, second.operation.token);
        let foreign_completion = AuthenticationCompletion::new(&second, Ok(MatchOutcome::Matched));

        assert!(!first_coordinator.client_disconnected(&second));
        assert_eq!(first_coordinator.abandon(&second), Response::Failure);
        assert_eq!(
            first_coordinator.finish(&foreign_completion),
            Response::Failure
        );
        assert_eq!(
            first_coordinator.finish_for(&second, &foreign_completion),
            Response::Failure
        );
        let own_completion = AuthenticationCompletion::new(&first, Ok(MatchOutcome::Matched));
        assert_eq!(
            first_coordinator.finish_for(&first, &own_completion),
            Response::Okay
        );
        assert_eq!(second_coordinator.abandon(&second), Response::Failure);
    }

    #[test]
    fn exclusive_lease_failure_suppresses_feedback() {
        let mut coordinator = BrokerSessionCoordinator::default();
        let active = start(&mut coordinator, AUTHENTICATE_REQUEST);
        let mut feedback = FakeFeedback {
            calls: Vec::new(),
            fail: false,
        };
        let completion = AuthenticationCompletion::new(
            &active,
            Err(AuthenticationSessionFailure::ExclusiveSepAndAcm),
        );
        assert_eq!(
            completion.result(),
            Err(AuthenticationSessionFailure::ExclusiveSepAndAcm)
        );
        assert!(feedback.calls.is_empty());
        assert_eq!(
            coordinator.finish_with_feedback(&completion, Some(&mut feedback)),
            Response::Failure
        );
        assert!(feedback.calls.is_empty());
    }

    #[test]
    fn cosmetic_failure_never_changes_success() {
        let mut coordinator = BrokerSessionCoordinator::default();
        let active = start(&mut coordinator, AUTHENTICATE_REQUEST);
        let mut feedback = FakeFeedback {
            calls: Vec::new(),
            fail: true,
        };
        let completion = AuthenticationCompletion::new(&active, Ok(MatchOutcome::Matched));
        assert_eq!(completion.result(), Ok(MatchOutcome::Matched));
        assert_eq!(
            coordinator.finish_with_feedback(&completion, Some(&mut feedback)),
            Response::Okay
        );
        assert_eq!(feedback.calls, [FeedbackAction::ShowSuccess]);
        assert!(matches!(
            coordinator.dispatch(peer(0), policy(), CANCEL_REQUEST),
            SessionDecision::Reply(Response::Denied)
        ));
    }

    #[test]
    fn authoritative_no_match_emits_retry_only_after_finalization() {
        let mut coordinator = BrokerSessionCoordinator::default();
        let active = start(&mut coordinator, AUTHENTICATE_REQUEST);
        let completion = AuthenticationCompletion::new(&active, Ok(MatchOutcome::NoMatch));
        let mut feedback = FakeFeedback {
            calls: Vec::new(),
            fail: false,
        };

        assert_eq!(
            coordinator.finish_with_feedback(&completion, Some(&mut feedback)),
            Response::Failure
        );
        assert_eq!(
            feedback.calls,
            [FeedbackAction::ShowRetry, FeedbackAction::PauseAfterRetry]
        );
    }

    #[test]
    fn cancellation_delivered_after_match_suppresses_success_feedback() {
        let mut coordinator = BrokerSessionCoordinator::default();
        let active = start(&mut coordinator, AUTHENTICATE_REQUEST);
        let mut feedback = FakeFeedback {
            calls: Vec::new(),
            fail: false,
        };
        let completion = AuthenticationCompletion::new(&active, Ok(MatchOutcome::Matched));
        assert_eq!(completion.result(), Ok(MatchOutcome::Matched));
        assert!(matches!(
            coordinator.dispatch(peer(0), policy(), CANCEL_REQUEST),
            SessionDecision::Reply(Response::Okay)
        ));
        assert!(feedback.calls.is_empty());
        assert_eq!(
            coordinator.finish_with_feedback(&completion, Some(&mut feedback)),
            Response::Failure
        );
        assert!(feedback.calls.is_empty());
    }
}

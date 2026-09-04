//! Dependency-free scheduling policy for the socket-activated auth broker.

use core::fmt;
use std::sync::Arc;
use std::time::Duration;

use crate::auth_feedback::AuthenticationFeedback;
use crate::auth_protocol::{
    AccessPolicy, MAX_MATCH_TIMEOUT, PeerMetadata, Response, SETUP_ALLOWANCE,
};
use crate::auth_session::{
    ActiveAuthentication, ActiveStandardOperation, AuthenticationCompletion,
    BrokerSessionCoordinator, SessionDecision, StandardCompletion, StandardSessionDecision,
};
use crate::standard_fingerprint_protocol::{ServerMessage, TerminalOutcome};
use crate::standard_operation_authority::ResolvedStandardOperation;

/// Complete setup-and-match budget for one hardware worker.
pub const OPERATION_TIMEOUT: Duration =
    Duration::from_secs(SETUP_ALLOWANCE.as_secs() + MAX_MATCH_TIMEOUT.as_secs());
/// Complete outer budget for enrollment setup, capture, durable export, and
/// cleanup. The live sensor budget remains independently bounded to ten
/// minutes.
pub const ENROLLMENT_OPERATION_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// Opaque lifecycle identity for one in-process worker.
///
/// This is not an authentication token and carries no cancellation authority.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct WorkerLease(u64);

impl fmt::Debug for WorkerLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("WorkerLease(<redacted>)")
    }
}

/// Result of offering one hardware operation to the scheduler.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerAdmission {
    /// The caller may start exactly one worker with this lease and deadline.
    Start {
        lease: WorkerLease,
        deadline: Duration,
    },
    /// One worker is already active; the request must receive `BUSY` now.
    Busy,
    /// The broker must terminate rather than accept more hardware work.
    Terminate,
}

/// Caller action selected from current time and worker ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleDecision {
    /// Keep servicing the socket and current worker.
    Continue,
    /// Deliver cancellation to the exact worker once; keep it active until it
    /// reports completion.
    Cancel(WorkerLease),
    /// No work is active or pending and the socket-activated process may exit.
    ExitIdle,
    /// Worker ownership became uncertain; terminate the broker process.
    Terminate,
}

/// Invalid broker scheduler policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchedulerError {
    ZeroIdleTimeout,
}

impl fmt::Display for SchedulerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("broker idle timeout must be nonzero")
    }
}

impl std::error::Error for SchedulerError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ActiveWorker {
    lease: WorkerLease,
    deadline: Duration,
    cancellation_sent: bool,
}

/// Pure one-worker lifecycle for a systemd socket-activated broker.
///
/// The caller supplies readings from one monotonic clock. The scheduler never
/// queues hardware requests: an active worker makes every new admission
/// immediately [`WorkerAdmission::Busy`]. Deadline expiry delivers one
/// cancellation decision, but the worker remains active until its exact lease
/// reports completion. A lost worker poisons the scheduler so uncertain work
/// can never be replaced by a new operation.
pub struct BrokerScheduler {
    idle_timeout: Duration,
    idle_since: Duration,
    active: Option<ActiveWorker>,
    next_lease: u64,
    poisoned: bool,
}

impl fmt::Debug for BrokerScheduler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerScheduler")
            .field("active", &self.active.is_some())
            .field(
                "deadline_expired",
                &self.active.is_some_and(|worker| worker.cancellation_sent),
            )
            .field("poisoned", &self.poisoned)
            .finish_non_exhaustive()
    }
}

impl BrokerScheduler {
    /// Creates an idle scheduler at `now`.
    ///
    /// # Errors
    ///
    /// A zero idle timeout is rejected to prevent socket-activation churn.
    pub const fn new(now: Duration, idle_timeout: Duration) -> Result<Self, SchedulerError> {
        if idle_timeout.is_zero() {
            return Err(SchedulerError::ZeroIdleTimeout);
        }
        Ok(Self {
            idle_timeout,
            idle_since: now,
            active: None,
            next_lease: 1,
            poisoned: false,
        })
    }

    /// Offers one validated broker operation to the hardware worker slot.
    ///
    /// No request is queued. Arithmetic exhaustion poisons the scheduler rather
    /// than starting an operation without a bounded deadline or unique lease.
    #[must_use]
    pub fn admit(&mut self, now: Duration) -> WorkerAdmission {
        self.admit_with_timeout(now, OPERATION_TIMEOUT)
    }

    fn admit_with_timeout(
        &mut self,
        now: Duration,
        operation_timeout: Duration,
    ) -> WorkerAdmission {
        if self.poisoned {
            return WorkerAdmission::Terminate;
        }
        if self.active.is_some() {
            return WorkerAdmission::Busy;
        }
        let Some(deadline) = now.checked_add(operation_timeout) else {
            self.poisoned = true;
            return WorkerAdmission::Terminate;
        };
        if self.next_lease == 0 {
            self.poisoned = true;
            return WorkerAdmission::Terminate;
        }

        let lease = WorkerLease(self.next_lease);
        self.next_lease = self.next_lease.checked_add(1).unwrap_or(0);
        self.active = Some(ActiveWorker {
            lease,
            deadline,
            cancellation_sent: false,
        });
        WorkerAdmission::Start { lease, deadline }
    }

    /// Completes the exact active worker and begins a new idle interval.
    ///
    /// A stale lease cannot clear or replace current work.
    pub fn complete(&mut self, lease: WorkerLease, now: Duration) -> bool {
        if self.active.is_none_or(|active| active.lease != lease) {
            return false;
        }
        self.active = None;
        self.idle_since = now;
        true
    }

    /// Marks an exact worker as lost without a trustworthy completion.
    ///
    /// The scheduler becomes permanently terminating. A stale report cannot
    /// poison a newer worker.
    pub fn worker_lost(&mut self, lease: WorkerLease) -> bool {
        if self.active.is_none_or(|active| active.lease != lease) {
            return false;
        }
        self.poisoned = true;
        true
    }

    fn owns(&self, lease: WorkerLease) -> bool {
        self.active.is_some_and(|active| active.lease == lease)
    }

    fn poison(&mut self) {
        self.poisoned = true;
    }

    fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Selects the next service-lifecycle action.
    ///
    /// `listener_ready` must come from the socket-activation event loop. Pending
    /// socket work wins an idle-timeout race so the process does not exit while
    /// a request is already queued by systemd.
    #[must_use]
    pub fn decide(&mut self, now: Duration, listener_ready: bool) -> LifecycleDecision {
        if self.poisoned {
            return LifecycleDecision::Terminate;
        }
        if let Some(active) = self.active.as_mut() {
            if now >= active.deadline && !active.cancellation_sent {
                active.cancellation_sent = true;
                return LifecycleDecision::Cancel(active.lease);
            }
            return LifecycleDecision::Continue;
        }
        if !listener_ready && now.saturating_sub(self.idle_since) >= self.idle_timeout {
            LifecycleDecision::ExitIdle
        } else {
            LifecycleDecision::Continue
        }
    }
}

/// One broker-authorized operation admitted to the sole hardware worker.
pub struct ScheduledAuthentication {
    authentication: ActiveAuthentication,
    lease: WorkerLease,
    deadline: Duration,
    service_identity: Arc<()>,
}

impl fmt::Debug for ScheduledAuthentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScheduledAuthentication")
            .field("authentication", &self.authentication)
            .field("lease", &self.lease)
            .field("deadline", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl ScheduledAuthentication {
    /// Token-associated authentication input for the hardware worker.
    #[must_use]
    pub const fn authentication(&self) -> &ActiveAuthentication {
        &self.authentication
    }

    /// One monotonic deadline shared by setup and matching work.
    #[must_use]
    pub const fn deadline(&self) -> Duration {
        self.deadline
    }

    /// Opaque identity used for lifecycle completion and cancellation routing.
    #[must_use]
    pub const fn lease(&self) -> WorkerLease {
        self.lease
    }
}

/// One broker-authorized standard operation admitted to the sole worker.
pub struct ScheduledStandardOperation {
    operation: ActiveStandardOperation,
    lease: WorkerLease,
    deadline: Duration,
    service_identity: Arc<()>,
}

impl fmt::Debug for ScheduledStandardOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ScheduledStandardOperation")
            .field("operation", &self.operation)
            .field("lease", &self.lease)
            .field("deadline", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl ScheduledStandardOperation {
    /// Exact standard operation and token-associated cancellation input.
    #[must_use]
    pub const fn operation(&self) -> &ActiveStandardOperation {
        &self.operation
    }

    /// Complete outer deadline for this operation class.
    #[must_use]
    pub const fn deadline(&self) -> Duration {
        self.deadline
    }

    /// Opaque identity used for lifecycle completion and cancellation routing.
    #[must_use]
    pub const fn lease(&self) -> WorkerLease {
        self.lease
    }
}

/// Pure result of one admitted broker packet.
pub enum ScheduledDispatch {
    /// Send the broker's immediate fixed response. This includes `BUSY`.
    Reply(Response),
    /// Start the only permitted in-process hardware worker.
    Start(ScheduledAuthentication),
    /// Internal lifecycle state is uncertain; terminate the broker.
    Terminate,
}

/// Pure result of offering one resolved standard operation to the service.
pub enum ScheduledStandardDispatch {
    /// Send one immediate typed response, including `Busy`.
    Reply(ServerMessage),
    /// Start the only permitted in-process hardware worker.
    Start(ScheduledStandardOperation),
    /// Internal lifecycle state is uncertain; terminate the broker.
    Terminate,
}

impl fmt::Debug for ScheduledStandardDispatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reply(response) => formatter.debug_tuple("Reply").field(response).finish(),
            Self::Start(active) => formatter.debug_tuple("Start").field(active).finish(),
            Self::Terminate => formatter.write_str("Terminate"),
        }
    }
}

impl fmt::Debug for ScheduledDispatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reply(response) => formatter.debug_tuple("Reply").field(response).finish(),
            Self::Start(active) => formatter.debug_tuple("Start").field(active).finish(),
            Self::Terminate => formatter.write_str("Terminate"),
        }
    }
}

/// Broker token authority composed with the one-worker service lifecycle.
///
/// This remains transport-independent: systemd listener adoption, readiness,
/// threads, and hardware are caller-owned. The composition proves that an
/// active broker operation receives immediate `BUSY` rather than entering a
/// second scheduler or queue.
pub struct BrokerServiceScheduler {
    coordinator: BrokerSessionCoordinator,
    workers: BrokerScheduler,
    identity: Arc<()>,
}

impl fmt::Debug for BrokerServiceScheduler {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerServiceScheduler")
            .field("coordinator", &self.coordinator)
            .field("workers", &self.workers)
            .finish_non_exhaustive()
    }
}

impl BrokerServiceScheduler {
    /// Creates an idle socket-activated broker policy.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid idle timeout.
    pub fn new(now: Duration, idle_timeout: Duration) -> Result<Self, SchedulerError> {
        Ok(Self {
            coordinator: BrokerSessionCoordinator::default(),
            workers: BrokerScheduler::new(now, idle_timeout)?,
            identity: Arc::new(()),
        })
    }

    /// Authorizes one exact packet and admits at most one hardware worker.
    #[must_use]
    pub fn dispatch(
        &mut self,
        peer: PeerMetadata,
        policy: AccessPolicy,
        packet: &[u8],
        now: Duration,
    ) -> ScheduledDispatch {
        if self.workers.is_poisoned() {
            return ScheduledDispatch::Terminate;
        }
        let decision = self.coordinator.dispatch(peer, policy, packet);
        self.schedule(decision, now)
    }

    /// Authorizes one resolved standard operation and admits it to the same
    /// worker slot used by legacy requests.
    #[must_use]
    pub fn dispatch_standard(
        &mut self,
        peer: PeerMetadata,
        recorded_owner: Option<AccessPolicy>,
        operation: ResolvedStandardOperation,
        now: Duration,
    ) -> ScheduledStandardDispatch {
        if self.workers.is_poisoned() {
            return ScheduledStandardDispatch::Terminate;
        }
        let decision = self
            .coordinator
            .dispatch_standard(peer, recorded_owner, operation);
        self.schedule_standard(decision, now)
    }

    /// Admits one already-decoded enrollment for a validated local non-root
    /// peer when owner state is authoritatively missing.
    #[must_use]
    pub(crate) fn enroll_without_owner(
        &mut self,
        peer: PeerMetadata,
        now: Duration,
    ) -> ScheduledDispatch {
        if self.workers.is_poisoned() {
            return ScheduledDispatch::Terminate;
        }
        let decision = self.coordinator.enroll_without_owner(peer);
        self.schedule(decision, now)
    }

    fn schedule(&mut self, decision: SessionDecision, now: Duration) -> ScheduledDispatch {
        match decision {
            SessionDecision::Reply(response) => ScheduledDispatch::Reply(response),
            SessionDecision::Start(authentication) => match self.workers.admit_with_timeout(
                now,
                match authentication.purpose() {
                    crate::auth_protocol::Purpose::Enrollment => ENROLLMENT_OPERATION_TIMEOUT,
                    crate::auth_protocol::Purpose::Authenticate
                    | crate::auth_protocol::Purpose::Approve => OPERATION_TIMEOUT,
                },
            ) {
                WorkerAdmission::Start { lease, deadline } => {
                    ScheduledDispatch::Start(ScheduledAuthentication {
                        authentication,
                        lease,
                        deadline,
                        service_identity: Arc::clone(&self.identity),
                    })
                }
                WorkerAdmission::Busy | WorkerAdmission::Terminate => {
                    let _ = self.coordinator.abandon(&authentication);
                    self.workers.poison();
                    ScheduledDispatch::Terminate
                }
            },
        }
    }

    fn schedule_standard(
        &mut self,
        decision: StandardSessionDecision,
        now: Duration,
    ) -> ScheduledStandardDispatch {
        match decision {
            StandardSessionDecision::Reply(response) => ScheduledStandardDispatch::Reply(response),
            StandardSessionDecision::Start(operation) => {
                let timeout = match operation.operation().operation() {
                    ResolvedStandardOperation::Enroll { .. }
                    | ResolvedStandardOperation::DeleteIdentity { .. } => {
                        ENROLLMENT_OPERATION_TIMEOUT
                    }
                    ResolvedStandardOperation::ListIdentities
                    | ResolvedStandardOperation::Verify { .. }
                    | ResolvedStandardOperation::Identify { .. } => OPERATION_TIMEOUT,
                };
                match self.workers.admit_with_timeout(now, timeout) {
                    WorkerAdmission::Start { lease, deadline } => {
                        ScheduledStandardDispatch::Start(ScheduledStandardOperation {
                            operation,
                            lease,
                            deadline,
                            service_identity: Arc::clone(&self.identity),
                        })
                    }
                    WorkerAdmission::Busy | WorkerAdmission::Terminate => {
                        let _ = self.coordinator.abandon_standard(&operation);
                        self.workers.poison();
                        ScheduledStandardDispatch::Terminate
                    }
                }
            }
        }
    }

    /// Routes an exact root cancellation while owner storage is unavailable.
    ///
    /// This can only cancel the current token; it never admits hardware work
    /// or changes the worker lease.
    #[must_use]
    pub(crate) fn cancel_without_owner(&mut self, peer: PeerMetadata) -> ScheduledDispatch {
        if self.workers.is_poisoned() {
            ScheduledDispatch::Terminate
        } else {
            ScheduledDispatch::Reply(self.coordinator.cancel_without_owner(peer))
        }
    }

    /// Finalizes the exact scheduled operation and returns its broker response.
    ///
    /// Stale worker or completion state fails without releasing current work.
    #[must_use]
    pub fn finish(
        &mut self,
        scheduled: &ScheduledAuthentication,
        completion: &AuthenticationCompletion,
        now: Duration,
    ) -> Response {
        if self.workers.is_poisoned()
            || !self.owns(scheduled)
            || !completion.belongs_to(&scheduled.authentication)
        {
            return Response::Failure;
        }
        let response = self
            .coordinator
            .finish_for(&scheduled.authentication, completion);
        if !self.workers.complete(scheduled.lease, now) {
            self.workers.poison();
            return Response::Failure;
        }
        response
    }

    /// Finalizes one exact standard worker and releases its shared lease.
    #[must_use]
    pub fn finish_standard(
        &mut self,
        scheduled: &ScheduledStandardOperation,
        completion: &StandardCompletion,
        now: Duration,
    ) -> ServerMessage {
        if self.workers.is_poisoned()
            || !self.owns_standard(scheduled)
            || !completion.belongs_to(&scheduled.operation)
        {
            return ServerMessage::Terminal(TerminalOutcome::Error);
        }
        let response = self
            .coordinator
            .finish_standard(&scheduled.operation, completion);
        if !self.workers.complete(scheduled.lease, now) {
            self.workers.poison();
            return ServerMessage::Terminal(TerminalOutcome::Error);
        }
        response
    }

    /// Finalizes the exact scheduled operation, applies best-effort feedback
    /// only after broker authority is resolved, and releases its worker slot.
    ///
    /// Stale worker or completion state fails without feedback or worker
    /// release. Cosmetic failure never changes the authoritative response.
    #[must_use]
    pub fn finish_with_feedback<Feedback: AuthenticationFeedback>(
        &mut self,
        scheduled: &ScheduledAuthentication,
        completion: &AuthenticationCompletion,
        feedback: Option<&mut Feedback>,
        now: Duration,
    ) -> Response {
        if self.workers.is_poisoned()
            || !self.owns(scheduled)
            || !completion.belongs_to(&scheduled.authentication)
        {
            return Response::Failure;
        }
        let response = self.coordinator.finish_with_feedback(completion, feedback);
        if !self.workers.complete(scheduled.lease, now) {
            self.workers.poison();
            return Response::Failure;
        }
        response
    }

    /// Releases an operation whose in-process worker could not be started.
    #[must_use]
    pub fn abandon(&mut self, scheduled: &ScheduledAuthentication, now: Duration) -> Response {
        if !self.owns(scheduled) {
            return Response::Failure;
        }
        let response = self.coordinator.abandon(&scheduled.authentication);
        if !self.workers.complete(scheduled.lease, now) {
            self.workers.poison();
            return Response::Failure;
        }
        response
    }

    /// Releases standard work whose in-process worker could not be started.
    #[must_use]
    pub fn abandon_standard(
        &mut self,
        scheduled: &ScheduledStandardOperation,
        now: Duration,
    ) -> ServerMessage {
        if !self.owns_standard(scheduled) {
            return ServerMessage::Terminal(TerminalOutcome::Error);
        }
        let response = self.coordinator.abandon_standard(&scheduled.operation);
        if !self.workers.complete(scheduled.lease, now) {
            self.workers.poison();
            return ServerMessage::Terminal(TerminalOutcome::Error);
        }
        response
    }

    /// Delivers disconnect cancellation to the exact scheduled operation.
    pub fn client_disconnected(&mut self, scheduled: &ScheduledAuthentication) -> bool {
        self.owns(scheduled)
            && self
                .coordinator
                .client_disconnected(&scheduled.authentication)
    }

    /// Delivers same-connection cancellation to exact scheduled standard work.
    pub fn cancel_standard(&mut self, scheduled: &ScheduledStandardOperation) -> bool {
        self.owns_standard(scheduled) && self.coordinator.cancel_standard(&scheduled.operation)
    }

    /// Delivers disconnect cancellation to exact scheduled standard work.
    pub fn standard_client_disconnected(&mut self, scheduled: &ScheduledStandardOperation) -> bool {
        self.owns_standard(scheduled)
            && self
                .coordinator
                .standard_client_disconnected(&scheduled.operation)
    }

    /// Delivers an elapsed-deadline cancellation to the exact scheduled work.
    ///
    /// Delivery is idempotent and does not release the worker slot. The exact
    /// operation must still report completion or be abandoned explicitly.
    pub fn deadline_expired(&mut self, scheduled: &ScheduledAuthentication) -> bool {
        self.owns(scheduled)
            && self
                .coordinator
                .client_disconnected(&scheduled.authentication)
    }

    /// Delivers deadline cancellation to exact scheduled standard work.
    pub fn standard_deadline_expired(&mut self, scheduled: &ScheduledStandardOperation) -> bool {
        self.standard_client_disconnected(scheduled)
    }

    /// Selects deadline cancellation, continued service, idle exit, or
    /// fail-closed termination.
    #[must_use]
    pub fn decide(&mut self, now: Duration, listener_ready: bool) -> LifecycleDecision {
        self.workers.decide(now, listener_ready)
    }

    /// Marks the exact worker as lost so no replacement work can be admitted.
    pub fn worker_lost(&mut self, scheduled: &ScheduledAuthentication) -> bool {
        self.owns(scheduled) && self.workers.worker_lost(scheduled.lease)
    }

    /// Marks an exact standard worker lost and poisons the shared scheduler.
    pub fn standard_worker_lost(&mut self, scheduled: &ScheduledStandardOperation) -> bool {
        self.owns_standard(scheduled) && self.workers.worker_lost(scheduled.lease)
    }

    fn owns(&self, scheduled: &ScheduledAuthentication) -> bool {
        Arc::ptr_eq(&self.identity, &scheduled.service_identity)
            && self.workers.owns(scheduled.lease)
    }

    fn owns_standard(&self, scheduled: &ScheduledStandardOperation) -> bool {
        Arc::ptr_eq(&self.identity, &scheduled.service_identity)
            && self.workers.owns(scheduled.lease)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_feedback::{AuthenticationFeedback, FeedbackAction};
    use crate::auth_protocol::{
        APPROVE_REQUEST, AUTHENTICATE_REQUEST, CANCEL_REQUEST, ENROLL_REQUEST, PeerAddressFamily,
        Purpose,
    };
    use crate::standard_fingerprint_protocol::{FingerLabel, IdentityId, Username};
    use crate::standard_operation_authority::ResolvedStandardAccount;

    const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct CosmeticError;

    #[derive(Default)]
    struct FakeFeedback {
        actions: Vec<FeedbackAction>,
        fail_first: bool,
    }

    impl AuthenticationFeedback for FakeFeedback {
        type Error = CosmeticError;

        fn apply(&mut self, action: FeedbackAction) -> Result<(), Self::Error> {
            self.actions.push(action);
            if self.fail_first && self.actions.len() == 1 {
                Err(CosmeticError)
            } else {
                Ok(())
            }
        }
    }

    fn scheduler(now: Duration) -> BrokerScheduler {
        BrokerScheduler::new(now, IDLE_TIMEOUT).expect("valid scheduler policy")
    }

    fn policy() -> AccessPolicy {
        AccessPolicy::new(42_000).expect("synthetic owner policy")
    }

    fn peer(user_id: u32) -> PeerMetadata {
        PeerMetadata {
            address_family: PeerAddressFamily::Local,
            user_id,
            group_id: 42_001,
        }
    }

    fn start(scheduler: &mut BrokerScheduler, now: Duration) -> (WorkerLease, Duration) {
        let WorkerAdmission::Start { lease, deadline } = scheduler.admit(now) else {
            panic!("one worker starts")
        };
        (lease, deadline)
    }

    fn standard_account() -> ResolvedStandardAccount {
        let name = Username::new("synthetic-owner").unwrap();
        ResolvedStandardAccount::new(&name, &name, 42_000).unwrap()
    }

    fn identity(seed: u8) -> IdentityId {
        IdentityId::new([seed; 16]).unwrap()
    }

    fn standard_start(
        service: &mut BrokerServiceScheduler,
        operation: ResolvedStandardOperation,
        now: Duration,
    ) -> ScheduledStandardOperation {
        let ScheduledStandardDispatch::Start(active) =
            service.dispatch_standard(peer(42_000), Some(policy()), operation, now)
        else {
            panic!("standard operation starts")
        };
        active
    }

    #[test]
    fn standard_operation_classes_receive_their_exact_outer_deadlines() {
        let now = Duration::from_secs(10);
        let mut service =
            BrokerServiceScheduler::new(now, IDLE_TIMEOUT).expect("valid service policy");
        for (operation, timeout) in [
            (ResolvedStandardOperation::ListIdentities, OPERATION_TIMEOUT),
            (
                ResolvedStandardOperation::Verify {
                    account: standard_account(),
                    identity: identity(0x31),
                },
                OPERATION_TIMEOUT,
            ),
            (
                ResolvedStandardOperation::Identify {
                    account: standard_account(),
                },
                OPERATION_TIMEOUT,
            ),
            (
                ResolvedStandardOperation::Enroll {
                    account: standard_account(),
                    finger: FingerLabel::LeftIndex,
                },
                ENROLLMENT_OPERATION_TIMEOUT,
            ),
            (
                ResolvedStandardOperation::DeleteIdentity {
                    account: standard_account(),
                    identity: identity(0x32),
                },
                ENROLLMENT_OPERATION_TIMEOUT,
            ),
        ] {
            let scheduled = standard_start(&mut service, operation, now);
            assert_eq!(scheduled.deadline(), now + timeout);
            assert_eq!(
                service.abandon_standard(&scheduled, now),
                ServerMessage::Terminal(TerminalOutcome::Error)
            );
        }
    }

    #[test]
    fn legacy_and_standard_work_are_immediately_busy_in_both_directions() {
        let now = Duration::from_secs(10);
        let mut service =
            BrokerServiceScheduler::new(now, IDLE_TIMEOUT).expect("valid service policy");
        let standard = standard_start(
            &mut service,
            ResolvedStandardOperation::Identify {
                account: standard_account(),
            },
            now,
        );
        assert!(matches!(
            service.dispatch(peer(42_000), policy(), AUTHENTICATE_REQUEST, now),
            ScheduledDispatch::Reply(Response::Busy)
        ));
        assert_eq!(
            service.abandon_standard(&standard, now),
            ServerMessage::Terminal(TerminalOutcome::Error)
        );

        let ScheduledDispatch::Start(legacy) =
            service.dispatch(peer(42_000), policy(), AUTHENTICATE_REQUEST, now)
        else {
            panic!("legacy operation starts")
        };
        assert!(matches!(
            service.dispatch_standard(
                peer(42_000),
                Some(policy()),
                ResolvedStandardOperation::Identify {
                    account: standard_account(),
                },
                now,
            ),
            ScheduledStandardDispatch::Reply(ServerMessage::Terminal(TerminalOutcome::Busy))
        ));
        assert_eq!(service.abandon(&legacy, now), Response::Failure);
    }

    #[test]
    fn standard_scheduling_rejects_foreign_handles_and_completions() {
        let now = Duration::from_secs(10);
        let mut first =
            BrokerServiceScheduler::new(now, IDLE_TIMEOUT).expect("valid first service");
        let mut second =
            BrokerServiceScheduler::new(now, IDLE_TIMEOUT).expect("valid second service");
        let first_active = standard_start(
            &mut first,
            ResolvedStandardOperation::Identify {
                account: standard_account(),
            },
            now,
        );
        let second_active = standard_start(
            &mut second,
            ResolvedStandardOperation::Identify {
                account: standard_account(),
            },
            now,
        );
        assert_eq!(first_active.lease(), second_active.lease());
        let foreign = second_active
            .operation()
            .completion_for_worker(ServerMessage::Terminal(TerminalOutcome::NoMatch));

        assert!(!first.cancel_standard(&second_active));
        assert!(!first.standard_client_disconnected(&second_active));
        assert_eq!(
            first.finish_standard(&first_active, &foreign, now),
            ServerMessage::Terminal(TerminalOutcome::Error)
        );
        assert!(matches!(
            first.dispatch(peer(42_000), policy(), AUTHENTICATE_REQUEST, now),
            ScheduledDispatch::Reply(Response::Busy)
        ));

        assert!(first.cancel_standard(&first_active));
        let exact = first_active
            .operation()
            .completion_for_worker(ServerMessage::Terminal(TerminalOutcome::NoMatch));
        assert_eq!(
            first.finish_standard(&first_active, &exact, now),
            ServerMessage::Terminal(TerminalOutcome::Cancelled)
        );
        assert_eq!(
            second.abandon_standard(&second_active, now),
            ServerMessage::Terminal(TerminalOutcome::Error)
        );
    }

    #[test]
    fn standard_deadline_cancellation_is_exact_and_keeps_the_worker_busy() {
        let now = Duration::from_secs(10);
        let mut first =
            BrokerServiceScheduler::new(now, IDLE_TIMEOUT).expect("valid first service");
        let mut second =
            BrokerServiceScheduler::new(now, IDLE_TIMEOUT).expect("valid second service");
        let first_active = standard_start(
            &mut first,
            ResolvedStandardOperation::Identify {
                account: standard_account(),
            },
            now,
        );
        let second_active = standard_start(
            &mut second,
            ResolvedStandardOperation::Identify {
                account: standard_account(),
            },
            now,
        );

        assert!(!first.standard_deadline_expired(&second_active));
        assert!(!first_active.operation().is_cancelled());
        assert!(first.standard_deadline_expired(&first_active));
        assert!(first.standard_deadline_expired(&first_active));
        assert!(first_active.operation().is_cancelled());
        assert!(matches!(
            first.dispatch(peer(42_000), policy(), AUTHENTICATE_REQUEST, now),
            ScheduledDispatch::Reply(Response::Busy)
        ));

        let completion = first_active
            .operation()
            .completion_for_worker(ServerMessage::Terminal(TerminalOutcome::NoMatch));
        assert_eq!(
            first.finish_standard(&first_active, &completion, now),
            ServerMessage::Terminal(TerminalOutcome::Cancelled)
        );
        assert_eq!(
            second.abandon_standard(&second_active, now),
            ServerMessage::Terminal(TerminalOutcome::Error)
        );
    }

    #[test]
    fn stale_standard_completion_cannot_release_a_newer_shared_worker() {
        let now = Duration::from_secs(10);
        let mut service =
            BrokerServiceScheduler::new(now, IDLE_TIMEOUT).expect("valid service policy");
        let stale = standard_start(
            &mut service,
            ResolvedStandardOperation::Identify {
                account: standard_account(),
            },
            now,
        );
        let stale_completion = stale
            .operation()
            .completion_for_worker(ServerMessage::Terminal(TerminalOutcome::NoMatch));
        assert_eq!(
            service.finish_standard(&stale, &stale_completion, now),
            ServerMessage::Terminal(TerminalOutcome::NoMatch)
        );

        let current = standard_start(
            &mut service,
            ResolvedStandardOperation::Identify {
                account: standard_account(),
            },
            now,
        );
        assert_eq!(
            service.finish_standard(&stale, &stale_completion, now),
            ServerMessage::Terminal(TerminalOutcome::Error)
        );
        assert!(matches!(
            service.dispatch(peer(42_000), policy(), AUTHENTICATE_REQUEST, now),
            ScheduledDispatch::Reply(Response::Busy)
        ));
        let current_completion = current
            .operation()
            .completion_for_worker(ServerMessage::Terminal(TerminalOutcome::NoMatch));
        assert_eq!(
            service.finish_standard(&current, &current_completion, now),
            ServerMessage::Terminal(TerminalOutcome::NoMatch)
        );
    }

    #[test]
    fn lost_standard_worker_poisons_the_one_shared_scheduler() {
        let now = Duration::from_secs(10);
        let mut service =
            BrokerServiceScheduler::new(now, IDLE_TIMEOUT).expect("valid service policy");
        let scheduled =
            standard_start(&mut service, ResolvedStandardOperation::ListIdentities, now);
        let completion = scheduled
            .operation()
            .completion_for_worker(ServerMessage::IdentityList {
                owner: None,
                identities: Vec::new(),
            });
        assert!(service.standard_worker_lost(&scheduled));
        assert_eq!(
            service.finish_standard(&scheduled, &completion, now),
            ServerMessage::Terminal(TerminalOutcome::Error)
        );
        assert_eq!(service.decide(now, true), LifecycleDecision::Terminate);
        assert!(matches!(
            service.dispatch_standard(
                peer(42_000),
                Some(policy()),
                ResolvedStandardOperation::ListIdentities,
                now,
            ),
            ScheduledStandardDispatch::Terminate
        ));
    }

    #[test]
    fn one_worker_starts_with_the_complete_bounded_deadline() {
        let now = Duration::from_secs(10);
        let mut scheduler = scheduler(now);
        let (lease, deadline) = start(&mut scheduler, now);

        assert_eq!(deadline, now + OPERATION_TIMEOUT);
        assert_eq!(scheduler.admit(now), WorkerAdmission::Busy);
        assert!(!format!("{lease:?}").contains('1'));
    }

    #[test]
    fn deadline_cancels_once_without_freeing_or_replacing_the_worker() {
        let now = Duration::from_secs(10);
        let mut scheduler = scheduler(now);
        let (lease, deadline) = start(&mut scheduler, now);

        assert_eq!(
            scheduler.decide(
                deadline
                    .checked_sub(Duration::from_nanos(1))
                    .expect("deadline is nonzero"),
                false,
            ),
            LifecycleDecision::Continue
        );
        assert_eq!(
            scheduler.decide(deadline, false),
            LifecycleDecision::Cancel(lease)
        );
        assert_eq!(
            scheduler.decide(deadline + Duration::from_secs(1), false),
            LifecycleDecision::Continue
        );
        assert_eq!(scheduler.admit(deadline), WorkerAdmission::Busy);
    }

    #[test]
    fn only_the_exact_worker_completion_returns_to_idle() {
        let now = Duration::from_secs(10);
        let mut scheduler = scheduler(now);
        let (first, _) = start(&mut scheduler, now);
        let stale = WorkerLease(first.0 + 1);

        assert!(!scheduler.complete(stale, now + Duration::from_secs(1)));
        assert_eq!(scheduler.admit(now), WorkerAdmission::Busy);
        assert!(scheduler.complete(first, now + Duration::from_secs(2)));
        assert!(matches!(
            scheduler.admit(now + Duration::from_secs(2)),
            WorkerAdmission::Start { .. }
        ));
    }

    #[test]
    fn uncertain_worker_terminates_and_never_accepts_replacement_work() {
        let now = Duration::from_secs(10);
        let mut scheduler = scheduler(now);
        let (lease, _) = start(&mut scheduler, now);

        assert!(!scheduler.worker_lost(WorkerLease(lease.0 + 1)));
        assert!(scheduler.worker_lost(lease));
        assert_eq!(scheduler.decide(now, true), LifecycleDecision::Terminate);
        assert_eq!(scheduler.admit(now), WorkerAdmission::Terminate);
    }

    #[test]
    fn idle_exit_waits_for_threshold_and_never_beats_socket_readiness() {
        let now = Duration::from_secs(10);
        let mut scheduler = scheduler(now);

        assert_eq!(
            scheduler.decide(
                (now + IDLE_TIMEOUT)
                    .checked_sub(Duration::from_nanos(1))
                    .expect("idle threshold is nonzero"),
                false,
            ),
            LifecycleDecision::Continue
        );
        assert_eq!(
            scheduler.decide(now + IDLE_TIMEOUT, true),
            LifecycleDecision::Continue
        );
        assert_eq!(
            scheduler.decide(now + IDLE_TIMEOUT, false),
            LifecycleDecision::ExitIdle
        );

        let (lease, _) = start(&mut scheduler, now + IDLE_TIMEOUT);
        assert_eq!(
            scheduler.decide(now + IDLE_TIMEOUT + OPERATION_TIMEOUT, false),
            LifecycleDecision::Cancel(lease)
        );
    }

    #[test]
    fn invalid_or_unrepresentable_timing_never_starts_work() {
        assert!(matches!(
            BrokerScheduler::new(Duration::ZERO, Duration::ZERO),
            Err(SchedulerError::ZeroIdleTimeout)
        ));

        let mut scheduler = scheduler(Duration::MAX);
        assert_eq!(scheduler.admit(Duration::MAX), WorkerAdmission::Terminate);
        assert_eq!(
            scheduler.decide(Duration::MAX, false),
            LifecycleDecision::Terminate
        );
    }

    #[test]
    fn broker_authority_and_worker_slot_return_busy_without_a_queue() {
        let now = Duration::from_secs(10);
        let mut service =
            BrokerServiceScheduler::new(now, IDLE_TIMEOUT).expect("valid service policy");
        let ScheduledDispatch::Start(active) =
            service.dispatch(peer(42_000), policy(), AUTHENTICATE_REQUEST, now)
        else {
            panic!("first operation starts")
        };

        assert!(matches!(
            service.dispatch(peer(42_000), policy(), AUTHENTICATE_REQUEST, now),
            ScheduledDispatch::Reply(Response::Busy)
        ));
        assert_eq!(
            service.decide(active.deadline(), false),
            LifecycleDecision::Cancel(active.lease())
        );
        assert!(matches!(
            service.dispatch(
                peer(42_000),
                policy(),
                AUTHENTICATE_REQUEST,
                active.deadline()
            ),
            ScheduledDispatch::Reply(Response::Busy)
        ));
    }

    #[test]
    fn enrollment_shares_the_only_worker_and_root_cancellation_path() {
        let now = Duration::from_secs(10);
        let mut service =
            BrokerServiceScheduler::new(now, IDLE_TIMEOUT).expect("valid service policy");
        let ScheduledDispatch::Start(enrollment) = service.enroll_without_owner(peer(42_000), now)
        else {
            panic!("missing-owner enrollment starts")
        };
        assert_eq!(enrollment.authentication().purpose(), Purpose::Enrollment);
        assert_eq!(enrollment.deadline(), now + ENROLLMENT_OPERATION_TIMEOUT);
        assert_eq!(
            enrollment
                .authentication()
                .enrollment_owner_candidate()
                .expect("scheduled enrollment carries candidate")
                .user_id(),
            42_000
        );
        assert!(matches!(
            service.dispatch(peer(42_000), policy(), ENROLL_REQUEST, now),
            ScheduledDispatch::Reply(Response::Busy)
        ));
        assert!(matches!(
            service.cancel_without_owner(peer(0)),
            ScheduledDispatch::Reply(Response::Okay)
        ));
        assert!(enrollment.authentication().is_cancelled());
        assert_eq!(service.abandon(&enrollment, now), Response::Failure);
    }

    #[test]
    fn authentication_and_approval_retain_the_short_outer_deadline() {
        let now = Duration::from_secs(10);
        let mut service =
            BrokerServiceScheduler::new(now, IDLE_TIMEOUT).expect("valid service policy");
        for request in [AUTHENTICATE_REQUEST, APPROVE_REQUEST] {
            let ScheduledDispatch::Start(scheduled) =
                service.dispatch(peer(42_000), policy(), request, now)
            else {
                panic!("authorized operation starts")
            };
            assert_eq!(scheduled.deadline(), now + OPERATION_TIMEOUT);
            assert_eq!(service.abandon(&scheduled, now), Response::Failure);
        }
    }

    #[test]
    fn root_cancellation_reaches_the_only_scheduled_operation() {
        let now = Duration::from_secs(10);
        let mut service =
            BrokerServiceScheduler::new(now, IDLE_TIMEOUT).expect("valid service policy");
        let ScheduledDispatch::Start(active) =
            service.dispatch(peer(42_000), policy(), AUTHENTICATE_REQUEST, now)
        else {
            panic!("first operation starts")
        };

        assert!(matches!(
            service.dispatch(peer(0), policy(), CANCEL_REQUEST, now),
            ScheduledDispatch::Reply(Response::Okay)
        ));
        assert!(active.authentication().is_cancelled());
        assert_eq!(service.abandon(&active, now), Response::Failure);
        assert!(matches!(
            service.dispatch(peer(42_000), policy(), AUTHENTICATE_REQUEST, now),
            ScheduledDispatch::Start(_)
        ));
    }

    #[test]
    fn deadline_delivery_is_exact_idempotent_and_keeps_the_worker_active() {
        let now = Duration::from_secs(10);
        let mut first =
            BrokerServiceScheduler::new(now, IDLE_TIMEOUT).expect("valid first service");
        let mut second =
            BrokerServiceScheduler::new(now, IDLE_TIMEOUT).expect("valid second service");
        let ScheduledDispatch::Start(first_active) =
            first.dispatch(peer(42_000), policy(), AUTHENTICATE_REQUEST, now)
        else {
            panic!("first service starts")
        };
        let ScheduledDispatch::Start(second_active) =
            second.dispatch(peer(42_000), policy(), AUTHENTICATE_REQUEST, now)
        else {
            panic!("second service starts")
        };

        assert!(!first.deadline_expired(&second_active));
        assert!(!first_active.authentication().is_cancelled());
        assert!(first.deadline_expired(&first_active));
        assert!(first_active.authentication().is_cancelled());
        assert!(first.deadline_expired(&first_active));
        assert!(matches!(
            first.dispatch(
                peer(42_000),
                policy(),
                AUTHENTICATE_REQUEST,
                first_active.deadline()
            ),
            ScheduledDispatch::Reply(Response::Busy)
        ));
        assert_eq!(first.abandon(&second_active, now), Response::Failure);
        assert!(matches!(
            first.dispatch(peer(42_000), policy(), AUTHENTICATE_REQUEST, now),
            ScheduledDispatch::Reply(Response::Busy)
        ));
        assert_eq!(first.abandon(&first_active, now), Response::Failure);
        assert!(matches!(
            first.dispatch(peer(42_000), policy(), AUTHENTICATE_REQUEST, now),
            ScheduledDispatch::Start(_)
        ));
        assert_eq!(second.abandon(&second_active, now), Response::Failure);
    }

    #[test]
    fn equal_local_lease_from_another_service_cannot_release_or_poison_work() {
        let now = Duration::from_secs(10);
        let mut first =
            BrokerServiceScheduler::new(now, IDLE_TIMEOUT).expect("valid first service");
        let mut second =
            BrokerServiceScheduler::new(now, IDLE_TIMEOUT).expect("valid second service");
        let ScheduledDispatch::Start(first_active) =
            first.dispatch(peer(42_000), policy(), AUTHENTICATE_REQUEST, now)
        else {
            panic!("first service starts")
        };
        let ScheduledDispatch::Start(second_active) =
            second.dispatch(peer(42_000), policy(), AUTHENTICATE_REQUEST, now)
        else {
            panic!("second service starts")
        };
        assert_eq!(first_active.lease(), second_active.lease());

        assert!(!first.client_disconnected(&second_active));
        assert!(!first.worker_lost(&second_active));
        assert_eq!(first.abandon(&second_active, now), Response::Failure);
        assert!(matches!(
            first.dispatch(peer(42_000), policy(), AUTHENTICATE_REQUEST, now),
            ScheduledDispatch::Reply(Response::Busy)
        ));
        assert_eq!(first.abandon(&first_active, now), Response::Failure);
        assert_eq!(second.abandon(&second_active, now), Response::Failure);
    }

    #[test]
    fn exact_completion_releases_the_slot_but_foreign_completion_does_not() {
        let now = Duration::from_secs(10);
        let mut first =
            BrokerServiceScheduler::new(now, IDLE_TIMEOUT).expect("valid first service");
        let mut second =
            BrokerServiceScheduler::new(now, IDLE_TIMEOUT).expect("valid second service");
        let ScheduledDispatch::Start(first_active) =
            first.dispatch(peer(42_000), policy(), AUTHENTICATE_REQUEST, now)
        else {
            panic!("first service starts")
        };
        let ScheduledDispatch::Start(second_active) =
            second.dispatch(peer(42_000), policy(), AUTHENTICATE_REQUEST, now)
        else {
            panic!("second service starts")
        };
        let first_completion =
            AuthenticationCompletion::matched_for_test(first_active.authentication());
        let second_completion =
            AuthenticationCompletion::matched_for_test(second_active.authentication());

        assert_eq!(
            first.finish(&first_active, &second_completion, now),
            Response::Failure
        );
        assert!(matches!(
            first.dispatch(peer(42_000), policy(), AUTHENTICATE_REQUEST, now),
            ScheduledDispatch::Reply(Response::Busy)
        ));
        assert_eq!(
            first.finish(&first_active, &first_completion, now),
            Response::Okay
        );
        assert!(matches!(
            first.dispatch(peer(42_000), policy(), AUTHENTICATE_REQUEST, now),
            ScheduledDispatch::Start(_)
        ));
        assert_eq!(
            second.finish(&second_active, &second_completion, now),
            Response::Okay
        );
    }

    #[test]
    fn authoritative_feedback_runs_before_exact_worker_release_and_is_cosmetic() {
        let now = Duration::from_secs(10);
        for fail_first in [false, true] {
            let mut service =
                BrokerServiceScheduler::new(now, IDLE_TIMEOUT).expect("valid service policy");
            let ScheduledDispatch::Start(active) =
                service.dispatch(peer(42_000), policy(), AUTHENTICATE_REQUEST, now)
            else {
                panic!("operation starts")
            };
            let completion = AuthenticationCompletion::matched_for_test(active.authentication());
            let mut feedback = FakeFeedback {
                actions: Vec::new(),
                fail_first,
            };

            assert_eq!(
                service.finish_with_feedback(&active, &completion, Some(&mut feedback), now,),
                Response::Okay
            );
            let expected = if fail_first {
                vec![FeedbackAction::ShowSuccess]
            } else {
                vec![
                    FeedbackAction::ShowSuccess,
                    FeedbackAction::PauseAfterSuccess,
                ]
            };
            assert_eq!(feedback.actions, expected);
            assert!(matches!(
                service.dispatch(peer(42_000), policy(), AUTHENTICATE_REQUEST, now),
                ScheduledDispatch::Start(_)
            ));
        }
    }

    #[test]
    fn cancellation_and_foreign_completion_cannot_present_feedback() {
        let now = Duration::from_secs(10);
        let mut first =
            BrokerServiceScheduler::new(now, IDLE_TIMEOUT).expect("valid first service");
        let mut second =
            BrokerServiceScheduler::new(now, IDLE_TIMEOUT).expect("valid second service");
        let ScheduledDispatch::Start(first_active) =
            first.dispatch(peer(42_000), policy(), AUTHENTICATE_REQUEST, now)
        else {
            panic!("first operation starts")
        };
        let ScheduledDispatch::Start(second_active) =
            second.dispatch(peer(42_000), policy(), AUTHENTICATE_REQUEST, now)
        else {
            panic!("second operation starts")
        };
        let foreign = AuthenticationCompletion::matched_for_test(second_active.authentication());
        let exact = AuthenticationCompletion::matched_for_test(first_active.authentication());
        let mut feedback = FakeFeedback::default();

        assert_eq!(
            first.finish_with_feedback(&first_active, &foreign, Some(&mut feedback), now),
            Response::Failure
        );
        assert!(feedback.actions.is_empty());
        assert!(matches!(
            first.dispatch(peer(42_000), policy(), AUTHENTICATE_REQUEST, now),
            ScheduledDispatch::Reply(Response::Busy)
        ));

        assert!(matches!(
            first.dispatch(peer(0), policy(), CANCEL_REQUEST, now),
            ScheduledDispatch::Reply(Response::Okay)
        ));
        assert_eq!(
            first.finish_with_feedback(&first_active, &exact, Some(&mut feedback), now),
            Response::Failure
        );
        assert!(feedback.actions.is_empty());
        assert!(matches!(
            first.dispatch(peer(42_000), policy(), AUTHENTICATE_REQUEST, now),
            ScheduledDispatch::Start(_)
        ));
        assert_eq!(second.abandon(&second_active, now), Response::Failure);
    }

    #[test]
    fn lost_worker_can_never_report_success_or_release_termination() {
        let now = Duration::from_secs(10);
        let mut service =
            BrokerServiceScheduler::new(now, IDLE_TIMEOUT).expect("valid service policy");
        let ScheduledDispatch::Start(active) =
            service.dispatch(peer(42_000), policy(), AUTHENTICATE_REQUEST, now)
        else {
            panic!("operation starts")
        };
        let completion = AuthenticationCompletion::matched_for_test(active.authentication());

        assert!(service.worker_lost(&active));
        assert_eq!(service.finish(&active, &completion, now), Response::Failure);
        assert_eq!(service.decide(now, true), LifecycleDecision::Terminate);
        assert!(matches!(
            service.dispatch(peer(0), policy(), CANCEL_REQUEST, now),
            ScheduledDispatch::Terminate
        ));
        assert!(matches!(
            service.cancel_without_owner(peer(0)),
            ScheduledDispatch::Terminate
        ));
    }
}

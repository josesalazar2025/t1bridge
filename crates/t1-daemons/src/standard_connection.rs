//! Transport-free LOCAL standard-fingerprint connection state.
//!
//! A daemon attaches this state to a connection accepted by the existing
//! systemd-owned, root-private local seqpacket listener and passes the same
//! [`BrokerServiceScheduler`] used by direct authentication. This module owns
//! no listener, coordinator, scheduler, thread, or hardware service.

use std::fmt;
use std::time::Duration;

use crate::auth_protocol::{AccessPolicy, PeerAddressFamily, PeerMetadata};
use crate::auth_scheduler::{
    BrokerServiceScheduler, ScheduledStandardDispatch, ScheduledStandardOperation,
};
use crate::auth_session::{ActiveStandardOperation, StandardCompletion};
use crate::nss_account::{NssAccountError, resolve_standard_account};
use crate::standard_fingerprint_protocol::{
    Capabilities, CapabilitySet, ClientMessage, EnrollProgress, MAX_IDENTITIES, ServerMessage,
    TerminalOutcome, Username, decode_client, encode_server,
};
use crate::standard_operation_authority::{ResolvedStandardAccount, ResolvedStandardOperation};

/// Immutable capability contract for every connection accepted by one daemon.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StandardConnectionConfig {
    capabilities: Capabilities,
}

impl StandardConnectionConfig {
    /// Advertises every Decision 63 operation with one hardware-proven fixed
    /// enrollment-stage count.
    ///
    /// # Errors
    ///
    /// Rejects zero or protocol-unrepresentable enrollment-stage counts.
    pub fn new(enroll_stages: u8) -> Result<Self, StandardConnectionError> {
        let operations = CapabilitySet::LIST
            | CapabilitySet::ENROLL
            | CapabilitySet::VERIFY
            | CapabilitySet::IDENTIFY
            | CapabilitySet::DELETE
            | CapabilitySet::CANCEL;
        let capabilities = Capabilities::new(operations, enroll_stages, MAX_IDENTITIES)
            .map_err(|_| StandardConnectionError::InvalidCapabilities)?;
        Ok(Self { capabilities })
    }

    /// Fixed response returned by every capability query on this daemon.
    #[must_use]
    pub const fn capabilities(self) -> Capabilities {
        self.capabilities
    }
}

/// One authenticated local connection, independent of descriptor ownership.
pub struct StandardConnection {
    peer: PeerMetadata,
    config: StandardConnectionConfig,
    opened: bool,
    active: Option<ScheduledStandardOperation>,
}

impl StandardConnection {
    /// Binds one kernel-authenticated local peer to immutable capabilities.
    ///
    /// # Errors
    ///
    /// Refuses metadata not derived from a local seqpacket peer.
    pub fn new(
        peer: PeerMetadata,
        config: StandardConnectionConfig,
    ) -> Result<Self, StandardConnectionError> {
        if peer.address_family != PeerAddressFamily::Local {
            return Err(StandardConnectionError::NonLocalPeer);
        }
        Ok(Self {
            peer,
            config,
            opened: false,
            active: None,
        })
    }

    /// Decodes and dispatches one complete bounded standard protocol packet.
    ///
    /// Capability queries and idempotent Open are immediate. Operations require
    /// Open and enter the existing shared broker scheduler. A second request
    /// while work is active receives Busy, except Cancel, which targets only
    /// this connection's exact active token and waits for worker completion.
    /// Canonical usernames are resolved before scheduler admission; List never
    /// calls the resolver because it carries no username.
    #[must_use]
    pub fn dispatch_packet(
        &mut self,
        service: &mut BrokerServiceScheduler,
        recorded_owner: Option<AccessPolicy>,
        packet: &[u8],
        now: Duration,
    ) -> StandardConnectionDispatch {
        self.dispatch_packet_with(
            service,
            recorded_owner,
            packet,
            now,
            resolve_standard_account,
        )
    }

    fn dispatch_packet_with(
        &mut self,
        service: &mut BrokerServiceScheduler,
        recorded_owner: Option<AccessPolicy>,
        packet: &[u8],
        now: Duration,
        resolve: impl FnOnce(&Username) -> Result<ResolvedStandardAccount, NssAccountError>,
    ) -> StandardConnectionDispatch {
        let Ok(message) = decode_client(packet) else {
            return reply(ServerMessage::Terminal(TerminalOutcome::Error));
        };

        if let Some(active) = self.active.as_ref() {
            return if message == ClientMessage::Cancel {
                // A closed mutation cutoff may legitimately reject delivery;
                // either way the authoritative worker completion remains the
                // only terminal response for the active request.
                let _ = service.cancel_standard(active);
                StandardConnectionDispatch::CancellationPending
            } else {
                reply(ServerMessage::Terminal(TerminalOutcome::Busy))
            };
        }

        match message {
            ClientMessage::GetCapabilities => {
                reply(ServerMessage::Capabilities(self.config.capabilities()))
            }
            ClientMessage::Open => {
                self.opened = true;
                reply(ServerMessage::Opened)
            }
            ClientMessage::Cancel => reply(ServerMessage::Terminal(TerminalOutcome::Error)),
            message if !self.opened => {
                let _ = message;
                reply(ServerMessage::Terminal(TerminalOutcome::Error))
            }
            message => {
                let Ok(operation) = resolve_operation(message, resolve) else {
                    return reply(ServerMessage::Terminal(TerminalOutcome::Error));
                };
                match service.dispatch_standard(self.peer, recorded_owner, operation, now) {
                    ScheduledStandardDispatch::Reply(message) => reply(message),
                    ScheduledStandardDispatch::Start(scheduled) => {
                        let worker = StandardWorkerJob {
                            operation: scheduled.operation().clone_for_worker(),
                            deadline: scheduled.deadline(),
                        };
                        self.active = Some(scheduled);
                        StandardConnectionDispatch::Start(worker)
                    }
                    ScheduledStandardDispatch::Terminate => StandardConnectionDispatch::Terminate,
                }
            }
        }
    }

    /// Validates one exact worker's nonterminal enrollment progress.
    ///
    /// # Errors
    ///
    /// Refuses progress from a foreign or inactive worker and progress for any
    /// operation other than enrollment.
    pub fn worker_progress(
        &self,
        worker: &StandardWorkerJob,
        progress: EnrollProgress,
    ) -> Result<StandardReply, StandardConnectionError> {
        let scheduled = self
            .active
            .as_ref()
            .ok_or(StandardConnectionError::NoActiveOperation)?;
        if !worker.belongs_to(scheduled) {
            return Err(StandardConnectionError::ForeignWorker);
        }
        if !matches!(
            worker.operation().operation().operation(),
            ResolvedStandardOperation::Enroll { .. }
        ) {
            return Err(StandardConnectionError::InvalidProgress);
        }
        let message = ServerMessage::EnrollProgress(progress);
        debug_assert!(!message.is_terminal());
        Ok(StandardReply::new(message))
    }

    /// Finalizes one exact worker through the existing shared scheduler.
    #[must_use]
    pub fn finish_worker(
        &mut self,
        service: &mut BrokerServiceScheduler,
        completion: &StandardCompletion,
        now: Duration,
    ) -> StandardConnectionDispatch {
        let Some(scheduled) = self.active.take() else {
            return StandardConnectionDispatch::Terminate;
        };
        if !completion.belongs_to(scheduled.operation()) {
            let _ = service.standard_worker_lost(&scheduled);
            return StandardConnectionDispatch::Terminate;
        }
        reply(service.finish_standard(&scheduled, completion, now))
    }

    /// Routes peer disconnect to the exact active scheduler token.
    pub fn client_disconnected(&self, service: &mut BrokerServiceScheduler) -> bool {
        self.active
            .as_ref()
            .is_some_and(|active| service.standard_client_disconnected(active))
    }

    /// Routes deadline expiry to the exact active scheduler token.
    pub fn deadline_expired(&self, service: &mut BrokerServiceScheduler) -> bool {
        self.active
            .as_ref()
            .is_some_and(|active| service.standard_deadline_expired(active))
    }

    /// Routes exact worker loss through the shared scheduler's poison path.
    #[must_use]
    pub fn worker_lost(
        &mut self,
        service: &mut BrokerServiceScheduler,
    ) -> StandardConnectionDispatch {
        let Some(scheduled) = self.active.take() else {
            return StandardConnectionDispatch::Terminate;
        };
        let _ = service.standard_worker_lost(&scheduled);
        StandardConnectionDispatch::Terminate
    }
}

impl fmt::Debug for StandardConnection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StandardConnection")
            .field("opened", &self.opened)
            .field("active", &self.active.is_some())
            .field("peer", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// Worker-facing exact operation and deadline selected by the shared service.
pub struct StandardWorkerJob {
    operation: ActiveStandardOperation,
    deadline: Duration,
}

impl StandardWorkerJob {
    /// Exact authorized operation for the injected worker callback.
    #[must_use]
    pub const fn operation(&self) -> &ActiveStandardOperation {
        &self.operation
    }

    /// Complete operation deadline selected by the shared scheduler.
    #[must_use]
    pub const fn deadline(&self) -> Duration {
        self.deadline
    }

    /// Whether exact-token cancellation has reached this worker.
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.operation.is_cancelled()
    }

    /// Binds one terminal or identity-list worker result to this exact job.
    #[must_use]
    pub fn completion(&self, result: ServerMessage) -> StandardCompletion {
        self.operation.completion_for_worker(result)
    }

    fn belongs_to(&self, scheduled: &ScheduledStandardOperation) -> bool {
        self.completion(ServerMessage::Terminal(TerminalOutcome::Error))
            .belongs_to(scheduled.operation())
    }
}

impl fmt::Debug for StandardWorkerJob {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StandardWorkerJob(<redacted>)")
    }
}

/// One encoded, bounded standard server packet retained for transport send.
pub struct StandardReply {
    message: ServerMessage,
    packet: Vec<u8>,
}

impl StandardReply {
    pub(crate) fn new(message: ServerMessage) -> Self {
        if let Ok(packet) = encode_server(&message) {
            Self { message, packet }
        } else {
            let message = ServerMessage::Terminal(TerminalOutcome::Error);
            let packet =
                encode_server(&message).expect("fixed standard error response is protocol-valid");
            Self { message, packet }
        }
    }

    /// Typed message retained with its exact encoded packet.
    #[must_use]
    pub const fn message(&self) -> &ServerMessage {
        &self.message
    }

    /// Complete packet, always within the protocol bound.
    #[must_use]
    pub fn packet(&self) -> &[u8] {
        &self.packet
    }
}

impl fmt::Debug for StandardReply {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StandardReply")
            .field("message", &"<redacted>")
            .field("packet_len", &self.packet.len())
            .finish()
    }
}

/// Result of one connection or worker event.
pub enum StandardConnectionDispatch {
    Reply(StandardReply),
    Start(StandardWorkerJob),
    CancellationPending,
    Terminate,
}

impl fmt::Debug for StandardConnectionDispatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Reply(reply) => formatter.debug_tuple("Reply").field(reply).finish(),
            Self::Start(_) => formatter.write_str("Start(<redacted>)"),
            Self::CancellationPending => formatter.write_str("CancellationPending"),
            Self::Terminate => formatter.write_str("Terminate"),
        }
    }
}

/// Payload-free local connection-state failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StandardConnectionError {
    NonLocalPeer,
    InvalidCapabilities,
    NoActiveOperation,
    ForeignWorker,
    InvalidProgress,
}

impl fmt::Display for StandardConnectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NonLocalPeer => "standard fingerprint peer is not local",
            Self::InvalidCapabilities => "standard fingerprint capabilities are invalid",
            Self::NoActiveOperation => "standard fingerprint operation is not active",
            Self::ForeignWorker => "standard fingerprint worker does not match",
            Self::InvalidProgress => "standard fingerprint progress is invalid",
        })
    }
}

impl std::error::Error for StandardConnectionError {}

fn resolve_operation(
    message: ClientMessage,
    resolve: impl FnOnce(&Username) -> Result<ResolvedStandardAccount, NssAccountError>,
) -> Result<ResolvedStandardOperation, NssAccountError> {
    match message {
        ClientMessage::ListIdentities => Ok(ResolvedStandardOperation::ListIdentities),
        ClientMessage::Enroll { username, finger } => {
            let account = resolve(&username)?;
            Ok(ResolvedStandardOperation::Enroll { account, finger })
        }
        ClientMessage::Verify { username, identity } => {
            let account = resolve(&username)?;
            Ok(ResolvedStandardOperation::Verify { account, identity })
        }
        ClientMessage::Identify { username } => {
            let account = resolve(&username)?;
            Ok(ResolvedStandardOperation::Identify { account })
        }
        ClientMessage::DeleteIdentity { username, identity } => {
            let account = resolve(&username)?;
            Ok(ResolvedStandardOperation::DeleteIdentity { account, identity })
        }
        ClientMessage::GetCapabilities | ClientMessage::Open | ClientMessage::Cancel => {
            unreachable!("connection controls are handled before operation resolution")
        }
    }
}

fn reply(message: ServerMessage) -> StandardConnectionDispatch {
    StandardConnectionDispatch::Reply(StandardReply::new(message))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_scheduler::{LifecycleDecision, OPERATION_TIMEOUT};
    use crate::standard_fingerprint_protocol::{
        ClientMessage, EnrollProgress, FingerLabel, Identity, IdentityId, MAX_PACKET_SIZE,
        decode_server, encode_client,
    };

    const OWNER_UID: u32 = 42_000;
    const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

    fn config() -> StandardConnectionConfig {
        StandardConnectionConfig::new(8).unwrap()
    }

    fn peer(user_id: u32) -> PeerMetadata {
        PeerMetadata {
            address_family: PeerAddressFamily::Local,
            user_id,
            group_id: 42_001,
        }
    }

    fn service() -> BrokerServiceScheduler {
        BrokerServiceScheduler::new(Duration::ZERO, IDLE_TIMEOUT).unwrap()
    }

    fn policy() -> AccessPolicy {
        AccessPolicy::new(OWNER_UID).unwrap()
    }

    fn username() -> Username {
        Username::new("synthetic-owner").unwrap()
    }

    fn account(name: &Username) -> Result<ResolvedStandardAccount, NssAccountError> {
        ResolvedStandardAccount::new(name, name, OWNER_UID)
            .map_err(|_| NssAccountError::InvalidResult)
    }

    fn identity(value: u8) -> IdentityId {
        IdentityId::new([value; 16]).unwrap()
    }

    fn packet(message: &ClientMessage) -> Vec<u8> {
        encode_client(message).unwrap()
    }

    fn reply_message(dispatch: StandardConnectionDispatch) -> ServerMessage {
        let StandardConnectionDispatch::Reply(reply) = dispatch else {
            panic!("expected reply")
        };
        assert!(reply.packet().len() <= MAX_PACKET_SIZE);
        assert_eq!(decode_server(reply.packet()).unwrap(), *reply.message());
        reply.message().clone()
    }

    fn opened_connection(user_id: u32) -> StandardConnection {
        let mut connection = StandardConnection::new(peer(user_id), config()).unwrap();
        let mut service = service();
        assert_eq!(
            reply_message(connection.dispatch_packet_with(
                &mut service,
                Some(policy()),
                &packet(&ClientMessage::Open),
                Duration::ZERO,
                account,
            )),
            ServerMessage::Opened
        );
        connection
    }

    #[test]
    fn configuration_is_fixed_and_requires_a_real_stage_count() {
        assert_eq!(
            StandardConnectionConfig::new(0),
            Err(StandardConnectionError::InvalidCapabilities)
        );
        let capabilities = config().capabilities();
        for operation in [
            CapabilitySet::LIST,
            CapabilitySet::ENROLL,
            CapabilitySet::VERIFY,
            CapabilitySet::IDENTIFY,
            CapabilitySet::DELETE,
            CapabilitySet::CANCEL,
        ] {
            assert!(capabilities.operations().contains(operation));
        }
        assert_eq!(capabilities.max_enroll_stages(), 8);
        assert_eq!(capabilities.max_identities(), MAX_IDENTITIES);
    }

    #[test]
    fn only_local_kernel_peer_metadata_can_construct_a_connection() {
        let mut remote = peer(OWNER_UID);
        remote.address_family = PeerAddressFamily::Other;
        assert!(matches!(
            StandardConnection::new(remote, config()),
            Err(StandardConnectionError::NonLocalPeer)
        ));
    }

    #[test]
    fn capabilities_and_open_are_immediate_fixed_bounded_replies() {
        let mut connection = StandardConnection::new(peer(OWNER_UID), config()).unwrap();
        let mut service = service();
        for _ in 0..2 {
            assert_eq!(
                reply_message(connection.dispatch_packet_with(
                    &mut service,
                    Some(policy()),
                    &packet(&ClientMessage::GetCapabilities),
                    Duration::ZERO,
                    |_| panic!("capability query has no account"),
                )),
                ServerMessage::Capabilities(config().capabilities())
            );
        }
        for _ in 0..2 {
            assert_eq!(
                reply_message(connection.dispatch_packet_with(
                    &mut service,
                    Some(policy()),
                    &packet(&ClientMessage::Open),
                    Duration::ZERO,
                    |_| panic!("open has no account"),
                )),
                ServerMessage::Opened
            );
        }
    }

    #[test]
    fn operation_requires_open_and_malformed_packets_fail_bounded() {
        let mut connection = StandardConnection::new(peer(OWNER_UID), config()).unwrap();
        let mut service = service();
        assert_eq!(
            reply_message(connection.dispatch_packet_with(
                &mut service,
                Some(policy()),
                &packet(&ClientMessage::ListIdentities),
                Duration::ZERO,
                |_| panic!("closed connection must not resolve"),
            )),
            ServerMessage::Terminal(TerminalOutcome::Error)
        );
        for malformed in [vec![], vec![0; MAX_PACKET_SIZE + 1]] {
            assert_eq!(
                reply_message(connection.dispatch_packet_with(
                    &mut service,
                    Some(policy()),
                    &malformed,
                    Duration::ZERO,
                    |_| panic!("malformed packet must not resolve"),
                )),
                ServerMessage::Terminal(TerminalOutcome::Error)
            );
        }
    }

    #[test]
    fn list_has_no_username_or_nss_lookup_and_finishes_through_scheduler() {
        let mut connection = opened_connection(0);
        let mut service = service();
        let StandardConnectionDispatch::Start(worker) = connection.dispatch_packet_with(
            &mut service,
            Some(policy()),
            &packet(&ClientMessage::ListIdentities),
            Duration::ZERO,
            |_| panic!("List must not resolve a username"),
        ) else {
            panic!("List starts")
        };
        let result = ServerMessage::IdentityList {
            owner: Some(username()),
            identities: vec![Identity {
                id: identity(2),
                finger: FingerLabel::LeftIndex,
            }],
        };
        let completion = worker.completion(result.clone());
        assert_eq!(
            reply_message(connection.finish_worker(
                &mut service,
                &completion,
                Duration::from_secs(1),
            )),
            result
        );
    }

    #[test]
    fn username_is_resolved_before_exact_scheduler_admission() {
        let mut connection = opened_connection(OWNER_UID);
        let mut service = service();
        let request = ClientMessage::Verify {
            username: username(),
            identity: identity(2),
        };
        let StandardConnectionDispatch::Start(worker) = connection.dispatch_packet_with(
            &mut service,
            Some(policy()),
            &packet(&request),
            Duration::ZERO,
            account,
        ) else {
            panic!("resolved Verify starts")
        };
        assert!(matches!(
            worker.operation().operation().operation(),
            ResolvedStandardOperation::Verify { account, identity: id }
                if account.canonical_username() == &username() && *id == identity(2)
        ));

        let completion = worker.completion(ServerMessage::Terminal(TerminalOutcome::Matched(
            identity(2),
        )));
        assert_eq!(
            reply_message(connection.finish_worker(
                &mut service,
                &completion,
                Duration::from_secs(1),
            )),
            ServerMessage::Terminal(TerminalOutcome::Matched(identity(2)))
        );
    }

    #[test]
    fn nss_failure_never_reaches_scheduler() {
        let mut connection = opened_connection(OWNER_UID);
        let mut service = service();
        let request = ClientMessage::Identify {
            username: username(),
        };
        assert_eq!(
            reply_message(connection.dispatch_packet_with(
                &mut service,
                Some(policy()),
                &packet(&request),
                Duration::ZERO,
                |_| Err(NssAccountError::NotFound),
            )),
            ServerMessage::Terminal(TerminalOutcome::Error)
        );
        assert_eq!(
            service.decide(Duration::from_secs(1), false),
            LifecycleDecision::Continue
        );
    }

    #[test]
    fn second_request_is_busy_but_exact_cancel_waits_for_completion() {
        let mut connection = opened_connection(OWNER_UID);
        let mut service = service();
        let request = ClientMessage::Identify {
            username: username(),
        };
        let StandardConnectionDispatch::Start(worker) = connection.dispatch_packet_with(
            &mut service,
            Some(policy()),
            &packet(&request),
            Duration::ZERO,
            account,
        ) else {
            panic!("Identify starts")
        };
        assert_eq!(
            reply_message(connection.dispatch_packet_with(
                &mut service,
                Some(policy()),
                &packet(&request),
                Duration::ZERO,
                account,
            )),
            ServerMessage::Terminal(TerminalOutcome::Busy)
        );
        assert!(matches!(
            connection.dispatch_packet_with(
                &mut service,
                Some(policy()),
                &packet(&ClientMessage::Cancel),
                Duration::ZERO,
                |_| panic!("Cancel has no username"),
            ),
            StandardConnectionDispatch::CancellationPending
        ));
        assert!(worker.is_cancelled());
        let completion = worker.completion(ServerMessage::Terminal(TerminalOutcome::Matched(
            identity(2),
        )));
        assert_eq!(
            reply_message(connection.finish_worker(
                &mut service,
                &completion,
                Duration::from_secs(1),
            )),
            ServerMessage::Terminal(TerminalOutcome::Cancelled)
        );
    }

    #[test]
    fn enrollment_progress_is_nonterminal_and_does_not_release_work() {
        let mut connection = opened_connection(OWNER_UID);
        let mut service = service();
        let request = ClientMessage::Enroll {
            username: username(),
            finger: FingerLabel::RightIndex,
        };
        let StandardConnectionDispatch::Start(worker) = connection.dispatch_packet_with(
            &mut service,
            Some(policy()),
            &packet(&request),
            Duration::ZERO,
            account,
        ) else {
            panic!("Enroll starts")
        };
        let progress = worker_progress(&connection, &worker, 3, 8);
        assert_eq!(
            progress.message(),
            &ServerMessage::EnrollProgress(EnrollProgress::new(3, 8).unwrap())
        );
        assert!(!progress.message().is_terminal());
        assert_eq!(
            reply_message(connection.dispatch_packet_with(
                &mut service,
                Some(policy()),
                &packet(&ClientMessage::ListIdentities),
                Duration::ZERO,
                |_| panic!("busy request must not resolve"),
            )),
            ServerMessage::Terminal(TerminalOutcome::Busy)
        );
        let completion = worker.completion(ServerMessage::Terminal(TerminalOutcome::Enrolled(
            identity(4),
        )));
        assert_eq!(
            reply_message(connection.finish_worker(
                &mut service,
                &completion,
                Duration::from_secs(1),
            )),
            ServerMessage::Terminal(TerminalOutcome::Enrolled(identity(4)))
        );
    }

    fn worker_progress(
        connection: &StandardConnection,
        worker: &StandardWorkerJob,
        completed: u8,
        total: u8,
    ) -> StandardReply {
        connection
            .worker_progress(worker, EnrollProgress::new(completed, total).unwrap())
            .unwrap()
    }

    #[test]
    fn progress_from_wrong_operation_or_worker_is_refused() {
        let mut first = opened_connection(OWNER_UID);
        let mut second = opened_connection(OWNER_UID);
        let mut first_service = service();
        let mut second_service = service();
        let request = ClientMessage::Verify {
            username: username(),
            identity: identity(2),
        };
        let StandardConnectionDispatch::Start(first_worker) = first.dispatch_packet_with(
            &mut first_service,
            Some(policy()),
            &packet(&request),
            Duration::ZERO,
            account,
        ) else {
            panic!("first starts")
        };
        let enroll = ClientMessage::Enroll {
            username: username(),
            finger: FingerLabel::LeftThumb,
        };
        let StandardConnectionDispatch::Start(second_worker) = second.dispatch_packet_with(
            &mut second_service,
            Some(policy()),
            &packet(&enroll),
            Duration::ZERO,
            account,
        ) else {
            panic!("second starts")
        };
        let progress = EnrollProgress::new(1, 8).unwrap();
        assert!(matches!(
            first.worker_progress(&first_worker, progress),
            Err(StandardConnectionError::InvalidProgress)
        ));
        assert!(matches!(
            first.worker_progress(&second_worker, progress),
            Err(StandardConnectionError::ForeignWorker)
        ));
    }

    #[test]
    fn disconnect_and_deadline_use_exact_scheduler_cancellation() {
        for deadline in [false, true] {
            let mut connection = opened_connection(OWNER_UID);
            let mut service = service();
            let request = ClientMessage::Identify {
                username: username(),
            };
            let StandardConnectionDispatch::Start(worker) = connection.dispatch_packet_with(
                &mut service,
                Some(policy()),
                &packet(&request),
                Duration::ZERO,
                account,
            ) else {
                panic!("Identify starts")
            };
            assert!(if deadline {
                connection.deadline_expired(&mut service)
            } else {
                connection.client_disconnected(&mut service)
            });
            assert!(worker.is_cancelled());
            let completion = worker.completion(ServerMessage::Terminal(TerminalOutcome::NoMatch));
            assert_eq!(
                reply_message(connection.finish_worker(
                    &mut service,
                    &completion,
                    OPERATION_TIMEOUT,
                )),
                ServerMessage::Terminal(TerminalOutcome::Cancelled)
            );
        }
    }

    #[test]
    fn foreign_completion_and_worker_loss_poison_shared_scheduler() {
        let mut first = opened_connection(OWNER_UID);
        let mut second = opened_connection(OWNER_UID);
        let mut first_service = service();
        let mut second_service = service();
        let request = ClientMessage::Identify {
            username: username(),
        };
        let StandardConnectionDispatch::Start(_first_worker) = first.dispatch_packet_with(
            &mut first_service,
            Some(policy()),
            &packet(&request),
            Duration::ZERO,
            account,
        ) else {
            panic!("first starts")
        };
        let StandardConnectionDispatch::Start(second_worker) = second.dispatch_packet_with(
            &mut second_service,
            Some(policy()),
            &packet(&request),
            Duration::ZERO,
            account,
        ) else {
            panic!("second starts")
        };
        let foreign = second_worker.completion(ServerMessage::Terminal(TerminalOutcome::NoMatch));
        assert!(matches!(
            first.finish_worker(&mut first_service, &foreign, Duration::ZERO),
            StandardConnectionDispatch::Terminate
        ));
        assert_eq!(
            first_service.decide(Duration::ZERO, false),
            LifecycleDecision::Terminate
        );

        assert!(matches!(
            second.worker_lost(&mut second_service),
            StandardConnectionDispatch::Terminate
        ));
        assert_eq!(
            second_service.decide(Duration::ZERO, false),
            LifecycleDecision::Terminate
        );
    }

    #[test]
    fn diagnostics_redact_peer_account_identity_and_packets() {
        let connection = opened_connection(OWNER_UID);
        let diagnostic = format!("{connection:?}");
        assert!(!diagnostic.contains(OWNER_UID.to_string().as_str()));
        assert!(!diagnostic.contains("synthetic-owner"));

        let reply = StandardReply::new(ServerMessage::Terminal(TerminalOutcome::Matched(
            identity(7),
        )));
        let diagnostic = format!("{reply:?}");
        assert!(!diagnostic.contains("7, 7, 7"));
        assert!(!diagnostic.contains("T1FP"));
        assert!(reply.packet().len() <= MAX_PACKET_SIZE);
    }
}

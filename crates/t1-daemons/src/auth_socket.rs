//! Systemd-activated local socket adapter for the authentication broker.
//!
//! This module adopts the one fixed broker listener and authenticates accepted
//! descriptors with kernel credentials. The caller still owns readiness
//! pacing, deadlines, concurrency, and worker lifetime; no event-loop or
//! worker policy is selected here.

use core::fmt;
use std::ffi::CStr;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::time::Duration;

use t1_platform::seqpacket::{
    PeerCredentials, SeqPacketClient, SeqPacketError, SeqPacketListener, SystemdActivation,
    SystemdSeqPacketListener,
};

use crate::auth_feedback::AuthenticationFeedback;
use crate::auth_protocol::{
    AUTHENTICATE_REQUEST, AccessPolicy, PeerAddressFamily, PeerMetadata, Request, Response,
    decode_request,
};
use crate::auth_scheduler::{BrokerServiceScheduler, ScheduledAuthentication, ScheduledDispatch};
use crate::auth_session::{ActiveAuthentication, AuthenticationCompletion};
use crate::enrollment_owner::{EnrollmentOwnerError, EnrollmentOwnerStore};

const REQUEST_CAPACITY: usize = AUTHENTICATE_REQUEST.len();
const ROOT_UID: u32 = 0;
const AUTH_SOCKET_PATH: &CStr = c"/run/t1-touchid/auth.sock";

/// Static transport failure from an already-connected broker session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrokerSocketError(pub SeqPacketError);

impl fmt::Display for BrokerSocketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "authentication socket failed: {}", self.0)
    }
}

impl std::error::Error for BrokerSocketError {}

/// Owned systemd-activated listener for the one fixed authentication socket.
pub struct ActivatedBrokerSocketListener {
    listener: SystemdSeqPacketListener,
}

impl fmt::Debug for ActivatedBrokerSocketListener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActivatedBrokerSocketListener")
            .finish_non_exhaustive()
    }
}

impl ActivatedBrokerSocketListener {
    #[must_use]
    pub const fn from_systemd_listener(listener: SystemdSeqPacketListener) -> Self {
        Self { listener }
    }

    /// Adopts exactly one validated systemd listener at the protocol path.
    ///
    /// # Errors
    ///
    /// Returns a static socket error if the activation environment, descriptor,
    /// socket shape, listening state, or pathname is not exact.
    pub fn adopt(activation: SystemdActivation) -> Result<Self, BrokerSocketError> {
        SystemdSeqPacketListener::adopt(activation, AUTH_SOCKET_PATH)
            .map(|listener| Self { listener })
            .map_err(BrokerSocketError)
    }

    /// Reports whether a client is queued without accepting or consuming it.
    ///
    /// # Errors
    ///
    /// Returns a static socket error when the readiness probe fails.
    pub fn is_ready(&self) -> Result<bool, BrokerSocketError> {
        self.listener.is_ready().map_err(BrokerSocketError)
    }

    /// Accepts one queued connection through the existing authenticated adapter.
    ///
    /// # Errors
    ///
    /// Returns a static socket error when no client is ready, the call is
    /// interrupted, or the listener can no longer accept safely.
    pub fn accept(&self) -> Result<BrokerSocketConnection<OwnedFd>, BrokerSocketError> {
        BrokerSocketListener {
            listener: self.listener.listener(),
        }
        .accept()
    }
}

/// Result of one nonblocking request receive attempt.
pub enum BrokerSocketDispatch<D> {
    /// No complete request is ready; retry after readiness notification.
    Pending(BrokerSocketConnection<D>),
    /// The peer closed before supplying a request. No response is possible.
    Closed,
    /// A fixed response is ready for an exact packet send.
    Reply(PendingBrokerReply<D>),
    /// An authenticated operation owns this connection until completion.
    Start(ActiveBrokerSocketSession<D>),
    /// The service authority became uncertain and the process must terminate.
    Terminate,
}

impl<D> fmt::Debug for BrokerSocketDispatch<D> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending(_) => formatter.write_str("Pending"),
            Self::Closed => formatter.write_str("Closed"),
            Self::Reply(reply) => formatter.debug_tuple("Reply").field(reply).finish(),
            Self::Start(active) => formatter.debug_tuple("Start").field(active).finish(),
            Self::Terminate => formatter.write_str("Terminate"),
        }
    }
}

/// Result of one exact nonblocking response send attempt.
#[derive(Debug)]
pub enum BrokerReplyProgress<D> {
    Sent(Response),
    Pending(PendingBrokerReply<D>),
}

/// Fixed response retained across nonblocking send retries.
pub struct PendingBrokerReply<D> {
    descriptor: D,
    response: Response,
}

impl<D> fmt::Debug for PendingBrokerReply<D> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingBrokerReply")
            .field("response", &self.response)
            .finish_non_exhaustive()
    }
}

impl<D: AsFd> PendingBrokerReply<D> {
    /// The exact typed response retained by this send state.
    #[must_use]
    pub const fn response(&self) -> Response {
        self.response
    }

    /// Attempts one exact four-byte packet send.
    ///
    /// `WouldBlock` and `Interrupted` retain the response for a later retry.
    /// No short or partial response is accepted as success.
    ///
    /// # Errors
    ///
    /// Returns a static socket error for a permanent transport failure.
    pub fn try_send(self) -> Result<BrokerReplyProgress<D>, BrokerSocketError> {
        match SeqPacketClient::new(self.descriptor.as_fd()).send(self.response.encode()) {
            Ok(()) => Ok(BrokerReplyProgress::Sent(self.response)),
            Err(SeqPacketError::WouldBlock | SeqPacketError::Interrupted) => {
                Ok(BrokerReplyProgress::Pending(self))
            }
            Err(error) => Err(BrokerSocketError(error)),
        }
    }
}

/// Borrowed systemd-owned listener that yields caller-owned connections.
#[derive(Clone, Copy, Debug)]
pub struct BrokerSocketListener<'fd> {
    listener: SeqPacketListener<'fd>,
}

impl<'fd> BrokerSocketListener<'fd> {
    #[must_use]
    pub const fn new(descriptor: BorrowedFd<'fd>) -> Self {
        Self {
            listener: SeqPacketListener::new(descriptor),
        }
    }

    #[must_use]
    pub const fn from_listener(listener: SeqPacketListener<'fd>) -> Self {
        Self { listener }
    }

    /// Accepts one connection whose descriptor survives every pending state.
    ///
    /// # Errors
    ///
    /// Returns a static socket error when the listener is invalid, interrupted,
    /// has no ready peer, or cannot accept the next connection.
    pub fn accept(self) -> Result<BrokerSocketConnection<OwnedFd>, BrokerSocketError> {
        self.listener
            .accept()
            .map(BrokerSocketConnection::new)
            .map_err(BrokerSocketError)
    }
}

/// One accepted, caller-owned local seqpacket connection.
#[derive(Debug)]
pub struct BrokerSocketConnection<D> {
    descriptor: D,
}

impl<D: AsFd> BrokerSocketConnection<D> {
    #[must_use]
    pub const fn new(descriptor: D) -> Self {
        Self { descriptor }
    }

    /// Authenticates the peer and receives one exact broker request packet.
    ///
    /// Kernel credentials are mapped to local peer metadata before request
    /// bytes are read. Unauthorized peers get `DENY` without parsing input.
    /// Oversized or malformed packets also get `DENY`. Readiness and
    /// interruption remain explicit so the caller can apply its own deadline.
    ///
    /// # Errors
    ///
    /// Returns a static error when the caller did not supply a connected local
    /// seqpacket descriptor or a permanent receive operation fails.
    pub fn receive_and_dispatch(
        self,
        service: &mut BrokerServiceScheduler,
        owner_store: &EnrollmentOwnerStore,
        now: Duration,
    ) -> Result<BrokerSocketDispatch<D>, BrokerSocketError> {
        let socket = SeqPacketClient::new(self.descriptor.as_fd());
        let dispatch = dispatch_connection(
            socket.peer_credentials(),
            || owner_store.access_policy(),
            |packet| socket.receive(packet),
            service,
            now,
        )?;
        Ok(match dispatch {
            CoreDispatch::Pending => BrokerSocketDispatch::Pending(self),
            CoreDispatch::Closed => BrokerSocketDispatch::Closed,
            CoreDispatch::Reply(response) => BrokerSocketDispatch::Reply(self.reply(response)),
            CoreDispatch::Start(scheduled) => {
                BrokerSocketDispatch::Start(ActiveBrokerSocketSession {
                    descriptor: self.descriptor,
                    scheduled,
                })
            }
            CoreDispatch::Terminate => BrokerSocketDispatch::Terminate,
        })
    }

    fn reply(self, response: Response) -> PendingBrokerReply<D> {
        PendingBrokerReply {
            descriptor: self.descriptor,
            response,
        }
    }
}

enum CoreDispatch {
    Pending,
    Closed,
    Reply(Response),
    Start(ScheduledAuthentication),
    Terminate,
}

fn dispatch_connection(
    credentials: Result<PeerCredentials, SeqPacketError>,
    policy: impl FnOnce() -> Result<AccessPolicy, EnrollmentOwnerError>,
    receive: impl FnOnce(&mut [u8]) -> Result<usize, SeqPacketError>,
    service: &mut BrokerServiceScheduler,
    now: Duration,
) -> Result<CoreDispatch, BrokerSocketError> {
    let credentials = match credentials {
        Ok(credentials) => credentials,
        Err(SeqPacketError::Credentials) => {
            return Ok(CoreDispatch::Reply(Response::Denied));
        }
        Err(error) => return Err(BrokerSocketError(error)),
    };
    let peer = local_peer(credentials);
    let policy = policy();
    match &policy {
        Ok(policy) if !policy.peer_is_authorized(peer) => {
            return Ok(CoreDispatch::Reply(Response::Denied));
        }
        Err(EnrollmentOwnerError::MissingOwner) if peer.user_id != ROOT_UID => {}
        Err(_) if peer.user_id != ROOT_UID => {
            return Ok(CoreDispatch::Reply(Response::Failure));
        }
        Ok(_) | Err(_) => {}
    }

    let mut packet = [0_u8; REQUEST_CAPACITY];
    let received = match receive(&mut packet) {
        Ok(received) => received,
        Err(SeqPacketError::WouldBlock | SeqPacketError::Interrupted) => {
            return Ok(CoreDispatch::Pending);
        }
        Err(SeqPacketError::PeerClosed) => return Ok(CoreDispatch::Closed),
        Err(SeqPacketError::Truncated) => return Ok(CoreDispatch::Reply(Response::Denied)),
        Err(error) => return Err(BrokerSocketError(error)),
    };
    if received > packet.len() {
        return Ok(CoreDispatch::Reply(Response::Denied));
    }

    let packet = &packet[..received];
    Ok(match policy {
        Ok(policy) => match service.dispatch(peer, policy, packet, now) {
            ScheduledDispatch::Reply(response) => CoreDispatch::Reply(response),
            ScheduledDispatch::Start(scheduled) => CoreDispatch::Start(scheduled),
            ScheduledDispatch::Terminate => CoreDispatch::Terminate,
        },
        Err(owner_error) => match decode_request(packet) {
            Ok(Request::Cancel) => match service.cancel_without_owner(peer) {
                ScheduledDispatch::Reply(response) => CoreDispatch::Reply(response),
                ScheduledDispatch::Terminate => CoreDispatch::Terminate,
                ScheduledDispatch::Start(_) => {
                    unreachable!("ownerless cancellation cannot start work")
                }
            },
            Ok(Request::Enroll)
                if owner_error == EnrollmentOwnerError::MissingOwner
                    && peer.user_id != ROOT_UID =>
            {
                match service.enroll_without_owner(peer, now) {
                    ScheduledDispatch::Reply(response) => CoreDispatch::Reply(response),
                    ScheduledDispatch::Start(scheduled) => CoreDispatch::Start(scheduled),
                    ScheduledDispatch::Terminate => CoreDispatch::Terminate,
                }
            }
            Ok(Request::Enroll) | Err(_) => CoreDispatch::Reply(Response::Denied),
            Ok(Request::Authenticate | Request::Approve) => CoreDispatch::Reply(Response::Failure),
        },
    })
}

/// Outcome of a non-consuming authentication-client disconnect probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisconnectObservation {
    Connected,
    CancellationDelivered,
    OperationInactive,
}

/// Active authentication tied to the owned request connection that started it.
pub struct ActiveBrokerSocketSession<D> {
    descriptor: D,
    scheduled: ScheduledAuthentication,
}

impl<D> fmt::Debug for ActiveBrokerSocketSession<D> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActiveBrokerSocketSession")
            .field("scheduled", &self.scheduled)
            .finish_non_exhaustive()
    }
}

impl<D: AsFd> ActiveBrokerSocketSession<D> {
    /// Token-associated operation used by the caller-owned hardware worker.
    #[must_use]
    pub const fn authentication(&self) -> &ActiveAuthentication {
        self.scheduled.authentication()
    }

    /// One monotonic setup-and-match deadline for this exact worker.
    #[must_use]
    pub const fn deadline(&self) -> Duration {
        self.scheduled.deadline()
    }

    /// Probes for peer closure without consuming unexpected queued data.
    ///
    /// A confirmed close or probe failure is delivered through the same exact
    /// token path as explicit cancellation. A later match therefore cannot
    /// authenticate a disconnected client. The caller chooses how often and
    /// from which worker or event loop this nonblocking probe runs.
    pub fn observe_disconnect(
        &self,
        service: &mut BrokerServiceScheduler,
    ) -> DisconnectObservation {
        observe_disconnect_result(
            SeqPacketClient::new(self.descriptor.as_fd()).peer_closed(),
            service,
            &self.scheduled,
        )
    }

    /// Delivers deadline cancellation to this exact scheduled operation.
    ///
    /// The worker remains active until [`Self::finish`] or [`Self::abandon`]
    /// resolves its lease.
    pub fn deadline_expired(&self, service: &mut BrokerServiceScheduler) -> bool {
        service.deadline_expired(&self.scheduled)
    }

    /// Finalizes the exact operation and retains its response for send.
    #[must_use]
    pub fn finish(
        self,
        service: &mut BrokerServiceScheduler,
        completion: &AuthenticationCompletion,
        now: Duration,
    ) -> PendingBrokerReply<D> {
        PendingBrokerReply {
            descriptor: self.descriptor,
            response: service.finish(&self.scheduled, completion, now),
        }
    }

    /// Finalizes the exact operation through authoritative best-effort
    /// feedback and retains the same connection for its final response.
    #[must_use]
    pub fn finish_with_feedback<Feedback: AuthenticationFeedback>(
        self,
        service: &mut BrokerServiceScheduler,
        completion: &AuthenticationCompletion,
        feedback: Option<&mut Feedback>,
        now: Duration,
    ) -> PendingBrokerReply<D> {
        PendingBrokerReply {
            descriptor: self.descriptor,
            response: service.finish_with_feedback(&self.scheduled, completion, feedback, now),
        }
    }

    /// Releases work that could not be handed to a caller-owned worker.
    #[must_use]
    pub fn abandon(
        self,
        service: &mut BrokerServiceScheduler,
        now: Duration,
    ) -> PendingBrokerReply<D> {
        PendingBrokerReply {
            descriptor: self.descriptor,
            response: service.abandon(&self.scheduled, now),
        }
    }

    /// Marks this exact worker lost so the service cannot admit replacement
    /// work under uncertain hardware ownership.
    pub fn worker_lost(self, service: &mut BrokerServiceScheduler) -> bool {
        service.worker_lost(&self.scheduled)
    }
}

fn observe_disconnect_result(
    peer_closed: Result<bool, SeqPacketError>,
    service: &mut BrokerServiceScheduler,
    scheduled: &ScheduledAuthentication,
) -> DisconnectObservation {
    if matches!(peer_closed, Ok(false)) {
        return DisconnectObservation::Connected;
    }
    if service.client_disconnected(scheduled) {
        DisconnectObservation::CancellationDelivered
    } else {
        DisconnectObservation::OperationInactive
    }
}

const fn local_peer(credentials: PeerCredentials) -> PeerMetadata {
    PeerMetadata {
        address_family: PeerAddressFamily::Local,
        user_id: credentials.user_id,
        group_id: credentials.group_id,
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::os::fd::{AsFd, OwnedFd};
    use std::os::unix::net::UnixDatagram;

    use super::*;
    use crate::auth_feedback::{AuthenticationFeedback, FeedbackAction};
    use crate::auth_protocol::{AUTHENTICATE_REQUEST, CANCEL_REQUEST, ENROLL_REQUEST, Purpose};
    use crate::auth_scheduler::{LifecycleDecision, OPERATION_TIMEOUT};

    const INTERACTIVE_USER: u32 = 42_000;
    const NOW: Duration = Duration::from_secs(10);
    const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

    #[derive(Default)]
    struct FakeFeedback(Vec<FeedbackAction>);

    impl AuthenticationFeedback for FakeFeedback {
        type Error = core::convert::Infallible;

        fn apply(&mut self, action: FeedbackAction) -> Result<(), Self::Error> {
            self.0.push(action);
            Ok(())
        }
    }

    fn policy() -> AccessPolicy {
        AccessPolicy::new(INTERACTIVE_USER).unwrap()
    }

    fn valid_policy() -> Result<AccessPolicy, EnrollmentOwnerError> {
        AccessPolicy::new(INTERACTIVE_USER).map_err(|_| EnrollmentOwnerError::CorruptState)
    }

    fn service() -> BrokerServiceScheduler {
        BrokerServiceScheduler::new(NOW, IDLE_TIMEOUT).unwrap()
    }

    fn credentials(user_id: u32) -> PeerCredentials {
        PeerCredentials {
            process_id: 777,
            user_id,
            group_id: 42_001,
        }
    }

    fn packet_receive(
        packet: &'static [u8],
    ) -> impl FnOnce(&mut [u8]) -> Result<usize, SeqPacketError> {
        move |buffer| {
            buffer[..packet.len()].copy_from_slice(packet);
            Ok(packet.len())
        }
    }

    #[test]
    fn maps_only_kernel_credential_fields_used_by_policy() {
        let metadata = local_peer(PeerCredentials {
            process_id: 777,
            user_id: INTERACTIVE_USER,
            group_id: 42_001,
        });
        assert_eq!(metadata.address_family, PeerAddressFamily::Local);
        assert_eq!(metadata.user_id, INTERACTIVE_USER);
        assert_eq!(metadata.group_id, 42_001);
        assert!(policy().peer_is_authorized(metadata));
        assert!(!format!("{metadata:?}").contains("42000"));
        assert!(!format!("{metadata:?}").contains("777"));
    }

    #[test]
    fn listener_and_connection_reject_the_wrong_socket_type() {
        let (socket, _peer) = UnixDatagram::pair().unwrap();
        assert!(matches!(
            BrokerSocketListener::new(socket.as_fd()).accept(),
            Err(BrokerSocketError(SeqPacketError::WrongSocket))
        ));

        let mut service = service();
        assert!(matches!(
            dispatch_connection(
                Err(SeqPacketError::WrongSocket),
                valid_policy,
                |_| unreachable!("wrong socket cannot receive"),
                &mut service,
                NOW,
            ),
            Err(BrokerSocketError(SeqPacketError::WrongSocket))
        ));
    }

    #[test]
    fn owned_reply_state_is_exact_and_diagnostics_are_payload_free() {
        let (socket, _peer) = UnixDatagram::pair().unwrap();
        let descriptor: OwnedFd = socket.into();
        let reply = BrokerSocketConnection::new(descriptor).reply(Response::Denied);
        assert_eq!(reply.response(), Response::Denied);
        assert_eq!(reply.response().encode(), b"DENY");
        let rendered = format!("{reply:?} {}", BrokerSocketError(SeqPacketError::Receive));
        assert!(!rendered.contains('/'));
        assert!(!rendered.contains("42000"));
    }

    #[test]
    fn different_recorded_owner_is_denied_before_enrollment_packet_receive() {
        let receive_called = Cell::new(false);
        let mut service = service();
        let dispatch = dispatch_connection(
            Ok(credentials(INTERACTIVE_USER + 1)),
            valid_policy,
            |_| {
                receive_called.set(true);
                Ok(0)
            },
            &mut service,
            NOW,
        )
        .unwrap();
        assert!(!receive_called.get());
        assert!(matches!(dispatch, CoreDispatch::Reply(Response::Denied)));
    }

    #[test]
    fn unavailable_owner_state_fails_before_receive_or_scheduler_mutation() {
        for error in [
            EnrollmentOwnerError::UnsafeStorage,
            EnrollmentOwnerError::CorruptState,
            EnrollmentOwnerError::StorageUnavailable,
        ] {
            let receive_called = Cell::new(false);
            let mut service = service();
            let dispatch = dispatch_connection(
                Ok(credentials(INTERACTIVE_USER)),
                || Err(error),
                |_| {
                    receive_called.set(true);
                    Ok(0)
                },
                &mut service,
                NOW,
            )
            .unwrap();
            assert!(!receive_called.get());
            assert!(matches!(dispatch, CoreDispatch::Reply(Response::Failure)));

            let CoreDispatch::Start(active) = dispatch_connection(
                Ok(credentials(INTERACTIVE_USER)),
                valid_policy,
                packet_receive(AUTHENTICATE_REQUEST),
                &mut service,
                NOW,
            )
            .unwrap() else {
                panic!("owner-state failure must leave the scheduler idle")
            };
            assert_eq!(service.abandon(&active, NOW), Response::Failure);
        }
    }

    #[test]
    fn missing_owner_admits_one_candidate_with_busy_and_root_cancel_authority() {
        let mut broker = service();
        let mut wrong_version = *ENROLL_REQUEST;
        wrong_version[6] = 2;
        assert!(matches!(
            dispatch_connection(
                Ok(credentials(INTERACTIVE_USER)),
                || Err(EnrollmentOwnerError::MissingOwner),
                move |buffer| {
                    buffer.copy_from_slice(&wrong_version);
                    Ok(wrong_version.len())
                },
                &mut broker,
                NOW,
            )
            .unwrap(),
            CoreDispatch::Reply(Response::Denied)
        ));

        let CoreDispatch::Start(enrollment) = dispatch_connection(
            Ok(credentials(INTERACTIVE_USER)),
            || Err(EnrollmentOwnerError::MissingOwner),
            packet_receive(ENROLL_REQUEST),
            &mut broker,
            NOW,
        )
        .unwrap() else {
            panic!("exact missing-owner enrollment starts")
        };
        assert_eq!(enrollment.authentication().purpose(), Purpose::Enrollment);
        assert_eq!(
            enrollment
                .authentication()
                .enrollment_owner_candidate()
                .expect("candidate is carried into scheduled work")
                .user_id(),
            INTERACTIVE_USER
        );

        assert!(matches!(
            dispatch_connection(
                Ok(credentials(INTERACTIVE_USER + 1)),
                || Err(EnrollmentOwnerError::MissingOwner),
                packet_receive(ENROLL_REQUEST),
                &mut broker,
                NOW,
            )
            .unwrap(),
            CoreDispatch::Reply(Response::Busy)
        ));
        assert!(matches!(
            dispatch_connection(
                Ok(credentials(INTERACTIVE_USER)),
                || Err(EnrollmentOwnerError::MissingOwner),
                packet_receive(AUTHENTICATE_REQUEST),
                &mut broker,
                NOW,
            )
            .unwrap(),
            CoreDispatch::Reply(Response::Failure)
        ));
        assert!(matches!(
            dispatch_connection(
                Ok(credentials(ROOT_UID)),
                || Err(EnrollmentOwnerError::MissingOwner),
                packet_receive(ENROLL_REQUEST),
                &mut broker,
                NOW,
            )
            .unwrap(),
            CoreDispatch::Reply(Response::Denied)
        ));
        assert!(matches!(
            dispatch_connection(
                Ok(credentials(ROOT_UID)),
                || Err(EnrollmentOwnerError::MissingOwner),
                packet_receive(CANCEL_REQUEST),
                &mut broker,
                NOW,
            )
            .unwrap(),
            CoreDispatch::Reply(Response::Okay)
        ));
        assert!(enrollment.authentication().is_cancelled());
        assert_eq!(broker.abandon(&enrollment, NOW), Response::Failure);
    }

    #[test]
    fn root_cancellation_survives_owner_storage_failure_without_starting_work() {
        let mut broker = service();
        let CoreDispatch::Start(scheduled) = dispatch_connection(
            Ok(credentials(INTERACTIVE_USER)),
            valid_policy,
            packet_receive(AUTHENTICATE_REQUEST),
            &mut broker,
            NOW,
        )
        .unwrap() else {
            panic!("authenticated request must start")
        };

        assert!(matches!(
            dispatch_connection(
                Ok(credentials(ROOT_UID)),
                || Err(EnrollmentOwnerError::StorageUnavailable),
                packet_receive(CANCEL_REQUEST),
                &mut broker,
                NOW,
            )
            .unwrap(),
            CoreDispatch::Reply(Response::Okay)
        ));
        assert!(scheduled.authentication().is_cancelled());
        assert_eq!(broker.abandon(&scheduled, NOW), Response::Failure);

        for (packet, expected) in [
            (CANCEL_REQUEST.as_slice(), Response::Denied),
            (AUTHENTICATE_REQUEST.as_slice(), Response::Failure),
            (b"BADREQ!\n".as_slice(), Response::Denied),
        ] {
            let mut idle = service();
            assert!(matches!(
                dispatch_connection(
                    Ok(credentials(ROOT_UID)),
                    || Err(EnrollmentOwnerError::MissingOwner),
                    move |buffer| {
                        buffer[..packet.len()].copy_from_slice(packet);
                        Ok(packet.len())
                    },
                    &mut idle,
                    NOW,
                )
                .unwrap(),
                CoreDispatch::Reply(response) if response == expected
            ));
        }
    }

    #[test]
    fn exact_packets_share_busy_cancel_and_disconnect_authority() {
        let mut service = service();
        let CoreDispatch::Start(scheduled) = dispatch_connection(
            Ok(credentials(INTERACTIVE_USER)),
            valid_policy,
            packet_receive(AUTHENTICATE_REQUEST),
            &mut service,
            NOW,
        )
        .unwrap() else {
            panic!("authenticated request must start");
        };

        assert!(matches!(
            dispatch_connection(
                Ok(credentials(INTERACTIVE_USER)),
                valid_policy,
                packet_receive(AUTHENTICATE_REQUEST),
                &mut service,
                NOW,
            )
            .unwrap(),
            CoreDispatch::Reply(Response::Busy)
        ));
        assert!(matches!(
            dispatch_connection(
                Ok(credentials(0)),
                valid_policy,
                packet_receive(CANCEL_REQUEST),
                &mut service,
                NOW,
            )
            .unwrap(),
            CoreDispatch::Reply(Response::Okay)
        ));
        assert!(scheduled.authentication().is_cancelled());
        assert_eq!(
            observe_disconnect_result(Ok(true), &mut service, &scheduled),
            DisconnectObservation::CancellationDelivered
        );
        assert_eq!(service.abandon(&scheduled, NOW), Response::Failure);
        assert_eq!(
            observe_disconnect_result(Err(SeqPacketError::Receive), &mut service, &scheduled),
            DisconnectObservation::OperationInactive
        );
    }

    #[test]
    fn owned_active_session_routes_the_exact_deadline_and_retains_its_reply() {
        let mut service = service();
        let CoreDispatch::Start(scheduled) = dispatch_connection(
            Ok(credentials(INTERACTIVE_USER)),
            valid_policy,
            packet_receive(AUTHENTICATE_REQUEST),
            &mut service,
            NOW,
        )
        .unwrap() else {
            panic!("authenticated request must start")
        };
        let deadline = scheduled.deadline();
        assert_eq!(deadline, NOW + OPERATION_TIMEOUT);
        assert_eq!(
            service.decide(deadline, false),
            LifecycleDecision::Cancel(scheduled.lease())
        );

        let (socket, _peer) = UnixDatagram::pair().unwrap();
        let active = ActiveBrokerSocketSession {
            descriptor: OwnedFd::from(socket),
            scheduled,
        };
        assert_eq!(active.deadline(), deadline);
        assert!(active.deadline_expired(&mut service));
        assert!(active.authentication().is_cancelled());
        let reply = active.abandon(&mut service, deadline);
        assert_eq!(reply.response(), Response::Failure);
    }

    #[test]
    fn owned_active_session_retains_reply_while_feedback_finalizes_exact_work() {
        let mut service = service();
        let CoreDispatch::Start(scheduled) = dispatch_connection(
            Ok(credentials(INTERACTIVE_USER)),
            valid_policy,
            packet_receive(AUTHENTICATE_REQUEST),
            &mut service,
            NOW,
        )
        .unwrap() else {
            panic!("authenticated request must start")
        };
        let completion = AuthenticationCompletion::matched_for_test(scheduled.authentication());
        let (socket, _peer) = UnixDatagram::pair().unwrap();
        let active = ActiveBrokerSocketSession {
            descriptor: OwnedFd::from(socket),
            scheduled,
        };
        let mut feedback = FakeFeedback::default();

        let reply =
            active.finish_with_feedback(&mut service, &completion, Some(&mut feedback), NOW);

        assert_eq!(reply.response(), Response::Okay);
        assert_eq!(
            feedback.0,
            [
                FeedbackAction::ShowSuccess,
                FeedbackAction::PauseAfterSuccess
            ]
        );
        assert!(matches!(
            service.dispatch(
                local_peer(credentials(INTERACTIVE_USER)),
                policy(),
                AUTHENTICATE_REQUEST,
                NOW
            ),
            crate::auth_scheduler::ScheduledDispatch::Start(_)
        ));
    }

    #[test]
    fn bounded_receive_states_are_explicit_and_fail_closed() {
        for (receive, expected) in [
            (SeqPacketError::WouldBlock, "pending"),
            (SeqPacketError::Interrupted, "pending"),
            (SeqPacketError::PeerClosed, "closed"),
            (SeqPacketError::Truncated, "denied"),
        ] {
            let mut service = service();
            let dispatch = dispatch_connection(
                Ok(credentials(INTERACTIVE_USER)),
                valid_policy,
                |_| Err(receive),
                &mut service,
                NOW,
            )
            .unwrap();
            assert!(matches!(
                (dispatch, expected),
                (CoreDispatch::Pending, "pending")
                    | (CoreDispatch::Closed, "closed")
                    | (CoreDispatch::Reply(Response::Denied), "denied")
            ));
        }

        let mut service = service();
        assert!(matches!(
            dispatch_connection(
                Ok(credentials(INTERACTIVE_USER)),
                valid_policy,
                |_| Ok(REQUEST_CAPACITY + 1),
                &mut service,
                NOW,
            )
            .unwrap(),
            CoreDispatch::Reply(Response::Denied)
        ));
    }

    #[test]
    fn scheduler_termination_is_not_downgraded_to_a_wire_reply() {
        let mut service = BrokerServiceScheduler::new(Duration::MAX, IDLE_TIMEOUT).unwrap();
        assert!(matches!(
            dispatch_connection(
                Ok(credentials(INTERACTIVE_USER)),
                valid_policy,
                packet_receive(AUTHENTICATE_REQUEST),
                &mut service,
                Duration::MAX,
            )
            .unwrap(),
            CoreDispatch::Terminate
        ));
    }
}

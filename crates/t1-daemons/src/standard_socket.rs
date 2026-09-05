//! Root-only seqpacket transport for the standard fingerprint protocol.
//!
//! This adapter owns no listener path, scheduler, worker, or hardware policy.
//! It authenticates one accepted local peer before reading bytes, retains the
//! transport-free [`StandardConnection`] across packets, and bounds outbound
//! state to one protocol packet.

use core::fmt;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::time::Duration;

use t1_platform::seqpacket::{
    SeqPacketClient, SeqPacketError, SeqPacketListener, SystemdSeqPacketListener,
};

use crate::auth_protocol::{PeerAddressFamily, PeerMetadata};
use crate::auth_scheduler::BrokerServiceScheduler;
use crate::enrollment_owner::{EnrollmentOwnerError, EnrollmentOwnerStore};
use crate::standard_connection::{
    StandardConnection, StandardConnectionConfig, StandardConnectionDispatch,
    StandardConnectionError, StandardReply, StandardWorkerJob,
};
use crate::standard_fingerprint_protocol::{
    ConnectionAction, EnrollProgress, MAX_PACKET_SIZE, ServerMessage, TerminalOutcome,
    decode_client,
};

const ROOT_UID: u32 = 0;

/// Owned activated listener for the root-only standard endpoint.
pub struct ActivatedStandardSocketListener {
    listener: SystemdSeqPacketListener,
}

impl fmt::Debug for ActivatedStandardSocketListener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActivatedStandardSocketListener")
            .finish_non_exhaustive()
    }
}

impl ActivatedStandardSocketListener {
    #[must_use]
    pub const fn from_systemd_listener(listener: SystemdSeqPacketListener) -> Self {
        Self { listener }
    }

    /// Reports whether a standard client is queued.
    ///
    /// # Errors
    ///
    /// Returns a static socket error if readiness cannot be checked safely.
    pub fn is_ready(&self) -> Result<bool, StandardSocketError> {
        self.listener.is_ready().map_err(Into::into)
    }

    /// Accepts one queued UID-zero connection before reading protocol bytes.
    ///
    /// # Errors
    ///
    /// Returns a static socket or protocol-state error on failed acceptance.
    pub fn accept(
        &self,
        config: StandardConnectionConfig,
    ) -> Result<Option<StandardSocketConnection<OwnedFd>>, StandardSocketError> {
        StandardSocketListener::from_listener(self.listener.listener()).accept(config)
    }
}

/// Redaction-safe standard transport failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StandardSocketError {
    Socket(SeqPacketError),
    Connection,
    ReplyPending,
}

impl fmt::Display for StandardSocketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Socket(_) => "standard fingerprint socket failed",
            Self::Connection => "standard fingerprint connection state failed",
            Self::ReplyPending => "standard fingerprint reply is already pending",
        })
    }
}

impl std::error::Error for StandardSocketError {}

impl From<SeqPacketError> for StandardSocketError {
    fn from(error: SeqPacketError) -> Self {
        Self::Socket(error)
    }
}

impl From<StandardConnectionError> for StandardSocketError {
    fn from(_: StandardConnectionError) -> Self {
        Self::Connection
    }
}

/// One nonblocking receive/dispatch event.
pub enum StandardSocketEvent {
    Pending,
    Closed,
    ReplyQueued,
    Start(StandardWorkerJob),
    CancellationPending,
    Terminate,
}

impl fmt::Debug for StandardSocketEvent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => formatter.write_str("Pending"),
            Self::Closed => formatter.write_str("Closed"),
            Self::ReplyQueued => formatter.write_str("ReplyQueued"),
            Self::Start(_) => formatter.write_str("Start(<redacted>)"),
            Self::CancellationPending => formatter.write_str("CancellationPending"),
            Self::Terminate => formatter.write_str("Terminate"),
        }
    }
}

/// Borrowed standard listener. Unauthorized peers are dropped before receive.
#[derive(Clone, Copy, Debug)]
pub struct StandardSocketListener<'fd> {
    listener: SeqPacketListener<'fd>,
}

impl<'fd> StandardSocketListener<'fd> {
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

    /// Accepts one root peer and constructs its protocol state.
    ///
    /// `Ok(None)` means kernel credentials rejected the peer before any packet
    /// was read. The root-only filesystem mode remains an independent gate.
    ///
    /// # Errors
    ///
    /// Returns a static socket or protocol-state error on failed acceptance.
    pub fn accept(
        self,
        config: StandardConnectionConfig,
    ) -> Result<Option<StandardSocketConnection<OwnedFd>>, StandardSocketError> {
        let descriptor = self.listener.accept()?;
        let credentials = match SeqPacketClient::new(descriptor.as_fd()).peer_credentials() {
            Ok(credentials) if credentials.user_id == ROOT_UID => credentials,
            Ok(_) | Err(SeqPacketError::Credentials) => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let peer = PeerMetadata {
            address_family: PeerAddressFamily::Local,
            user_id: credentials.user_id,
            group_id: credentials.group_id,
        };
        let connection = StandardConnection::new(peer, config)?;
        Ok(Some(StandardSocketConnection {
            descriptor,
            connection,
            outbound: None,
        }))
    }
}

/// One persistent standard protocol connection with one bounded outbound slot.
pub struct StandardSocketConnection<D> {
    descriptor: D,
    connection: StandardConnection,
    outbound: Option<StandardReply>,
}

impl<D> fmt::Debug for StandardSocketConnection<D> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StandardSocketConnection")
            .field("connection", &self.connection)
            .field("outbound", &self.outbound.is_some())
            .finish_non_exhaustive()
    }
}

impl<D: AsFd> StandardSocketConnection<D> {
    #[cfg(all(test, feature = "auth-broker-service"))]
    pub(crate) const fn for_test(descriptor: D, connection: StandardConnection) -> Self {
        Self {
            descriptor,
            connection,
            outbound: None,
        }
    }

    /// Receives and dispatches one complete bounded packet.
    ///
    /// # Errors
    ///
    /// Returns a static error for permanent transport or connection failure.
    pub fn receive_and_dispatch(
        &mut self,
        service: &mut BrokerServiceScheduler,
        owner_store: &EnrollmentOwnerStore,
        now: Duration,
    ) -> Result<StandardSocketEvent, StandardSocketError> {
        if self.outbound.is_some() {
            return Ok(StandardSocketEvent::Pending);
        }

        let socket = SeqPacketClient::new(self.descriptor.as_fd());
        let mut packet = [0_u8; MAX_PACKET_SIZE];
        let received = match socket.receive(&mut packet) {
            Ok(received) => received,
            Err(SeqPacketError::WouldBlock | SeqPacketError::Interrupted) => {
                return Ok(StandardSocketEvent::Pending);
            }
            Err(SeqPacketError::PeerClosed) => return Ok(StandardSocketEvent::Closed),
            Err(SeqPacketError::Truncated) => {
                self.queue(StandardReply::new(ServerMessage::Terminal(
                    TerminalOutcome::Error,
                )))?;
                return Ok(StandardSocketEvent::ReplyQueued);
            }
            Err(error) => return Err(error.into()),
        };

        let packet = &packet[..received];
        let owner = match decode_client(packet).map(|message| message.connection_action()) {
            Ok(ConnectionAction::Start(_)) => match owner_store.access_policy() {
                Ok(owner) => Some(owner),
                Err(EnrollmentOwnerError::MissingOwner) => None,
                Err(_) => {
                    self.queue(StandardReply::new(ServerMessage::Terminal(
                        TerminalOutcome::Error,
                    )))?;
                    return Ok(StandardSocketEvent::ReplyQueued);
                }
            },
            Ok(
                ConnectionAction::QueryCapabilities
                | ConnectionAction::Open
                | ConnectionAction::CancelActive,
            )
            | Err(_) => None,
        };

        Ok(
            match self.connection.dispatch_packet(service, owner, packet, now) {
                StandardConnectionDispatch::Reply(reply) => {
                    self.queue(reply)?;
                    StandardSocketEvent::ReplyQueued
                }
                StandardConnectionDispatch::Start(worker) => StandardSocketEvent::Start(worker),
                StandardConnectionDispatch::CancellationPending => {
                    StandardSocketEvent::CancellationPending
                }
                StandardConnectionDispatch::Terminate => StandardSocketEvent::Terminate,
            },
        )
    }

    /// Queues validated enrollment progress for the exact active worker.
    ///
    /// # Errors
    ///
    /// Returns a static error for a foreign worker or occupied outbound slot.
    pub fn queue_worker_progress(
        &mut self,
        worker: &StandardWorkerJob,
        progress: EnrollProgress,
    ) -> Result<(), StandardSocketError> {
        let reply = self.connection.worker_progress(worker, progress)?;
        self.queue(reply)
    }

    /// Finalizes the exact active worker and queues its terminal response.
    ///
    /// # Errors
    ///
    /// Returns a static error for foreign completion or occupied outbound slot.
    pub fn finish_worker(
        &mut self,
        service: &mut BrokerServiceScheduler,
        completion: &crate::auth_session::StandardCompletion,
        now: Duration,
    ) -> Result<StandardSocketEvent, StandardSocketError> {
        Ok(
            match self.connection.finish_worker(service, completion, now) {
                StandardConnectionDispatch::Reply(reply) => {
                    self.queue(reply)?;
                    StandardSocketEvent::ReplyQueued
                }
                StandardConnectionDispatch::Terminate => StandardSocketEvent::Terminate,
                StandardConnectionDispatch::Start(_)
                | StandardConnectionDispatch::CancellationPending => {
                    return Err(StandardSocketError::Connection);
                }
            },
        )
    }

    /// Attempts the one queued packet send. Returns true once the slot is free.
    ///
    /// # Errors
    ///
    /// Returns a static error for permanent transport failure.
    pub fn flush_reply(&mut self) -> Result<bool, StandardSocketError> {
        let Some(reply) = self.outbound.take() else {
            return Ok(true);
        };
        match SeqPacketClient::new(self.descriptor.as_fd()).send(reply.packet()) {
            Ok(()) => Ok(true),
            Err(SeqPacketError::WouldBlock | SeqPacketError::Interrupted) => {
                self.outbound = Some(reply);
                Ok(false)
            }
            Err(error) => Err(error.into()),
        }
    }

    #[must_use]
    pub const fn has_pending_reply(&self) -> bool {
        self.outbound.is_some()
    }

    /// Observes peer closure without consuming protocol bytes.
    ///
    /// # Errors
    ///
    /// Returns a static error if the connected descriptor cannot be probed.
    pub fn peer_closed(&self) -> Result<bool, StandardSocketError> {
        SeqPacketClient::new(self.descriptor.as_fd())
            .peer_closed()
            .map_err(Into::into)
    }

    pub fn client_disconnected(&self, service: &mut BrokerServiceScheduler) -> bool {
        self.connection.client_disconnected(service)
    }

    pub fn deadline_expired(&self, service: &mut BrokerServiceScheduler) -> bool {
        self.connection.deadline_expired(service)
    }

    #[cfg(feature = "auth-broker-service")]
    pub(crate) fn is_active_in(&self, service: &BrokerServiceScheduler) -> bool {
        self.connection.is_active_in(service)
    }

    #[cfg(feature = "auth-broker-service")]
    pub(crate) fn discard_reply(&mut self) {
        self.outbound = None;
    }

    #[must_use]
    pub fn worker_lost(&mut self, service: &mut BrokerServiceScheduler) -> StandardSocketEvent {
        let _ = self.connection.worker_lost(service);
        StandardSocketEvent::Terminate
    }

    fn queue(&mut self, reply: StandardReply) -> Result<(), StandardSocketError> {
        if self.outbound.replace(reply).is_some() {
            return Err(StandardSocketError::ReplyPending);
        }
        Ok(())
    }
}

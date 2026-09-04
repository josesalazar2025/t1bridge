//! Live, device-scoped `BridgeXPC` operation adapters.
//!
//! Device discovery and validation remain with the privileged caller. This
//! module accepts only its nonzero kernel interface index, connects to the
//! fixed private-link protocol endpoint, bounds all socket I/O, negotiates the
//! existing `BridgeXPC` session, and safely shares that one session between
//! command and callback workflow handles.

use crate::control::{
    BiometricTransport, BridgeCommandError, RequestIdSource, SessionBiometricTransport,
};
use crate::enroll_workflow::{EnrollmentEvent, EnrollmentEventSource};
use crate::match_workflow::{MatchEvent, MatchEventSource};
use crate::policy_workflow::UserPolicyRetryRuntime;
use crate::rpc::RpcError;
use crate::session::{BridgeXpcSession, SessionError};
use core::cell::{BorrowMutError, RefCell};
use core::convert::Infallible;
use core::fmt;
use core::num::NonZeroU32;
use core::time::Duration;
use std::io::{self, Read, Write};
use std::net::{Ipv6Addr, Shutdown, SocketAddr, SocketAddrV6, TcpStream};
use std::rc::Rc;
use std::time::Instant;

const BRIDGEOS_PEER: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0xaede, 0x48ff, 0xfe33, 0x4455);
const BIOMETRIC_SERVICE_PORT: u16 = 52_032;
const PROCESS_NAME: &str = "t1-touchid";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const SOCKET_IO_TIMEOUT: Duration = Duration::from_secs(30);
const CALLBACK_POLL_INTERVAL: Duration = Duration::from_millis(100);
const MAX_OPERATION_TIMEOUT: Duration = Duration::from_secs(10 * 60);

/// A redaction-safe live connection or negotiation failure.
pub enum LiveConnectionError {
    Socket,
    TimeoutConfiguration,
    Session,
    DescriptorDuplication,
    ClientVersion,
}

impl fmt::Debug for LiveConnectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Socket => formatter.write_str("Socket([redacted])"),
            Self::TimeoutConfiguration => formatter.write_str("TimeoutConfiguration([redacted])"),
            Self::Session => formatter.write_str("Session([redacted])"),
            Self::DescriptorDuplication => formatter.write_str("DescriptorDuplication([redacted])"),
            Self::ClientVersion => formatter.write_str("ClientVersion([redacted])"),
        }
    }
}

impl fmt::Display for LiveConnectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Socket => "BridgeXPC connection failed",
            Self::TimeoutConfiguration => "BridgeXPC timeout configuration failed",
            Self::Session => "BridgeXPC session negotiation failed",
            Self::DescriptorDuplication => "BridgeXPC readiness handle could not be created",
            Self::ClientVersion => "BridgeXPC biometric client setup failed",
        })
    }
}

impl std::error::Error for LiveConnectionError {}

/// One negotiated connection to the fixed `BridgeOS` biometric service.
pub struct LiveBridgeConnection {
    session: BridgeXpcSession<TcpStream>,
    readiness: TcpStream,
}

/// A redacted handle that interrupts blocking I/O on one live connection.
pub struct LiveBridgeInterrupt {
    stream: TcpStream,
}

impl fmt::Debug for LiveBridgeInterrupt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("LiveBridgeInterrupt([redacted])")
    }
}

impl LiveBridgeInterrupt {
    /// Wakes any blocking read or write on every clone of this socket.
    pub fn interrupt(&self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

/// An owned `BridgeXPC` connection whose client version and FDR preparation
/// completed before native SEP/session acquisition.
pub struct PreparedLiveBridgeConnection {
    session: BridgeXpcSession<TcpStream>,
    readiness: TcpStream,
}

/// Failure while converting a live connection into prepared owned state.
pub enum LiveClientPreparationError<E> {
    Connection(LiveConnectionError),
    Preparation(E),
}

impl<E> fmt::Debug for LiveClientPreparationError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connection(error) => formatter.debug_tuple("Connection").field(error).finish(),
            Self::Preparation(_) => formatter.write_str("Preparation([redacted])"),
        }
    }
}

impl<E> fmt::Display for LiveClientPreparationError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Connection(_) => "BridgeXPC client-version preparation failed",
            Self::Preparation(_) => "BridgeXPC biometric preparation failed",
        })
    }
}

impl<E> std::error::Error for LiveClientPreparationError<E> {}

impl LiveBridgeConnection {
    /// Connects through one already-validated T1 interface index.
    ///
    /// The endpoint is a fixed private-link protocol constant. Socket and
    /// diagnostics never accept or expose an interface name or address.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe failure when connection, timeout setup,
    /// descriptor duplication, or HELLO negotiation fails.
    pub fn connect(interface_index: NonZeroU32) -> Result<Self, LiveConnectionError> {
        let endpoint = bridge_peer_address(interface_index);
        let stream = TcpStream::connect_timeout(&endpoint, CONNECT_TIMEOUT)
            .map_err(|_| LiveConnectionError::Socket)?;
        stream
            .set_read_timeout(Some(SOCKET_IO_TIMEOUT))
            .map_err(|_| LiveConnectionError::TimeoutConfiguration)?;
        stream
            .set_write_timeout(Some(SOCKET_IO_TIMEOUT))
            .map_err(|_| LiveConnectionError::TimeoutConfiguration)?;
        let readiness = stream
            .try_clone()
            .map_err(|_| LiveConnectionError::DescriptorDuplication)?;
        let session = BridgeXpcSession::connect(stream, PROCESS_NAME)
            .map_err(|_| LiveConnectionError::Session)?;
        Ok(Self { session, readiness })
    }

    /// Returns a handle that can wake blocking connection I/O from another thread.
    ///
    /// # Errors
    ///
    /// Returns a redacted failure when the socket handle cannot be duplicated.
    pub fn interrupt_handle(&self) -> Result<LiveBridgeInterrupt, LiveConnectionError> {
        self.readiness
            .try_clone()
            .map(|stream| LiveBridgeInterrupt { stream })
            .map_err(|_| LiveConnectionError::DescriptorDuplication)
    }

    /// Selects biometric client version two and borrows this connection for
    /// one command/callback operation.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe failure if the readiness descriptor cannot be
    /// duplicated or exact client-version selection fails.
    pub fn start_operation<I: RequestIdSource>(
        &mut self,
        request_ids: I,
    ) -> Result<LiveBridgeOperation<'_, TcpStream, I, TcpCallbackReadiness>, LiveConnectionError>
    {
        let readiness = self
            .readiness
            .try_clone()
            .map(TcpCallbackReadiness::new)
            .map_err(|_| LiveConnectionError::DescriptorDuplication)?;
        let mut transport = SessionBiometricTransport::new(&mut self.session, request_ids);
        initialize_biometric_client(&mut transport)?;
        Ok(LiveBridgeOperation::new(transport, readiness))
    }

    /// Selects the client version, runs caller preparation on that same
    /// `BridgeXPC` session, and returns owned prepared state.
    ///
    /// The preparation closure is the exact under-lock, pre-SEP boundary used
    /// for FDR loading. The returned type can start an operation without
    /// repeating client-version selection.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe connection error or the caller's preparation
    /// failure without retaining the connection.
    pub fn prepare<I, E>(
        mut self,
        request_ids: I,
        prepare: impl FnOnce(&mut SessionBiometricTransport<'_, TcpStream, I>) -> Result<(), E>,
    ) -> Result<PreparedLiveBridgeConnection, LiveClientPreparationError<E>>
    where
        I: RequestIdSource,
    {
        let mut transport = SessionBiometricTransport::new(&mut self.session, request_ids);
        initialize_biometric_client(&mut transport)
            .map_err(LiveClientPreparationError::Connection)?;
        prepare(&mut transport).map_err(LiveClientPreparationError::Preparation)?;
        drop(transport);
        Ok(PreparedLiveBridgeConnection {
            session: self.session,
            readiness: self.readiness,
        })
    }
}

impl PreparedLiveBridgeConnection {
    /// Borrows the prepared session for one command/callback operation without
    /// issuing another client-version RPC.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe failure if the readiness descriptor cannot be
    /// duplicated.
    pub fn start_operation<I: RequestIdSource>(
        &mut self,
        request_ids: I,
    ) -> Result<LiveBridgeOperation<'_, TcpStream, I, TcpCallbackReadiness>, LiveConnectionError>
    {
        let readiness = self
            .readiness
            .try_clone()
            .map(TcpCallbackReadiness::new)
            .map_err(|_| LiveConnectionError::DescriptorDuplication)?;
        Ok(prepared_operation(
            &mut self.session,
            request_ids,
            readiness,
        ))
    }
}

fn initialize_biometric_client<S, I>(
    transport: &mut SessionBiometricTransport<'_, S, I>,
) -> Result<(), LiveConnectionError>
where
    S: Read + Write,
    I: RequestIdSource,
{
    transport
        .select_client_version()
        .map_err(|_| LiveConnectionError::ClientVersion)
}

fn prepared_operation<S, I, R>(
    session: &mut BridgeXpcSession<S>,
    request_ids: I,
    readiness: R,
) -> LiveBridgeOperation<'_, S, I, R>
where
    S: Read + Write,
    I: RequestIdSource,
{
    LiveBridgeOperation::new(
        SessionBiometricTransport::new_prepared(session, request_ids),
        readiness,
    )
}

fn bridge_peer_address(interface_index: NonZeroU32) -> SocketAddr {
    SocketAddr::V6(SocketAddrV6::new(
        BRIDGEOS_PEER,
        BIOMETRIC_SERVICE_PORT,
        0,
        interface_index.get(),
    ))
}

/// Error returned by the command half of a live operation.
pub enum LiveBiometricError {
    SessionBusy,
    Command(BridgeCommandError),
}

impl fmt::Debug for LiveBiometricError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SessionBusy => formatter.write_str("SessionBusy"),
            Self::Command(_) => formatter.write_str("Command([redacted])"),
        }
    }
}

impl fmt::Display for LiveBiometricError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SessionBusy => "BridgeXPC session is already in use",
            Self::Command(_) => "BridgeXPC biometric command failed",
        })
    }
}

impl std::error::Error for LiveBiometricError {}

type SharedTransport<'a, S, I> = Rc<RefCell<SessionBiometricTransport<'a, S, I>>>;

/// Command handle sharing one negotiated session with its callback source.
pub struct LiveBiometricTransport<'a, S, I> {
    transport: SharedTransport<'a, S, I>,
}

impl<S, I> BiometricTransport for LiveBiometricTransport<'_, S, I>
where
    S: Read + Write,
    I: RequestIdSource,
{
    type Error = LiveBiometricError;

    fn execute(&mut self, packet: &crate::commands::CommandPacket) -> Result<Vec<u8>, Self::Error> {
        self.transport
            .try_borrow_mut()
            .map_err(|_: BorrowMutError| LiveBiometricError::SessionBusy)?
            .execute(packet)
            .map_err(LiveBiometricError::Command)
    }
}

/// Waits for callback stream readiness without consuming protocol bytes.
pub trait CallbackReadiness {
    type Error;

    /// Returns true once the stream is readable, including orderly closure.
    ///
    /// # Errors
    ///
    /// Returns an implementation-defined readiness failure.
    fn wait_readable(&mut self, timeout: Duration) -> Result<bool, Self::Error>;

    /// Bounds the subsequent complete frame read to the remaining deadline.
    ///
    /// # Errors
    ///
    /// Returns an implementation-defined timeout-configuration failure.
    fn set_read_timeout(&mut self, timeout: Duration) -> Result<(), Self::Error>;
}

/// Redaction-safe TCP readiness failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TcpReadinessError;

impl fmt::Display for TcpReadinessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BridgeXPC callback readiness failed")
    }
}

impl std::error::Error for TcpReadinessError {}

/// Non-consuming readiness owner for one duplicated TCP descriptor.
pub struct TcpCallbackReadiness {
    stream: TcpStream,
}

impl TcpCallbackReadiness {
    const fn new(stream: TcpStream) -> Self {
        Self { stream }
    }
}

impl CallbackReadiness for TcpCallbackReadiness {
    type Error = TcpReadinessError;

    fn wait_readable(&mut self, timeout: Duration) -> Result<bool, Self::Error> {
        self.stream
            .set_read_timeout(Some(timeout))
            .map_err(|_| TcpReadinessError)?;
        let mut byte = [0_u8; 1];
        match self.stream.peek(&mut byte) {
            Ok(_) => Ok(true),
            Err(error) if is_timeout(&error) => Ok(false),
            Err(_) => Err(TcpReadinessError),
        }
    }

    fn set_read_timeout(&mut self, timeout: Duration) -> Result<(), Self::Error> {
        self.stream
            .set_read_timeout(Some(timeout))
            .map_err(|_| TcpReadinessError)
    }
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// Monotonic time source used for operation deadlines.
pub trait MonotonicClock {
    fn now(&self) -> Duration;
}

/// Process-local monotonic clock backed by [`Instant`].
pub struct ProcessMonotonicClock {
    origin: Instant,
}

impl ProcessMonotonicClock {
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for ProcessMonotonicClock {
    fn default() -> Self {
        Self::new()
    }
}

impl MonotonicClock for ProcessMonotonicClock {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }
}

/// Invalid caller-owned operation timeout.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationDeadlineError {
    Zero,
    TooLong,
}

impl fmt::Display for OperationDeadlineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Zero => "BridgeXPC operation timeout is zero",
            Self::TooLong => "BridgeXPC operation timeout exceeds its bound",
        })
    }
}

impl std::error::Error for OperationDeadlineError {}

/// One version-selected operation before command/event handles are split.
pub struct LiveBridgeOperation<'a, S, I, R> {
    transport: SharedTransport<'a, S, I>,
    readiness: R,
}

/// Production command and callback handles for one live operation.
pub type OperationAdapters<'a, S, I, R, C> = (
    LiveBiometricTransport<'a, S, I>,
    CallbackEventSource<'a, S, I, R, ProcessMonotonicClock, C>,
);

/// Command and callback handles using an injected monotonic clock.
pub type OperationAdaptersWithClock<'a, S, I, R, K, C> = (
    LiveBiometricTransport<'a, S, I>,
    CallbackEventSource<'a, S, I, R, K, C>,
);

impl<'a, S, I, R> LiveBridgeOperation<'a, S, I, R> {
    fn new(transport: SessionBiometricTransport<'a, S, I>, readiness: R) -> Self {
        Self {
            transport: Rc::new(RefCell::new(transport)),
            readiness,
        }
    }

    /// Splits one session into sequential command and callback handles.
    ///
    /// Cancellation is checked before queued callbacks, before each readiness
    /// wait, and after each complete callback frame. Enrollment maps the same
    /// terminal cancellation decision to its existing clean timeout/cancel
    /// outcome because its event contract has no distinct cancelled variant.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero or excessive timeout.
    pub fn into_adapters<C>(
        self,
        timeout: Duration,
        cancelled: C,
    ) -> Result<OperationAdapters<'a, S, I, R, C>, OperationDeadlineError>
    where
        C: FnMut() -> bool,
    {
        self.into_adapters_with_clock(timeout, ProcessMonotonicClock::new(), cancelled)
    }

    /// Testable form of [`Self::into_adapters`] with a caller-owned monotonic clock.
    ///
    /// # Errors
    ///
    /// Returns an error for a zero or excessive timeout.
    pub fn into_adapters_with_clock<K, C>(
        self,
        timeout: Duration,
        clock: K,
        cancelled: C,
    ) -> Result<OperationAdaptersWithClock<'a, S, I, R, K, C>, OperationDeadlineError>
    where
        K: MonotonicClock,
        C: FnMut() -> bool,
    {
        if timeout.is_zero() {
            return Err(OperationDeadlineError::Zero);
        }
        if timeout > MAX_OPERATION_TIMEOUT {
            return Err(OperationDeadlineError::TooLong);
        }
        Ok((
            LiveBiometricTransport {
                transport: Rc::clone(&self.transport),
            },
            CallbackEventSource {
                transport: self.transport,
                readiness: self.readiness,
                clock,
                timeout,
                deadline: None,
                cancelled,
            },
        ))
    }
}

/// Callback-delivery error that never exposes network or callback contents.
pub enum CallbackEventError {
    SessionBusy,
    Readiness,
    Session,
    DeadlineOverflow,
}

impl fmt::Debug for CallbackEventError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SessionBusy => formatter.write_str("SessionBusy"),
            Self::Readiness => formatter.write_str("Readiness([redacted])"),
            Self::Session => formatter.write_str("Session([redacted])"),
            Self::DeadlineOverflow => formatter.write_str("DeadlineOverflow"),
        }
    }
}

impl fmt::Display for CallbackEventError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::SessionBusy => "BridgeXPC session is already in use",
            Self::Readiness => "BridgeXPC callback readiness failed",
            Self::Session => "BridgeXPC callback delivery failed",
            Self::DeadlineOverflow => "BridgeXPC operation deadline overflowed",
        })
    }
}

impl std::error::Error for CallbackEventError {}

enum CallbackDecision {
    Callback(crate::mesa::ServiceStatusEvent),
    Cancelled,
    TimedOut,
}

/// One callback source shared by the existing match and enrollment workflows.
pub struct CallbackEventSource<'a, S, I, R, K, C> {
    transport: SharedTransport<'a, S, I>,
    readiness: R,
    clock: K,
    timeout: Duration,
    deadline: Option<Duration>,
    cancelled: C,
}

impl<S, I, R, K, C> CallbackEventSource<'_, S, I, R, K, C>
where
    S: Read + Write,
    I: RequestIdSource,
    R: CallbackReadiness,
    K: MonotonicClock,
    C: FnMut() -> bool,
{
    fn complete_decision(
        &mut self,
        decision: CallbackDecision,
    ) -> Result<CallbackDecision, CallbackEventError> {
        self.readiness
            .set_read_timeout(SOCKET_IO_TIMEOUT)
            .map_err(|_| CallbackEventError::Readiness)?;
        Ok(decision)
    }

    fn next_decision(&mut self) -> Result<CallbackDecision, CallbackEventError> {
        let deadline = if let Some(deadline) = self.deadline {
            deadline
        } else {
            let deadline = self
                .clock
                .now()
                .checked_add(self.timeout)
                .ok_or(CallbackEventError::DeadlineOverflow)?;
            self.deadline = Some(deadline);
            deadline
        };
        loop {
            if (self.cancelled)() {
                return self.complete_decision(CallbackDecision::Cancelled);
            }
            let queued_event = {
                let mut transport = self
                    .transport
                    .try_borrow_mut()
                    .map_err(|_: BorrowMutError| CallbackEventError::SessionBusy)?;
                transport.take_service_event()
            };
            if let Some(event) = queued_event {
                return self.complete_decision(CallbackDecision::Callback(event));
            }

            let now = self.clock.now();
            if now >= deadline {
                return self.complete_decision(CallbackDecision::TimedOut);
            }
            let Some(remaining) = deadline.checked_sub(now) else {
                return self.complete_decision(CallbackDecision::TimedOut);
            };
            let wait = remaining.min(CALLBACK_POLL_INTERVAL);
            if !self
                .readiness
                .wait_readable(wait)
                .map_err(|_| CallbackEventError::Readiness)?
            {
                continue;
            }
            self.readiness
                .set_read_timeout(remaining.min(SOCKET_IO_TIMEOUT))
                .map_err(|_| CallbackEventError::Readiness)?;
            let event = self
                .transport
                .try_borrow_mut()
                .map_err(|_: BorrowMutError| CallbackEventError::SessionBusy)?
                .service_inbound_request()
                .map_err(|_| CallbackEventError::Session)?;
            if (self.cancelled)() {
                return self.complete_decision(CallbackDecision::Cancelled);
            }
            if let Some(event) = event {
                return self.complete_decision(CallbackDecision::Callback(event));
            }
        }
    }
}

impl<S, I, R, K, C> MatchEventSource for CallbackEventSource<'_, S, I, R, K, C>
where
    S: Read + Write,
    I: RequestIdSource,
    R: CallbackReadiness,
    K: MonotonicClock,
    C: FnMut() -> bool,
{
    type Error = CallbackEventError;

    fn next_event(&mut self) -> Result<MatchEvent, Self::Error> {
        self.next_decision().map(|decision| match decision {
            CallbackDecision::Callback(event) => MatchEvent::Callback(event),
            CallbackDecision::Cancelled => MatchEvent::Cancelled,
            CallbackDecision::TimedOut => MatchEvent::TimedOut,
        })
    }
}

impl<S, I, R, K, C> EnrollmentEventSource for CallbackEventSource<'_, S, I, R, K, C>
where
    S: Read + Write,
    I: RequestIdSource,
    R: CallbackReadiness,
    K: MonotonicClock,
    C: FnMut() -> bool,
{
    type Error = CallbackEventError;

    fn next_event(&mut self) -> Result<EnrollmentEvent, Self::Error> {
        self.next_decision().map(|decision| match decision {
            CallbackDecision::Callback(event) => EnrollmentEvent::ServiceStatus(event),
            CallbackDecision::Cancelled | CallbackDecision::TimedOut => EnrollmentEvent::TimedOut,
        })
    }
}

/// Extracts only the signed native biometric status used by policy retry.
#[must_use]
pub const fn bridge_command_native_status(error: &BridgeCommandError) -> Option<i64> {
    match error {
        BridgeCommandError::Rpc(RpcError::BiometricCommandFailed { status, .. })
        | BridgeCommandError::Session(SessionError::Rpc(RpcError::BiometricCommandFailed {
            status,
            ..
        })) => Some(*status),
        _ => None,
    }
}

/// Extracts a native status through the live command-handle wrapper.
#[must_use]
pub const fn live_biometric_native_status(error: &LiveBiometricError) -> Option<i64> {
    match error {
        LiveBiometricError::Command(error) => bridge_command_native_status(error),
        LiveBiometricError::SessionBusy => None,
    }
}

/// Caller-owned monotonic retry wait seam.
pub trait MonotonicWait {
    type Error;

    /// Waits for at least `delay` on a monotonic clock.
    ///
    /// # Errors
    ///
    /// Returns an implementation-defined wait failure.
    fn wait(&mut self, delay: Duration) -> Result<(), Self::Error>;
}

/// Production wait using an [`Instant`]-measured sleep loop.
#[derive(Default)]
pub struct ThreadMonotonicWait;

impl MonotonicWait for ThreadMonotonicWait {
    type Error = Infallible;

    fn wait(&mut self, delay: Duration) -> Result<(), Self::Error> {
        let started = Instant::now();
        while let Some(remaining) = delay.checked_sub(started.elapsed()) {
            if remaining.is_zero() {
                break;
            }
            std::thread::sleep(remaining);
        }
        Ok(())
    }
}

/// Native-status classifier and monotonic waiter for policy workflows.
pub struct LivePolicyRetryRuntime<W = ThreadMonotonicWait> {
    waiter: W,
}

impl LivePolicyRetryRuntime {
    #[must_use]
    pub fn new() -> Self {
        Self {
            waiter: ThreadMonotonicWait,
        }
    }
}

impl Default for LivePolicyRetryRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl<W> LivePolicyRetryRuntime<W> {
    #[must_use]
    pub const fn with_waiter(waiter: W) -> Self {
        Self { waiter }
    }

    #[must_use]
    pub fn into_waiter(self) -> W {
        self.waiter
    }
}

impl<W: MonotonicWait> UserPolicyRetryRuntime<BridgeCommandError> for LivePolicyRetryRuntime<W> {
    type WaitError = W::Error;

    fn native_status(&self, error: &BridgeCommandError) -> Option<i64> {
        bridge_command_native_status(error)
    }

    fn wait(&mut self, delay: Duration) -> Result<(), Self::WaitError> {
        self.waiter.wait(delay)
    }
}

impl<W: MonotonicWait> UserPolicyRetryRuntime<LiveBiometricError> for LivePolicyRetryRuntime<W> {
    type WaitError = W::Error;

    fn native_status(&self, error: &LiveBiometricError) -> Option<i64> {
        live_biometric_native_status(error)
    }

    fn wait(&mut self, delay: Duration) -> Result<(), Self::WaitError> {
        self.waiter.wait(delay)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bplist::Value;
    use crate::commands::calibration_status_command;
    use crate::framing::{FRAME_BINARY_PLIST, FRAME_HELLO, Frame};
    use crate::rpc::{
        RequestId, RpcEnvelope, decode_envelope, encode_reply, encode_request,
        perform_biometric_command_request, set_client_version_request,
    };
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::io::Cursor;
    use std::net::TcpListener;

    #[test]
    fn interrupt_handle_wakes_blocking_socket_io() {
        let listener = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let interrupt = LiveBridgeInterrupt {
            stream: client.try_clone().unwrap(),
        };

        interrupt.interrupt();

        let mut byte = [0_u8; 1];
        assert_eq!(server.read(&mut byte).unwrap(), 0);
    }

    const REQUEST_ID_BYTES: [u8; 16] = [0x41; 16];

    struct MemoryStream {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl MemoryStream {
        fn new(frames: &[Frame]) -> Self {
            let mut input = Vec::new();
            for frame in frames {
                input.extend_from_slice(&frame.encode().unwrap());
            }
            Self {
                input: Cursor::new(input),
                output: Vec::new(),
            }
        }
    }

    impl Read for MemoryStream {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.input.read(buffer)
        }
    }

    impl Write for MemoryStream {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.output.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[derive(Clone)]
    struct FakeClock(Rc<Cell<Duration>>);

    impl FakeClock {
        fn new(now: Duration) -> Self {
            Self(Rc::new(Cell::new(now)))
        }

        fn advance(&self, amount: Duration) {
            self.0.set(self.0.get() + amount);
        }
    }

    impl MonotonicClock for FakeClock {
        fn now(&self) -> Duration {
            self.0.get()
        }
    }

    struct ScriptedReadiness {
        readable: VecDeque<bool>,
        clock: Option<FakeClock>,
        waits: Rc<Cell<usize>>,
        configured: Vec<Duration>,
    }

    impl ScriptedReadiness {
        fn never(clock: FakeClock) -> Self {
            Self {
                readable: VecDeque::new(),
                clock: Some(clock),
                waits: Rc::new(Cell::new(0)),
                configured: Vec::new(),
            }
        }

        fn readable() -> Self {
            Self {
                readable: VecDeque::from([true]),
                clock: None,
                waits: Rc::new(Cell::new(0)),
                configured: Vec::new(),
            }
        }
    }

    impl CallbackReadiness for ScriptedReadiness {
        type Error = Infallible;

        fn wait_readable(&mut self, timeout: Duration) -> Result<bool, Self::Error> {
            self.waits.set(self.waits.get() + 1);
            if let Some(clock) = &self.clock {
                clock.advance(timeout);
            }
            Ok(self.readable.pop_front().unwrap_or(false))
        }

        fn set_read_timeout(&mut self, timeout: Duration) -> Result<(), Self::Error> {
            self.configured.push(timeout);
            Ok(())
        }
    }

    fn hello() -> Frame {
        Frame::new(
            FRAME_HELLO,
            br#"{"MaxSupportedProtocolVersion":1}"#.to_vec(),
        )
        .unwrap()
    }

    fn plist_frame(body: Vec<u8>) -> Frame {
        Frame::new(FRAME_BINARY_PLIST, body).unwrap()
    }

    fn callback(id: &RequestId) -> Frame {
        plist_frame(
            encode_request(
                id,
                &[
                    Value::Integer(9),
                    Value::Integer(0xe3ff_8000),
                    Value::Data(vec![0x10, 0x20]),
                    Value::Integer(12),
                    Value::Integer(34),
                ],
            )
            .unwrap(),
        )
    }

    fn decode_frames(mut encoded: &[u8]) -> Vec<Frame> {
        let mut frames = Vec::new();
        while !encoded.is_empty() {
            let (frame, remainder) = Frame::decode_prefix(encoded).unwrap();
            frames.push(frame);
            encoded = remainder;
        }
        frames
    }

    #[test]
    fn operation_setup_only_selects_client_version() {
        let version_id = RequestId::from_uuid_v4_bytes([0x31; 16]);
        let version_reply = plist_frame(
            encode_reply(&version_id, &[Value::Integer(0), Value::Boolean(true)]).unwrap(),
        );
        let mut session =
            BridgeXpcSession::connect(MemoryStream::new(&[hello(), version_reply]), PROCESS_NAME)
                .unwrap();
        let mut transport =
            SessionBiometricTransport::new(&mut session, [version_id.clone()].into_iter());

        initialize_biometric_client(&mut transport).unwrap();
        drop(transport);

        let frames = decode_frames(&session.into_inner().output);
        assert_eq!(frames.len(), 2);
        assert_eq!(
            decode_envelope(&frames[1].body).unwrap(),
            RpcEnvelope::Request {
                request_id: version_id,
                payload: set_client_version_request(2),
            }
        );
    }

    #[test]
    fn prepared_operation_does_not_repeat_client_version_selection() {
        let command_id = RequestId::from_uuid_v4_bytes([0x32; 16]);
        let command_reply = plist_frame(
            encode_reply(&command_id, &[Value::Integer(0), Value::Data(vec![1])]).unwrap(),
        );
        let mut session =
            BridgeXpcSession::connect(MemoryStream::new(&[hello(), command_reply]), PROCESS_NAME)
                .unwrap();
        let operation = prepared_operation(
            &mut session,
            [command_id.clone()].into_iter(),
            ScriptedReadiness::readable(),
        );
        let (mut commands, _events) = operation
            .into_adapters_with_clock(
                Duration::from_secs(1),
                FakeClock::new(Duration::ZERO),
                || false,
            )
            .unwrap();

        assert_eq!(
            commands.execute(&calibration_status_command()).unwrap(),
            vec![1]
        );
        drop(commands);

        let frames = decode_frames(&session.into_inner().output);
        assert_eq!(frames.len(), 2);
        assert_eq!(
            decode_envelope(&frames[1].body).unwrap(),
            RpcEnvelope::Request {
                request_id: command_id,
                payload: perform_biometric_command_request(&calibration_status_command()),
            }
        );
    }

    fn operation<'a, R, I>(
        session: &'a mut BridgeXpcSession<MemoryStream>,
        request_ids: I,
        readiness: R,
    ) -> LiveBridgeOperation<'a, MemoryStream, I, R>
    where
        I: RequestIdSource + 'a,
    {
        LiveBridgeOperation::new(
            SessionBiometricTransport::new(session, request_ids),
            readiness,
        )
    }

    #[test]
    fn peer_endpoint_is_fixed_and_scoped_only_by_validated_index() {
        let index = NonZeroU32::new(41).unwrap();
        let SocketAddr::V6(endpoint) = bridge_peer_address(index) else {
            panic!("fixed endpoint must be IPv6");
        };
        assert_eq!(*endpoint.ip(), BRIDGEOS_PEER);
        assert_eq!(endpoint.port(), BIOMETRIC_SERVICE_PORT);
        assert_eq!(endpoint.flowinfo(), 0);
        assert_eq!(endpoint.scope_id(), index.get());
    }

    #[test]
    fn queued_rpc_callback_is_drained_before_readiness_wait() {
        let request_id = RequestId::from_uuid_v4_bytes(REQUEST_ID_BYTES);
        let callback_id = RequestId::from_uuid_v4_bytes([0x52; 16]);
        let version_reply = plist_frame(
            encode_reply(&request_id, &[Value::Integer(0), Value::Boolean(true)]).unwrap(),
        );
        let mut session = BridgeXpcSession::connect(
            MemoryStream::new(&[hello(), callback(&callback_id), version_reply]),
            PROCESS_NAME,
        )
        .unwrap();
        let mut transport = SessionBiometricTransport::new(&mut session, [request_id].into_iter());
        transport.select_client_version().unwrap();
        let waits = Rc::new(Cell::new(0));
        let operation = LiveBridgeOperation::new(
            transport,
            ScriptedReadiness {
                readable: VecDeque::new(),
                clock: None,
                waits: Rc::clone(&waits),
                configured: Vec::new(),
            },
        );
        let (_commands, mut events) = operation
            .into_adapters_with_clock(
                Duration::from_secs(1),
                FakeClock::new(Duration::ZERO),
                || false,
            )
            .unwrap();

        let MatchEvent::Callback(event) = MatchEventSource::next_event(&mut events).unwrap() else {
            panic!("queued callback must be delivered");
        };
        assert_eq!(event.service, 0xe3ff_8000);
        assert_eq!(event.data, [0x10, 0x20]);
        assert_eq!(waits.get(), 0);
    }

    #[test]
    fn readable_callback_is_acknowledged_and_delivered() {
        let callback_id = RequestId::from_uuid_v4_bytes([0x63; 16]);
        let mut session = BridgeXpcSession::connect(
            MemoryStream::new(&[hello(), callback(&callback_id)]),
            PROCESS_NAME,
        )
        .unwrap();
        let operation = operation(
            &mut session,
            Vec::<RequestId>::new().into_iter(),
            ScriptedReadiness::readable(),
        );
        {
            let (_commands, mut events) = operation
                .into_adapters_with_clock(
                    Duration::from_secs(1),
                    FakeClock::new(Duration::ZERO),
                    || false,
                )
                .unwrap();

            assert!(matches!(
                MatchEventSource::next_event(&mut events).unwrap(),
                MatchEvent::Callback(_)
            ));
        }

        let frames = decode_frames(&session.into_inner().output);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].message_type, FRAME_HELLO);
        assert_eq!(frames[1].message_type, FRAME_BINARY_PLIST);
        assert_eq!(
            decode_envelope(&frames[1].body).unwrap(),
            RpcEnvelope::Reply {
                request_id: callback_id,
                result: vec![Value::Integer(0)],
            }
        );
    }

    #[test]
    fn tcp_readiness_peek_does_not_consume_callback_bytes() {
        let listener = TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        peer.write_all(&[0x5a]).unwrap();

        let mut readiness = TcpCallbackReadiness::new(client);
        assert!(readiness.wait_readable(Duration::from_secs(1)).unwrap());
        let mut byte = [0_u8; 1];
        readiness.stream.read_exact(&mut byte).unwrap();
        assert_eq!(byte, [0x5a]);
    }

    #[test]
    fn cancellation_precedes_queued_callbacks_and_maps_cleanly_for_enrollment() {
        let mut match_session =
            BridgeXpcSession::connect(MemoryStream::new(&[hello()]), PROCESS_NAME).unwrap();
        let match_operation = operation(
            &mut match_session,
            Vec::<RequestId>::new().into_iter(),
            ScriptedReadiness::readable(),
        );
        let (_, mut match_events) = match_operation
            .into_adapters_with_clock(
                Duration::from_secs(1),
                FakeClock::new(Duration::ZERO),
                || true,
            )
            .unwrap();
        assert!(matches!(
            MatchEventSource::next_event(&mut match_events).unwrap(),
            MatchEvent::Cancelled
        ));

        let mut enrollment_session =
            BridgeXpcSession::connect(MemoryStream::new(&[hello()]), PROCESS_NAME).unwrap();
        let enrollment_operation = operation(
            &mut enrollment_session,
            Vec::<RequestId>::new().into_iter(),
            ScriptedReadiness::readable(),
        );
        let (_, mut enrollment_events) = enrollment_operation
            .into_adapters_with_clock(
                Duration::from_secs(1),
                FakeClock::new(Duration::ZERO),
                || true,
            )
            .unwrap();
        assert!(matches!(
            EnrollmentEventSource::next_event(&mut enrollment_events).unwrap(),
            EnrollmentEvent::TimedOut
        ));
    }

    #[test]
    fn deadline_starts_at_first_event_wait_and_uses_bounded_readiness_waits() {
        let mut session =
            BridgeXpcSession::connect(MemoryStream::new(&[hello()]), PROCESS_NAME).unwrap();
        let clock = FakeClock::new(Duration::from_secs(7));
        let readiness = ScriptedReadiness::never(clock.clone());
        let waits = Rc::clone(&readiness.waits);
        let operation = operation(&mut session, Vec::<RequestId>::new().into_iter(), readiness);
        let (_, mut events) = operation
            .into_adapters_with_clock(Duration::from_millis(250), clock, || false)
            .unwrap();
        events.clock.advance(Duration::from_secs(5));

        assert!(matches!(
            MatchEventSource::next_event(&mut events).unwrap(),
            MatchEvent::TimedOut
        ));
        assert_eq!(waits.get(), 3);
        assert_eq!(events.readiness.configured.last(), Some(&SOCKET_IO_TIMEOUT));
    }

    #[test]
    fn operation_timeout_is_strictly_bounded() {
        for (timeout, expected) in [
            (Duration::ZERO, OperationDeadlineError::Zero),
            (
                MAX_OPERATION_TIMEOUT + Duration::from_nanos(1),
                OperationDeadlineError::TooLong,
            ),
        ] {
            let mut session =
                BridgeXpcSession::connect(MemoryStream::new(&[hello()]), PROCESS_NAME).unwrap();
            let operation = operation(
                &mut session,
                Vec::<RequestId>::new().into_iter(),
                ScriptedReadiness::readable(),
            );
            assert!(matches!(
                operation.into_adapters_with_clock(
                    timeout,
                    FakeClock::new(Duration::ZERO),
                    || false
                ),
                Err(error) if error == expected
            ));
        }
    }

    #[test]
    fn command_handle_reuses_session_biometric_transport() {
        let mut session =
            BridgeXpcSession::connect(MemoryStream::new(&[hello()]), PROCESS_NAME).unwrap();
        let operation = operation(
            &mut session,
            Vec::<RequestId>::new().into_iter(),
            ScriptedReadiness::readable(),
        );
        let (mut commands, _events) = operation
            .into_adapters_with_clock(
                Duration::from_secs(1),
                FakeClock::new(Duration::ZERO),
                || false,
            )
            .unwrap();
        assert!(matches!(
            commands.execute(&calibration_status_command()),
            Err(LiveBiometricError::Command(
                BridgeCommandError::ClientVersionNotSelected
            ))
        ));
    }

    #[test]
    fn native_status_extraction_is_exact_and_redacted_wrapper_preserves_it() {
        let status = -536_870_186;
        let direct = BridgeCommandError::Rpc(RpcError::BiometricCommandFailed {
            status,
            command: 0x34,
        });
        assert_eq!(bridge_command_native_status(&direct), Some(status));
        assert_eq!(
            live_biometric_native_status(&LiveBiometricError::Command(direct)),
            Some(status)
        );
        assert_eq!(
            bridge_command_native_status(&BridgeCommandError::RequestIdUnavailable),
            None
        );
    }

    #[derive(Default)]
    struct RecordingWait(Vec<Duration>);

    impl MonotonicWait for RecordingWait {
        type Error = Infallible;

        fn wait(&mut self, delay: Duration) -> Result<(), Self::Error> {
            self.0.push(delay);
            Ok(())
        }
    }

    #[test]
    fn policy_runtime_classifies_status_and_delegates_exact_wait() {
        let error = LiveBiometricError::Command(BridgeCommandError::Rpc(
            RpcError::BiometricCommandFailed {
                status: 16,
                command: 0x34,
            },
        ));
        let mut runtime = LivePolicyRetryRuntime::with_waiter(RecordingWait::default());
        assert_eq!(
            UserPolicyRetryRuntime::<LiveBiometricError>::native_status(&runtime, &error),
            Some(16)
        );
        UserPolicyRetryRuntime::<LiveBiometricError>::wait(
            &mut runtime,
            Duration::from_millis(150),
        )
        .unwrap();
        assert_eq!(runtime.into_waiter().0, [Duration::from_millis(150)]);
    }

    #[test]
    fn diagnostics_do_not_include_endpoint_or_callback_material() {
        let connection = LiveConnectionError::Socket;
        let callback = CallbackEventError::Readiness;
        for output in [
            format!("{connection:?} {connection}"),
            format!("{callback:?} {callback}"),
        ] {
            assert!(!output.contains("fe80"));
            assert!(!output.contains("52032"));
            assert!(!output.contains("aede"));
            assert!(!output.contains("private callback"));
        }
    }

    #[test]
    fn timeout_transport_errors_are_classified_without_diagnostics() {
        for kind in [io::ErrorKind::WouldBlock, io::ErrorKind::TimedOut] {
            assert!(is_timeout(&io::Error::from(kind)));
        }
        assert!(!is_timeout(&io::Error::from(
            io::ErrorKind::ConnectionReset
        )));
    }
}

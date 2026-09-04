//! Fixed local client for direct Touch ID enrollment and matching.

use std::ffi::OsStr;
use std::fmt;
use std::os::fd::{AsFd, OwnedFd};
use std::time::{Duration, Instant};

use t1_platform::seqpacket::{SeqPacketClient, SeqPacketError, connect_auth};

use crate::auth_protocol::{Request, Response, decode_response};
use crate::auth_scheduler::{ENROLLMENT_OPERATION_TIMEOUT, OPERATION_TIMEOUT};

const REPLY_MARGIN: Duration = Duration::from_secs(35);
const RETRY_WAIT: Duration = Duration::from_millis(10);
const RESPONSE_CAPACITY: usize = 4;

/// One exact operation supported by the direct local client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TouchIdCommand {
    Enroll,
    Authenticate,
    Approve,
}

impl TouchIdCommand {
    /// Decodes exactly one supported command-line operation.
    #[must_use]
    pub fn parse(argument: &OsStr) -> Option<Self> {
        if argument == "enroll" {
            Some(Self::Enroll)
        } else if argument == "authenticate" {
            Some(Self::Authenticate)
        } else if argument == "approve" {
            Some(Self::Approve)
        } else {
            None
        }
    }

    const fn request(self) -> Request {
        match self {
            Self::Enroll => Request::Enroll,
            Self::Authenticate => Request::Authenticate,
            Self::Approve => Request::Approve,
        }
    }

    const fn operation_timeout(self) -> Duration {
        match self {
            Self::Enroll => ENROLLMENT_OPERATION_TIMEOUT,
            Self::Authenticate | Self::Approve => OPERATION_TIMEOUT,
        }
    }

    fn watchdog(self) -> Result<Duration, TouchIdClientError> {
        self.operation_timeout()
            .checked_add(REPLY_MARGIN)
            .ok_or(TouchIdClientError::DeadlineExceeded)
    }
}

/// Static, payload-free direct client failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TouchIdClientError {
    InvalidCommand,
    BrokerUnavailable,
    UntrustedBroker,
    DeadlineExceeded,
    SendFailed,
    ReceiveFailed,
    InvalidResponse,
    Denied,
    Busy,
    BrokerFailure,
}

impl fmt::Display for TouchIdClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidCommand => "expected enroll, authenticate, or approve",
            Self::BrokerUnavailable => "Touch ID broker is unavailable",
            Self::UntrustedBroker => "Touch ID broker identity could not be verified",
            Self::DeadlineExceeded => "Touch ID request timed out",
            Self::SendFailed => "Touch ID request could not be sent",
            Self::ReceiveFailed => "Touch ID response could not be received",
            Self::InvalidResponse => "Touch ID broker returned an invalid response",
            Self::Denied => "Touch ID request was denied",
            Self::Busy => "Touch ID broker is busy",
            Self::BrokerFailure => "Touch ID operation failed",
        })
    }
}

impl std::error::Error for TouchIdClientError {}

/// Runs one direct request against the fixed root-owned local broker.
///
/// # Errors
///
/// Returns a static failure unless the broker returns exactly `OKAY` before
/// the purpose-specific monotonic watchdog expires.
pub fn run(command: TouchIdCommand) -> Result<(), TouchIdClientError> {
    let descriptor = connect_auth().map_err(map_connect_error)?;
    let mut transport = LiveTransport { descriptor };
    let mut runtime = ProcessRuntime::new();
    exchange(&mut transport, &mut runtime, command, command.watchdog()?)
}

fn map_connect_error(error: SeqPacketError) -> TouchIdClientError {
    match error {
        SeqPacketError::PeerDenied | SeqPacketError::Credentials => {
            TouchIdClientError::UntrustedBroker
        }
        _ => TouchIdClientError::BrokerUnavailable,
    }
}

trait PacketTransport {
    fn send(&mut self, packet: &[u8]) -> Result<(), SeqPacketError>;
    fn receive(&mut self, buffer: &mut [u8]) -> Result<usize, SeqPacketError>;
}

struct LiveTransport {
    descriptor: OwnedFd,
}

impl PacketTransport for LiveTransport {
    fn send(&mut self, packet: &[u8]) -> Result<(), SeqPacketError> {
        SeqPacketClient::new(self.descriptor.as_fd()).send(packet)
    }

    fn receive(&mut self, buffer: &mut [u8]) -> Result<usize, SeqPacketError> {
        SeqPacketClient::new(self.descriptor.as_fd()).receive(buffer)
    }
}

trait MonotonicRuntime {
    fn now(&self) -> Duration;
    fn wait(&mut self, duration: Duration);
}

struct ProcessRuntime {
    origin: Instant,
}

impl ProcessRuntime {
    fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl MonotonicRuntime for ProcessRuntime {
    fn now(&self) -> Duration {
        self.origin.elapsed()
    }

    fn wait(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

fn exchange<Transport, Runtime>(
    transport: &mut Transport,
    runtime: &mut Runtime,
    command: TouchIdCommand,
    watchdog: Duration,
) -> Result<(), TouchIdClientError>
where
    Transport: PacketTransport,
    Runtime: MonotonicRuntime,
{
    let deadline = runtime
        .now()
        .checked_add(watchdog)
        .ok_or(TouchIdClientError::DeadlineExceeded)?;
    send_before_deadline(transport, runtime, command.request().encode(), deadline)?;

    let mut response = [0_u8; RESPONSE_CAPACITY];
    let length = receive_before_deadline(transport, runtime, &mut response, deadline)?;
    let response =
        decode_response(&response[..length]).map_err(|_| TouchIdClientError::InvalidResponse)?;
    match response {
        Response::Okay => Ok(()),
        Response::Denied => Err(TouchIdClientError::Denied),
        Response::Busy => Err(TouchIdClientError::Busy),
        Response::Failure => Err(TouchIdClientError::BrokerFailure),
    }
}

fn send_before_deadline<Transport, Runtime>(
    transport: &mut Transport,
    runtime: &mut Runtime,
    packet: &[u8],
    deadline: Duration,
) -> Result<(), TouchIdClientError>
where
    Transport: PacketTransport,
    Runtime: MonotonicRuntime,
{
    loop {
        if runtime.now() >= deadline {
            return Err(TouchIdClientError::DeadlineExceeded);
        }
        match transport.send(packet) {
            Ok(()) => return Ok(()),
            Err(SeqPacketError::WouldBlock | SeqPacketError::Interrupted) => {
                wait_for_retry(runtime, deadline)?;
            }
            Err(_) => return Err(TouchIdClientError::SendFailed),
        }
    }
}

fn receive_before_deadline<Transport, Runtime>(
    transport: &mut Transport,
    runtime: &mut Runtime,
    buffer: &mut [u8],
    deadline: Duration,
) -> Result<usize, TouchIdClientError>
where
    Transport: PacketTransport,
    Runtime: MonotonicRuntime,
{
    loop {
        if runtime.now() >= deadline {
            return Err(TouchIdClientError::DeadlineExceeded);
        }
        match transport.receive(buffer) {
            Ok(length) if length <= buffer.len() => return Ok(length),
            Ok(_) => return Err(TouchIdClientError::InvalidResponse),
            Err(SeqPacketError::WouldBlock | SeqPacketError::Interrupted) => {
                wait_for_retry(runtime, deadline)?;
            }
            Err(SeqPacketError::Truncated) => {
                return Err(TouchIdClientError::InvalidResponse);
            }
            Err(_) => return Err(TouchIdClientError::ReceiveFailed),
        }
    }
}

fn wait_for_retry<Runtime: MonotonicRuntime>(
    runtime: &mut Runtime,
    deadline: Duration,
) -> Result<(), TouchIdClientError> {
    let now = runtime.now();
    let remaining = deadline
        .checked_sub(now)
        .filter(|remaining| !remaining.is_zero())
        .ok_or(TouchIdClientError::DeadlineExceeded)?;
    runtime.wait(remaining.min(RETRY_WAIT));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    enum ReceiveStep {
        Packet(Vec<u8>),
        Error(SeqPacketError),
        InvalidLength(usize),
    }

    struct FakeTransport {
        send_steps: VecDeque<Result<(), SeqPacketError>>,
        receive_steps: VecDeque<ReceiveStep>,
        sent: Vec<Vec<u8>>,
    }

    impl FakeTransport {
        fn reply(packet: &[u8]) -> Self {
            Self {
                send_steps: [Ok(())].into_iter().collect(),
                receive_steps: [ReceiveStep::Packet(packet.to_vec())].into_iter().collect(),
                sent: Vec::new(),
            }
        }
    }

    impl PacketTransport for FakeTransport {
        fn send(&mut self, packet: &[u8]) -> Result<(), SeqPacketError> {
            self.sent.push(packet.to_vec());
            self.send_steps.pop_front().expect("scripted send")
        }

        fn receive(&mut self, buffer: &mut [u8]) -> Result<usize, SeqPacketError> {
            match self.receive_steps.pop_front().expect("scripted receive") {
                ReceiveStep::Packet(packet) => {
                    assert!(packet.len() <= buffer.len());
                    buffer[..packet.len()].copy_from_slice(&packet);
                    Ok(packet.len())
                }
                ReceiveStep::Error(error) => Err(error),
                ReceiveStep::InvalidLength(length) => Ok(length),
            }
        }
    }

    #[derive(Default)]
    struct FakeRuntime {
        now: Duration,
        waits: Vec<Duration>,
    }

    impl MonotonicRuntime for FakeRuntime {
        fn now(&self) -> Duration {
            self.now
        }

        fn wait(&mut self, duration: Duration) {
            self.waits.push(duration);
            self.now += duration;
        }
    }

    #[test]
    fn parses_only_the_three_product_commands() {
        assert_eq!(
            TouchIdCommand::parse(OsStr::new("enroll")),
            Some(TouchIdCommand::Enroll)
        );
        assert_eq!(
            TouchIdCommand::parse(OsStr::new("authenticate")),
            Some(TouchIdCommand::Authenticate)
        );
        assert_eq!(
            TouchIdCommand::parse(OsStr::new("approve")),
            Some(TouchIdCommand::Approve)
        );
        assert_eq!(TouchIdCommand::parse(OsStr::new("cancel")), None);
        assert_eq!(TouchIdCommand::parse(&OsString::from_vec(vec![0xff])), None);
    }

    #[test]
    fn each_command_sends_its_exact_typed_request_and_accepts_only_okay() {
        for (command, request) in [
            (TouchIdCommand::Enroll, Request::Enroll),
            (TouchIdCommand::Authenticate, Request::Authenticate),
            (TouchIdCommand::Approve, Request::Approve),
        ] {
            let mut transport = FakeTransport::reply(Response::Okay.encode());
            let mut runtime = FakeRuntime::default();
            assert_eq!(
                exchange(
                    &mut transport,
                    &mut runtime,
                    command,
                    command.watchdog().unwrap()
                ),
                Ok(())
            );
            assert_eq!(transport.sent, [request.encode()]);
        }
    }

    #[test]
    fn watchdogs_match_broker_budgets_with_one_reply_margin() {
        assert_eq!(
            TouchIdCommand::Enroll.watchdog(),
            Ok(ENROLLMENT_OPERATION_TIMEOUT + REPLY_MARGIN)
        );
        assert_eq!(
            TouchIdCommand::Authenticate.watchdog(),
            Ok(OPERATION_TIMEOUT + REPLY_MARGIN)
        );
        assert_eq!(
            TouchIdCommand::Approve.watchdog(),
            Ok(OPERATION_TIMEOUT + REPLY_MARGIN)
        );
    }

    #[test]
    fn exact_non_success_responses_are_typed_failures() {
        for (response, expected) in [
            (Response::Denied, TouchIdClientError::Denied),
            (Response::Busy, TouchIdClientError::Busy),
            (Response::Failure, TouchIdClientError::BrokerFailure),
        ] {
            let mut transport = FakeTransport::reply(response.encode());
            assert_eq!(
                exchange(
                    &mut transport,
                    &mut FakeRuntime::default(),
                    TouchIdCommand::Authenticate,
                    Duration::from_secs(1),
                ),
                Err(expected)
            );
        }
    }

    #[test]
    fn malformed_short_oversized_and_truncated_responses_fail_closed() {
        let scenarios = [
            ReceiveStep::Packet(b"OK".to_vec()),
            ReceiveStep::Packet(b"NOPE".to_vec()),
            ReceiveStep::InvalidLength(RESPONSE_CAPACITY + 1),
            ReceiveStep::Error(SeqPacketError::Truncated),
        ];
        for scenario in scenarios {
            let mut transport = FakeTransport {
                send_steps: [Ok(())].into_iter().collect(),
                receive_steps: [scenario].into_iter().collect(),
                sent: Vec::new(),
            };
            assert_eq!(
                exchange(
                    &mut transport,
                    &mut FakeRuntime::default(),
                    TouchIdCommand::Approve,
                    Duration::from_secs(1),
                ),
                Err(TouchIdClientError::InvalidResponse)
            );
        }
    }

    #[test]
    fn transient_send_and_receive_states_retry_without_changing_payload() {
        let mut transport = FakeTransport {
            send_steps: [
                Err(SeqPacketError::WouldBlock),
                Err(SeqPacketError::Interrupted),
                Ok(()),
            ]
            .into_iter()
            .collect(),
            receive_steps: [
                ReceiveStep::Error(SeqPacketError::WouldBlock),
                ReceiveStep::Error(SeqPacketError::Interrupted),
                ReceiveStep::Packet(Response::Okay.encode().to_vec()),
            ]
            .into_iter()
            .collect(),
            sent: Vec::new(),
        };
        let mut runtime = FakeRuntime::default();
        assert_eq!(
            exchange(
                &mut transport,
                &mut runtime,
                TouchIdCommand::Enroll,
                Duration::from_secs(1),
            ),
            Ok(())
        );
        assert_eq!(transport.sent, [Request::Enroll.encode(); 3]);
        assert_eq!(runtime.waits, [RETRY_WAIT; 4]);
    }

    #[test]
    fn one_deadline_bounds_send_and_receive_together() {
        let mut transport = FakeTransport {
            send_steps: [Ok(())].into_iter().collect(),
            receive_steps: [
                ReceiveStep::Error(SeqPacketError::WouldBlock),
                ReceiveStep::Error(SeqPacketError::WouldBlock),
                ReceiveStep::Error(SeqPacketError::WouldBlock),
            ]
            .into_iter()
            .collect(),
            sent: Vec::new(),
        };
        let mut runtime = FakeRuntime::default();
        assert_eq!(
            exchange(
                &mut transport,
                &mut runtime,
                TouchIdCommand::Authenticate,
                Duration::from_millis(25),
            ),
            Err(TouchIdClientError::DeadlineExceeded)
        );
        assert_eq!(runtime.now, Duration::from_millis(25));
        assert_eq!(
            runtime.waits,
            [
                Duration::from_millis(10),
                Duration::from_millis(10),
                Duration::from_millis(5),
            ]
        );
    }

    #[test]
    fn permanent_transport_failures_remain_stage_specific() {
        let mut send_failure = FakeTransport {
            send_steps: [Err(SeqPacketError::Send)].into_iter().collect(),
            receive_steps: VecDeque::new(),
            sent: Vec::new(),
        };
        assert_eq!(
            exchange(
                &mut send_failure,
                &mut FakeRuntime::default(),
                TouchIdCommand::Authenticate,
                Duration::from_secs(1),
            ),
            Err(TouchIdClientError::SendFailed)
        );

        let mut receive_failure = FakeTransport {
            send_steps: [Ok(())].into_iter().collect(),
            receive_steps: [ReceiveStep::Error(SeqPacketError::Receive)]
                .into_iter()
                .collect(),
            sent: Vec::new(),
        };
        assert_eq!(
            exchange(
                &mut receive_failure,
                &mut FakeRuntime::default(),
                TouchIdCommand::Authenticate,
                Duration::from_secs(1),
            ),
            Err(TouchIdClientError::ReceiveFailed)
        );
    }
}

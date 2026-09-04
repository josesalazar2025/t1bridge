//! Safe, nonblocking access to authenticated local `SOCK_SEQPACKET` sockets.

use std::ffi::CStr;
use std::fmt;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::ffi;

/// Kernel-supplied identity for one connected local peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(clippy::struct_field_names)]
pub struct PeerCredentials {
    pub process_id: i32,
    pub user_id: u32,
    pub group_id: u32,
}

/// Static failure from the local seqpacket boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SeqPacketError {
    InvalidArgument,
    DescriptorInspection,
    WrongSocket,
    NotListener,
    NotConnected,
    WouldBlock,
    Interrupted,
    Accept,
    Credentials,
    Receive,
    Truncated,
    PeerClosed,
    Send,
    ShortSend,
    Activation,
    WrongPath,
    Readiness,
    Connect,
    PeerDenied,
    Unknown,
}

impl fmt::Display for SeqPacketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidArgument => "invalid local socket argument",
            Self::DescriptorInspection => "local socket descriptor inspection failed",
            Self::WrongSocket => "descriptor is not a local seqpacket socket",
            Self::NotListener => "local seqpacket descriptor is not listening",
            Self::NotConnected => "local seqpacket descriptor is not connected",
            Self::WouldBlock => "local seqpacket operation would block",
            Self::Interrupted => "local seqpacket operation was interrupted",
            Self::Accept => "local seqpacket accept failed",
            Self::Credentials => "local peer credential lookup failed",
            Self::Receive => "local seqpacket receive failed",
            Self::Truncated => "local seqpacket was truncated",
            Self::PeerClosed => "local seqpacket peer closed",
            Self::Send => "local seqpacket send failed",
            Self::ShortSend => "local seqpacket send was short",
            Self::Activation => "systemd socket activation failed",
            Self::WrongPath => "activated listener has an unexpected path",
            Self::Readiness => "local listener readiness check failed",
            Self::Connect => "local service connection failed",
            Self::PeerDenied => "local peer is not authorized",
            Self::Unknown => "unknown local seqpacket error",
        })
    }
}

impl std::error::Error for SeqPacketError {}

static SYSTEMD_LISTENER_ADOPTION_ATTEMPTED: AtomicBool = AtomicBool::new(false);

/// Canonical numeric values read from systemd's activation environment.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SystemdActivation {
    process_id: i32,
    descriptor_count: u32,
}

impl fmt::Debug for SystemdActivation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SystemdActivation")
    }
}

impl SystemdActivation {
    /// Parses canonical `LISTEN_PID` and `LISTEN_FDS` values without reading or
    /// mutating the process environment.
    ///
    /// Process-entry code must obtain both strings before starting any worker.
    /// Only one positive decimal PID and exactly one descriptor are accepted.
    ///
    /// # Errors
    ///
    /// Returns a static activation error for absent, signed, padded,
    /// out-of-range, or otherwise noncanonical values.
    pub fn parse(listen_pid: &str, listen_fds: &str) -> Result<Self, SeqPacketError> {
        let canonical_pid = !listen_pid.is_empty()
            && listen_pid.bytes().all(|byte| byte.is_ascii_digit())
            && (listen_pid.len() == 1 || !listen_pid.starts_with('0'));
        if !canonical_pid || listen_fds != "1" {
            return Err(SeqPacketError::Activation);
        }
        let process_id = listen_pid
            .parse::<i32>()
            .ok()
            .filter(|process_id| *process_id > 0)
            .ok_or(SeqPacketError::Activation)?;
        Ok(Self {
            process_id,
            descriptor_count: 1,
        })
    }
}

/// Canonical activation values for exactly two ordered listener descriptors.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SystemdActivationPair {
    process_id: i32,
    descriptor_count: u32,
}

impl fmt::Debug for SystemdActivationPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SystemdActivationPair")
    }
}

impl SystemdActivationPair {
    /// Parses canonical `LISTEN_PID` and `LISTEN_FDS` values for exactly two
    /// ordered descriptors without reading or mutating the environment.
    ///
    /// # Errors
    ///
    /// Returns a static activation error for absent, signed, padded,
    /// out-of-range, or otherwise noncanonical values.
    pub fn parse(listen_pid: &str, listen_fds: &str) -> Result<Self, SeqPacketError> {
        let canonical_pid = !listen_pid.is_empty()
            && listen_pid.bytes().all(|byte| byte.is_ascii_digit())
            && (listen_pid.len() == 1 || !listen_pid.starts_with('0'));
        if !canonical_pid || listen_fds != "2" {
            return Err(SeqPacketError::Activation);
        }
        let process_id = listen_pid
            .parse::<i32>()
            .ok()
            .filter(|process_id| *process_id > 0)
            .ok_or(SeqPacketError::Activation)?;
        Ok(Self {
            process_id,
            descriptor_count: 2,
        })
    }
}

/// Owned copy of exactly one validated systemd-activated seqpacket listener.
pub struct SystemdSeqPacketListener {
    descriptor: OwnedFd,
}

/// Owned copies of exactly two validated ordered systemd listeners.
pub struct SystemdSeqPacketListenerPair {
    first: SystemdSeqPacketListener,
    second: SystemdSeqPacketListener,
}

impl fmt::Debug for SystemdSeqPacketListenerPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SystemdSeqPacketListenerPair")
            .finish_non_exhaustive()
    }
}

impl SystemdSeqPacketListenerPair {
    /// Adopts exactly two systemd listeners at two distinct ordered paths.
    ///
    /// Both inherited descriptors are validated before either is consumed.
    /// Success returns close-on-exec, nonblocking owned listeners. This process
    /// may attempt either single- or pair-listener adoption only once.
    ///
    /// # Errors
    ///
    /// Returns a static error for invalid activation values, descriptor shape,
    /// listener state, path order, duplication, or descriptor consumption.
    pub fn adopt(
        activation: SystemdActivationPair,
        first_expected_path: &CStr,
        second_expected_path: &CStr,
    ) -> Result<Self, SeqPacketError> {
        SYSTEMD_LISTENER_ADOPTION_ATTEMPTED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| SeqPacketError::Activation)?;
        let (status, descriptors) = ffi::adopt_systemd_listener_pair(
            activation.process_id,
            activation.descriptor_count,
            first_expected_path,
            second_expected_path,
        );
        check(status)?;
        let (first, second) = descriptors.ok_or(SeqPacketError::Activation)?;
        Ok(Self {
            first: SystemdSeqPacketListener { descriptor: first },
            second: SystemdSeqPacketListener { descriptor: second },
        })
    }

    /// Borrows the first listener in activation order.
    #[must_use]
    pub const fn first(&self) -> &SystemdSeqPacketListener {
        &self.first
    }

    /// Borrows the second listener in activation order.
    #[must_use]
    pub const fn second(&self) -> &SystemdSeqPacketListener {
        &self.second
    }

    /// Separates the pair while preserving ownership and activation order.
    #[must_use]
    pub fn into_listeners(self) -> (SystemdSeqPacketListener, SystemdSeqPacketListener) {
        (self.first, self.second)
    }
}

impl fmt::Debug for SystemdSeqPacketListener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SystemdSeqPacketListener")
            .finish_non_exhaustive()
    }
}

impl SystemdSeqPacketListener {
    /// Adopts exactly one systemd listener at the expected Unix pathname.
    ///
    /// This process may attempt adoption exactly once. The native boundary
    /// validates the supplied process ID, descriptor count, socket shape,
    /// listening state, and exact pathname. Success consumes inherited
    /// descriptor 3 and returns one close-on-exec, nonblocking owned descriptor.
    /// No process environment state is read or mutated by this method.
    ///
    /// # Errors
    ///
    /// Returns a static error without taking descriptor ownership when any
    /// activation or listener invariant fails.
    pub fn adopt(
        activation: SystemdActivation,
        expected_path: &CStr,
    ) -> Result<Self, SeqPacketError> {
        SYSTEMD_LISTENER_ADOPTION_ATTEMPTED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| SeqPacketError::Activation)?;
        let (status, descriptor) = ffi::adopt_systemd_listener(
            activation.process_id,
            activation.descriptor_count,
            expected_path,
        );
        check(status)?;
        descriptor
            .map(|descriptor| Self { descriptor })
            .ok_or(SeqPacketError::Activation)
    }

    /// Reports whether a connection is queued without accepting or consuming it.
    ///
    /// # Errors
    ///
    /// Returns a static error when the owned descriptor is no longer a valid
    /// listener or the zero-time readiness probe fails.
    pub fn is_ready(&self) -> Result<bool, SeqPacketError> {
        let (status, ready) = ffi::listener_ready(self.descriptor.as_raw_fd());
        check(status)?;
        Ok(ready)
    }

    /// Borrows the validated listener for nonblocking acceptance.
    #[must_use]
    pub fn listener(&self) -> SeqPacketListener<'_> {
        SeqPacketListener::new(self.descriptor.as_fd())
    }
}

/// Borrowed local seqpacket listener descriptor.
#[derive(Clone, Copy, Debug)]
pub struct SeqPacketListener<'fd> {
    descriptor: BorrowedFd<'fd>,
}

impl<'fd> SeqPacketListener<'fd> {
    #[must_use]
    pub const fn new(descriptor: BorrowedFd<'fd>) -> Self {
        Self { descriptor }
    }

    /// Accepts one close-on-exec, nonblocking client descriptor.
    ///
    /// # Errors
    ///
    /// Returns a static error if the descriptor shape is invalid, no client is
    /// ready, the call is interrupted, or acceptance fails.
    pub fn accept(self) -> Result<OwnedFd, SeqPacketError> {
        let (status, client) = ffi::accept(self.descriptor.as_raw_fd());
        check(status)?;
        client.ok_or(SeqPacketError::Accept)
    }
}

/// Borrowed connected local seqpacket descriptor.
#[derive(Clone, Copy, Debug)]
pub struct SeqPacketClient<'fd> {
    descriptor: BorrowedFd<'fd>,
}

impl<'fd> SeqPacketClient<'fd> {
    #[must_use]
    pub const fn new(descriptor: BorrowedFd<'fd>) -> Self {
        Self { descriptor }
    }

    /// Reads kernel-authenticated process, user, and group credentials.
    ///
    /// # Errors
    ///
    /// Returns a static error if the descriptor is not a connected local
    /// seqpacket socket or the kernel credential query fails.
    pub fn peer_credentials(self) -> Result<PeerCredentials, SeqPacketError> {
        let (status, credentials) = ffi::peer_credentials(self.descriptor.as_raw_fd());
        check(status)?;
        Ok(PeerCredentials {
            process_id: credentials.process_id,
            user_id: credentials.user_id,
            group_id: credentials.group_id,
        })
    }

    /// Requires this connection's kernel-captured peer groups to contain the
    /// service process's non-root effective group.
    ///
    /// The packaged root service runs with `Group=t1bridge`, so this checks
    /// primary and supplementary membership without NSS, `/proc`, or message
    /// data. A root effective group or unavailable `SO_PEERGROUPS` fails closed.
    ///
    /// # Errors
    ///
    /// Returns [`SeqPacketError::PeerDenied`] unless membership is proven.
    pub fn require_peer_in_effective_group(self) -> Result<(), SeqPacketError> {
        check(ffi::peer_in_effective_group(self.descriptor.as_raw_fd()))
    }

    /// Probes whether the one-request peer has closed, without consuming data.
    ///
    /// # Errors
    ///
    /// Returns a static error if the descriptor is not a connected local
    /// seqpacket socket, the probe is interrupted, or receive inspection
    /// fails. Callers enforcing cancellation should treat an error as a lost
    /// peer.
    pub fn peer_closed(self) -> Result<bool, SeqPacketError> {
        let (status, peer_closed) = ffi::peer_closed(self.descriptor.as_raw_fd());
        check(status)?;
        Ok(peer_closed)
    }

    /// Receives one complete packet without blocking.
    ///
    /// # Errors
    ///
    /// Returns a static error for an empty buffer, invalid socket, interruption,
    /// would-block, peer closure, truncation, or receive failure. A truncated
    /// prefix must not be interpreted. Any received file descriptor is rejected
    /// and closed.
    pub fn receive(self, buffer: &mut [u8]) -> Result<usize, SeqPacketError> {
        if buffer.is_empty() {
            return Err(SeqPacketError::InvalidArgument);
        }
        let (status, received) = ffi::receive(self.descriptor.as_raw_fd(), buffer);
        check(status)?;
        Ok(received)
    }

    /// Receives one complete packet with exactly the declared zero or one fd.
    ///
    /// Exact one-fd success transfers one close-on-exec [`OwnedFd`]. Exact
    /// zero-fd success returns `None`. Count mismatches, packet or control
    /// truncation, and unexpected ancillary data close every received fd before
    /// returning an error.
    ///
    /// # Errors
    ///
    /// Returns a static error for an empty buffer, invalid socket, interruption,
    /// would-block, peer closure, truncation, or receive failure.
    pub fn receive_with_fd(
        self,
        buffer: &mut [u8],
        expect_descriptor: bool,
    ) -> Result<(usize, Option<OwnedFd>), SeqPacketError> {
        if buffer.is_empty() {
            return Err(SeqPacketError::InvalidArgument);
        }
        let (status, received, descriptor) =
            ffi::receive_with_fd(self.descriptor.as_raw_fd(), buffer, expect_descriptor);
        check(status)?;
        if expect_descriptor && descriptor.is_none() {
            return Err(SeqPacketError::Receive);
        }
        Ok((received, descriptor))
    }

    /// Receives one packet carrying either zero or one rights descriptor.
    ///
    /// This is the service-side primitive used before the packet type is known.
    /// The typed wire codec must then require one descriptor only for
    /// `RegisterBuffer`. Native rejection closes all received descriptors.
    ///
    /// # Errors
    ///
    /// Returns a static error for an empty buffer, invalid socket,
    /// interruption, would-block, peer closure, truncation, unsupported
    /// ancillary data, more than one descriptor, or receive failure.
    pub fn receive_at_most_one_fd(
        self,
        buffer: &mut [u8],
    ) -> Result<(usize, Option<OwnedFd>), SeqPacketError> {
        if buffer.is_empty() {
            return Err(SeqPacketError::InvalidArgument);
        }
        let (status, received, descriptor) =
            ffi::receive_at_most_one_fd(self.descriptor.as_raw_fd(), buffer);
        check(status)?;
        Ok((received, descriptor))
    }

    /// Sends exactly one complete packet without blocking or raising `SIGPIPE`.
    ///
    /// # Errors
    ///
    /// Returns a static error for an empty packet, invalid socket, interruption,
    /// would-block, short send, or send failure.
    pub fn send(self, packet: &[u8]) -> Result<(), SeqPacketError> {
        if packet.is_empty() {
            return Err(SeqPacketError::InvalidArgument);
        }
        check(ffi::send(self.descriptor.as_raw_fd(), packet))
    }

    /// Sends exactly one packet with zero or one borrowed fd.
    ///
    /// The optional descriptor remains caller-owned and open after success or
    /// failure.
    ///
    /// # Errors
    ///
    /// Returns a static error for an empty packet, invalid socket, interruption,
    /// would-block, short send, or send failure.
    pub fn send_with_fd(
        self,
        packet: &[u8],
        descriptor: Option<BorrowedFd<'_>>,
    ) -> Result<(), SeqPacketError> {
        if packet.is_empty() {
            return Err(SeqPacketError::InvalidArgument);
        }
        check(ffi::send_with_fd(
            self.descriptor.as_raw_fd(),
            packet,
            descriptor,
        ))
    }
}

/// Connects to the fixed Touch Bar hardware endpoint and requires a root peer.
///
/// Success returns one validated close-on-exec, nonblocking seqpacket
/// descriptor. No protocol bytes are sent before the kernel credential check.
///
/// # Errors
///
/// Returns a static connection or credential error, or
/// [`SeqPacketError::PeerDenied`] when the connected service is not root.
pub fn connect_touchbar() -> Result<OwnedFd, SeqPacketError> {
    let (status, descriptor) = ffi::connect_touchbar();
    check(status)?;
    let descriptor = descriptor.ok_or(SeqPacketError::Connect)?;
    require_root_peer(&descriptor)?;
    Ok(descriptor)
}

/// Connects to the fixed Touch ID broker endpoint and requires a root peer.
///
/// Success returns one validated close-on-exec, nonblocking seqpacket
/// descriptor. The native boundary accepts no caller-selected pathname and no
/// protocol bytes are sent before the kernel credential check.
///
/// # Errors
///
/// Returns a static connection or credential error, or
/// [`SeqPacketError::PeerDenied`] when the connected broker is not root.
pub fn connect_auth() -> Result<OwnedFd, SeqPacketError> {
    let (status, descriptor) = ffi::connect_auth();
    check(status)?;
    let descriptor = descriptor.ok_or(SeqPacketError::Connect)?;
    require_root_peer(&descriptor)?;
    Ok(descriptor)
}

fn require_root_peer(descriptor: &OwnedFd) -> Result<(), SeqPacketError> {
    let credentials = SeqPacketClient::new(descriptor.as_fd()).peer_credentials()?;
    require_root_credentials(credentials)
}

fn require_root_credentials(credentials: PeerCredentials) -> Result<(), SeqPacketError> {
    if credentials.user_id == 0 {
        Ok(())
    } else {
        Err(SeqPacketError::PeerDenied)
    }
}

fn check(status: i32) -> Result<(), SeqPacketError> {
    match status {
        0 => Ok(()),
        1 => Err(SeqPacketError::InvalidArgument),
        2 => Err(SeqPacketError::DescriptorInspection),
        3 => Err(SeqPacketError::WrongSocket),
        4 => Err(SeqPacketError::NotListener),
        5 => Err(SeqPacketError::NotConnected),
        6 => Err(SeqPacketError::WouldBlock),
        7 => Err(SeqPacketError::Interrupted),
        8 => Err(SeqPacketError::Accept),
        9 => Err(SeqPacketError::Credentials),
        10 => Err(SeqPacketError::Receive),
        11 => Err(SeqPacketError::Truncated),
        12 => Err(SeqPacketError::PeerClosed),
        13 => Err(SeqPacketError::Send),
        14 => Err(SeqPacketError::ShortSend),
        15 => Err(SeqPacketError::Activation),
        16 => Err(SeqPacketError::WrongPath),
        17 => Err(SeqPacketError::Readiness),
        18 => Err(SeqPacketError::Connect),
        19 => Err(SeqPacketError::PeerDenied),
        _ => Err(SeqPacketError::Unknown),
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::os::fd::{AsFd, AsRawFd};
    use std::os::unix::net::{UnixDatagram, UnixStream};

    use super::*;

    #[test]
    fn activation_values_are_canonical_and_exactly_one_descriptor() {
        assert_eq!(
            SystemdActivation::parse("1", "1"),
            Ok(SystemdActivation {
                process_id: 1,
                descriptor_count: 1,
            })
        );
        assert_eq!(
            SystemdActivation::parse(&i32::MAX.to_string(), "1"),
            Ok(SystemdActivation {
                process_id: i32::MAX,
                descriptor_count: 1,
            })
        );

        for (process_id, descriptor_count) in [
            ("", "1"),
            ("0", "1"),
            ("01", "1"),
            ("+1", "1"),
            ("-1", "1"),
            ("2147483648", "1"),
            ("1", "0"),
            ("1", "2"),
            ("1", "01"),
        ] {
            assert_eq!(
                SystemdActivation::parse(process_id, descriptor_count),
                Err(SeqPacketError::Activation)
            );
        }
    }

    #[test]
    fn pair_activation_values_are_canonical_and_exactly_two_descriptors() {
        assert_eq!(
            SystemdActivationPair::parse("1", "2"),
            Ok(SystemdActivationPair {
                process_id: 1,
                descriptor_count: 2,
            })
        );
        assert_eq!(
            SystemdActivationPair::parse(&i32::MAX.to_string(), "2"),
            Ok(SystemdActivationPair {
                process_id: i32::MAX,
                descriptor_count: 2,
            })
        );

        for (process_id, descriptor_count) in [
            ("", "2"),
            ("0", "2"),
            ("01", "2"),
            ("+1", "2"),
            ("-1", "2"),
            ("2147483648", "2"),
            ("1", "0"),
            ("1", "1"),
            ("1", "02"),
            ("1", "3"),
        ] {
            assert_eq!(
                SystemdActivationPair::parse(process_id, descriptor_count),
                Err(SeqPacketError::Activation)
            );
        }
    }

    #[test]
    fn maps_every_native_status_without_native_text() {
        let expected = [
            Ok(()),
            Err(SeqPacketError::InvalidArgument),
            Err(SeqPacketError::DescriptorInspection),
            Err(SeqPacketError::WrongSocket),
            Err(SeqPacketError::NotListener),
            Err(SeqPacketError::NotConnected),
            Err(SeqPacketError::WouldBlock),
            Err(SeqPacketError::Interrupted),
            Err(SeqPacketError::Accept),
            Err(SeqPacketError::Credentials),
            Err(SeqPacketError::Receive),
            Err(SeqPacketError::Truncated),
            Err(SeqPacketError::PeerClosed),
            Err(SeqPacketError::Send),
            Err(SeqPacketError::ShortSend),
            Err(SeqPacketError::Activation),
            Err(SeqPacketError::WrongPath),
            Err(SeqPacketError::Readiness),
            Err(SeqPacketError::Connect),
            Err(SeqPacketError::PeerDenied),
        ];
        for (status, expected) in (0_i32..).zip(expected) {
            assert_eq!(check(status), expected);
        }
        assert_eq!(check(999), Err(SeqPacketError::Unknown));
    }

    #[test]
    fn diagnostics_are_static() {
        for error in [
            SeqPacketError::InvalidArgument,
            SeqPacketError::DescriptorInspection,
            SeqPacketError::WrongSocket,
            SeqPacketError::NotListener,
            SeqPacketError::NotConnected,
            SeqPacketError::WouldBlock,
            SeqPacketError::Interrupted,
            SeqPacketError::Accept,
            SeqPacketError::Credentials,
            SeqPacketError::Receive,
            SeqPacketError::Truncated,
            SeqPacketError::PeerClosed,
            SeqPacketError::Send,
            SeqPacketError::ShortSend,
            SeqPacketError::Activation,
            SeqPacketError::WrongPath,
            SeqPacketError::Readiness,
            SeqPacketError::Connect,
            SeqPacketError::PeerDenied,
            SeqPacketError::Unknown,
        ] {
            assert!(!error.to_string().contains('/'));
        }
    }

    #[test]
    fn fixed_service_clients_accept_only_kernel_root_credentials() {
        let root = PeerCredentials {
            process_id: 42,
            user_id: 0,
            group_id: 0,
        };
        let non_root = PeerCredentials {
            process_id: 43,
            user_id: 1_000,
            group_id: 1_000,
        };
        assert_eq!(require_root_credentials(root), Ok(()));
        assert_eq!(
            require_root_credentials(non_root),
            Err(SeqPacketError::PeerDenied)
        );
    }

    #[test]
    fn native_boundary_rejects_the_wrong_local_socket_type() {
        let (socket, _peer) = UnixDatagram::pair().unwrap();
        assert!(matches!(
            SeqPacketListener::new(socket.as_fd()).accept(),
            Err(SeqPacketError::WrongSocket)
        ));

        let client = SeqPacketClient::new(socket.as_fd());
        assert_eq!(client.peer_credentials(), Err(SeqPacketError::WrongSocket));
        assert_eq!(client.peer_closed(), Err(SeqPacketError::WrongSocket));
        assert_eq!(
            client.receive(&mut [0_u8; 8]),
            Err(SeqPacketError::WrongSocket)
        );
        assert_eq!(client.send(b"synthetic"), Err(SeqPacketError::WrongSocket));
        assert_eq!(
            client.receive(&mut []),
            Err(SeqPacketError::InvalidArgument)
        );
        assert_eq!(client.send(&[]), Err(SeqPacketError::InvalidArgument));
    }

    #[test]
    fn real_seqpacket_zero_fd_methods_preserve_packet_boundaries() {
        let (sender, receiver) = ffi::seqpacket_pair_for_test().expect("create seqpacket pair");
        let sender = SeqPacketClient::new(sender.as_fd());
        let receiver = SeqPacketClient::new(receiver.as_fd());

        sender.send(b"first").expect("send legacy packet");
        sender
            .send_with_fd(b"second", None)
            .expect("send explicit zero-fd packet");

        let mut packet = [0_u8; 16];
        let packet_length = receiver
            .receive(&mut packet)
            .expect("receive legacy packet");
        assert_eq!(&packet[..packet_length], b"first");
        let (packet_length, descriptor) = receiver
            .receive_with_fd(&mut packet, false)
            .expect("receive explicit zero-fd packet");
        assert_eq!(&packet[..packet_length], b"second");
        assert!(descriptor.is_none());
    }

    #[test]
    fn real_seqpacket_transfers_one_cloexec_fd_without_consuming_sender() {
        let (sender, receiver) = ffi::seqpacket_pair_for_test().expect("create seqpacket pair");
        let (transferred, mut peer) = UnixStream::pair().expect("create transfer socket");
        let original_descriptor = transferred.as_raw_fd();

        SeqPacketClient::new(sender.as_fd())
            .send_with_fd(b"frame", Some(transferred.as_fd()))
            .expect("send one descriptor");
        assert_eq!(transferred.as_raw_fd(), original_descriptor);
        assert!(transferred.peer_addr().is_ok());
        drop(transferred);

        let mut packet = [0_u8; 16];
        let (packet_length, transferred) = SeqPacketClient::new(receiver.as_fd())
            .receive_with_fd(&mut packet, true)
            .expect("receive one descriptor");
        assert_eq!(&packet[..packet_length], b"frame");
        let transferred = transferred.expect("exact success returns descriptor");
        assert!(
            ffi::descriptor_is_cloexec_for_test(transferred.as_fd())
                .expect("inspect descriptor flags")
        );

        let mut transferred = UnixStream::from(transferred);
        peer.write_all(b"x").expect("write through retained file");
        let mut marker = [0_u8; 1];
        transferred
            .read_exact(&mut marker)
            .expect("read through transferred file");
        assert_eq!(marker, *b"x");
    }

    #[test]
    fn real_seqpacket_receives_optional_descriptor_before_type_decode() {
        let (sender, receiver) = ffi::seqpacket_pair_for_test().expect("create seqpacket pair");
        let (transferred, mut peer) = UnixStream::pair().expect("create transfer socket");
        let mut packet = [0_u8; 16];

        SeqPacketClient::new(sender.as_fd())
            .send(b"plain")
            .expect("send zero-descriptor packet");
        let (length, descriptor) = SeqPacketClient::new(receiver.as_fd())
            .receive_at_most_one_fd(&mut packet)
            .expect("receive zero descriptors");
        assert_eq!(&packet[..length], b"plain");
        assert!(descriptor.is_none());

        SeqPacketClient::new(sender.as_fd())
            .send_with_fd(b"frame", Some(transferred.as_fd()))
            .expect("send one-descriptor packet");
        drop(transferred);
        let (length, descriptor) = SeqPacketClient::new(receiver.as_fd())
            .receive_at_most_one_fd(&mut packet)
            .expect("receive one descriptor");
        assert_eq!(&packet[..length], b"frame");
        drop(descriptor.expect("one descriptor transferred"));
        peer.set_nonblocking(true).expect("make peer nonblocking");
        assert_eq!(peer.read(&mut [0_u8; 1]).expect("observe closed fd"), 0);
    }

    #[test]
    fn real_seqpacket_enforces_the_process_effective_group_policy() {
        let (peer, service) = ffi::seqpacket_pair_for_test().expect("create seqpacket pair");

        let result = SeqPacketClient::new(service.as_fd()).require_peer_in_effective_group();
        if ffi::effective_group_is_root_for_test() {
            assert_eq!(result, Err(SeqPacketError::PeerDenied));
        } else {
            result.expect("same-process peer has the non-root effective primary group");
        }
        assert!(peer.as_raw_fd() >= 0);
    }

    #[test]
    fn real_seqpacket_zero_one_mismatches_are_hard_errors() {
        let (sender, receiver) = ffi::seqpacket_pair_for_test().expect("create seqpacket pair");
        let (transferred, mut peer) = UnixStream::pair().expect("create transfer socket");

        SeqPacketClient::new(sender.as_fd())
            .send_with_fd(b"extra", Some(transferred.as_fd()))
            .expect("send unexpected descriptor");
        drop(transferred);

        let mut packet = [0_u8; 16];
        assert!(matches!(
            SeqPacketClient::new(receiver.as_fd()).receive_with_fd(&mut packet, false),
            Err(SeqPacketError::Truncated)
        ));
        peer.set_nonblocking(true).expect("make peer nonblocking");
        assert_eq!(peer.read(&mut [0_u8; 1]).expect("observe closed peer"), 0);

        SeqPacketClient::new(sender.as_fd())
            .send_with_fd(b"missing", None)
            .expect("send packet without descriptor");
        assert!(matches!(
            SeqPacketClient::new(receiver.as_fd()).receive_with_fd(&mut packet, true),
            Err(SeqPacketError::Truncated)
        ));

        SeqPacketClient::new(sender.as_fd())
            .send(b"after")
            .expect("send after mismatches");
        let packet_length = SeqPacketClient::new(receiver.as_fd())
            .receive(&mut packet)
            .expect("receive after mismatches");
        assert_eq!(&packet[..packet_length], b"after");
    }

    #[test]
    fn real_seqpacket_payload_truncation_closes_received_fd() {
        let (sender, receiver) = ffi::seqpacket_pair_for_test().expect("create seqpacket pair");
        let (transferred, mut peer) = UnixStream::pair().expect("create transfer socket");

        SeqPacketClient::new(sender.as_fd())
            .send_with_fd(b"too-long", Some(transferred.as_fd()))
            .expect("send descriptor with long payload");
        drop(transferred);

        assert!(matches!(
            SeqPacketClient::new(receiver.as_fd()).receive_with_fd(&mut [0_u8; 4], true),
            Err(SeqPacketError::Truncated)
        ));
        peer.set_nonblocking(true).expect("make peer nonblocking");
        assert_eq!(peer.read(&mut [0_u8; 1]).expect("observe closed peer"), 0);
    }
}

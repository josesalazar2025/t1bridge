//! Production dynamic-device listener for the T1 xART service.
//!
//! Discovery and socket binding are owned by one focused native boundary. No
//! interface name, sysfs path, address, or device identifier crosses this API.

use std::ffi::{CString, OsStr};
use std::fmt;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, TcpListener, TcpStream};
use std::num::NonZeroU32;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::os::unix::ffi::OsStrExt;

use crate::xart_live_ffi;
use crate::xart_service::{
    ActivationError, DeviceLease, InterfaceDescriptor, PeerAdmissionError, PeerObservation,
    XartServiceLifecycle,
};
use crate::xart_session::{XartConnectionError, serve_admitted_tcp_connection};
use crate::xart_store::XartStore;

const APPLE_VENDOR_ID: u16 = 0x05ac;
const APPLE_T1_PRODUCT_ID: u16 = 0x8600;
const APPLE_T1_NCM_CONTROL_INTERFACE: u8 = 4;
const APPLE_T1_NCM_DRIVER: &str = "apple_t1_ncm";

/// Static failure from dynamic interface discovery, binding, or acceptance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XartListenerError {
    InvalidArgument,
    EnumerationFailed,
    CandidateLimit,
    DeviceNotFound,
    DeviceAmbiguous,
    SocketFailed,
    BindFailed,
    ListenFailed,
    InspectionFailed,
    WrongInterface,
    WouldBlock,
    Interrupted,
    AcceptFailed,
    WrongPeerFamily,
    BlockingModeFailed,
    Unknown,
}

impl fmt::Display for XartListenerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidArgument => "invalid xART listener argument",
            Self::EnumerationFailed => "T1 network-interface discovery failed",
            Self::CandidateLimit => "T1 network-interface discovery limit exceeded",
            Self::DeviceNotFound => "T1 network interface is unavailable",
            Self::DeviceAmbiguous => "T1 network interface is ambiguous",
            Self::SocketFailed => "xART listener socket creation failed",
            Self::BindFailed => "xART listener interface bind failed",
            Self::ListenFailed => "xART listener activation failed",
            Self::InspectionFailed => "xART listener inspection failed",
            Self::WrongInterface => "xART listener binding changed",
            Self::WouldBlock => "no xART connection is ready",
            Self::Interrupted => "xART connection acceptance was interrupted",
            Self::AcceptFailed => "xART connection acceptance failed",
            Self::WrongPeerFamily => "xART peer is not IPv6",
            Self::BlockingModeFailed => "xART listener blocking mode setup failed",
            Self::Unknown => "unknown xART listener failure",
        })
    }
}

impl std::error::Error for XartListenerError {}

/// Read-only proof of the unique live `apple_t1_ncm` kernel interface.
///
/// The interface name, sysfs path, USB path, and addresses never cross the
/// native boundary. The only retained payload is a nonzero kernel index.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ValidatedNcmInterface(NonZeroU32);

impl ValidatedNcmInterface {
    /// Performs one bounded read-only discovery and validation pass.
    ///
    /// # Errors
    ///
    /// Returns a static error when the expected interface is absent,
    /// ambiguous, malformed, inaccessible, or exceeds the discovery bound.
    pub fn discover() -> Result<Self, XartListenerError> {
        checked_interface(xart_live_ffi::discover_interface())
    }

    /// Returns the validated ephemeral kernel interface index.
    #[must_use]
    pub const fn kernel_index(self) -> NonZeroU32 {
        self.0
    }
}

impl fmt::Debug for ValidatedNcmInterface {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ValidatedNcmInterface { index: <redacted> }")
    }
}

/// Static failure while preparing the uniquely validated T1 NCM link.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NcmReadyError {
    InvalidOperation,
    DiscoveryFailed,
    LinkUpFailed,
    InspectionFailed,
    Timeout,
    DeviceChanged,
    ClockFailed,
    WaitFailed,
    Unknown,
}

impl fmt::Display for NcmReadyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidOperation => "invalid NCM readiness operation",
            Self::DiscoveryFailed => "T1 NCM interface discovery failed",
            Self::LinkUpFailed => "T1 NCM link activation failed",
            Self::InspectionFailed => "T1 NCM link readiness inspection failed",
            Self::Timeout => "T1 NCM link readiness timed out",
            Self::DeviceChanged => "T1 NCM interface changed during activation",
            Self::ClockFailed => "T1 NCM readiness clock failed",
            Self::WaitFailed => "T1 NCM readiness wait failed",
            Self::Unknown => "unknown T1 NCM readiness failure",
        })
    }
}

impl std::error::Error for NcmReadyError {}

/// Brings the uniquely validated T1 NCM interface up and waits boundedly for
/// usable IPv6 link-local addressing.
///
/// # Errors
///
/// Returns a static, identifier-free failure if discovery, link mutation,
/// readiness, timing, or post-mutation revalidation cannot be proven.
pub fn prepare_ncm_link(expected_interface: &OsStr) -> Result<(), NcmReadyError> {
    let expected_interface =
        CString::new(expected_interface.as_bytes()).map_err(|_| NcmReadyError::InvalidOperation)?;
    xart_live_ffi::prepare_ncm_link(&expected_interface).map_err(map_ready_status)
}

/// Redacted live-boundary or admitted-session failure.
#[derive(Debug)]
pub enum XartLiveError {
    Listener(XartListenerError),
    Activation(ActivationError),
    Admission(PeerAdmissionError),
    Connection(XartConnectionError),
}

impl fmt::Display for XartLiveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Listener(error) => error.fmt(formatter),
            Self::Activation(error) => write!(formatter, "xART device activation failed: {error}"),
            Self::Admission(error) => write!(formatter, "xART peer rejected: {error}"),
            Self::Connection(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for XartLiveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Listener(error) => Some(error),
            Self::Activation(error) => Some(error),
            Self::Admission(error) => Some(error),
            Self::Connection(error) => Some(error),
        }
    }
}

/// One listener bound to the uniquely validated live `apple_t1_ncm` device.
///
/// The listener is IPv6-only, close-on-exec, nonblocking, and bound with
/// `SO_BINDTODEVICE`. The interface name is used only transiently inside the
/// native boundary and is never retained or exposed here.
pub struct DynamicXartListener {
    listener: TcpListener,
    lifecycle: XartServiceLifecycle,
    lease: DeviceLease,
}

impl fmt::Debug for DynamicXartListener {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DynamicXartListener { device: <redacted> }")
    }
}

impl DynamicXartListener {
    /// Discovers exactly one kernel-validated T1 NCM interface and binds the
    /// fixed xART protocol port exclusively to it.
    ///
    /// # Errors
    ///
    /// Returns a static error when discovery is absent, ambiguous, malformed,
    /// or exceeds its bound, or when socket creation/binding cannot be proven.
    pub fn discover_and_bind() -> Result<Self, XartLiveError> {
        let opened = xart_live_ffi::open_listener()
            .map_err(|status| XartLiveError::Listener(map_status(status)))?;
        let interface =
            checked_interface(Ok(opened.interface_index)).map_err(XartLiveError::Listener)?;
        let descriptor = InterfaceDescriptor::new(
            interface.kernel_index().get(),
            APPLE_T1_NCM_DRIVER,
            APPLE_VENDOR_ID,
            APPLE_T1_PRODUCT_ID,
            APPLE_T1_NCM_CONTROL_INTERFACE,
        );
        let mut lifecycle = XartServiceLifecycle::default();
        let lease = lifecycle
            .device_added(&descriptor)
            .map_err(XartLiveError::Activation)?;
        Ok(Self {
            listener: TcpListener::from(opened.descriptor),
            lifecycle,
            lease,
        })
    }

    /// Accepts and serves one queued connection.
    ///
    /// The native boundary re-reads the listener's bound interface and captures
    /// the accepted IPv6 peer before returning the descriptor. Rust admits that
    /// evidence before the existing session entry point configures timeouts or
    /// parses a single protocol byte. The session entry point independently
    /// re-reads the peer endpoint before its final admission.
    ///
    /// # Errors
    ///
    /// `WouldBlock` and `Interrupted` are explicit so a caller-owned event loop
    /// can retry. Permanent listener, admission, and session failures remain
    /// endpoint- and payload-redacted.
    pub fn serve_next(&self, store: &XartStore) -> Result<(), XartLiveError> {
        let accepted = xart_live_ffi::accept(self.listener.as_raw_fd())
            .map_err(|status| XartLiveError::Listener(map_status(status)))?;
        let peer = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::from(accepted.peer_address),
            accepted.peer_port,
            0,
            accepted.peer_scope_id,
        ));
        let observation = PeerObservation::new(accepted.listener_interface_index, peer);
        self.lifecycle
            .with_admitted_peer(self.lease, observation, || ())
            .map_err(XartLiveError::Admission)?;

        serve_admitted_tcp_connection(
            TcpStream::from(accepted.descriptor),
            &self.lifecycle,
            self.lease,
            accepted.listener_interface_index,
            store,
        )
        .map_err(XartLiveError::Connection)
    }

    /// Changes the fully validated listener to blocking acceptance for the
    /// production daemon loop.
    ///
    /// Binding and peer inspection are unchanged: accepted connections still
    /// pass through the native reinspection and Rust admission boundaries.
    ///
    /// # Errors
    ///
    /// Returns a static error if the kernel refuses the mode transition.
    pub fn use_blocking_accept(&self) -> Result<(), XartLiveError> {
        self.listener
            .set_nonblocking(false)
            .map_err(|_| XartLiveError::Listener(XartListenerError::BlockingModeFailed))
    }
}

impl AsFd for DynamicXartListener {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.listener.as_fd()
    }
}

fn checked_interface(result: Result<u32, i32>) -> Result<ValidatedNcmInterface, XartListenerError> {
    let index = result.map_err(map_status)?;
    NonZeroU32::new(index)
        .map(ValidatedNcmInterface)
        .ok_or(XartListenerError::Unknown)
}

fn map_status(status: i32) -> XartListenerError {
    match status {
        1 => XartListenerError::InvalidArgument,
        2 => XartListenerError::EnumerationFailed,
        3 => XartListenerError::CandidateLimit,
        4 => XartListenerError::DeviceNotFound,
        5 => XartListenerError::DeviceAmbiguous,
        6 => XartListenerError::SocketFailed,
        7 => XartListenerError::BindFailed,
        8 => XartListenerError::ListenFailed,
        9 => XartListenerError::InspectionFailed,
        10 => XartListenerError::WrongInterface,
        11 => XartListenerError::WouldBlock,
        12 => XartListenerError::Interrupted,
        13 => XartListenerError::AcceptFailed,
        14 => XartListenerError::WrongPeerFamily,
        _ => XartListenerError::Unknown,
    }
}

fn map_ready_status(status: i32) -> NcmReadyError {
    match status {
        1 => NcmReadyError::InvalidOperation,
        2 => NcmReadyError::DiscoveryFailed,
        3 => NcmReadyError::LinkUpFailed,
        4 => NcmReadyError::InspectionFailed,
        5 => NcmReadyError::Timeout,
        6 => NcmReadyError::DeviceChanged,
        7 => NcmReadyError::ClockFailed,
        8 => NcmReadyError::WaitFailed,
        _ => NcmReadyError::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_every_native_failure_without_endpoint_data() {
        let expected = [
            XartListenerError::InvalidArgument,
            XartListenerError::EnumerationFailed,
            XartListenerError::CandidateLimit,
            XartListenerError::DeviceNotFound,
            XartListenerError::DeviceAmbiguous,
            XartListenerError::SocketFailed,
            XartListenerError::BindFailed,
            XartListenerError::ListenFailed,
            XartListenerError::InspectionFailed,
            XartListenerError::WrongInterface,
            XartListenerError::WouldBlock,
            XartListenerError::Interrupted,
            XartListenerError::AcceptFailed,
            XartListenerError::WrongPeerFamily,
        ];
        for (status, expected) in (1_i32..).zip(expected) {
            assert_eq!(map_status(status), expected);
        }
        assert_eq!(map_status(0), XartListenerError::Unknown);
        assert_eq!(map_status(99), XartListenerError::Unknown);
    }

    #[test]
    fn read_only_discovery_preserves_exact_static_outcomes() {
        assert_eq!(
            checked_interface(Err(4)),
            Err(XartListenerError::DeviceNotFound)
        );
        assert_eq!(
            checked_interface(Err(5)),
            Err(XartListenerError::DeviceAmbiguous)
        );
        assert_eq!(
            checked_interface(Err(2)),
            Err(XartListenerError::EnumerationFailed)
        );
        assert_eq!(checked_interface(Ok(0)), Err(XartListenerError::Unknown));

        let interface = checked_interface(Ok(41)).expect("accept synthetic validated index");
        assert_eq!(interface.kernel_index(), NonZeroU32::new(41).unwrap());
    }

    #[test]
    fn maps_every_ncm_readiness_failure() {
        let expected = [
            NcmReadyError::InvalidOperation,
            NcmReadyError::DiscoveryFailed,
            NcmReadyError::LinkUpFailed,
            NcmReadyError::InspectionFailed,
            NcmReadyError::Timeout,
            NcmReadyError::DeviceChanged,
            NcmReadyError::ClockFailed,
            NcmReadyError::WaitFailed,
        ];
        for (status, expected) in (1_i32..).zip(expected) {
            assert_eq!(map_ready_status(status), expected);
        }
        assert_eq!(map_ready_status(0), NcmReadyError::Unknown);
        assert_eq!(map_ready_status(99), NcmReadyError::Unknown);
    }
}

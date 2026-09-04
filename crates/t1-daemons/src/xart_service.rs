//! Device lifecycle and pre-protocol admission for the T1 xART service.

use std::fmt;
use std::net::{Ipv6Addr, SocketAddr};
use std::num::NonZeroU32;

const APPLE_VENDOR_ID: u16 = 0x05ac;
const APPLE_T1_PRODUCT_ID: u16 = 0x8600;
const APPLE_T1_NCM_CONTROL_INTERFACE: u8 = 4;
const APPLE_T1_NCM_DRIVER: &str = "apple_t1_ncm";
const BRIDGEOS_XART_PEER: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0xaede, 0x48ff, 0xfe33, 0x4455);

/// Network-interface identity supplied by the device-event adapter.
///
/// The live adapter must obtain these values from the kernel device associated
/// with the udev/systemd event. No interface name, sysfs path, address, or
/// connection identifier is retained after validation.
#[derive(Clone, Eq, PartialEq)]
pub struct InterfaceDescriptor {
    interface_index: u32,
    driver: String,
    usb_vendor_id: u16,
    usb_product_id: u16,
    usb_interface_number: u8,
}

impl InterfaceDescriptor {
    #[must_use]
    pub fn new(
        interface_index: u32,
        driver: impl Into<String>,
        usb_vendor_id: u16,
        usb_product_id: u16,
        usb_interface_number: u8,
    ) -> Self {
        Self {
            interface_index,
            driver: driver.into(),
            usb_vendor_id,
            usb_product_id,
            usb_interface_number,
        }
    }
}

impl fmt::Debug for InterfaceDescriptor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InterfaceDescriptor { identity: <redacted> }")
    }
}

/// Why a supplied network interface is not the expected T1 NCM function.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterfaceValidationError {
    MissingInterfaceIndex,
    WrongDriver,
    WrongUsbDevice,
    WrongUsbInterface,
}

impl fmt::Display for InterfaceValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::MissingInterfaceIndex => "network interface index is missing",
            Self::WrongDriver => "network interface is not owned by the T1 NCM driver",
            Self::WrongUsbDevice => "network interface is not attached to the T1 USB device",
            Self::WrongUsbInterface => "network interface is not the T1 NCM control function",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for InterfaceValidationError {}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ValidatedInterface {
    index: NonZeroU32,
}

fn validate_interface(
    descriptor: &InterfaceDescriptor,
) -> Result<ValidatedInterface, InterfaceValidationError> {
    let index = NonZeroU32::new(descriptor.interface_index)
        .ok_or(InterfaceValidationError::MissingInterfaceIndex)?;
    if descriptor.driver != APPLE_T1_NCM_DRIVER {
        return Err(InterfaceValidationError::WrongDriver);
    }
    if descriptor.usb_vendor_id != APPLE_VENDOR_ID
        || descriptor.usb_product_id != APPLE_T1_PRODUCT_ID
    {
        return Err(InterfaceValidationError::WrongUsbDevice);
    }
    if descriptor.usb_interface_number != APPLE_T1_NCM_CONTROL_INTERFACE {
        return Err(InterfaceValidationError::WrongUsbInterface);
    }
    Ok(ValidatedInterface { index })
}

/// Kernel-observed endpoint for one accepted TCP connection.
///
/// `listener_interface_index` is the interface to which the listener was
/// kernel-bound, using a scoped link-local bind or `SO_BINDTODEVICE`. The live
/// adapter must derive this index from that binding and obtain `peer` from the
/// accepted socket rather than configuration or protocol bytes.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PeerObservation {
    listener_interface_index: u32,
    peer: SocketAddr,
}

impl PeerObservation {
    #[must_use]
    pub const fn new(listener_interface_index: u32, peer: SocketAddr) -> Self {
        Self {
            listener_interface_index,
            peer,
        }
    }
}

impl fmt::Debug for PeerObservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PeerObservation { endpoint: <redacted> }")
    }
}

/// Opaque lifetime token for one device-bound service instance.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct DeviceLease {
    interface_index: NonZeroU32,
    generation: u64,
}

impl fmt::Debug for DeviceLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeviceLease { device: <redacted> }")
    }
}

/// Failure to activate one xART service instance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ActivationError {
    InvalidInterface(InterfaceValidationError),
    DeviceAlreadyActive,
    GenerationExhausted,
}

impl fmt::Display for ActivationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInterface(source) => write!(formatter, "invalid T1 interface: {source}"),
            Self::DeviceAlreadyActive => formatter.write_str("an xART device is already active"),
            Self::GenerationExhausted => formatter.write_str("xART device generation exhausted"),
        }
    }
}

impl std::error::Error for ActivationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidInterface(source) => Some(source),
            _ => None,
        }
    }
}

/// Pre-protocol peer-admission failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerAdmissionError {
    DeviceNotActive,
    ListenerOnWrongInterface,
    PeerIsNotIpv6,
    PeerIsNotLinkLocal,
    PeerOnWrongInterface,
    UnexpectedPeer,
}

impl fmt::Display for PeerAdmissionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::DeviceNotActive => "xART device is not active",
            Self::ListenerOnWrongInterface => "xART listener is not bound to the active device",
            Self::PeerIsNotIpv6 => "xART peer is not IPv6",
            Self::PeerIsNotLinkLocal => "xART peer is not IPv6 link-local",
            Self::PeerOnWrongInterface => "xART peer has the wrong interface scope",
            Self::UnexpectedPeer => "xART peer is not the expected BridgeOS endpoint",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for PeerAdmissionError {}

#[derive(Clone, Copy)]
struct ActiveDevice {
    interface: ValidatedInterface,
    expected_peer: Ipv6Addr,
    generation: u64,
}

/// One-device lifecycle and admission policy for the xART service.
///
/// Udev/systemd owns event delivery and process lifetime. This state machine
/// validates the supplied descriptor, rejects a second active device, binds
/// removal to the exact activation generation, and permits protocol work only
/// for the expected link-local peer on that interface.
#[derive(Default)]
pub struct XartServiceLifecycle {
    active: Option<ActiveDevice>,
    next_generation: u64,
}

impl fmt::Debug for XartServiceLifecycle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(if self.active.is_some() {
            "XartServiceLifecycle { device: <active-redacted> }"
        } else {
            "XartServiceLifecycle { device: <inactive> }"
        })
    }
}

impl XartServiceLifecycle {
    /// Activates one validated T1 NCM device for the `BridgeOS` xART peer.
    ///
    /// The fixed peer is part of the private-link protocol, not a per-machine
    /// identifier, and is neither persisted nor logged. A second interface is
    /// rejected rather than selected arbitrarily.
    ///
    /// # Errors
    ///
    /// Returns an error when the supplied descriptor is not the T1 NCM
    /// function, another device is active, or a unique lifecycle generation
    /// can no longer be allocated.
    pub fn device_added(
        &mut self,
        descriptor: &InterfaceDescriptor,
    ) -> Result<DeviceLease, ActivationError> {
        let interface =
            validate_interface(descriptor).map_err(ActivationError::InvalidInterface)?;
        if self.active.is_some() {
            return Err(ActivationError::DeviceAlreadyActive);
        }

        let generation = self
            .next_generation
            .checked_add(1)
            .ok_or(ActivationError::GenerationExhausted)?;
        self.next_generation = generation;
        self.active = Some(ActiveDevice {
            interface,
            expected_peer: BRIDGEOS_XART_PEER,
            generation,
        });
        Ok(DeviceLease {
            interface_index: interface.index,
            generation,
        })
    }

    /// Tears down only the service instance created by the matching add event.
    ///
    /// A delayed removal from an older generation cannot stop a replacement
    /// device that reused the same kernel interface index.
    pub fn device_removed(&mut self, lease: DeviceLease) -> bool {
        let matches = self.active.is_some_and(|active| {
            active.interface.index == lease.interface_index && active.generation == lease.generation
        });
        if matches {
            self.active = None;
        }
        matches
    }

    /// Runs protocol work only after interface and peer admission succeeds.
    ///
    /// The callback is the protocol-parser boundary. It is never evaluated for
    /// loopback, ordinary-network, other-interface, ambiguous, or stale peers.
    /// The live adapter must kernel-bind the listener to the validated device;
    /// an accepted socket may report either zero or that interface's scope ID.
    ///
    /// # Errors
    ///
    /// Returns an error unless the lease is current and the observed peer is
    /// the exact interface-scoped link-local endpoint admitted at activation.
    pub fn with_admitted_peer<T>(
        &self,
        lease: DeviceLease,
        observation: PeerObservation,
        protocol: impl FnOnce() -> T,
    ) -> Result<T, PeerAdmissionError> {
        self.admit(lease, observation)?;
        Ok(protocol())
    }

    fn admit(
        &self,
        lease: DeviceLease,
        observation: PeerObservation,
    ) -> Result<(), PeerAdmissionError> {
        let Some(active) = self.active.filter(|active| {
            active.interface.index == lease.interface_index && active.generation == lease.generation
        }) else {
            return Err(PeerAdmissionError::DeviceNotActive);
        };
        let interface_index = active.interface.index.get();
        if observation.listener_interface_index != interface_index {
            return Err(PeerAdmissionError::ListenerOnWrongInterface);
        }
        let SocketAddr::V6(peer) = observation.peer else {
            return Err(PeerAdmissionError::PeerIsNotIpv6);
        };
        if !peer.ip().is_unicast_link_local() {
            return Err(PeerAdmissionError::PeerIsNotLinkLocal);
        }
        if peer.scope_id() != 0 && peer.scope_id() != interface_index {
            return Err(PeerAdmissionError::PeerOnWrongInterface);
        }
        if peer.ip() != &active.expected_peer {
            return Err(PeerAdmissionError::UnexpectedPeer);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::net::{Ipv4Addr, SocketAddrV4, SocketAddrV6};

    const SYNTHETIC_INTERFACE_INDEX: u32 = 41;

    fn descriptor(interface_index: u32) -> InterfaceDescriptor {
        InterfaceDescriptor::new(
            interface_index,
            APPLE_T1_NCM_DRIVER,
            APPLE_VENDOR_ID,
            APPLE_T1_PRODUCT_ID,
            APPLE_T1_NCM_CONTROL_INTERFACE,
        )
    }

    const fn expected_peer() -> Ipv6Addr {
        BRIDGEOS_XART_PEER
    }

    fn observation(
        listener_interface_index: u32,
        address: Ipv6Addr,
        scope_id: u32,
    ) -> PeerObservation {
        PeerObservation::new(
            listener_interface_index,
            SocketAddr::V6(SocketAddrV6::new(address, 49_000, 0, scope_id)),
        )
    }

    fn active() -> (XartServiceLifecycle, DeviceLease) {
        let mut lifecycle = XartServiceLifecycle::default();
        let lease = lifecycle
            .device_added(&descriptor(SYNTHETIC_INTERFACE_INDEX))
            .expect("activate synthetic T1 interface");
        (lifecycle, lease)
    }

    #[test]
    fn validates_the_complete_supplied_interface_identity() {
        let invalid = [
            (
                InterfaceDescriptor::new(
                    0,
                    APPLE_T1_NCM_DRIVER,
                    APPLE_VENDOR_ID,
                    APPLE_T1_PRODUCT_ID,
                    APPLE_T1_NCM_CONTROL_INTERFACE,
                ),
                InterfaceValidationError::MissingInterfaceIndex,
            ),
            (
                InterfaceDescriptor::new(
                    SYNTHETIC_INTERFACE_INDEX,
                    "cdc_ncm",
                    APPLE_VENDOR_ID,
                    APPLE_T1_PRODUCT_ID,
                    APPLE_T1_NCM_CONTROL_INTERFACE,
                ),
                InterfaceValidationError::WrongDriver,
            ),
            (
                InterfaceDescriptor::new(
                    SYNTHETIC_INTERFACE_INDEX,
                    APPLE_T1_NCM_DRIVER,
                    0x1234,
                    APPLE_T1_PRODUCT_ID,
                    APPLE_T1_NCM_CONTROL_INTERFACE,
                ),
                InterfaceValidationError::WrongUsbDevice,
            ),
            (
                InterfaceDescriptor::new(
                    SYNTHETIC_INTERFACE_INDEX,
                    APPLE_T1_NCM_DRIVER,
                    APPLE_VENDOR_ID,
                    APPLE_T1_PRODUCT_ID,
                    9,
                ),
                InterfaceValidationError::WrongUsbInterface,
            ),
        ];

        for (descriptor, expected) in invalid {
            let mut lifecycle = XartServiceLifecycle::default();
            assert_eq!(
                lifecycle.device_added(&descriptor),
                Err(ActivationError::InvalidInterface(expected))
            );
        }
    }

    #[test]
    fn permits_only_one_descriptor_validated_device() {
        let mut lifecycle = XartServiceLifecycle::default();
        let lease = lifecycle
            .device_added(&descriptor(SYNTHETIC_INTERFACE_INDEX))
            .expect("activate first device");
        assert_eq!(
            lifecycle.device_added(&descriptor(SYNTHETIC_INTERFACE_INDEX + 1)),
            Err(ActivationError::DeviceAlreadyActive)
        );
        assert!(lifecycle.device_removed(lease));
    }

    #[test]
    fn admits_the_expected_peer_with_kernel_reported_or_implicit_scope() {
        let (lifecycle, lease) = active();
        for scope_id in [SYNTHETIC_INTERFACE_INDEX, 0] {
            let protocol_called = Cell::new(false);
            let result = lifecycle.with_admitted_peer(
                lease,
                observation(SYNTHETIC_INTERFACE_INDEX, expected_peer(), scope_id),
                || {
                    protocol_called.set(true);
                    17
                },
            );

            assert_eq!(result, Ok(17));
            assert!(protocol_called.get());
        }
    }

    #[test]
    fn rejects_foreign_endpoints_before_protocol_work() {
        let (lifecycle, lease) = active();
        let other_link_local = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x5678);
        let cases = [
            (
                PeerObservation::new(
                    SYNTHETIC_INTERFACE_INDEX,
                    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 49_000)),
                ),
                PeerAdmissionError::PeerIsNotIpv6,
            ),
            (
                observation(
                    SYNTHETIC_INTERFACE_INDEX,
                    Ipv6Addr::LOCALHOST,
                    SYNTHETIC_INTERFACE_INDEX,
                ),
                PeerAdmissionError::PeerIsNotLinkLocal,
            ),
            (
                observation(
                    SYNTHETIC_INTERFACE_INDEX,
                    expected_peer(),
                    SYNTHETIC_INTERFACE_INDEX + 1,
                ),
                PeerAdmissionError::PeerOnWrongInterface,
            ),
            (
                observation(
                    SYNTHETIC_INTERFACE_INDEX,
                    other_link_local,
                    SYNTHETIC_INTERFACE_INDEX,
                ),
                PeerAdmissionError::UnexpectedPeer,
            ),
            (
                observation(
                    SYNTHETIC_INTERFACE_INDEX + 1,
                    expected_peer(),
                    SYNTHETIC_INTERFACE_INDEX,
                ),
                PeerAdmissionError::ListenerOnWrongInterface,
            ),
            (
                observation(SYNTHETIC_INTERFACE_INDEX + 1, expected_peer(), 0),
                PeerAdmissionError::ListenerOnWrongInterface,
            ),
        ];

        for (observation, expected) in cases {
            let protocol_called = Cell::new(false);
            let result = lifecycle.with_admitted_peer(lease, observation, || {
                protocol_called.set(true);
            });
            assert_eq!(result, Err(expected));
            assert!(!protocol_called.get());
        }
    }

    #[test]
    fn removal_is_bound_to_the_exact_device_generation() {
        let (mut lifecycle, first) = active();
        assert!(lifecycle.device_removed(first));
        let second = lifecycle
            .device_added(&descriptor(SYNTHETIC_INTERFACE_INDEX))
            .expect("reactivate reused interface index");

        assert!(!lifecycle.device_removed(first));
        let result = lifecycle.with_admitted_peer(
            second,
            observation(
                SYNTHETIC_INTERFACE_INDEX,
                expected_peer(),
                SYNTHETIC_INTERFACE_INDEX,
            ),
            || "parsed",
        );
        assert_eq!(result, Ok("parsed"));
        assert!(lifecycle.device_removed(second));
        assert_eq!(
            lifecycle.with_admitted_peer(
                second,
                observation(
                    SYNTHETIC_INTERFACE_INDEX,
                    expected_peer(),
                    SYNTHETIC_INTERFACE_INDEX,
                ),
                || "must not parse",
            ),
            Err(PeerAdmissionError::DeviceNotActive)
        );
    }

    #[test]
    fn debug_output_redacts_runtime_device_and_peer_values() {
        let descriptor = descriptor(SYNTHETIC_INTERFACE_INDEX);
        let (lifecycle, lease) = active();
        let peer = observation(
            SYNTHETIC_INTERFACE_INDEX,
            expected_peer(),
            SYNTHETIC_INTERFACE_INDEX,
        );

        for output in [
            format!("{descriptor:?}"),
            format!("{lifecycle:?}"),
            format!("{lease:?}"),
            format!("{peer:?}"),
        ] {
            assert!(!output.contains("41"));
            assert!(!output.contains("fe80"));
            assert!(!output.contains("1234"));
        }
    }
}

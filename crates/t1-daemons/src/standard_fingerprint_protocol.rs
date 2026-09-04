//! Transport-free wire contract for standard fingerprint clients.
//!
//! This additive protocol does not replace the fixed eight-byte direct
//! authentication protocol. A future root-client transport must authenticate
//! its peer independently and resolve the canonical username supplied here.
//! Packets contain no client-supplied numeric UID, filesystem path, command,
//! device handle, or hardware payload.

use std::fmt;

/// Complete fixed header length.
pub const HEADER_SIZE: usize = 12;
/// Maximum accepted packet, including the fixed header.
pub const MAX_PACKET_SIZE: usize = 1024;
/// Wire bound for one canonical account name.
pub const MAX_USERNAME_SIZE: usize = 255;
/// Maximum identities accepted from Mesa or retained in standard metadata.
pub const MAX_IDENTITIES: u8 = 5;
/// Maximum identities T1 permits for one active enrollment owner.
pub const MAX_OWNER_IDENTITIES: u8 = 3;
/// Maximum enrollment stages advertised or reported.
pub const MAX_ENROLL_STAGES: u8 = 100;

const MAGIC: &[u8; 4] = b"T1FP";
const VERSION: u8 = 1;
const RESERVED: u16 = 0;

const CLIENT_CAPABILITIES: u8 = 0x01;
const CLIENT_OPEN: u8 = 0x02;
const CLIENT_LIST: u8 = 0x03;
const CLIENT_ENROLL: u8 = 0x04;
const CLIENT_VERIFY: u8 = 0x05;
const CLIENT_IDENTIFY: u8 = 0x06;
const CLIENT_DELETE: u8 = 0x07;
const CLIENT_CANCEL: u8 = 0x08;

const SERVER_CAPABILITIES: u8 = 0x81;
const SERVER_OPENED: u8 = 0x82;
const SERVER_IDENTITIES: u8 = 0x83;
const SERVER_ENROLL_PROGRESS: u8 = 0x84;
const SERVER_TERMINAL: u8 = 0x85;

/// A validated portable account name carried for later broker-side lookup.
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct Username(Box<str>);

impl Username {
    /// Validates one bounded account name for canonical broker-side lookup.
    ///
    /// Account naming rules belong to the active NSS source, not this wire
    /// layer. The later resolver must require an exact canonical-name match and
    /// a non-root UID. This layer rejects only values that cannot cross the C
    /// resolver boundary safely.
    ///
    /// # Errors
    ///
    /// Returns [`ProtocolError::InvalidUsername`] for an empty, oversized, or
    /// non-canonical value.
    pub fn new(value: &str) -> Result<Self, ProtocolError> {
        let bytes = value.as_bytes();
        if bytes.is_empty() || bytes.len() > MAX_USERNAME_SIZE || bytes.contains(&0) {
            return Err(ProtocolError::InvalidUsername);
        }
        Ok(Self(value.into()))
    }

    /// Returns the validated account name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Username {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Username(<redacted>)")
    }
}

/// Opaque nonzero 16-byte Mesa identity identifier.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct IdentityId([u8; 16]);

impl IdentityId {
    /// Validates an opaque identity identifier returned by Mesa.
    ///
    /// # Errors
    ///
    /// Mesa does not promise UUID version or variant bits. Only its documented
    /// all-zero sentinel is rejected here.
    pub fn new(bytes: [u8; 16]) -> Result<Self, ProtocolError> {
        if bytes == [0; 16] {
            Err(ProtocolError::InvalidIdentity)
        } else {
            Ok(Self(bytes))
        }
    }

    /// Returns the opaque wire bytes.
    #[must_use]
    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }
}

impl fmt::Debug for IdentityId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IdentityId(<redacted>)")
    }
}

/// Standard ten-finger labels; no free-form label crosses the boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FingerLabel {
    LeftThumb = 1,
    LeftIndex = 2,
    LeftMiddle = 3,
    LeftRing = 4,
    LeftLittle = 5,
    RightThumb = 6,
    RightIndex = 7,
    RightMiddle = 8,
    RightRing = 9,
    RightLittle = 10,
}

impl FingerLabel {
    const fn decode(value: u8) -> Result<Self, ProtocolError> {
        match value {
            1 => Ok(Self::LeftThumb),
            2 => Ok(Self::LeftIndex),
            3 => Ok(Self::LeftMiddle),
            4 => Ok(Self::LeftRing),
            5 => Ok(Self::LeftLittle),
            6 => Ok(Self::RightThumb),
            7 => Ok(Self::RightIndex),
            8 => Ok(Self::RightMiddle),
            9 => Ok(Self::RightRing),
            10 => Ok(Self::RightLittle),
            _ => Err(ProtocolError::InvalidFingerLabel),
        }
    }
}

/// One listed standard identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    pub id: IdentityId,
    pub finger: FingerLabel,
}

/// Operations a server may advertise.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilitySet(u16);

impl CapabilitySet {
    pub const LIST: Self = Self(1 << 0);
    pub const ENROLL: Self = Self(1 << 1);
    pub const VERIFY: Self = Self(1 << 2);
    pub const IDENTIFY: Self = Self(1 << 3);
    pub const DELETE: Self = Self(1 << 4);
    pub const CANCEL: Self = Self(1 << 5);

    const KNOWN_BITS: u16 = Self::LIST.0
        | Self::ENROLL.0
        | Self::VERIFY.0
        | Self::IDENTIFY.0
        | Self::DELETE.0
        | Self::CANCEL.0;
    const IDENTITY_OPERATION_BITS: u16 =
        Self::LIST.0 | Self::ENROLL.0 | Self::VERIFY.0 | Self::IDENTIFY.0 | Self::DELETE.0;

    /// Creates a capability set from known bits only.
    ///
    /// # Errors
    ///
    /// Rejects every unassigned capability bit.
    pub const fn from_bits(bits: u16) -> Result<Self, ProtocolError> {
        if bits & !Self::KNOWN_BITS == 0 {
            Ok(Self(bits))
        } else {
            Err(ProtocolError::InvalidCapabilities)
        }
    }

    /// Returns the exact wire bits.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Returns whether every bit in `capability` is present.
    #[must_use]
    pub const fn contains(self, capability: Self) -> bool {
        self.0 & capability.0 == capability.0
    }
}

impl std::ops::BitOr for CapabilitySet {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

/// Validated capability response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Capabilities {
    operations: CapabilitySet,
    max_enroll_stages: u8,
    max_identities: u8,
}

impl Capabilities {
    /// Creates a self-consistent capability response.
    ///
    /// # Errors
    ///
    /// Enrollment requires a nonzero bounded stage count. Any identity
    /// operation requires a nonzero bounded identity capacity. Unsupported
    /// operation families require the corresponding bound to be zero.
    pub const fn new(
        operations: CapabilitySet,
        max_enroll_stages: u8,
        max_identities: u8,
    ) -> Result<Self, ProtocolError> {
        let enrollment = operations.contains(CapabilitySet::ENROLL);
        let identity_operations = operations.bits() & CapabilitySet::IDENTITY_OPERATION_BITS != 0;
        if max_enroll_stages > MAX_ENROLL_STAGES
            || enrollment != (max_enroll_stages != 0)
            || max_identities > MAX_IDENTITIES
            || identity_operations != (max_identities != 0)
        {
            return Err(ProtocolError::InvalidCapabilities);
        }
        Ok(Self {
            operations,
            max_enroll_stages,
            max_identities,
        })
    }

    #[must_use]
    pub const fn operations(self) -> CapabilitySet {
        self.operations
    }

    #[must_use]
    pub const fn max_enroll_stages(self) -> u8 {
        self.max_enroll_stages
    }

    #[must_use]
    pub const fn max_identities(self) -> u8 {
        self.max_identities
    }
}

/// Validated enrollment progress.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnrollProgress {
    completed_stage: u8,
    total_stages: u8,
}

impl EnrollProgress {
    /// Creates a bounded progress event.
    ///
    /// # Errors
    ///
    /// Rejects zero, reversed, or oversized stage ranges.
    pub const fn new(completed_stage: u8, total_stages: u8) -> Result<Self, ProtocolError> {
        if completed_stage == 0
            || total_stages == 0
            || completed_stage > total_stages
            || total_stages > MAX_ENROLL_STAGES
        {
            return Err(ProtocolError::InvalidRange);
        }
        Ok(Self {
            completed_stage,
            total_stages,
        })
    }

    #[must_use]
    pub const fn completed_stage(self) -> u8 {
        self.completed_stage
    }

    #[must_use]
    pub const fn total_stages(self) -> u8 {
        self.total_stages
    }
}

/// Client packets accepted on the future standard-fingerprint connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientMessage {
    GetCapabilities,
    Open,
    ListIdentities,
    Enroll {
        username: Username,
        finger: FingerLabel,
    },
    Verify {
        username: Username,
        identity: IdentityId,
    },
    Identify {
        username: Username,
    },
    DeleteIdentity {
        username: Username,
        identity: IdentityId,
    },
    Cancel,
}

/// Connection-scoped operation classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationKind {
    ListIdentities,
    Enroll,
    Verify,
    Identify,
    DeleteIdentity,
}

/// How one client message participates in single-connection arbitration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectionAction {
    QueryCapabilities,
    Open,
    Start(OperationKind),
    CancelActive,
}

impl ClientMessage {
    /// Classifies the message without introducing multiplexing tokens.
    ///
    /// A transport can allow one `Start` at a time on a connection, reject a
    /// second with `Busy`, and bind `CancelActive` to that sole operation.
    #[must_use]
    pub const fn connection_action(&self) -> ConnectionAction {
        match self {
            Self::GetCapabilities => ConnectionAction::QueryCapabilities,
            Self::Open => ConnectionAction::Open,
            Self::ListIdentities => ConnectionAction::Start(OperationKind::ListIdentities),
            Self::Enroll { .. } => ConnectionAction::Start(OperationKind::Enroll),
            Self::Verify { .. } => ConnectionAction::Start(OperationKind::Verify),
            Self::Identify { .. } => ConnectionAction::Start(OperationKind::Identify),
            Self::DeleteIdentity { .. } => ConnectionAction::Start(OperationKind::DeleteIdentity),
            Self::Cancel => ConnectionAction::CancelActive,
        }
    }
}

/// Typed terminal result; only enrollment and matching carry an identity ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalOutcome {
    Completed,
    Enrolled(IdentityId),
    Matched(IdentityId),
    NoMatch,
    Cancelled,
    DeviceLost,
    Busy,
    SecondOwner,
    Unsupported,
    Duplicate,
    CapacityFull,
    Error,
}

/// Server packets returned on the same connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServerMessage {
    Capabilities(Capabilities),
    Opened,
    IdentityList {
        owner: Option<Username>,
        identities: Vec<Identity>,
    },
    EnrollProgress(EnrollProgress),
    Terminal(TerminalOutcome),
}

impl ServerMessage {
    /// Returns whether the message completes its request or active operation.
    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        !matches!(self, Self::EnrollProgress(_))
    }
}

/// Payload-free protocol failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    WrongLength,
    PacketTooLarge,
    BadMagic,
    UnsupportedVersion,
    UnsupportedType,
    NonzeroReserved,
    PayloadLengthMismatch,
    InvalidUsername,
    InvalidFingerLabel,
    InvalidIdentity,
    InvalidCapabilities,
    InvalidRange,
    InvalidPayload,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WrongLength => "standard fingerprint packet has the wrong length",
            Self::PacketTooLarge => "standard fingerprint packet exceeds its bound",
            Self::BadMagic => "standard fingerprint packet has invalid magic",
            Self::UnsupportedVersion => "standard fingerprint protocol version is unsupported",
            Self::UnsupportedType => "standard fingerprint message type is unsupported",
            Self::NonzeroReserved => "standard fingerprint reserved field is nonzero",
            Self::PayloadLengthMismatch => "standard fingerprint payload length does not match",
            Self::InvalidUsername => "standard fingerprint username is invalid",
            Self::InvalidFingerLabel => "standard fingerprint finger label is invalid",
            Self::InvalidIdentity => "standard fingerprint identity is invalid",
            Self::InvalidCapabilities => "standard fingerprint capabilities are invalid",
            Self::InvalidRange => "standard fingerprint numeric range is invalid",
            Self::InvalidPayload => "standard fingerprint payload is invalid",
        })
    }
}

impl std::error::Error for ProtocolError {}

/// Encodes one complete client packet.
///
/// # Errors
///
/// Returns a payload-free validation error if a public collection exceeds its
/// protocol bound.
pub fn encode_client(message: &ClientMessage) -> Result<Vec<u8>, ProtocolError> {
    let mut payload = Vec::new();
    let message_type = match message {
        ClientMessage::GetCapabilities => CLIENT_CAPABILITIES,
        ClientMessage::Open => CLIENT_OPEN,
        ClientMessage::ListIdentities => CLIENT_LIST,
        ClientMessage::Enroll { username, finger } => {
            encode_username(&mut payload, username);
            payload.push(*finger as u8);
            CLIENT_ENROLL
        }
        ClientMessage::Verify { username, identity } => {
            encode_username(&mut payload, username);
            payload.extend_from_slice(&identity.as_bytes());
            CLIENT_VERIFY
        }
        ClientMessage::Identify { username } => {
            encode_username(&mut payload, username);
            CLIENT_IDENTIFY
        }
        ClientMessage::DeleteIdentity { username, identity } => {
            encode_username(&mut payload, username);
            payload.extend_from_slice(&identity.as_bytes());
            CLIENT_DELETE
        }
        ClientMessage::Cancel => CLIENT_CANCEL,
    };
    encode_packet(message_type, &payload)
}

/// Decodes one complete client packet.
///
/// # Errors
///
/// Strictly rejects wrong bounds, header fields, types, payload lengths,
/// usernames, labels, identities, and trailing bytes.
pub fn decode_client(packet: &[u8]) -> Result<ClientMessage, ProtocolError> {
    let (message_type, payload) = decode_packet(packet)?;
    let mut cursor = 0;
    let message = match message_type {
        CLIENT_CAPABILITIES => {
            require_empty(payload)?;
            ClientMessage::GetCapabilities
        }
        CLIENT_OPEN => {
            require_empty(payload)?;
            ClientMessage::Open
        }
        CLIENT_LIST => {
            require_empty(payload)?;
            ClientMessage::ListIdentities
        }
        CLIENT_ENROLL => ClientMessage::Enroll {
            username: decode_username(payload, &mut cursor)?,
            finger: FingerLabel::decode(take_byte(payload, &mut cursor)?)?,
        },
        CLIENT_VERIFY => ClientMessage::Verify {
            username: decode_username(payload, &mut cursor)?,
            identity: decode_identity(payload, &mut cursor)?,
        },
        CLIENT_IDENTIFY => ClientMessage::Identify {
            username: decode_username(payload, &mut cursor)?,
        },
        CLIENT_DELETE => ClientMessage::DeleteIdentity {
            username: decode_username(payload, &mut cursor)?,
            identity: decode_identity(payload, &mut cursor)?,
        },
        CLIENT_CANCEL => {
            require_empty(payload)?;
            ClientMessage::Cancel
        }
        _ => return Err(ProtocolError::UnsupportedType),
    };
    if cursor != payload.len() {
        return Err(ProtocolError::InvalidPayload);
    }
    Ok(message)
}

/// Encodes one complete server packet.
///
/// # Errors
///
/// Rejects oversized, duplicate, nil, or otherwise invalid public list data.
pub fn encode_server(message: &ServerMessage) -> Result<Vec<u8>, ProtocolError> {
    let mut payload = Vec::new();
    let message_type = match message {
        ServerMessage::Capabilities(capabilities) => {
            payload.extend_from_slice(&capabilities.operations().bits().to_be_bytes());
            payload.push(capabilities.max_enroll_stages());
            payload.push(capabilities.max_identities());
            SERVER_CAPABILITIES
        }
        ServerMessage::Opened => SERVER_OPENED,
        ServerMessage::IdentityList { owner, identities } => {
            validate_identity_list(owner.as_ref(), identities)?;
            payload.push(u8::try_from(identities.len()).map_err(|_| ProtocolError::InvalidRange)?);
            if let Some(owner) = owner {
                encode_username(&mut payload, owner);
            }
            for identity in identities {
                payload.extend_from_slice(&identity.id.as_bytes());
                payload.push(identity.finger as u8);
            }
            SERVER_IDENTITIES
        }
        ServerMessage::EnrollProgress(progress) => {
            payload.push(progress.completed_stage());
            payload.push(progress.total_stages());
            SERVER_ENROLL_PROGRESS
        }
        ServerMessage::Terminal(outcome) => {
            match outcome {
                TerminalOutcome::Completed => payload.push(1),
                TerminalOutcome::Enrolled(identity) => {
                    payload.push(2);
                    payload.extend_from_slice(&identity.as_bytes());
                }
                TerminalOutcome::Matched(identity) => {
                    payload.push(3);
                    payload.extend_from_slice(&identity.as_bytes());
                }
                TerminalOutcome::NoMatch => payload.push(4),
                TerminalOutcome::Cancelled => payload.push(5),
                TerminalOutcome::DeviceLost => payload.push(6),
                TerminalOutcome::Busy => payload.push(7),
                TerminalOutcome::SecondOwner => payload.push(8),
                TerminalOutcome::Unsupported => payload.push(9),
                TerminalOutcome::Error => payload.push(10),
                TerminalOutcome::Duplicate => payload.push(11),
                TerminalOutcome::CapacityFull => payload.push(12),
            }
            SERVER_TERMINAL
        }
    };
    encode_packet(message_type, &payload)
}

/// Decodes one complete server packet.
///
/// # Errors
///
/// Strictly rejects wrong bounds, header fields, types, capability bits,
/// identity lists, progress ranges, outcome shapes, and trailing bytes.
pub fn decode_server(packet: &[u8]) -> Result<ServerMessage, ProtocolError> {
    let (message_type, payload) = decode_packet(packet)?;
    let mut cursor = 0;
    let message = match message_type {
        SERVER_CAPABILITIES => {
            if payload.len() != 4 {
                return Err(ProtocolError::InvalidPayload);
            }
            let operations =
                CapabilitySet::from_bits(u16::from_be_bytes([payload[0], payload[1]]))?;
            cursor = payload.len();
            ServerMessage::Capabilities(Capabilities::new(operations, payload[2], payload[3])?)
        }
        SERVER_OPENED => {
            require_empty(payload)?;
            ServerMessage::Opened
        }
        SERVER_IDENTITIES => {
            let count = usize::from(take_byte(payload, &mut cursor)?);
            if count > usize::from(MAX_IDENTITIES) {
                return Err(ProtocolError::InvalidPayload);
            }
            let owner = if count == 0 {
                None
            } else {
                Some(decode_username(payload, &mut cursor)?)
            };
            let mut identities = Vec::with_capacity(count);
            for _ in 0..count {
                identities.push(Identity {
                    id: decode_identity(payload, &mut cursor)?,
                    finger: FingerLabel::decode(take_byte(payload, &mut cursor)?)?,
                });
            }
            validate_identity_list(owner.as_ref(), &identities)?;
            ServerMessage::IdentityList { owner, identities }
        }
        SERVER_ENROLL_PROGRESS => {
            if payload.len() != 2 {
                return Err(ProtocolError::InvalidPayload);
            }
            cursor = payload.len();
            ServerMessage::EnrollProgress(EnrollProgress::new(payload[0], payload[1])?)
        }
        SERVER_TERMINAL => {
            let code = take_byte(payload, &mut cursor)?;
            let outcome = match code {
                1 => TerminalOutcome::Completed,
                2 => TerminalOutcome::Enrolled(decode_identity(payload, &mut cursor)?),
                3 => TerminalOutcome::Matched(decode_identity(payload, &mut cursor)?),
                4 => TerminalOutcome::NoMatch,
                5 => TerminalOutcome::Cancelled,
                6 => TerminalOutcome::DeviceLost,
                7 => TerminalOutcome::Busy,
                8 => TerminalOutcome::SecondOwner,
                9 => TerminalOutcome::Unsupported,
                10 => TerminalOutcome::Error,
                11 => TerminalOutcome::Duplicate,
                12 => TerminalOutcome::CapacityFull,
                _ => return Err(ProtocolError::InvalidPayload),
            };
            ServerMessage::Terminal(outcome)
        }
        _ => return Err(ProtocolError::UnsupportedType),
    };
    if cursor != payload.len() {
        return Err(ProtocolError::InvalidPayload);
    }
    Ok(message)
}

fn encode_packet(message_type: u8, payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let packet_size = HEADER_SIZE
        .checked_add(payload.len())
        .ok_or(ProtocolError::PacketTooLarge)?;
    if packet_size > MAX_PACKET_SIZE {
        return Err(ProtocolError::PacketTooLarge);
    }
    let payload_length = u16::try_from(payload.len()).map_err(|_| ProtocolError::PacketTooLarge)?;
    let mut packet = Vec::with_capacity(packet_size);
    packet.extend_from_slice(MAGIC);
    packet.push(VERSION);
    packet.push(message_type);
    packet.extend_from_slice(&RESERVED.to_be_bytes());
    packet.extend_from_slice(&payload_length.to_be_bytes());
    packet.extend_from_slice(&RESERVED.to_be_bytes());
    packet.extend_from_slice(payload);
    Ok(packet)
}

fn decode_packet(packet: &[u8]) -> Result<(u8, &[u8]), ProtocolError> {
    if packet.len() < HEADER_SIZE {
        return Err(ProtocolError::WrongLength);
    }
    if packet.len() > MAX_PACKET_SIZE {
        return Err(ProtocolError::PacketTooLarge);
    }
    if &packet[..4] != MAGIC {
        return Err(ProtocolError::BadMagic);
    }
    if packet[4] != VERSION {
        return Err(ProtocolError::UnsupportedVersion);
    }
    if u16::from_be_bytes([packet[6], packet[7]]) != RESERVED
        || u16::from_be_bytes([packet[10], packet[11]]) != RESERVED
    {
        return Err(ProtocolError::NonzeroReserved);
    }
    let payload_length = usize::from(u16::from_be_bytes([packet[8], packet[9]]));
    if payload_length != packet.len() - HEADER_SIZE {
        return Err(ProtocolError::PayloadLengthMismatch);
    }
    Ok((packet[5], &packet[HEADER_SIZE..]))
}

fn encode_username(payload: &mut Vec<u8>, username: &Username) {
    payload.push(u8::try_from(username.as_str().len()).expect("validated username bound"));
    payload.extend_from_slice(username.as_str().as_bytes());
}

fn decode_username(payload: &[u8], cursor: &mut usize) -> Result<Username, ProtocolError> {
    let length = usize::from(take_byte(payload, cursor)?);
    let bytes = take_slice(payload, cursor, length)?;
    let value = std::str::from_utf8(bytes).map_err(|_| ProtocolError::InvalidUsername)?;
    Username::new(value)
}

fn decode_identity(payload: &[u8], cursor: &mut usize) -> Result<IdentityId, ProtocolError> {
    let bytes: [u8; 16] = take_slice(payload, cursor, 16)?
        .try_into()
        .map_err(|_| ProtocolError::InvalidIdentity)?;
    IdentityId::new(bytes)
}

fn take_byte(payload: &[u8], cursor: &mut usize) -> Result<u8, ProtocolError> {
    let value = *payload.get(*cursor).ok_or(ProtocolError::InvalidPayload)?;
    *cursor += 1;
    Ok(value)
}

fn take_slice<'a>(
    payload: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], ProtocolError> {
    let end = cursor
        .checked_add(length)
        .ok_or(ProtocolError::InvalidPayload)?;
    let value = payload
        .get(*cursor..end)
        .ok_or(ProtocolError::InvalidPayload)?;
    *cursor = end;
    Ok(value)
}

fn require_empty(payload: &[u8]) -> Result<(), ProtocolError> {
    if payload.is_empty() {
        Ok(())
    } else {
        Err(ProtocolError::InvalidPayload)
    }
}

fn validate_identity_list(
    owner: Option<&Username>,
    identities: &[Identity],
) -> Result<(), ProtocolError> {
    if identities.len() > usize::from(MAX_IDENTITIES) {
        return Err(ProtocolError::InvalidRange);
    }
    if owner.is_some() == identities.is_empty() {
        return Err(ProtocolError::InvalidPayload);
    }
    for (index, identity) in identities.iter().enumerate() {
        if identities[..index]
            .iter()
            .any(|earlier| earlier.id == identity.id)
        {
            return Err(ProtocolError::InvalidIdentity);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_protocol::{
        APPROVE_REQUEST, AUTHENTICATE_REQUEST, CANCEL_REQUEST, ENROLL_REQUEST,
    };

    fn username() -> Username {
        Username::new("synthetic-user").unwrap()
    }

    fn identity(seed: u8) -> IdentityId {
        let mut bytes = [0_u8; 16];
        bytes[0] = seed;
        IdentityId::new(bytes).unwrap()
    }

    fn with_payload(message_type: u8, payload: &[u8]) -> Vec<u8> {
        encode_packet(message_type, payload).unwrap()
    }

    #[test]
    fn existing_direct_authentication_packets_are_unchanged() {
        assert_eq!(AUTHENTICATE_REQUEST, b"T1AUTH\x01\n");
        assert_eq!(APPROVE_REQUEST, b"T1APRV\x01\n");
        assert_eq!(ENROLL_REQUEST, b"T1ENRL\x01\n");
        assert_eq!(CANCEL_REQUEST, b"T1CNCL\x01\n");
    }

    #[test]
    fn fixed_header_is_exact_and_network_ordered() {
        assert_eq!(
            encode_client(&ClientMessage::GetCapabilities).unwrap(),
            b"T1FP\x01\x01\0\0\0\0\0\0"
        );
        let packet = encode_client(&ClientMessage::Identify {
            username: username(),
        })
        .unwrap();
        assert_eq!(packet[8..10], [0, 15]);
    }

    #[test]
    fn all_client_messages_round_trip() {
        let messages = [
            ClientMessage::GetCapabilities,
            ClientMessage::Open,
            ClientMessage::ListIdentities,
            ClientMessage::Enroll {
                username: username(),
                finger: FingerLabel::RightIndex,
            },
            ClientMessage::Verify {
                username: username(),
                identity: identity(1),
            },
            ClientMessage::Identify {
                username: username(),
            },
            ClientMessage::DeleteIdentity {
                username: username(),
                identity: identity(2),
            },
            ClientMessage::Cancel,
        ];
        for message in messages {
            let encoded = encode_client(&message).unwrap();
            assert!(encoded.len() <= MAX_PACKET_SIZE);
            assert_eq!(decode_client(&encoded), Ok(message));
        }
    }

    #[test]
    fn client_wire_contains_a_name_and_no_numeric_uid_field() {
        let message = ClientMessage::Enroll {
            username: Username::new("agent_7").unwrap(),
            finger: FingerLabel::LeftThumb,
        };
        let packet = encode_client(&message).unwrap();
        assert_eq!(&packet[HEADER_SIZE..], b"\x07agent_7\x01");
    }

    #[test]
    fn connection_actions_express_one_active_operation() {
        assert_eq!(
            ClientMessage::GetCapabilities.connection_action(),
            ConnectionAction::QueryCapabilities
        );
        assert_eq!(
            ClientMessage::Open.connection_action(),
            ConnectionAction::Open
        );
        assert_eq!(
            ClientMessage::Enroll {
                username: username(),
                finger: FingerLabel::LeftIndex,
            }
            .connection_action(),
            ConnectionAction::Start(OperationKind::Enroll)
        );
        assert_eq!(
            ClientMessage::Cancel.connection_action(),
            ConnectionAction::CancelActive
        );
    }

    #[test]
    fn all_server_messages_and_terminal_outcomes_round_trip() {
        let flags = CapabilitySet::LIST
            | CapabilitySet::ENROLL
            | CapabilitySet::VERIFY
            | CapabilitySet::IDENTIFY
            | CapabilitySet::DELETE
            | CapabilitySet::CANCEL;
        let capabilities = Capabilities::new(flags, 8, MAX_IDENTITIES).unwrap();
        let server_messages = [
            ServerMessage::Capabilities(capabilities),
            ServerMessage::Opened,
            ServerMessage::IdentityList {
                owner: Some(username()),
                identities: vec![Identity {
                    id: identity(1),
                    finger: FingerLabel::LeftMiddle,
                }],
            },
            ServerMessage::EnrollProgress(EnrollProgress::new(3, 8).unwrap()),
        ];
        for message in server_messages {
            let encoded = encode_server(&message).unwrap();
            assert_eq!(decode_server(&encoded), Ok(message));
        }

        for outcome in [
            TerminalOutcome::Completed,
            TerminalOutcome::Enrolled(identity(2)),
            TerminalOutcome::Matched(identity(3)),
            TerminalOutcome::NoMatch,
            TerminalOutcome::Cancelled,
            TerminalOutcome::DeviceLost,
            TerminalOutcome::Busy,
            TerminalOutcome::SecondOwner,
            TerminalOutcome::Unsupported,
            TerminalOutcome::Duplicate,
            TerminalOutcome::CapacityFull,
            TerminalOutcome::Error,
        ] {
            let message = ServerMessage::Terminal(outcome);
            assert_eq!(
                decode_server(&encode_server(&message).unwrap()),
                Ok(message)
            );
        }
    }

    #[test]
    fn only_progress_is_nonterminal() {
        assert!(!ServerMessage::EnrollProgress(EnrollProgress::new(1, 2).unwrap()).is_terminal());
        assert!(ServerMessage::Terminal(TerminalOutcome::Busy).is_terminal());
        assert!(
            ServerMessage::IdentityList {
                owner: None,
                identities: Vec::new()
            }
            .is_terminal()
        );
    }

    #[test]
    fn usernames_are_bounded_nul_free_and_redacted_for_later_nss_resolution() {
        for valid in [
            "a",
            "_service",
            "agent-7",
            "Directory.User",
            "a name accepted only if NSS returns it canonically",
        ] {
            let name = Username::new(valid).unwrap();
            assert_eq!(name.as_str(), valid);
        }
        let redacted = Username::new("synthetic-account-name").unwrap();
        assert!(!format!("{redacted:?}").contains(redacted.as_str()));
        for invalid in ["", "contains\0nul", &"a".repeat(MAX_USERNAME_SIZE + 1)] {
            assert_eq!(Username::new(invalid), Err(ProtocolError::InvalidUsername));
        }
    }

    #[test]
    fn malformed_headers_and_bounds_fail_closed() {
        let valid = encode_client(&ClientMessage::Open).unwrap();
        assert_eq!(
            decode_client(&valid[..HEADER_SIZE - 1]),
            Err(ProtocolError::WrongLength)
        );

        let mut oversized = vec![0_u8; MAX_PACKET_SIZE + 1];
        oversized[..HEADER_SIZE].copy_from_slice(&valid);
        assert_eq!(
            decode_client(&oversized),
            Err(ProtocolError::PacketTooLarge)
        );

        let mut bad = valid.clone();
        bad[0] ^= 1;
        assert_eq!(decode_client(&bad), Err(ProtocolError::BadMagic));
        bad = valid.clone();
        bad[4] += 1;
        assert_eq!(decode_client(&bad), Err(ProtocolError::UnsupportedVersion));
        bad = valid.clone();
        bad[5] = 0x7f;
        assert_eq!(decode_client(&bad), Err(ProtocolError::UnsupportedType));
        bad = valid.clone();
        bad[6] = 1;
        assert_eq!(decode_client(&bad), Err(ProtocolError::NonzeroReserved));
        bad = valid.clone();
        bad[11] = 1;
        assert_eq!(decode_client(&bad), Err(ProtocolError::NonzeroReserved));
        bad = valid.clone();
        bad[9] = 1;
        assert_eq!(
            decode_client(&bad),
            Err(ProtocolError::PayloadLengthMismatch)
        );
    }

    #[test]
    fn malformed_client_payloads_fail_closed() {
        assert_eq!(
            decode_client(&with_payload(CLIENT_OPEN, &[0])),
            Err(ProtocolError::InvalidPayload)
        );
        assert_eq!(
            decode_client(&with_payload(CLIENT_LIST, &[3, b'a'])),
            Err(ProtocolError::InvalidPayload)
        );
        assert_eq!(
            decode_client(&with_payload(CLIENT_ENROLL, &[1, 0, 1])),
            Err(ProtocolError::InvalidUsername)
        );
        assert_eq!(
            decode_client(&with_payload(CLIENT_ENROLL, &[1, b'a', 11])),
            Err(ProtocolError::InvalidFingerLabel)
        );
        let mut nil_verify = vec![1, b'a'];
        nil_verify.extend_from_slice(&[0; 16]);
        assert_eq!(
            decode_client(&with_payload(CLIENT_VERIFY, &nil_verify)),
            Err(ProtocolError::InvalidIdentity)
        );
        let mut trailing = encode_client(&ClientMessage::Identify {
            username: username(),
        })
        .unwrap();
        trailing.push(0);
        let payload_length = u16::try_from(trailing.len() - HEADER_SIZE).unwrap();
        trailing[8..10].copy_from_slice(&payload_length.to_be_bytes());
        assert_eq!(decode_client(&trailing), Err(ProtocolError::InvalidPayload));
    }

    #[test]
    fn capabilities_and_progress_reject_unknown_or_inconsistent_ranges() {
        assert_eq!(
            CapabilitySet::from_bits(1 << 15),
            Err(ProtocolError::InvalidCapabilities)
        );
        assert_eq!(
            Capabilities::new(CapabilitySet::ENROLL, 0, 1),
            Err(ProtocolError::InvalidCapabilities)
        );
        assert_eq!(
            Capabilities::new(CapabilitySet::CANCEL, 1, 0),
            Err(ProtocolError::InvalidCapabilities)
        );
        assert_eq!(
            Capabilities::new(CapabilitySet::LIST, 0, 0),
            Err(ProtocolError::InvalidCapabilities)
        );
        assert_eq!(
            Capabilities::new(CapabilitySet::LIST, 0, MAX_IDENTITIES + 1),
            Err(ProtocolError::InvalidCapabilities)
        );
        assert_eq!(EnrollProgress::new(0, 4), Err(ProtocolError::InvalidRange));
        assert_eq!(EnrollProgress::new(5, 4), Err(ProtocolError::InvalidRange));
        assert_eq!(
            EnrollProgress::new(1, MAX_ENROLL_STAGES + 1),
            Err(ProtocolError::InvalidRange)
        );
    }

    #[test]
    fn malformed_server_payloads_fail_closed() {
        assert_eq!(
            decode_server(&with_payload(SERVER_CAPABILITIES, &[0, 0, 0])),
            Err(ProtocolError::InvalidPayload)
        );
        assert_eq!(
            decode_server(&with_payload(SERVER_CAPABILITIES, &[0x80, 0, 0, 0])),
            Err(ProtocolError::InvalidCapabilities)
        );
        assert_eq!(
            decode_server(&with_payload(SERVER_ENROLL_PROGRESS, &[2, 1])),
            Err(ProtocolError::InvalidRange)
        );
        assert_eq!(
            decode_server(&with_payload(SERVER_TERMINAL, &[13])),
            Err(ProtocolError::InvalidPayload)
        );
        assert_eq!(
            decode_server(&with_payload(SERVER_TERMINAL, &[1, 0])),
            Err(ProtocolError::InvalidPayload)
        );
        assert_eq!(
            decode_server(&with_payload(SERVER_TERMINAL, &[2])),
            Err(ProtocolError::InvalidPayload)
        );
    }

    #[test]
    fn identity_lists_reject_duplicates_nil_and_overflow() {
        let duplicate = Identity {
            id: identity(1),
            finger: FingerLabel::LeftThumb,
        };
        assert_eq!(
            encode_server(&ServerMessage::IdentityList {
                owner: Some(username()),
                identities: vec![duplicate, duplicate]
            }),
            Err(ProtocolError::InvalidIdentity)
        );

        let mut nil = vec![1, 1, b'a'];
        nil.extend_from_slice(&[0; 16]);
        nil.push(FingerLabel::LeftThumb as u8);
        assert_eq!(
            decode_server(&with_payload(SERVER_IDENTITIES, &nil)),
            Err(ProtocolError::InvalidIdentity)
        );

        let too_many = vec![duplicate; usize::from(MAX_IDENTITIES) + 1];
        assert_eq!(
            encode_server(&ServerMessage::IdentityList {
                owner: Some(username()),
                identities: too_many
            }),
            Err(ProtocolError::InvalidRange)
        );
        assert_eq!(
            encode_server(&ServerMessage::IdentityList {
                owner: Some(username()),
                identities: Vec::new()
            }),
            Err(ProtocolError::InvalidPayload)
        );
        assert_eq!(
            encode_server(&ServerMessage::IdentityList {
                owner: None,
                identities: vec![duplicate]
            }),
            Err(ProtocolError::InvalidPayload)
        );
    }

    #[test]
    fn identity_ids_are_opaque_and_do_not_require_uuid_bits() {
        let id = IdentityId::new([0xff; 16]).unwrap();
        assert_eq!(id.as_bytes(), [0xff; 16]);
        assert_eq!(
            IdentityId::new([0; 16]),
            Err(ProtocolError::InvalidIdentity)
        );
    }
}

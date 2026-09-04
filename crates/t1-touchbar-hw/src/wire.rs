//! Typed Touch Bar hardware IPC v1 wire messages.

use std::{error::Error, fmt};

use crate::{
    digitizer::DisplayDimensions,
    frame_state::DamageRectangle,
    packet::{self, Packet, PacketError},
};

pub const PROTOCOL_MINOR: u16 = 1;
pub const MAX_BUFFERS: u32 = 3;
pub const MAX_DAMAGE_RECTANGLES: usize = 64;
pub const MAX_CONTACTS: usize = 10;
pub const MAX_KEYS: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum MessageType {
    Hello = 0x0001,
    RegisterBuffer = 0x0002,
    SubmitFrame = 0x0003,
    TapKeys = 0x0004,
    SetDisplayBrightness = 0x0005,
    SetKeyboardBacklight = 0x0006,
    CancelTouchId = 0x0007,
    StepDisplayBrightness = 0x0008,
    StepKeyboardBacklight = 0x0009,
    HelloAck = 0x8001,
    Ack = 0x8002,
    Error = 0x8003,
    FrameReleased = 0x9001,
    InputFrame = 0x9002,
}

impl MessageType {
    #[must_use]
    pub const fn wire_value(self) -> u16 {
        self as u16
    }

    #[must_use]
    pub const fn direction(self) -> Direction {
        match self {
            Self::Hello
            | Self::RegisterBuffer
            | Self::SubmitFrame
            | Self::TapKeys
            | Self::SetDisplayBrightness
            | Self::SetKeyboardBacklight
            | Self::CancelTouchId
            | Self::StepDisplayBrightness
            | Self::StepKeyboardBacklight => Direction::ClientToService,
            Self::HelloAck | Self::Ack | Self::Error | Self::FrameReleased | Self::InputFrame => {
                Direction::ServiceToClient
            }
        }
    }

    #[must_use]
    pub const fn class(self) -> MessageClass {
        match self {
            Self::Hello
            | Self::RegisterBuffer
            | Self::SubmitFrame
            | Self::TapKeys
            | Self::SetDisplayBrightness
            | Self::SetKeyboardBacklight
            | Self::CancelTouchId
            | Self::StepDisplayBrightness
            | Self::StepKeyboardBacklight => MessageClass::Request,
            Self::HelloAck | Self::Ack | Self::Error => MessageClass::Response,
            Self::FrameReleased | Self::InputFrame => MessageClass::Event,
        }
    }

    #[must_use]
    pub const fn ancillary_expectation(self) -> AncillaryExpectation {
        match self {
            Self::RegisterBuffer => AncillaryExpectation::OneDescriptor,
            _ => AncillaryExpectation::None,
        }
    }

    #[must_use]
    pub const fn from_wire(value: u16) -> Option<Self> {
        Some(match value {
            0x0001 => Self::Hello,
            0x0002 => Self::RegisterBuffer,
            0x0003 => Self::SubmitFrame,
            0x0004 => Self::TapKeys,
            0x0005 => Self::SetDisplayBrightness,
            0x0006 => Self::SetKeyboardBacklight,
            0x0007 => Self::CancelTouchId,
            0x0008 => Self::StepDisplayBrightness,
            0x0009 => Self::StepKeyboardBacklight,
            0x8001 => Self::HelloAck,
            0x8002 => Self::Ack,
            0x8003 => Self::Error,
            0x9001 => Self::FrameReleased,
            0x9002 => Self::InputFrame,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    ClientToService,
    ServiceToClient,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageClass {
    Request,
    Response,
    Event,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AncillaryExpectation {
    None,
    OneDescriptor,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AncillaryMetadata {
    pub rights_descriptor_count: usize,
    pub control_truncated: bool,
    pub has_other_control: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FeatureBits(u64);

impl FeatureBits {
    pub const SEALED_MEMFD_FRAMES: Self = Self(0x01);
    pub const INPUT_FRAMES: Self = Self(0x02);
    pub const TYPED_KEY_TAPS: Self = Self(0x04);
    pub const DISPLAY_BRIGHTNESS: Self = Self(0x08);
    pub const KEYBOARD_BACKLIGHT: Self = Self(0x10);
    pub const TOUCH_ID_CANCELLATION: Self = Self(0x20);
    pub const INITIAL_SERVICE: Self = Self(0x07);
    pub const ASSIGNED: Self = Self(0x3f);

    #[must_use]
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    #[must_use]
    pub const fn bits(self) -> u64 {
        self.0
    }

    #[must_use]
    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }
}

impl std::ops::BitOr for FeatureBits {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum PixelFormat {
    Xrgb8888 = 1,
}

impl PixelFormat {
    #[must_use]
    pub const fn wire_value(self) -> u32 {
        self as u32
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum ErrorCode {
    Unsupported = 1,
    UnsupportedFeature = 2,
    ResourceLimit = 3,
    InvalidBuffer = 4,
    UnknownBuffer = 5,
    BufferBusy = 6,
    ActionDenied = 7,
    DeviceUnavailable = 8,
    IoFailure = 9,
    InternalFailure = 10,
}

impl ErrorCode {
    #[must_use]
    pub const fn wire_value(self) -> u32 {
        self as u32
    }

    const fn from_wire(value: u32) -> Option<Self> {
        Some(match value {
            1 => Self::Unsupported,
            2 => Self::UnsupportedFeature,
            3 => Self::ResourceLimit,
            4 => Self::InvalidBuffer,
            5 => Self::UnknownBuffer,
            6 => Self::BufferBusy,
            7 => Self::ActionDenied,
            8 => Self::DeviceUnavailable,
            9 => Self::IoFailure,
            10 => Self::InternalFailure,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub enum KeyCode {
    Escape = 1,
    F1 = 59,
    F2 = 60,
    F3 = 61,
    F4 = 62,
    F5 = 63,
    F6 = 64,
    F7 = 65,
    F8 = 66,
    F9 = 67,
    F10 = 68,
    F11 = 87,
    F12 = 88,
}

impl KeyCode {
    #[must_use]
    pub const fn wire_value(self) -> u16 {
        self as u16
    }

    const fn from_wire(value: u16) -> Option<Self> {
        Some(match value {
            1 => Self::Escape,
            59 => Self::F1,
            60 => Self::F2,
            61 => Self::F3,
            62 => Self::F4,
            63 => Self::F5,
            64 => Self::F6,
            65 => Self::F7,
            66 => Self::F8,
            67 => Self::F9,
            68 => Self::F10,
            87 => Self::F11,
            88 => Self::F12,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Percentage(u8);

impl Percentage {
    /// Creates a wire percentage in the inclusive zero-through-100 range.
    ///
    /// # Errors
    ///
    /// Returns [`WireError::InvalidRange`] above 100.
    pub fn new(value: u8) -> Result<Self, WireError> {
        if value > 100 {
            return Err(WireError::InvalidRange);
        }
        Ok(Self(value))
    }

    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hello {
    pub minor: u16,
    pub required_features: FeatureBits,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HelloAck {
    pub minor: u16,
    pub width: u32,
    pub height: u32,
    pub pixel_format: PixelFormat,
    pub max_buffers: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegisterBuffer {
    pub buffer_id: u32,
    pub stride: u32,
    pub byte_length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmitFrame {
    pub buffer_id: u32,
    pub frame_id: u64,
    pub damage: Vec<DamageRectangle>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TapKeys {
    pub keys: Vec<KeyCode>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameReleased {
    pub buffer_id: u32,
    pub frame_id: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InputContact {
    pub id: u8,
    pub tip: bool,
    pub in_range: bool,
    pub x: u32,
    pub y: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireInputFrame {
    pub monotonic_ns: u64,
    pub fn_pressed: bool,
    pub contacts: Vec<InputContact>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum StepDirection {
    Down = 0,
    Up = 1,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownRequest {
    pub message_type: u16,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClientMessage {
    Hello(Hello),
    RegisterBuffer(RegisterBuffer),
    SubmitFrame(SubmitFrame),
    TapKeys(TapKeys),
    SetDisplayBrightness(Percentage),
    SetKeyboardBacklight(Percentage),
    CancelTouchId,
    StepDisplayBrightness(StepDirection),
    StepKeyboardBacklight(StepDirection),
    Unknown(UnknownRequest),
}

impl ClientMessage {
    #[must_use]
    pub const fn message_type(&self) -> Option<MessageType> {
        match self {
            Self::Hello(_) => Some(MessageType::Hello),
            Self::RegisterBuffer(_) => Some(MessageType::RegisterBuffer),
            Self::SubmitFrame(_) => Some(MessageType::SubmitFrame),
            Self::TapKeys(_) => Some(MessageType::TapKeys),
            Self::SetDisplayBrightness(_) => Some(MessageType::SetDisplayBrightness),
            Self::SetKeyboardBacklight(_) => Some(MessageType::SetKeyboardBacklight),
            Self::CancelTouchId => Some(MessageType::CancelTouchId),
            Self::StepDisplayBrightness(_) => Some(MessageType::StepDisplayBrightness),
            Self::StepKeyboardBacklight(_) => Some(MessageType::StepKeyboardBacklight),
            Self::Unknown(_) => None,
        }
    }

    #[must_use]
    pub const fn ancillary_expectation(&self) -> AncillaryExpectation {
        match self.message_type() {
            Some(message_type) => message_type.ancillary_expectation(),
            None => AncillaryExpectation::None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceMessage {
    HelloAck(HelloAck),
    Ack,
    Error(ErrorCode),
    FrameReleased(FrameReleased),
    InputFrame(WireInputFrame),
}

impl ServiceMessage {
    #[must_use]
    pub const fn message_type(&self) -> MessageType {
        match self {
            Self::HelloAck(_) => MessageType::HelloAck,
            Self::Ack => MessageType::Ack,
            Self::Error(_) => MessageType::Error,
            Self::FrameReleased(_) => MessageType::FrameReleased,
            Self::InputFrame(_) => MessageType::InputFrame,
        }
    }

    #[must_use]
    pub const fn ancillary_expectation(&self) -> AncillaryExpectation {
        AncillaryExpectation::None
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Envelope<Message> {
    pub request_id: u32,
    pub message: Message,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WireError {
    Packet(PacketError),
    WrongDirection,
    WrongState,
    UnknownServiceMessage,
    ZeroRequestId,
    NonzeroEventRequestId,
    WrongPayloadLength,
    ReservedNonzero,
    InvalidBoolean,
    InvalidCount,
    InvalidRange,
    DuplicateKey,
    DuplicateContact,
    AncillaryTruncated,
    UnexpectedAncillary,
    DescriptorCountMismatch,
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Packet(error) => return error.fmt(formatter),
            Self::WrongDirection => "message is invalid in this protocol direction",
            Self::WrongState => "message is invalid in the current protocol state",
            Self::UnknownServiceMessage => "service sent an unknown message type",
            Self::ZeroRequestId => "request or response identifier is zero",
            Self::NonzeroEventRequestId => "unsolicited event identifier is nonzero",
            Self::WrongPayloadLength => "message payload has the wrong length",
            Self::ReservedNonzero => "reserved message field is nonzero",
            Self::InvalidBoolean => "message boolean is not zero or one",
            Self::InvalidCount => "message count is out of range",
            Self::InvalidRange => "message field is out of range",
            Self::DuplicateKey => "key tap repeats a key code",
            Self::DuplicateContact => "input frame repeats an active contact identifier",
            Self::AncillaryTruncated => "message ancillary data was truncated",
            Self::UnexpectedAncillary => "message carries unsupported ancillary data",
            Self::DescriptorCountMismatch => "message descriptor count does not match its type",
        };
        formatter.write_str(message)
    }
}

impl Error for WireError {}

impl From<PacketError> for WireError {
    fn from(error: PacketError) -> Self {
        Self::Packet(error)
    }
}

/// Decodes one client request, enforcing direction, handshake phase, request
/// identifiers, payload fields, negotiated bounds, and ancillary shape.
///
/// `dimensions` is absent before `Hello` completes and present afterward.
///
/// # Errors
///
/// Returns [`WireError`] for any connection-closing protocol violation. A
/// well-framed unknown request is returned as [`ClientMessage::Unknown`].
pub fn decode_client(
    bytes: &[u8],
    ancillary: AncillaryMetadata,
    dimensions: Option<DisplayDimensions>,
) -> Result<Envelope<ClientMessage>, WireError> {
    let packet = packet::decode(bytes)?;
    require_request_id(packet.request_id)?;
    let Some(message_type) = MessageType::from_wire(packet.message_type) else {
        if dimensions.is_none() {
            return Err(WireError::WrongState);
        }
        validate_ancillary(AncillaryExpectation::None, ancillary)?;
        return Ok(Envelope {
            request_id: packet.request_id,
            message: ClientMessage::Unknown(UnknownRequest {
                message_type: packet.message_type,
                payload: packet.payload.to_vec(),
            }),
        });
    };
    if message_type.direction() != Direction::ClientToService {
        return Err(WireError::WrongDirection);
    }
    validate_phase(message_type, dimensions.is_some())?;
    validate_ancillary(message_type.ancillary_expectation(), ancillary)?;

    let message = match message_type {
        MessageType::Hello => ClientMessage::Hello(decode_hello(packet.payload)?),
        MessageType::RegisterBuffer => {
            ClientMessage::RegisterBuffer(decode_register_buffer(packet.payload)?)
        }
        MessageType::SubmitFrame => ClientMessage::SubmitFrame(decode_submit_frame(
            packet.payload,
            dimensions.ok_or(WireError::WrongState)?,
        )?),
        MessageType::TapKeys => ClientMessage::TapKeys(decode_tap_keys(packet.payload)?),
        MessageType::SetDisplayBrightness => {
            ClientMessage::SetDisplayBrightness(decode_percentage(packet.payload)?)
        }
        MessageType::SetKeyboardBacklight => {
            ClientMessage::SetKeyboardBacklight(decode_percentage(packet.payload)?)
        }
        MessageType::CancelTouchId => {
            require_length(packet.payload, 0)?;
            ClientMessage::CancelTouchId
        }
        MessageType::StepDisplayBrightness => {
            ClientMessage::StepDisplayBrightness(decode_step_direction(packet.payload)?)
        }
        MessageType::StepKeyboardBacklight => {
            ClientMessage::StepKeyboardBacklight(decode_step_direction(packet.payload)?)
        }
        _ => return Err(WireError::WrongDirection),
    };
    Ok(Envelope {
        request_id: packet.request_id,
        message,
    })
}

/// Decodes one service response or event with v1 validation.
///
/// `dimensions` is absent before `HelloAck` completes and present afterward.
///
/// # Errors
///
/// Returns [`WireError`] for malformed, unknown, wrong-direction, or
/// wrong-phase service messages.
pub fn decode_service(
    bytes: &[u8],
    ancillary: AncillaryMetadata,
    dimensions: Option<DisplayDimensions>,
) -> Result<Envelope<ServiceMessage>, WireError> {
    let packet = packet::decode(bytes)?;
    let message_type =
        MessageType::from_wire(packet.message_type).ok_or(WireError::UnknownServiceMessage)?;
    if message_type.direction() != Direction::ServiceToClient {
        return Err(WireError::WrongDirection);
    }
    validate_phase(message_type, dimensions.is_some())?;
    validate_identifier(message_type.class(), packet.request_id)?;
    validate_ancillary(message_type.ancillary_expectation(), ancillary)?;

    let message = match message_type {
        MessageType::HelloAck => ServiceMessage::HelloAck(decode_hello_ack(packet.payload)?),
        MessageType::Ack => {
            require_length(packet.payload, 0)?;
            ServiceMessage::Ack
        }
        MessageType::Error => ServiceMessage::Error(decode_error(packet.payload)?),
        MessageType::FrameReleased => {
            ServiceMessage::FrameReleased(decode_frame_released(packet.payload)?)
        }
        MessageType::InputFrame => ServiceMessage::InputFrame(decode_input_frame(
            packet.payload,
            dimensions.ok_or(WireError::WrongState)?,
        )?),
        _ => return Err(WireError::WrongDirection),
    };
    Ok(Envelope {
        request_id: packet.request_id,
        message,
    })
}

/// Encodes one client request after applying the same validation as decoding.
///
/// # Errors
///
/// Returns [`WireError`] for an invalid identifier, phase, value, payload size,
/// or attempt to encode a known type through [`ClientMessage::Unknown`].
pub fn encode_client(
    envelope: &Envelope<ClientMessage>,
    dimensions: Option<DisplayDimensions>,
) -> Result<Vec<u8>, WireError> {
    require_request_id(envelope.request_id)?;
    let (message_type, payload) = encode_client_payload(&envelope.message, dimensions)?;
    Packet {
        message_type,
        request_id: envelope.request_id,
        payload: &payload,
    }
    .encode()
    .map_err(Into::into)
}

/// Encodes one service response or event after v1 validation.
///
/// # Errors
///
/// Returns [`WireError`] for an invalid identifier, phase, field, or payload
/// size.
pub fn encode_service(
    envelope: &Envelope<ServiceMessage>,
    dimensions: Option<DisplayDimensions>,
) -> Result<Vec<u8>, WireError> {
    let message_type = envelope.message.message_type();
    validate_phase(message_type, dimensions.is_some())?;
    validate_identifier(message_type.class(), envelope.request_id)?;
    let payload = encode_service_payload(&envelope.message, dimensions)?;
    Packet {
        message_type: message_type.wire_value(),
        request_id: envelope.request_id,
        payload: &payload,
    }
    .encode()
    .map_err(Into::into)
}

fn encode_client_payload(
    message: &ClientMessage,
    dimensions: Option<DisplayDimensions>,
) -> Result<(u16, Vec<u8>), WireError> {
    if let ClientMessage::Unknown(unknown) = message {
        if dimensions.is_none() {
            return Err(WireError::WrongState);
        }
        if MessageType::from_wire(unknown.message_type).is_some() {
            return Err(WireError::WrongDirection);
        }
        return Ok((unknown.message_type, unknown.payload.clone()));
    }
    let message_type = message.message_type().expect("known message has a type");
    validate_phase(message_type, dimensions.is_some())?;
    let mut payload = Vec::new();
    match message {
        ClientMessage::Hello(hello) => {
            payload.extend_from_slice(&hello.minor.to_le_bytes());
            payload.extend_from_slice(&0_u16.to_le_bytes());
            payload.extend_from_slice(&hello.required_features.bits().to_le_bytes());
        }
        ClientMessage::RegisterBuffer(buffer) => {
            validate_nonzero(&buffer.buffer_id)?;
            if buffer.stride == 0 || buffer.byte_length == 0 {
                return Err(WireError::InvalidRange);
            }
            payload.extend_from_slice(&buffer.buffer_id.to_le_bytes());
            payload.extend_from_slice(&buffer.stride.to_le_bytes());
            payload.extend_from_slice(&buffer.byte_length.to_le_bytes());
        }
        ClientMessage::SubmitFrame(frame) => {
            let display = dimensions.ok_or(WireError::WrongState)?;
            validate_nonzero(&frame.buffer_id)?;
            validate_nonzero(&frame.frame_id)?;
            validate_damage(&frame.damage, display)?;
            payload.extend_from_slice(&frame.buffer_id.to_le_bytes());
            payload.extend_from_slice(&frame.frame_id.to_le_bytes());
            payload.extend_from_slice(
                &u32::try_from(frame.damage.len())
                    .map_err(|_| WireError::InvalidCount)?
                    .to_le_bytes(),
            );
            for rectangle in &frame.damage {
                payload.extend_from_slice(&rectangle.x.to_le_bytes());
                payload.extend_from_slice(&rectangle.y.to_le_bytes());
                payload.extend_from_slice(&rectangle.width.to_le_bytes());
                payload.extend_from_slice(&rectangle.height.to_le_bytes());
            }
        }
        ClientMessage::TapKeys(keys) => encode_keys(keys, &mut payload)?,
        ClientMessage::SetDisplayBrightness(percentage)
        | ClientMessage::SetKeyboardBacklight(percentage) => payload.push(percentage.value()),
        ClientMessage::CancelTouchId => {}
        ClientMessage::StepDisplayBrightness(direction)
        | ClientMessage::StepKeyboardBacklight(direction) => payload.push(*direction as u8),
        ClientMessage::Unknown(_) => unreachable!(),
    }
    Ok((message_type.wire_value(), payload))
}

fn encode_service_payload(
    message: &ServiceMessage,
    dimensions: Option<DisplayDimensions>,
) -> Result<Vec<u8>, WireError> {
    let mut payload = Vec::new();
    match message {
        ServiceMessage::HelloAck(ack) => {
            validate_hello_ack(*ack)?;
            payload.extend_from_slice(&ack.minor.to_le_bytes());
            payload.extend_from_slice(&0_u16.to_le_bytes());
            payload.extend_from_slice(&ack.width.to_le_bytes());
            payload.extend_from_slice(&ack.height.to_le_bytes());
            payload.extend_from_slice(&ack.pixel_format.wire_value().to_le_bytes());
            payload.extend_from_slice(&ack.max_buffers.to_le_bytes());
        }
        ServiceMessage::Ack => {}
        ServiceMessage::Error(error) => {
            payload.extend_from_slice(&error.wire_value().to_le_bytes());
        }
        ServiceMessage::FrameReleased(frame) => {
            validate_nonzero(&frame.buffer_id)?;
            validate_nonzero(&frame.frame_id)?;
            payload.extend_from_slice(&frame.buffer_id.to_le_bytes());
            payload.extend_from_slice(&frame.frame_id.to_le_bytes());
        }
        ServiceMessage::InputFrame(frame) => {
            let display = dimensions.ok_or(WireError::WrongState)?;
            validate_input_frame(frame, display)?;
            payload.extend_from_slice(&frame.monotonic_ns.to_le_bytes());
            payload.push(u8::from(frame.fn_pressed));
            payload.push(u8::try_from(frame.contacts.len()).map_err(|_| WireError::InvalidCount)?);
            payload.extend_from_slice(&0_u16.to_le_bytes());
            for contact in &frame.contacts {
                payload.push(contact.id);
                payload.push(u8::from(contact.tip));
                payload.push(u8::from(contact.in_range));
                payload.push(0);
                payload.extend_from_slice(&contact.x.to_le_bytes());
                payload.extend_from_slice(&contact.y.to_le_bytes());
            }
        }
    }
    Ok(payload)
}

fn decode_hello(payload: &[u8]) -> Result<Hello, WireError> {
    require_length(payload, 12)?;
    require_reserved(&payload[2..4])?;
    Ok(Hello {
        minor: read_u16(payload, 0),
        required_features: FeatureBits::from_bits(read_u64(payload, 4)),
    })
}

fn decode_hello_ack(payload: &[u8]) -> Result<HelloAck, WireError> {
    require_length(payload, 20)?;
    require_reserved(&payload[2..4])?;
    let pixel_format = match read_u32(payload, 12) {
        1 => PixelFormat::Xrgb8888,
        _ => return Err(WireError::InvalidRange),
    };
    let ack = HelloAck {
        minor: read_u16(payload, 0),
        width: read_u32(payload, 4),
        height: read_u32(payload, 8),
        pixel_format,
        max_buffers: read_u32(payload, 16),
    };
    validate_hello_ack(ack)?;
    Ok(ack)
}

fn validate_hello_ack(ack: HelloAck) -> Result<(), WireError> {
    if ack.minor > PROTOCOL_MINOR
        || ack.width == 0
        || ack.height == 0
        || !(1..=MAX_BUFFERS).contains(&ack.max_buffers)
    {
        return Err(WireError::InvalidRange);
    }
    Ok(())
}

fn decode_step_direction(payload: &[u8]) -> Result<StepDirection, WireError> {
    require_length(payload, 1)?;
    match payload[0] {
        0 => Ok(StepDirection::Down),
        1 => Ok(StepDirection::Up),
        _ => Err(WireError::InvalidRange),
    }
}

fn decode_register_buffer(payload: &[u8]) -> Result<RegisterBuffer, WireError> {
    require_length(payload, 16)?;
    let buffer = RegisterBuffer {
        buffer_id: read_u32(payload, 0),
        stride: read_u32(payload, 4),
        byte_length: read_u64(payload, 8),
    };
    validate_nonzero(&buffer.buffer_id)?;
    if buffer.stride == 0 || buffer.byte_length == 0 {
        return Err(WireError::InvalidRange);
    }
    Ok(buffer)
}

fn decode_submit_frame(
    payload: &[u8],
    dimensions: DisplayDimensions,
) -> Result<SubmitFrame, WireError> {
    if payload.len() < 16 {
        return Err(WireError::WrongPayloadLength);
    }
    let buffer_id = read_u32(payload, 0);
    let frame_id = read_u64(payload, 4);
    validate_nonzero(&buffer_id)?;
    validate_nonzero(&frame_id)?;
    let count = usize::try_from(read_u32(payload, 12)).map_err(|_| WireError::InvalidCount)?;
    if count > MAX_DAMAGE_RECTANGLES {
        return Err(WireError::InvalidCount);
    }
    let expected = 16_usize
        .checked_add(count.checked_mul(16).ok_or(WireError::InvalidCount)?)
        .ok_or(WireError::InvalidCount)?;
    require_length(payload, expected)?;
    let mut damage = Vec::with_capacity(count);
    for rectangle in payload[16..].as_chunks::<16>().0 {
        damage.push(DamageRectangle {
            x: read_u32(rectangle, 0),
            y: read_u32(rectangle, 4),
            width: read_u32(rectangle, 8),
            height: read_u32(rectangle, 12),
        });
    }
    validate_damage(&damage, dimensions)?;
    Ok(SubmitFrame {
        buffer_id,
        frame_id,
        damage,
    })
}

fn validate_damage(
    damage: &[DamageRectangle],
    dimensions: DisplayDimensions,
) -> Result<(), WireError> {
    if damage.len() > MAX_DAMAGE_RECTANGLES {
        return Err(WireError::InvalidCount);
    }
    if damage.iter().any(|rectangle| {
        rectangle.width == 0
            || rectangle.height == 0
            || rectangle
                .x
                .checked_add(rectangle.width)
                .is_none_or(|right| right > dimensions.width())
            || rectangle
                .y
                .checked_add(rectangle.height)
                .is_none_or(|bottom| bottom > dimensions.height())
    }) {
        return Err(WireError::InvalidRange);
    }
    Ok(())
}

fn decode_tap_keys(payload: &[u8]) -> Result<TapKeys, WireError> {
    require_length(payload, 12)?;
    let count = usize::from(payload[0]);
    if !(1..=MAX_KEYS).contains(&count) {
        return Err(WireError::InvalidCount);
    }
    require_reserved(&payload[1..4])?;
    let mut keys = Vec::with_capacity(count);
    for slot in 0..MAX_KEYS {
        let value = read_u16(payload, 4 + slot * 2);
        if slot < count {
            let key = KeyCode::from_wire(value).ok_or(WireError::InvalidRange)?;
            if keys.contains(&key) {
                return Err(WireError::DuplicateKey);
            }
            keys.push(key);
        } else if value != 0 {
            return Err(WireError::ReservedNonzero);
        }
    }
    Ok(TapKeys { keys })
}

fn encode_keys(keys: &TapKeys, payload: &mut Vec<u8>) -> Result<(), WireError> {
    if !(1..=MAX_KEYS).contains(&keys.keys.len()) {
        return Err(WireError::InvalidCount);
    }
    for (index, key) in keys.keys.iter().enumerate() {
        if keys.keys[..index].contains(key) {
            return Err(WireError::DuplicateKey);
        }
    }
    payload.push(u8::try_from(keys.keys.len()).map_err(|_| WireError::InvalidCount)?);
    payload.extend_from_slice(&[0; 3]);
    for slot in 0..MAX_KEYS {
        let key = keys.keys.get(slot).map_or(0, |key| key.wire_value());
        payload.extend_from_slice(&key.to_le_bytes());
    }
    Ok(())
}

fn decode_percentage(payload: &[u8]) -> Result<Percentage, WireError> {
    require_length(payload, 1)?;
    Percentage::new(payload[0])
}

fn decode_error(payload: &[u8]) -> Result<ErrorCode, WireError> {
    require_length(payload, 4)?;
    ErrorCode::from_wire(read_u32(payload, 0)).ok_or(WireError::InvalidRange)
}

fn decode_frame_released(payload: &[u8]) -> Result<FrameReleased, WireError> {
    require_length(payload, 12)?;
    let frame = FrameReleased {
        buffer_id: read_u32(payload, 0),
        frame_id: read_u64(payload, 4),
    };
    validate_nonzero(&frame.buffer_id)?;
    validate_nonzero(&frame.frame_id)?;
    Ok(frame)
}

fn decode_input_frame(
    payload: &[u8],
    dimensions: DisplayDimensions,
) -> Result<WireInputFrame, WireError> {
    if payload.len() < 12 {
        return Err(WireError::WrongPayloadLength);
    }
    let fn_pressed = decode_bool(payload[8])?;
    let count = usize::from(payload[9]);
    if count > MAX_CONTACTS {
        return Err(WireError::InvalidCount);
    }
    require_reserved(&payload[10..12])?;
    let expected = 12_usize
        .checked_add(count.checked_mul(12).ok_or(WireError::InvalidCount)?)
        .ok_or(WireError::InvalidCount)?;
    require_length(payload, expected)?;
    let mut contacts = Vec::with_capacity(count);
    for contact in payload[12..].as_chunks::<12>().0 {
        require_reserved(&contact[3..4])?;
        contacts.push(InputContact {
            id: contact[0],
            tip: decode_bool(contact[1])?,
            in_range: decode_bool(contact[2])?,
            x: read_u32(contact, 4),
            y: read_u32(contact, 8),
        });
    }
    let frame = WireInputFrame {
        monotonic_ns: read_u64(payload, 0),
        fn_pressed,
        contacts,
    };
    validate_input_frame(&frame, dimensions)?;
    Ok(frame)
}

fn validate_input_frame(
    frame: &WireInputFrame,
    dimensions: DisplayDimensions,
) -> Result<(), WireError> {
    if frame.contacts.len() > MAX_CONTACTS {
        return Err(WireError::InvalidCount);
    }
    let mut active_ids = 0_u16;
    for contact in &frame.contacts {
        if contact.id > 15 || contact.x >= dimensions.width() || contact.y >= dimensions.height() {
            return Err(WireError::InvalidRange);
        }
        if contact.tip || contact.in_range {
            let id = 1_u16 << contact.id;
            if active_ids & id != 0 {
                return Err(WireError::DuplicateContact);
            }
            active_ids |= id;
        }
    }
    Ok(())
}

fn validate_phase(message_type: MessageType, established: bool) -> Result<(), WireError> {
    let allowed = match message_type {
        MessageType::Hello | MessageType::HelloAck => !established,
        MessageType::Error => true,
        _ => established,
    };
    if !allowed {
        return Err(WireError::WrongState);
    }
    Ok(())
}

fn validate_identifier(class: MessageClass, request_id: u32) -> Result<(), WireError> {
    match class {
        MessageClass::Request | MessageClass::Response => require_request_id(request_id),
        MessageClass::Event if request_id == 0 => Ok(()),
        MessageClass::Event => Err(WireError::NonzeroEventRequestId),
    }
}

fn require_request_id(request_id: u32) -> Result<(), WireError> {
    if request_id == 0 {
        return Err(WireError::ZeroRequestId);
    }
    Ok(())
}

fn validate_ancillary(
    expectation: AncillaryExpectation,
    ancillary: AncillaryMetadata,
) -> Result<(), WireError> {
    if ancillary.control_truncated {
        return Err(WireError::AncillaryTruncated);
    }
    if ancillary.has_other_control {
        return Err(WireError::UnexpectedAncillary);
    }
    let expected = match expectation {
        AncillaryExpectation::None => 0,
        AncillaryExpectation::OneDescriptor => 1,
    };
    if ancillary.rights_descriptor_count != expected {
        return Err(WireError::DescriptorCountMismatch);
    }
    Ok(())
}

fn require_length(payload: &[u8], expected: usize) -> Result<(), WireError> {
    if payload.len() != expected {
        return Err(WireError::WrongPayloadLength);
    }
    Ok(())
}

fn require_reserved(bytes: &[u8]) -> Result<(), WireError> {
    if bytes.iter().any(|byte| *byte != 0) {
        return Err(WireError::ReservedNonzero);
    }
    Ok(())
}

fn validate_nonzero<T>(value: &T) -> Result<(), WireError>
where
    T: Default + PartialEq,
{
    if *value == T::default() {
        return Err(WireError::InvalidRange);
    }
    Ok(())
}

fn decode_bool(value: u8) -> Result<bool, WireError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(WireError::InvalidBoolean),
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("validated slice"),
    )
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("validated slice"),
    )
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("validated slice"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dimensions() -> DisplayDimensions {
        DisplayDimensions::new(100, 20).expect("valid dimensions")
    }

    fn no_ancillary() -> AncillaryMetadata {
        AncillaryMetadata::default()
    }

    fn packet(message_type: u16, request_id: u32, payload: &[u8]) -> Vec<u8> {
        Packet {
            message_type,
            request_id,
            payload,
        }
        .encode()
        .expect("bounded synthetic packet")
    }

    #[test]
    fn assigns_exact_message_feature_pixel_error_and_key_values() {
        assert_eq!(MessageType::Hello.wire_value(), 0x0001);
        assert_eq!(MessageType::CancelTouchId.wire_value(), 0x0007);
        assert_eq!(MessageType::StepDisplayBrightness.wire_value(), 0x0008);
        assert_eq!(MessageType::StepKeyboardBacklight.wire_value(), 0x0009);
        assert_eq!(MessageType::HelloAck.wire_value(), 0x8001);
        assert_eq!(MessageType::InputFrame.wire_value(), 0x9002);
        assert_eq!(FeatureBits::SEALED_MEMFD_FRAMES.bits(), 0x01);
        assert_eq!(FeatureBits::INPUT_FRAMES.bits(), 0x02);
        assert_eq!(FeatureBits::TYPED_KEY_TAPS.bits(), 0x04);
        assert_eq!(FeatureBits::DISPLAY_BRIGHTNESS.bits(), 0x08);
        assert_eq!(FeatureBits::KEYBOARD_BACKLIGHT.bits(), 0x10);
        assert_eq!(FeatureBits::TOUCH_ID_CANCELLATION.bits(), 0x20);
        assert_eq!(FeatureBits::INITIAL_SERVICE.bits(), 0x07);
        assert_eq!(PixelFormat::Xrgb8888.wire_value(), 1);
        assert_eq!(
            [
                ErrorCode::Unsupported.wire_value(),
                ErrorCode::UnsupportedFeature.wire_value(),
                ErrorCode::ResourceLimit.wire_value(),
                ErrorCode::InvalidBuffer.wire_value(),
                ErrorCode::UnknownBuffer.wire_value(),
                ErrorCode::BufferBusy.wire_value(),
                ErrorCode::ActionDenied.wire_value(),
                ErrorCode::DeviceUnavailable.wire_value(),
                ErrorCode::IoFailure.wire_value(),
                ErrorCode::InternalFailure.wire_value(),
            ],
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        );
        assert_eq!(
            [
                KeyCode::Escape.wire_value(),
                KeyCode::F1.wire_value(),
                KeyCode::F2.wire_value(),
                KeyCode::F3.wire_value(),
                KeyCode::F4.wire_value(),
                KeyCode::F5.wire_value(),
                KeyCode::F6.wire_value(),
                KeyCode::F7.wire_value(),
                KeyCode::F8.wire_value(),
                KeyCode::F9.wire_value(),
                KeyCode::F10.wire_value(),
                KeyCode::F11.wire_value(),
                KeyCode::F12.wire_value(),
            ],
            [1, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 87, 88]
        );
    }

    #[test]
    fn encodes_exact_hello_and_hello_ack_packets() {
        let hello = encode_client(
            &Envelope {
                request_id: 0x4433_2211,
                message: ClientMessage::Hello(Hello {
                    minor: 0,
                    required_features: FeatureBits::INITIAL_SERVICE,
                }),
            },
            None,
        )
        .expect("valid hello");
        assert_eq!(
            hello,
            [
                b'T', b'1', b'H', b'W', 1, 0, 1, 0, 12, 0, 0, 0, 0x11, 0x22, 0x33, 0x44, 0, 0, 0,
                0, 7, 0, 0, 0, 0, 0, 0, 0,
            ]
        );

        let ack = encode_service(
            &Envelope {
                request_id: 0x4433_2211,
                message: ServiceMessage::HelloAck(HelloAck {
                    minor: 0,
                    width: 100,
                    height: 20,
                    pixel_format: PixelFormat::Xrgb8888,
                    max_buffers: 3,
                }),
            },
            None,
        )
        .expect("valid hello ack");
        assert_eq!(
            ack,
            [
                b'T', b'1', b'H', b'W', 1, 0, 1, 0x80, 20, 0, 0, 0, 0x11, 0x22, 0x33, 0x44, 0, 0,
                0, 0, 100, 0, 0, 0, 20, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0,
            ]
        );
    }

    #[test]
    fn encodes_exact_buffer_and_frame_requests() {
        let register = Envelope {
            request_id: 1,
            message: ClientMessage::RegisterBuffer(RegisterBuffer {
                buffer_id: 2,
                stride: 400,
                byte_length: 8_000,
            }),
        };
        assert_eq!(
            encode_client(&register, Some(dimensions())).expect("valid registration"),
            [
                b'T', b'1', b'H', b'W', 1, 0, 2, 0, 16, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 0x90, 1,
                0, 0, 0x40, 0x1f, 0, 0, 0, 0, 0, 0,
            ]
        );
        assert_eq!(
            register.message.ancillary_expectation(),
            AncillaryExpectation::OneDescriptor
        );

        let submit = encode_client(
            &Envelope {
                request_id: 2,
                message: ClientMessage::SubmitFrame(SubmitFrame {
                    buffer_id: 2,
                    frame_id: 0x0807_0605_0403_0201,
                    damage: vec![DamageRectangle {
                        x: 1,
                        y: 2,
                        width: 3,
                        height: 4,
                    }],
                }),
            },
            Some(dimensions()),
        )
        .expect("valid submission");
        assert_eq!(
            submit,
            [
                b'T', b'1', b'H', b'W', 1, 0, 3, 0, 32, 0, 0, 0, 2, 0, 0, 0, 2, 0, 0, 0, 1, 2, 3,
                4, 5, 6, 7, 8, 1, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0,
            ]
        );
    }

    #[test]
    fn encodes_exact_typed_action_requests_including_reserved_actions() {
        let cases = [
            (
                ClientMessage::TapKeys(TapKeys {
                    keys: vec![KeyCode::Escape, KeyCode::F12],
                }),
                vec![
                    4, 0, 12, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 1, 0, 88, 0, 0, 0, 0, 0,
                ],
            ),
            (
                ClientMessage::SetDisplayBrightness(Percentage::new(100).expect("bounded")),
                vec![5, 0, 1, 0, 0, 0, 1, 0, 0, 0, 100],
            ),
            (
                ClientMessage::SetKeyboardBacklight(Percentage::new(0).expect("bounded")),
                vec![6, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0],
            ),
            (
                ClientMessage::CancelTouchId,
                vec![7, 0, 0, 0, 0, 0, 1, 0, 0, 0],
            ),
            (
                ClientMessage::StepDisplayBrightness(StepDirection::Down),
                vec![8, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0],
            ),
            (
                ClientMessage::StepKeyboardBacklight(StepDirection::Up),
                vec![9, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1],
            ),
        ];
        for (message, tail) in cases {
            let encoded = encode_client(
                &Envelope {
                    request_id: 1,
                    message,
                },
                Some(dimensions()),
            )
            .expect("valid action");
            assert_eq!(&encoded[6..], tail);
        }
    }

    #[test]
    fn encodes_exact_ack_error_release_and_input_packets() {
        assert_eq!(
            encode_service(
                &Envelope {
                    request_id: 9,
                    message: ServiceMessage::Ack,
                },
                Some(dimensions()),
            )
            .expect("valid ack"),
            [
                b'T', b'1', b'H', b'W', 1, 0, 2, 0x80, 0, 0, 0, 0, 9, 0, 0, 0
            ]
        );
        assert_eq!(
            encode_service(
                &Envelope {
                    request_id: 9,
                    message: ServiceMessage::Error(ErrorCode::ActionDenied),
                },
                Some(dimensions()),
            )
            .expect("valid error"),
            [
                b'T', b'1', b'H', b'W', 1, 0, 3, 0x80, 4, 0, 0, 0, 9, 0, 0, 0, 7, 0, 0, 0,
            ]
        );
        assert_eq!(
            encode_service(
                &Envelope {
                    request_id: 0,
                    message: ServiceMessage::FrameReleased(FrameReleased {
                        buffer_id: 2,
                        frame_id: 3,
                    }),
                },
                Some(dimensions()),
            )
            .expect("valid release"),
            [
                b'T', b'1', b'H', b'W', 1, 0, 1, 0x90, 12, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 3, 0,
                0, 0, 0, 0, 0, 0,
            ]
        );

        let input = encode_service(
            &Envelope {
                request_id: 0,
                message: ServiceMessage::InputFrame(WireInputFrame {
                    monotonic_ns: 0x0807_0605_0403_0201,
                    fn_pressed: true,
                    contacts: vec![InputContact {
                        id: 15,
                        tip: true,
                        in_range: false,
                        x: 99,
                        y: 19,
                    }],
                }),
            },
            Some(dimensions()),
        )
        .expect("valid input");
        assert_eq!(
            input,
            [
                b'T', b'1', b'H', b'W', 1, 0, 2, 0x90, 24, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6,
                7, 8, 1, 1, 0, 0, 15, 1, 0, 0, 99, 0, 0, 0, 19, 0, 0, 0,
            ]
        );
    }

    #[test]
    fn exact_packets_decode_to_their_typed_messages() {
        let hello = packet(0x0001, 7, &[0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            decode_client(&hello, no_ancillary(), None),
            Ok(Envelope {
                request_id: 7,
                message: ClientMessage::Hello(Hello {
                    minor: 0,
                    required_features: FeatureBits::INITIAL_SERVICE,
                }),
            })
        );

        let register = packet(
            0x0002,
            8,
            &[2, 0, 0, 0, 0x90, 1, 0, 0, 0x40, 0x1f, 0, 0, 0, 0, 0, 0],
        );
        assert_eq!(
            decode_client(
                &register,
                AncillaryMetadata {
                    rights_descriptor_count: 1,
                    ..no_ancillary()
                },
                Some(dimensions()),
            ),
            Ok(Envelope {
                request_id: 8,
                message: ClientMessage::RegisterBuffer(RegisterBuffer {
                    buffer_id: 2,
                    stride: 400,
                    byte_length: 8_000,
                }),
            })
        );

        let ack = packet(
            0x8001,
            7,
            &[
                0, 0, 0, 0, 100, 0, 0, 0, 20, 0, 0, 0, 1, 0, 0, 0, 3, 0, 0, 0,
            ],
        );
        assert_eq!(
            decode_service(&ack, no_ancillary(), None),
            Ok(Envelope {
                request_id: 7,
                message: ServiceMessage::HelloAck(HelloAck {
                    minor: 0,
                    width: 100,
                    height: 20,
                    pixel_format: PixelFormat::Xrgb8888,
                    max_buffers: 3,
                }),
            })
        );
    }

    #[test]
    fn enforces_direction_phase_and_request_event_identifier_rules() {
        let hello = packet(0x0001, 1, &[0; 12]);
        assert_eq!(
            decode_service(&hello, no_ancillary(), None),
            Err(WireError::WrongDirection)
        );
        assert_eq!(
            decode_client(&hello, no_ancillary(), Some(dimensions())),
            Err(WireError::WrongState)
        );
        assert_eq!(
            decode_client(&packet(0x0001, 0, &[0; 12]), no_ancillary(), None),
            Err(WireError::ZeroRequestId)
        );
        assert_eq!(
            decode_service(
                &packet(0x9001, 1, &[1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0]),
                no_ancillary(),
                Some(dimensions())
            ),
            Err(WireError::NonzeroEventRequestId)
        );
        assert_eq!(
            decode_service(&packet(0x8002, 0, &[]), no_ancillary(), Some(dimensions())),
            Err(WireError::ZeroRequestId)
        );
    }

    #[test]
    fn returns_well_formed_unknown_client_requests_without_state_change_semantics() {
        let encoded = packet(0x7777, 4, &[1, 2, 3]);
        assert_eq!(
            decode_client(&encoded, no_ancillary(), Some(dimensions())),
            Ok(Envelope {
                request_id: 4,
                message: ClientMessage::Unknown(UnknownRequest {
                    message_type: 0x7777,
                    payload: vec![1, 2, 3],
                }),
            })
        );
        assert_eq!(
            decode_service(&encoded, no_ancillary(), Some(dimensions())),
            Err(WireError::UnknownServiceMessage)
        );
    }

    #[test]
    fn rejects_reserved_boolean_count_slot_and_value_violations() {
        let mut hello = [0_u8; 12];
        hello[2] = 1;
        assert_eq!(
            decode_client(&packet(0x0001, 1, &hello), no_ancillary(), None),
            Err(WireError::ReservedNonzero)
        );

        let mut keys = [0_u8; 12];
        keys[0] = 1;
        keys[4..6].copy_from_slice(&1_u16.to_le_bytes());
        keys[6..8].copy_from_slice(&59_u16.to_le_bytes());
        assert_eq!(
            decode_client(
                &packet(0x0004, 1, &keys),
                no_ancillary(),
                Some(dimensions())
            ),
            Err(WireError::ReservedNonzero)
        );
        keys[0] = 2;
        keys[6..8].copy_from_slice(&1_u16.to_le_bytes());
        assert_eq!(
            decode_client(
                &packet(0x0004, 1, &keys),
                no_ancillary(),
                Some(dimensions())
            ),
            Err(WireError::DuplicateKey)
        );
        keys[0] = 5;
        assert_eq!(
            decode_client(
                &packet(0x0004, 1, &keys),
                no_ancillary(),
                Some(dimensions())
            ),
            Err(WireError::InvalidCount)
        );
        assert_eq!(
            decode_client(
                &packet(0x0005, 1, &[101]),
                no_ancillary(),
                Some(dimensions())
            ),
            Err(WireError::InvalidRange)
        );
        assert_eq!(
            decode_client(&packet(0x0008, 1, &[2]), no_ancillary(), Some(dimensions())),
            Err(WireError::InvalidRange)
        );

        let mut input = [0_u8; 12];
        input[8] = 2;
        assert_eq!(
            decode_service(
                &packet(0x9002, 0, &input),
                no_ancillary(),
                Some(dimensions())
            ),
            Err(WireError::InvalidBoolean)
        );
        input[8] = 0;
        input[9] = 11;
        assert_eq!(
            decode_service(
                &packet(0x9002, 0, &input),
                no_ancillary(),
                Some(dimensions())
            ),
            Err(WireError::InvalidCount)
        );
    }

    #[test]
    fn rejects_nonzero_ids_bad_bounds_and_bad_dynamic_lengths() {
        let submit = SubmitFrame {
            buffer_id: 1,
            frame_id: 1,
            damage: vec![DamageRectangle {
                x: 99,
                y: 0,
                width: 2,
                height: 1,
            }],
        };
        assert_eq!(
            encode_client(
                &Envelope {
                    request_id: 1,
                    message: ClientMessage::SubmitFrame(submit),
                },
                Some(dimensions()),
            ),
            Err(WireError::InvalidRange)
        );
        let zero_frame = packet(0x0003, 1, &[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            decode_client(&zero_frame, no_ancillary(), Some(dimensions())),
            Err(WireError::InvalidRange)
        );
        let bad_count_length = packet(0x0003, 1, &[1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]);
        assert_eq!(
            decode_client(&bad_count_length, no_ancillary(), Some(dimensions())),
            Err(WireError::WrongPayloadLength)
        );

        let duplicate_contacts = WireInputFrame {
            monotonic_ns: 1,
            fn_pressed: false,
            contacts: vec![
                InputContact {
                    id: 2,
                    tip: true,
                    in_range: true,
                    x: 0,
                    y: 0,
                },
                InputContact {
                    id: 2,
                    tip: false,
                    in_range: true,
                    x: 1,
                    y: 1,
                },
            ],
        };
        assert_eq!(
            encode_service(
                &Envelope {
                    request_id: 0,
                    message: ServiceMessage::InputFrame(duplicate_contacts),
                },
                Some(dimensions()),
            ),
            Err(WireError::DuplicateContact)
        );
    }

    #[test]
    fn enforces_register_only_exactly_one_rights_descriptor() {
        let hello = packet(0x0001, 1, &[0; 12]);
        assert_eq!(
            decode_client(
                &hello,
                AncillaryMetadata {
                    rights_descriptor_count: 1,
                    ..no_ancillary()
                },
                None,
            ),
            Err(WireError::DescriptorCountMismatch)
        );
        let register = packet(0x0002, 1, &[1, 0, 0, 0, 4, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            decode_client(&register, no_ancillary(), Some(dimensions())),
            Err(WireError::DescriptorCountMismatch)
        );
        assert_eq!(
            decode_client(
                &register,
                AncillaryMetadata {
                    rights_descriptor_count: 1,
                    control_truncated: true,
                    has_other_control: false,
                },
                Some(dimensions()),
            ),
            Err(WireError::AncillaryTruncated)
        );
        assert_eq!(
            decode_client(
                &register,
                AncillaryMetadata {
                    rights_descriptor_count: 1,
                    control_truncated: false,
                    has_other_control: true,
                },
                Some(dimensions()),
            ),
            Err(WireError::UnexpectedAncillary)
        );
    }
}

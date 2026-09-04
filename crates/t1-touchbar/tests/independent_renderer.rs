//! Acceptance client for the frozen renderer contract.
//!
//! This deliberately does not use the built-in renderer. It models the work a
//! separately authored renderer must perform using only public protocol types.

use t1_platform::frame_memfd::{ReadOnlyFrame, RendererFrame};
use t1_touchbar::overlay_state::{
    DecodedField, DecodedOverlayRecord, DecodedValue, OverlayState, OverlayValidation,
    validate_overlay_record,
};
use t1_touchbar_hw::digitizer::DisplayDimensions;
use t1_touchbar_hw::frame_state::{
    DamageRectangle, FrameLayout, FrameState, VerifiedBufferMetadata,
};
use t1_touchbar_hw::wire::{
    self, AncillaryMetadata, ClientMessage, Envelope, FeatureBits, FrameReleased, Hello, HelloAck,
    InputContact, PixelFormat, RegisterBuffer, ServiceMessage, SubmitFrame, WireInputFrame,
};

const BUFFER_ID: u32 = 41;
const FIRST_FRAME_ID: u64 = 73;

#[derive(Debug)]
struct IndependentRenderer {
    next_request_id: u32,
    dimensions: Option<DisplayDimensions>,
    frame: Option<RendererFrame>,
    last_input: Option<WireInputFrame>,
    cosmetic_state: Option<OverlayState>,
}

impl IndependentRenderer {
    fn new() -> Self {
        Self {
            next_request_id: 1,
            dimensions: None,
            frame: None,
            last_input: None,
            cosmetic_state: None,
        }
    }

    fn hello_packet(&mut self) -> Vec<u8> {
        self.encode(ClientMessage::Hello(Hello {
            minor: wire::PROTOCOL_MINOR,
            required_features: FeatureBits::INITIAL_SERVICE | FeatureBits::TOUCH_ID_CANCELLATION,
        }))
    }

    fn accept_hello(&mut self, packet: &[u8]) -> RegisterTransfer<'_> {
        let response = wire::decode_service(packet, AncillaryMetadata::default(), None)
            .expect("decode hello response");
        let ServiceMessage::HelloAck(ack) = response.message else {
            panic!("service must acknowledge the renderer hello");
        };
        let dimensions = DisplayDimensions::new(ack.width, ack.height)
            .expect("accept negotiated display dimensions");
        let layout = FrameLayout::new(ack.width, ack.height).expect("derive frame layout");
        self.dimensions = Some(dimensions);
        self.frame = Some(RendererFrame::new(layout.byte_length()).expect("create renderer frame"));
        let request_id = self.take_request_id();
        let packet = wire::encode_client(
            &Envelope {
                request_id,
                message: ClientMessage::RegisterBuffer(RegisterBuffer {
                    buffer_id: BUFFER_ID,
                    stride: layout.stride(),
                    byte_length: layout.byte_length(),
                }),
            },
            Some(dimensions),
        )
        .expect("encode buffer registration");
        RegisterTransfer {
            packet,
            frame: self.frame.as_ref().expect("renderer frame"),
        }
    }

    fn submit_packet(&mut self, frame_id: u64) -> Vec<u8> {
        let dimensions = self.dimensions.expect("negotiated dimensions");
        let frame = self.frame.as_mut().expect("registered renderer frame");
        frame.as_mut_slice().fill(0x24);
        self.encode(ClientMessage::SubmitFrame(SubmitFrame {
            buffer_id: BUFFER_ID,
            frame_id,
            damage: vec![DamageRectangle {
                x: 0,
                y: 0,
                width: dimensions.width(),
                height: dimensions.height(),
            }],
        }))
    }

    fn consume_service_packet(&mut self, packet: &[u8]) -> ServiceMessage {
        let response = wire::decode_service(packet, AncillaryMetadata::default(), self.dimensions)
            .expect("decode established service message");
        if let ServiceMessage::InputFrame(input) = &response.message {
            self.last_input = Some(input.clone());
        }
        response.message
    }

    fn consume_cosmetic_state(&mut self, state: &'static str) {
        let fields = [
            DecodedField {
                name: "version",
                value: DecodedValue::Integer(1),
            },
            DecodedField {
                name: "pid",
                value: DecodedValue::Integer(4242),
            },
            DecodedField {
                name: "state",
                value: DecodedValue::String(state),
            },
        ];
        let mut liveness = |_| true;
        let OverlayValidation::Overlay(overlay) =
            validate_overlay_record(DecodedOverlayRecord { fields: &fields }, &mut liveness)
        else {
            panic!("valid live cosmetic state must be accepted");
        };
        self.cosmetic_state = Some(overlay.state);
    }

    fn disconnected(&mut self) {
        self.dimensions = None;
        self.frame = None;
        self.last_input = None;
    }

    fn encode(&mut self, message: ClientMessage) -> Vec<u8> {
        let request_id = self.take_request_id();
        wire::encode_client(
            &Envelope {
                request_id,
                message,
            },
            self.dimensions,
        )
        .expect("encode independent renderer request")
    }

    fn take_request_id(&mut self) -> u32 {
        let request_id = self.next_request_id;
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .expect("request id space");
        request_id
    }
}

struct RegisterTransfer<'frame> {
    packet: Vec<u8>,
    frame: &'frame RendererFrame,
}

struct ContractService {
    dimensions: DisplayDimensions,
    frames: FrameState<u32, u64>,
}

impl ContractService {
    fn new(width: u32, height: u32) -> Self {
        let dimensions = DisplayDimensions::new(width, height).expect("service dimensions");
        let layout = FrameLayout::new(width, height).expect("service frame layout");
        Self {
            dimensions,
            frames: FrameState::new(layout),
        }
    }

    fn accept_hello(&self, packet: &[u8]) -> Vec<u8> {
        let request = wire::decode_client(packet, AncillaryMetadata::default(), None)
            .expect("service decodes hello");
        let ClientMessage::Hello(hello) = request.message else {
            panic!("first renderer request must be hello");
        };
        assert_eq!(hello.minor, wire::PROTOCOL_MINOR);
        assert!(
            hello
                .required_features
                .contains(FeatureBits::INITIAL_SERVICE | FeatureBits::TOUCH_ID_CANCELLATION)
        );
        wire::encode_service(
            &Envelope {
                request_id: request.request_id,
                message: ServiceMessage::HelloAck(HelloAck {
                    minor: wire::PROTOCOL_MINOR,
                    width: self.dimensions.width(),
                    height: self.dimensions.height(),
                    pixel_format: PixelFormat::Xrgb8888,
                    max_buffers: wire::MAX_BUFFERS,
                }),
            },
            None,
        )
        .expect("service encodes hello acknowledgement")
    }

    fn register(&mut self, transfer: &RegisterTransfer<'_>) {
        let request = wire::decode_client(
            &transfer.packet,
            AncillaryMetadata {
                rights_descriptor_count: 1,
                ..AncillaryMetadata::default()
            },
            Some(self.dimensions),
        )
        .expect("service decodes registration");
        let ClientMessage::RegisterBuffer(register) = request.message else {
            panic!("renderer must register its frame");
        };
        let reader = ReadOnlyFrame::accept(transfer.frame.descriptor(), register.byte_length)
            .expect("service accepts the transferred frame");
        assert_eq!(reader.len(), transfer.frame.len());
        self.frames
            .register_buffer(
                register.buffer_id,
                VerifiedBufferMetadata {
                    stride: register.stride,
                    byte_length: register.byte_length,
                },
            )
            .expect("service registers the frame");
    }

    fn submit(&mut self, packet: &[u8]) -> Vec<u8> {
        let request =
            wire::decode_client(packet, AncillaryMetadata::default(), Some(self.dimensions))
                .expect("service decodes submission");
        let ClientMessage::SubmitFrame(submit) = request.message else {
            panic!("renderer must submit a frame");
        };
        self.frames
            .submit_frame(&submit.buffer_id, submit.frame_id, &submit.damage)
            .expect("service accepts frame submission");
        self.frames
            .release_frame(&submit.buffer_id, &submit.frame_id)
            .expect("service releases exact frame");
        wire::encode_service(
            &Envelope {
                request_id: 0,
                message: ServiceMessage::FrameReleased(FrameReleased {
                    buffer_id: submit.buffer_id,
                    frame_id: submit.frame_id,
                }),
            },
            Some(self.dimensions),
        )
        .expect("service encodes frame release")
    }

    fn input_packet(&self, fn_pressed: bool) -> Vec<u8> {
        wire::encode_service(
            &Envelope {
                request_id: 0,
                message: ServiceMessage::InputFrame(WireInputFrame {
                    monotonic_ns: 991,
                    fn_pressed,
                    contacts: vec![InputContact {
                        id: 3,
                        tip: true,
                        in_range: true,
                        x: self.dimensions.width() / 2,
                        y: self.dimensions.height() / 2,
                    }],
                }),
            },
            Some(self.dimensions),
        )
        .expect("service encodes normalized input")
    }
}

#[test]
fn independent_renderer_survives_the_complete_public_contract_lifecycle() {
    let mut renderer = IndependentRenderer::new();
    let mut first_service = ContractService::new(180, 24);

    let hello_ack = first_service.accept_hello(&renderer.hello_packet());
    let registration = renderer.accept_hello(&hello_ack);
    first_service.register(&registration);
    let release = first_service.submit(&renderer.submit_packet(FIRST_FRAME_ID));
    assert_eq!(
        renderer.consume_service_packet(&release),
        ServiceMessage::FrameReleased(FrameReleased {
            buffer_id: BUFFER_ID,
            frame_id: FIRST_FRAME_ID,
        })
    );

    let input = first_service.input_packet(true);
    assert!(matches!(
        renderer.consume_service_packet(&input),
        ServiceMessage::InputFrame(_)
    ));
    let observed = renderer
        .last_input
        .as_ref()
        .expect("renderer consumed input");
    assert!(observed.fn_pressed);
    assert_eq!(observed.contacts[0].id, 3);

    for (wire_name, expected) in [
        ("enrollment", OverlayState::Enrollment),
        ("authenticate", OverlayState::Authenticate),
        ("approve", OverlayState::Approve),
        ("retry", OverlayState::Retry),
        ("success", OverlayState::Success),
    ] {
        renderer.consume_cosmetic_state(wire_name);
        assert_eq!(renderer.cosmetic_state, Some(expected));
    }

    renderer.disconnected();
    assert!(renderer.dimensions.is_none());
    assert!(renderer.frame.is_none());

    let mut changed_service = ContractService::new(220, 30);
    let changed_ack = changed_service.accept_hello(&renderer.hello_packet());
    let changed_registration = renderer.accept_hello(&changed_ack);
    assert_eq!(changed_registration.frame.len(), 220 * 30 * 4);
    changed_service.register(&changed_registration);
    let changed_release = changed_service.submit(&renderer.submit_packet(FIRST_FRAME_ID + 1));
    let expected_changed_frame = FIRST_FRAME_ID + 1;
    assert!(matches!(
        renderer.consume_service_packet(&changed_release),
        ServiceMessage::FrameReleased(FrameReleased {
            frame_id,
            ..
        }) if frame_id == expected_changed_frame
    ));
}

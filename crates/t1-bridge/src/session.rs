//! Stateful `BridgeXPC` client exchange over an already-connected stream.

use crate::bplist::Value;
use crate::framing::{FRAME_BINARY_PLIST, FRAME_HELLO, Frame};
use crate::hello::{HelloError, encode_hello, validate_peer_hello};
use crate::mesa::ServiceStatusEvent;
use crate::rpc::{
    RequestId, RpcEnvelope, RpcError, decode_envelope, decode_raw_dictionary,
    encode_raw_dictionary, encode_reply, encode_request, handle_inbound_request,
};
use crate::transport::{BridgeXpcTransport, TransportError};
use core::fmt;
use std::collections::{BTreeMap, VecDeque};
use std::io::{Read, Write};

/// Session-level protocol or stream failure.
#[derive(Debug)]
pub enum SessionError {
    Transport(TransportError),
    Hello(HelloError),
    Rpc(RpcError),
    ExpectedHello { actual: u32 },
    UnsolicitedReply,
}

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(error) => error.fmt(formatter),
            Self::Hello(error) => error.fmt(formatter),
            Self::Rpc(error) => error.fmt(formatter),
            Self::ExpectedHello { actual } => {
                write!(
                    formatter,
                    "expected BridgeXPC HELLO, got frame type {actual}"
                )
            }
            Self::UnsolicitedReply => formatter.write_str("received an unsolicited RPC reply"),
        }
    }
}

impl std::error::Error for SessionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(error) => Some(error),
            Self::Hello(error) => Some(error),
            Self::Rpc(error) => Some(error),
            Self::ExpectedHello { .. } | Self::UnsolicitedReply => None,
        }
    }
}

impl From<TransportError> for SessionError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

impl From<HelloError> for SessionError {
    fn from(error: HelloError) -> Self {
        Self::Hello(error)
    }
}

impl From<RpcError> for SessionError {
    fn from(error: RpcError) -> Self {
        Self::Rpc(error)
    }
}

/// A redaction-safe raw-dictionary exchange failure.
///
/// Raw dictionaries are used by `BridgeXPC` message listeners and deliberately
/// have no RPC envelope or request identifier.
pub enum RawDictionaryError {
    /// Framing or caller-owned stream I/O failed.
    Transport(TransportError),
    /// Binary-plist encoding or dictionary validation failed.
    Rpc(RpcError),
}

impl fmt::Debug for RawDictionaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(_) => formatter.write_str("Transport([redacted])"),
            Self::Rpc(error) => formatter.debug_tuple("Rpc").field(error).finish(),
        }
    }
}

impl fmt::Display for RawDictionaryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(_) => formatter.write_str("BridgeXPC dictionary exchange failed"),
            Self::Rpc(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for RawDictionaryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Transport(_) => None,
            Self::Rpc(error) => Some(error),
        }
    }
}

impl From<TransportError> for RawDictionaryError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

impl From<RpcError> for RawDictionaryError {
    fn from(error: RpcError) -> Self {
        Self::Rpc(error)
    }
}

/// A negotiated `BridgeXPC` client over a caller-owned connected stream.
pub struct BridgeXpcSession<S> {
    transport: BridgeXpcTransport<S>,
    service_events: VecDeque<ServiceStatusEvent>,
}

impl<S: Read + Write> BridgeXpcSession<S> {
    /// Completes the client-side HELLO exchange.
    ///
    /// The peer must send HELLO first. Network discovery, socket creation, and
    /// timeout policy remain with the daemon.
    ///
    /// # Errors
    ///
    /// Returns an error for stream failures, the wrong first frame type, an
    /// invalid peer HELLO, or an invalid local process name.
    pub fn connect(stream: S, process_name: &str) -> Result<Self, SessionError> {
        let mut transport = BridgeXpcTransport::new(stream);
        let peer_hello = transport.receive_frame()?;
        if peer_hello.message_type != FRAME_HELLO {
            return Err(SessionError::ExpectedHello {
                actual: peer_hello.message_type,
            });
        }
        validate_peer_hello(&peer_hello.body)?;

        let hello =
            Frame::new(FRAME_HELLO, encode_hello(process_name)?).map_err(TransportError::from)?;
        transport.send_frame(&hello)?;
        Ok(Self {
            transport,
            service_events: VecDeque::new(),
        })
    }

    /// Performs one synchronous RPC while acknowledging inbound callbacks.
    ///
    /// Frames of other types and replies for other request IDs are ignored,
    /// matching the reference client. Valid service-status callbacks are
    /// queued for [`Self::take_service_event`].
    ///
    /// # Errors
    ///
    /// Returns an error for transport, plist, envelope, or callback failures.
    pub fn call(
        &mut self,
        request_id: &RequestId,
        payload: &[Value],
    ) -> Result<Vec<Value>, SessionError> {
        self.send_plist(encode_request(request_id, payload)?)?;

        loop {
            let frame = self.transport.receive_frame()?;
            if frame.message_type != FRAME_BINARY_PLIST {
                continue;
            }
            match decode_envelope(&frame.body)? {
                RpcEnvelope::Reply {
                    request_id: response_id,
                    result,
                } if response_id == *request_id => return Ok(result),
                RpcEnvelope::Reply { .. } => {}
                RpcEnvelope::Request {
                    request_id,
                    payload,
                } => self.acknowledge_request(&request_id, &payload)?,
            }
        }
    }

    /// Exchanges one raw dictionary with a `BridgeXPC` message listener.
    ///
    /// Unlike [`Self::call`], this protocol sends the dictionary as the plist
    /// root. It does not allocate or consume an RPC request identifier.
    /// Non-binary-plist frames are ignored and the first binary-plist reply
    /// must also have a dictionary root.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe error for framing, stream, binary-plist, or
    /// dictionary-shape failures.
    pub fn call_raw_dictionary(
        &mut self,
        request: &BTreeMap<String, Value>,
    ) -> Result<BTreeMap<String, Value>, RawDictionaryError> {
        let body = encode_raw_dictionary(request)?;
        let frame = Frame::new(FRAME_BINARY_PLIST, body).map_err(TransportError::from)?;
        self.transport.send_frame(&frame)?;

        loop {
            let frame = self.transport.receive_frame()?;
            if frame.message_type == FRAME_BINARY_PLIST {
                return decode_raw_dictionary(&frame.body).map_err(RawDictionaryError::from);
            }
        }
    }

    /// Receives and acknowledges one possible callback frame.
    ///
    /// Non-binary-plist frames are ignored. A callback event is returned
    /// directly; it is not also added to the queue.
    ///
    /// # Errors
    ///
    /// Returns an error for transport or protocol failures, including an
    /// unsolicited reply.
    pub fn service_inbound_request(&mut self) -> Result<Option<ServiceStatusEvent>, SessionError> {
        let frame = self.transport.receive_frame()?;
        if frame.message_type != FRAME_BINARY_PLIST {
            return Ok(None);
        }
        match decode_envelope(&frame.body)? {
            RpcEnvelope::Reply { .. } => Err(SessionError::UnsolicitedReply),
            RpcEnvelope::Request {
                request_id,
                payload,
            } => {
                let handled = handle_inbound_request(&payload)?;
                self.send_plist(encode_reply(&request_id, handled.reply())?)?;
                Ok(handled.into_service_event())
            }
        }
    }

    /// Removes the oldest callback collected during [`Self::call`].
    #[must_use]
    pub fn take_service_event(&mut self) -> Option<ServiceStatusEvent> {
        self.service_events.pop_front()
    }

    /// Returns the caller-owned stream.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.transport.into_inner()
    }

    fn acknowledge_request(
        &mut self,
        request_id: &RequestId,
        payload: &[Value],
    ) -> Result<(), SessionError> {
        let handled = handle_inbound_request(payload)?;
        self.send_plist(encode_reply(request_id, handled.reply())?)?;
        if let Some(event) = handled.into_service_event() {
            self.service_events.push_back(event);
        }
        Ok(())
    }

    fn send_plist(&mut self, body: Vec<u8>) -> Result<(), SessionError> {
        let frame = Frame::new(FRAME_BINARY_PLIST, body).map_err(TransportError::from)?;
        self.transport.send_frame(&frame)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bplist;
    use crate::rpc::{BRIDGEXPC_NIL, encode_reply, encode_request};
    use std::io::{self, Cursor};

    struct Duplex {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl Duplex {
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

    impl Read for Duplex {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.input.read(buffer)
        }
    }

    impl Write for Duplex {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.output.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn hello_frame() -> Frame {
        Frame::new(
            FRAME_HELLO,
            br#"{"MaxSupportedProtocolVersion":1}"#.to_vec(),
        )
        .unwrap()
    }

    fn plist_frame(body: Vec<u8>) -> Frame {
        Frame::new(FRAME_BINARY_PLIST, body).unwrap()
    }

    fn id(byte: u8) -> RequestId {
        RequestId::from_uuid_v4_bytes([byte; 16])
    }

    fn output_frames(stream: &Duplex) -> Vec<Frame> {
        let mut remainder = stream.output.as_slice();
        let mut frames = Vec::new();
        while !remainder.is_empty() {
            let (frame, rest) = Frame::decode_prefix(remainder).unwrap();
            frames.push(frame);
            remainder = rest;
        }
        frames
    }

    #[test]
    fn client_validates_peer_then_sends_exact_hello() {
        let session =
            BridgeXpcSession::connect(Duplex::new(&[hello_frame()]), "t1-touchid").unwrap();
        let frames = output_frames(&session.into_inner());
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].message_type, FRAME_HELLO);
        assert_eq!(frames[0].body, encode_hello("t1-touchid").unwrap());
    }

    #[test]
    fn call_ignores_other_frames_acknowledges_callback_and_returns_matching_reply() {
        let call_id = id(0x11);
        let callback_id = Value::String("peer-callback-id".into());
        let callback = bplist::encode(&Value::Array(vec![
            Value::Integer(1),
            Value::Boolean(false),
            callback_id,
            Value::Array(vec![
                Value::Integer(9),
                Value::Integer(7),
                Value::String(BRIDGEXPC_NIL.into()),
                Value::Integer(10),
                Value::Integer(20),
            ]),
        ]))
        .unwrap();
        let expected = vec![Value::Integer(0), Value::Boolean(true)];
        let frames = [
            hello_frame(),
            Frame::new(77, Vec::new()).unwrap(),
            plist_frame(callback),
            plist_frame(encode_reply(&id(0x22), &[Value::Integer(99)]).unwrap()),
            plist_frame(encode_reply(&call_id, &expected).unwrap()),
        ];
        let mut session = BridgeXpcSession::connect(Duplex::new(&frames), "client").unwrap();

        assert_eq!(
            session.call(&call_id, &[Value::Integer(3)]).unwrap(),
            expected
        );
        let event = session.take_service_event().unwrap();
        assert_eq!(event.service, 7);
        assert!(event.data.is_empty());

        let output = output_frames(&session.into_inner());
        assert_eq!(output.len(), 3);
        assert_eq!(
            decode_envelope(&output[1].body).unwrap(),
            RpcEnvelope::Request {
                request_id: call_id,
                payload: vec![Value::Integer(3)],
            }
        );
        let RpcEnvelope::Reply { request_id, result } = decode_envelope(&output[2].body).unwrap()
        else {
            panic!("expected callback reply");
        };
        assert_eq!(request_id.as_str(), "peer-callback-id");
        assert_eq!(result, vec![Value::Integer(0)]);
    }

    #[test]
    fn raw_dictionary_call_has_no_rpc_envelope_or_request_identifier() {
        let mut request = BTreeMap::new();
        request.insert("synthetic.command".into(), Value::Integer(200));
        let mut response = BTreeMap::new();
        response.insert("synthetic.success".into(), Value::Boolean(true));
        let frames = [
            hello_frame(),
            Frame::new(77, Vec::new()).unwrap(),
            plist_frame(encode_raw_dictionary(&response).unwrap()),
        ];
        let mut session = BridgeXpcSession::connect(Duplex::new(&frames), "client").unwrap();

        assert_eq!(session.call_raw_dictionary(&request).unwrap(), response);

        let output = output_frames(&session.into_inner());
        assert_eq!(output.len(), 2);
        assert_eq!(decode_raw_dictionary(&output[1].body).unwrap(), request);
        assert_eq!(
            decode_envelope(&output[1].body),
            Err(RpcError::InvalidEnvelope)
        );
    }

    #[test]
    fn raw_dictionary_call_rejects_a_non_dictionary_reply() {
        let reply = bplist::encode(&Value::Array(vec![Value::Data(
            b"synthetic opaque reply".to_vec(),
        )]))
        .unwrap();
        let frames = [hello_frame(), plist_frame(reply)];
        let mut session = BridgeXpcSession::connect(Duplex::new(&frames), "client").unwrap();

        assert!(matches!(
            session.call_raw_dictionary(&BTreeMap::new()),
            Err(RawDictionaryError::Rpc(RpcError::InvalidRawDictionary))
        ));
    }

    #[test]
    fn raw_dictionary_transport_diagnostics_are_redacted() {
        let marker = "private stream marker";
        let error = RawDictionaryError::Transport(TransportError::Io {
            part: crate::transport::FramePart::Body,
            source: io::Error::other(marker),
        });
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(marker));
        assert!(std::error::Error::source(&error).is_none());
    }

    #[test]
    fn standalone_callback_is_returned_and_echoes_peer_id() {
        let peer_request = Value::Array(vec![
            Value::Integer(1),
            Value::Boolean(false),
            Value::String("opaque-peer-id".into()),
            Value::Array(vec![
                Value::Integer(10),
                Value::Integer(8),
                Value::Data(vec![1, 2]),
                Value::Integer(30),
                Value::Integer(40),
            ]),
        ]);
        let frames = [
            hello_frame(),
            plist_frame(bplist::encode(&peer_request).unwrap()),
        ];
        let mut session = BridgeXpcSession::connect(Duplex::new(&frames), "client").unwrap();
        let event = session.service_inbound_request().unwrap().unwrap();
        assert_eq!(event.service, 8);
        assert_eq!(event.data, vec![1, 2]);

        let output = output_frames(&session.into_inner());
        let RpcEnvelope::Reply { request_id, result } = decode_envelope(&output[1].body).unwrap()
        else {
            panic!("expected callback reply");
        };
        assert_eq!(request_id.as_str(), "opaque-peer-id");
        assert_eq!(result, vec![Value::Integer(0)]);
    }

    #[test]
    fn rejects_wrong_or_invalid_peer_hello() {
        let result = BridgeXpcSession::connect(
            Duplex::new(&[Frame::new(FRAME_BINARY_PLIST, Vec::new()).unwrap()]),
            "client",
        );
        let Err(error) = result else {
            panic!("expected wrong-frame error");
        };
        assert!(matches!(
            error,
            SessionError::ExpectedHello {
                actual: FRAME_BINARY_PLIST
            }
        ));

        let result = BridgeXpcSession::connect(
            Duplex::new(&[Frame::new(FRAME_HELLO, b"{}".to_vec()).unwrap()]),
            "client",
        );
        let Err(error) = result else {
            panic!("expected invalid-HELLO error");
        };
        assert!(matches!(
            error,
            SessionError::Hello(HelloError::MissingProtocolVersion)
        ));
    }

    #[test]
    fn standalone_service_rejects_unsolicited_reply() {
        let frames = [
            hello_frame(),
            plist_frame(encode_reply(&id(0x33), &[]).unwrap()),
        ];
        let mut session = BridgeXpcSession::connect(Duplex::new(&frames), "client").unwrap();
        assert!(matches!(
            session.service_inbound_request(),
            Err(SessionError::UnsolicitedReply)
        ));
    }

    #[test]
    fn call_reports_truncated_stream_without_leaking_payloads() {
        let mut stream = Duplex::new(&[hello_frame()]);
        stream.input.get_mut().extend_from_slice(&[0; 3]);
        let mut session = BridgeXpcSession::connect(stream, "client").unwrap();
        let error = session.call(&id(0x44), &[]).unwrap_err();
        assert!(matches!(error, SessionError::Transport(_)));
    }

    #[test]
    fn request_encoding_used_by_session_is_exact() {
        let request_id = id(0x55);
        let encoded = encode_request(&request_id, &[Value::Integer(7)]).unwrap();
        let decoded = decode_envelope(&encoded).unwrap();
        assert_eq!(
            decoded,
            RpcEnvelope::Request {
                request_id,
                payload: vec![Value::Integer(7)]
            }
        );
    }
}

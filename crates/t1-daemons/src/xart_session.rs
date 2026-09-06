//! One dependency-free `BridgeXPC` xART service session.

use crate::xart_protocol::handle_request;
use crate::xart_service::{DeviceLease, PeerAdmissionError, PeerObservation, XartServiceLifecycle};
use crate::xart_store::XartStore;
use std::error::Error;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;
use t1_bridge::bplist::{self, Value};
use t1_bridge::framing::{FRAME_BINARY_PLIST, FRAME_HELLO, Frame};
use t1_bridge::hello::{self, HelloError};
use t1_bridge::transport::{BridgeXpcTransport, TransportError};

const PROCESS_NAME: &str = "xartstorageremoted";
const CONNECTION_IO_TIMEOUT: Duration = Duration::from_secs(30);

/// A payload-redacted xART session failure.
#[derive(Debug)]
pub enum XartSessionError {
    /// The already-connected TCP stream could not be bounded before use.
    ConnectionConfiguration(io::Error),
    /// A frame could not be read or written.
    Transport(TransportError),
    /// The peer did not answer the server HELLO with a HELLO frame.
    ExpectedPeerHello,
    /// The local or peer HELLO body was invalid.
    Hello(HelloError),
    /// A binary-property-list request or response was invalid.
    BinaryPlist(bplist::Error),
}

impl fmt::Display for XartSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ConnectionConfiguration(_) => {
                formatter.write_str("xART connection timeout configuration failed")
            }
            Self::Transport(source) => write!(formatter, "xART session transport failed: {source}"),
            Self::ExpectedPeerHello => formatter.write_str("xART peer did not send a HELLO frame"),
            Self::Hello(source) => write!(formatter, "xART HELLO exchange failed: {source}"),
            Self::BinaryPlist(source) => {
                write!(
                    formatter,
                    "xART binary-property-list processing failed: {source}"
                )
            }
        }
    }
}

impl Error for XartSessionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::ConnectionConfiguration(source) => Some(source),
            Self::Transport(source) => Some(source),
            Self::Hello(source) => Some(source),
            Self::BinaryPlist(source) => Some(source),
            Self::ExpectedPeerHello => None,
        }
    }
}

impl From<TransportError> for XartSessionError {
    fn from(error: TransportError) -> Self {
        Self::Transport(error)
    }
}

impl From<HelloError> for XartSessionError {
    fn from(error: HelloError) -> Self {
        Self::Hello(error)
    }
}

impl From<bplist::Error> for XartSessionError {
    fn from(error: bplist::Error) -> Self {
        Self::BinaryPlist(error)
    }
}

/// A payload- and endpoint-redacted accepted-connection failure.
#[derive(Debug)]
pub enum XartConnectionError {
    /// The kernel did not provide endpoint metadata for the accepted socket.
    PeerMetadataUnavailable,
    /// The accepted peer did not pass the active T1 interface policy.
    PeerAdmission(PeerAdmissionError),
    /// The admitted protocol session failed.
    Session(XartSessionError),
}

impl fmt::Display for XartConnectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PeerMetadataUnavailable => {
                formatter.write_str("xART peer metadata is unavailable")
            }
            Self::PeerAdmission(source) => write!(formatter, "xART peer rejected: {source}"),
            Self::Session(source) => write!(formatter, "xART connection failed: {source}"),
        }
    }
}

impl Error for XartConnectionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::PeerAdmission(source) => Some(source),
            Self::Session(source) => Some(source),
            Self::PeerMetadataUnavailable => None,
        }
    }
}

/// Admits and serves one already-connected xART TCP stream.
///
/// This entry point owns and closes the connection when the session ends. It
/// reads the peer endpoint from the accepted socket and admits it against the
/// device-event-supplied lifecycle before configuring the stream or exchanging
/// protocol bytes. `listener_interface_index` must be the kernel index used to
/// bind the instance's listener.
///
/// # Errors
///
/// Returns an error when peer metadata is unavailable, admission fails, either
/// timeout cannot be applied, or the xART session fails. Errors never include
/// interface names, peer addresses, or opaque xART bytes.
pub fn serve_admitted_tcp_connection(
    mut stream: TcpStream,
    lifecycle: &XartServiceLifecycle,
    lease: DeviceLease,
    listener_interface_index: u32,
    store: &XartStore,
) -> Result<(), XartConnectionError> {
    let peer = stream
        .peer_addr()
        .map_err(|_| XartConnectionError::PeerMetadataUnavailable)?;
    let observation = PeerObservation::new(listener_interface_index, peer);

    lifecycle
        .with_admitted_peer(lease, observation, || {
            stream
                .set_read_timeout(Some(CONNECTION_IO_TIMEOUT))
                .map_err(XartSessionError::ConnectionConfiguration)?;
            stream
                .set_write_timeout(Some(CONNECTION_IO_TIMEOUT))
                .map_err(XartSessionError::ConnectionConfiguration)?;
            serve_connection(&mut stream, store)
        })
        .map_err(XartConnectionError::PeerAdmission)?
        .map_err(XartConnectionError::Session)
}

/// Serves one connected xART `BridgeXPC` byte stream until it closes or fails.
///
/// The server sends its HELLO before reading from the peer. After the peer
/// HELLO is validated, non-binary-plist frames are ignored. Each accepted raw
/// request dictionary is handled synchronously and receives one binary-plist
/// response. Opaque xART bytes are never inspected or included in errors.
///
/// The peer closing cleanly between requests is this loop's normal exit and
/// returns `Ok(())`, not an error; only a mid-frame truncation or another
/// transport failure is reported.
///
/// # Errors
///
/// Returns an error when framing or stream I/O fails (other than the peer
/// cleanly closing between requests), the peer HELLO is absent or invalid, or
/// a request or response binary plist cannot be processed.
fn serve_connection<S: Read + Write>(
    stream: &mut S,
    store: &XartStore,
) -> Result<(), XartSessionError> {
    let mut transport = BridgeXpcTransport::new(stream);
    let server_hello = Frame::new(FRAME_HELLO, hello::encode_hello(PROCESS_NAME)?)
        .map_err(TransportError::from)?;
    transport.send_frame(&server_hello)?;

    let peer_hello = transport.receive_frame()?;
    if peer_hello.message_type != FRAME_HELLO {
        return Err(XartSessionError::ExpectedPeerHello);
    }
    hello::validate_peer_hello(&peer_hello.body)?;

    loop {
        let frame = match transport.receive_frame() {
            Ok(frame) => frame,
            // The peer is done once it closes cleanly between requests; that
            // is this loop's only normal exit, not a session failure.
            Err(TransportError::ConnectionClosed) => return Ok(()),
            Err(error) => return Err(error.into()),
        };
        if frame.message_type != FRAME_BINARY_PLIST {
            continue;
        }

        let request = bplist::decode(&frame.body)?;
        let response = Value::Dictionary(handle_request(store, &request));
        let body = bplist::encode(&response)?;
        let response = Frame::new(FRAME_BINARY_PLIST, body).map_err(TransportError::from)?;
        transport.send_frame(&response)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::fs;
    use std::io::{self, Cursor};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use t1_bridge::framing::{FRAME_HEADER_LEN, Frame};
    use t1_bridge::transport::FramePart;

    const VERSION_KEY: &str = "xart-msg.version";
    const COMMAND_KEY: &str = "xart-msg.command";
    const SUCCESS_KEY: &str = "xart-msg.success";
    const XART_KEY: &str = "xart-msg.xart";
    const UINT64_WRAPPER_KEY: &str = "__com.apple.BridgeXPC.uint64";

    static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "t1bridge-xart-session-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create isolated test directory");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[derive(Default)]
    struct MemoryStream {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl MemoryStream {
        fn new(input: Vec<u8>) -> Self {
            Self {
                input: Cursor::new(input),
                output: Vec::new(),
            }
        }
    }

    impl Read for MemoryStream {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.input.read(bytes)
        }
    }

    impl Write for MemoryStream {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.output.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn store(directory: &Path) -> XartStore {
        XartStore::new(directory, [0x22; 16], false)
    }

    fn hello_frame() -> Frame {
        Frame::new(
            FRAME_HELLO,
            br#"{"MaxSupportedProtocolVersion":1}"#.to_vec(),
        )
        .expect("synthetic HELLO frame")
    }

    fn wrapped_uint64(value: u64) -> Value {
        Value::Dictionary(BTreeMap::from([(
            UINT64_WRAPPER_KEY.into(),
            Value::Integer(i128::from(value)),
        )]))
    }

    fn request(command: u64) -> Value {
        Value::Dictionary(BTreeMap::from([
            (VERSION_KEY.into(), wrapped_uint64(1)),
            (COMMAND_KEY.into(), wrapped_uint64(command)),
        ]))
    }

    fn plist_frame(value: &Value) -> Frame {
        Frame::new(
            FRAME_BINARY_PLIST,
            bplist::encode(value).expect("encode synthetic plist"),
        )
        .expect("synthetic plist frame")
    }

    fn wire_frames(frames: &[Frame]) -> Vec<u8> {
        let mut wire = Vec::new();
        for frame in frames {
            wire.extend_from_slice(&frame.encode().expect("encode synthetic frame"));
        }
        wire
    }

    fn output_frames(stream: &MemoryStream) -> Vec<Frame> {
        let mut remaining = stream.output.as_slice();
        let mut frames = Vec::new();
        while !remaining.is_empty() {
            let (frame, suffix) = Frame::decode_prefix(remaining).expect("decode server output");
            frames.push(frame);
            remaining = suffix;
        }
        frames
    }

    fn assert_closed(error: &XartSessionError, part: FramePart) {
        assert!(matches!(
            error,
            XartSessionError::Transport(TransportError::UnexpectedEof { part: actual })
                if *actual == part
        ));
    }

    fn assert_connection_closed(error: &XartSessionError) {
        assert!(matches!(
            error,
            XartSessionError::Transport(TransportError::ConnectionClosed)
        ));
    }

    #[test]
    fn sends_server_hello_before_attempting_to_read_peer_hello() {
        let directory = TestDirectory::new();
        let mut stream = MemoryStream::default();

        // No peer HELLO ever arrives, so this is a failure (not a clean exit
        // between requests) even though the underlying transport error is the
        // same "peer closed before any byte arrived" case.
        let error = serve_connection(&mut stream, &store(&directory.0)).unwrap_err();

        assert_connection_closed(&error);
        let frames = output_frames(&stream);
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].message_type, FRAME_HELLO);
        assert!(
            std::str::from_utf8(&frames[0].body)
                .expect("server HELLO is UTF-8")
                .contains(r#""ProcessName":"xartstorageremoted""#)
        );
    }

    #[test]
    fn rejects_wrong_type_and_malformed_peer_hello() {
        let directory = TestDirectory::new();
        let invalid_type = Frame::new(FRAME_BINARY_PLIST, Vec::new()).unwrap();
        let mut stream = MemoryStream::new(wire_frames(&[invalid_type]));
        assert!(matches!(
            serve_connection(&mut stream, &store(&directory.0)),
            Err(XartSessionError::ExpectedPeerHello)
        ));

        let malformed = Frame::new(FRAME_HELLO, br#"{"secret":"marker"}"#.to_vec()).unwrap();
        let mut stream = MemoryStream::new(wire_frames(&[malformed]));
        let error = serve_connection(&mut stream, &store(&directory.0)).unwrap_err();
        assert!(matches!(
            &error,
            XartSessionError::Hello(HelloError::MissingProtocolVersion)
        ));
        assert!(!format!("{error:?}").contains("marker"));
    }

    #[test]
    fn ignores_non_plist_frames_then_answers_fetch() {
        let directory = TestDirectory::new();
        let ignored = Frame::new(0x5359_4e54, b"not a plist".to_vec()).unwrap();
        let input = wire_frames(&[hello_frame(), ignored, plist_frame(&request(100))]);
        let mut stream = MemoryStream::new(input);

        // The peer closes cleanly right after its one request; that is a
        // normal end of the session, not a failure.
        serve_connection(&mut stream, &store(&directory.0)).unwrap();

        let frames = output_frames(&stream);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].message_type, FRAME_HELLO);
        assert_eq!(frames[1].message_type, FRAME_BINARY_PLIST);
        let Value::Dictionary(response) = bplist::decode(&frames[1].body).unwrap() else {
            panic!("fetch response is a dictionary");
        };
        assert_eq!(response.get(SUCCESS_KEY), Some(&Value::Boolean(true)));
        assert_eq!(response.get(XART_KEY), Some(&Value::Data(vec![0; 4])));
    }

    #[test]
    fn valid_save_and_following_fetch_round_trip_opaque_bytes() {
        let directory = TestDirectory::new();
        let store = store(&directory.0);
        let wire_blob = vec![4, 0, 0, 0, 0xaa, 0xbb, 0xcc, 0xdd];
        let Value::Dictionary(mut save) = request(150) else {
            unreachable!();
        };
        save.insert(XART_KEY.into(), Value::Data(wire_blob.clone()));
        let input = wire_frames(&[
            hello_frame(),
            plist_frame(&Value::Dictionary(save)),
            plist_frame(&request(100)),
        ]);
        let mut stream = MemoryStream::new(input);

        // The peer closes cleanly right after its second request; that is a
        // normal end of the session, not a failure.
        serve_connection(&mut stream, &store).unwrap();

        let frames = output_frames(&stream);
        assert_eq!(frames.len(), 3);
        for response in &frames[1..] {
            let Value::Dictionary(fields) = bplist::decode(&response.body).unwrap() else {
                panic!("xART response is a dictionary");
            };
            assert_eq!(fields.get(SUCCESS_KEY), Some(&Value::Boolean(true)));
        }
        let Value::Dictionary(fetch) = bplist::decode(&frames[2].body).unwrap() else {
            unreachable!();
        };
        assert_eq!(fetch.get(XART_KEY), Some(&Value::Data(wire_blob)));
    }

    #[test]
    fn invalid_binary_plist_stops_without_echoing_opaque_input() {
        let directory = TestDirectory::new();
        let marker = b"SYNTHETIC_OPAQUE_MARKER";
        let invalid = Frame::new(FRAME_BINARY_PLIST, marker.to_vec()).unwrap();
        let mut stream = MemoryStream::new(wire_frames(&[hello_frame(), invalid]));

        let error = serve_connection(&mut stream, &store(&directory.0)).unwrap_err();

        assert!(matches!(&error, XartSessionError::BinaryPlist(_)));
        assert!(!format!("{error:?}").contains("SYNTHETIC_OPAQUE_MARKER"));
        assert_eq!(output_frames(&stream).len(), 1);
    }

    #[test]
    fn distinguishes_clean_close_from_truncated_body() {
        let directory = TestDirectory::new();
        // No requests follow the HELLO, and the stream just ends: a clean
        // close between requests, not a failure.
        let mut header_eof = MemoryStream::new(wire_frames(&[hello_frame()]));
        serve_connection(&mut header_eof, &store(&directory.0)).unwrap();

        let mut input = wire_frames(&[hello_frame()]);
        let declared = Frame::new(FRAME_BINARY_PLIST, vec![0; 8])
            .unwrap()
            .encode()
            .unwrap();
        input.extend_from_slice(&declared[..FRAME_HEADER_LEN + 3]);
        let mut body_eof = MemoryStream::new(input);
        let error = serve_connection(&mut body_eof, &store(&directory.0)).unwrap_err();
        assert_closed(&error, FramePart::Body);
    }
}

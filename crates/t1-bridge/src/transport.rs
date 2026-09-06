//! Exact stream I/O for `BridgeXPC` frames.

use crate::framing::{FRAME_HEADER_LEN, Frame, FrameError, FrameHeader};
use std::collections::TryReserveError;
use std::error::Error;
use std::fmt;
use std::io::{self, Read, Write};

/// Identifies the frame part involved in a stream failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FramePart {
    /// The fixed-size wire header.
    Header,
    /// The opaque frame body.
    Body,
}

impl fmt::Display for FramePart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Header => formatter.write_str("header"),
            Self::Body => formatter.write_str("body"),
        }
    }
}

/// A framing, allocation, or stream failure.
#[derive(Debug)]
pub enum TransportError {
    /// The wire header is invalid or the body exceeds the protocol limit.
    Frame(FrameError),
    /// The peer closed the stream before the frame part was complete.
    UnexpectedEof {
        /// Frame part being read.
        part: FramePart,
    },
    /// The peer closed the stream cleanly before any byte of a new frame
    /// arrived. Distinct from [`Self::UnexpectedEof`]: this is a normal way
    /// for a connection to end between frames, not a truncated one.
    ConnectionClosed,
    /// The stream accepted no bytes before the frame part was complete.
    WriteZero {
        /// Frame part being written.
        part: FramePart,
    },
    /// Memory for a validated frame body could not be reserved.
    AllocationFailed {
        /// Validated body length in bytes.
        body_len: usize,
        /// Allocation failure reported by the standard library.
        source: TryReserveError,
    },
    /// The stream reported another I/O failure.
    Io {
        /// Frame part being transferred.
        part: FramePart,
        /// Underlying I/O error.
        source: io::Error,
    },
}

impl fmt::Display for TransportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frame(source) => write!(formatter, "{source}"),
            Self::UnexpectedEof { part } => {
                write!(formatter, "BridgeXPC peer closed while reading the {part}")
            }
            Self::ConnectionClosed => {
                formatter.write_str("BridgeXPC peer closed the connection before a new frame")
            }
            Self::WriteZero { part } => {
                write!(formatter, "BridgeXPC stream stopped accepting the {part}")
            }
            Self::AllocationFailed { body_len, .. } => write!(
                formatter,
                "could not allocate the {body_len}-byte BridgeXPC body"
            ),
            Self::Io { part, source } => {
                write!(formatter, "BridgeXPC {part} I/O failed: {source}")
            }
        }
    }
}

impl Error for TransportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Frame(source) => Some(source),
            Self::AllocationFailed { source, .. } => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::UnexpectedEof { .. } | Self::WriteZero { .. } | Self::ConnectionClosed => None,
        }
    }
}

impl From<FrameError> for TransportError {
    fn from(error: FrameError) -> Self {
        Self::Frame(error)
    }
}

/// Reads and writes complete `BridgeXPC` frames over one byte stream.
#[derive(Debug)]
pub struct BridgeXpcTransport<S> {
    stream: S,
}

impl<S> BridgeXpcTransport<S> {
    /// Wraps a connected byte stream.
    #[must_use]
    pub const fn new(stream: S) -> Self {
        Self { stream }
    }

    /// Returns the wrapped stream.
    #[must_use]
    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S: Read + Write> BridgeXpcTransport<S> {
    /// Receives one complete frame.
    ///
    /// The header is validated before body allocation. Partial and interrupted
    /// reads are completed by [`Read::read_exact`].
    ///
    /// # Errors
    ///
    /// Returns an error for invalid framing, premature peer closure,
    /// allocation failure, or another stream read failure.
    pub fn receive_frame(&mut self) -> Result<Frame, TransportError> {
        let mut header_bytes = [0_u8; FRAME_HEADER_LEN];
        self.read_exact(FramePart::Header, &mut header_bytes)?;
        let header = FrameHeader::decode_exact(&header_bytes)?;

        let mut body = Vec::new();
        body.try_reserve_exact(header.body_len).map_err(|source| {
            TransportError::AllocationFailed {
                body_len: header.body_len,
                source,
            }
        })?;
        body.resize(header.body_len, 0);
        self.read_exact(FramePart::Body, &mut body)?;

        Ok(Frame {
            message_type: header.message_type,
            body,
        })
    }

    /// Sends one complete frame as its header immediately followed by its body.
    ///
    /// Partial and interrupted writes are completed by [`Write::write_all`].
    /// The method does not flush the stream.
    ///
    /// # Errors
    ///
    /// Returns an error when the body exceeds the protocol limit or the stream
    /// cannot accept the complete frame.
    pub fn send_frame(&mut self, frame: &Frame) -> Result<(), TransportError> {
        let header = FrameHeader::new(frame.message_type, frame.body.len())?.encode();
        self.write_all(FramePart::Header, &header)?;
        self.write_all(FramePart::Body, &frame.body)
    }

    /// Fills `bytes` completely, or reports exactly how the stream fell
    /// short.
    ///
    /// `std::io::Read::read_exact` cannot tell a peer that closes cleanly
    /// between frames from one that dies mid-frame: both surface as
    /// `ErrorKind::UnexpectedEof` with no byte count. This loops directly so
    /// zero bytes filled for a fresh header can be reported as
    /// [`TransportError::ConnectionClosed`], while any other short read
    /// (a header interrupted partway through, or any short body read)
    /// remains [`TransportError::UnexpectedEof`].
    fn read_exact(&mut self, part: FramePart, bytes: &mut [u8]) -> Result<(), TransportError> {
        let mut filled = 0;
        while filled < bytes.len() {
            match self.stream.read(&mut bytes[filled..]) {
                Ok(0) if filled == 0 && part == FramePart::Header => {
                    return Err(TransportError::ConnectionClosed);
                }
                Ok(0) => return Err(TransportError::UnexpectedEof { part }),
                Ok(read) => filled += read,
                Err(source) if source.kind() == io::ErrorKind::Interrupted => {}
                Err(source) => return Err(TransportError::Io { part, source }),
            }
        }
        Ok(())
    }

    fn write_all(&mut self, part: FramePart, bytes: &[u8]) -> Result<(), TransportError> {
        self.stream.write_all(bytes).map_err(|source| {
            if source.kind() == io::ErrorKind::WriteZero {
                TransportError::WriteZero { part }
            } else {
                TransportError::Io { part, source }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{BridgeXpcTransport, FramePart, TransportError};
    use crate::framing::{
        BRIDGEXPC_MAGIC, BRIDGEXPC_VERSION, FRAME_BINARY_PLIST, FRAME_HEADER_LEN, Frame,
        FrameError, MAX_FRAME_BODY_LEN,
    };
    use std::io::{self, Cursor, Read, Write};

    struct ChunkedStream {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
        maximum_chunk: usize,
        interrupt_read_once: bool,
        interrupt_write_once: bool,
    }

    impl ChunkedStream {
        fn new(input: Vec<u8>, maximum_chunk: usize) -> Self {
            Self {
                input: Cursor::new(input),
                output: Vec::new(),
                maximum_chunk,
                interrupt_read_once: false,
                interrupt_write_once: false,
            }
        }
    }

    impl Read for ChunkedStream {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.interrupt_read_once {
                self.interrupt_read_once = false;
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            let count = buffer.len().min(self.maximum_chunk);
            self.input.read(&mut buffer[..count])
        }
    }

    impl Write for ChunkedStream {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if self.interrupt_write_once {
                self.interrupt_write_once = false;
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            let count = buffer.len().min(self.maximum_chunk);
            self.output.extend_from_slice(&buffer[..count]);
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn header_bytes(message_type: u32, body_len: u64) -> [u8; FRAME_HEADER_LEN] {
        let mut bytes = [0_u8; FRAME_HEADER_LEN];
        bytes[0..2].copy_from_slice(&BRIDGEXPC_MAGIC.to_le_bytes());
        bytes[2..4].copy_from_slice(&BRIDGEXPC_VERSION.to_le_bytes());
        bytes[4..8].copy_from_slice(&message_type.to_le_bytes());
        bytes[8..16].copy_from_slice(&body_len.to_le_bytes());
        bytes
    }

    #[test]
    fn receive_completes_partial_and_interrupted_reads() {
        let expected = Frame::new(FRAME_BINARY_PLIST, b"opaque".to_vec()).unwrap();
        let mut stream = ChunkedStream::new(expected.encode().unwrap(), 2);
        stream.interrupt_read_once = true;
        let mut transport = BridgeXpcTransport::new(stream);

        assert_eq!(transport.receive_frame().unwrap(), expected);
    }

    #[test]
    fn receive_reports_eof_during_header() {
        let stream = ChunkedStream::new(vec![0; FRAME_HEADER_LEN - 1], 3);
        let error = BridgeXpcTransport::new(stream).receive_frame().unwrap_err();

        assert!(matches!(
            error,
            TransportError::UnexpectedEof {
                part: FramePart::Header
            }
        ));
    }

    #[test]
    fn receive_reports_connection_closed_for_a_stream_with_no_bytes() {
        let stream = ChunkedStream::new(Vec::new(), 3);
        let error = BridgeXpcTransport::new(stream).receive_frame().unwrap_err();

        assert!(matches!(error, TransportError::ConnectionClosed));
    }

    #[test]
    fn receive_reports_eof_during_body() {
        let mut wire = header_bytes(FRAME_BINARY_PLIST, 3).to_vec();
        wire.extend_from_slice(b"xy");
        let stream = ChunkedStream::new(wire, 3);
        let error = BridgeXpcTransport::new(stream).receive_frame().unwrap_err();

        assert!(matches!(
            error,
            TransportError::UnexpectedEof {
                part: FramePart::Body
            }
        ));
    }

    #[test]
    fn receive_rejects_oversized_length_before_reading_a_body() {
        let header = header_bytes(FRAME_BINARY_PLIST, MAX_FRAME_BODY_LEN as u64 + 1);
        let stream = ChunkedStream::new(header.to_vec(), FRAME_HEADER_LEN);
        let mut transport = BridgeXpcTransport::new(stream);

        let error = transport.receive_frame().unwrap_err();
        let stream = transport.into_inner();

        assert!(matches!(
            error,
            TransportError::Frame(FrameError::BodyTooLarge { .. })
        ));
        assert_eq!(stream.input.position(), FRAME_HEADER_LEN as u64);
    }

    #[test]
    fn receive_accepts_an_empty_body_without_an_extra_read() {
        let header = header_bytes(FRAME_BINARY_PLIST, 0);
        let stream = ChunkedStream::new(header.to_vec(), FRAME_HEADER_LEN);
        let mut transport = BridgeXpcTransport::new(stream);

        assert_eq!(
            transport.receive_frame().unwrap(),
            Frame {
                message_type: FRAME_BINARY_PLIST,
                body: Vec::new()
            }
        );
    }

    #[test]
    fn send_writes_exact_header_then_body_across_partial_writes() {
        let mut stream = ChunkedStream::new(Vec::new(), 2);
        stream.interrupt_write_once = true;
        let frame = Frame::new(FRAME_BINARY_PLIST, b"payload".to_vec()).unwrap();
        let mut transport = BridgeXpcTransport::new(stream);

        transport.send_frame(&frame).unwrap();
        let stream = transport.into_inner();

        assert_eq!(
            stream.output,
            [
                0x92, 0xb8, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, b'p', b'a', b'y', b'l', b'o', b'a', b'd',
            ]
        );
    }

    struct ZeroWriter;

    impl Read for ZeroWriter {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
    }

    impl Write for ZeroWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Ok(0)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn send_reports_a_writer_that_stops_making_progress() {
        let frame = Frame::new(FRAME_BINARY_PLIST, b"body".to_vec()).unwrap();
        let error = BridgeXpcTransport::new(ZeroWriter)
            .send_frame(&frame)
            .unwrap_err();

        assert!(matches!(
            error,
            TransportError::WriteZero {
                part: FramePart::Header
            }
        ));
    }

    #[test]
    fn send_rejects_an_oversized_body_before_writing() {
        let frame = Frame {
            message_type: FRAME_BINARY_PLIST,
            body: vec![0; MAX_FRAME_BODY_LEN + 1],
        };
        let stream = ChunkedStream::new(Vec::new(), FRAME_HEADER_LEN);
        let mut transport = BridgeXpcTransport::new(stream);

        let error = transport.send_frame(&frame).unwrap_err();
        let stream = transport.into_inner();

        assert!(matches!(
            error,
            TransportError::Frame(FrameError::BodyTooLarge { .. })
        ));
        assert!(stream.output.is_empty());
    }
}

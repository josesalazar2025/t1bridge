//! `BridgeXPC` wire-frame encoding and decoding.

use core::fmt;

pub const BRIDGEXPC_MAGIC: u16 = 0xb892;
pub const BRIDGEXPC_VERSION: u16 = 1;
pub const FRAME_HELLO: u32 = 1;
pub const FRAME_BINARY_PLIST: u32 = 2;
pub const FRAME_HEADER_LEN: usize = 16;
pub const MAX_FRAME_BODY_LEN: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameHeader {
    pub message_type: u32,
    pub body_len: usize,
}

impl FrameHeader {
    /// Creates a header for an outbound frame.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::BodyTooLarge`] when `body_len` exceeds the
    /// protocol's defensive size limit.
    pub fn new(message_type: u32, body_len: usize) -> Result<Self, FrameError> {
        validate_body_len(body_len as u64)?;
        Ok(Self {
            message_type,
            body_len,
        })
    }

    /// Decodes exactly one 16-byte frame header.
    ///
    /// # Errors
    ///
    /// Returns an error when the slice is not exactly one header, the magic or
    /// version is unsupported, or the declared body length is too large.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, FrameError> {
        if bytes.len() < FRAME_HEADER_LEN {
            return Err(FrameError::IncompleteHeader {
                available: bytes.len(),
            });
        }
        if bytes.len() > FRAME_HEADER_LEN {
            return Err(FrameError::TrailingBytes {
                count: bytes.len() - FRAME_HEADER_LEN,
            });
        }

        let magic = u16::from_le_bytes([bytes[0], bytes[1]]);
        if magic != BRIDGEXPC_MAGIC {
            return Err(FrameError::InvalidMagic { actual: magic });
        }

        let version = u16::from_le_bytes([bytes[2], bytes[3]]);
        if version != BRIDGEXPC_VERSION {
            return Err(FrameError::UnsupportedVersion { actual: version });
        }

        let message_type = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let declared_body_len = u64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        validate_body_len(declared_body_len)?;

        let body_len =
            usize::try_from(declared_body_len).map_err(|_| FrameError::BodyTooLarge {
                declared: declared_body_len,
                maximum: MAX_FRAME_BODY_LEN,
            })?;
        Ok(Self {
            message_type,
            body_len,
        })
    }

    #[must_use]
    pub fn encode(self) -> [u8; FRAME_HEADER_LEN] {
        let mut bytes = [0_u8; FRAME_HEADER_LEN];
        bytes[0..2].copy_from_slice(&BRIDGEXPC_MAGIC.to_le_bytes());
        bytes[2..4].copy_from_slice(&BRIDGEXPC_VERSION.to_le_bytes());
        bytes[4..8].copy_from_slice(&self.message_type.to_le_bytes());
        bytes[8..16].copy_from_slice(&(self.body_len as u64).to_le_bytes());
        bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub message_type: u32,
    pub body: Vec<u8>,
}

impl Frame {
    /// Creates an outbound frame with an opaque body.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::BodyTooLarge`] when the body exceeds the
    /// protocol's defensive size limit.
    pub fn new(message_type: u32, body: Vec<u8>) -> Result<Self, FrameError> {
        FrameHeader::new(message_type, body.len())?;
        Ok(Self { message_type, body })
    }

    /// Decodes a slice containing exactly one complete frame.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid or incomplete frame, or when bytes
    /// remain after the declared body.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, FrameError> {
        let (frame, remainder) = Self::decode_prefix(bytes)?;
        if !remainder.is_empty() {
            return Err(FrameError::TrailingBytes {
                count: remainder.len(),
            });
        }
        Ok(frame)
    }

    /// Decodes the first complete frame and returns the unconsumed suffix.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid header, an oversized declared body, or
    /// an incomplete header or body.
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, &[u8]), FrameError> {
        if bytes.len() < FRAME_HEADER_LEN {
            return Err(FrameError::IncompleteHeader {
                available: bytes.len(),
            });
        }

        let header = FrameHeader::decode_exact(&bytes[..FRAME_HEADER_LEN])?;
        let available = bytes.len() - FRAME_HEADER_LEN;
        if available < header.body_len {
            return Err(FrameError::IncompleteBody {
                declared: header.body_len,
                available,
            });
        }

        let body_end = FRAME_HEADER_LEN + header.body_len;
        Ok((
            Self {
                message_type: header.message_type,
                body: bytes[FRAME_HEADER_LEN..body_end].to_vec(),
            },
            &bytes[body_end..],
        ))
    }

    /// Encodes the frame as its header followed by its opaque body.
    ///
    /// # Errors
    ///
    /// Returns [`FrameError::BodyTooLarge`] when the body exceeds the
    /// protocol's defensive size limit.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        let header = FrameHeader::new(self.message_type, self.body.len())?;
        let mut bytes = Vec::with_capacity(FRAME_HEADER_LEN + self.body.len());
        bytes.extend_from_slice(&header.encode());
        bytes.extend_from_slice(&self.body);
        Ok(bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameError {
    IncompleteHeader { available: usize },
    InvalidMagic { actual: u16 },
    UnsupportedVersion { actual: u16 },
    BodyTooLarge { declared: u64, maximum: usize },
    IncompleteBody { declared: usize, available: usize },
    TrailingBytes { count: usize },
}

impl fmt::Display for FrameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IncompleteHeader { available } => write!(
                formatter,
                "incomplete BridgeXPC header: expected {FRAME_HEADER_LEN} bytes, got {available}"
            ),
            Self::InvalidMagic { actual } => {
                write!(formatter, "invalid BridgeXPC magic: 0x{actual:04x}")
            }
            Self::UnsupportedVersion { actual } => {
                write!(formatter, "unsupported BridgeXPC version: {actual}")
            }
            Self::BodyTooLarge { declared, maximum } => write!(
                formatter,
                "BridgeXPC body is too large: declared {declared} bytes, maximum is {maximum}"
            ),
            Self::IncompleteBody {
                declared,
                available,
            } => write!(
                formatter,
                "incomplete BridgeXPC body: declared {declared} bytes, got {available}"
            ),
            Self::TrailingBytes { count } => {
                write!(formatter, "BridgeXPC frame has {count} trailing bytes")
            }
        }
    }
}

impl std::error::Error for FrameError {}

fn validate_body_len(body_len: u64) -> Result<(), FrameError> {
    if body_len > MAX_FRAME_BODY_LEN as u64 {
        return Err(FrameError::BodyTooLarge {
            declared: body_len,
            maximum: MAX_FRAME_BODY_LEN,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header_bytes(message_type: u32, body_len: u64) -> [u8; FRAME_HEADER_LEN] {
        let mut bytes = [0_u8; FRAME_HEADER_LEN];
        bytes[0..2].copy_from_slice(&BRIDGEXPC_MAGIC.to_le_bytes());
        bytes[2..4].copy_from_slice(&BRIDGEXPC_VERSION.to_le_bytes());
        bytes[4..8].copy_from_slice(&message_type.to_le_bytes());
        bytes[8..16].copy_from_slice(&body_len.to_le_bytes());
        bytes
    }

    #[test]
    fn header_encoding_matches_the_little_endian_wire_layout() {
        let header = FrameHeader::new(FRAME_BINARY_PLIST, 3).unwrap();
        assert_eq!(
            header.encode(),
            [
                0x92, 0xb8, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00,
            ]
        );
    }

    #[test]
    fn header_decoding_preserves_unknown_message_types() {
        let bytes = header_bytes(0xfeed_beef, 7);
        assert_eq!(
            FrameHeader::decode_exact(&bytes),
            Ok(FrameHeader {
                message_type: 0xfeed_beef,
                body_len: 7,
            })
        );
    }

    #[test]
    fn zero_length_frame_round_trips() {
        let frame = Frame::new(FRAME_HELLO, Vec::new()).unwrap();
        let encoded = frame.encode().unwrap();
        assert_eq!(encoded.len(), FRAME_HEADER_LEN);
        assert_eq!(Frame::decode_exact(&encoded), Ok(frame));
    }

    #[test]
    fn opaque_body_round_trips_without_interpretation() {
        let body = vec![0x00, 0xff, b'b', b'p', b'l', b'i', b's', b't', 0x00];
        let frame = Frame::new(FRAME_BINARY_PLIST, body).unwrap();
        assert_eq!(Frame::decode_exact(&frame.encode().unwrap()), Ok(frame));
    }

    #[test]
    fn incomplete_headers_report_the_available_byte_count() {
        for available in [0, 1, FRAME_HEADER_LEN - 1] {
            assert_eq!(
                Frame::decode_prefix(&[0_u8; FRAME_HEADER_LEN][..available]),
                Err(FrameError::IncompleteHeader { available })
            );
        }
    }

    #[test]
    fn exact_header_decode_rejects_extra_bytes() {
        let mut bytes = header_bytes(FRAME_HELLO, 0).to_vec();
        bytes.push(0xaa);
        assert_eq!(
            FrameHeader::decode_exact(&bytes),
            Err(FrameError::TrailingBytes { count: 1 })
        );
    }

    #[test]
    fn invalid_magic_is_rejected() {
        let mut bytes = header_bytes(FRAME_HELLO, 0);
        bytes[0..2].copy_from_slice(&0x1234_u16.to_le_bytes());
        assert_eq!(
            Frame::decode_exact(&bytes),
            Err(FrameError::InvalidMagic { actual: 0x1234 })
        );
    }

    #[test]
    fn unsupported_version_is_rejected() {
        let mut bytes = header_bytes(FRAME_HELLO, 0);
        bytes[2..4].copy_from_slice(&2_u16.to_le_bytes());
        assert_eq!(
            Frame::decode_exact(&bytes),
            Err(FrameError::UnsupportedVersion { actual: 2 })
        );
    }

    #[test]
    fn oversized_declared_body_is_rejected_before_allocation() {
        let bytes = header_bytes(FRAME_BINARY_PLIST, MAX_FRAME_BODY_LEN as u64 + 1);
        assert_eq!(
            Frame::decode_prefix(&bytes),
            Err(FrameError::BodyTooLarge {
                declared: MAX_FRAME_BODY_LEN as u64 + 1,
                maximum: MAX_FRAME_BODY_LEN,
            })
        );

        assert_eq!(
            FrameHeader::new(FRAME_BINARY_PLIST, MAX_FRAME_BODY_LEN + 1),
            Err(FrameError::BodyTooLarge {
                declared: MAX_FRAME_BODY_LEN as u64 + 1,
                maximum: MAX_FRAME_BODY_LEN,
            })
        );
    }

    #[test]
    fn incomplete_body_reports_declared_and_available_lengths() {
        let mut bytes = header_bytes(FRAME_BINARY_PLIST, 4).to_vec();
        bytes.extend_from_slice(&[1, 2, 3]);
        assert_eq!(
            Frame::decode_prefix(&bytes),
            Err(FrameError::IncompleteBody {
                declared: 4,
                available: 3,
            })
        );
    }

    #[test]
    fn prefix_decode_returns_unconsumed_bytes() {
        let first = Frame::new(FRAME_HELLO, b"hello".to_vec()).unwrap();
        let second = Frame::new(FRAME_BINARY_PLIST, b"plist".to_vec()).unwrap();
        let mut bytes = first.encode().unwrap();
        let second_bytes = second.encode().unwrap();
        bytes.extend_from_slice(&second_bytes);

        let (decoded, remainder) = Frame::decode_prefix(&bytes).unwrap();
        assert_eq!(decoded, first);
        assert_eq!(remainder, second_bytes);
    }

    #[test]
    fn exact_decode_rejects_a_second_frame_as_trailing_bytes() {
        let first = Frame::new(FRAME_HELLO, Vec::new()).unwrap();
        let second = Frame::new(FRAME_BINARY_PLIST, vec![1, 2, 3]).unwrap();
        let mut bytes = first.encode().unwrap();
        let second_bytes = second.encode().unwrap();
        bytes.extend_from_slice(&second_bytes);

        assert_eq!(
            Frame::decode_exact(&bytes),
            Err(FrameError::TrailingBytes {
                count: second_bytes.len(),
            })
        );
    }

    #[test]
    fn maximum_body_length_is_accepted() {
        assert_eq!(
            FrameHeader::new(FRAME_BINARY_PLIST, MAX_FRAME_BODY_LEN),
            Ok(FrameHeader {
                message_type: FRAME_BINARY_PLIST,
                body_len: MAX_FRAME_BODY_LEN,
            })
        );
    }
}

use std::{error::Error, fmt};

pub const HEADER_LENGTH: usize = 16;
pub const MAX_PACKET_LENGTH: usize = 64 * 1024;
pub const MAX_PAYLOAD_LENGTH: usize = MAX_PACKET_LENGTH - HEADER_LENGTH;

const MAGIC: [u8; 4] = *b"T1HW";
const PROTOCOL_MAJOR: u16 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Packet<'a> {
    pub message_type: u16,
    pub request_id: u32,
    pub payload: &'a [u8],
}

impl Packet<'_> {
    /// Encodes one complete v1 packet.
    ///
    /// # Errors
    ///
    /// Returns [`PacketError::Oversize`] if the payload would make the packet
    /// exceed 64 KiB.
    pub fn encode(&self) -> Result<Vec<u8>, PacketError> {
        if self.payload.len() > MAX_PAYLOAD_LENGTH {
            return Err(PacketError::Oversize);
        }

        let payload_length =
            u32::try_from(self.payload.len()).map_err(|_| PacketError::Oversize)?;
        let mut encoded = Vec::with_capacity(HEADER_LENGTH + self.payload.len());
        encoded.extend_from_slice(&MAGIC);
        encoded.extend_from_slice(&PROTOCOL_MAJOR.to_le_bytes());
        encoded.extend_from_slice(&self.message_type.to_le_bytes());
        encoded.extend_from_slice(&payload_length.to_le_bytes());
        encoded.extend_from_slice(&self.request_id.to_le_bytes());
        encoded.extend_from_slice(self.payload);
        Ok(encoded)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketError {
    TooShort,
    BadMagic,
    WrongMajor,
    Oversize,
    LengthMismatch,
}

impl fmt::Display for PacketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::TooShort => "Touch Bar hardware packet is shorter than its header",
            Self::BadMagic => "Touch Bar hardware packet has invalid magic",
            Self::WrongMajor => "Touch Bar hardware packet has an unsupported major version",
            Self::Oversize => "Touch Bar hardware packet exceeds the size limit",
            Self::LengthMismatch => "Touch Bar hardware packet length does not match its header",
        };
        formatter.write_str(message)
    }
}

impl Error for PacketError {}

/// Decodes one complete v1 packet while borrowing its payload.
///
/// # Errors
///
/// Returns [`PacketError`] if the packet is too short, has invalid magic or a
/// protocol major other than one, exceeds 64 KiB, or does not have exactly the
/// declared payload length.
pub fn decode(packet: &[u8]) -> Result<Packet<'_>, PacketError> {
    if packet.len() < HEADER_LENGTH {
        return Err(PacketError::TooShort);
    }
    if packet.len() > MAX_PACKET_LENGTH {
        return Err(PacketError::Oversize);
    }
    if packet[..4] != MAGIC {
        return Err(PacketError::BadMagic);
    }

    let major = u16::from_le_bytes([packet[4], packet[5]]);
    if major != PROTOCOL_MAJOR {
        return Err(PacketError::WrongMajor);
    }

    let message_type = u16::from_le_bytes([packet[6], packet[7]]);
    let payload_length = u32::from_le_bytes([packet[8], packet[9], packet[10], packet[11]]);
    let request_id = u32::from_le_bytes([packet[12], packet[13], packet[14], packet[15]]);
    let payload = &packet[HEADER_LENGTH..];
    if usize::try_from(payload_length) != Ok(payload.len()) {
        return Err(PacketError::LengthMismatch);
    }

    Ok(Packet {
        message_type,
        request_id,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(major: u16, message_type: u16, payload_length: u32, request_id: u32) -> [u8; 16] {
        let mut header = [0_u8; HEADER_LENGTH];
        header[..4].copy_from_slice(&MAGIC);
        header[4..6].copy_from_slice(&major.to_le_bytes());
        header[6..8].copy_from_slice(&message_type.to_le_bytes());
        header[8..12].copy_from_slice(&payload_length.to_le_bytes());
        header[12..16].copy_from_slice(&request_id.to_le_bytes());
        header
    }

    #[test]
    fn encodes_the_exact_little_endian_header() {
        let encoded = Packet {
            message_type: 0x1234,
            request_id: 0x89ab_cdef,
            payload: &[0xaa, 0xbb, 0xcc],
        }
        .encode()
        .expect("packet is within the size limit");

        assert_eq!(
            encoded,
            [
                b'T', b'1', b'H', b'W', 0x01, 0x00, 0x34, 0x12, 0x03, 0x00, 0x00, 0x00, 0xef, 0xcd,
                0xab, 0x89, 0xaa, 0xbb, 0xcc,
            ]
        );
    }

    #[test]
    fn decodes_and_borrows_the_original_payload() {
        let mut encoded = header(1, u16::MAX, 3, u32::MAX).to_vec();
        encoded.extend_from_slice(&[1, 2, 3]);

        let decoded = decode(&encoded).expect("valid packet");

        assert_eq!(decoded.message_type, u16::MAX);
        assert_eq!(decoded.request_id, u32::MAX);
        assert_eq!(decoded.payload, &[1, 2, 3]);
        assert_eq!(decoded.payload.as_ptr(), encoded[HEADER_LENGTH..].as_ptr());
    }

    #[test]
    fn accepts_empty_payload_and_zero_opaque_fields() {
        let encoded = Packet {
            message_type: 0,
            request_id: 0,
            payload: &[],
        }
        .encode()
        .expect("empty packet is valid");

        assert_eq!(encoded.len(), HEADER_LENGTH);
        assert_eq!(
            decode(&encoded),
            Ok(Packet {
                message_type: 0,
                request_id: 0,
                payload: &[],
            })
        );
    }

    #[test]
    fn accepts_the_maximum_packet_size() {
        let payload = vec![0x5a; MAX_PAYLOAD_LENGTH];
        let encoded = Packet {
            message_type: 7,
            request_id: 9,
            payload: &payload,
        }
        .encode()
        .expect("maximum packet is valid");

        assert_eq!(encoded.len(), MAX_PACKET_LENGTH);
        assert_eq!(
            decode(&encoded).expect("maximum packet decodes").payload,
            payload
        );
    }

    #[test]
    fn rejects_every_truncated_header_length() {
        for length in 0..HEADER_LENGTH {
            assert_eq!(
                decode(&[0_u8; HEADER_LENGTH][..length]),
                Err(PacketError::TooShort)
            );
        }
    }

    #[test]
    fn rejects_each_bad_magic_byte() {
        for index in 0..MAGIC.len() {
            let mut packet = header(1, 0, 0, 0);
            packet[index] ^= 0xff;
            assert_eq!(decode(&packet), Err(PacketError::BadMagic));
        }
    }

    #[test]
    fn rejects_every_non_v1_major_boundary() {
        for major in [0, 2, u16::MAX] {
            assert_eq!(
                decode(&header(major, 0, 0, 0)),
                Err(PacketError::WrongMajor)
            );
        }
    }

    #[test]
    fn rejects_packets_over_64_kib_for_encode_and_decode() {
        let payload = vec![0_u8; MAX_PAYLOAD_LENGTH + 1];
        assert_eq!(
            Packet {
                message_type: 0,
                request_id: 0,
                payload: &payload,
            }
            .encode(),
            Err(PacketError::Oversize)
        );

        let declared_length =
            u32::try_from(MAX_PAYLOAD_LENGTH + 1).expect("test packet length fits in u32");
        let mut encoded = header(1, 0, declared_length, 0).to_vec();
        encoded.extend_from_slice(&payload);
        assert_eq!(encoded.len(), MAX_PACKET_LENGTH + 1);
        assert_eq!(decode(&encoded), Err(PacketError::Oversize));
    }

    #[test]
    fn rejects_declared_lengths_shorter_or_longer_than_the_payload() {
        for declared_length in [0, 2, 4, u32::MAX] {
            let mut encoded = header(1, 0, declared_length, 0).to_vec();
            encoded.extend_from_slice(&[1, 2, 3]);
            assert_eq!(decode(&encoded), Err(PacketError::LengthMismatch));
        }
    }

    #[test]
    fn diagnostics_are_static_and_do_not_echo_packet_data() {
        assert_eq!(
            PacketError::TooShort.to_string(),
            "Touch Bar hardware packet is shorter than its header"
        );
        assert_eq!(
            PacketError::BadMagic.to_string(),
            "Touch Bar hardware packet has invalid magic"
        );
        assert_eq!(
            PacketError::WrongMajor.to_string(),
            "Touch Bar hardware packet has an unsupported major version"
        );
        assert_eq!(
            PacketError::Oversize.to_string(),
            "Touch Bar hardware packet exceeds the size limit"
        );
        assert_eq!(
            PacketError::LengthMismatch.to_string(),
            "Touch Bar hardware packet length does not match its header"
        );
    }
}

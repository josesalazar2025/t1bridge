use std::{error::Error, fmt};

pub const CONTACT_SLOT_COUNT: usize = 10;
pub const CONTACT_SLOT_SIZE: usize = 4;
pub const DIGITIZER_PAYLOAD_SIZE: usize = 52;

const CONTACT_BYTES: usize = CONTACT_SLOT_COUNT * CONTACT_SLOT_SIZE;
const RAW_X_MAX: u16 = 32_767;
const RAW_Y_MAX: u8 = 127;
const CONTACT_ID_MASK: u8 = 0x0f;
const TIP_MASK: u8 = 0x10;
const IN_RANGE_MASK: u8 = 0x20;
const RESERVED_MASK: u8 = 0xc0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawContact {
    pub id: u8,
    pub x: u16,
    pub y: u8,
    pub tip: bool,
    pub in_range: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DigitizerReport {
    contacts: Vec<RawContact>,
}

impl DigitizerReport {
    #[must_use]
    pub fn contacts(&self) -> &[RawContact] {
        &self.contacts
    }

    #[must_use]
    pub fn scaled_contacts(&self, dimensions: DisplayDimensions) -> Vec<DisplayContact> {
        self.contacts
            .iter()
            .copied()
            .map(|contact| contact.scale(dimensions))
            .collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisplayDimensions {
    width: u32,
    height: u32,
}

impl DisplayDimensions {
    /// Creates dimensions reported by the display negotiation.
    ///
    /// # Errors
    ///
    /// Returns [`DigitizerError::InvalidDisplayDimensions`] if either axis is
    /// zero.
    pub fn new(width: u32, height: u32) -> Result<Self, DigitizerError> {
        if width == 0 || height == 0 {
            return Err(DigitizerError::InvalidDisplayDimensions);
        }
        Ok(Self { width, height })
    }

    #[must_use]
    pub fn width(self) -> u32 {
        self.width
    }

    #[must_use]
    pub fn height(self) -> u32 {
        self.height
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DisplayContact {
    pub id: u8,
    pub x: f64,
    pub y: f64,
    pub tip: bool,
    pub in_range: bool,
}

impl RawContact {
    fn scale(self, dimensions: DisplayDimensions) -> DisplayContact {
        DisplayContact {
            id: self.id,
            x: f64::from(self.x) * f64::from(dimensions.width - 1) / f64::from(RAW_X_MAX),
            y: f64::from(self.y) * f64::from(dimensions.height - 1) / f64::from(RAW_Y_MAX),
            tip: self.tip,
            in_range: self.in_range,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigitizerError {
    WrongPayloadLength,
    ReservedFlagBits,
    XOutOfRange,
    YOutOfRange,
    DuplicateActiveContact,
    InvalidDisplayDimensions,
}

impl fmt::Display for DigitizerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::WrongPayloadLength => "invalid digitizer payload length",
            Self::ReservedFlagBits => "invalid digitizer contact flags",
            Self::XOutOfRange => "digitizer x coordinate is out of range",
            Self::YOutOfRange => "digitizer y coordinate is out of range",
            Self::DuplicateActiveContact => "digitizer payload repeats an active contact",
            Self::InvalidDisplayDimensions => "invalid negotiated display dimensions",
        };
        formatter.write_str(message)
    }
}

impl Error for DigitizerError {}

/// Parses one complete descriptor-defined input payload.
///
/// # Errors
///
/// Returns [`DigitizerError`] when the payload shape, flags, coordinate ranges,
/// or active contact identifiers are invalid.
pub fn parse_digitizer_payload(payload: &[u8]) -> Result<DigitizerReport, DigitizerError> {
    if payload.len() != DIGITIZER_PAYLOAD_SIZE {
        return Err(DigitizerError::WrongPayloadLength);
    }

    let mut active_ids = 0_u16;
    let mut contacts = Vec::with_capacity(CONTACT_SLOT_COUNT);
    for slot in payload[..CONTACT_BYTES].as_chunks::<CONTACT_SLOT_SIZE>().0 {
        let flags = slot[0];
        if flags & RESERVED_MASK != 0 {
            return Err(DigitizerError::ReservedFlagBits);
        }

        let x = u16::from_le_bytes([slot[1], slot[2]]);
        if x > RAW_X_MAX {
            return Err(DigitizerError::XOutOfRange);
        }
        let y = slot[3];
        if y > RAW_Y_MAX {
            return Err(DigitizerError::YOutOfRange);
        }

        let contact = RawContact {
            id: flags & CONTACT_ID_MASK,
            x,
            y,
            tip: flags & TIP_MASK != 0,
            in_range: flags & IN_RANGE_MASK != 0,
        };
        if contact.tip || contact.in_range {
            let id_bit = 1_u16 << contact.id;
            if active_ids & id_bit != 0 {
                return Err(DigitizerError::DuplicateActiveContact);
            }
            active_ids |= id_bit;
            contacts.push(contact);
        }
    }

    // The remaining twelve bytes are vendor-defined and deliberately do not
    // enter the typed report.
    Ok(DigitizerReport { contacts })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload_with(slot: usize, contact: [u8; CONTACT_SLOT_SIZE]) -> [u8; DIGITIZER_PAYLOAD_SIZE] {
        let mut payload = [0_u8; DIGITIZER_PAYLOAD_SIZE];
        let start = slot * CONTACT_SLOT_SIZE;
        payload[start..start + CONTACT_SLOT_SIZE].copy_from_slice(&contact);
        payload
    }

    #[test]
    fn parses_active_slots_and_omits_inactive_slots() {
        let mut payload = payload_with(0, [0x31, 0xff, 0x7f, 0x7f]);
        payload[4..8].copy_from_slice(&[0x12, 0x00, 0x40, 0x20]);

        let report = parse_digitizer_payload(&payload).expect("valid payload");

        assert_eq!(
            report.contacts(),
            &[
                RawContact {
                    id: 1,
                    x: RAW_X_MAX,
                    y: RAW_Y_MAX,
                    tip: true,
                    in_range: true,
                },
                RawContact {
                    id: 2,
                    x: 16_384,
                    y: 32,
                    tip: true,
                    in_range: false,
                },
            ]
        );
    }

    #[test]
    fn drops_vendor_tail() {
        let mut first = payload_with(0, [0x31, 1, 0, 1]);
        let mut second = first;
        first[CONTACT_BYTES..].fill(0x55);
        second[CONTACT_BYTES..].fill(0xaa);

        assert_eq!(
            parse_digitizer_payload(&first).expect("valid payload"),
            parse_digitizer_payload(&second).expect("valid payload")
        );
    }

    #[test]
    fn requires_exact_payload_length() {
        assert_eq!(
            parse_digitizer_payload(&[0_u8; DIGITIZER_PAYLOAD_SIZE - 1]),
            Err(DigitizerError::WrongPayloadLength)
        );
        assert_eq!(
            parse_digitizer_payload(&[0_u8; DIGITIZER_PAYLOAD_SIZE + 1]),
            Err(DigitizerError::WrongPayloadLength)
        );
    }

    #[test]
    fn rejects_reserved_contact_flag_bits() {
        let payload = payload_with(0, [0x40, 0, 0, 0]);
        assert_eq!(
            parse_digitizer_payload(&payload),
            Err(DigitizerError::ReservedFlagBits)
        );
    }

    #[test]
    fn rejects_coordinates_outside_descriptor_ranges() {
        let bad_x = payload_with(0, [0, 0x00, 0x80, 0]);
        assert_eq!(
            parse_digitizer_payload(&bad_x),
            Err(DigitizerError::XOutOfRange)
        );

        let bad_y = payload_with(0, [0, 0, 0, 128]);
        assert_eq!(
            parse_digitizer_payload(&bad_y),
            Err(DigitizerError::YOutOfRange)
        );
    }

    #[test]
    fn rejects_repeated_active_contact_ids() {
        let mut payload = payload_with(0, [0x31, 0, 0, 0]);
        payload[4..8].copy_from_slice(&[0x11, 1, 0, 1]);
        assert_eq!(
            parse_digitizer_payload(&payload),
            Err(DigitizerError::DuplicateActiveContact)
        );
    }

    #[test]
    fn scales_raw_endpoints_to_negotiated_display() {
        let dimensions = DisplayDimensions::new(2_170, 60).expect("valid dimensions");
        let mut payload = payload_with(0, [0x31, 0, 0, 0]);
        payload[4..8].copy_from_slice(&[0x32, 0xff, 0x7f, 0x7f]);

        let contacts = parse_digitizer_payload(&payload)
            .expect("valid payload")
            .scaled_contacts(dimensions);

        assert!(contacts[0].x.abs() < f64::EPSILON);
        assert!(contacts[0].y.abs() < f64::EPSILON);
        assert!((contacts[1].x - 2_169.0).abs() < f64::EPSILON);
        assert!((contacts[1].y - 59.0).abs() < f64::EPSILON);
        assert!(contacts[1].tip);
        assert!(contacts[1].in_range);
    }

    #[test]
    fn scales_axes_without_assuming_orientation() {
        let dimensions = DisplayDimensions::new(101, 51).expect("valid dimensions");
        let payload = payload_with(0, [0x31, 0x00, 0x40, 64]);
        let contact = parse_digitizer_payload(&payload)
            .expect("valid payload")
            .scaled_contacts(dimensions)[0];

        assert!((contact.x - 50.001_526).abs() < 0.000_1);
        assert!((contact.y - 25.196_85).abs() < 0.000_1);
    }

    #[test]
    fn rejects_zero_negotiated_dimensions() {
        assert_eq!(
            DisplayDimensions::new(0, 1),
            Err(DigitizerError::InvalidDisplayDimensions)
        );
        assert_eq!(
            DisplayDimensions::new(1, 0),
            Err(DigitizerError::InvalidDisplayDimensions)
        );
    }

    #[test]
    fn diagnostics_do_not_include_payload_values() {
        let error = parse_digitizer_payload(&[0_u8; 7]).expect_err("invalid payload");
        assert_eq!(error.to_string(), "invalid digitizer payload length");
    }
}

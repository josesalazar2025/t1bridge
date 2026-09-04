//! Bounded generation metadata for standard fingerprint identities.
//!
//! This manifest carries only the canonical account name, opaque Mesa
//! identity identifiers, and optional standard finger labels. It deliberately
//! contains no numeric UID or free-form label.

use std::collections::HashSet;
use std::fmt;

use crate::standard_fingerprint_protocol::{
    FingerLabel, IdentityId, MAX_IDENTITIES, MAX_USERNAME_SIZE, Username,
};

const MAGIC: &[u8; 4] = b"T1IM";
const VERSION: u8 = 1;
const RESERVED: u16 = 0;
const HEADER_SIZE: usize = 9;
const ENTRY_SIZE: usize = 17;
pub(crate) const MAX_MANIFEST_SIZE: usize =
    HEADER_SIZE + MAX_USERNAME_SIZE + MAX_IDENTITIES as usize * ENTRY_SIZE;

/// One opaque identity and its optional standard finger label.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdentityMetadataEntry {
    pub id: IdentityId,
    pub finger: Option<FingerLabel>,
}

/// Metadata stored alongside one durable catacomb generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityMetadata {
    pub owner: Username,
    pub identities: Vec<IdentityMetadataEntry>,
}

impl IdentityMetadata {
    /// Builds a bounded manifest and rejects duplicate identity identifiers.
    ///
    /// # Errors
    ///
    /// Returns [`MetadataError::TooManyIdentities`] when Mesa's five-identity
    /// bound is exceeded, or [`MetadataError::DuplicateIdentity`] when an
    /// opaque identity occurs more than once.
    pub fn new(
        owner: Username,
        identities: Vec<IdentityMetadataEntry>,
    ) -> Result<Self, MetadataError> {
        validate_identities(&identities)?;
        Ok(Self { owner, identities })
    }
}

/// Payload-free manifest validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataError {
    TooManyIdentities,
    BadMagic,
    UnsupportedVersion,
    NonzeroReserved,
    InvalidUsername,
    InvalidIdentity,
    DuplicateIdentity,
    InvalidFingerLabel,
    TrailingData,
    Truncated,
}

impl fmt::Display for MetadataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TooManyIdentities => "identity metadata exceeds the identity bound",
            Self::BadMagic => "identity metadata has invalid magic",
            Self::UnsupportedVersion => "identity metadata version is unsupported",
            Self::NonzeroReserved => "identity metadata reserved field is nonzero",
            Self::InvalidUsername => "identity metadata owner is invalid",
            Self::InvalidIdentity => "identity metadata contains an invalid identity",
            Self::DuplicateIdentity => "identity metadata contains a duplicate identity",
            Self::InvalidFingerLabel => "identity metadata contains an invalid finger label",
            Self::TrailingData => "identity metadata contains trailing data",
            Self::Truncated => "identity metadata is truncated",
        })
    }
}

impl std::error::Error for MetadataError {}

/// Encodes one validated generation manifest.
///
/// # Errors
///
/// Revalidates the public collection fields so callers cannot encode an
/// oversized or duplicate identity set after construction.
pub fn encode(metadata: &IdentityMetadata) -> Result<Vec<u8>, MetadataError> {
    validate_identities(&metadata.identities)?;

    let username = metadata.owner.as_str().as_bytes();
    let username_length =
        u8::try_from(username.len()).map_err(|_| MetadataError::InvalidUsername)?;
    let count =
        u8::try_from(metadata.identities.len()).map_err(|_| MetadataError::TooManyIdentities)?;
    let mut encoded =
        Vec::with_capacity(HEADER_SIZE + username.len() + ENTRY_SIZE * count as usize);
    encoded.extend_from_slice(MAGIC);
    encoded.push(VERSION);
    encoded.push(count);
    encoded.extend_from_slice(&RESERVED.to_be_bytes());
    encoded.push(username_length);
    encoded.extend_from_slice(username);
    for identity in &metadata.identities {
        encoded.extend_from_slice(&identity.id.as_bytes());
        encoded.push(identity.finger.map_or(0, |finger| finger as u8));
    }
    Ok(encoded)
}

/// Decodes and validates one complete generation manifest.
///
/// # Errors
///
/// Rejects malformed, unbounded, duplicate, truncated, and extended inputs.
pub fn decode(encoded: &[u8]) -> Result<IdentityMetadata, MetadataError> {
    if encoded.len() > MAX_MANIFEST_SIZE {
        return Err(MetadataError::TooManyIdentities);
    }
    let header = encoded.get(..HEADER_SIZE).ok_or(MetadataError::Truncated)?;
    if &header[..4] != MAGIC {
        return Err(MetadataError::BadMagic);
    }
    if header[4] != VERSION {
        return Err(MetadataError::UnsupportedVersion);
    }
    let count = usize::from(header[5]);
    if count > usize::from(MAX_IDENTITIES) {
        return Err(MetadataError::TooManyIdentities);
    }
    if u16::from_be_bytes([header[6], header[7]]) != RESERVED {
        return Err(MetadataError::NonzeroReserved);
    }

    let mut cursor = HEADER_SIZE;
    let username_length = usize::from(header[8]);
    let username_bytes = take(encoded, &mut cursor, username_length)?;
    let username = std::str::from_utf8(username_bytes)
        .map_err(|_| MetadataError::InvalidUsername)
        .and_then(|value| Username::new(value).map_err(|_| MetadataError::InvalidUsername))?;

    let mut identities = Vec::with_capacity(count);
    for _ in 0..count {
        let bytes: [u8; 16] = take(encoded, &mut cursor, 16)?
            .try_into()
            .map_err(|_| MetadataError::Truncated)?;
        let id = IdentityId::new(bytes).map_err(|_| MetadataError::InvalidIdentity)?;
        let finger = decode_finger(take_byte(encoded, &mut cursor)?)?;
        identities.push(IdentityMetadataEntry { id, finger });
    }
    if cursor != encoded.len() {
        return Err(MetadataError::TrailingData);
    }
    IdentityMetadata::new(username, identities)
}

fn validate_identities(identities: &[IdentityMetadataEntry]) -> Result<(), MetadataError> {
    if identities.len() > usize::from(MAX_IDENTITIES) {
        return Err(MetadataError::TooManyIdentities);
    }
    let mut unique = HashSet::with_capacity(identities.len());
    if identities
        .iter()
        .any(|identity| !unique.insert(identity.id))
    {
        return Err(MetadataError::DuplicateIdentity);
    }
    Ok(())
}

fn decode_finger(value: u8) -> Result<Option<FingerLabel>, MetadataError> {
    let finger = match value {
        0 => return Ok(None),
        1 => FingerLabel::LeftThumb,
        2 => FingerLabel::LeftIndex,
        3 => FingerLabel::LeftMiddle,
        4 => FingerLabel::LeftRing,
        5 => FingerLabel::LeftLittle,
        6 => FingerLabel::RightThumb,
        7 => FingerLabel::RightIndex,
        8 => FingerLabel::RightMiddle,
        9 => FingerLabel::RightRing,
        10 => FingerLabel::RightLittle,
        _ => return Err(MetadataError::InvalidFingerLabel),
    };
    Ok(Some(finger))
}

fn take<'a>(
    encoded: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], MetadataError> {
    let end = cursor.checked_add(length).ok_or(MetadataError::Truncated)?;
    let value = encoded.get(*cursor..end).ok_or(MetadataError::Truncated)?;
    *cursor = end;
    Ok(value)
}

fn take_byte(encoded: &[u8], cursor: &mut usize) -> Result<u8, MetadataError> {
    let value = *encoded.get(*cursor).ok_or(MetadataError::Truncated)?;
    *cursor += 1;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> Username {
        Username::new("synthetic-owner").unwrap()
    }

    fn id(value: u8) -> IdentityId {
        IdentityId::new([value; 16]).unwrap()
    }

    fn manifest() -> IdentityMetadata {
        IdentityMetadata::new(
            owner(),
            vec![
                IdentityMetadataEntry {
                    id: id(1),
                    finger: None,
                },
                IdentityMetadataEntry {
                    id: id(2),
                    finger: Some(FingerLabel::RightIndex),
                },
            ],
        )
        .unwrap()
    }

    #[test]
    fn round_trip_preserves_labeled_and_legacy_identities() {
        let metadata = manifest();
        assert_eq!(decode(&encode(&metadata).unwrap()).unwrap(), metadata);
    }

    #[test]
    fn maximum_identities_and_username_are_accepted() {
        let metadata = IdentityMetadata::new(
            Username::new(&"a".repeat(MAX_USERNAME_SIZE)).unwrap(),
            (1..=MAX_IDENTITIES)
                .map(|value| IdentityMetadataEntry {
                    id: id(value),
                    finger: Some(FingerLabel::LeftThumb),
                })
                .collect(),
        )
        .unwrap();
        assert_eq!(decode(&encode(&metadata).unwrap()).unwrap(), metadata);
    }

    #[test]
    fn every_standard_finger_label_round_trips() {
        for finger in [
            FingerLabel::LeftThumb,
            FingerLabel::LeftIndex,
            FingerLabel::LeftMiddle,
            FingerLabel::LeftRing,
            FingerLabel::LeftLittle,
            FingerLabel::RightThumb,
            FingerLabel::RightIndex,
            FingerLabel::RightMiddle,
            FingerLabel::RightRing,
            FingerLabel::RightLittle,
        ] {
            let metadata = IdentityMetadata::new(
                owner(),
                vec![IdentityMetadataEntry {
                    id: id(1),
                    finger: Some(finger),
                }],
            )
            .unwrap();
            assert_eq!(decode(&encode(&metadata).unwrap()).unwrap(), metadata);
        }
    }

    #[test]
    fn oversized_and_duplicate_identity_sets_are_rejected() {
        let too_many: Vec<_> = (1..=MAX_IDENTITIES + 1)
            .map(|value| IdentityMetadataEntry {
                id: id(value),
                finger: None,
            })
            .collect();
        assert_eq!(
            IdentityMetadata::new(owner(), too_many),
            Err(MetadataError::TooManyIdentities)
        );

        let duplicate = IdentityMetadataEntry {
            id: id(1),
            finger: None,
        };
        assert_eq!(
            IdentityMetadata::new(owner(), vec![duplicate, duplicate]),
            Err(MetadataError::DuplicateIdentity)
        );
    }

    #[test]
    fn malformed_header_fields_are_rejected() {
        let valid = encode(&manifest()).unwrap();
        for (offset, value, expected) in [
            (0, b'X', MetadataError::BadMagic),
            (4, VERSION + 1, MetadataError::UnsupportedVersion),
            (6, 1, MetadataError::NonzeroReserved),
            (5, MAX_IDENTITIES + 1, MetadataError::TooManyIdentities),
        ] {
            let mut malformed = valid.clone();
            malformed[offset] = value;
            assert_eq!(decode(&malformed), Err(expected));
        }
    }

    #[test]
    fn invalid_username_identity_and_label_are_rejected() {
        let valid = encode(&manifest()).unwrap();

        let mut empty_owner = valid.clone();
        empty_owner[8] = 0;
        assert_eq!(decode(&empty_owner), Err(MetadataError::InvalidUsername));

        let mut nul_owner = valid.clone();
        nul_owner[HEADER_SIZE] = 0;
        assert_eq!(decode(&nul_owner), Err(MetadataError::InvalidUsername));

        let mut non_utf8_owner = valid.clone();
        non_utf8_owner[HEADER_SIZE] = 0xff;
        assert_eq!(decode(&non_utf8_owner), Err(MetadataError::InvalidUsername));

        let first_identity = HEADER_SIZE + owner().as_str().len();
        let mut zero_identity = valid.clone();
        zero_identity[first_identity..first_identity + 16].fill(0);
        assert_eq!(decode(&zero_identity), Err(MetadataError::InvalidIdentity));

        let mut duplicate_identity = valid.clone();
        let second_identity = first_identity + ENTRY_SIZE;
        duplicate_identity.copy_within(first_identity..first_identity + 16, second_identity);
        assert_eq!(
            decode(&duplicate_identity),
            Err(MetadataError::DuplicateIdentity)
        );

        let mut invalid_label = valid;
        invalid_label[first_identity + 16] = 11;
        assert_eq!(
            decode(&invalid_label),
            Err(MetadataError::InvalidFingerLabel)
        );
    }

    #[test]
    fn trailing_truncated_and_overlong_inputs_are_rejected() {
        let valid = encode(&manifest()).unwrap();

        let mut trailing = valid.clone();
        trailing.push(0);
        assert_eq!(decode(&trailing), Err(MetadataError::TrailingData));

        assert_eq!(
            decode(&valid[..valid.len() - 1]),
            Err(MetadataError::Truncated)
        );
        assert_eq!(
            decode(&vec![0; MAX_MANIFEST_SIZE + 1]),
            Err(MetadataError::TooManyIdentities)
        );
    }

    #[test]
    fn diagnostics_do_not_expose_owner_or_identity_bytes() {
        let metadata = manifest();
        let diagnostic = format!("{metadata:?}");
        assert!(!diagnostic.contains("synthetic-owner"));
        assert!(!diagnostic.contains("1, 1, 1"));

        for error in [
            MetadataError::InvalidUsername,
            MetadataError::InvalidIdentity,
            MetadataError::DuplicateIdentity,
        ] {
            let diagnostic = format!("{error:?}: {error}");
            assert!(!diagnostic.contains("synthetic-owner"));
            assert!(!diagnostic.contains("010101"));
        }
    }
}

//! Parsing and size validation for opaque Mesa catacomb metadata.
//!
//! Catacomb identifiers, hashes, and secure exports may describe biometric
//! state. This module validates their wire shape without interpreting or
//! logging their contents.

use crate::biometric::MAX_CATACOMB_COMPONENTS;
use core::fmt;

/// Exact byte length of a Mesa catacomb identifier.
pub const CATACOMB_ID_SIZE: usize = 16;
/// Exact byte length of a catacomb database hash.
pub const CATACOMB_HASH_SIZE: usize = 32;
/// Exact byte length of the hash-presence flag and hash response.
pub const CATACOMB_HASH_RESPONSE_SIZE: usize = 1 + CATACOMB_HASH_SIZE;
/// Exact byte length of a template-list CRC response.
pub const TEMPLATE_LIST_CRC_SIZE: usize = size_of::<u32>();
/// Exact byte length of one catacomb state entry.
pub const CATACOMB_STATE_ENTRY_SIZE: usize = 2 * size_of::<u32>();
/// Maximum number of state entries, including Mesa's extra master component.
pub const MAX_CATACOMB_STATE_ENTRIES: usize = MAX_CATACOMB_COMPONENTS as usize + 1;
/// Exact byte length of a secure-catacomb size response.
pub const SECURE_CATACOMB_SIZE_RESPONSE_SIZE: usize = size_of::<u32>();
/// Largest secure-catacomb payload accepted by the native protocol flow.
pub const MAX_SECURE_CATACOMB_SIZE: usize = 16 * 1024 * 1024 - 8;

/// An opaque 16-byte Mesa catacomb identifier.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct CatacombId([u8; CATACOMB_ID_SIZE]);

impl CatacombId {
    /// Returns the identifier bytes in their original wire order.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CATACOMB_ID_SIZE] {
        &self.0
    }
}

impl fmt::Debug for CatacombId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CatacombId([redacted])")
    }
}

/// An opaque 32-byte Mesa catacomb database hash.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct CatacombHash([u8; CATACOMB_HASH_SIZE]);

impl CatacombHash {
    /// Returns the hash bytes in their original wire order.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; CATACOMB_HASH_SIZE] {
        &self.0
    }
}

impl fmt::Debug for CatacombHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CatacombHash([redacted])")
    }
}

/// One little-endian `(user_id, state)` component entry reported by Mesa.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatacombStateEntry {
    /// Raw biometric user ID. `u32::MAX` denotes the master component.
    pub user_id: u32,
    /// Raw state bits, retained for recovery decisions by the caller.
    pub state: u32,
}

/// A borrowed secure-catacomb payload whose size has been validated.
///
/// The encrypted bytes remain opaque and are omitted from `Debug` output.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct OpaqueCatacomb<'a>(&'a [u8]);

impl<'a> OpaqueCatacomb<'a> {
    /// Returns the unchanged opaque payload for transport or protected storage.
    #[must_use]
    pub const fn as_bytes(self) -> &'a [u8] {
        self.0
    }
}

impl fmt::Debug for OpaqueCatacomb<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpaqueCatacomb")
            .field("len", &self.0.len())
            .field("contents", &"[redacted]")
            .finish()
    }
}

/// Identifies the fixed-layout catacomb response being parsed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatacombResponseKind {
    /// Catacomb identifier.
    Id,
    /// Optional database hash.
    Hash,
    /// Template-list CRC.
    TemplateListCrc,
    /// Secure export size.
    SecureExportSize,
}

impl fmt::Display for CatacombResponseKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Id => formatter.write_str("catacomb-ID"),
            Self::Hash => formatter.write_str("catacomb-hash"),
            Self::TemplateListCrc => formatter.write_str("template-list CRC"),
            Self::SecureExportSize => formatter.write_str("secure-catacomb size"),
        }
    }
}

/// A malformed catacomb response or invalid opaque payload size.
///
/// Errors retain only lengths and counters. No identifier, hash, state bytes,
/// or secure-catacomb contents are included.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatacombError {
    /// A fixed-layout response did not have its exact protocol length.
    InvalidResponseLength {
        /// Response being parsed.
        response: CatacombResponseKind,
        /// Required byte length.
        expected: usize,
        /// Observed byte length.
        actual: usize,
    },
    /// Mesa reported more component slots than the defensive limit.
    ImplausibleComponentCount {
        /// Component count reported by Mesa.
        actual: u32,
        /// Largest accepted component count.
        maximum: u32,
    },
    /// The state-response capacity could not be represented as a byte length.
    StateCapacityOverflow {
        /// Component count used to calculate the capacity.
        component_count: u32,
    },
    /// A state response ended partway through an eight-byte entry.
    MisalignedStateResponse {
        /// Observed response byte length.
        actual: usize,
        /// Required entry alignment.
        entry_size: usize,
    },
    /// A state response exceeded the capacity derived from daemon metadata.
    StateResponseExceedsCapacity {
        /// Observed response byte length.
        actual: usize,
        /// Maximum response byte length for the reported component count.
        capacity: usize,
    },
    /// A secure-catacomb size was zero, too large, or unrepresentable.
    InvalidSecureCatacombSize {
        /// Observed or declared byte length.
        actual: u64,
        /// Largest accepted byte length.
        maximum: usize,
    },
    /// A secure export did not match the preceding size response.
    SecureExportSizeMismatch {
        /// Size reported before the export.
        expected: usize,
        /// Observed export response size.
        actual: usize,
    },
}

impl fmt::Display for CatacombError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidResponseLength {
                response,
                expected,
                actual,
            } => write!(
                formatter,
                "{response} response is {actual} bytes; expected {expected}"
            ),
            Self::ImplausibleComponentCount { actual, maximum } => write!(
                formatter,
                "refusing implausible catacomb component count {actual}; maximum is {maximum}"
            ),
            Self::StateCapacityOverflow { component_count } => write!(
                formatter,
                "catacomb-state capacity overflows for {component_count} components"
            ),
            Self::MisalignedStateResponse { actual, entry_size } => write!(
                formatter,
                "catacomb-state response is {actual} bytes; entry size is {entry_size}"
            ),
            Self::StateResponseExceedsCapacity { actual, capacity } => write!(
                formatter,
                "catacomb-state response is {actual} bytes; capacity is {capacity}"
            ),
            Self::InvalidSecureCatacombSize { actual, maximum } => write!(
                formatter,
                "invalid secure-catacomb size {actual}; accepted range is 1..={maximum}"
            ),
            Self::SecureExportSizeMismatch { expected, actual } => write!(
                formatter,
                "secure-catacomb response is {actual} bytes; expected {expected}"
            ),
        }
    }
}

impl std::error::Error for CatacombError {}

/// Parses an exact 16-byte catacomb identifier response.
///
/// # Errors
///
/// Returns an error unless `response` has the exact identifier size.
pub fn parse_catacomb_id(response: &[u8]) -> Result<CatacombId, CatacombError> {
    let id = response.try_into().map_err(|_| {
        invalid_response_length(response, CATACOMB_ID_SIZE, CatacombResponseKind::Id)
    })?;
    Ok(CatacombId(id))
}

/// Parses Mesa's presence byte followed by a 32-byte catacomb hash.
///
/// A zero presence byte returns `None` without interpreting the remaining
/// bytes. Any nonzero presence byte returns the opaque hash, matching the
/// native client behavior.
///
/// # Errors
///
/// Returns an error unless `response` is exactly 33 bytes.
pub fn parse_catacomb_hash(response: &[u8]) -> Result<Option<CatacombHash>, CatacombError> {
    let Some((&present, hash)) = response.split_first() else {
        return Err(invalid_response_length(
            response,
            CATACOMB_HASH_RESPONSE_SIZE,
            CatacombResponseKind::Hash,
        ));
    };
    let hash: [u8; CATACOMB_HASH_SIZE] = hash.try_into().map_err(|_| {
        invalid_response_length(
            response,
            CATACOMB_HASH_RESPONSE_SIZE,
            CatacombResponseKind::Hash,
        )
    })?;
    if present == 0 {
        return Ok(None);
    }
    Ok(Some(CatacombHash(hash)))
}

/// Parses the four-byte little-endian template-list CRC response.
///
/// # Errors
///
/// Returns an error unless `response` is exactly four bytes.
pub fn parse_template_list_crc(response: &[u8]) -> Result<u32, CatacombError> {
    parse_u32_response(response, CatacombResponseKind::TemplateListCrc)
}

/// Calculates the maximum state-response capacity for daemon metadata.
///
/// Mesa reserves one additional state entry beyond its reported component
/// count for the master component.
///
/// # Errors
///
/// Returns an error when the component count exceeds the protocol limit or
/// when its byte capacity cannot be represented by `usize`.
pub fn catacomb_state_response_capacity(component_count: u32) -> Result<usize, CatacombError> {
    if component_count > MAX_CATACOMB_COMPONENTS {
        return Err(CatacombError::ImplausibleComponentCount {
            actual: component_count,
            maximum: MAX_CATACOMB_COMPONENTS,
        });
    }
    let count = usize::try_from(component_count)
        .map_err(|_| CatacombError::StateCapacityOverflow { component_count })?;
    count
        .checked_add(1)
        .and_then(|entries| entries.checked_mul(CATACOMB_STATE_ENTRY_SIZE))
        .ok_or(CatacombError::StateCapacityOverflow { component_count })
}

/// Parses zero or more complete little-endian catacomb state entries.
///
/// The response may contain at most the reported component count plus one
/// master entry. User IDs and state bits remain raw protocol values.
///
/// # Errors
///
/// Returns an error for an implausible component count, a partial entry, or a
/// response longer than the capacity derived from daemon metadata.
pub fn parse_catacomb_states(
    response: &[u8],
    component_count: u32,
) -> Result<Vec<CatacombStateEntry>, CatacombError> {
    let capacity = catacomb_state_response_capacity(component_count)?;
    let (state_entries, remainder) = response.as_chunks::<CATACOMB_STATE_ENTRY_SIZE>();
    if !remainder.is_empty() {
        return Err(CatacombError::MisalignedStateResponse {
            actual: response.len(),
            entry_size: CATACOMB_STATE_ENTRY_SIZE,
        });
    }
    if response.len() > capacity {
        return Err(CatacombError::StateResponseExceedsCapacity {
            actual: response.len(),
            capacity,
        });
    }

    let mut entries = Vec::with_capacity(response.len() / CATACOMB_STATE_ENTRY_SIZE);
    for entry in state_entries {
        let [
            user_0,
            user_1,
            user_2,
            user_3,
            state_0,
            state_1,
            state_2,
            state_3,
        ] = *entry;
        entries.push(CatacombStateEntry {
            user_id: u32::from_le_bytes([user_0, user_1, user_2, user_3]),
            state: u32::from_le_bytes([state_0, state_1, state_2, state_3]),
        });
    }
    Ok(entries)
}

/// Parses and bounds-checks a four-byte secure-catacomb export size.
///
/// # Errors
///
/// Returns an error unless the response is exactly four bytes and declares a
/// size in `1..=MAX_SECURE_CATACOMB_SIZE` representable by `usize`.
pub fn parse_secure_catacomb_size(response: &[u8]) -> Result<usize, CatacombError> {
    let declared = parse_u32_response(response, CatacombResponseKind::SecureExportSize)?;
    let size = usize::try_from(declared).map_err(|_| CatacombError::InvalidSecureCatacombSize {
        actual: u64::from(declared),
        maximum: MAX_SECURE_CATACOMB_SIZE,
    })?;
    validate_secure_catacomb_size(size)?;
    Ok(size)
}

/// Validates a prospective opaque secure-catacomb byte length.
///
/// # Errors
///
/// Returns an error for zero or a value above the 16 MiB protocol ceiling.
pub fn validate_secure_catacomb_size(size: usize) -> Result<(), CatacombError> {
    if size == 0 || size > MAX_SECURE_CATACOMB_SIZE {
        return Err(CatacombError::InvalidSecureCatacombSize {
            actual: u64::try_from(size).unwrap_or(u64::MAX),
            maximum: MAX_SECURE_CATACOMB_SIZE,
        });
    }
    Ok(())
}

/// Validates an opaque catacomb before it is used for restore or load.
///
/// # Errors
///
/// Returns an error when `data` is empty or exceeds the protocol ceiling.
pub fn validate_secure_catacomb(data: &[u8]) -> Result<OpaqueCatacomb<'_>, CatacombError> {
    validate_secure_catacomb_size(data.len())?;
    Ok(OpaqueCatacomb(data))
}

/// Validates an opaque export against its preceding size response.
///
/// # Errors
///
/// Returns an error when `expected_size` is outside the protocol bounds or
/// the export does not have exactly that many bytes.
pub fn validate_secure_catacomb_export(
    response: &[u8],
    expected_size: usize,
) -> Result<OpaqueCatacomb<'_>, CatacombError> {
    validate_secure_catacomb_size(expected_size)?;
    if response.len() != expected_size {
        return Err(CatacombError::SecureExportSizeMismatch {
            expected: expected_size,
            actual: response.len(),
        });
    }
    Ok(OpaqueCatacomb(response))
}

fn parse_u32_response(
    response: &[u8],
    response_kind: CatacombResponseKind,
) -> Result<u32, CatacombError> {
    let &[byte_0, byte_1, byte_2, byte_3] = response else {
        return Err(invalid_response_length(
            response,
            size_of::<u32>(),
            response_kind,
        ));
    };
    Ok(u32::from_le_bytes([byte_0, byte_1, byte_2, byte_3]))
}

fn invalid_response_length(
    response: &[u8],
    expected: usize,
    response_kind: CatacombResponseKind,
) -> CatacombError {
    CatacombError::InvalidResponseLength {
        response: response_kind,
        expected,
        actual: response.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_exact_opaque_catacomb_id_and_redacts_debug() {
        let bytes = [
            0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed,
            0xfe, 0x0f,
        ];
        let id = parse_catacomb_id(&bytes).expect("synthetic ID is valid");
        assert_eq!(id.as_bytes(), &bytes);
        assert_eq!(format!("{id:?}"), "CatacombId([redacted])");
    }

    #[test]
    fn catacomb_id_requires_exact_size() {
        for response in [
            &[0_u8; CATACOMB_ID_SIZE - 1][..],
            &[0_u8; CATACOMB_ID_SIZE + 1][..],
        ] {
            assert!(matches!(
                parse_catacomb_id(response),
                Err(CatacombError::InvalidResponseLength {
                    response: CatacombResponseKind::Id,
                    expected: CATACOMB_ID_SIZE,
                    actual,
                }) if actual == response.len()
            ));
        }
    }

    #[test]
    fn parses_present_hash_and_redacts_debug() {
        let expected = [0xa5; CATACOMB_HASH_SIZE];
        let mut response = [0_u8; CATACOMB_HASH_RESPONSE_SIZE];
        response[0] = 1;
        response[1..].copy_from_slice(&expected);

        let hash = parse_catacomb_hash(&response)
            .expect("synthetic hash response is valid")
            .expect("presence flag is set");
        assert_eq!(hash.as_bytes(), &expected);
        assert_eq!(format!("{hash:?}"), "CatacombHash([redacted])");
    }

    #[test]
    fn any_nonzero_hash_presence_flag_is_present() {
        let mut response = [0_u8; CATACOMB_HASH_RESPONSE_SIZE];
        response[0] = 0xff;
        response[1..].fill(0x3c);
        assert!(
            parse_catacomb_hash(&response)
                .expect("response has exact size")
                .is_some()
        );
    }

    #[test]
    fn absent_hash_does_not_expose_trailing_bytes() {
        let mut response = [0x5a; CATACOMB_HASH_RESPONSE_SIZE];
        response[0] = 0;
        assert_eq!(parse_catacomb_hash(&response), Ok(None));
    }

    #[test]
    fn catacomb_hash_requires_presence_byte_and_exact_hash_size() {
        assert!(parse_catacomb_hash(&[0_u8; CATACOMB_HASH_SIZE]).is_err());
        assert!(parse_catacomb_hash(&[0_u8; CATACOMB_HASH_RESPONSE_SIZE + 1]).is_err());
    }

    #[test]
    fn template_crc_is_little_endian_and_exact_size() {
        assert_eq!(
            parse_template_list_crc(&[0x78, 0x56, 0x34, 0x12]),
            Ok(0x1234_5678)
        );
        assert!(parse_template_list_crc(&[0x78, 0x56, 0x34]).is_err());
        assert!(parse_template_list_crc(&[0x78, 0x56, 0x34, 0x12, 0]).is_err());
    }

    #[test]
    fn state_capacity_reserves_master_entry_and_enforces_limit() {
        assert_eq!(catacomb_state_response_capacity(0), Ok(8));
        assert_eq!(
            catacomb_state_response_capacity(MAX_CATACOMB_COMPONENTS),
            Ok(MAX_CATACOMB_STATE_ENTRIES * CATACOMB_STATE_ENTRY_SIZE)
        );
        assert_eq!(
            catacomb_state_response_capacity(MAX_CATACOMB_COMPONENTS + 1),
            Err(CatacombError::ImplausibleComponentCount {
                actual: MAX_CATACOMB_COMPONENTS + 1,
                maximum: MAX_CATACOMB_COMPONENTS,
            })
        );
    }

    #[test]
    fn parses_state_entries_in_order_without_interpreting_values() {
        let mut response = Vec::new();
        response.extend_from_slice(&501_u32.to_le_bytes());
        response.extend_from_slice(&0x8000_0003_u32.to_le_bytes());
        response.extend_from_slice(&u32::MAX.to_le_bytes());
        response.extend_from_slice(&1_u32.to_le_bytes());

        assert_eq!(
            parse_catacomb_states(&response, 1),
            Ok(vec![
                CatacombStateEntry {
                    user_id: 501,
                    state: 0x8000_0003,
                },
                CatacombStateEntry {
                    user_id: u32::MAX,
                    state: 1,
                },
            ])
        );
    }

    #[test]
    fn empty_state_response_is_valid() {
        assert_eq!(parse_catacomb_states(&[], 0), Ok(vec![]));
    }

    #[test]
    fn rejects_partial_or_over_capacity_state_responses() {
        assert_eq!(
            parse_catacomb_states(&[0; CATACOMB_STATE_ENTRY_SIZE + 1], 1),
            Err(CatacombError::MisalignedStateResponse {
                actual: CATACOMB_STATE_ENTRY_SIZE + 1,
                entry_size: CATACOMB_STATE_ENTRY_SIZE,
            })
        );
        assert_eq!(
            parse_catacomb_states(&[0; 2 * CATACOMB_STATE_ENTRY_SIZE], 0),
            Err(CatacombError::StateResponseExceedsCapacity {
                actual: 2 * CATACOMB_STATE_ENTRY_SIZE,
                capacity: CATACOMB_STATE_ENTRY_SIZE,
            })
        );
    }

    #[test]
    fn secure_export_size_is_little_endian_exact_and_bounded() {
        assert_eq!(parse_secure_catacomb_size(&1_u32.to_le_bytes()), Ok(1));
        let maximum = u32::try_from(MAX_SECURE_CATACOMB_SIZE).expect("maximum fits u32");
        assert_eq!(
            parse_secure_catacomb_size(&maximum.to_le_bytes()),
            Ok(MAX_SECURE_CATACOMB_SIZE)
        );
        assert!(parse_secure_catacomb_size(&[]).is_err());
        assert!(parse_secure_catacomb_size(&[0; 5]).is_err());
        assert!(matches!(
            parse_secure_catacomb_size(&0_u32.to_le_bytes()),
            Err(CatacombError::InvalidSecureCatacombSize { actual: 0, .. })
        ));
        assert!(matches!(
            parse_secure_catacomb_size(&(maximum + 1).to_le_bytes()),
            Err(CatacombError::InvalidSecureCatacombSize { actual, .. })
                if actual == u64::from(maximum + 1)
        ));
    }

    #[test]
    fn opaque_blob_validation_accepts_only_protocol_size_range() {
        let bytes = [0x42, 0x73, 0xa4];
        let catacomb = validate_secure_catacomb(&bytes).expect("nonempty small blob is valid");
        assert_eq!(catacomb.as_bytes(), &bytes);
        assert_eq!(
            format!("{catacomb:?}"),
            "OpaqueCatacomb { len: 3, contents: \"[redacted]\" }"
        );
        assert!(validate_secure_catacomb(&[]).is_err());
        assert!(validate_secure_catacomb_size(MAX_SECURE_CATACOMB_SIZE).is_ok());
        assert!(validate_secure_catacomb_size(MAX_SECURE_CATACOMB_SIZE + 1).is_err());
    }

    #[test]
    fn export_must_match_valid_previously_reported_size() {
        let response = [0x19, 0x2a, 0x3b];
        assert_eq!(
            validate_secure_catacomb_export(&response, response.len())
                .expect("matching export is valid")
                .as_bytes(),
            &response
        );
        assert_eq!(
            validate_secure_catacomb_export(&response, response.len() + 1),
            Err(CatacombError::SecureExportSizeMismatch {
                expected: response.len() + 1,
                actual: response.len(),
            })
        );
        assert!(matches!(
            validate_secure_catacomb_export(&response, 0),
            Err(CatacombError::InvalidSecureCatacombSize { actual: 0, .. })
        ));
        assert!(matches!(
            validate_secure_catacomb_export(&response, MAX_SECURE_CATACOMB_SIZE + 1),
            Err(CatacombError::InvalidSecureCatacombSize { .. })
        ));
    }
}

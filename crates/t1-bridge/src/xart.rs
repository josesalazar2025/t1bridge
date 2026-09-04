//! Read-only xART recovery-directory request and parser.

use core::fmt;
use std::collections::BTreeMap;
use std::io::{Read, Write};

use crate::bplist::Value;
use crate::session::{BridgeXpcSession, RawDictionaryError};

/// Size of the complete packed xART directory returned by recovery command 200.
pub const XART_DIRECTORY_SIZE: usize = 0x334;
/// Size of one packed UUID and location entry.
pub const XART_DIRECTORY_ENTRY_SIZE: usize = 17;
/// Number of entry slots in the fixed-size directory.
pub const XART_DIRECTORY_MAX_ENTRIES: usize = 48;

const XART_DIRECTORY_COUNT_SIZE: usize = size_of::<u32>();
const XART_RECOVERY_VERSION: u64 = 1;
const XART_FETCH_DIRECTORY_COMMAND: u64 = 200;
const VERSION_KEY: &str = "xart-msg.version";
const COMMAND_KEY: &str = "xart-msg.command";
const SUCCESS_KEY: &str = "xart-msg.success";
const DIRECTORY_KEY: &str = "xart-msg.directory";
const UINT64_WRAPPER_KEY: &str = "__com.apple.BridgeXPC.uint64";

/// One declared xART directory entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XartDirectoryEntry {
    /// Opaque volume UUID bytes in wire order.
    pub volume_uuid: [u8; 16],
    /// Whether the entry refers to external storage.
    pub external: bool,
}

/// A malformed packed xART directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XartDirectoryError {
    /// The response was not the protocol's fixed directory size.
    InvalidSize {
        /// Actual response size in bytes.
        actual: usize,
        /// Required response size in bytes.
        expected: usize,
    },
    /// The directory count exceeded the number of packed slots.
    TooManyEntries {
        /// Count declared by the response.
        count: u32,
        /// Maximum accepted count.
        maximum: usize,
    },
    /// A declared entry used an unknown storage-location value.
    InvalidLocation {
        /// Zero-based index of the malformed entry.
        index: usize,
        /// Raw location byte from the response.
        value: u8,
    },
}

impl fmt::Display for XartDirectoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSize { actual, expected } => write!(
                formatter,
                "xART directory has {actual} bytes; expected {expected}"
            ),
            Self::TooManyEntries { count, maximum } => write!(
                formatter,
                "xART directory claims {count} entries; maximum is {maximum}"
            ),
            Self::InvalidLocation { index, value } => write!(
                formatter,
                "xART directory entry {index} has invalid location {value}"
            ),
        }
    }
}

impl std::error::Error for XartDirectoryError {}

/// A redaction-safe read-only xART recovery failure.
pub enum XartFetchError {
    /// The raw `BridgeXPC` dictionary exchange failed.
    Exchange(RawDictionaryError),
    /// A present recovery-protocol version was not the exact wrapped value 1.
    InvalidVersion,
    /// Recovery command 200 did not report success.
    FetchFailed,
    /// The successful reply omitted its opaque packed directory bytes.
    MissingDirectory,
    /// The packed recovery directory was malformed.
    Directory(XartDirectoryError),
}

impl fmt::Debug for XartFetchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exchange(_) => formatter.write_str("Exchange([redacted])"),
            Self::InvalidVersion => formatter.write_str("InvalidVersion"),
            Self::FetchFailed => formatter.write_str("FetchFailed"),
            Self::MissingDirectory => formatter.write_str("MissingDirectory"),
            Self::Directory(error) => formatter.debug_tuple("Directory").field(error).finish(),
        }
    }
}

impl fmt::Display for XartFetchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exchange(_) => formatter.write_str("xART recovery exchange failed"),
            Self::InvalidVersion => formatter.write_str("xART recovery version is invalid"),
            Self::FetchFailed => formatter.write_str("xART directory fetch failed"),
            Self::MissingDirectory => {
                formatter.write_str("xART recovery reply omitted directory data")
            }
            Self::Directory(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for XartFetchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Directory(error) => Some(error),
            Self::Exchange(_)
            | Self::InvalidVersion
            | Self::FetchFailed
            | Self::MissingDirectory => None,
        }
    }
}

impl From<RawDictionaryError> for XartFetchError {
    fn from(error: RawDictionaryError) -> Self {
        Self::Exchange(error)
    }
}

impl From<XartDirectoryError> for XartFetchError {
    fn from(error: XartDirectoryError) -> Self {
        Self::Directory(error)
    }
}

/// Fetches the packed recovery directory with the read-only native command 200.
///
/// This uses `BridgeXPC`'s raw-dictionary listener protocol, not an RPC envelope.
/// The request contains only the exact wrapped version and command values and
/// cannot carry xART data or select the save operation.
///
/// # Errors
///
/// Returns a redaction-safe error when the exchange fails, the response has an
/// invalid optional version or unsuccessful result, directory data is absent,
/// or the packed directory is malformed.
pub fn fetch_xart_directory<S: Read + Write>(
    session: &mut BridgeXpcSession<S>,
) -> Result<Vec<XartDirectoryEntry>, XartFetchError> {
    let response = session.call_raw_dictionary(&directory_request())?;

    if response
        .get(VERSION_KEY)
        .is_some_and(|value| !is_wrapped_u64(value, XART_RECOVERY_VERSION))
    {
        return Err(XartFetchError::InvalidVersion);
    }
    if response.get(SUCCESS_KEY) != Some(&Value::Boolean(true)) {
        return Err(XartFetchError::FetchFailed);
    }
    let Some(Value::Data(directory)) = response.get(DIRECTORY_KEY) else {
        return Err(XartFetchError::MissingDirectory);
    };
    parse_xart_directory(directory).map_err(XartFetchError::from)
}

fn directory_request() -> BTreeMap<String, Value> {
    BTreeMap::from([
        (VERSION_KEY.to_owned(), wrapped_u64(XART_RECOVERY_VERSION)),
        (
            COMMAND_KEY.to_owned(),
            wrapped_u64(XART_FETCH_DIRECTORY_COMMAND),
        ),
    ])
}

fn wrapped_u64(value: u64) -> Value {
    Value::Dictionary(BTreeMap::from([(
        UINT64_WRAPPER_KEY.to_owned(),
        Value::Integer(i128::from(value)),
    )]))
}

fn is_wrapped_u64(value: &Value, expected: u64) -> bool {
    let Value::Dictionary(wrapper) = value else {
        return false;
    };
    wrapper.len() == 1
        && wrapper.get(UINT64_WRAPPER_KEY) == Some(&Value::Integer(i128::from(expected)))
}

/// Parses one complete packed xART recovery directory.
///
/// UUID bytes are intentionally kept opaque. Location `0` means internal and
/// location `1` means external. Unused fixed-size slots are not interpreted.
///
/// # Errors
///
/// Returns an error unless `data` has the exact fixed size, its little-endian
/// count fits the 48 packed slots, and every declared entry has location `0`
/// or `1`.
pub fn parse_xart_directory(data: &[u8]) -> Result<Vec<XartDirectoryEntry>, XartDirectoryError> {
    if data.len() != XART_DIRECTORY_SIZE {
        return Err(XartDirectoryError::InvalidSize {
            actual: data.len(),
            expected: XART_DIRECTORY_SIZE,
        });
    }

    let declared_count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let count =
        usize::try_from(declared_count).map_err(|_| XartDirectoryError::TooManyEntries {
            count: declared_count,
            maximum: XART_DIRECTORY_MAX_ENTRIES,
        })?;
    if count > XART_DIRECTORY_MAX_ENTRIES {
        return Err(XartDirectoryError::TooManyEntries {
            count: declared_count,
            maximum: XART_DIRECTORY_MAX_ENTRIES,
        });
    }

    let mut entries = Vec::with_capacity(count);
    for index in 0..count {
        let offset = XART_DIRECTORY_COUNT_SIZE + index * XART_DIRECTORY_ENTRY_SIZE;
        let mut volume_uuid = [0_u8; 16];
        volume_uuid.copy_from_slice(&data[offset..offset + 16]);
        let location = data[offset + 16];
        let external = match location {
            0 => false,
            1 => true,
            value => return Err(XartDirectoryError::InvalidLocation { index, value }),
        };
        entries.push(XartDirectoryEntry {
            volume_uuid,
            external,
        });
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::framing::{FRAME_BINARY_PLIST, FRAME_HELLO, Frame};
    use crate::hello::encode_hello;
    use crate::rpc::{RpcError, decode_envelope, decode_raw_dictionary, encode_raw_dictionary};
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

    fn dictionary_frame(dictionary: &BTreeMap<String, Value>) -> Frame {
        Frame::new(
            FRAME_BINARY_PLIST,
            encode_raw_dictionary(dictionary).unwrap(),
        )
        .unwrap()
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

    fn fetch_response(
        response: &BTreeMap<String, Value>,
    ) -> Result<Vec<XartDirectoryEntry>, XartFetchError> {
        let frames = [hello_frame(), dictionary_frame(response)];
        let mut session =
            BridgeXpcSession::connect(Duplex::new(&frames), "synthetic-client").unwrap();
        fetch_xart_directory(&mut session)
    }

    fn directory_with_count(count: u32) -> [u8; XART_DIRECTORY_SIZE] {
        let mut directory = [0_u8; XART_DIRECTORY_SIZE];
        directory[..XART_DIRECTORY_COUNT_SIZE].copy_from_slice(&count.to_le_bytes());
        directory
    }

    fn write_entry(
        directory: &mut [u8; XART_DIRECTORY_SIZE],
        index: usize,
        volume_uuid: [u8; 16],
        location: u8,
    ) {
        let offset = XART_DIRECTORY_COUNT_SIZE + index * XART_DIRECTORY_ENTRY_SIZE;
        directory[offset..offset + 16].copy_from_slice(&volume_uuid);
        directory[offset + 16] = location;
    }

    #[test]
    fn parses_empty_directory() {
        assert_eq!(parse_xart_directory(&directory_with_count(0)), Ok(vec![]));
    }

    #[test]
    fn fetch_uses_one_exact_read_only_raw_dictionary_request() {
        let first_uuid = [0x11; 16];
        let second_uuid = [0x22; 16];
        let mut directory = directory_with_count(2);
        write_entry(&mut directory, 0, first_uuid, 0);
        write_entry(&mut directory, 1, second_uuid, 1);
        let response = BTreeMap::from([
            (VERSION_KEY.to_owned(), wrapped_u64(XART_RECOVERY_VERSION)),
            (SUCCESS_KEY.to_owned(), Value::Boolean(true)),
            (DIRECTORY_KEY.to_owned(), Value::Data(directory.to_vec())),
        ]);
        let frames = [
            hello_frame(),
            Frame::new(77, Vec::new()).unwrap(),
            dictionary_frame(&response),
        ];
        let mut session =
            BridgeXpcSession::connect(Duplex::new(&frames), "synthetic-client").unwrap();

        assert_eq!(
            fetch_xart_directory(&mut session).unwrap(),
            vec![
                XartDirectoryEntry {
                    volume_uuid: first_uuid,
                    external: false,
                },
                XartDirectoryEntry {
                    volume_uuid: second_uuid,
                    external: true,
                },
            ]
        );

        let output = output_frames(&session.into_inner());
        assert_eq!(output.len(), 2);
        assert_eq!(output[0].message_type, FRAME_HELLO);
        assert_eq!(output[0].body, encode_hello("synthetic-client").unwrap());
        let request = decode_raw_dictionary(&output[1].body).unwrap();
        assert_eq!(request, directory_request());
        assert_eq!(request.len(), 2);
        assert_eq!(
            request.get(COMMAND_KEY),
            Some(&wrapped_u64(XART_FETCH_DIRECTORY_COMMAND))
        );
        assert!(!request.contains_key(DIRECTORY_KEY));
        assert_eq!(
            decode_envelope(&output[1].body),
            Err(RpcError::InvalidEnvelope)
        );
    }

    #[test]
    fn fetch_accepts_the_reference_optional_version() {
        let response = BTreeMap::from([
            (SUCCESS_KEY.to_owned(), Value::Boolean(true)),
            (
                DIRECTORY_KEY.to_owned(),
                Value::Data(directory_with_count(0).to_vec()),
            ),
        ]);
        assert_eq!(fetch_response(&response).unwrap(), Vec::new());
    }

    #[test]
    fn fetch_rejects_malformed_and_unsuccessful_replies() {
        let invalid_version = BTreeMap::from([
            (VERSION_KEY.to_owned(), wrapped_u64(2)),
            (SUCCESS_KEY.to_owned(), Value::Boolean(true)),
            (
                DIRECTORY_KEY.to_owned(),
                Value::Data(directory_with_count(0).to_vec()),
            ),
        ]);
        assert!(matches!(
            fetch_response(&invalid_version),
            Err(XartFetchError::InvalidVersion)
        ));

        let failed = BTreeMap::from([
            (SUCCESS_KEY.to_owned(), Value::Boolean(false)),
            (
                "xart-msg.error".to_owned(),
                Value::String("private peer detail".into()),
            ),
        ]);
        let error = fetch_response(&failed).unwrap_err();
        assert!(matches!(error, XartFetchError::FetchFailed));
        assert!(!format!("{error:?} {error}").contains("private peer detail"));

        let missing = BTreeMap::from([(SUCCESS_KEY.to_owned(), Value::Boolean(true))]);
        assert!(matches!(
            fetch_response(&missing),
            Err(XartFetchError::MissingDirectory)
        ));

        let wrong_type = BTreeMap::from([
            (SUCCESS_KEY.to_owned(), Value::Boolean(true)),
            (
                DIRECTORY_KEY.to_owned(),
                Value::String("private directory marker".into()),
            ),
        ]);
        assert!(matches!(
            fetch_response(&wrong_type),
            Err(XartFetchError::MissingDirectory)
        ));

        let malformed = BTreeMap::from([
            (SUCCESS_KEY.to_owned(), Value::Boolean(true)),
            (DIRECTORY_KEY.to_owned(), Value::Data(vec![0; 4])),
        ]);
        assert!(matches!(
            fetch_response(&malformed),
            Err(XartFetchError::Directory(
                XartDirectoryError::InvalidSize { .. }
            ))
        ));
    }

    #[test]
    fn preserves_opaque_uuid_bytes_and_entry_order() {
        let first_uuid = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let second_uuid = [
            0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
            0x11, 0x00,
        ];
        let mut directory = directory_with_count(2);
        write_entry(&mut directory, 0, first_uuid, 0);
        write_entry(&mut directory, 1, second_uuid, 1);

        assert_eq!(
            parse_xart_directory(&directory),
            Ok(vec![
                XartDirectoryEntry {
                    volume_uuid: first_uuid,
                    external: false,
                },
                XartDirectoryEntry {
                    volume_uuid: second_uuid,
                    external: true,
                },
            ])
        );
    }

    #[test]
    fn accepts_all_48_declared_slots() {
        let mut directory = directory_with_count(
            u32::try_from(XART_DIRECTORY_MAX_ENTRIES).expect("slot count fits u32"),
        );
        for index in 0..XART_DIRECTORY_MAX_ENTRIES {
            let mut volume_uuid = [0_u8; 16];
            volume_uuid[0] = u8::try_from(index).unwrap();
            write_entry(
                &mut directory,
                index,
                volume_uuid,
                u8::try_from(index % 2).unwrap(),
            );
        }

        let entries = parse_xart_directory(&directory).unwrap();
        assert_eq!(entries.len(), XART_DIRECTORY_MAX_ENTRIES);
        assert_eq!(entries[0].volume_uuid[0], 0);
        assert_eq!(entries[47].volume_uuid[0], 47);
        assert!(!entries[46].external);
        assert!(entries[47].external);
    }

    #[test]
    fn rejects_short_and_long_directories() {
        assert_eq!(
            parse_xart_directory(&[0_u8; XART_DIRECTORY_SIZE - 1]),
            Err(XartDirectoryError::InvalidSize {
                actual: XART_DIRECTORY_SIZE - 1,
                expected: XART_DIRECTORY_SIZE,
            })
        );
        assert_eq!(
            parse_xart_directory(&[0_u8; XART_DIRECTORY_SIZE + 1]),
            Err(XartDirectoryError::InvalidSize {
                actual: XART_DIRECTORY_SIZE + 1,
                expected: XART_DIRECTORY_SIZE,
            })
        );
    }

    #[test]
    fn decodes_count_as_little_endian_and_rejects_more_than_48_entries() {
        let directory = directory_with_count(49);
        assert_eq!(
            parse_xart_directory(&directory),
            Err(XartDirectoryError::TooManyEntries {
                count: 49,
                maximum: XART_DIRECTORY_MAX_ENTRIES,
            })
        );

        let mut big_endian_count = [0_u8; XART_DIRECTORY_SIZE];
        big_endian_count[..XART_DIRECTORY_COUNT_SIZE].copy_from_slice(&49_u32.to_be_bytes());
        assert_eq!(
            parse_xart_directory(&big_endian_count),
            Err(XartDirectoryError::TooManyEntries {
                count: 49_u32.swap_bytes(),
                maximum: XART_DIRECTORY_MAX_ENTRIES,
            })
        );
    }

    #[test]
    fn rejects_unknown_locations_in_any_declared_entry() {
        for (index, value) in [(0, 2), (1, u8::MAX)] {
            let mut directory = directory_with_count(2);
            write_entry(
                &mut directory,
                index,
                [u8::try_from(index).unwrap(); 16],
                value,
            );
            assert_eq!(
                parse_xart_directory(&directory),
                Err(XartDirectoryError::InvalidLocation { index, value })
            );
        }
    }

    #[test]
    fn ignores_unused_slots() {
        let mut directory = directory_with_count(1);
        write_entry(&mut directory, 0, [0x11; 16], 0);
        write_entry(&mut directory, 1, [0x22; 16], 0xff);

        assert_eq!(
            parse_xart_directory(&directory),
            Ok(vec![XartDirectoryEntry {
                volume_uuid: [0x11; 16],
                external: false,
            }])
        );
    }
}

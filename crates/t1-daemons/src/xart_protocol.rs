//! Request handling for the T1 xART storage service.

use crate::xart_store::{XartStore, XartStoreError};
use std::collections::BTreeMap;
use t1_bridge::bplist::Value;

const PROTOCOL_VERSION: u64 = 1;
const FETCH_COMMAND: u64 = 100;
const SAVE_COMMAND: u64 = 150;

const VERSION_KEY: &str = "xart-msg.version";
const COMMAND_KEY: &str = "xart-msg.command";
const SUCCESS_KEY: &str = "xart-msg.success";
const ERROR_KEY: &str = "xart-msg.error";
const XART_KEY: &str = "xart-msg.xart";
const VOLUME_UUID_KEY: &str = "xart-msg.volume-uuid";
const VOLUME_EXTERNAL_KEY: &str = "xart-msg.volume-external?";

const UINT64_WRAPPER_KEY: &str = "__com.apple.BridgeXPC.uint64";
const UUID_WRAPPER_KEY: &str = "__com.apple.BridgeXPC.UUID";

/// Handles one decoded xART storage request.
///
/// The opaque xART value is passed directly to the store and is never logged
/// or interpreted here. Protocol and storage failures become bounded,
/// payload-free response dictionaries as required by the peer.
#[must_use]
pub fn handle_request(store: &XartStore, request: &Value) -> BTreeMap<String, Value> {
    let Value::Dictionary(request) = request else {
        return failure("request is not a dictionary");
    };

    if request.get(VERSION_KEY).and_then(decode_uint64) != Some(PROTOCOL_VERSION) {
        return failure("invalid or missing protocol version");
    }

    match request.get(COMMAND_KEY).and_then(decode_uint64) {
        Some(FETCH_COMMAND) => fetch(store),
        Some(SAVE_COMMAND) => save(store, request.get(XART_KEY)),
        _ => failure("unsupported command"),
    }
}

fn fetch(store: &XartStore) -> BTreeMap<String, Value> {
    match store.fetch() {
        Ok(fetched) => BTreeMap::from([
            (VERSION_KEY.into(), bridgexpc_uint64(PROTOCOL_VERSION)),
            (SUCCESS_KEY.into(), Value::Boolean(true)),
            (XART_KEY.into(), Value::Data(fetched.wire_blob)),
            (VOLUME_UUID_KEY.into(), bridgexpc_uuid(fetched.volume_id)),
            (
                VOLUME_EXTERNAL_KEY.into(),
                Value::Boolean(fetched.volume_external),
            ),
        ]),
        Err(error) => storage_failure(error),
    }
}

fn save(store: &XartStore, value: Option<&Value>) -> BTreeMap<String, Value> {
    let Some(Value::Data(wire_blob)) = value else {
        return failure("save request contained an invalid xART");
    };

    match store.save(wire_blob) {
        Ok(()) => BTreeMap::from([
            (VERSION_KEY.into(), bridgexpc_uint64(PROTOCOL_VERSION)),
            (SUCCESS_KEY.into(), Value::Boolean(true)),
        ]),
        Err(error) => storage_failure(error),
    }
}

fn storage_failure(error: XartStoreError) -> BTreeMap<String, Value> {
    let message = match error {
        XartStoreError::InvalidWireBlob => "save request contained an invalid xART",
        XartStoreError::StorageUnavailable => "xART storage is unavailable",
        XartStoreError::UnsafeStorage => "xART storage is unsafe",
        XartStoreError::InvalidStoredBlob => "stored xART is invalid",
    };
    failure(message)
}

fn failure(message: &str) -> BTreeMap<String, Value> {
    BTreeMap::from([
        (VERSION_KEY.into(), bridgexpc_uint64(PROTOCOL_VERSION)),
        (SUCCESS_KEY.into(), Value::Boolean(false)),
        (ERROR_KEY.into(), Value::String(message.into())),
    ])
}

fn bridgexpc_uint64(value: u64) -> Value {
    Value::Dictionary(BTreeMap::from([(
        UINT64_WRAPPER_KEY.into(),
        Value::Integer(i128::from(value)),
    )]))
}

fn bridgexpc_uuid(value: [u8; 16]) -> Value {
    Value::Dictionary(BTreeMap::from([(
        UUID_WRAPPER_KEY.into(),
        Value::Data(value.to_vec()),
    )]))
}

fn decode_uint64(value: &Value) -> Option<u64> {
    match value {
        Value::Integer(value) => u64::try_from(*value).ok(),
        Value::Dictionary(wrapper) if wrapper.len() == 1 => wrapper
            .get(UINT64_WRAPPER_KEY)
            .and_then(|value| match value {
                Value::Integer(value) => u64::try_from(*value).ok(),
                _ => None,
            }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "t1bridge-xart-protocol-test-{}-{sequence}",
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

    fn store(directory: &Path) -> XartStore {
        XartStore::new(directory, [0x22; 16], false)
    }

    fn request(command: u64) -> Value {
        Value::Dictionary(BTreeMap::from([
            (VERSION_KEY.into(), bridgexpc_uint64(PROTOCOL_VERSION)),
            (COMMAND_KEY.into(), bridgexpc_uint64(command)),
        ]))
    }

    fn is_success(response: &BTreeMap<String, Value>) -> bool {
        response.get(SUCCESS_KEY) == Some(&Value::Boolean(true))
    }

    #[test]
    fn missing_record_fetch_bootstraps_zero_length_with_volume_metadata() {
        let directory = TestDirectory::new();
        let response = handle_request(&store(&directory.0), &request(FETCH_COMMAND));
        assert!(is_success(&response));
        assert_eq!(response.get(XART_KEY), Some(&Value::Data(vec![0; 4])));
        assert_eq!(
            response.get(VOLUME_UUID_KEY),
            Some(&bridgexpc_uuid([0x22; 16]))
        );
        assert_eq!(
            response.get(VOLUME_EXTERNAL_KEY),
            Some(&Value::Boolean(false))
        );
    }

    #[test]
    fn valid_save_is_always_enabled_and_round_trips_opaque_bytes() {
        let directory = TestDirectory::new();
        let store = store(&directory.0);
        let wire_blob = vec![3, 0, 0, 0, 0xaa, 0xbb, 0xcc];
        let Value::Dictionary(mut fields) = request(SAVE_COMMAND) else {
            unreachable!();
        };
        fields.insert(XART_KEY.into(), Value::Data(wire_blob.clone()));
        assert!(is_success(&handle_request(
            &store,
            &Value::Dictionary(fields)
        )));

        let fetched = handle_request(&store, &request(FETCH_COMMAND));
        assert_eq!(fetched.get(XART_KEY), Some(&Value::Data(wire_blob)));
    }

    #[test]
    fn validates_request_shape_version_command_and_save_data() {
        let directory = TestDirectory::new();
        let store = store(&directory.0);
        for invalid in [
            Value::Array(Vec::new()),
            Value::Dictionary(BTreeMap::new()),
            request(999),
        ] {
            assert!(!is_success(&handle_request(&store, &invalid)));
        }

        let response = handle_request(&store, &request(SAVE_COMMAND));
        assert_eq!(
            response.get(ERROR_KEY),
            Some(&Value::String(
                "save request contained an invalid xART".into()
            ))
        );
    }

    #[test]
    fn accepts_plain_or_wrapped_nonnegative_uint64_only() {
        assert_eq!(decode_uint64(&Value::Integer(1)), Some(1));
        assert_eq!(decode_uint64(&bridgexpc_uint64(u64::MAX)), Some(u64::MAX));
        assert_eq!(decode_uint64(&Value::Integer(-1)), None);
        assert_eq!(decode_uint64(&Value::Boolean(true)), None);

        let wrapper_with_extra_key = Value::Dictionary(BTreeMap::from([
            (UINT64_WRAPPER_KEY.into(), Value::Integer(1)),
            ("extra".into(), Value::Integer(2)),
        ]));
        assert_eq!(decode_uint64(&wrapper_with_extra_key), None);
    }

    #[test]
    fn response_debug_never_discloses_opaque_xart_data() {
        let directory = TestDirectory::new();
        let store = store(&directory.0);
        let marker = b"SYNTHETIC_SECRET_MARKER";
        let mut wire_blob = Vec::with_capacity(marker.len() + 4);
        wire_blob.extend_from_slice(
            &u32::try_from(marker.len())
                .expect("synthetic marker fits u32")
                .to_le_bytes(),
        );
        wire_blob.extend_from_slice(marker);
        let Value::Dictionary(mut fields) = request(SAVE_COMMAND) else {
            unreachable!();
        };
        fields.insert(XART_KEY.into(), Value::Data(wire_blob));
        assert!(is_success(&handle_request(
            &store,
            &Value::Dictionary(fields)
        )));

        let response = handle_request(&store, &request(FETCH_COMMAND));
        assert!(!format!("{response:?}").contains("SYNTHETIC_SECRET_MARKER"));
    }
}

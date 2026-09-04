//! Opaque persistence for the T1 xART anti-replay record.

use std::fmt;
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

/// Largest xART payload accepted by SEP's mailbox protocol.
pub const XART_MAX_PAYLOAD_SIZE: usize = 0x3fef;

// Linux UAPI values. `OpenOptionsExt::custom_flags` is the safe standard-library
// route for opening the stored record and directory without following a final
// symlink.
const O_DIRECTORY: i32 = 0o2_00000;
const O_NOFOLLOW: i32 = 0o4_00000;

static TEMPORARY_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);
const RECORD_FILE_NAME: &str = "record.xart";

/// Storage failure that is safe to report without exposing the opaque record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XartStoreError {
    InvalidWireBlob,
    StorageUnavailable,
    UnsafeStorage,
    InvalidStoredBlob,
}

impl fmt::Display for XartStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidWireBlob => "xART wire blob is invalid",
            Self::StorageUnavailable => "xART storage is unavailable",
            Self::UnsafeStorage => "xART storage has unsafe ownership or permissions",
            Self::InvalidStoredBlob => "stored xART is invalid",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for XartStoreError {}

/// A fetched xART record and the volume metadata returned with it.
#[derive(Clone, Eq, PartialEq)]
pub struct FetchedXart {
    /// Four-byte little-endian payload length followed by the opaque payload.
    pub wire_blob: Vec<u8>,
    pub volume_id: [u8; 16],
    pub volume_external: bool,
}

impl fmt::Debug for FetchedXart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FetchedXart")
            .field("wire_blob_len", &self.wire_blob.len())
            .field("wire_blob", &"[redacted]")
            .field("volume_id", &"[redacted]")
            .field("volume_external", &self.volume_external)
            .finish()
    }
}

/// Persistent storage for the one admitted T1 device's opaque xART record.
pub struct XartStore {
    directory: PathBuf,
    volume_id: [u8; 16],
    volume_external: bool,
}

impl fmt::Debug for XartStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("XartStore")
            .field("directory", &self.directory)
            .field("volume_id", &"[redacted]")
            .field("volume_external", &self.volume_external)
            .finish()
    }
}

impl XartStore {
    /// Creates a store for the admitted xART service.
    pub fn new(directory: impl Into<PathBuf>, volume_id: [u8; 16], volume_external: bool) -> Self {
        Self {
            directory: directory.into(),
            volume_id,
            volume_external,
        }
    }

    /// Fetches the stored opaque record.
    ///
    /// A missing record is a successful first-volume bootstrap containing a
    /// four-byte zero length, matching the T1 service contract.
    ///
    /// # Errors
    ///
    /// Returns an error when the record cannot be opened or read, is not a
    /// regular file owned by the effective user with mode `0600`, or has an
    /// invalid size.
    pub fn fetch(&self) -> Result<FetchedXart, XartStoreError> {
        let path = self.path();
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return self.fetched(&[]);
            }
            Err(_) => return Err(XartStoreError::StorageUnavailable),
        };

        let metadata = file
            .metadata()
            .map_err(|_| XartStoreError::StorageUnavailable)?;
        validate_record_metadata(&metadata)?;
        let payload_size =
            usize::try_from(metadata.len()).map_err(|_| XartStoreError::InvalidStoredBlob)?;
        if payload_size == 0 || payload_size > XART_MAX_PAYLOAD_SIZE {
            return Err(XartStoreError::InvalidStoredBlob);
        }

        let mut payload = vec![0; payload_size];
        file.read_exact(&mut payload)
            .map_err(|_| XartStoreError::InvalidStoredBlob)?;
        let mut trailing_byte = [0_u8; 1];
        if file
            .read(&mut trailing_byte)
            .map_err(|_| XartStoreError::StorageUnavailable)?
            != 0
        {
            return Err(XartStoreError::InvalidStoredBlob);
        }

        self.fetched(&payload)
    }

    /// Atomically saves a length-wrapped opaque record and durably syncs both
    /// the file and its containing directory.
    ///
    /// # Errors
    ///
    /// Returns an error when the wrapper is malformed or safe and durable
    /// storage cannot be completed.
    pub fn save(&self, wire_blob: &[u8]) -> Result<(), XartStoreError> {
        let payload = validate_wire_blob(wire_blob)?;
        let directory = self.prepare_directory()?;
        let (mut temporary, temporary_path) = self.create_temporary_file()?;

        let result = (|| {
            temporary
                .set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|_| XartStoreError::StorageUnavailable)?;
            temporary
                .write_all(payload)
                .map_err(|_| XartStoreError::StorageUnavailable)?;
            temporary
                .sync_all()
                .map_err(|_| XartStoreError::StorageUnavailable)?;
            drop(temporary);

            fs::rename(&temporary_path, self.path())
                .map_err(|_| XartStoreError::StorageUnavailable)?;
            directory
                .sync_all()
                .map_err(|_| XartStoreError::StorageUnavailable)
        })();

        if result.is_err() {
            let _ = fs::remove_file(temporary_path);
        }
        result
    }

    fn fetched(&self, payload: &[u8]) -> Result<FetchedXart, XartStoreError> {
        let payload_length =
            u32::try_from(payload.len()).map_err(|_| XartStoreError::InvalidStoredBlob)?;
        let mut wire_blob = Vec::with_capacity(payload.len() + 4);
        wire_blob.extend_from_slice(&payload_length.to_le_bytes());
        wire_blob.extend_from_slice(payload);
        Ok(FetchedXart {
            wire_blob,
            volume_id: self.volume_id,
            volume_external: self.volume_external,
        })
    }

    fn path(&self) -> PathBuf {
        self.directory.join(RECORD_FILE_NAME)
    }

    fn prepare_directory(&self) -> Result<File, XartStoreError> {
        fs::create_dir_all(&self.directory).map_err(|_| XartStoreError::StorageUnavailable)?;
        let directory = OpenOptions::new()
            .read(true)
            .custom_flags(O_DIRECTORY | O_NOFOLLOW)
            .open(&self.directory)
            .map_err(|_| XartStoreError::UnsafeStorage)?;
        let metadata = directory
            .metadata()
            .map_err(|_| XartStoreError::StorageUnavailable)?;
        validate_directory_identity(&metadata)?;
        directory
            .set_permissions(fs::Permissions::from_mode(0o700))
            .map_err(|_| XartStoreError::StorageUnavailable)?;
        let secured_metadata = directory
            .metadata()
            .map_err(|_| XartStoreError::StorageUnavailable)?;
        if secured_metadata.mode() & 0o777 != 0o700 {
            return Err(XartStoreError::UnsafeStorage);
        }
        Ok(directory)
    }

    fn create_temporary_file(&self) -> Result<(File, PathBuf), XartStoreError> {
        for _ in 0..64 {
            let sequence = TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let name = format!(".record.{}.{}.tmp", std::process::id(), sequence);
            let path = self.directory.join(name);
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(O_NOFOLLOW)
                .open(&path)
            {
                Ok(file) => return Ok((file, path)),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(XartStoreError::StorageUnavailable),
            }
        }
        Err(XartStoreError::StorageUnavailable)
    }
}

fn validate_wire_blob(wire_blob: &[u8]) -> Result<&[u8], XartStoreError> {
    let header = wire_blob.get(..4).ok_or(XartStoreError::InvalidWireBlob)?;
    let declared_size = usize::try_from(u32::from_le_bytes(
        header
            .try_into()
            .map_err(|_| XartStoreError::InvalidWireBlob)?,
    ))
    .map_err(|_| XartStoreError::InvalidWireBlob)?;
    if declared_size == 0
        || declared_size > XART_MAX_PAYLOAD_SIZE
        || wire_blob.len().checked_sub(4) != Some(declared_size)
    {
        return Err(XartStoreError::InvalidWireBlob);
    }
    Ok(&wire_blob[4..])
}

fn validate_record_metadata(metadata: &Metadata) -> Result<(), XartStoreError> {
    if !metadata.file_type().is_file()
        || metadata.mode() & 0o777 != 0o600
        || metadata.uid() != effective_uid()?
    {
        return Err(XartStoreError::UnsafeStorage);
    }
    Ok(())
}

fn validate_directory_identity(metadata: &Metadata) -> Result<(), XartStoreError> {
    if !metadata.file_type().is_dir() || metadata.uid() != effective_uid()? {
        return Err(XartStoreError::UnsafeStorage);
    }
    Ok(())
}

fn effective_uid() -> Result<u32, XartStoreError> {
    let status =
        fs::read_to_string("/proc/self/status").map_err(|_| XartStoreError::StorageUnavailable)?;
    let uid_line = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .ok_or(XartStoreError::StorageUnavailable)?;
    uid_line
        .split_ascii_whitespace()
        .nth(1)
        .ok_or(XartStoreError::StorageUnavailable)?
        .parse()
        .map_err(|_| XartStoreError::StorageUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::path::Path;

    static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "t1bridge-xart-store-test-{}-{sequence}",
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

    fn wire_blob(payload: &[u8]) -> Vec<u8> {
        let mut wire = Vec::with_capacity(payload.len() + 4);
        wire.extend_from_slice(
            &u32::try_from(payload.len())
                .expect("synthetic payload fits in u32")
                .to_le_bytes(),
        );
        wire.extend_from_slice(payload);
        wire
    }

    #[test]
    fn missing_fetch_returns_zero_length_bootstrap_without_creating_a_file() {
        let directory = TestDirectory::new();
        let store = store(&directory.0);

        let fetched = store.fetch().expect("missing record is a valid bootstrap");

        assert_eq!(fetched.wire_blob, [0, 0, 0, 0]);
        assert_eq!(fetched.volume_id, store.volume_id);
        assert!(!fetched.volume_external);
        assert!(!store.path().exists());
    }

    #[test]
    fn valid_save_is_always_enabled_and_round_trips_atomically() {
        let directory = TestDirectory::new();
        let store = store(&directory.0);
        let payload: Vec<u8> = (0_u8..=255).cycle().take(2048).collect();

        store
            .save(&wire_blob(&payload))
            .expect("save opaque record");
        let metadata = fs::metadata(store.path()).expect("stored record metadata");
        let fetched = store.fetch().expect("fetch opaque record");

        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(fetched.wire_blob, wire_blob(&payload));
        assert_eq!(fetched.volume_id, store.volume_id);
        assert!(!fetched.volume_external);
        let entries = fs::read_dir(&directory.0)
            .expect("read store directory")
            .collect::<Result<Vec<_>, _>>()
            .expect("read every store entry");
        assert_eq!(
            entries.len(),
            1,
            "atomic save must not leave a temporary file"
        );
    }

    #[test]
    fn malformed_wire_blobs_are_rejected() {
        let directory = TestDirectory::new();
        let store = store(&directory.0);
        let oversized = wire_blob(&vec![0; XART_MAX_PAYLOAD_SIZE + 1]);
        let cases = [
            Vec::new(),
            vec![0, 0, 0, 0],
            vec![1, 0, 0, 0],
            vec![2, 0, 0, 0, 0],
            oversized,
        ];

        for case in cases {
            assert_eq!(store.save(&case), Err(XartStoreError::InvalidWireBlob));
        }
        assert!(!store.path().exists());
    }

    #[test]
    fn maximum_sized_payload_round_trips() {
        let directory = TestDirectory::new();
        let store = store(&directory.0);
        let payload = vec![0xa5; XART_MAX_PAYLOAD_SIZE];

        store
            .save(&wire_blob(&payload))
            .expect("save maximum record");

        assert_eq!(
            store.fetch().expect("fetch maximum record").wire_blob,
            wire_blob(&payload)
        );
    }

    #[test]
    fn fetch_rejects_a_world_readable_file() {
        let directory = TestDirectory::new();
        let store = store(&directory.0);
        fs::write(store.path(), b"opaque").expect("create unsafe record");
        fs::set_permissions(store.path(), fs::Permissions::from_mode(0o644))
            .expect("make record world readable");

        assert_eq!(store.fetch(), Err(XartStoreError::UnsafeStorage));
    }

    #[test]
    fn fetch_rejects_empty_and_oversized_records() {
        let directory = TestDirectory::new();
        let store = store(&directory.0);

        for payload in [Vec::new(), vec![0; XART_MAX_PAYLOAD_SIZE + 1]] {
            fs::write(store.path(), payload).expect("create invalid record");
            fs::set_permissions(store.path(), fs::Permissions::from_mode(0o600))
                .expect("secure record permissions");
            assert_eq!(store.fetch(), Err(XartStoreError::InvalidStoredBlob));
        }
    }

    #[test]
    fn fetch_does_not_follow_a_symlink() {
        let directory = TestDirectory::new();
        let store = store(&directory.0);
        let target = directory.0.join("unrelated");
        fs::write(&target, b"opaque").expect("create symlink target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600))
            .expect("secure target permissions");
        symlink(&target, store.path()).expect("create stored-record symlink");

        assert_eq!(store.fetch(), Err(XartStoreError::StorageUnavailable));
        assert_eq!(fs::read(target).expect("read untouched target"), b"opaque");
    }

    #[test]
    fn save_rejects_a_symlinked_storage_directory() {
        let parent = TestDirectory::new();
        let target = parent.0.join("target");
        let link = parent.0.join("store");
        fs::create_dir(&target).expect("create target directory");
        symlink(&target, &link).expect("create directory symlink");
        let store = store(&link);

        assert_eq!(
            store.save(&wire_blob(b"opaque")),
            Err(XartStoreError::UnsafeStorage)
        );
        assert!(
            fs::read_dir(target)
                .expect("read target directory")
                .next()
                .is_none()
        );
    }

    #[test]
    fn save_replaces_a_record_symlink_without_touching_its_target() {
        let directory = TestDirectory::new();
        let store = store(&directory.0);
        let target = directory.0.join("unrelated");
        fs::write(&target, b"unrelated data").expect("create symlink target");
        symlink(&target, store.path()).expect("create stored-record symlink");

        store
            .save(&wire_blob(b"opaque"))
            .expect("replace symlink atomically");

        assert_eq!(
            fs::read(target).expect("read untouched target"),
            b"unrelated data"
        );
        assert_eq!(
            store.fetch().expect("fetch replacement").wire_blob,
            wire_blob(b"opaque")
        );
    }

    #[test]
    fn stored_file_owner_must_equal_the_effective_user() {
        let current_uid = effective_uid().expect("read effective UID");
        let directory = TestDirectory::new();
        let store = store(&directory.0);
        fs::write(store.path(), b"opaque").expect("create record");
        fs::set_permissions(store.path(), fs::Permissions::from_mode(0o600))
            .expect("secure record permissions");

        assert_eq!(
            fs::metadata(store.path()).expect("record metadata").uid(),
            current_uid
        );
        assert!(store.fetch().is_ok());
    }

    #[test]
    fn uses_one_fixed_identifier_free_storage_name() {
        let directory = TestDirectory::new();
        let store = store(&directory.0);

        assert_eq!(store.path(), directory.0.join("record.xart"));
    }

    #[test]
    fn debug_output_redacts_the_blob_and_runtime_identifiers() {
        let directory = TestDirectory::new();
        let store = store(&directory.0);
        let fetched = store.fetched(b"opaque-secret-marker").unwrap();

        let fetched_debug = format!("{fetched:?}");
        assert!(!fetched_debug.contains("opaque-secret-marker"));
        assert!(!fetched_debug.contains("22222222"));
        assert!(fetched_debug.contains("[redacted]"));

        let store_debug = format!("{store:?}");
        assert!(!store_debug.contains("22222222"));
        assert!(store_debug.contains("[redacted]"));
    }
}

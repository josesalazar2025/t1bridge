//! Durable single-owner policy for Touch ID enrollment and authentication.

use core::fmt;
use std::fs::{self, DirBuilder, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::auth_protocol::{AccessPolicy, PolicyError};

const OWNER_FILE: &str = "owner.uid";
const OWNER_PENDING_PREFIX: &str = ".owner.uid.pending-";
const DIRECTORY_MODE: u32 = 0o700;
const OWNER_FILE_MODE: u32 = 0o600;
const MAX_OWNER_FILE_SIZE: u64 = 11;

// Linux UAPI values used through the safe standard-library open interface.
const O_DIRECTORY: i32 = 0o2_00000;
const O_NOFOLLOW: i32 = 0o4_00000;

static PENDING_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A validated, non-root Linux UID that owns the one enrolled biometric set.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EnrollmentOwner(u32);

impl EnrollmentOwner {
    /// Validates a Linux UID for first-owner enrollment.
    ///
    /// # Errors
    ///
    /// Root is rejected because it does not identify a non-root enrollment
    /// owner.
    pub const fn new(user_id: u32) -> Result<Self, EnrollmentOwnerError> {
        if user_id == 0 {
            Err(EnrollmentOwnerError::InvalidOwner)
        } else {
            Ok(Self(user_id))
        }
    }

    /// Returns the validated Linux UID for kernel-credential comparison.
    #[must_use]
    pub const fn as_raw(self) -> u32 {
        self.0
    }
}

impl fmt::Debug for EnrollmentOwner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EnrollmentOwner(<redacted>)")
    }
}

/// Result of reserving the enrollment owner before hardware mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerClaim {
    /// No owner existed, so this owner was durably recorded.
    Recorded,
    /// The same owner was already recorded; no storage mutation occurred.
    Existing,
}

/// Redaction-safe ownership-state failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentOwnerError {
    /// Root or an otherwise invalid UID was offered as an enrollment owner.
    InvalidOwner,
    /// No owner state exists, so biometric authentication cannot be authorized.
    MissingOwner,
    /// A different non-root UID already owns the enrolled biometric set.
    DifferentOwner,
    /// The owner directory or file has unsafe metadata.
    UnsafeStorage,
    /// The owner file does not contain one canonical non-root UID.
    CorruptState,
    /// Owner state could not be read or durably written.
    StorageUnavailable,
}

impl fmt::Display for EnrollmentOwnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidOwner => "enrollment owner is invalid",
            Self::MissingOwner => "enrollment owner is not recorded",
            Self::DifferentOwner => "a different user owns Touch ID enrollment",
            Self::UnsafeStorage => "enrollment-owner storage is unsafe",
            Self::CorruptState => "enrollment-owner state is corrupt",
            Self::StorageUnavailable => "enrollment-owner storage is unavailable",
        })
    }
}

impl std::error::Error for EnrollmentOwnerError {}

/// Root-owned storage for the one Linux UID permitted to use the biometric set.
pub struct EnrollmentOwnerStore {
    directory: PathBuf,
    expected_user_id: u32,
    expected_group_id: u32,
}

struct PendingOwnerFile {
    path: PathBuf,
    file: File,
}

impl PendingOwnerFile {
    fn remove(self) -> io::Result<()> {
        fs::remove_file(&self.path)
    }
}

impl Drop for PendingOwnerFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

impl fmt::Debug for EnrollmentOwnerStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnrollmentOwnerStore")
            .field("directory", &"[redacted]")
            .finish_non_exhaustive()
    }
}

impl EnrollmentOwnerStore {
    /// Creates production owner storage. The directory and state must be owned
    /// by root with exact private modes.
    #[must_use]
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            expected_user_id: 0,
            expected_group_id: 0,
        }
    }

    /// Loads the recorded owner without changing storage.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe failure for missing, unsafe, unreadable, or
    /// corrupt state.
    pub fn load(&self) -> Result<EnrollmentOwner, EnrollmentOwnerError> {
        let directory = self.open_directory(false)?;
        let owner = self.read_owner()?;
        self.ensure_directory_identity(&directory)?;
        Ok(owner)
    }

    /// Loads the recorded owner as the broker's peer-admission policy.
    ///
    /// # Errors
    ///
    /// Fails closed when owner state is missing, unsafe, unreadable, corrupt,
    /// or cannot form a valid non-root policy.
    pub fn access_policy(&self) -> Result<AccessPolicy, EnrollmentOwnerError> {
        AccessPolicy::new(self.load()?.as_raw()).map_err(map_policy_error)
    }

    /// Durably records the first enrollment owner or validates the same owner.
    ///
    /// A different existing owner is refused without changing any filesystem
    /// object. The exact owner file is created exclusively and synchronized
    /// before enrollment may reach hardware.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe failure for a different owner or any unsafe,
    /// corrupt, unavailable, or non-durable state.
    pub fn claim(&self, owner: EnrollmentOwner) -> Result<OwnerClaim, EnrollmentOwnerError> {
        let directory = self.open_directory(true)?;
        match self.read_owner() {
            Ok(existing) => {
                self.ensure_directory_identity(&directory)?;
                // A previous publisher may have returned an error before its
                // directory sync completed. Re-synchronize even an existing
                // canonical record so success always precedes hardware with a
                // durable first-owner directory entry.
                directory
                    .sync_all()
                    .map_err(|_| EnrollmentOwnerError::StorageUnavailable)?;
                return if existing == owner {
                    Ok(OwnerClaim::Existing)
                } else {
                    Err(EnrollmentOwnerError::DifferentOwner)
                };
            }
            Err(EnrollmentOwnerError::MissingOwner) => {}
            Err(error) => return Err(error),
        }

        let mut pending = self.create_pending_file()?;

        pending
            .file
            .set_permissions(fs::Permissions::from_mode(OWNER_FILE_MODE))
            .map_err(|_| EnrollmentOwnerError::StorageUnavailable)?;
        validate_private_file_metadata(
            &pending
                .file
                .metadata()
                .map_err(|_| EnrollmentOwnerError::StorageUnavailable)?,
            self.expected_user_id,
            self.expected_group_id,
        )?;
        pending
            .file
            .write_all(format!("{}\n", owner.as_raw()).as_bytes())
            .map_err(|_| EnrollmentOwnerError::StorageUnavailable)?;
        pending
            .file
            .sync_all()
            .map_err(|_| EnrollmentOwnerError::StorageUnavailable)?;
        self.ensure_directory_identity(&directory)?;

        let owner_path = self.directory.join(OWNER_FILE);
        match fs::hard_link(&pending.path, &owner_path) {
            Ok(()) => {
                // The exclusively created temporary name keeps the fully
                // synchronized inode stable while its temporary directory
                // entry is removed. A crash in this interval leaves a
                // recognizable same-inode link that `read_owner` can
                // distinguish from an arbitrary hard link.
                pending
                    .remove()
                    .map_err(|_| EnrollmentOwnerError::StorageUnavailable)?;
                directory
                    .sync_all()
                    .map_err(|_| EnrollmentOwnerError::StorageUnavailable)?;
                self.ensure_directory_identity(&directory)?;
                if self.read_owner()? != owner {
                    return Err(EnrollmentOwnerError::CorruptState);
                }
                Ok(OwnerClaim::Recorded)
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                pending
                    .remove()
                    .map_err(|_| EnrollmentOwnerError::StorageUnavailable)?;
                directory
                    .sync_all()
                    .map_err(|_| EnrollmentOwnerError::StorageUnavailable)?;
                self.ensure_directory_identity(&directory)?;
                match self.read_owner()? {
                    existing if existing == owner => Ok(OwnerClaim::Existing),
                    _ => Err(EnrollmentOwnerError::DifferentOwner),
                }
            }
            Err(_) => Err(EnrollmentOwnerError::StorageUnavailable),
        }
    }

    fn read_owner(&self) -> Result<EnrollmentOwner, EnrollmentOwnerError> {
        let path = self.directory.join(OWNER_FILE);
        let mut file = match OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW)
            .open(path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(EnrollmentOwnerError::MissingOwner);
            }
            Err(_) => return Err(EnrollmentOwnerError::StorageUnavailable),
        };
        let metadata = file
            .metadata()
            .map_err(|_| EnrollmentOwnerError::StorageUnavailable)?;
        self.validate_owner_file_metadata(&file, &metadata)?;
        if metadata.len() == 0 || metadata.len() > MAX_OWNER_FILE_SIZE {
            return Err(EnrollmentOwnerError::CorruptState);
        }

        let mut encoded = String::new();
        (&mut file)
            .take(MAX_OWNER_FILE_SIZE + 1)
            .read_to_string(&mut encoded)
            .map_err(|_| EnrollmentOwnerError::CorruptState)?;
        if u64::try_from(encoded.len()).ok() != Some(metadata.len()) {
            return Err(EnrollmentOwnerError::CorruptState);
        }
        parse_owner(&encoded)
    }

    fn create_pending_file(&self) -> Result<PendingOwnerFile, EnrollmentOwnerError> {
        // A bounded retry handles stale or concurrently claimed names without
        // introducing randomness or another dependency. `create_new` is the
        // race authority across processes.
        for _ in 0..64 {
            let sequence = PENDING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = self
                .directory
                .join(format!("{OWNER_PENDING_PREFIX}{sequence}"));
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .mode(OWNER_FILE_MODE)
                .custom_flags(O_NOFOLLOW)
                .open(&path)
            {
                Ok(file) => return Ok(PendingOwnerFile { path, file }),
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(EnrollmentOwnerError::StorageUnavailable),
            }
        }
        Err(EnrollmentOwnerError::StorageUnavailable)
    }

    fn validate_owner_file_metadata(
        &self,
        file: &File,
        metadata: &Metadata,
    ) -> Result<(), EnrollmentOwnerError> {
        validate_private_file_metadata(metadata, self.expected_user_id, self.expected_group_id)?;
        if metadata.nlink() == 1 {
            return Ok(());
        }

        // A crash after atomic publication but before removal of our unique
        // temporary name can leave extra links. Accept only when every extra
        // link is a private, recognized pending entry in this same validated
        // directory and points to the exact owner inode. An unrelated hard
        // link, including one outside this directory, still fails closed.
        let mut recognized_links = 0_u64;
        let entries =
            fs::read_dir(&self.directory).map_err(|_| EnrollmentOwnerError::StorageUnavailable)?;
        for entry in entries {
            let entry = entry.map_err(|_| EnrollmentOwnerError::StorageUnavailable)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| EnrollmentOwnerError::UnsafeStorage)?;
            if !is_pending_name(&name) {
                continue;
            }
            let pending = match OpenOptions::new()
                .read(true)
                .custom_flags(O_NOFOLLOW)
                .open(entry.path())
            {
                Ok(pending) => pending,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(_) => return Err(EnrollmentOwnerError::UnsafeStorage),
            };
            let pending_metadata = pending
                .metadata()
                .map_err(|_| EnrollmentOwnerError::StorageUnavailable)?;
            validate_private_file_metadata(
                &pending_metadata,
                self.expected_user_id,
                self.expected_group_id,
            )?;
            if pending_metadata.dev() == metadata.dev() && pending_metadata.ino() == metadata.ino()
            {
                recognized_links = recognized_links
                    .checked_add(1)
                    .ok_or(EnrollmentOwnerError::UnsafeStorage)?;
            }
        }
        let current = file
            .metadata()
            .map_err(|_| EnrollmentOwnerError::StorageUnavailable)?;
        validate_private_file_metadata(&current, self.expected_user_id, self.expected_group_id)?;
        if current.nlink() == 1 {
            return Ok(());
        }
        if current.nlink() != metadata.nlink() {
            return Err(EnrollmentOwnerError::UnsafeStorage);
        }
        if recognized_links
            .checked_add(1)
            .is_some_and(|links| links == current.nlink())
        {
            Ok(())
        } else {
            Err(EnrollmentOwnerError::UnsafeStorage)
        }
    }

    fn ensure_directory_identity(&self, opened: &File) -> Result<(), EnrollmentOwnerError> {
        let opened = opened
            .metadata()
            .map_err(|_| EnrollmentOwnerError::StorageUnavailable)?;
        let current = fs::symlink_metadata(&self.directory)
            .map_err(|_| EnrollmentOwnerError::UnsafeStorage)?;
        if current.file_type().is_dir()
            && current.dev() == opened.dev()
            && current.ino() == opened.ino()
        {
            Ok(())
        } else {
            Err(EnrollmentOwnerError::UnsafeStorage)
        }
    }

    fn open_directory(&self, create: bool) -> Result<File, EnrollmentOwnerError> {
        if create {
            let mut builder = DirBuilder::new();
            builder.mode(DIRECTORY_MODE);
            match builder.create(&self.directory) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(_) => return Err(EnrollmentOwnerError::StorageUnavailable),
            }
        }

        let directory = match OpenOptions::new()
            .read(true)
            .custom_flags(O_DIRECTORY | O_NOFOLLOW)
            .open(&self.directory)
        {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(EnrollmentOwnerError::MissingOwner);
            }
            Err(_) => return Err(EnrollmentOwnerError::UnsafeStorage),
        };
        let metadata = directory
            .metadata()
            .map_err(|_| EnrollmentOwnerError::StorageUnavailable)?;
        if !metadata.file_type().is_dir()
            || metadata.uid() != self.expected_user_id
            || metadata.gid() != self.expected_group_id
            || metadata.mode() & 0o777 != DIRECTORY_MODE
        {
            return Err(EnrollmentOwnerError::UnsafeStorage);
        }
        Ok(directory)
    }

    #[cfg(test)]
    pub(crate) fn for_test(directory: impl Into<PathBuf>, user_id: u32, group_id: u32) -> Self {
        Self {
            directory: directory.into(),
            expected_user_id: user_id,
            expected_group_id: group_id,
        }
    }
}

fn validate_private_file_metadata(
    metadata: &Metadata,
    expected_user_id: u32,
    expected_group_id: u32,
) -> Result<(), EnrollmentOwnerError> {
    if !metadata.file_type().is_file()
        || metadata.uid() != expected_user_id
        || metadata.gid() != expected_group_id
        || metadata.mode() & 0o777 != OWNER_FILE_MODE
    {
        return Err(EnrollmentOwnerError::UnsafeStorage);
    }
    Ok(())
}

fn parse_owner(encoded: &str) -> Result<EnrollmentOwner, EnrollmentOwnerError> {
    let digits = encoded
        .strip_suffix('\n')
        .ok_or(EnrollmentOwnerError::CorruptState)?;
    if digits.is_empty()
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
        || (digits.len() > 1 && digits.starts_with('0'))
    {
        return Err(EnrollmentOwnerError::CorruptState);
    }
    let user_id = digits
        .parse::<u32>()
        .map_err(|_| EnrollmentOwnerError::CorruptState)?;
    EnrollmentOwner::new(user_id).map_err(|_| EnrollmentOwnerError::CorruptState)
}

fn is_pending_name(name: &str) -> bool {
    let Some(sequence) = name.strip_prefix(OWNER_PENDING_PREFIX) else {
        return false;
    };
    !sequence.is_empty()
        && sequence.bytes().all(|byte| byte.is_ascii_digit())
        && (sequence == "0" || !sequence.starts_with('0'))
}

const fn map_policy_error(_: PolicyError) -> EnrollmentOwnerError {
    EnrollmentOwnerError::CorruptState
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_protocol::{
        AUTHENTICATE_REQUEST, BrokerDecision, BrokerState, PeerAddressFamily, PeerMetadata,
        Response,
    };
    use std::os::unix::fs::symlink;
    use std::sync::{Arc, Barrier};
    use std::thread;

    static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "t1bridge-owner-policy-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create isolated test directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(DIRECTORY_MODE))
                .expect("secure test directory");
            Self(path)
        }

        fn store(&self) -> EnrollmentOwnerStore {
            let metadata = fs::metadata(&self.0).expect("test directory metadata");
            EnrollmentOwnerStore::for_test(self.0.join("catacombs"), metadata.uid(), metadata.gid())
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn owner(user_id: u32) -> EnrollmentOwner {
        EnrollmentOwner::new(user_id).expect("synthetic non-root owner")
    }

    fn peer(user_id: u32) -> PeerMetadata {
        PeerMetadata {
            address_family: PeerAddressFamily::Local,
            user_id,
            group_id: user_id.saturating_add(1),
        }
    }

    #[test]
    fn first_claim_is_durable_and_same_owner_is_read_only() {
        let directory = TestDirectory::new();
        let store = directory.store();
        let selected = owner(42_000);

        assert_eq!(store.claim(selected), Ok(OwnerClaim::Recorded));
        assert_eq!(store.load(), Ok(selected));
        let path = store.directory.join(OWNER_FILE);
        let before = fs::metadata(&path).expect("owner state metadata");
        let bytes = fs::read(&path).expect("owner state bytes");

        assert_eq!(store.claim(selected), Ok(OwnerClaim::Existing));
        let after = fs::metadata(path).expect("owner state metadata");
        assert_eq!(bytes, b"42000\n");
        assert_eq!(before.ino(), after.ino());
        assert_eq!(before.len(), after.len());
        assert_eq!(after.nlink(), 1);
    }

    #[test]
    fn second_owner_is_refused_without_storage_mutation() {
        let directory = TestDirectory::new();
        let store = directory.store();
        store.claim(owner(42_000)).expect("record first owner");
        let before = fs::read_dir(&store.directory)
            .expect("list state")
            .map(|entry| {
                let entry = entry.expect("state entry");
                (
                    entry.file_name(),
                    fs::read(entry.path()).expect("state bytes"),
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(
            store.claim(owner(42_001)),
            Err(EnrollmentOwnerError::DifferentOwner)
        );
        let after = fs::read_dir(&store.directory)
            .expect("list state")
            .map(|entry| {
                let entry = entry.expect("state entry");
                (
                    entry.file_name(),
                    fs::read(entry.path()).expect("state bytes"),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(after, before);
    }

    #[test]
    fn stored_owner_is_the_only_non_root_broker_identity() {
        let directory = TestDirectory::new();
        let store = directory.store();
        store.claim(owner(42_000)).expect("record owner");
        let policy = store.access_policy().expect("load access policy");

        for admitted in [0, 42_000] {
            let mut broker = BrokerState::default();
            assert!(matches!(
                broker.handle_packet(peer(admitted), policy, AUTHENTICATE_REQUEST),
                BrokerDecision::Start(_)
            ));
        }
        let mut broker = BrokerState::default();
        assert_eq!(
            broker.handle_packet(peer(42_001), policy, AUTHENTICATE_REQUEST),
            BrokerDecision::Reply(Response::Denied)
        );
    }

    #[test]
    fn missing_corrupt_and_unsafe_state_fail_closed() {
        let directory = TestDirectory::new();
        let store = directory.store();
        assert_eq!(store.load(), Err(EnrollmentOwnerError::MissingOwner));

        fs::create_dir(&store.directory).expect("create state directory");
        fs::set_permissions(&store.directory, fs::Permissions::from_mode(DIRECTORY_MODE))
            .expect("secure state directory");
        let owner_path = store.directory.join(OWNER_FILE);
        for corrupt in [b"0\n".as_slice(), b"042000\n", b"42000", b"not-a-uid\n"] {
            fs::write(&owner_path, corrupt).expect("write corrupt owner");
            fs::set_permissions(&owner_path, fs::Permissions::from_mode(OWNER_FILE_MODE))
                .expect("set owner mode");
            assert_eq!(store.load(), Err(EnrollmentOwnerError::CorruptState));
        }

        fs::set_permissions(&owner_path, fs::Permissions::from_mode(0o644))
            .expect("set unsafe mode");
        assert_eq!(store.load(), Err(EnrollmentOwnerError::UnsafeStorage));
    }

    #[test]
    fn symlink_and_hardlink_owner_state_are_never_accepted() {
        let directory = TestDirectory::new();
        let store = directory.store();
        fs::create_dir(&store.directory).expect("create state directory");
        fs::set_permissions(&store.directory, fs::Permissions::from_mode(DIRECTORY_MODE))
            .expect("secure state directory");
        let unrelated = directory.0.join("unrelated");
        fs::write(&unrelated, b"42000\n").expect("write unrelated file");
        fs::set_permissions(&unrelated, fs::Permissions::from_mode(OWNER_FILE_MODE))
            .expect("secure unrelated file");
        let owner_path = store.directory.join(OWNER_FILE);

        symlink(&unrelated, &owner_path).expect("create owner symlink");
        assert!(matches!(
            store.load(),
            Err(EnrollmentOwnerError::StorageUnavailable | EnrollmentOwnerError::UnsafeStorage)
        ));
        fs::remove_file(&owner_path).expect("remove symlink");
        fs::hard_link(&unrelated, &owner_path).expect("create owner hardlink");
        assert_eq!(store.load(), Err(EnrollmentOwnerError::UnsafeStorage));
        assert_eq!(fs::read(unrelated).expect("unrelated bytes"), b"42000\n");
    }

    #[test]
    fn published_owner_survives_crash_window_without_accepting_other_hardlinks() {
        let directory = TestDirectory::new();
        let store = directory.store();
        fs::create_dir(&store.directory).expect("create state directory");
        fs::set_permissions(&store.directory, fs::Permissions::from_mode(DIRECTORY_MODE))
            .expect("secure state directory");
        let pending_path = store.directory.join(format!("{OWNER_PENDING_PREFIX}0"));
        fs::write(&pending_path, b"42000\n").expect("write synchronized pending state");
        fs::set_permissions(&pending_path, fs::Permissions::from_mode(OWNER_FILE_MODE))
            .expect("secure pending state");
        File::open(&pending_path)
            .expect("open pending state")
            .sync_all()
            .expect("synchronize pending state");
        let owner_path = store.directory.join(OWNER_FILE);
        fs::hard_link(&pending_path, &owner_path).expect("publish owner state");

        assert_eq!(store.load(), Ok(owner(42_000)));

        let unrelated_link = directory.0.join("unrelated-owner-link");
        fs::hard_link(&owner_path, &unrelated_link).expect("create unrelated hardlink");
        assert_eq!(store.load(), Err(EnrollmentOwnerError::UnsafeStorage));
    }

    #[test]
    fn owner_validation_accepts_publisher_removing_its_pending_link() {
        let directory = TestDirectory::new();
        let store = directory.store();
        fs::create_dir(&store.directory).expect("create state directory");
        fs::set_permissions(&store.directory, fs::Permissions::from_mode(DIRECTORY_MODE))
            .expect("secure state directory");
        let pending_path = store.directory.join(format!("{OWNER_PENDING_PREFIX}0"));
        fs::write(&pending_path, b"42000\n").expect("write pending owner");
        fs::set_permissions(&pending_path, fs::Permissions::from_mode(OWNER_FILE_MODE))
            .expect("secure pending owner");
        let owner_path = store.directory.join(OWNER_FILE);
        fs::hard_link(&pending_path, &owner_path).expect("publish owner");
        let owner_file = File::open(&owner_path).expect("open published owner");
        let publishing_metadata = owner_file.metadata().expect("publishing metadata");
        assert_eq!(publishing_metadata.nlink(), 2);

        fs::remove_file(pending_path).expect("finish publication");

        assert_eq!(
            store.validate_owner_file_metadata(&owner_file, &publishing_metadata),
            Ok(())
        );
        assert_eq!(store.load(), Ok(owner(42_000)));
    }

    #[test]
    fn owner_validation_rejects_a_changed_multilink_count() {
        let directory = TestDirectory::new();
        let store = directory.store();
        fs::create_dir(&store.directory).expect("create state directory");
        fs::set_permissions(&store.directory, fs::Permissions::from_mode(DIRECTORY_MODE))
            .expect("secure state directory");
        let first_pending = store.directory.join(format!("{OWNER_PENDING_PREFIX}0"));
        fs::write(&first_pending, b"42000\n").expect("write pending owner");
        fs::set_permissions(&first_pending, fs::Permissions::from_mode(OWNER_FILE_MODE))
            .expect("secure pending owner");
        let owner_path = store.directory.join(OWNER_FILE);
        fs::hard_link(&first_pending, &owner_path).expect("publish owner");
        let second_pending = store.directory.join(format!("{OWNER_PENDING_PREFIX}1"));
        fs::hard_link(&first_pending, &second_pending).expect("link second pending name");
        let owner_file = File::open(&owner_path).expect("open published owner");
        let publishing_metadata = owner_file.metadata().expect("publishing metadata");
        assert_eq!(publishing_metadata.nlink(), 3);

        fs::remove_file(second_pending).expect("remove one pending name");

        assert_eq!(
            store.validate_owner_file_metadata(&owner_file, &publishing_metadata),
            Err(EnrollmentOwnerError::UnsafeStorage)
        );
    }

    #[test]
    fn concurrent_different_claims_publish_exactly_one_complete_owner() {
        let directory = TestDirectory::new();
        let store = Arc::new(directory.store());
        let barrier = Arc::new(Barrier::new(2));
        let claims = [42_000, 42_001].map(|user_id| {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                (user_id, store.claim(owner(user_id)))
            })
        });
        let results = claims.map(|claim| claim.join().expect("claim thread completes"));

        assert_eq!(
            results
                .iter()
                .filter(|(_, result)| *result == Ok(OwnerClaim::Recorded))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|(_, result)| *result == Err(EnrollmentOwnerError::DifferentOwner))
                .count(),
            1
        );
        let recorded = store.load().expect("one complete owner is durable");
        assert!(results.iter().any(|(user_id, result)| {
            *result == Ok(OwnerClaim::Recorded) && recorded == owner(*user_id)
        }));
        let metadata = fs::metadata(store.directory.join(OWNER_FILE)).expect("owner metadata");
        assert_eq!(metadata.nlink(), 1);
    }

    #[test]
    fn directory_replacement_is_detected_before_hardware_can_start() {
        let directory = TestDirectory::new();
        let store = directory.store();
        fs::create_dir(&store.directory).expect("create state directory");
        fs::set_permissions(&store.directory, fs::Permissions::from_mode(DIRECTORY_MODE))
            .expect("secure state directory");
        let opened = store
            .open_directory(false)
            .expect("open original directory");
        let moved = directory.0.join("moved-state");
        fs::rename(&store.directory, &moved).expect("move original directory");
        fs::create_dir(&store.directory).expect("create replacement directory");
        fs::set_permissions(&store.directory, fs::Permissions::from_mode(DIRECTORY_MODE))
            .expect("secure replacement directory");

        assert_eq!(
            store.ensure_directory_identity(&opened),
            Err(EnrollmentOwnerError::UnsafeStorage)
        );
    }

    #[test]
    fn owner_values_and_diagnostics_are_redacted() {
        assert_eq!(
            EnrollmentOwner::new(0),
            Err(EnrollmentOwnerError::InvalidOwner)
        );
        assert!(!format!("{:?}", owner(42_000)).contains("42000"));
        assert!(!format!("{:?}", EnrollmentOwnerStore::new("/private/path")).contains('/'));
        for error in [
            EnrollmentOwnerError::InvalidOwner,
            EnrollmentOwnerError::MissingOwner,
            EnrollmentOwnerError::DifferentOwner,
            EnrollmentOwnerError::UnsafeStorage,
            EnrollmentOwnerError::CorruptState,
            EnrollmentOwnerError::StorageUnavailable,
        ] {
            assert!(!format!("{error:?} {error}").contains("42000"));
        }
    }
}

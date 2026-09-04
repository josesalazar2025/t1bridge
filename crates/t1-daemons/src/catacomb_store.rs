//! Durable, generation-atomic storage for catacombs and identity metadata.
//!
//! One small marker selects both blobs and optional validated metadata from a
//! private generation, so readers cannot combine artifacts across updates.

mod legacy_recovery;

pub use legacy_recovery::{LegacyRecoveryReservation, LegacyRecoveryReservationError};

use std::fmt;
use std::fs::{self, DirBuilder, File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use t1_bridge::catacomb::MAX_SECURE_CATACOMB_SIZE;
use t1_platform::secret;

use crate::identity_metadata::{MAX_MANIFEST_SIZE, decode as decode_identity_metadata};

const ACTIVE_MARKER: &str = "active";
const MASTER_FILE: &str = "master.raw";
const USER_FILE: &str = "user.raw";
const IDENTITY_METADATA_FILE: &str = "identities.meta";
const MAX_MARKER_SIZE: u64 = 128;

// Linux UAPI values used through the safe standard-library open interface.
const O_DIRECTORY: i32 = 0o2_00000;
const O_NOFOLLOW: i32 = 0o4_00000;

static ARTIFACT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A storage failure that never contains catacomb bytes or identifiers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatacombStoreError {
    MissingPair,
    IncompletePair,
    InvalidBlob,
    InvalidMetadata,
    StorageUnavailable,
    UnsafeStorage,
    PendingExport,
    InvalidTransactionState,
    PromotionDurabilityUnknown,
}

impl fmt::Display for CatacombStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingPair => "no active catacomb pair exists",
            Self::IncompletePair => "the active catacomb pair is incomplete",
            Self::InvalidBlob => "a catacomb blob has an invalid size",
            Self::InvalidMetadata => "catacomb identity metadata is invalid",
            Self::StorageUnavailable => "catacomb storage is unavailable",
            Self::UnsafeStorage => "catacomb storage has unsafe metadata",
            Self::PendingExport => "a catacomb export is pending recovery",
            Self::InvalidTransactionState => "catacomb transaction order is invalid",
            Self::PromotionDurabilityUnknown => {
                "catacomb pair was promoted but its durability is unknown"
            }
        })
    }
}

impl std::error::Error for CatacombStoreError {}

/// One inseparable generation. Contents are always redacted.
#[derive(Clone, Eq, PartialEq)]
pub struct CatacombPair {
    master: Vec<u8>,
    user: Vec<u8>,
    metadata: Option<Vec<u8>>,
}

impl CatacombPair {
    /// Returns the master blob, which must be restored before the user blob.
    #[must_use]
    pub fn master(&self) -> &[u8] {
        &self.master
    }

    /// Returns the user blob, which must be restored after the master blob.
    #[must_use]
    pub fn user(&self) -> &[u8] {
        &self.user
    }

    /// Returns validated opaque metadata, or `None` for a legacy generation.
    #[must_use]
    pub fn metadata(&self) -> Option<&[u8]> {
        self.metadata.as_deref()
    }
}

impl fmt::Debug for CatacombPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CatacombPair")
            .field("master_len", &self.master.len())
            .field("master", &"[redacted]")
            .field("user_len", &self.user.len())
            .field("user", &"[redacted]")
            .field("metadata", &"[redacted]")
            .finish()
    }
}

impl Drop for CatacombPair {
    fn drop(&mut self) {
        secret::wipe(&mut self.master);
        secret::wipe(&mut self.user);
        if let Some(metadata) = &mut self.metadata {
            secret::wipe(metadata);
        }
    }
}

/// Stores opaque pairs below a caller-selected private directory.
pub struct CatacombPairStore {
    directory: PathBuf,
}

/// Result of inspecting reserved, ambiguous export state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatacombRecoveryOutcome {
    /// No reserved export needs a device decision.
    Clean,
    /// The live device accepted and the store promoted one complete candidate.
    Promoted,
    /// State was incomplete, conflicting, unsafe, or rejected by the device.
    Quarantined,
}

/// Recovery failure with validator diagnostics kept opaque.
pub enum CatacombRecoveryError<E> {
    Store(CatacombStoreError),
    Validator(E),
}

impl<E> fmt::Debug for CatacombRecoveryError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => formatter.debug_tuple("Store").field(error).finish(),
            Self::Validator(_) => formatter.write_str("Validator([redacted])"),
        }
    }
}

impl<E> fmt::Display for CatacombRecoveryError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Store(error) => error.fmt(formatter),
            Self::Validator(_) => formatter.write_str("live catacomb validation failed"),
        }
    }
}

impl<E> std::error::Error for CatacombRecoveryError<E> {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransactionState {
    Empty,
    MetadataDurable,
    UserDurable,
    PairDurable,
}

/// One staged generation with explicit native-export boundaries.
///
/// The concrete user's blob becomes durable first. The caller may then finish
/// that native export before writing the master blob. Promotion remains
/// impossible until both members are durable.
pub struct CatacombPairTransaction<'a> {
    store: &'a CatacombPairStore,
    directory: File,
    stage: PathBuf,
    generation: PathBuf,
    generation_name: String,
    marker_temporary: PathBuf,
    recovery_marker: PathBuf,
    state: TransactionState,
    generation_renamed: bool,
    marker_replaced: bool,
    recovery_reserved: bool,
}

impl CatacombPairStore {
    #[must_use]
    pub fn new(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
        }
    }

    /// Loads exactly the generation named by the active marker.
    ///
    /// The returned field order is master then user to make the required SEP
    /// restore order explicit. A partial, unsafe, or invalid pair is never
    /// returned.
    ///
    /// # Errors
    ///
    /// Returns an error when there is no promoted pair, either member is
    /// missing or invalid, or any storage object is unsafe.
    pub fn load(&self) -> Result<CatacombPair, CatacombStoreError> {
        let directory = self.open_existing_directory()?;
        let generation = self.read_active_generation()?;
        let generation_directory = self.directory.join(generation);
        let pair = read_pair(&generation_directory)?;
        drop(directory);
        Ok(pair)
    }

    /// Reports whether first-owner enrollment can safely claim an empty store.
    ///
    /// An absent directory is empty. Any active, staged, pending, or inactive
    /// catacomb namespace entry counts as biometric state, including malformed
    /// lookalikes, because missing owner metadata must never transfer existing
    /// fingerprints to a new Linux user. Other state kept beside catacombs is
    /// ignored.
    ///
    /// # Errors
    ///
    /// Returns an error when the store cannot be safely inspected. Callers
    /// must treat an error as not empty.
    pub fn is_empty_for_first_owner(&self) -> Result<bool, CatacombStoreError> {
        let _directory = match self.open_existing_directory() {
            Ok(directory) => directory,
            Err(CatacombStoreError::MissingPair) => return Ok(true),
            Err(error) => return Err(error),
        };
        let entries =
            fs::read_dir(&self.directory).map_err(|_| CatacombStoreError::StorageUnavailable)?;
        for entry in entries {
            let name = entry
                .map_err(|_| CatacombStoreError::StorageUnavailable)?
                .file_name()
                .into_string()
                .map_err(|_| CatacombStoreError::UnsafeStorage)?;
            if name == ACTIVE_MARKER
                || name.starts_with("pair-")
                || name.starts_with(".stage-")
                || name.starts_with(".recovery-")
                || name.starts_with(".active-")
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Durably promotes a complete new pair while preserving the old active
    /// generation until the final marker replacement.
    ///
    /// The arguments follow native export order: concrete user first, master
    /// last. Both are validated before filesystem state changes.
    ///
    /// # Errors
    ///
    /// Returns an error if either blob is invalid or the private, durable
    /// transaction cannot be completed. A failure before marker replacement
    /// leaves any prior pair selected. A directory-sync failure after atomic
    /// replacement is reported as [`CatacombStoreError::PromotionDurabilityUnknown`];
    /// callers must load and validate the selected pair rather than retrying
    /// blindly.
    pub fn commit(&self, user: &[u8], master: &[u8]) -> Result<(), CatacombStoreError> {
        self.commit_inner(user, master, || Ok(()))
    }

    /// Starts a private generation without changing the active marker.
    ///
    /// # Errors
    ///
    /// Returns an error when the store directory is unavailable or unsafe, or
    /// a private staging directory cannot be created.
    pub fn begin_transaction(&self) -> Result<CatacombPairTransaction<'_>, CatacombStoreError> {
        let directory = self.prepare_directory()?;
        self.reject_recovery_state()?;
        let token = artifact_token();
        let stage = self.directory.join(format!(".stage-{token}"));
        create_private_directory(&stage)?;
        Ok(CatacombPairTransaction {
            store: self,
            directory,
            stage,
            generation: self.directory.join(format!("pair-{token}")),
            generation_name: format!("pair-{token}"),
            marker_temporary: self.directory.join(format!(".active-{token}.tmp")),
            recovery_marker: self.directory.join(format!(".recovery-{token}")),
            state: TransactionState::Empty,
            generation_renamed: false,
            marker_replaced: false,
            recovery_reserved: false,
        })
    }

    /// Removes only abandoned, pre-export staging artifacts.
    ///
    /// The active generation and every exactly reserved recovery generation
    /// are retained. Unreserved stages and inactive generations are known not
    /// to be the only potentially current SEP pair and are removed.
    ///
    /// # Errors
    ///
    /// Returns an error rather than removing an artifact with unexpected
    /// type, ownership, permissions, link count, or contents.
    pub fn recover(&self) -> Result<(), CatacombStoreError> {
        let directory = self.open_existing_directory()?;
        directory
            .sync_all()
            .map_err(|_| CatacombStoreError::StorageUnavailable)?;
        let active = match self.read_active_generation() {
            Ok(generation) => Some(generation),
            Err(CatacombStoreError::MissingPair) => None,
            Err(error) => return Err(error),
        };
        if active.is_some() {
            // Never discard an older complete generation on the authority of
            // a marker whose selected pair is partial or unsafe.
            self.load()?;
        }

        let mut entries = fs::read_dir(&self.directory)
            .map_err(|_| CatacombStoreError::StorageUnavailable)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| CatacombStoreError::StorageUnavailable)?;
        entries.sort_by_key(fs::DirEntry::file_name);

        let recovery_tokens = self.recovery_tokens()?;
        for entry in entries {
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| CatacombStoreError::UnsafeStorage)?;
            if name == ACTIVE_MARKER || active.as_deref() == Some(name.as_str()) {
                continue;
            }
            if let Some(token) = name
                .strip_prefix(".stage-")
                .filter(|_| is_stage_name(&name))
            {
                if !recovery_tokens.iter().any(|reserved| reserved == token) {
                    remove_private_generation(&entry.path())?;
                }
            } else if let Some(token) = name
                .strip_prefix("pair-")
                .filter(|_| is_generation_name(&name))
            {
                if !recovery_tokens.iter().any(|reserved| reserved == token) {
                    remove_private_generation(&entry.path())?;
                }
            } else if is_marker_temporary_name(&name) {
                remove_private_file(&entry.path())?;
            }
        }
        directory
            .sync_all()
            .map_err(|_| CatacombStoreError::StorageUnavailable)
    }

    /// Resolves at most one complete ambiguous generation through a live T1.
    ///
    /// The validator must compare the candidate with the currently attached
    /// physical T1. It is never called for incomplete, conflicting, or unsafe
    /// state. Rejection leaves every object untouched and keeps new export
    /// transactions blocked.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe storage failure or the caller's opaque live
    /// validator failure. Every error retains the recovery reservation.
    pub fn recover_with_validator<V, E>(
        &self,
        mut validator: V,
    ) -> Result<CatacombRecoveryOutcome, CatacombRecoveryError<E>>
    where
        V: FnMut(&CatacombPair) -> Result<bool, E>,
    {
        let directory = match self.open_existing_directory() {
            Ok(directory) => directory,
            Err(CatacombStoreError::MissingPair) => {
                return Ok(CatacombRecoveryOutcome::Clean);
            }
            Err(error) => return Err(CatacombRecoveryError::Store(error)),
        };
        directory
            .sync_all()
            .map_err(|_| CatacombRecoveryError::Store(CatacombStoreError::StorageUnavailable))?;

        let tokens = match self.recovery_tokens() {
            Ok(tokens) => tokens,
            Err(CatacombStoreError::UnsafeStorage | CatacombStoreError::IncompletePair) => {
                return Ok(CatacombRecoveryOutcome::Quarantined);
            }
            Err(error) => return Err(CatacombRecoveryError::Store(error)),
        };
        if tokens.is_empty() {
            return Ok(CatacombRecoveryOutcome::Clean);
        }
        if tokens.len() != 1 {
            return Ok(CatacombRecoveryOutcome::Quarantined);
        }

        let token = &tokens[0];
        let stage = self.directory.join(format!(".stage-{token}"));
        let generation_name = format!("pair-{token}");
        let generation = self.directory.join(&generation_name);
        let stage_exists = fs::symlink_metadata(&stage).is_ok();
        let generation_exists = fs::symlink_metadata(&generation).is_ok();
        if stage_exists || !generation_exists {
            return Ok(CatacombRecoveryOutcome::Quarantined);
        }

        let pair = match read_pair(&generation) {
            Ok(pair) => pair,
            Err(
                CatacombStoreError::IncompletePair
                | CatacombStoreError::InvalidBlob
                | CatacombStoreError::InvalidMetadata
                | CatacombStoreError::UnsafeStorage,
            ) => return Ok(CatacombRecoveryOutcome::Quarantined),
            Err(error) => return Err(CatacombRecoveryError::Store(error)),
        };
        if !validator(&pair).map_err(CatacombRecoveryError::Validator)? {
            return Ok(CatacombRecoveryOutcome::Quarantined);
        }

        let active = match self.read_active_generation() {
            Ok(active) => Some(active),
            Err(CatacombStoreError::MissingPair) => None,
            Err(error) => return Err(CatacombRecoveryError::Store(error)),
        };
        if active.as_deref() != Some(generation_name.as_str()) {
            let temporary = self.directory.join(format!(".active-{token}.tmp"));
            remove_private_file(&temporary).map_err(CatacombRecoveryError::Store)?;
            write_marker(&temporary, &generation_name).map_err(CatacombRecoveryError::Store)?;
            if fs::rename(&temporary, self.directory.join(ACTIVE_MARKER)).is_err() {
                let _ = remove_private_file(&temporary);
                return Err(CatacombRecoveryError::Store(
                    CatacombStoreError::StorageUnavailable,
                ));
            }
            directory.sync_all().map_err(|_| {
                CatacombRecoveryError::Store(CatacombStoreError::PromotionDurabilityUnknown)
            })?;
        }

        let recovery_marker = self.directory.join(format!(".recovery-{token}"));
        remove_private_file(&recovery_marker).map_err(CatacombRecoveryError::Store)?;
        directory
            .sync_all()
            .map_err(|_| CatacombRecoveryError::Store(CatacombStoreError::StorageUnavailable))?;
        Ok(CatacombRecoveryOutcome::Promoted)
    }

    fn commit_inner<F>(
        &self,
        user: &[u8],
        master: &[u8],
        before_promotion: F,
    ) -> Result<(), CatacombStoreError>
    where
        F: FnOnce() -> Result<(), CatacombStoreError>,
    {
        validate_blob(user)?;
        validate_blob(master)?;
        let mut transaction = self.begin_transaction()?;
        transaction.write_user(user)?;
        transaction.write_master(master)?;
        transaction.promote_inner(before_promotion, false)
    }

    fn open_existing_directory(&self) -> Result<File, CatacombStoreError> {
        match OpenOptions::new()
            .read(true)
            .custom_flags(O_DIRECTORY | O_NOFOLLOW)
            .open(&self.directory)
        {
            Ok(directory) => {
                validate_directory_metadata(
                    &directory
                        .metadata()
                        .map_err(|_| CatacombStoreError::StorageUnavailable)?,
                )?;
                Ok(directory)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                Err(CatacombStoreError::MissingPair)
            }
            Err(_) => Err(CatacombStoreError::UnsafeStorage),
        }
    }

    fn prepare_directory(&self) -> Result<File, CatacombStoreError> {
        if !self.directory.exists() {
            let mut builder = DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder
                .create(&self.directory)
                .map_err(|_| CatacombStoreError::StorageUnavailable)?;
            fs::set_permissions(&self.directory, fs::Permissions::from_mode(0o700))
                .map_err(|_| CatacombStoreError::StorageUnavailable)?;
        }
        self.open_existing_directory()
    }

    fn read_active_generation(&self) -> Result<String, CatacombStoreError> {
        let marker_path = self.directory.join(ACTIVE_MARKER);
        let mut marker = match OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW)
            .open(marker_path)
        {
            Ok(marker) => marker,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(CatacombStoreError::MissingPair);
            }
            Err(_) => return Err(CatacombStoreError::UnsafeStorage),
        };
        let metadata = marker
            .metadata()
            .map_err(|_| CatacombStoreError::StorageUnavailable)?;
        validate_private_file_metadata(&metadata)?;
        if metadata.len() == 0 || metadata.len() > MAX_MARKER_SIZE {
            return Err(CatacombStoreError::UnsafeStorage);
        }
        let size =
            usize::try_from(metadata.len()).map_err(|_| CatacombStoreError::UnsafeStorage)?;
        let mut bytes = vec![0; size];
        marker
            .read_exact(&mut bytes)
            .map_err(|_| CatacombStoreError::StorageUnavailable)?;
        let mut trailing = [0_u8; 1];
        if marker
            .read(&mut trailing)
            .map_err(|_| CatacombStoreError::StorageUnavailable)?
            != 0
        {
            return Err(CatacombStoreError::UnsafeStorage);
        }
        let text = std::str::from_utf8(&bytes).map_err(|_| CatacombStoreError::UnsafeStorage)?;
        let generation = text
            .strip_suffix('\n')
            .ok_or(CatacombStoreError::UnsafeStorage)?;
        if !is_generation_name(generation) {
            return Err(CatacombStoreError::UnsafeStorage);
        }
        Ok(generation.to_owned())
    }

    fn reject_recovery_state(&self) -> Result<(), CatacombStoreError> {
        let entries =
            fs::read_dir(&self.directory).map_err(|_| CatacombStoreError::StorageUnavailable)?;
        for entry in entries {
            let entry = entry.map_err(|_| CatacombStoreError::StorageUnavailable)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| CatacombStoreError::UnsafeStorage)?;
            if name.starts_with(".recovery-") {
                return Err(CatacombStoreError::PendingExport);
            }
        }
        Ok(())
    }

    fn recovery_tokens(&self) -> Result<Vec<String>, CatacombStoreError> {
        let entries =
            fs::read_dir(&self.directory).map_err(|_| CatacombStoreError::StorageUnavailable)?;
        let mut tokens = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|_| CatacombStoreError::StorageUnavailable)?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| CatacombStoreError::UnsafeStorage)?;
            let Some(token) = name.strip_prefix(".recovery-") else {
                continue;
            };
            if !is_token(token) {
                return Err(CatacombStoreError::UnsafeStorage);
            }
            let metadata = fs::symlink_metadata(entry.path())
                .map_err(|_| CatacombStoreError::StorageUnavailable)?;
            validate_private_file_metadata(&metadata)?;
            if metadata.len() != 0 {
                return Err(CatacombStoreError::UnsafeStorage);
            }
            tokens.push(token.to_owned());
        }
        tokens.sort();
        Ok(tokens)
    }
}

impl CatacombPairTransaction<'_> {
    /// Durably reserves the final private generation before SEP can advance.
    ///
    /// The caller must invoke this after a read-only size query and before the
    /// first native save command. Once it succeeds, every drop or promotion
    /// failure retains the generation and reservation for live-device recovery.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid transaction order or when the private
    /// generation and durable reservation cannot be created.
    pub fn reserve_recovery(&mut self) -> Result<(), CatacombStoreError> {
        if self.state != TransactionState::Empty || self.recovery_reserved {
            return Err(CatacombStoreError::InvalidTransactionState);
        }
        fs::rename(&self.stage, &self.generation)
            .map_err(|_| CatacombStoreError::StorageUnavailable)?;
        self.generation_renamed = true;
        self.directory
            .sync_all()
            .map_err(|_| CatacombStoreError::StorageUnavailable)?;

        let marker = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(O_NOFOLLOW)
            .open(&self.recovery_marker)
            .map_err(|_| CatacombStoreError::StorageUnavailable)?;
        self.recovery_reserved = true;
        marker
            .set_permissions(fs::Permissions::from_mode(0o600))
            .and_then(|()| marker.sync_all())
            .map_err(|_| CatacombStoreError::StorageUnavailable)?;
        self.directory
            .sync_all()
            .map_err(|_| CatacombStoreError::StorageUnavailable)
    }

    /// Writes and synchronizes validated identity metadata before native save.
    ///
    /// This is valid only for a durably reserved, otherwise-empty generation.
    /// Metadata-free callers retain the legacy transaction path.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed metadata, invalid ordering, unsafe
    /// storage, or an I/O failure.
    pub fn write_metadata(&mut self, metadata: &[u8]) -> Result<(), CatacombStoreError> {
        if self.state != TransactionState::Empty || !self.recovery_reserved {
            return Err(CatacombStoreError::InvalidTransactionState);
        }
        validate_metadata(metadata)?;
        let directory = self.write_directory();
        write_new_blob(&directory.join(IDENTITY_METADATA_FILE), metadata)?;
        sync_directory(directory)?;
        self.state = TransactionState::MetadataDurable;
        Ok(())
    }

    /// Writes and synchronizes the concrete user's opaque export.
    ///
    /// A successful return is the boundary after which the caller may issue
    /// Mesa's finish-save command for the user.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid data, unsafe storage, I/O failure, or a
    /// repeated/out-of-order call.
    pub fn write_user(&mut self, user: &[u8]) -> Result<(), CatacombStoreError> {
        if !matches!(
            self.state,
            TransactionState::Empty | TransactionState::MetadataDurable
        ) {
            return Err(CatacombStoreError::InvalidTransactionState);
        }
        validate_blob(user)?;
        let directory = self.write_directory();
        write_new_blob(&directory.join(USER_FILE), user)?;
        sync_directory(directory)?;
        self.state = TransactionState::UserDurable;
        Ok(())
    }

    /// Writes and synchronizes the master export after the user export.
    ///
    /// A successful return is the boundary after which the caller may issue
    /// Mesa's finish-save command for the master.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid data, unsafe storage, I/O failure, or an
    /// out-of-order call.
    pub fn write_master(&mut self, master: &[u8]) -> Result<(), CatacombStoreError> {
        if self.state != TransactionState::UserDurable {
            return Err(CatacombStoreError::InvalidTransactionState);
        }
        validate_blob(master)?;
        let directory = self.write_directory();
        write_new_blob(&directory.join(MASTER_FILE), master)?;
        sync_directory(directory)?;
        self.state = TransactionState::PairDurable;
        Ok(())
    }

    /// Atomically selects the complete durable pair.
    ///
    /// # Errors
    ///
    /// Returns an error when both members are not durable or promotion cannot
    /// complete. If marker replacement succeeds but its directory sync fails,
    /// the result is [`CatacombStoreError::PromotionDurabilityUnknown`].
    pub fn promote(self) -> Result<(), CatacombStoreError> {
        self.promote_inner(|| Ok(()), false)
    }

    /// Promotes after both native finish commands have succeeded.
    ///
    /// A pre-marker promotion failure retains the complete generation as a
    /// pending recovery artifact, because SEP may already depend on it.
    ///
    /// # Errors
    ///
    /// Returns the promotion failure, or a storage failure if the durable pair
    /// could not be retained for recovery.
    pub fn promote_after_native_finish(self) -> Result<(), CatacombStoreError> {
        self.promote_inner(|| Ok(()), true)
    }

    fn write_directory(&self) -> &Path {
        if self.generation_renamed {
            &self.generation
        } else {
            &self.stage
        }
    }

    fn promote_inner<F>(
        mut self,
        before_marker: F,
        preserve_on_failure: bool,
    ) -> Result<(), CatacombStoreError>
    where
        F: FnOnce() -> Result<(), CatacombStoreError>,
    {
        if self.state != TransactionState::PairDurable
            || (preserve_on_failure && !self.recovery_reserved)
        {
            return Err(CatacombStoreError::InvalidTransactionState);
        }
        (|| {
            if !self.generation_renamed {
                fs::rename(&self.stage, &self.generation)
                    .map_err(|_| CatacombStoreError::StorageUnavailable)?;
                self.generation_renamed = true;
                self.directory
                    .sync_all()
                    .map_err(|_| CatacombStoreError::StorageUnavailable)?;
            }
            before_marker()?;

            write_marker(&self.marker_temporary, &self.generation_name)?;
            fs::rename(
                &self.marker_temporary,
                self.store.directory.join(ACTIVE_MARKER),
            )
            .map_err(|_| CatacombStoreError::StorageUnavailable)?;
            self.marker_replaced = true;
            self.directory
                .sync_all()
                .map_err(|_| CatacombStoreError::PromotionDurabilityUnknown)?;
            if self.recovery_reserved {
                remove_private_file(&self.recovery_marker)?;
                self.directory
                    .sync_all()
                    .map_err(|_| CatacombStoreError::StorageUnavailable)?;
                self.recovery_reserved = false;
            }
            Ok(())
        })()
    }
}

impl fmt::Debug for CatacombPairTransaction<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CatacombPairTransaction")
            .field("state", &self.state)
            .field("paths", &"[redacted]")
            .finish()
    }
}

impl Drop for CatacombPairTransaction<'_> {
    fn drop(&mut self) {
        let _ = remove_private_file(&self.marker_temporary);
        if !self.recovery_reserved {
            let _ = remove_private_generation(&self.stage);
            if !self.marker_replaced {
                let _ = remove_private_generation(&self.generation);
            }
        }
    }
}

impl fmt::Debug for CatacombPairStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CatacombPairStore")
            .field("directory", &"[redacted]")
            .finish()
    }
}

fn validate_blob(blob: &[u8]) -> Result<(), CatacombStoreError> {
    if blob.is_empty() || blob.len() > MAX_SECURE_CATACOMB_SIZE {
        return Err(CatacombStoreError::InvalidBlob);
    }
    Ok(())
}

fn validate_metadata(metadata: &[u8]) -> Result<(), CatacombStoreError> {
    if metadata.len() > MAX_MANIFEST_SIZE || decode_identity_metadata(metadata).is_err() {
        return Err(CatacombStoreError::InvalidMetadata);
    }
    Ok(())
}

fn read_pair(generation_directory: &Path) -> Result<CatacombPair, CatacombStoreError> {
    let _generation_handle = open_checked_directory(generation_directory)?;
    // Master-first reads mirror the hardware restore contract.
    let mut master = read_blob(&generation_directory.join(MASTER_FILE))?;
    let user = match read_blob(&generation_directory.join(USER_FILE)) {
        Ok(user) => user,
        Err(error) => {
            secret::wipe(&mut master);
            return Err(error);
        }
    };
    let metadata = match read_metadata(&generation_directory.join(IDENTITY_METADATA_FILE)) {
        Ok(metadata) => metadata,
        Err(error) => {
            secret::wipe(&mut master);
            let mut user = user;
            secret::wipe(&mut user);
            return Err(error);
        }
    };
    Ok(CatacombPair {
        master,
        user,
        metadata,
    })
}

fn read_metadata(path: &Path) -> Result<Option<Vec<u8>>, CatacombStoreError> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(CatacombStoreError::UnsafeStorage),
    };
    let file_metadata = file
        .metadata()
        .map_err(|_| CatacombStoreError::StorageUnavailable)?;
    validate_private_file_metadata(&file_metadata)?;
    let size =
        usize::try_from(file_metadata.len()).map_err(|_| CatacombStoreError::InvalidMetadata)?;
    if size > MAX_MANIFEST_SIZE {
        return Err(CatacombStoreError::InvalidMetadata);
    }
    let mut metadata = vec![0; size];
    if file.read_exact(&mut metadata).is_err() {
        secret::wipe(&mut metadata);
        return Err(CatacombStoreError::StorageUnavailable);
    }
    let mut trailing = [0_u8; 1];
    if file
        .read(&mut trailing)
        .map_err(|_| CatacombStoreError::StorageUnavailable)?
        != 0
        || validate_metadata(&metadata).is_err()
    {
        secret::wipe(&mut metadata);
        return Err(CatacombStoreError::InvalidMetadata);
    }
    Ok(Some(metadata))
}

fn read_blob(path: &Path) -> Result<Vec<u8>, CatacombStoreError> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(CatacombStoreError::IncompletePair);
        }
        Err(_) => return Err(CatacombStoreError::UnsafeStorage),
    };
    let metadata = file
        .metadata()
        .map_err(|_| CatacombStoreError::StorageUnavailable)?;
    validate_private_file_metadata(&metadata)?;
    let size = usize::try_from(metadata.len()).map_err(|_| CatacombStoreError::InvalidBlob)?;
    if size == 0 || size > MAX_SECURE_CATACOMB_SIZE {
        return Err(CatacombStoreError::InvalidBlob);
    }
    let mut blob = vec![0; size];
    if file.read_exact(&mut blob).is_err() {
        secret::wipe(&mut blob);
        return Err(CatacombStoreError::StorageUnavailable);
    }
    let mut trailing = [0_u8; 1];
    match file.read(&mut trailing) {
        Ok(0) => Ok(blob),
        Ok(_) => {
            secret::wipe(&mut blob);
            Err(CatacombStoreError::InvalidBlob)
        }
        Err(_) => {
            secret::wipe(&mut blob);
            Err(CatacombStoreError::StorageUnavailable)
        }
    }
}

fn write_new_blob(path: &Path, blob: &[u8]) -> Result<(), CatacombStoreError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|_| CatacombStoreError::StorageUnavailable)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| CatacombStoreError::StorageUnavailable)?;
    file.write_all(blob)
        .map_err(|_| CatacombStoreError::StorageUnavailable)?;
    file.sync_all()
        .map_err(|_| CatacombStoreError::StorageUnavailable)
}

fn write_marker(path: &Path, generation: &str) -> Result<(), CatacombStoreError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|_| CatacombStoreError::StorageUnavailable)?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| CatacombStoreError::StorageUnavailable)?;
    file.write_all(generation.as_bytes())
        .and_then(|()| file.write_all(b"\n"))
        .map_err(|_| CatacombStoreError::StorageUnavailable)?;
    file.sync_all()
        .map_err(|_| CatacombStoreError::StorageUnavailable)
}

fn create_private_directory(path: &Path) -> Result<(), CatacombStoreError> {
    let mut builder = DirBuilder::new();
    builder.mode(0o700);
    builder
        .create(path)
        .map_err(|_| CatacombStoreError::StorageUnavailable)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|_| CatacombStoreError::StorageUnavailable)
}

fn open_checked_directory(path: &Path) -> Result<File, CatacombStoreError> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECTORY | O_NOFOLLOW)
        .open(path)
        .map_err(|_| CatacombStoreError::UnsafeStorage)?;
    validate_directory_metadata(
        &directory
            .metadata()
            .map_err(|_| CatacombStoreError::StorageUnavailable)?,
    )?;
    Ok(directory)
}

fn sync_directory(path: &Path) -> Result<(), CatacombStoreError> {
    open_checked_directory(path)?
        .sync_all()
        .map_err(|_| CatacombStoreError::StorageUnavailable)
}

fn validate_private_file_metadata(metadata: &Metadata) -> Result<(), CatacombStoreError> {
    validate_file_identity(
        metadata.file_type().is_file(),
        metadata.mode(),
        metadata.uid(),
        metadata.nlink(),
        effective_uid()?,
    )
}

fn validate_file_identity(
    is_file: bool,
    mode: u32,
    owner: u32,
    link_count: u64,
    expected_owner: u32,
) -> Result<(), CatacombStoreError> {
    if !is_file || mode & 0o777 != 0o600 || owner != expected_owner || link_count != 1 {
        return Err(CatacombStoreError::UnsafeStorage);
    }
    Ok(())
}

fn validate_directory_metadata(metadata: &Metadata) -> Result<(), CatacombStoreError> {
    if !metadata.file_type().is_dir()
        || metadata.mode() & 0o777 != 0o700
        || metadata.uid() != effective_uid()?
    {
        return Err(CatacombStoreError::UnsafeStorage);
    }
    Ok(())
}

fn effective_uid() -> Result<u32, CatacombStoreError> {
    let status = fs::read_to_string("/proc/self/status")
        .map_err(|_| CatacombStoreError::StorageUnavailable)?;
    let uid_line = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .ok_or(CatacombStoreError::StorageUnavailable)?;
    uid_line
        .split_ascii_whitespace()
        .nth(1)
        .ok_or(CatacombStoreError::StorageUnavailable)?
        .parse()
        .map_err(|_| CatacombStoreError::StorageUnavailable)
}

fn artifact_token() -> String {
    let sequence = ARTIFACT_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    format!("{:x}-{nanos:x}-{sequence:x}", std::process::id())
}

fn is_generation_name(name: &str) -> bool {
    name.strip_prefix("pair-").is_some_and(is_token)
}

fn is_stage_name(name: &str) -> bool {
    name.strip_prefix(".stage-").is_some_and(is_token)
}

fn is_marker_temporary_name(name: &str) -> bool {
    name.strip_prefix(".active-")
        .and_then(|rest| rest.strip_suffix(".tmp"))
        .is_some_and(is_token)
}

fn is_token(token: &str) -> bool {
    let mut fields = token.split('-');
    let valid = fields
        .by_ref()
        .take(3)
        .all(|field| !field.is_empty() && field.bytes().all(|byte| byte.is_ascii_hexdigit()));
    valid && fields.next().is_none() && token.bytes().filter(|byte| *byte == b'-').count() == 2
}

fn remove_private_file(path: &Path) -> Result<(), CatacombStoreError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(CatacombStoreError::StorageUnavailable),
    };
    validate_private_file_metadata(&metadata)?;
    fs::remove_file(path).map_err(|_| CatacombStoreError::StorageUnavailable)
}

fn remove_private_generation(path: &Path) -> Result<(), CatacombStoreError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(CatacombStoreError::StorageUnavailable),
    };
    validate_directory_metadata(&metadata)?;
    let entries = fs::read_dir(path)
        .map_err(|_| CatacombStoreError::StorageUnavailable)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CatacombStoreError::StorageUnavailable)?;
    for entry in entries {
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| CatacombStoreError::UnsafeStorage)?;
        if !matches!(
            name.as_str(),
            MASTER_FILE | USER_FILE | IDENTITY_METADATA_FILE
        ) {
            return Err(CatacombStoreError::UnsafeStorage);
        }
        remove_private_file(&entry.path())?;
    }
    fs::remove_dir(path).map_err(|_| CatacombStoreError::StorageUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "t1bridge-catacomb-store-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create isolated test parent");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure isolated test parent");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn store(test_directory: &TestDirectory) -> CatacombPairStore {
        CatacombPairStore::new(test_directory.0.join("store"))
    }

    fn generation_path(store: &CatacombPairStore) -> PathBuf {
        let name = store
            .read_active_generation()
            .expect("read synthetic active generation");
        store.directory.join(name)
    }

    fn identity_metadata(value: u8) -> Vec<u8> {
        use crate::identity_metadata::{IdentityMetadata, IdentityMetadataEntry, encode};
        use crate::standard_fingerprint_protocol::{IdentityId, Username};

        encode(
            &IdentityMetadata::new(
                Username::new("synthetic-owner").unwrap(),
                vec![IdentityMetadataEntry {
                    id: IdentityId::new([value; 16]).unwrap(),
                    finger: None,
                }],
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn complete_pair_round_trips_in_restore_order() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        let user = b"synthetic user catacomb";
        let master = b"synthetic master catacomb";

        store.commit(user, master).expect("commit synthetic pair");
        let pair = store.load().expect("load synthetic pair");

        assert_eq!(pair.master(), master);
        assert_eq!(pair.user(), user);
        assert_eq!(pair.metadata(), None);
        let generation = generation_path(&store);
        assert_eq!(fs::metadata(&generation).unwrap().mode() & 0o777, 0o700);
        assert_eq!(
            fs::metadata(store.directory.join(ACTIVE_MARKER))
                .unwrap()
                .mode()
                & 0o777,
            0o600
        );
        for name in [MASTER_FILE, USER_FILE] {
            let metadata = fs::metadata(generation.join(name)).unwrap();
            assert_eq!(metadata.mode() & 0o777, 0o600);
            assert_eq!(metadata.nlink(), 1);
            assert_eq!(metadata.uid(), effective_uid().unwrap());
        }
    }

    #[test]
    fn staged_transaction_exposes_only_durable_native_finish_boundaries() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        let mut transaction = store.begin_transaction().unwrap();

        assert_eq!(transaction.state, TransactionState::Empty);
        assert_eq!(store.load(), Err(CatacombStoreError::MissingPair));
        transaction.write_user(b"synthetic user").unwrap();
        assert_eq!(transaction.state, TransactionState::UserDurable);
        assert!(transaction.stage.join(USER_FILE).is_file());
        assert!(!transaction.stage.join(MASTER_FILE).exists());
        assert_eq!(store.load(), Err(CatacombStoreError::MissingPair));

        transaction.write_master(b"synthetic master").unwrap();
        assert_eq!(transaction.state, TransactionState::PairDurable);
        assert!(transaction.stage.join(MASTER_FILE).is_file());
        transaction.promote().unwrap();

        let pair = store.load().unwrap();
        assert_eq!(pair.user(), b"synthetic user");
        assert_eq!(pair.master(), b"synthetic master");
    }

    #[test]
    fn staged_transaction_rejects_out_of_order_or_repeated_members() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        let mut transaction = store.begin_transaction().unwrap();

        assert_eq!(
            transaction.write_master(b"master"),
            Err(CatacombStoreError::InvalidTransactionState)
        );
        transaction.write_user(b"user").unwrap();
        assert_eq!(
            transaction.write_user(b"replacement"),
            Err(CatacombStoreError::InvalidTransactionState)
        );
        assert_eq!(
            transaction.promote(),
            Err(CatacombStoreError::InvalidTransactionState)
        );
        assert_eq!(store.load(), Err(CatacombStoreError::MissingPair));
    }

    #[test]
    fn reserved_metadata_round_trips_and_enforces_native_order() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        let metadata = identity_metadata(1);
        let mut transaction = store.begin_transaction().unwrap();

        assert_eq!(
            transaction.write_metadata(&metadata),
            Err(CatacombStoreError::InvalidTransactionState)
        );
        transaction.reserve_recovery().unwrap();
        transaction.write_metadata(&metadata).unwrap();
        assert_eq!(
            transaction.write_metadata(&metadata),
            Err(CatacombStoreError::InvalidTransactionState)
        );
        transaction.write_user(b"synthetic user").unwrap();
        assert_eq!(
            transaction.write_metadata(&metadata),
            Err(CatacombStoreError::InvalidTransactionState)
        );
        transaction.write_master(b"synthetic master").unwrap();
        transaction.promote_after_native_finish().unwrap();

        assert_eq!(store.load().unwrap().metadata(), Some(metadata.as_slice()));
    }

    #[test]
    fn malformed_metadata_fails_closed_and_is_bounded_before_write() {
        let directory = TestDirectory::new();
        let pending_store = store(&directory);
        let mut transaction = pending_store.begin_transaction().unwrap();
        transaction.reserve_recovery().unwrap();
        assert_eq!(
            transaction.write_metadata(b"malformed"),
            Err(CatacombStoreError::InvalidMetadata)
        );
        assert_eq!(
            transaction.write_metadata(&vec![0; MAX_MANIFEST_SIZE + 1]),
            Err(CatacombStoreError::InvalidMetadata)
        );
        drop(transaction);

        let active_directory = TestDirectory::new();
        let active_store = store(&active_directory);
        active_store.commit(b"user", b"master").unwrap();
        write_new_blob(
            &generation_path(&active_store).join(IDENTITY_METADATA_FILE),
            b"malformed",
        )
        .unwrap();
        assert_eq!(
            active_store.load(),
            Err(CatacombStoreError::InvalidMetadata)
        );
    }

    #[test]
    fn dropping_partial_transaction_preserves_active_pair_and_cleans_stage() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        store.commit(b"active user", b"active master").unwrap();
        let stage;
        {
            let mut transaction = store.begin_transaction().unwrap();
            transaction.write_user(b"uncommitted user").unwrap();
            stage = transaction.stage.clone();
        }

        assert!(!stage.exists());
        let pair = store.load().unwrap();
        assert_eq!(pair.user(), b"active user");
        assert_eq!(pair.master(), b"active master");
    }

    #[test]
    fn uncertain_finish_material_is_retained_and_blocks_new_export() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        let generation;
        let recovery_marker;
        {
            let mut transaction = store.begin_transaction().unwrap();
            transaction.reserve_recovery().unwrap();
            transaction.write_user(b"recovery user").unwrap();
            generation = transaction.generation.clone();
            recovery_marker = transaction.recovery_marker.clone();
        }

        assert!(generation.join(USER_FILE).is_file());
        assert!(recovery_marker.is_file());
        store.recover().unwrap();
        assert!(generation.join(USER_FILE).is_file());
        assert!(matches!(
            store.begin_transaction(),
            Err(CatacombStoreError::PendingExport)
        ));
    }

    #[test]
    fn reserved_empty_generation_survives_crash_and_is_quarantined() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        store.commit(b"active user", b"active master").unwrap();
        let active = generation_path(&store);
        let generation;
        {
            let mut transaction = store.begin_transaction().unwrap();
            transaction.reserve_recovery().unwrap();
            generation = transaction.generation.clone();
        }

        let mut validator_called = false;
        assert_eq!(
            store
                .recover_with_validator(|_| {
                    validator_called = true;
                    Ok::<bool, ()>(true)
                })
                .unwrap(),
            CatacombRecoveryOutcome::Quarantined
        );
        assert!(!validator_called);
        assert!(generation.is_dir());
        assert!(active.is_dir());
        assert_eq!(store.load().unwrap().user(), b"active user");
        assert!(matches!(
            store.begin_transaction(),
            Err(CatacombStoreError::PendingExport)
        ));
    }

    #[test]
    fn absent_store_is_clean_without_creation_or_validation() {
        let directory = TestDirectory::new();
        let path = directory.0.join("absent-store");
        let store = CatacombPairStore::new(&path);
        let mut validator_called = false;

        assert_eq!(
            store
                .recover_with_validator(|_| {
                    validator_called = true;
                    Ok::<bool, ()>(true)
                })
                .unwrap(),
            CatacombRecoveryOutcome::Clean
        );
        assert!(!validator_called);
        assert!(!path.exists());
    }

    #[test]
    fn first_owner_requires_an_absent_catacomb_namespace() {
        let directory = TestDirectory::new();
        let path = directory.0.join("store");
        let store = CatacombPairStore::new(&path);

        assert!(store.is_empty_for_first_owner().unwrap());
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(path.join("owner.uid"), b"42000\n").unwrap();
        assert!(store.is_empty_for_first_owner().unwrap());

        fs::write(path.join(".recovery-malformed"), b"").unwrap();
        assert!(!store.is_empty_for_first_owner().unwrap());
    }

    #[test]
    fn live_validator_alone_can_promote_one_complete_candidate() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        store.commit(b"old user", b"old master").unwrap();
        let old_generation = generation_path(&store);
        let candidate;
        let marker;
        {
            let mut transaction = store.begin_transaction().unwrap();
            transaction.reserve_recovery().unwrap();
            transaction.write_user(b"current user").unwrap();
            transaction.write_master(b"current master").unwrap();
            candidate = transaction.generation.clone();
            marker = transaction.recovery_marker.clone();
        }

        assert_eq!(
            store
                .recover_with_validator(|pair| {
                    assert_eq!(pair.user(), b"current user");
                    assert_eq!(pair.master(), b"current master");
                    Ok::<bool, ()>(true)
                })
                .unwrap(),
            CatacombRecoveryOutcome::Promoted
        );
        assert_eq!(generation_path(&store), candidate);
        assert!(!marker.exists());
        assert!(old_generation.join(USER_FILE).is_file());
        assert!(old_generation.join(MASTER_FILE).is_file());
        assert!(store.begin_transaction().is_ok());
    }

    #[test]
    fn live_recovery_replaces_its_exact_stale_marker_temporary() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        let candidate;
        let marker_temporary;
        {
            let mut transaction = store.begin_transaction().unwrap();
            transaction.reserve_recovery().unwrap();
            transaction.write_user(b"current user").unwrap();
            transaction.write_master(b"current master").unwrap();
            candidate = transaction.generation.clone();
            marker_temporary = transaction.marker_temporary.clone();
        }
        write_marker(&marker_temporary, "pair-a-b-c").unwrap();

        assert_eq!(
            store
                .recover_with_validator(|_| Ok::<bool, ()>(true))
                .unwrap(),
            CatacombRecoveryOutcome::Promoted
        );
        assert_eq!(generation_path(&store), candidate);
        assert!(!marker_temporary.exists());
        assert!(store.begin_transaction().is_ok());
    }

    #[test]
    fn live_recovery_finishes_after_active_marker_was_already_replaced() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        let candidate;
        let generation_name;
        let marker_temporary;
        let recovery_marker;
        {
            let mut transaction = store.begin_transaction().unwrap();
            transaction.reserve_recovery().unwrap();
            transaction.write_user(b"current user").unwrap();
            transaction.write_master(b"current master").unwrap();
            candidate = transaction.generation.clone();
            generation_name = transaction.generation_name.clone();
            marker_temporary = transaction.marker_temporary.clone();
            recovery_marker = transaction.recovery_marker.clone();
        }
        write_marker(&marker_temporary, &generation_name).unwrap();
        fs::rename(&marker_temporary, store.directory.join(ACTIVE_MARKER)).unwrap();
        sync_directory(&store.directory).unwrap();

        assert_eq!(
            store
                .recover_with_validator(|_| Ok::<bool, ()>(true))
                .unwrap(),
            CatacombRecoveryOutcome::Promoted
        );
        assert_eq!(generation_path(&store), candidate);
        assert!(!recovery_marker.exists());
        assert!(store.begin_transaction().is_ok());
    }

    #[test]
    fn cleanup_removes_only_unreserved_inactive_generations() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        store.commit(b"old user", b"old master").unwrap();
        let old_generation = generation_path(&store);
        store.commit(b"active user", b"active master").unwrap();
        let active_generation = generation_path(&store);

        let reserved_generation;
        {
            let mut transaction = store.begin_transaction().unwrap();
            transaction.reserve_recovery().unwrap();
            transaction.write_user(b"possible user").unwrap();
            reserved_generation = transaction.generation.clone();
        }
        let abandoned_stage = store.directory.join(".stage-a-b-c");
        create_private_directory(&abandoned_stage).unwrap();
        write_new_blob(&abandoned_stage.join(USER_FILE), b"abandoned").unwrap();

        store.recover().unwrap();

        assert!(!old_generation.exists());
        assert!(!abandoned_stage.exists());
        assert!(active_generation.is_dir());
        assert!(reserved_generation.join(USER_FILE).is_file());
        assert!(matches!(
            store.begin_transaction(),
            Err(CatacombStoreError::PendingExport)
        ));
    }

    #[test]
    fn validator_rejection_leaves_complete_candidate_quarantined() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        store.commit(b"old user", b"old master").unwrap();
        let candidate;
        {
            let mut transaction = store.begin_transaction().unwrap();
            transaction.reserve_recovery().unwrap();
            transaction.write_user(b"other user").unwrap();
            transaction.write_master(b"other master").unwrap();
            candidate = transaction.generation.clone();
        }

        assert_eq!(
            store
                .recover_with_validator(|_| Ok::<bool, ()>(false))
                .unwrap(),
            CatacombRecoveryOutcome::Quarantined
        );
        assert!(candidate.join(USER_FILE).is_file());
        assert_eq!(store.load().unwrap().user(), b"old user");
        assert!(matches!(
            store.begin_transaction(),
            Err(CatacombStoreError::PendingExport)
        ));
    }

    #[test]
    fn validator_failures_are_redacted_and_leave_the_candidate_reserved() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        let recovery_marker;
        {
            let mut transaction = store.begin_transaction().unwrap();
            transaction.reserve_recovery().unwrap();
            transaction.write_user(b"possible user").unwrap();
            transaction.write_master(b"possible master").unwrap();
            recovery_marker = transaction.recovery_marker.clone();
        }

        let error = store
            .recover_with_validator(|_| Err::<bool, _>("private validator detail"))
            .unwrap_err();

        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("private validator detail"));
        assert!(std::error::Error::source(&error).is_none());
        assert!(recovery_marker.is_file());
        assert!(matches!(
            store.begin_transaction(),
            Err(CatacombStoreError::PendingExport)
        ));
    }

    #[test]
    fn multiple_or_conflicting_candidates_never_reach_validator() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        let first_marker;
        {
            let mut transaction = store.begin_transaction().unwrap();
            transaction.reserve_recovery().unwrap();
            transaction.write_user(b"first user").unwrap();
            transaction.write_master(b"first master").unwrap();
            first_marker = transaction.recovery_marker.clone();
        }
        let second_marker = store.directory.join(".recovery-a-b-c");
        let second_generation = store.directory.join("pair-a-b-c");
        create_private_directory(&second_generation).unwrap();
        write_new_blob(&second_generation.join(USER_FILE), b"second user").unwrap();
        write_new_blob(&second_generation.join(MASTER_FILE), b"second master").unwrap();
        File::options()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&second_marker)
            .unwrap()
            .sync_all()
            .unwrap();

        let mut validator_called = false;
        assert_eq!(
            store
                .recover_with_validator(|_| {
                    validator_called = true;
                    Ok::<bool, ()>(true)
                })
                .unwrap(),
            CatacombRecoveryOutcome::Quarantined
        );
        assert!(!validator_called);
        assert!(first_marker.exists());
        assert!(second_marker.exists());
    }

    #[test]
    fn unsafe_candidate_is_quarantined_without_validation_or_mutation() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        let generation;
        {
            let mut transaction = store.begin_transaction().unwrap();
            transaction.reserve_recovery().unwrap();
            transaction.write_user(b"unsafe user").unwrap();
            transaction.write_master(b"unsafe master").unwrap();
            generation = transaction.generation.clone();
        }
        let user_path = generation.join(USER_FILE);
        fs::set_permissions(&user_path, fs::Permissions::from_mode(0o640)).unwrap();

        let mut validator_called = false;
        assert_eq!(
            store
                .recover_with_validator(|_| {
                    validator_called = true;
                    Ok::<bool, ()>(true)
                })
                .unwrap(),
            CatacombRecoveryOutcome::Quarantined
        );
        assert!(!validator_called);
        assert_eq!(fs::metadata(&user_path).unwrap().mode() & 0o777, 0o640);
        assert!(matches!(
            store.begin_transaction(),
            Err(CatacombStoreError::PendingExport)
        ));
    }

    #[test]
    fn malformed_recovery_metadata_is_quarantined_before_validation() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        store.commit(b"old user", b"old master").unwrap();
        let old_generation = generation_path(&store);
        let candidate;
        {
            let mut transaction = store.begin_transaction().unwrap();
            transaction.reserve_recovery().unwrap();
            transaction.write_metadata(&identity_metadata(2)).unwrap();
            transaction.write_user(b"possible user").unwrap();
            transaction.write_master(b"possible master").unwrap();
            candidate = transaction.generation.clone();
        }
        fs::write(candidate.join(IDENTITY_METADATA_FILE), b"malformed").unwrap();

        let mut validator_called = false;
        assert_eq!(
            store
                .recover_with_validator(|_| {
                    validator_called = true;
                    Ok::<bool, ()>(true)
                })
                .unwrap(),
            CatacombRecoveryOutcome::Quarantined
        );
        assert!(!validator_called);
        assert_eq!(generation_path(&store), old_generation);
    }

    #[test]
    fn finalized_pair_is_retained_when_pre_marker_promotion_fails() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        store.commit(b"old user", b"old master").unwrap();
        let mut transaction = store.begin_transaction().unwrap();
        transaction.reserve_recovery().unwrap();
        transaction.write_metadata(&identity_metadata(3)).unwrap();
        transaction.write_user(b"new user").unwrap();
        transaction.write_master(b"new master").unwrap();
        let generation = transaction.generation.clone();
        let recovery_marker = transaction.recovery_marker.clone();

        assert_eq!(
            transaction.promote_inner(|| Err(CatacombStoreError::StorageUnavailable), true,),
            Err(CatacombStoreError::StorageUnavailable)
        );
        assert!(generation.join(USER_FILE).is_file());
        assert!(generation.join(MASTER_FILE).is_file());
        assert!(generation.join(IDENTITY_METADATA_FILE).is_file());
        assert!(recovery_marker.is_file());
        let active = store.load().unwrap();
        assert_eq!(active.user(), b"old user");
        assert_eq!(active.master(), b"old master");
        assert_eq!(active.metadata(), None);
        assert!(matches!(
            store.begin_transaction(),
            Err(CatacombStoreError::PendingExport)
        ));
    }

    #[test]
    fn active_marker_rename_failure_retains_the_only_possible_pair() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        let mut transaction = store.begin_transaction().unwrap();
        transaction.reserve_recovery().unwrap();
        transaction.write_user(b"new user").unwrap();
        transaction.write_master(b"new master").unwrap();
        let generation = transaction.generation.clone();
        let recovery_marker = transaction.recovery_marker.clone();
        fs::create_dir(store.directory.join(ACTIVE_MARKER)).unwrap();

        assert_eq!(
            transaction.promote_after_native_finish(),
            Err(CatacombStoreError::StorageUnavailable)
        );
        assert!(generation.join(USER_FILE).is_file());
        assert!(generation.join(MASTER_FILE).is_file());
        assert!(recovery_marker.is_file());
        assert!(matches!(
            store.begin_transaction(),
            Err(CatacombStoreError::PendingExport)
        ));
    }

    #[test]
    fn missing_and_partial_pairs_are_never_returned() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        assert_eq!(store.load(), Err(CatacombStoreError::MissingPair));

        store.commit(b"user", b"master").unwrap();
        fs::remove_file(generation_path(&store).join(USER_FILE)).unwrap();
        assert_eq!(store.load(), Err(CatacombStoreError::IncompletePair));
    }

    #[test]
    fn marker_cannot_mix_members_from_different_generations() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        store.commit(b"first user", b"first master").unwrap();
        let first = generation_path(&store);
        store.commit(b"second user", b"second master").unwrap();
        let second = generation_path(&store);

        // A linked member would allow a generation to be assembled from two
        // transactions; the strict one-link rule rejects it.
        fs::remove_file(second.join(USER_FILE)).unwrap();
        fs::hard_link(first.join(USER_FILE), second.join(USER_FILE)).unwrap();
        assert_eq!(store.load(), Err(CatacombStoreError::UnsafeStorage));
    }

    #[test]
    fn metadata_cannot_be_linked_across_generations() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        let mut first = store.begin_transaction().unwrap();
        first.reserve_recovery().unwrap();
        first.write_metadata(&identity_metadata(1)).unwrap();
        first.write_user(b"first user").unwrap();
        first.write_master(b"first master").unwrap();
        first.promote_after_native_finish().unwrap();
        let first = generation_path(&store);

        let mut second = store.begin_transaction().unwrap();
        second.reserve_recovery().unwrap();
        second.write_metadata(&identity_metadata(2)).unwrap();
        second.write_user(b"second user").unwrap();
        second.write_master(b"second master").unwrap();
        second.promote_after_native_finish().unwrap();
        let second = generation_path(&store);

        fs::remove_file(second.join(IDENTITY_METADATA_FILE)).unwrap();
        fs::hard_link(
            first.join(IDENTITY_METADATA_FILE),
            second.join(IDENTITY_METADATA_FILE),
        )
        .unwrap();
        assert_eq!(store.load(), Err(CatacombStoreError::UnsafeStorage));
    }

    #[test]
    fn symlinked_marker_member_and_store_are_rejected() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        store.commit(b"user", b"master").unwrap();
        let generation = generation_path(&store);
        let unrelated = directory.0.join("unrelated");
        fs::write(&unrelated, b"do not read").unwrap();
        fs::set_permissions(&unrelated, fs::Permissions::from_mode(0o600)).unwrap();

        fs::remove_file(generation.join(MASTER_FILE)).unwrap();
        symlink(&unrelated, generation.join(MASTER_FILE)).unwrap();
        assert_eq!(store.load(), Err(CatacombStoreError::UnsafeStorage));
        assert_eq!(fs::read(&unrelated).unwrap(), b"do not read");

        let linked_store = CatacombPairStore::new(directory.0.join("linked-store"));
        symlink(&store.directory, &linked_store.directory).unwrap();
        assert_eq!(linked_store.load(), Err(CatacombStoreError::UnsafeStorage));
    }

    #[test]
    fn mode_owner_and_link_count_validation_is_strict() {
        let expected = 1000;
        assert_eq!(
            validate_file_identity(true, 0o100_600, expected, 1, expected),
            Ok(())
        );
        for result in [
            validate_file_identity(false, 0o040_600, expected, 1, expected),
            validate_file_identity(true, 0o100_640, expected, 1, expected),
            validate_file_identity(true, 0o100_600, expected + 1, 1, expected),
            validate_file_identity(true, 0o100_600, expected, 2, expected),
        ] {
            assert_eq!(result, Err(CatacombStoreError::UnsafeStorage));
        }
    }

    #[test]
    fn unsafe_runtime_modes_are_rejected() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        store.commit(b"user", b"master").unwrap();
        let user_path = generation_path(&store).join(USER_FILE);
        fs::set_permissions(&user_path, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(store.load(), Err(CatacombStoreError::UnsafeStorage));

        fs::set_permissions(&store.directory, fs::Permissions::from_mode(0o750)).unwrap();
        assert_eq!(store.load(), Err(CatacombStoreError::UnsafeStorage));
    }

    #[test]
    fn empty_oversized_and_truncated_blobs_are_rejected() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        assert_eq!(
            store.commit(&[], b"master"),
            Err(CatacombStoreError::InvalidBlob)
        );
        assert_eq!(
            store.commit(&vec![0; MAX_SECURE_CATACOMB_SIZE + 1], b"master"),
            Err(CatacombStoreError::InvalidBlob)
        );

        store.commit(b"user", b"master").unwrap();
        let master_path = generation_path(&store).join(MASTER_FILE);
        File::options()
            .write(true)
            .truncate(true)
            .open(master_path)
            .unwrap();
        assert_eq!(store.load(), Err(CatacombStoreError::InvalidBlob));
    }

    #[test]
    fn failed_promotion_preserves_the_previous_valid_pair() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        store.commit(b"old user", b"old master").unwrap();

        let result = store.commit_inner(b"new user", b"new master", || {
            Err(CatacombStoreError::StorageUnavailable)
        });

        assert_eq!(result, Err(CatacombStoreError::StorageUnavailable));
        let pair = store.load().expect("previous pair remains active");
        assert_eq!(pair.user(), b"old user");
        assert_eq!(pair.master(), b"old master");
    }

    #[test]
    fn recovery_removes_abandoned_stages_without_touching_active_pair() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        store.commit(b"active user", b"active master").unwrap();
        let abandoned = store.directory.join(".stage-1-2-3");
        create_private_directory(&abandoned).unwrap();
        write_new_blob(&abandoned.join(USER_FILE), b"partial user").unwrap();

        store.recover().expect("recover interrupted transaction");

        assert!(!abandoned.exists());
        let pair = store.load().expect("active pair survives recovery");
        assert_eq!(pair.user(), b"active user");
        assert_eq!(pair.master(), b"active master");
    }

    #[test]
    fn recovery_refuses_unexpected_content_in_an_abandoned_stage() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        store.commit(b"active user", b"active master").unwrap();
        let abandoned = store.directory.join(".stage-a-b-c");
        create_private_directory(&abandoned).unwrap();
        write_new_blob(&abandoned.join("unexpected"), b"preserve").unwrap();

        assert_eq!(store.recover(), Err(CatacombStoreError::UnsafeStorage));
        assert!(abandoned.join("unexpected").exists());
        assert_eq!(store.load().unwrap().user(), b"active user");
    }

    #[test]
    fn recovery_preserves_older_generation_when_active_pair_is_partial() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        store.commit(b"older user", b"older master").unwrap();
        let older = generation_path(&store);
        store.commit(b"newer user", b"newer master").unwrap();
        fs::remove_file(generation_path(&store).join(MASTER_FILE)).unwrap();

        assert_eq!(store.recover(), Err(CatacombStoreError::IncompletePair));
        assert!(older.join(USER_FILE).is_file());
        assert!(older.join(MASTER_FILE).is_file());
    }

    #[test]
    fn debug_and_errors_do_not_disclose_opaque_values_or_paths() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        let pair = CatacombPair {
            master: b"secret master material".to_vec(),
            user: b"secret user material".to_vec(),
            metadata: Some(b"secret metadata material".to_vec()),
        };
        let debug = format!("{pair:?} {store:?}");
        assert!(!debug.contains("secret"));
        assert!(!debug.contains(directory.0.to_string_lossy().as_ref()));
        assert!(debug.contains("[redacted]"));

        for error in [
            CatacombStoreError::MissingPair,
            CatacombStoreError::IncompletePair,
            CatacombStoreError::InvalidBlob,
            CatacombStoreError::InvalidMetadata,
            CatacombStoreError::StorageUnavailable,
            CatacombStoreError::UnsafeStorage,
            CatacombStoreError::PendingExport,
            CatacombStoreError::InvalidTransactionState,
            CatacombStoreError::PromotionDurabilityUnknown,
        ] {
            let rendered = format!("{error:?}: {error}");
            assert!(!rendered.contains("secret"));
            assert!(!rendered.contains(directory.0.to_string_lossy().as_ref()));
        }
    }
}

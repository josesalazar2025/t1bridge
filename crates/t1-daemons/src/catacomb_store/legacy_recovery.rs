//! Reservation of one uniquely identifiable inactive legacy generation.

use core::fmt;
use std::fs::{self, File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;

use super::{
    ACTIVE_MARKER, CatacombPairStore, CatacombStoreError, O_NOFOLLOW, is_generation_name,
    is_marker_temporary_name, is_stage_name, read_pair, validate_private_file_metadata,
};
use crate::identity_metadata::decode as decode_identity_metadata;

/// Durable reservation state without exposing a generation name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyRecoveryReservation {
    Created,
    Existing,
}

/// Redaction-safe refusal or storage failure from legacy recovery reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LegacyRecoveryReservationError {
    Refused,
    Store(CatacombStoreError),
}

impl fmt::Display for LegacyRecoveryReservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Refused => "legacy recovery state is not uniquely eligible",
            Self::Store(_) => "legacy recovery storage is unavailable",
        })
    }
}

impl std::error::Error for LegacyRecoveryReservationError {}

impl From<CatacombStoreError> for LegacyRecoveryReservationError {
    fn from(error: CatacombStoreError) -> Self {
        Self::Store(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GenerationKind {
    Labeled,
    Legacy,
}

struct Generation {
    name: String,
    kind: GenerationKind,
}

impl CatacombPairStore {
    /// Durably reserves the only complete inactive metadata-free generation.
    ///
    /// Initial reservation requires exactly two complete generations: the
    /// active generation contains at least one standard label and the other
    /// has no metadata. No caller supplies or receives a generation name.
    /// An exact existing reservation is accepted for crash convergence,
    /// including after the active-marker rename reached disk but its final
    /// durability was reported uncertain.
    ///
    /// This method never changes the active marker and never deletes a file or
    /// generation. Every ambiguous, staged, temporary, malformed, or
    /// differently shaped state is refused without selecting a candidate.
    ///
    /// # Errors
    ///
    /// Returns a redacted refusal for ineligible or ambiguous state, or a
    /// storage failure when private metadata cannot be validated or the
    /// reservation cannot be synchronized.
    pub fn reserve_unique_inactive_legacy_recovery(
        &self,
    ) -> Result<LegacyRecoveryReservation, LegacyRecoveryReservationError> {
        let directory = self.open_existing_directory()?;
        directory
            .sync_all()
            .map_err(|_| CatacombStoreError::StorageUnavailable)?;
        let active = self.read_active_generation()?;
        let generations = self.legacy_recovery_generations(&active)?;
        let [first, second] = generations.as_slice() else {
            return Err(LegacyRecoveryReservationError::Refused);
        };
        let (labeled, legacy) = match (first.kind, second.kind) {
            (GenerationKind::Labeled, GenerationKind::Legacy) => (first, second),
            (GenerationKind::Legacy, GenerationKind::Labeled) => (second, first),
            _ => return Err(LegacyRecoveryReservationError::Refused),
        };

        let recovery_tokens = self.recovery_tokens()?;
        match recovery_tokens.as_slice() {
            [] if active == labeled.name => {
                create_reservation(
                    &directory,
                    &self.directory.join(recovery_name(&legacy.name)),
                )?;
                Ok(LegacyRecoveryReservation::Created)
            }
            [token]
                if generation_name(token) == legacy.name
                    && (active == labeled.name || active == legacy.name) =>
            {
                Ok(LegacyRecoveryReservation::Existing)
            }
            _ => Err(LegacyRecoveryReservationError::Refused),
        }
    }

    fn legacy_recovery_generations(
        &self,
        active: &str,
    ) -> Result<Vec<Generation>, LegacyRecoveryReservationError> {
        let mut names = Vec::new();
        let entries =
            fs::read_dir(&self.directory).map_err(|_| CatacombStoreError::StorageUnavailable)?;
        for entry in entries {
            let name = entry
                .map_err(|_| CatacombStoreError::StorageUnavailable)?
                .file_name()
                .into_string()
                .map_err(|_| CatacombStoreError::UnsafeStorage)?;
            if name == ACTIVE_MARKER || name.starts_with(".recovery-") {
                continue;
            }
            if name.starts_with("pair-") {
                if !is_generation_name(&name) {
                    return Err(LegacyRecoveryReservationError::Refused);
                }
                names.push(name);
            } else if name.starts_with(".stage-")
                || name.starts_with(".active-")
                || is_stage_name(&name)
                || is_marker_temporary_name(&name)
            {
                return Err(LegacyRecoveryReservationError::Refused);
            }
        }
        names.sort();
        if !names.iter().any(|name| name == active) {
            return Err(LegacyRecoveryReservationError::Refused);
        }
        names
            .into_iter()
            .map(|name| {
                let pair = read_pair(&self.directory.join(&name))?;
                let kind = match pair.metadata() {
                    None => GenerationKind::Legacy,
                    Some(encoded) => {
                        let metadata = decode_identity_metadata(encoded)
                            .map_err(|_| CatacombStoreError::InvalidMetadata)?;
                        if metadata
                            .identities
                            .iter()
                            .any(|identity| identity.finger.is_some())
                        {
                            GenerationKind::Labeled
                        } else {
                            return Err(LegacyRecoveryReservationError::Refused);
                        }
                    }
                };
                Ok(Generation { name, kind })
            })
            .collect()
    }
}

fn create_reservation(
    directory: &File,
    path: &std::path::Path,
) -> Result<(), LegacyRecoveryReservationError> {
    let marker = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|_| CatacombStoreError::StorageUnavailable)?;
    validate_private_file_metadata(
        &marker
            .metadata()
            .map_err(|_| CatacombStoreError::StorageUnavailable)?,
    )?;
    marker
        .sync_all()
        .map_err(|_| CatacombStoreError::StorageUnavailable)?;
    directory
        .sync_all()
        .map_err(|_| CatacombStoreError::StorageUnavailable)?;
    Ok(())
}

fn recovery_name(generation: &str) -> String {
    format!(
        ".recovery-{}",
        generation.strip_prefix("pair-").unwrap_or_default()
    )
}

fn generation_name(token: &str) -> String {
    format!("pair-{token}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::identity_metadata::{IdentityMetadata, IdentityMetadataEntry, encode};
    use crate::standard_fingerprint_protocol::{FingerLabel, IdentityId, Username};

    static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    const USER_BLOB: &[u8] = b"synthetic encrypted user catacomb";
    const MASTER_BLOB: &[u8] = b"synthetic encrypted master catacomb";

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "t1bridge-legacy-recovery-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn manifest(labeled: bool) -> Vec<u8> {
        encode(
            &IdentityMetadata::new(
                Username::new("synthetic-owner").unwrap(),
                vec![IdentityMetadataEntry {
                    id: IdentityId::new([0x41; 16]).unwrap(),
                    finger: labeled.then_some(FingerLabel::RightIndex),
                }],
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn commit(store: &CatacombPairStore, metadata: Option<&[u8]>) {
        let mut transaction = store.begin_transaction().unwrap();
        transaction.reserve_recovery().unwrap();
        if let Some(metadata) = metadata {
            transaction.write_metadata(metadata).unwrap();
        }
        transaction.write_user(USER_BLOB).unwrap();
        transaction.write_master(MASTER_BLOB).unwrap();
        transaction.promote_after_native_finish().unwrap();
    }

    fn generation_count(path: &Path) -> usize {
        fs::read_dir(path)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_str().is_some_and(is_generation_name))
            .count()
    }

    fn recovery_count(path: &Path) -> usize {
        fs::read_dir(path)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with(".recovery-"))
            })
            .count()
    }

    #[test]
    fn unique_inactive_legacy_is_reserved_and_promoted_without_deletion() {
        let directory = TestDirectory::new();
        let store = CatacombPairStore::new(directory.0.join("store"));
        commit(&store, None);
        commit(&store, Some(&manifest(true)));
        let active_before = fs::read(store.directory.join(ACTIVE_MARKER)).unwrap();

        assert_eq!(
            store.reserve_unique_inactive_legacy_recovery(),
            Ok(LegacyRecoveryReservation::Created)
        );
        assert_eq!(generation_count(&store.directory), 2);
        assert_eq!(recovery_count(&store.directory), 1);
        assert_eq!(
            fs::read(store.directory.join(ACTIVE_MARKER)).unwrap(),
            active_before
        );
        assert_eq!(
            store
                .recover_with_validator(|pair| Ok::<bool, ()>(pair.metadata().is_none()))
                .unwrap(),
            super::super::CatacombRecoveryOutcome::Promoted
        );
        assert_eq!(generation_count(&store.directory), 2);
        assert_eq!(recovery_count(&store.directory), 0);
        assert!(store.load().unwrap().metadata().is_none());
    }

    #[test]
    fn reservation_is_idempotent_and_rejection_keeps_every_generation() {
        let directory = TestDirectory::new();
        let store = CatacombPairStore::new(directory.0.join("store"));
        commit(&store, None);
        commit(&store, Some(&manifest(true)));

        assert_eq!(
            store.reserve_unique_inactive_legacy_recovery(),
            Ok(LegacyRecoveryReservation::Created)
        );
        assert_eq!(
            store.reserve_unique_inactive_legacy_recovery(),
            Ok(LegacyRecoveryReservation::Existing)
        );
        assert_eq!(
            store
                .recover_with_validator(|_| Ok::<bool, ()>(false))
                .unwrap(),
            super::super::CatacombRecoveryOutcome::Quarantined
        );
        assert_eq!(generation_count(&store.directory), 2);
        assert_eq!(recovery_count(&store.directory), 1);
        assert!(store.load().unwrap().metadata().is_some());
    }

    #[test]
    fn ambiguous_legacy_candidates_are_refused_without_mutation() {
        let directory = TestDirectory::new();
        let store = CatacombPairStore::new(directory.0.join("store"));
        commit(&store, None);
        commit(&store, None);
        commit(&store, Some(&manifest(true)));
        let active_before = fs::read(store.directory.join(ACTIVE_MARKER)).unwrap();

        assert_eq!(
            store.reserve_unique_inactive_legacy_recovery(),
            Err(LegacyRecoveryReservationError::Refused)
        );
        assert_eq!(generation_count(&store.directory), 3);
        assert_eq!(recovery_count(&store.directory), 0);
        assert_eq!(
            fs::read(store.directory.join(ACTIVE_MARKER)).unwrap(),
            active_before
        );
    }

    #[test]
    fn unlabeled_active_or_extra_labeled_generation_is_refused() {
        let first = TestDirectory::new();
        let first_store = CatacombPairStore::new(first.0.join("store"));
        commit(&first_store, Some(&manifest(true)));
        commit(&first_store, None);
        assert_eq!(
            first_store.reserve_unique_inactive_legacy_recovery(),
            Err(LegacyRecoveryReservationError::Refused)
        );

        let second = TestDirectory::new();
        let second_store = CatacombPairStore::new(second.0.join("store"));
        commit(&second_store, None);
        commit(&second_store, Some(&manifest(true)));
        commit(&second_store, Some(&manifest(true)));
        assert_eq!(
            second_store.reserve_unique_inactive_legacy_recovery(),
            Err(LegacyRecoveryReservationError::Refused)
        );
        assert_eq!(generation_count(&second_store.directory), 3);
    }

    #[test]
    fn metadata_without_a_label_is_not_an_active_labeled_generation() {
        let directory = TestDirectory::new();
        let store = CatacombPairStore::new(directory.0.join("store"));
        commit(&store, None);
        commit(&store, Some(&manifest(false)));

        assert_eq!(
            store.reserve_unique_inactive_legacy_recovery(),
            Err(LegacyRecoveryReservationError::Refused)
        );
        assert_eq!(generation_count(&store.directory), 2);
        assert_eq!(recovery_count(&store.directory), 0);
    }
}

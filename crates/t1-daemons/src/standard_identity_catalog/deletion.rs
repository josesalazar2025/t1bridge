//! Exact deletion of one labeled standard identity.

use core::fmt;

use t1_bridge::control::BiometricTransport;
use t1_bridge::policy::BiometricUserId;

use super::{CatalogError, StandardIdentityCatalog};
use crate::catacomb_session::CatacombBackup;
use crate::catacomb_store::CatacombPairTransaction;
use crate::identity_lifecycle::{
    IdentityRemovalError, remove_identity_with_transaction_and_metadata,
    remove_prepared_identity_with_transaction_and_metadata,
};
use crate::standard_fingerprint_protocol::IdentityId;

/// A redaction-safe labeled deletion failure.
pub enum StandardIdentityDeletionError<TransportError> {
    /// The target was not an exact labeled member, or the catalog was invalid.
    Catalog(CatalogError),
    /// The exact Mesa deletion or durable generation transaction failed.
    Removal(IdentityRemovalError<TransportError>),
}

impl<TransportError> fmt::Debug for StandardIdentityDeletionError<TransportError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Catalog(error) => formatter.debug_tuple("Catalog").field(error).finish(),
            Self::Removal(error) => formatter.debug_tuple("Removal").field(error).finish(),
        }
    }
}

impl<TransportError> fmt::Display for StandardIdentityDeletionError<TransportError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Catalog(_) => formatter.write_str("standard identity deletion was refused"),
            Self::Removal(_) => formatter.write_str("standard identity deletion failed"),
        }
    }
}

impl<TransportError> std::error::Error for StandardIdentityDeletionError<TransportError> {}

/// Deletes exactly one labeled identity and atomically persists the complete
/// remaining catalog with the resulting user/master catacombs.
///
/// The catalog target and next manifest are validated before any transport
/// work. Immediately before mutation, the shared removal workflow rechecks
/// that Mesa's complete live set still equals this reconciled catalog. Hidden
/// legacy identities and unrelated labeled identities remain in the manifest.
///
/// # Errors
///
/// Refuses an absent or unlabeled target before hardware access. Thereafter,
/// returns a redacted exact-removal, persistence, or postcommit-set failure.
pub fn delete_labeled_identity_with_transaction<Transport: BiometricTransport>(
    transport: &mut Transport,
    transaction: CatacombPairTransaction<'_>,
    user_id: BiometricUserId,
    catalog: &StandardIdentityCatalog,
    target: IdentityId,
) -> Result<CatacombBackup, StandardIdentityDeletionError<Transport::Error>> {
    let mut next = catalog.clone();
    next.remove_labeled(target)
        .map_err(StandardIdentityDeletionError::Catalog)?;
    let metadata = next
        .encode_next_manifest()
        .map_err(StandardIdentityDeletionError::Catalog)?;
    let expected_before: Vec<_> = catalog
        .identities
        .iter()
        .map(|entry| entry.id.as_bytes())
        .collect();

    remove_identity_with_transaction_and_metadata(
        transport,
        transaction,
        user_id,
        target.as_bytes(),
        &expected_before,
        &metadata,
    )
    .map_err(StandardIdentityDeletionError::Removal)
}

/// Deletes one labelled identity using the live set returned by the caller's
/// immediately preceding policy/restore operation.
///
/// # Errors
///
/// Returns a typed catalog, transport, persistence, or verification failure
/// without deleting any identity other than the exact labelled target.
pub fn delete_prepared_labeled_identity_with_transaction<Transport: BiometricTransport>(
    transport: &mut Transport,
    transaction: CatacombPairTransaction<'_>,
    user_id: BiometricUserId,
    prepared_before: &[t1_bridge::mesa::Identity],
    catalog: &StandardIdentityCatalog,
    target: IdentityId,
) -> Result<CatacombBackup, StandardIdentityDeletionError<Transport::Error>> {
    let mut next = catalog.clone();
    next.remove_labeled(target)
        .map_err(StandardIdentityDeletionError::Catalog)?;
    let metadata = next
        .encode_next_manifest()
        .map_err(StandardIdentityDeletionError::Catalog)?;
    let expected_before: Vec<_> = catalog
        .identities
        .iter()
        .map(|entry| entry.id.as_bytes())
        .collect();

    remove_prepared_identity_with_transaction_and_metadata(
        transport,
        transaction,
        user_id,
        prepared_before,
        target.as_bytes(),
        &expected_before,
        &metadata,
    )
    .map_err(StandardIdentityDeletionError::Removal)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use t1_bridge::biometric::{COMMAND_HEADER_SIZE, DAEMON_INFO_SIZE};
    use t1_bridge::commands::CommandPacket;
    use t1_bridge::mesa::{IDENTITY_V1_SIZE, parse_identity};

    use crate::catacomb_store::{CatacombPairStore, CatacombStoreError};
    use crate::identity_metadata::{
        IdentityMetadata, IdentityMetadataEntry, decode as decode_metadata,
        encode as encode_metadata,
    };
    use crate::standard_fingerprint_protocol::{FingerLabel, Username};

    const USER: i32 = 501;
    static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct SyntheticTransportError;

    impl fmt::Display for SyntheticTransportError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("private deletion transport detail")
        }
    }

    impl std::error::Error for SyntheticTransportError {}

    struct FakeTransport {
        responses: VecDeque<Result<Vec<u8>, SyntheticTransportError>>,
        commands: Vec<(u16, Vec<u8>)>,
    }

    impl FakeTransport {
        fn new(
            responses: impl IntoIterator<Item = Result<Vec<u8>, SyntheticTransportError>>,
        ) -> Self {
            Self {
                responses: responses.into_iter().collect(),
                commands: Vec::new(),
            }
        }

        fn codes(&self) -> Vec<u16> {
            self.commands.iter().map(|command| command.0).collect()
        }
    }

    impl BiometricTransport for FakeTransport {
        type Error = SyntheticTransportError;

        fn execute(&mut self, packet: &CommandPacket) -> Result<Vec<u8>, Self::Error> {
            self.commands.push((
                u16::from_le_bytes(packet.request()[2..4].try_into().unwrap()),
                packet.request().to_vec(),
            ));
            self.responses.pop_front().expect("synthetic response")
        }
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "t1bridge-standard-delete-test-{}-{sequence}",
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

    fn id(value: u8) -> IdentityId {
        IdentityId::new([value; 16]).unwrap()
    }

    fn entry(value: u8, finger: Option<FingerLabel>) -> IdentityMetadataEntry {
        IdentityMetadataEntry {
            id: id(value),
            finger,
        }
    }

    fn owner() -> Username {
        Username::new("synthetic-owner").unwrap()
    }

    fn user() -> BiometricUserId {
        BiometricUserId::new(i64::from(USER)).unwrap()
    }

    fn manifest() -> IdentityMetadata {
        IdentityMetadata::new(
            owner(),
            vec![
                entry(1, None),
                entry(2, Some(FingerLabel::RightIndex)),
                entry(3, Some(FingerLabel::LeftThumb)),
            ],
        )
        .unwrap()
    }

    fn catalog() -> StandardIdentityCatalog {
        StandardIdentityCatalog::reconcile(Some(manifest()), owner(), &[id(1), id(2), id(3)])
            .unwrap()
    }

    fn daemon_info() -> Vec<u8> {
        let mut response = vec![0_u8; DAEMON_INFO_SIZE];
        response[..4].copy_from_slice(&1_u32.to_le_bytes());
        response[4..8].copy_from_slice(&5_u32.to_le_bytes());
        response
    }

    fn identity(identifier: IdentityId) -> Vec<u8> {
        [
            USER.to_le_bytes().as_slice(),
            identifier.as_bytes().as_slice(),
        ]
        .concat()
    }

    fn identities(identifiers: &[IdentityId]) -> Vec<u8> {
        identifiers
            .iter()
            .flat_map(|identifier| identity(*identifier))
            .collect()
    }

    fn prepared(identifiers: &[IdentityId]) -> Vec<t1_bridge::mesa::Identity> {
        identifiers
            .iter()
            .map(|identifier| parse_identity(&identity(*identifier)).unwrap())
            .collect()
    }

    fn preparation(before: &[IdentityId]) -> Vec<Result<Vec<u8>, SyntheticTransportError>> {
        vec![
            Ok(Vec::new()),
            Ok(daemon_info()),
            Ok([USER.cast_unsigned().to_le_bytes(), 3_u32.to_le_bytes()].concat()),
            Ok(identities(before)),
        ]
    }

    fn persistence(after: &[IdentityId]) -> Vec<Result<Vec<u8>, SyntheticTransportError>> {
        let user = b"synthetic encrypted user";
        let master = b"synthetic encrypted master";
        vec![
            Ok(u32::try_from(user.len()).unwrap().to_le_bytes().to_vec()),
            Ok(user.to_vec()),
            Ok(Vec::new()),
            Ok(u32::try_from(master.len()).unwrap().to_le_bytes().to_vec()),
            Ok(master.to_vec()),
            Ok(Vec::new()),
            Ok(identities(after)),
        ]
    }

    fn store(directory: &TestDirectory) -> CatacombPairStore {
        CatacombPairStore::new(directory.0.join("store"))
    }

    fn install_active_pair(store: &CatacombPairStore) {
        let metadata = encode_metadata(&manifest()).unwrap();
        let mut transaction = store.begin_transaction().unwrap();
        transaction.reserve_recovery().unwrap();
        transaction.write_metadata(&metadata).unwrap();
        transaction.write_user(b"old user").unwrap();
        transaction.write_master(b"old master").unwrap();
        transaction.promote_after_native_finish().unwrap();
    }

    #[test]
    fn prepared_labeled_delete_uses_restored_set_without_repreparing_user() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        let mut responses = vec![Ok(Vec::new())];
        responses.extend(persistence(&[id(1), id(3)]));
        let mut transport = FakeTransport::new(responses);
        let restored = prepared(&[id(1), id(2), id(3)]);

        delete_prepared_labeled_identity_with_transaction(
            &mut transport,
            store.begin_transaction().unwrap(),
            user(),
            &restored,
            &catalog(),
            id(2),
        )
        .unwrap();

        assert_eq!(
            transport.codes(),
            [0x0d, 0x3d, 0x3e, 0x3f, 0x3d, 0x3e, 0x3f, 0x42]
        );
        let remove = &transport.commands[0].1;
        assert_eq!(remove.len(), COMMAND_HEADER_SIZE + IDENTITY_V1_SIZE);
        assert_eq!(&remove[COMMAND_HEADER_SIZE + 4..], &[2; 16]);
        let committed = decode_metadata(store.load().unwrap().metadata().unwrap()).unwrap();
        assert_eq!(
            committed.identities,
            vec![entry(1, None), entry(3, Some(FingerLabel::LeftThumb))]
        );
    }

    #[test]
    fn unlabeled_or_absent_target_refuses_before_hardware() {
        for target in [id(1), id(4)] {
            let directory = TestDirectory::new();
            let store = store(&directory);
            let mut transport = FakeTransport::new([]);

            assert!(matches!(
                delete_labeled_identity_with_transaction(
                    &mut transport,
                    store.begin_transaction().unwrap(),
                    user(),
                    &catalog(),
                    target,
                ),
                Err(StandardIdentityDeletionError::Catalog(
                    CatalogError::IdentityNotLabeled
                ))
            ));
            assert!(transport.commands.is_empty());
            assert_eq!(store.load(), Err(CatacombStoreError::MissingPair));
        }
    }

    #[test]
    fn changed_live_set_refuses_before_delete_or_recovery_reservation() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        let mut transport = FakeTransport::new(preparation(&[id(1), id(2), id(4)]));

        assert!(matches!(
            delete_labeled_identity_with_transaction(
                &mut transport,
                store.begin_transaction().unwrap(),
                user(),
                &catalog(),
                id(2),
            ),
            Err(StandardIdentityDeletionError::Removal(
                IdentityRemovalError::PreMutationIdentityChange {
                    missing: 1,
                    unexpected: 1
                }
            ))
        ));
        assert_eq!(transport.codes(), [0x31, 0x28, 0x3c, 0x42]);
        assert!(store.begin_transaction().is_ok());
    }

    #[test]
    fn ambiguous_delete_keeps_old_marker_and_reserved_next_manifest() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        install_active_pair(&store);
        let old_metadata = store.load().unwrap().metadata().unwrap().to_vec();
        let mut responses = preparation(&[id(1), id(2), id(3)]);
        responses.push(Err(SyntheticTransportError));
        let mut transport = FakeTransport::new(responses);

        assert!(matches!(
            delete_labeled_identity_with_transaction(
                &mut transport,
                store.begin_transaction().unwrap(),
                user(),
                &catalog(),
                id(2),
            ),
            Err(StandardIdentityDeletionError::Removal(
                IdentityRemovalError::CommandAmbiguous(_)
            ))
        ));
        assert_eq!(
            store.load().unwrap().metadata(),
            Some(old_metadata.as_slice())
        );
        assert!(matches!(
            store.begin_transaction(),
            Err(CatacombStoreError::PendingExport)
        ));
    }

    #[test]
    fn diagnostics_do_not_expose_owner_or_identity_or_transport_details() {
        let errors = [
            format!(
                "{:?}",
                StandardIdentityDeletionError::<SyntheticTransportError>::Catalog(
                    CatalogError::IdentityNotLabeled,
                )
            ),
            format!(
                "{:?}",
                StandardIdentityDeletionError::Removal(IdentityRemovalError::CommandAmbiguous(
                    crate::identity_lifecycle::IdentityRemovalCommandError::Transport(
                        SyntheticTransportError,
                    ),
                ),)
            ),
        ];
        for diagnostic in errors {
            assert!(!diagnostic.contains("synthetic-owner"));
            assert!(!diagnostic.contains("private"));
            assert!(!diagnostic.contains("020202"));
        }
    }
}

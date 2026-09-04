//! Paired secure-catacomb export with native finish-after-durability ordering.

use core::fmt;

use t1_bridge::catacomb::{
    CatacombError, parse_secure_catacomb_size, validate_secure_catacomb_export,
};
use t1_bridge::commands::{
    CommandError, finish_save_secure_catacomb_command, save_secure_catacomb_command,
    secure_catacomb_size_command, validate_empty_response,
};
use t1_bridge::control::BiometricTransport;
use t1_bridge::policy::BiometricUserId;
use t1_platform::secret;

use crate::catacomb_store::{CatacombPairStore, CatacombPairTransaction, CatacombStoreError};
use crate::identity_metadata::decode as decode_identity_metadata;

const MASTER_USER_ID: i64 = -1;

/// Sizes of a newly promoted opaque catacomb pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CatacombBackup {
    /// Concrete user's encrypted export size.
    pub user_size: usize,
    /// Master component's encrypted export size.
    pub master_size: usize,
}

/// A transaction whose recovery reservation and next identity manifest are
/// durable before a caller enters a Mesa mutation boundary.
pub(crate) struct ReservedMetadataTransaction<'store>(CatacombPairTransaction<'store>);

#[derive(Clone, Copy)]
enum TransactionPreparation<'metadata> {
    Reserve(Option<&'metadata [u8]>),
    AlreadyReserved,
}

/// A redaction-safe paired-export failure.
pub enum CatacombSessionError<E> {
    /// The caller-owned biometric transport failed.
    Transport(E),
    /// A command packet or empty response was invalid.
    Command(CommandError),
    /// A secure export size or payload was invalid.
    Catacomb(CatacombError),
    /// Durable private storage failed.
    Store(CatacombStoreError),
}

impl<E> fmt::Debug for CatacombSessionError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(_) => formatter.write_str("Transport([redacted])"),
            Self::Command(error) => formatter.debug_tuple("Command").field(error).finish(),
            Self::Catacomb(error) => formatter.debug_tuple("Catacomb").field(error).finish(),
            Self::Store(error) => formatter.debug_tuple("Store").field(error).finish(),
        }
    }
}

impl<E> fmt::Display for CatacombSessionError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(_) => formatter.write_str("biometric transport failed"),
            Self::Command(error) => error.fmt(formatter),
            Self::Catacomb(error) => error.fmt(formatter),
            Self::Store(error) => error.fmt(formatter),
        }
    }
}

impl<E> std::error::Error for CatacombSessionError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Command(error) => Some(error),
            Self::Catacomb(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::Transport(_) => None,
        }
    }
}

impl<E> From<CommandError> for CatacombSessionError<E> {
    fn from(error: CommandError) -> Self {
        Self::Command(error)
    }
}

impl<E> From<CatacombError> for CatacombSessionError<E> {
    fn from(error: CatacombError) -> Self {
        Self::Catacomb(error)
    }
}

impl<E> From<CatacombStoreError> for CatacombSessionError<E> {
    fn from(error: CatacombStoreError) -> Self {
        Self::Store(error)
    }
}

/// Exports, durably stages, finishes, and atomically promotes one user/master
/// pair in the native order.
///
/// Storage is prepared before the first hardware command. Each finish command
/// is sent only after that member's file and staging directory are synced. The
/// active marker changes only after both finish commands succeed.
///
/// # Errors
///
/// Returns a transport, protocol, or storage error. Any prior active pair
/// remains selected unless promotion reached marker replacement, in which case
/// an uncertain final directory sync is reported distinctly by the store.
pub fn backup_catacomb_pair<T: BiometricTransport>(
    transport: &mut T,
    store: &CatacombPairStore,
    user_id: BiometricUserId,
) -> Result<CatacombBackup, CatacombSessionError<T::Error>> {
    let transaction = store.begin_transaction()?;
    backup_catacomb_pair_with_transaction(transport, transaction, user_id)
}

/// Exports and promotes a pair using storage reserved by the caller.
///
/// This entry point lets enrollment reserve a private paired transaction
/// before the first sensor command while retaining the native user-then-master
/// export, durability, finish, and promotion ordering owned by this module.
///
/// # Errors
///
/// Returns the same transport, protocol, or storage errors as
/// [`backup_catacomb_pair`].
pub fn backup_catacomb_pair_with_transaction<T: BiometricTransport>(
    transport: &mut T,
    transaction: CatacombPairTransaction<'_>,
    user_id: BiometricUserId,
) -> Result<CatacombBackup, CatacombSessionError<T::Error>> {
    backup_catacomb_pair_inner(transport, transaction, user_id, None)
}

/// Exports and promotes a pair together with one identity manifest.
///
/// The validated metadata is durably reserved before the first native save.
/// The user/master sequence is shared with the metadata-free legacy path.
///
/// # Errors
///
/// Returns before any hardware command for malformed metadata, then otherwise
/// returns the same errors as [`backup_catacomb_pair_with_transaction`].
pub fn backup_catacomb_pair_with_transaction_and_metadata<T: BiometricTransport>(
    transport: &mut T,
    transaction: CatacombPairTransaction<'_>,
    user_id: BiometricUserId,
    metadata: &[u8],
) -> Result<CatacombBackup, CatacombSessionError<T::Error>> {
    decode_identity_metadata(metadata)
        .map_err(|_| CatacombSessionError::Store(CatacombStoreError::InvalidMetadata))?;
    backup_catacomb_pair_inner(transport, transaction, user_id, Some(metadata))
}

/// Durably reserves a recovery generation and writes its validated identity
/// manifest before a caller mutates Mesa state.
pub(crate) fn reserve_transaction_with_metadata<'store>(
    mut transaction: CatacombPairTransaction<'store>,
    metadata: &[u8],
) -> Result<ReservedMetadataTransaction<'store>, CatacombStoreError> {
    decode_identity_metadata(metadata).map_err(|_| CatacombStoreError::InvalidMetadata)?;
    transaction.reserve_recovery()?;
    transaction.write_metadata(metadata)?;
    Ok(ReservedMetadataTransaction(transaction))
}

/// Completes the shared native export sequence for an already reserved
/// metadata generation.
pub(crate) fn backup_catacomb_pair_with_reserved_metadata<T: BiometricTransport>(
    transport: &mut T,
    transaction: ReservedMetadataTransaction<'_>,
    user_id: BiometricUserId,
) -> Result<CatacombBackup, CatacombSessionError<T::Error>> {
    backup_catacomb_pair_inner_with_reservation(
        transport,
        transaction.0,
        user_id,
        TransactionPreparation::AlreadyReserved,
    )
}

fn backup_catacomb_pair_inner<T: BiometricTransport>(
    transport: &mut T,
    transaction: CatacombPairTransaction<'_>,
    user_id: BiometricUserId,
    metadata: Option<&[u8]>,
) -> Result<CatacombBackup, CatacombSessionError<T::Error>> {
    backup_catacomb_pair_inner_with_reservation(
        transport,
        transaction,
        user_id,
        TransactionPreparation::Reserve(metadata),
    )
}

fn backup_catacomb_pair_inner_with_reservation<T: BiometricTransport>(
    transport: &mut T,
    mut transaction: CatacombPairTransaction<'_>,
    user_id: BiometricUserId,
    preparation: TransactionPreparation<'_>,
) -> Result<CatacombBackup, CatacombSessionError<T::Error>> {
    let user_id = i64::from(user_id.as_raw());
    let user_size = query_export_size(transport, user_id)?;
    if let TransactionPreparation::Reserve(metadata) = preparation {
        transaction.reserve_recovery()?;
        if let Some(metadata) = metadata {
            transaction.write_metadata(metadata)?;
        }
    }
    let mut user = export_catacomb(transport, user_id, user_size)?;
    let write_user = transaction.write_user(&user);
    secret::wipe(&mut user);
    write_user?;
    finish_export(transport, user_id)?;

    let master_size = query_export_size(transport, MASTER_USER_ID)?;
    let mut master = export_catacomb(transport, MASTER_USER_ID, master_size)?;
    let write_master = transaction.write_master(&master);
    secret::wipe(&mut master);
    write_master?;
    finish_export(transport, MASTER_USER_ID)?;

    transaction.promote_after_native_finish()?;
    Ok(CatacombBackup {
        user_size,
        master_size,
    })
}

fn query_export_size<T: BiometricTransport>(
    transport: &mut T,
    user_id: i64,
) -> Result<usize, CatacombSessionError<T::Error>> {
    let size_packet = secure_catacomb_size_command(user_id)?;
    let size_response = transport
        .execute(&size_packet)
        .map_err(CatacombSessionError::Transport)?;
    parse_secure_catacomb_size(&size_response).map_err(CatacombSessionError::Catacomb)
}

fn export_catacomb<T: BiometricTransport>(
    transport: &mut T,
    user_id: i64,
    size: usize,
) -> Result<Vec<u8>, CatacombSessionError<T::Error>> {
    let export_packet = save_secure_catacomb_command(user_id, size)?;
    let mut response = transport
        .execute(&export_packet)
        .map_err(CatacombSessionError::Transport)?;
    if let Err(error) = validate_secure_catacomb_export(&response, size) {
        secret::wipe(&mut response);
        return Err(CatacombSessionError::Catacomb(error));
    }
    Ok(response)
}

fn finish_export<T: BiometricTransport>(
    transport: &mut T,
    user_id: i64,
) -> Result<(), CatacombSessionError<T::Error>> {
    let packet = finish_save_secure_catacomb_command(user_id)?;
    let response = transport
        .execute(&packet)
        .map_err(CatacombSessionError::Transport)?;
    validate_empty_response(&response).map_err(CatacombSessionError::Command)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use t1_bridge::biometric::COMMAND_HEADER_SIZE;
    use t1_bridge::commands::CommandPacket;

    static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct SyntheticError;

    impl fmt::Display for SyntheticError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("synthetic transport failure")
        }
    }

    impl std::error::Error for SyntheticError {}

    struct FakeTransport {
        responses: VecDeque<Result<Vec<u8>, SyntheticError>>,
        commands: Vec<(u16, u32, usize)>,
    }

    impl FakeTransport {
        fn new(responses: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self {
                responses: responses.into_iter().map(Ok).collect(),
                commands: Vec::new(),
            }
        }
    }

    impl BiometricTransport for FakeTransport {
        type Error = SyntheticError;

        fn execute(&mut self, packet: &CommandPacket) -> Result<Vec<u8>, Self::Error> {
            let request = packet.request();
            self.commands.push((
                u16::from_le_bytes(request[2..4].try_into().unwrap()),
                u32::from_le_bytes(
                    request[COMMAND_HEADER_SIZE..COMMAND_HEADER_SIZE + 4]
                        .try_into()
                        .unwrap(),
                ),
                packet.response_capacity(),
            ));
            self.responses.pop_front().expect("synthetic response")
        }
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "t1bridge-catacomb-session-test-{}-{sequence}",
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

    fn user() -> BiometricUserId {
        BiometricUserId::new(501).unwrap()
    }

    fn identity_metadata() -> Vec<u8> {
        use crate::identity_metadata::{IdentityMetadata, IdentityMetadataEntry, encode};
        use crate::standard_fingerprint_protocol::{IdentityId, Username};

        encode(
            &IdentityMetadata::new(
                Username::new("synthetic-owner").unwrap(),
                vec![IdentityMetadataEntry {
                    id: IdentityId::new([7; 16]).unwrap(),
                    finger: None,
                }],
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn commits_user_then_master_with_finish_after_each_durable_write() {
        let directory = TestDirectory::new();
        let store = CatacombPairStore::new(directory.0.join("store"));
        let user_blob = b"synthetic encrypted user".to_vec();
        let master_blob = b"synthetic encrypted master".to_vec();
        let mut transport = FakeTransport::new([
            u32::try_from(user_blob.len())
                .unwrap()
                .to_le_bytes()
                .to_vec(),
            user_blob.clone(),
            Vec::new(),
            u32::try_from(master_blob.len())
                .unwrap()
                .to_le_bytes()
                .to_vec(),
            master_blob.clone(),
            Vec::new(),
        ]);

        assert_eq!(
            backup_catacomb_pair(&mut transport, &store, user()).unwrap(),
            CatacombBackup {
                user_size: user_blob.len(),
                master_size: master_blob.len(),
            }
        );
        assert_eq!(
            transport.commands,
            [
                (0x3d, 501, 4),
                (0x3e, 501, user_blob.len()),
                (0x3f, 501, 0),
                (0x3d, u32::MAX, 4),
                (0x3e, u32::MAX, master_blob.len()),
                (0x3f, u32::MAX, 0),
            ]
        );
        let pair = store.load().unwrap();
        assert_eq!(pair.user(), user_blob);
        assert_eq!(pair.master(), master_blob);
    }

    #[test]
    fn metadata_wrapper_uses_the_shared_native_export_sequence() {
        let directory = TestDirectory::new();
        let store = CatacombPairStore::new(directory.0.join("store"));
        let metadata = identity_metadata();
        let user_blob = b"synthetic encrypted user".to_vec();
        let master_blob = b"synthetic encrypted master".to_vec();
        let mut transport = FakeTransport::new([
            u32::try_from(user_blob.len())
                .unwrap()
                .to_le_bytes()
                .to_vec(),
            user_blob,
            Vec::new(),
            u32::try_from(master_blob.len())
                .unwrap()
                .to_le_bytes()
                .to_vec(),
            master_blob,
            Vec::new(),
        ]);
        let transaction = store.begin_transaction().unwrap();

        backup_catacomb_pair_with_transaction_and_metadata(
            &mut transport,
            transaction,
            user(),
            &metadata,
        )
        .unwrap();

        assert_eq!(store.load().unwrap().metadata(), Some(metadata.as_slice()));
        assert_eq!(
            transport
                .commands
                .iter()
                .map(|command| command.0)
                .collect::<Vec<_>>(),
            [0x3d, 0x3e, 0x3f, 0x3d, 0x3e, 0x3f]
        );
    }

    #[test]
    fn invalid_metadata_fails_before_hardware_or_reservation() {
        let directory = TestDirectory::new();
        let store = CatacombPairStore::new(directory.0.join("store"));
        let transaction = store.begin_transaction().unwrap();
        let mut transport = FakeTransport::new([]);

        assert!(matches!(
            backup_catacomb_pair_with_transaction_and_metadata(
                &mut transport,
                transaction,
                user(),
                b"malformed",
            ),
            Err(CatacombSessionError::Store(
                CatacombStoreError::InvalidMetadata
            ))
        ));
        assert!(transport.commands.is_empty());
        assert!(store.begin_transaction().is_ok());
    }

    #[test]
    fn invalid_store_fails_before_hardware() {
        let directory = TestDirectory::new();
        let path = directory.0.join("not-a-directory");
        fs::write(&path, b"preserve").unwrap();
        let store = CatacombPairStore::new(path);
        let mut transport = FakeTransport::new([]);

        assert!(matches!(
            backup_catacomb_pair(&mut transport, &store, user()),
            Err(CatacombSessionError::Store(_))
        ));
        assert!(transport.commands.is_empty());
    }

    #[test]
    fn short_export_never_finishes_or_promotes() {
        let directory = TestDirectory::new();
        let store = CatacombPairStore::new(directory.0.join("store"));
        let mut transport = FakeTransport::new([8_u32.to_le_bytes().to_vec(), vec![0; 7]]);

        assert!(matches!(
            backup_catacomb_pair(&mut transport, &store, user()),
            Err(CatacombSessionError::Catacomb(
                CatacombError::SecureExportSizeMismatch { .. }
            ))
        ));
        assert_eq!(
            transport
                .commands
                .iter()
                .map(|command| command.0)
                .collect::<Vec<_>>(),
            [0x3d, 0x3e]
        );
        assert_eq!(store.load(), Err(CatacombStoreError::MissingPair));
    }

    #[test]
    fn failed_finish_preserves_previous_active_pair() {
        let directory = TestDirectory::new();
        let store = CatacombPairStore::new(directory.0.join("store"));
        store.commit(b"old user", b"old master").unwrap();
        let user_blob = b"new encrypted user".to_vec();
        let mut transport = FakeTransport::new([
            u32::try_from(user_blob.len())
                .unwrap()
                .to_le_bytes()
                .to_vec(),
            user_blob,
            vec![1],
        ]);
        let metadata = identity_metadata();
        let transaction = store.begin_transaction().unwrap();

        assert!(matches!(
            backup_catacomb_pair_with_transaction_and_metadata(
                &mut transport,
                transaction,
                user(),
                &metadata,
            ),
            Err(CatacombSessionError::Command(
                CommandError::UnexpectedResponseData { actual: 1 }
            ))
        ));
        let pair = store.load().unwrap();
        assert_eq!(pair.user(), b"old user");
        assert_eq!(pair.master(), b"old master");
        assert_eq!(pair.metadata(), None);
        assert!(matches!(
            store.begin_transaction(),
            Err(CatacombStoreError::PendingExport)
        ));
    }

    #[test]
    fn failure_after_user_finish_preserves_its_durable_export() {
        let directory = TestDirectory::new();
        let store = CatacombPairStore::new(directory.0.join("store"));
        let user_blob = b"new encrypted user".to_vec();
        let mut transport = FakeTransport::new([
            u32::try_from(user_blob.len())
                .unwrap()
                .to_le_bytes()
                .to_vec(),
            user_blob,
            Vec::new(),
            Vec::new(),
        ]);

        assert!(matches!(
            backup_catacomb_pair(&mut transport, &store, user()),
            Err(CatacombSessionError::Catacomb(
                CatacombError::InvalidResponseLength { .. }
            ))
        ));
        assert_eq!(
            transport
                .commands
                .iter()
                .map(|command| command.0)
                .collect::<Vec<_>>(),
            [0x3d, 0x3e, 0x3f, 0x3d]
        );
        assert!(matches!(
            store.begin_transaction(),
            Err(CatacombStoreError::PendingExport)
        ));
    }

    #[test]
    fn transport_diagnostics_do_not_disclose_opaque_material() {
        let directory = TestDirectory::new();
        let store = CatacombPairStore::new(directory.0.join("store"));
        let mut transport = FakeTransport {
            responses: VecDeque::from([Err(SyntheticError)]),
            commands: Vec::new(),
        };
        let error = backup_catacomb_pair(&mut transport, &store, user()).unwrap_err();
        assert_eq!(
            format!("{error:?} {error}"),
            "Transport([redacted]) biometric transport failed"
        );
        assert!(std::error::Error::source(&error).is_none());
    }
}

//! Atomic per-identity mutation and paired-catacomb persistence.

use core::fmt;

use t1_bridge::commands::{CommandError, remove_identity_command, validate_empty_response};
use t1_bridge::control::BiometricTransport;
use t1_bridge::mesa::{Identity, IdentityIdentifier};
use t1_bridge::policy::BiometricUserId;
use t1_bridge::user_workflow::{UserWorkflowError, list_user_identities, prepare_user};

use crate::catacomb_session::{
    CatacombBackup, CatacombSessionError, ReservedMetadataTransaction,
    backup_catacomb_pair_with_reserved_metadata, backup_catacomb_pair_with_transaction,
    reserve_transaction_with_metadata,
};
use crate::catacomb_store::CatacombPairTransaction;

enum RemovalPersistence<'store> {
    Legacy(CatacombPairTransaction<'store>),
    Metadata(ReservedMetadataTransaction<'store>),
}

/// Failure while issuing a removal command whose completion may be ambiguous.
pub enum IdentityRemovalCommandError<TransportError> {
    /// The transport failed after the command was handed to it.
    Transport(TransportError),
    /// The command returned data despite its zero-output contract.
    Response(CommandError),
}

impl<TransportError> fmt::Debug for IdentityRemovalCommandError<TransportError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(_) => formatter.write_str("Transport([redacted])"),
            Self::Response(error) => formatter.debug_tuple("Response").field(error).finish(),
        }
    }
}

impl<TransportError> fmt::Display for IdentityRemovalCommandError<TransportError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(_) => formatter.write_str("identity-removal transport failed"),
            Self::Response(error) => error.fmt(formatter),
        }
    }
}

/// A redaction-safe per-identity removal transaction failure.
pub enum IdentityRemovalError<TransportError> {
    /// The user or its complete pre-mutation identity set could not be prepared.
    Preparation(UserWorkflowError<TransportError>),
    /// The requested identity was absent before any mutation.
    TargetMissing,
    /// The live identity set changed after standard catalog reconciliation.
    PreMutationIdentityChange {
        /// Catalog identities missing from the immediate live set.
        missing: usize,
        /// Live identities absent from the reconciled catalog.
        unexpected: usize,
    },
    /// Mesa may have applied the command, but its completion was not provable.
    CommandAmbiguous(IdentityRemovalCommandError<TransportError>),
    /// The mutated user/master catacomb pair could not be durably promoted.
    Persistence(CatacombSessionError<TransportError>),
    /// The committed identity list could not be read and validated.
    PostCommitVerification(UserWorkflowError<TransportError>),
    /// The removed identity remained present after persistence.
    TargetStillPresent,
    /// An unrelated identity disappeared or an unrequested identity appeared.
    CollateralIdentityChange {
        /// Number of preexisting unrelated identities now missing.
        missing: usize,
        /// Number of identities not present in the expected post-removal set.
        unexpected: usize,
    },
}

impl<TransportError> fmt::Debug for IdentityRemovalError<TransportError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Preparation(error) => formatter.debug_tuple("Preparation").field(error).finish(),
            Self::TargetMissing => formatter.write_str("TargetMissing"),
            Self::PreMutationIdentityChange {
                missing,
                unexpected,
            } => formatter
                .debug_struct("PreMutationIdentityChange")
                .field("missing", missing)
                .field("unexpected", unexpected)
                .finish(),
            Self::CommandAmbiguous(error) => formatter
                .debug_tuple("CommandAmbiguous")
                .field(error)
                .finish(),
            Self::Persistence(error) => formatter.debug_tuple("Persistence").field(error).finish(),
            Self::PostCommitVerification(error) => formatter
                .debug_tuple("PostCommitVerification")
                .field(error)
                .finish(),
            Self::TargetStillPresent => formatter.write_str("TargetStillPresent"),
            Self::CollateralIdentityChange {
                missing,
                unexpected,
            } => formatter
                .debug_struct("CollateralIdentityChange")
                .field("missing", missing)
                .field("unexpected", unexpected)
                .finish(),
        }
    }
}

impl<TransportError> fmt::Display for IdentityRemovalError<TransportError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Preparation(_) => formatter.write_str("identity-removal preparation failed"),
            Self::TargetMissing => formatter.write_str("identity was not enrolled before removal"),
            Self::PreMutationIdentityChange { .. } => formatter
                .write_str("live identities changed before removal; no identity was removed"),
            Self::CommandAmbiguous(_) => {
                formatter.write_str("identity-removal command completion is ambiguous")
            }
            Self::Persistence(_) => formatter.write_str("catacomb persistence failed"),
            Self::PostCommitVerification(_) => {
                formatter.write_str("post-commit identity verification failed; revalidate storage")
            }
            Self::TargetStillPresent => formatter
                .write_str("removed identity remains after catacomb commit; revalidate storage"),
            Self::CollateralIdentityChange { .. } => formatter.write_str(
                "unrelated identities changed during removal; revalidate biometric state",
            ),
        }
    }
}

impl<TransportError> std::error::Error for IdentityRemovalError<TransportError> {}

/// Removes exactly one enrolled identity and durably promotes the resulting
/// user/master catacomb pair.
///
/// The caller must reserve `transaction` before entering any live biometric
/// mutation boundary. The full validated identity set is retained across the
/// mutation so the final read can prove the target is absent, every unrelated
/// identity remains, and no new identity appeared.
///
/// # Errors
///
/// Returns a distinct error for preparation, an absent target, ambiguous
/// command completion, persistence, unreadable post-commit state, a surviving
/// target, or collateral identity changes.
pub fn remove_identity_with_transaction<Transport: BiometricTransport>(
    transport: &mut Transport,
    transaction: CatacombPairTransaction<'_>,
    user_id: BiometricUserId,
    target_identifier: IdentityIdentifier,
) -> Result<CatacombBackup, IdentityRemovalError<Transport::Error>> {
    remove_identity_inner(
        transport,
        transaction,
        user_id,
        target_identifier,
        None,
        None,
    )
}

/// Removes one identity after rechecking a reconciled standard catalog and
/// durably reserving its complete next manifest before Mesa mutation.
pub(crate) fn remove_identity_with_transaction_and_metadata<Transport: BiometricTransport>(
    transport: &mut Transport,
    transaction: CatacombPairTransaction<'_>,
    user_id: BiometricUserId,
    target_identifier: IdentityIdentifier,
    expected_before: &[IdentityIdentifier],
    metadata: &[u8],
) -> Result<CatacombBackup, IdentityRemovalError<Transport::Error>> {
    remove_identity_inner(
        transport,
        transaction,
        user_id,
        target_identifier,
        Some((expected_before, metadata)),
        None,
    )
}

/// Removes one identity using the live set returned by the caller's immediately
/// preceding restore, without selecting and refreshing that user a second time.
pub(crate) fn remove_prepared_identity_with_transaction_and_metadata<
    Transport: BiometricTransport,
>(
    transport: &mut Transport,
    transaction: CatacombPairTransaction<'_>,
    user_id: BiometricUserId,
    prepared_before: &[Identity],
    target_identifier: IdentityIdentifier,
    expected_before: &[IdentityIdentifier],
    metadata: &[u8],
) -> Result<CatacombBackup, IdentityRemovalError<Transport::Error>> {
    remove_identity_inner(
        transport,
        transaction,
        user_id,
        target_identifier,
        Some((expected_before, metadata)),
        Some(prepared_before),
    )
}

fn remove_identity_inner<Transport: BiometricTransport>(
    transport: &mut Transport,
    transaction: CatacombPairTransaction<'_>,
    user_id: BiometricUserId,
    target_identifier: IdentityIdentifier,
    standard: Option<(&[IdentityIdentifier], &[u8])>,
    prepared_before: Option<&[Identity]>,
) -> Result<CatacombBackup, IdentityRemovalError<Transport::Error>> {
    let before = match prepared_before {
        Some(before) => before.to_vec(),
        None => prepare_user(transport, user_id).map_err(IdentityRemovalError::Preparation)?,
    };
    let target = before
        .iter()
        .copied()
        .find(|identity| identity.identifier() == target_identifier)
        .ok_or(IdentityRemovalError::TargetMissing)?;

    let persistence = if let Some((expected_before, metadata)) = standard {
        verify_pre_mutation_set(&before, expected_before)?;
        let transaction =
            reserve_transaction_with_metadata(transaction, metadata).map_err(|error| {
                IdentityRemovalError::Persistence(CatacombSessionError::Store(error))
            })?;
        RemovalPersistence::Metadata(transaction)
    } else {
        RemovalPersistence::Legacy(transaction)
    };

    let response = transport
        .execute(&remove_identity_command(target))
        .map_err(|error| {
            IdentityRemovalError::CommandAmbiguous(IdentityRemovalCommandError::Transport(error))
        })?;
    validate_empty_response(&response).map_err(|error| {
        IdentityRemovalError::CommandAmbiguous(IdentityRemovalCommandError::Response(error))
    })?;

    let backup = match persistence {
        RemovalPersistence::Legacy(transaction) => {
            backup_catacomb_pair_with_transaction(transport, transaction, user_id)
        }
        RemovalPersistence::Metadata(transaction) => {
            backup_catacomb_pair_with_reserved_metadata(transport, transaction, user_id)
        }
    }
    .map_err(IdentityRemovalError::Persistence)?;
    let after = list_user_identities(transport, user_id)
        .map_err(IdentityRemovalError::PostCommitVerification)?;
    verify_identity_delta(&before, &after, target_identifier)?;
    Ok(backup)
}

fn verify_pre_mutation_set<TransportError>(
    actual: &[Identity],
    expected: &[IdentityIdentifier],
) -> Result<(), IdentityRemovalError<TransportError>> {
    let missing = expected
        .iter()
        .filter(|identifier| {
            !actual
                .iter()
                .any(|identity| identity.identifier() == **identifier)
        })
        .count();
    let unexpected = actual
        .iter()
        .filter(|identity| !expected.contains(&identity.identifier()))
        .count();
    if missing != 0 || unexpected != 0 || expected.len() != actual.len() {
        return Err(IdentityRemovalError::PreMutationIdentityChange {
            missing,
            unexpected,
        });
    }
    Ok(())
}

fn verify_identity_delta<TransportError>(
    before: &[Identity],
    after: &[Identity],
    target_identifier: IdentityIdentifier,
) -> Result<(), IdentityRemovalError<TransportError>> {
    if after
        .iter()
        .any(|identity| identity.identifier() == target_identifier)
    {
        return Err(IdentityRemovalError::TargetStillPresent);
    }

    let mut unmatched = after.to_vec();
    let mut missing = 0;
    for expected in before
        .iter()
        .filter(|identity| identity.identifier() != target_identifier)
    {
        if let Some(index) = unmatched.iter().position(|actual| actual == expected) {
            unmatched.swap_remove(index);
        } else {
            missing += 1;
        }
    }
    let unexpected = unmatched.len();
    if missing != 0 || unexpected != 0 {
        return Err(IdentityRemovalError::CollateralIdentityChange {
            missing,
            unexpected,
        });
    }
    Ok(())
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
    use t1_bridge::mesa::IDENTITY_V1_SIZE;

    const USER: i32 = 501;
    const TARGET: IdentityIdentifier = [0x11; 16];
    const PRESERVED: IdentityIdentifier = [0x22; 16];
    const ADDED: IdentityIdentifier = [0x33; 16];
    static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct SyntheticTransportError;

    impl fmt::Display for SyntheticTransportError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("private identity transport detail")
        }
    }

    impl std::error::Error for SyntheticTransportError {}

    struct FakeTransport {
        responses: VecDeque<Result<Vec<u8>, SyntheticTransportError>>,
        commands: Vec<(u16, Vec<u8>, usize)>,
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
                "t1bridge-identity-lifecycle-test-{}-{sequence}",
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
        BiometricUserId::new(i64::from(USER)).unwrap()
    }

    fn daemon_info() -> Vec<u8> {
        let mut response = vec![0_u8; DAEMON_INFO_SIZE];
        response[..4].copy_from_slice(&1_u32.to_le_bytes());
        response[4..8].copy_from_slice(&5_u32.to_le_bytes());
        response
    }

    fn states() -> Vec<u8> {
        [USER.cast_unsigned().to_le_bytes(), 3_u32.to_le_bytes()].concat()
    }

    fn identity(identifier: IdentityIdentifier) -> Vec<u8> {
        [USER.to_le_bytes().as_slice(), identifier.as_slice()].concat()
    }

    fn identities(identifiers: &[IdentityIdentifier]) -> Vec<u8> {
        identifiers
            .iter()
            .flat_map(|identifier| identity(*identifier))
            .collect()
    }

    fn preparation(before: &[IdentityIdentifier]) -> Vec<Result<Vec<u8>, SyntheticTransportError>> {
        vec![
            Ok(Vec::new()),
            Ok(daemon_info()),
            Ok(states()),
            Ok(identities(before)),
        ]
    }

    fn persistence_and_verification(
        after: &[IdentityIdentifier],
    ) -> Vec<Result<Vec<u8>, SyntheticTransportError>> {
        let user_blob = b"synthetic encrypted user";
        let master_blob = b"synthetic encrypted master";
        vec![
            Ok(u32::try_from(user_blob.len())
                .unwrap()
                .to_le_bytes()
                .to_vec()),
            Ok(user_blob.to_vec()),
            Ok(Vec::new()),
            Ok(u32::try_from(master_blob.len())
                .unwrap()
                .to_le_bytes()
                .to_vec()),
            Ok(master_blob.to_vec()),
            Ok(Vec::new()),
            Ok(identities(after)),
        ]
    }

    fn transaction(
        store: &crate::catacomb_store::CatacombPairStore,
    ) -> CatacombPairTransaction<'_> {
        store.begin_transaction().unwrap()
    }

    #[test]
    fn removes_only_target_then_persists_and_verifies_exact_identity_set() {
        let directory = TestDirectory::new();
        let store = crate::catacomb_store::CatacombPairStore::new(directory.0.join("store"));
        let mut responses = preparation(&[TARGET, PRESERVED]);
        responses.push(Ok(Vec::new()));
        responses.extend(persistence_and_verification(&[PRESERVED]));
        let mut transport = FakeTransport::new(responses);

        let backup =
            remove_identity_with_transaction(&mut transport, transaction(&store), user(), TARGET)
                .unwrap();

        assert_eq!(backup.user_size, b"synthetic encrypted user".len());
        assert_eq!(backup.master_size, b"synthetic encrypted master".len());
        assert_eq!(
            transport.codes(),
            [
                0x31, 0x28, 0x3c, 0x42, 0x0d, 0x3d, 0x3e, 0x3f, 0x3d, 0x3e, 0x3f, 0x42
            ]
        );
        let remove = &transport.commands[4];
        assert_eq!(remove.2, 0);
        assert_eq!(remove.1.len(), COMMAND_HEADER_SIZE + IDENTITY_V1_SIZE);
        assert_eq!(
            &remove.1[COMMAND_HEADER_SIZE..COMMAND_HEADER_SIZE + 4],
            &USER.cast_unsigned().to_le_bytes()
        );
        assert_eq!(&remove.1[COMMAND_HEADER_SIZE + 4..], &TARGET);
        let pair = store.load().unwrap();
        assert_eq!(pair.user(), b"synthetic encrypted user");
        assert_eq!(pair.master(), b"synthetic encrypted master");
    }

    #[test]
    fn missing_target_refuses_before_mutation_or_persistence() {
        let directory = TestDirectory::new();
        let store = crate::catacomb_store::CatacombPairStore::new(directory.0.join("store"));
        let mut transport = FakeTransport::new(preparation(&[PRESERVED]));

        assert!(matches!(
            remove_identity_with_transaction(&mut transport, transaction(&store), user(), TARGET),
            Err(IdentityRemovalError::TargetMissing)
        ));
        assert_eq!(transport.codes(), [0x31, 0x28, 0x3c, 0x42]);
    }

    #[test]
    fn delete_transport_and_response_failures_are_ambiguous_and_stop() {
        for response in [Err(SyntheticTransportError), Ok(vec![0xaa])] {
            let directory = TestDirectory::new();
            let store = crate::catacomb_store::CatacombPairStore::new(directory.0.join("store"));
            let mut responses = preparation(&[TARGET]);
            responses.push(response);
            let mut transport = FakeTransport::new(responses);

            assert!(matches!(
                remove_identity_with_transaction(
                    &mut transport,
                    transaction(&store),
                    user(),
                    TARGET
                ),
                Err(IdentityRemovalError::CommandAmbiguous(_))
            ));
            assert_eq!(transport.codes(), [0x31, 0x28, 0x3c, 0x42, 0x0d]);
        }
    }

    #[test]
    fn persistence_and_post_commit_read_failures_remain_distinct() {
        let directory = TestDirectory::new();
        let store = crate::catacomb_store::CatacombPairStore::new(directory.0.join("store"));
        let mut persistence_responses = preparation(&[TARGET]);
        persistence_responses.extend([Ok(Vec::new()), Ok(Vec::new())]);
        let mut persistence_transport = FakeTransport::new(persistence_responses);
        assert!(matches!(
            remove_identity_with_transaction(
                &mut persistence_transport,
                transaction(&store),
                user(),
                TARGET
            ),
            Err(IdentityRemovalError::Persistence(_))
        ));

        let directory = TestDirectory::new();
        let store = crate::catacomb_store::CatacombPairStore::new(directory.0.join("store"));
        let mut verification_responses = preparation(&[TARGET]);
        verification_responses.push(Ok(Vec::new()));
        let mut committed = persistence_and_verification(&[]);
        committed.pop();
        committed.push(Err(SyntheticTransportError));
        verification_responses.extend(committed);
        let mut verification_transport = FakeTransport::new(verification_responses);
        assert!(matches!(
            remove_identity_with_transaction(
                &mut verification_transport,
                transaction(&store),
                user(),
                TARGET
            ),
            Err(IdentityRemovalError::PostCommitVerification(_))
        ));
    }

    #[test]
    fn target_survival_and_collateral_changes_are_distinct() {
        for (after, expected) in [
            (&[TARGET, PRESERVED][..], "target"),
            (&[][..], "missing"),
            (&[PRESERVED, ADDED][..], "unexpected"),
        ] {
            let directory = TestDirectory::new();
            let store = crate::catacomb_store::CatacombPairStore::new(directory.0.join("store"));
            let mut responses = preparation(&[TARGET, PRESERVED]);
            responses.push(Ok(Vec::new()));
            responses.extend(persistence_and_verification(after));
            let mut transport = FakeTransport::new(responses);

            let error = remove_identity_with_transaction(
                &mut transport,
                transaction(&store),
                user(),
                TARGET,
            )
            .unwrap_err();
            match expected {
                "target" => assert!(matches!(error, IdentityRemovalError::TargetStillPresent)),
                "missing" => assert!(matches!(
                    error,
                    IdentityRemovalError::CollateralIdentityChange {
                        missing: 1,
                        unexpected: 0
                    }
                )),
                "unexpected" => assert!(matches!(
                    error,
                    IdentityRemovalError::CollateralIdentityChange {
                        missing: 0,
                        unexpected: 1
                    }
                )),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn errors_do_not_render_transport_or_identity_details() {
        let error = IdentityRemovalError::CommandAmbiguous(IdentityRemovalCommandError::Transport(
            SyntheticTransportError,
        ));
        for rendered in [format!("{error:?}"), error.to_string()] {
            assert!(!rendered.contains("private"));
            assert!(!rendered.contains("detail"));
            assert!(!rendered.contains("11"));
        }
    }
}

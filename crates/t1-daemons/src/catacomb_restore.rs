//! Master-first restore of one durable secure-catacomb pair.

use core::fmt;

use t1_bridge::biometric::{ResponseError, parse_daemon_info};
use t1_bridge::catacomb::{CatacombError, CatacombStateEntry, parse_catacomb_states};
use t1_bridge::commands::{
    CommandError, CommandPacket, catacomb_states_command, daemon_info_command, identities_command,
    load_secure_catacomb_command, parse_sks_lock_state, set_active_user_command,
    sks_lock_state_command, validate_empty_response, validate_identity_list_response,
};
use t1_bridge::control::{BiometricTransport, ControlError, ensure_fdr_calibration_loaded};
use t1_bridge::mesa::{IDENTITY_V1_SIZE, Identity, MesaError, parse_identity};
use t1_bridge::policy::BiometricUserId;
use t1_platform::secret;

use crate::catacomb_store::{
    CatacombPair, CatacombPairStore, CatacombRecoveryError, CatacombRecoveryOutcome,
    CatacombStoreError,
};

const MASTER_USER_ID: i64 = -1;
const MASTER_STATE_USER_ID: u32 = u32::MAX;
const MASTER_LOADED: u32 = 1;
const USER_SECURELY_LOADED: u32 = 3;
const CATACOMB_CORRUPTED: u32 = 0x80;

/// Identities validated after selecting or restoring one user's catacomb.
#[derive(Clone, Eq, PartialEq)]
pub struct RestoredCatacomb {
    identities: Vec<Identity>,
    already_loaded: bool,
}

impl RestoredCatacomb {
    /// Returns the validated identities needed by the subsequent match flow.
    #[must_use]
    pub fn identities(&self) -> &[Identity] {
        &self.identities
    }

    /// Returns the identity count without exposing opaque identifiers.
    #[must_use]
    pub const fn identity_count(&self) -> usize {
        self.identities.len()
    }

    /// Reports whether live identities made a restore unnecessary.
    #[must_use]
    pub const fn already_loaded(&self) -> bool {
        self.already_loaded
    }
}

impl fmt::Debug for RestoredCatacomb {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RestoredCatacomb")
            .field("identity_count", &self.identities.len())
            .field("identities", &"[redacted]")
            .field("already_loaded", &self.already_loaded)
            .finish()
    }
}

/// Hardware command stage within paired restore.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatacombRestoreStage {
    /// Read the requested user's live identities before deciding to restore.
    LiveIdentities,
    /// Select the master component before loading the durable pair.
    SelectMaster,
    /// Refresh the component map before loading the durable master.
    RefreshBeforeRestore,
    /// Load the durable master component.
    LoadMaster,
    /// Validate the master component after loading it.
    ValidateMaster,
    /// Load the durable user component.
    LoadUser,
    /// Validate the user component after loading it.
    ValidateUser,
    /// Read the restored user's identities.
    RestoredIdentities,
    /// Read the restored user's secure-key-store state.
    LockState,
}

impl fmt::Display for CatacombRestoreStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::LiveIdentities => "live identity read",
            Self::SelectMaster => "master selection",
            Self::RefreshBeforeRestore => "pre-restore component refresh",
            Self::LoadMaster => "master load",
            Self::ValidateMaster => "master validation",
            Self::LoadUser => "user load",
            Self::ValidateUser => "user validation",
            Self::RestoredIdentities => "restored identity read",
            Self::LockState => "restored lock-state read",
        })
    }
}

/// A redaction-safe paired-restore failure.
pub enum CatacombRestoreError<E> {
    /// The caller-owned biometric transport failed.
    Transport {
        /// Restore stage issuing the failed command.
        stage: CatacombRestoreStage,
        /// Opaque caller-owned transport failure.
        error: E,
    },
    /// Durable pair storage failed validation or could not be read.
    Store(CatacombStoreError),
    /// The live sensor could not be calibrated before recovery validation.
    Calibration(ControlError<E>),
    /// A command packet or fixed response was malformed.
    Command(CommandError),
    /// Mesa daemon metadata was malformed.
    Response(ResponseError),
    /// Catacomb state metadata was malformed.
    Catacomb(CatacombError),
    /// An identity record was malformed.
    Mesa(MesaError),
    /// A live identity-list response contained another user's identity.
    LiveIdentityForAnotherUser,
    /// The master component did not report its loaded bit after restore.
    MasterNotLoaded {
        /// Raw master state, if the component was present.
        state: Option<u32>,
    },
    /// The concrete user did not report both required loaded bits.
    UserNotSecurelyLoaded {
        /// Raw user state, if the component was present.
        state: Option<u32>,
    },
    /// The restored user blob contained no enrolled identities.
    NoEnrolledFingerprints,
    /// A restored identity-list response contained another user's identity.
    RestoredIdentityForAnotherUser,
    /// The secure-key-store state marked the restored catacomb corrupted.
    CorruptedCatacomb,
}

impl<E> fmt::Debug for CatacombRestoreError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport { stage, .. } => formatter
                .debug_struct("Transport")
                .field("stage", stage)
                .field("error", &"[redacted]")
                .finish(),
            Self::Store(error) => formatter.debug_tuple("Store").field(error).finish(),
            Self::Calibration(error) => formatter.debug_tuple("Calibration").field(error).finish(),
            Self::Command(error) => formatter.debug_tuple("Command").field(error).finish(),
            Self::Response(error) => formatter.debug_tuple("Response").field(error).finish(),
            Self::Catacomb(error) => formatter.debug_tuple("Catacomb").field(error).finish(),
            Self::Mesa(error) => formatter.debug_tuple("Mesa").field(error).finish(),
            Self::LiveIdentityForAnotherUser => formatter.write_str("LiveIdentityForAnotherUser"),
            Self::MasterNotLoaded { state } => formatter
                .debug_struct("MasterNotLoaded")
                .field("state", state)
                .finish(),
            Self::UserNotSecurelyLoaded { state } => formatter
                .debug_struct("UserNotSecurelyLoaded")
                .field("state", state)
                .finish(),
            Self::NoEnrolledFingerprints => formatter.write_str("NoEnrolledFingerprints"),
            Self::RestoredIdentityForAnotherUser => {
                formatter.write_str("RestoredIdentityForAnotherUser")
            }
            Self::CorruptedCatacomb => formatter.write_str("CorruptedCatacomb"),
        }
    }
}

impl<E> fmt::Display for CatacombRestoreError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport { stage, .. } => {
                write!(formatter, "biometric transport failed during {stage}")
            }
            Self::Store(error) => error.fmt(formatter),
            Self::Calibration(_) => formatter.write_str("recovery calibration failed"),
            Self::Command(error) => error.fmt(formatter),
            Self::Response(error) => error.fmt(formatter),
            Self::Catacomb(error) => error.fmt(formatter),
            Self::Mesa(error) => error.fmt(formatter),
            Self::LiveIdentityForAnotherUser => {
                formatter.write_str("live catacomb contains an identity for another user")
            }
            Self::MasterNotLoaded { state } => {
                write!(
                    formatter,
                    "restored master catacomb is not loaded (state={state:?})"
                )
            }
            Self::UserNotSecurelyLoaded { state } => write!(
                formatter,
                "restored user catacomb is not securely loaded (state={state:?})"
            ),
            Self::NoEnrolledFingerprints => {
                formatter.write_str("restored catacomb contains no enrolled fingerprints")
            }
            Self::RestoredIdentityForAnotherUser => {
                formatter.write_str("restored catacomb contains an identity for another user")
            }
            Self::CorruptedCatacomb => {
                formatter.write_str("SEP reports the restored catacomb as corrupted")
            }
        }
    }
}

impl<E: std::error::Error + 'static> std::error::Error for CatacombRestoreError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Store(error) => Some(error),
            Self::Calibration(error) => Some(error),
            Self::Command(error) => Some(error),
            Self::Response(error) => Some(error),
            Self::Catacomb(error) => Some(error),
            Self::Mesa(error) => Some(error),
            Self::Transport { .. }
            | Self::LiveIdentityForAnotherUser
            | Self::MasterNotLoaded { .. }
            | Self::UserNotSecurelyLoaded { .. }
            | Self::NoEnrolledFingerprints
            | Self::RestoredIdentityForAnotherUser
            | Self::CorruptedCatacomb => None,
        }
    }
}

impl<E> From<CatacombStoreError> for CatacombRestoreError<E> {
    fn from(error: CatacombStoreError) -> Self {
        Self::Store(error)
    }
}

impl<E> From<CommandError> for CatacombRestoreError<E> {
    fn from(error: CommandError) -> Self {
        Self::Command(error)
    }
}

impl<E> From<ResponseError> for CatacombRestoreError<E> {
    fn from(error: ResponseError) -> Self {
        Self::Response(error)
    }
}

impl<E> From<CatacombError> for CatacombRestoreError<E> {
    fn from(error: CatacombError) -> Self {
        Self::Catacomb(error)
    }
}

impl<E> From<MesaError> for CatacombRestoreError<E> {
    fn from(error: MesaError) -> Self {
        Self::Mesa(error)
    }
}

/// Restores the active master/user pair in native order and validates it.
///
/// The selected durable pair is validated before live state is inspected.
/// Existing valid identities short-circuit without mutation. Otherwise the
/// master component is selected and refreshed. The durable master is loaded and
/// checked even if a previous generation reports its loaded bit. The concrete
/// user blob is then loaded and independently checked.
/// The user is not selected before command `0x40`; the load itself establishes
/// that active component, matching the native ordering.
///
/// The live fast path treats every valid identity for the requested biometric
/// user as authoritative, matching the proven native flow. That state may have
/// been left by another root-managed stack using the same biometric user, so
/// competing stacks must not operate concurrently. An empty live identity set
/// falls back to the validated durable pair.
///
/// # Errors
///
/// Returns before mutation for unsafe storage or inconsistent live identities.
/// After mutation begins, every response and final identity is validated; a
/// missing state bit, empty identity list, cross-user identity, or corrupted
/// SKS state fails the restore.
pub fn restore_catacomb_pair<T: BiometricTransport>(
    transport: &mut T,
    store: &CatacombPairStore,
    user_id: BiometricUserId,
) -> Result<RestoredCatacomb, CatacombRestoreError<T::Error>> {
    let pair = store.load()?;

    restore_pair(transport, &pair, user_id, true, false)
}

/// Restores a durable pair for enrollment, including a securely loaded user
/// whose validated identity catalog is empty after exact deletion.
#[cfg(feature = "auth-broker-service")]
pub(crate) fn restore_catacomb_pair_for_enrollment<T: BiometricTransport>(
    transport: &mut T,
    store: &CatacombPairStore,
    user_id: BiometricUserId,
) -> Result<RestoredCatacomb, CatacombRestoreError<T::Error>> {
    let pair = store.load()?;

    restore_pair(transport, &pair, user_id, true, true)
}

/// Validates one reserved candidate against the live T1 without trusting
/// pre-existing identities.
///
/// Calibration is validated and loaded before the master-first restore. A
/// complete successful restore is accepted. A candidate with missing state,
/// wrong-user or absent identities, or a live corruption flag is definitively
/// rejected. Transport and malformed protocol responses remain errors because
/// they cannot establish whether the candidate is current.
///
/// # Errors
///
/// Returns a redaction-safe live validation failure when the device result is
/// unavailable or unverifiable.
pub fn validate_recovery_candidate<T: BiometricTransport>(
    transport: &mut T,
    pair: &CatacombPair,
    user_id: BiometricUserId,
    fdr_record: &[u8],
) -> Result<bool, CatacombRestoreError<T::Error>> {
    ensure_fdr_calibration_loaded(transport, fdr_record)
        .map_err(CatacombRestoreError::Calibration)?;
    match restore_pair(transport, pair, user_id, false, false) {
        Ok(_) => Ok(true),
        Err(
            CatacombRestoreError::MasterNotLoaded { .. }
            | CatacombRestoreError::UserNotSecurelyLoaded { .. }
            | CatacombRestoreError::NoEnrolledFingerprints
            | CatacombRestoreError::RestoredIdentityForAnotherUser
            | CatacombRestoreError::CorruptedCatacomb,
        ) => Ok(false),
        Err(error) => Err(error),
    }
}

/// Resolves one ambiguous durable candidate only after live T1 validation.
///
/// Storage owns quarantine and marker promotion. Calibration and restoration
/// run only for one complete candidate; clean, incomplete, conflicting, and
/// unsafe states do not touch hardware. An unverifiable result retains the
/// recovery reservation.
///
/// # Errors
///
/// Returns a redaction-safe storage or live validation failure. An
/// unverifiable live result preserves the store's recovery reservation;
/// storage errors retain the store's more specific crash-state semantics.
pub fn recover_ambiguous_pair<T: BiometricTransport>(
    transport: &mut T,
    store: &CatacombPairStore,
    user_id: BiometricUserId,
    fdr_record: &[u8],
) -> Result<CatacombRecoveryOutcome, CatacombRecoveryError<CatacombRestoreError<T::Error>>> {
    store.recover_with_validator(|pair| {
        validate_recovery_candidate(transport, pair, user_id, fdr_record)
    })
}

fn restore_pair<T: BiometricTransport>(
    transport: &mut T,
    pair: &CatacombPair,
    user_id: BiometricUserId,
    allow_live_short_circuit: bool,
    allow_empty_identities: bool,
) -> Result<RestoredCatacomb, CatacombRestoreError<T::Error>> {
    if allow_live_short_circuit {
        let existing = read_identities(transport, user_id, CatacombRestoreStage::LiveIdentities)?;
        if !existing.is_empty() {
            ensure_identity_user(&existing, user_id)
                .map_err(|()| CatacombRestoreError::LiveIdentityForAnotherUser)?;
            return Ok(RestoredCatacomb {
                identities: existing,
                already_loaded: true,
            });
        }
    }

    execute_empty(
        transport,
        &set_active_user_command(MASTER_USER_ID)?,
        CatacombRestoreStage::SelectMaster,
    )?;
    drop(read_catacomb_states(
        transport,
        CatacombRestoreStage::RefreshBeforeRestore,
    )?);

    execute_empty(
        transport,
        &load_secure_catacomb_command(pair.master())?,
        CatacombRestoreStage::LoadMaster,
    )?;
    let master_states = read_catacomb_states(transport, CatacombRestoreStage::ValidateMaster)?;
    let master_state = state_for(&master_states, MASTER_STATE_USER_ID);
    if master_state.is_none_or(|state| state & MASTER_LOADED == 0) {
        return Err(CatacombRestoreError::MasterNotLoaded {
            state: master_state,
        });
    }

    execute_empty(
        transport,
        &load_secure_catacomb_command(pair.user())?,
        CatacombRestoreStage::LoadUser,
    )?;
    let user_states = read_catacomb_states(transport, CatacombRestoreStage::ValidateUser)?;
    let user_state = state_for(&user_states, user_id.as_raw());
    if user_state.is_none_or(|state| state & USER_SECURELY_LOADED != USER_SECURELY_LOADED) {
        return Err(CatacombRestoreError::UserNotSecurelyLoaded { state: user_state });
    }

    let identities = read_identities(transport, user_id, CatacombRestoreStage::RestoredIdentities)?;
    if identities.is_empty() && !allow_empty_identities {
        return Err(CatacombRestoreError::NoEnrolledFingerprints);
    }
    ensure_identity_user(&identities, user_id)
        .map_err(|()| CatacombRestoreError::RestoredIdentityForAnotherUser)?;

    let lock_response = execute(
        transport,
        &sks_lock_state_command(user_id),
        CatacombRestoreStage::LockState,
    )?;
    if parse_sks_lock_state(&lock_response)? & CATACOMB_CORRUPTED != 0 {
        return Err(CatacombRestoreError::CorruptedCatacomb);
    }

    Ok(RestoredCatacomb {
        identities,
        already_loaded: false,
    })
}

fn execute<T: BiometricTransport>(
    transport: &mut T,
    packet: &CommandPacket,
    stage: CatacombRestoreStage,
) -> Result<Vec<u8>, CatacombRestoreError<T::Error>> {
    transport
        .execute(packet)
        .map_err(|error| CatacombRestoreError::Transport { stage, error })
}

fn execute_empty<T: BiometricTransport>(
    transport: &mut T,
    packet: &CommandPacket,
    stage: CatacombRestoreStage,
) -> Result<(), CatacombRestoreError<T::Error>> {
    let response = execute(transport, packet, stage)?;
    validate_empty_response(&response).map_err(CatacombRestoreError::Command)
}

fn read_catacomb_states<T: BiometricTransport>(
    transport: &mut T,
    stage: CatacombRestoreStage,
) -> Result<Vec<CatacombStateEntry>, CatacombRestoreError<T::Error>> {
    let daemon_response = execute(transport, &daemon_info_command(), stage)?;
    let daemon = parse_daemon_info(&daemon_response)?;
    let packet = catacomb_states_command(daemon.component_count)?;
    let response = execute(transport, &packet, stage)?;
    parse_catacomb_states(&response, daemon.component_count).map_err(CatacombRestoreError::Catacomb)
}

fn read_identities<T: BiometricTransport>(
    transport: &mut T,
    user_id: BiometricUserId,
    stage: CatacombRestoreStage,
) -> Result<Vec<Identity>, CatacombRestoreError<T::Error>> {
    let mut response = execute(transport, &identities_command(user_id), stage)?;
    let parsed = (|| {
        validate_identity_list_response(&response)?;
        response
            .as_chunks::<IDENTITY_V1_SIZE>()
            .0
            .iter()
            .map(|identity| parse_identity(identity))
            .collect::<Result<Vec<_>, _>>()
            .map_err(CatacombRestoreError::Mesa)
    })();
    secret::wipe(&mut response);
    parsed
}

fn ensure_identity_user(identities: &[Identity], user_id: BiometricUserId) -> Result<(), ()> {
    let expected = i32::try_from(user_id.as_raw()).map_err(|_| ())?;
    if identities
        .iter()
        .any(|identity| identity.user_id() != expected)
    {
        return Err(());
    }
    Ok(())
}

fn state_for(states: &[CatacombStateEntry], user_id: u32) -> Option<u32> {
    states
        .iter()
        .rev()
        .find(|entry| entry.user_id == user_id)
        .map(|entry| entry.state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use t1_bridge::biometric::{COMMAND_HEADER_SIZE, DAEMON_INFO_SIZE};
    use t1_bridge::calibration::MODULE_SERIAL_NUMBER_SIZE;

    const USER: u32 = 42;
    const OTHER_USER: u32 = 43;
    const MODULE_SERIAL: &[u8; MODULE_SERIAL_NUMBER_SIZE] = b"TESTMODULE00000001";
    const USER_BLOB: &[u8] = b"synthetic encrypted user blob";
    const MASTER_BLOB: &[u8] = b"synthetic encrypted master blob";

    static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct SyntheticError;

    impl fmt::Display for SyntheticError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("sensitive synthetic transport detail")
        }
    }

    impl std::error::Error for SyntheticError {}

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct Observation {
        code: u16,
        payload_len: usize,
        response_capacity: usize,
        payload_prefix: Option<u32>,
    }

    struct FakeTransport {
        responses: VecDeque<Result<Vec<u8>, SyntheticError>>,
        commands: Vec<Observation>,
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
            let payload = &request[COMMAND_HEADER_SIZE..];
            self.commands.push(Observation {
                code: u16::from_le_bytes(request[2..4].try_into().unwrap()),
                payload_len: payload.len(),
                response_capacity: packet.response_capacity(),
                payload_prefix: payload
                    .get(..4)
                    .map(|bytes| u32::from_le_bytes(bytes.try_into().unwrap())),
            });
            self.responses.pop_front().expect("synthetic response")
        }
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "t1bridge-catacomb-restore-test-{}-{sequence}",
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

    fn store(directory: &TestDirectory) -> CatacombPairStore {
        let store = CatacombPairStore::new(directory.0.join("store"));
        store.commit(USER_BLOB, MASTER_BLOB).unwrap();
        store
    }

    fn pending_store(directory: &TestDirectory) -> CatacombPairStore {
        let store = CatacombPairStore::new(directory.0.join("store"));
        {
            let mut transaction = store.begin_transaction().unwrap();
            transaction.reserve_recovery().unwrap();
            transaction.write_user(USER_BLOB).unwrap();
            transaction.write_master(MASTER_BLOB).unwrap();
        }
        store
    }

    fn daemon_info(component_count: u32) -> Vec<u8> {
        let mut response = vec![0; DAEMON_INFO_SIZE];
        response[..4].copy_from_slice(&component_count.to_le_bytes());
        response
    }

    fn states(entries: &[(u32, u32)]) -> Vec<u8> {
        entries
            .iter()
            .flat_map(|(user_id, state)| {
                user_id.to_le_bytes().into_iter().chain(state.to_le_bytes())
            })
            .collect()
    }

    fn identity(user_id: u32, marker: u8) -> Vec<u8> {
        let mut identity = vec![marker; IDENTITY_V1_SIZE];
        identity[..4].copy_from_slice(&user_id.to_le_bytes());
        identity
    }

    fn successful_responses() -> Vec<Vec<u8>> {
        vec![
            Vec::new(),
            Vec::new(),
            daemon_info(2),
            Vec::new(),
            Vec::new(),
            daemon_info(2),
            states(&[(u32::MAX, 1)]),
            Vec::new(),
            daemon_info(2),
            states(&[(u32::MAX, 1), (USER, 3)]),
            [identity(USER, 0x21), identity(USER, 0x42)].concat(),
            0_u32.to_le_bytes().to_vec(),
        ]
    }

    fn forced_restore_responses() -> Vec<Vec<u8>> {
        successful_responses().into_iter().skip(1).collect()
    }

    fn previously_loaded_master_responses() -> Vec<Vec<u8>> {
        vec![
            Vec::new(),
            Vec::new(),
            daemon_info(1),
            states(&[(u32::MAX, 3)]),
            Vec::new(),
            daemon_info(1),
            states(&[(u32::MAX, 3)]),
            Vec::new(),
            daemon_info(2),
            states(&[(u32::MAX, 3), (USER, 3)]),
            identity(USER, 0x21),
            0_u32.to_le_bytes().to_vec(),
        ]
    }

    fn recovery_responses() -> Vec<Vec<u8>> {
        let mut responses = vec![
            MODULE_SERIAL.to_vec(),
            calibrated_daemon_info(),
            calibrated_daemon_info(),
        ];
        responses.extend(forced_restore_responses());
        responses
    }

    fn calibrated_daemon_info() -> Vec<u8> {
        let mut response = daemon_info(0);
        response[22] = 1;
        response
    }

    #[test]
    fn restores_master_then_user_and_validates_final_state() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        let mut transport = FakeTransport::new(successful_responses());

        let restored = restore_catacomb_pair(&mut transport, &store, user()).unwrap();

        assert_eq!(restored.identity_count(), 2);
        assert!(!restored.already_loaded());
        let rendered = format!("{restored:?}");
        assert!(rendered.contains("identity_count: 2"));
        assert!(rendered.contains("[redacted]"));
        assert!(!rendered.contains("!\"#$"));
        assert_eq!(
            transport
                .commands
                .iter()
                .map(|observation| observation.code)
                .collect::<Vec<_>>(),
            [
                0x42, 0x31, 0x28, 0x3c, 0x40, 0x28, 0x3c, 0x40, 0x28, 0x3c, 0x42, 0x27
            ]
        );
        assert_eq!(transport.commands[1].payload_prefix, Some(u32::MAX));
        assert_eq!(
            transport.commands[4].payload_prefix,
            Some(u32::from_le_bytes(MASTER_BLOB[..4].try_into().unwrap()))
        );
        assert_eq!(
            transport.commands[7].payload_prefix,
            Some(u32::from_le_bytes(USER_BLOB[..4].try_into().unwrap()))
        );
        assert_eq!(transport.commands[4].payload_len, MASTER_BLOB.len());
        assert_eq!(transport.commands[7].payload_len, USER_BLOB.len());
    }

    #[test]
    fn valid_live_identities_short_circuit_without_mutation() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        let mut transport = FakeTransport::new([identity(USER, 0x31)]);

        let restored = restore_catacomb_pair(&mut transport, &store, user()).unwrap();

        assert!(restored.already_loaded());
        assert_eq!(restored.identity_count(), 1);
        assert_eq!(transport.commands.len(), 1);
        assert_eq!(transport.commands[0].code, 0x42);
    }

    #[test]
    fn ordinary_restore_reloads_master_even_when_state_reports_loaded() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        let mut transport = FakeTransport::new(previously_loaded_master_responses());

        let restored = restore_catacomb_pair(&mut transport, &store, user()).unwrap();

        assert!(!restored.already_loaded());
        assert_eq!(restored.identity_count(), 1);
        assert_eq!(
            transport
                .commands
                .iter()
                .map(|observation| observation.code)
                .collect::<Vec<_>>(),
            [
                0x42, 0x31, 0x28, 0x3c, 0x40, 0x28, 0x3c, 0x40, 0x28, 0x3c, 0x42, 0x27
            ]
        );
        assert_eq!(
            transport.commands[4].payload_prefix,
            Some(u32::from_le_bytes(MASTER_BLOB[..4].try_into().unwrap()))
        );
        assert_eq!(transport.commands[4].payload_len, MASTER_BLOB.len());
        assert_eq!(
            transport.commands[7].payload_prefix,
            Some(u32::from_le_bytes(USER_BLOB[..4].try_into().unwrap()))
        );
        assert_eq!(transport.commands[7].payload_len, USER_BLOB.len());
    }

    #[test]
    fn recovery_forces_master_first_validation_and_promotes_only_after_success() {
        let directory = TestDirectory::new();
        let store = pending_store(&directory);
        let mut responses = recovery_responses();
        responses[5] = states(&[(u32::MAX, 3)]);
        let mut transport = FakeTransport::new(responses);

        assert_eq!(
            recover_ambiguous_pair(&mut transport, &store, user(), &fdr_record()).unwrap(),
            CatacombRecoveryOutcome::Promoted
        );
        assert_eq!(store.load().unwrap().user(), USER_BLOB);
        assert_eq!(transport.commands.first().unwrap().code, 0x22);
        assert_eq!(transport.commands[3].code, 0x31);
        assert_eq!(transport.commands[6].code, 0x40);
        assert_eq!(transport.commands[9].code, 0x40);
        assert!(store.begin_transaction().is_ok());
    }

    #[test]
    fn clean_or_incomplete_recovery_state_never_touches_hardware() {
        let clean_directory = TestDirectory::new();
        let clean = store(&clean_directory);
        let mut transport = FakeTransport::new([]);
        assert_eq!(
            recover_ambiguous_pair(&mut transport, &clean, user(), &fdr_record()).unwrap(),
            CatacombRecoveryOutcome::Clean
        );
        assert!(transport.commands.is_empty());

        let incomplete_directory = TestDirectory::new();
        let incomplete = CatacombPairStore::new(incomplete_directory.0.join("store"));
        {
            let mut transaction = incomplete.begin_transaction().unwrap();
            transaction.reserve_recovery().unwrap();
            transaction.write_user(USER_BLOB).unwrap();
        }
        assert_eq!(
            recover_ambiguous_pair(&mut transport, &incomplete, user(), &fdr_record()).unwrap(),
            CatacombRecoveryOutcome::Quarantined
        );
        assert!(transport.commands.is_empty());
        assert!(matches!(
            incomplete.begin_transaction(),
            Err(CatacombStoreError::PendingExport)
        ));
    }

    #[test]
    fn definitive_rejection_quarantines_but_unverifiable_failure_is_returned() {
        let rejected_directory = TestDirectory::new();
        let rejected = pending_store(&rejected_directory);
        let mut responses = recovery_responses();
        responses[12] = Vec::new();
        responses.truncate(13);
        let mut transport = FakeTransport::new(responses);
        assert_eq!(
            recover_ambiguous_pair(&mut transport, &rejected, user(), &fdr_record()).unwrap(),
            CatacombRecoveryOutcome::Quarantined
        );
        assert!(matches!(
            rejected.begin_transaction(),
            Err(CatacombStoreError::PendingExport)
        ));

        let unavailable_directory = TestDirectory::new();
        let unavailable = pending_store(&unavailable_directory);
        let mut transport = FakeTransport {
            responses: VecDeque::from([Err(SyntheticError)]),
            commands: Vec::new(),
        };
        let error = recover_ambiguous_pair(&mut transport, &unavailable, user(), &fdr_record())
            .unwrap_err();
        assert!(matches!(
            error,
            CatacombRecoveryError::Validator(CatacombRestoreError::Calibration(
                ControlError::Transport(SyntheticError)
            ))
        ));
        assert!(matches!(
            unavailable.begin_transaction(),
            Err(CatacombStoreError::PendingExport)
        ));
    }

    #[test]
    fn cross_user_live_identity_fails_before_mutation() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        let mut transport = FakeTransport::new([identity(OTHER_USER, 0x31)]);

        assert!(matches!(
            restore_catacomb_pair(&mut transport, &store, user()),
            Err(CatacombRestoreError::LiveIdentityForAnotherUser)
        ));
        assert_eq!(transport.commands.len(), 1);
    }

    #[test]
    fn storage_is_validated_before_hardware() {
        let directory = TestDirectory::new();
        let store = CatacombPairStore::new(directory.0.join("missing"));
        let mut transport = FakeTransport::new([]);

        assert!(matches!(
            restore_catacomb_pair(&mut transport, &store, user()),
            Err(CatacombRestoreError::Store(CatacombStoreError::MissingPair))
        ));
        assert!(transport.commands.is_empty());
    }

    #[test]
    fn missing_master_state_stops_before_user_load() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        let mut transport = FakeTransport::new([
            Vec::new(),
            Vec::new(),
            daemon_info(1),
            Vec::new(),
            Vec::new(),
            daemon_info(1),
            states(&[(USER, 3)]),
        ]);

        assert!(matches!(
            restore_catacomb_pair(&mut transport, &store, user()),
            Err(CatacombRestoreError::MasterNotLoaded { state: None })
        ));
        assert_eq!(
            transport
                .commands
                .iter()
                .map(|observation| observation.code)
                .collect::<Vec<_>>(),
            [0x42, 0x31, 0x28, 0x3c, 0x40, 0x28, 0x3c]
        );
    }

    #[test]
    fn insecure_user_state_stops_before_identity_validation() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        let mut responses = successful_responses();
        responses[9] = states(&[(u32::MAX, 1), (USER, 1)]);
        responses.truncate(10);
        let mut transport = FakeTransport::new(responses);

        assert!(matches!(
            restore_catacomb_pair(&mut transport, &store, user()),
            Err(CatacombRestoreError::UserNotSecurelyLoaded { state: Some(1) })
        ));
        assert_eq!(transport.commands.last().unwrap().code, 0x3c);
    }

    #[test]
    fn empty_and_cross_user_final_identities_are_rejected() {
        for (identities, expected_cross_user) in
            [(Vec::new(), false), (identity(OTHER_USER, 0x72), true)]
        {
            let directory = TestDirectory::new();
            let store = store(&directory);
            let mut responses = successful_responses();
            responses[10] = identities;
            responses.truncate(11);
            let mut transport = FakeTransport::new(responses);

            let error = restore_catacomb_pair(&mut transport, &store, user()).unwrap_err();
            assert_eq!(
                matches!(&error, CatacombRestoreError::RestoredIdentityForAnotherUser),
                expected_cross_user
            );
            assert_eq!(
                matches!(&error, CatacombRestoreError::NoEnrolledFingerprints),
                !expected_cross_user
            );
        }
    }

    #[cfg(feature = "auth-broker-service")]
    #[test]
    fn enrollment_restore_accepts_valid_empty_identity_catalog() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        let mut responses = successful_responses();
        responses[10] = Vec::new();
        let mut transport = FakeTransport::new(responses);

        let restored =
            restore_catacomb_pair_for_enrollment(&mut transport, &store, user()).unwrap();

        assert_eq!(restored.identity_count(), 0);
        assert!(!restored.already_loaded());
        assert_eq!(transport.commands.last().unwrap().code, 0x27);
    }

    #[test]
    fn corrupted_lock_state_fails_after_final_identity_validation() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        let mut responses = successful_responses();
        responses[11] = CATACOMB_CORRUPTED.to_le_bytes().to_vec();
        let mut transport = FakeTransport::new(responses);

        assert!(matches!(
            restore_catacomb_pair(&mut transport, &store, user()),
            Err(CatacombRestoreError::CorruptedCatacomb)
        ));
        assert_eq!(transport.commands.last().unwrap().code, 0x27);
    }

    #[test]
    fn transport_error_and_result_debug_redact_sensitive_values() {
        let directory = TestDirectory::new();
        let store = store(&directory);
        let mut transport = FakeTransport {
            responses: VecDeque::from([Err(SyntheticError)]),
            commands: Vec::new(),
        };

        let error = restore_catacomb_pair(&mut transport, &store, user()).unwrap_err();
        assert_eq!(
            format!("{error:?} {error}"),
            "Transport { stage: LiveIdentities, error: \"[redacted]\" } biometric transport failed during live identity read"
        );
        assert!(!format!("{error:?}").contains("sensitive"));
        assert!(std::error::Error::source(&error).is_none());

        let mut responses = successful_responses()
            .into_iter()
            .map(Ok)
            .collect::<VecDeque<_>>();
        responses[4] = Err(SyntheticError);
        let mut transport = FakeTransport {
            responses,
            commands: Vec::new(),
        };
        assert!(matches!(
            restore_catacomb_pair(&mut transport, &store, user()),
            Err(CatacombRestoreError::Transport {
                stage: CatacombRestoreStage::LoadMaster,
                ..
            })
        ));
    }

    fn fdr_record() -> Vec<u8> {
        let mut calibration = vec![0; 96];
        let calibration_size = u32::try_from(calibration.len()).unwrap();
        calibration[4..8].copy_from_slice(&calibration_size.to_le_bytes());
        calibration[16..20].copy_from_slice(b"CALB");
        calibration[32..32 + MODULE_SERIAL.len()].copy_from_slice(MODULE_SERIAL);
        der(
            0x30,
            &[
                der(0x16, b"comb"),
                der(
                    0x30,
                    &[der(0x16, b"fdrd"), der(0x04, &img4(&calibration))].concat(),
                ),
            ]
            .concat(),
        )
    }

    fn img4(calibration: &[u8]) -> Vec<u8> {
        der(
            0x30,
            &[
                der(0x16, b"IMG4"),
                der(
                    0x30,
                    &[
                        der(0x16, b"IM4P"),
                        der(0x16, b"FSCl"),
                        der(0x16, b"1.0"),
                        der(0x04, calibration),
                    ]
                    .concat(),
                ),
            ]
            .concat(),
        )
    }

    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut encoded = vec![tag];
        if content.len() < 128 {
            encoded.push(u8::try_from(content.len()).unwrap());
        } else {
            encoded.push(0x81);
            encoded.push(u8::try_from(content.len()).unwrap());
        }
        encoded.extend_from_slice(content);
        encoded
    }
}

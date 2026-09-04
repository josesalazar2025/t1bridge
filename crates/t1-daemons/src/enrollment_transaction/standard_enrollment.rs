//! Standard-labeled enrollment with generation-atomic identity metadata.

use core::fmt;

use t1_bridge::control::{BiometricTransport, ControlError, ensure_fdr_calibration_loaded};
use t1_bridge::enroll_workflow::{
    EnrollmentError, EnrollmentEventSource, EnrollmentOutcome, EnrollmentProgress, run_enrollment,
};
use t1_bridge::match_workflow::{IdentityMatchOutcome, MatchWorkflowError};
use t1_bridge::mesa::Identity;
use t1_bridge::policy::{BiometricUserId, SystemPolicyTarget};
use t1_bridge::policy_workflow::{
    PolicyWorkflowError, SystemPolicyWorkflowError, UserPolicyRetryRuntime, enable_system_touch_id,
    enable_user_touch_id,
};
use t1_bridge::user_workflow::{
    UserWorkflowError, list_user_identities, prepare_user, read_catacomb_states, rebind_empty_user,
};

use crate::auth_operation::{
    AuthenticationOperationError, restore_user_for_enrollment_after_calibration,
};
use crate::catacomb_restore::{CatacombRestoreError, recover_ambiguous_pair};
use crate::catacomb_session::{
    CatacombBackup, CatacombSessionError, backup_catacomb_pair_with_transaction_and_metadata,
};
use crate::catacomb_store::{
    CatacombPairStore, CatacombPairTransaction, CatacombRecoveryError, CatacombRecoveryOutcome,
    CatacombStoreError,
};
use crate::identity_metadata::{IdentityMetadata, MetadataError, decode as decode_metadata};
use crate::standard_fingerprint_protocol::{
    EnrollProgress, FingerLabel, IdentityId, MAX_OWNER_IDENTITIES, Username,
};
use crate::standard_identity_catalog::{CatalogError, StandardIdentityCatalog};

const SECURELY_LOADED_STATE_BITS: u32 = 3;
const RAW_PROGRESS_MIN: u64 = 0x64;
const RAW_PROGRESS_MAX: u64 = 0x163;
const STANDARD_PROGRESS_TOTAL: u8 = 100;

/// Standard enrollment preparation reserved under the fixed external lock.
pub(crate) struct PreparedStandardEnrollment<'store> {
    pub transaction: CatacombPairTransaction<'store>,
    pub committed_metadata: Option<IdentityMetadata>,
    pub active_pair: Option<&'store CatacombPairStore>,
}

/// Redacted recovery, storage, metadata, or calibration preparation failure.
pub(crate) enum StandardEnrollmentPreparationError<TransportError> {
    Recovery(CatacombRecoveryError<CatacombRestoreError<TransportError>>),
    RecoveryBlocked,
    Store(CatacombStoreError),
    Metadata(MetadataError),
    Calibration(ControlError<TransportError>),
}

impl<TransportError> fmt::Debug for StandardEnrollmentPreparationError<TransportError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Recovery(_) => "Recovery([redacted])",
            Self::RecoveryBlocked => "RecoveryBlocked",
            Self::Store(_) => "Store([redacted])",
            Self::Metadata(_) => "Metadata([redacted])",
            Self::Calibration(_) => "Calibration([redacted])",
        })
    }
}

/// Recovers the selected generation, loads its optional standard metadata,
/// reserves the next generation, and makes FDR calibration live. The returned
/// active-pair reference is restored only after the caller acquires ACM.
pub(crate) fn prepare_standard_enrollment<'store, Transport>(
    transport: &mut Transport,
    store: &'store CatacombPairStore,
    user_id: BiometricUserId,
    fdr_record: &[u8],
) -> Result<PreparedStandardEnrollment<'store>, StandardEnrollmentPreparationError<Transport::Error>>
where
    Transport: BiometricTransport,
{
    match recover_ambiguous_pair(transport, store, user_id, fdr_record)
        .map_err(StandardEnrollmentPreparationError::Recovery)?
    {
        CatacombRecoveryOutcome::Clean | CatacombRecoveryOutcome::Promoted => {}
        CatacombRecoveryOutcome::Quarantined => {
            return Err(StandardEnrollmentPreparationError::RecoveryBlocked);
        }
    }
    let (committed_metadata, has_active_pair) = match store.load() {
        Ok(pair) => (
            pair.metadata()
                .map(decode_metadata)
                .transpose()
                .map_err(StandardEnrollmentPreparationError::Metadata)?,
            true,
        ),
        Err(CatacombStoreError::MissingPair) => (None, false),
        Err(error) => return Err(StandardEnrollmentPreparationError::Store(error)),
    };
    let transaction = store
        .begin_transaction()
        .map_err(StandardEnrollmentPreparationError::Store)?;
    ensure_fdr_calibration_loaded(transport, fdr_record)
        .map_err(StandardEnrollmentPreparationError::Calibration)?;
    Ok(PreparedStandardEnrollment {
        transaction,
        committed_metadata,
        active_pair: has_active_pair.then_some(store),
    })
}

/// Successful standard enrollment and its durable catacomb generation.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct StandardEnrollmentSuccess {
    pub identity: IdentityId,
    pub catacombs: CatacombBackup,
}

impl fmt::Debug for StandardEnrollmentSuccess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StandardEnrollmentSuccess")
            .field("identity", &"[redacted]")
            .field("catacombs", &self.catacombs)
            .finish()
    }
}

/// Payload-free failure inside one standard enrollment transaction.
pub(crate) enum StandardEnrollmentError<TransportError, WaitError, EventError> {
    Restore(AuthenticationOperationError<TransportError, WaitError, EventError>),
    User(UserWorkflowError<TransportError>),
    CatacombNotSecurelyLoaded,
    IdentityCapacityReached,
    Catalog(CatalogError),
    DuplicateCheck(MatchWorkflowError<TransportError, EventError>),
    DuplicateIdentity,
    InvalidIdentity,
    SystemPolicy(SystemPolicyWorkflowError<TransportError>),
    UserPolicy(PolicyWorkflowError<TransportError, WaitError>),
    Enrollment(EnrollmentError<TransportError, EventError>),
    EnrollmentTimedOut,
    EnrollmentCancelled,
    Persistence(CatacombSessionError<TransportError>),
    PostCommitIdentityVerification(UserWorkflowError<TransportError>),
    PostCommitIdentitySetChanged,
}

impl<TransportError, WaitError, EventError> fmt::Debug
    for StandardEnrollmentError<TransportError, WaitError, EventError>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Restore(_) => "Restore([redacted])",
            Self::User(_) => "User([redacted])",
            Self::CatacombNotSecurelyLoaded => "CatacombNotSecurelyLoaded",
            Self::IdentityCapacityReached => "IdentityCapacityReached",
            Self::Catalog(_) => "Catalog([redacted])",
            Self::DuplicateCheck(_) => "DuplicateCheck([redacted])",
            Self::DuplicateIdentity => "DuplicateIdentity",
            Self::InvalidIdentity => "InvalidIdentity",
            Self::SystemPolicy(_) => "SystemPolicy([redacted])",
            Self::UserPolicy(_) => "UserPolicy([redacted])",
            Self::Enrollment(_) => "Enrollment([redacted])",
            Self::EnrollmentTimedOut => "EnrollmentTimedOut",
            Self::EnrollmentCancelled => "EnrollmentCancelled",
            Self::Persistence(_) => "Persistence([redacted])",
            Self::PostCommitIdentityVerification(_) => "PostCommitIdentityVerification([redacted])",
            Self::PostCommitIdentitySetChanged => "PostCommitIdentitySetChanged",
        })
    }
}

impl<TransportError, WaitError, EventError> fmt::Display
    for StandardEnrollmentError<TransportError, WaitError, EventError>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Restore(_) => "standard enrollment durable restore failed",
            Self::User(_) => "standard enrollment user preparation failed",
            Self::CatacombNotSecurelyLoaded => {
                "standard enrollment user catacomb is not securely loaded"
            }
            Self::IdentityCapacityReached => "standard enrollment identity capacity was reached",
            Self::Catalog(_) => "standard enrollment identity catalog is invalid",
            Self::DuplicateCheck(_) => "standard enrollment duplicate check failed",
            Self::DuplicateIdentity => "fingerprint is already enrolled",
            Self::InvalidIdentity => "standard enrollment returned an invalid identity",
            Self::SystemPolicy(_) => "standard enrollment system policy failed",
            Self::UserPolicy(_) => "standard enrollment user policy failed",
            Self::Enrollment(_) => "Mesa standard enrollment failed",
            Self::EnrollmentTimedOut => "Mesa standard enrollment timed out",
            Self::EnrollmentCancelled => "Mesa standard enrollment was cancelled",
            Self::Persistence(_) => "standard enrollment persistence failed",
            Self::PostCommitIdentityVerification(_) => {
                "standard enrollment post-commit identity read failed"
            }
            Self::PostCommitIdentitySetChanged => {
                "standard enrollment identity set changed during persistence"
            }
        })
    }
}

impl<TransportError, WaitError, EventError> std::error::Error
    for StandardEnrollmentError<TransportError, WaitError, EventError>
{
}

/// Enrolls and labels exactly Mesa's newly returned identity.
///
/// The complete pre-enrollment Mesa identity set is reconciled with optional
/// committed metadata before mutation. Missing metadata imports those existing
/// identities only as hidden legacy anchors. The next complete manifest is
/// promoted atomically with the catacomb pair, then the physical identity set
/// is read again and must equal the exact pre-state plus the returned ID.
///
/// # Errors
///
/// Returns a payload-free preparation, catalog, policy, enrollment,
/// persistence, cancellation, or exact postcondition failure.
#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub(crate) fn run_reserved_standard_enrollment<Transport, Retry, Events, DuplicateCheck>(
    transport: &mut Transport,
    retry_runtime: &mut Retry,
    events: &mut Events,
    transaction: CatacombPairTransaction<'_>,
    user_id: BiometricUserId,
    owner: Username,
    finger: FingerLabel,
    committed_metadata: Option<IdentityMetadata>,
    active_pair: Option<&CatacombPairStore>,
    credential: &[u8],
    mut progress: Option<&mut dyn FnMut(EnrollProgress)>,
    duplicate_check: &mut DuplicateCheck,
    before_start: &mut dyn FnMut(),
    mesa_completed: &mut dyn FnMut() -> bool,
) -> Result<
    StandardEnrollmentSuccess,
    StandardEnrollmentError<Transport::Error, Retry::WaitError, Events::Error>,
>
where
    Transport: BiometricTransport,
    Retry: UserPolicyRetryRuntime<Transport::Error>,
    Events: EnrollmentEventSource,
    DuplicateCheck:
        FnMut(
            &mut Transport,
            &mut Events,
            BiometricUserId,
            &[Identity],
        )
            -> Result<IdentityMatchOutcome, MatchWorkflowError<Transport::Error, Events::Error>>,
{
    let identities = prepare_standard_enrollment_user::<_, _, Events::Error>(
        transport,
        retry_runtime,
        user_id,
        active_pair,
        credential,
    )?;
    if identities.len() >= usize::from(MAX_OWNER_IDENTITIES) {
        return Err(StandardEnrollmentError::IdentityCapacityReached);
    }

    let before = identity_ids(&identities)?;
    let mut catalog = StandardIdentityCatalog::reconcile(committed_metadata, owner, &before)
        .map_err(StandardEnrollmentError::Catalog)?;

    enable_system_touch_id(
        transport,
        SystemPolicyTarget::TouchIdFeatures,
        Some(credential),
    )
    .map_err(StandardEnrollmentError::SystemPolicy)?;
    enable_user_touch_id(
        transport,
        retry_runtime,
        i64::from(user_id.as_raw()),
        Some(credential),
    )
    .map_err(StandardEnrollmentError::UserPolicy)?;

    before_start();
    if !identities.is_empty() {
        match duplicate_check(transport, events, user_id, &identities)
            .map_err(StandardEnrollmentError::DuplicateCheck)?
        {
            IdentityMatchOutcome::Matched(_) => {
                return Err(StandardEnrollmentError::DuplicateIdentity);
            }
            IdentityMatchOutcome::NoMatch => {}
            IdentityMatchOutcome::Cancelled => {
                return Err(StandardEnrollmentError::EnrollmentCancelled);
            }
            IdentityMatchOutcome::TimedOut => {
                return Err(StandardEnrollmentError::EnrollmentTimedOut);
            }
        }
    }
    let mut normalizer = StandardProgressNormalizer::default();
    let mut report_progress = |raw| {
        if let Some(normalized) = normalizer.normalize(raw)
            && let Some(callback) = progress.as_deref_mut()
        {
            callback(normalized);
        }
    };
    let outcome = run_enrollment(
        transport,
        events,
        i64::from(user_id.as_raw()),
        Some(credential),
        Some(&mut report_progress),
    )
    .map_err(StandardEnrollmentError::Enrollment)?;
    let EnrollmentOutcome::Completed(identity) = outcome else {
        return Err(StandardEnrollmentError::EnrollmentTimedOut);
    };
    if !mesa_completed() {
        return Err(StandardEnrollmentError::EnrollmentCancelled);
    }

    let identity =
        IdentityId::new(identity).map_err(|_| StandardEnrollmentError::InvalidIdentity)?;
    catalog
        .add_labeled(identity, finger)
        .map_err(StandardEnrollmentError::Catalog)?;
    let metadata = catalog
        .encode_next_manifest()
        .map_err(StandardEnrollmentError::Catalog)?;
    let mut expected = before;
    expected.push(identity);

    let catacombs = backup_catacomb_pair_with_transaction_and_metadata(
        transport,
        transaction,
        user_id,
        &metadata,
    )
    .map_err(StandardEnrollmentError::Persistence)?;
    let committed = list_user_identities(transport, user_id)
        .map_err(StandardEnrollmentError::PostCommitIdentityVerification)?;
    let committed = identity_ids(&committed)?;
    if !same_identity_set(&expected, &committed) || !committed.contains(&identity) {
        return Err(StandardEnrollmentError::PostCommitIdentitySetChanged);
    }

    Ok(StandardEnrollmentSuccess {
        identity,
        catacombs,
    })
}

fn prepare_standard_enrollment_user<Transport, Retry, EventError>(
    transport: &mut Transport,
    retry_runtime: &mut Retry,
    user_id: BiometricUserId,
    active_pair: Option<&CatacombPairStore>,
    credential: &[u8],
) -> Result<Vec<Identity>, StandardEnrollmentError<Transport::Error, Retry::WaitError, EventError>>
where
    Transport: BiometricTransport,
    Retry: UserPolicyRetryRuntime<Transport::Error>,
{
    if let Some(store) = active_pair {
        return restore_user_for_enrollment_after_calibration::<_, _, EventError>(
            transport,
            retry_runtime,
            user_id,
            Some(store),
            Some(credential),
        )
        .map_err(StandardEnrollmentError::Restore);
    }

    let mut identities = prepare_user(transport, user_id).map_err(StandardEnrollmentError::User)?;
    let mut states = read_catacomb_states(transport).map_err(StandardEnrollmentError::User)?;
    if !catacomb_is_secure(&states, user_id) {
        identities =
            rebind_empty_user(transport, user_id).map_err(StandardEnrollmentError::User)?;
        states = read_catacomb_states(transport).map_err(StandardEnrollmentError::User)?;
    }
    if !catacomb_is_secure(&states, user_id) {
        return Err(StandardEnrollmentError::CatacombNotSecurelyLoaded);
    }
    Ok(identities)
}

fn identity_ids<TransportError, WaitError, EventError>(
    identities: &[t1_bridge::mesa::Identity],
) -> Result<Vec<IdentityId>, StandardEnrollmentError<TransportError, WaitError, EventError>> {
    identities
        .iter()
        .map(|identity| {
            IdentityId::new(identity.identifier())
                .map_err(|_| StandardEnrollmentError::InvalidIdentity)
        })
        .collect()
}

fn same_identity_set(expected: &[IdentityId], actual: &[IdentityId]) -> bool {
    expected.len() == actual.len()
        && expected.iter().all(|identity| {
            actual
                .iter()
                .filter(|candidate| *candidate == identity)
                .count()
                == 1
        })
}

fn catacomb_is_secure(
    states: &[t1_bridge::catacomb::CatacombStateEntry],
    user_id: BiometricUserId,
) -> bool {
    states.iter().any(|entry| {
        entry.user_id == user_id.as_raw()
            && entry.state & SECURELY_LOADED_STATE_BITS == SECURELY_LOADED_STATE_BITS
    })
}

#[derive(Default)]
struct StandardProgressNormalizer {
    last: Option<u8>,
}

impl StandardProgressNormalizer {
    fn normalize(&mut self, raw: EnrollmentProgress) -> Option<EnrollProgress> {
        let raw = raw.value();
        if !(RAW_PROGRESS_MIN..=RAW_PROGRESS_MAX).contains(&raw) {
            return None;
        }
        let range = RAW_PROGRESS_MAX - RAW_PROGRESS_MIN;
        let completed = (raw - RAW_PROGRESS_MIN) * u64::from(STANDARD_PROGRESS_TOTAL) / range;
        let completed = u8::try_from(completed).ok()?;
        if completed == 0 || self.last == Some(completed) {
            return None;
        }
        self.last = Some(completed);
        EnrollProgress::new(completed, STANDARD_PROGRESS_TOTAL).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use t1_bridge::biometric::DAEMON_INFO_SIZE;
    use t1_bridge::calibration::MODULE_SERIAL_NUMBER_SIZE;
    use t1_bridge::commands::CommandPacket;
    use t1_bridge::enroll_workflow::{EnrollmentEvent, EnrollmentEventSource};
    use t1_bridge::mesa::{
        IDENTITY_V1_SIZE, MESA_ENROLLMENT_COMPLETE, MESA_ENROLLMENT_STATUS,
        MESA_MESSAGE_HEADER_SIZE, MESA_MESSAGE_TYPE_V1, MESA_SERVICE_MESSAGE, ServiceStatusEvent,
    };

    use crate::catacomb_store::CatacombPairStore;
    use crate::identity_metadata::{IdentityMetadataEntry, decode as decode_metadata};

    const USER: i32 = 501;
    const LEGACY: [u8; 16] = [0x11; 16];
    const NEW: [u8; 16] = [0x22; 16];
    const COLLATERAL: [u8; 16] = [0x33; 16];
    const EXISTING_LABELED: [u8; 16] = [0x44; 16];
    const CREDENTIAL: [u8; 16] = [0x5a; 16];
    const MODULE_SERIAL: &[u8; MODULE_SERIAL_NUMBER_SIZE] = b"SYNTHETICMODULE001";
    const USER_BLOB: &[u8] = b"synthetic encrypted legacy user";
    const MASTER_BLOB: &[u8] = b"synthetic encrypted legacy master";
    static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct SyntheticError;

    impl fmt::Display for SyntheticError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("private synthetic detail")
        }
    }

    impl std::error::Error for SyntheticError {}

    struct NoRetry;

    impl UserPolicyRetryRuntime<SyntheticError> for NoRetry {
        type WaitError = SyntheticError;

        fn native_status(&self, _error: &SyntheticError) -> Option<i64> {
            None
        }

        fn wait(&mut self, _delay: core::time::Duration) -> Result<(), Self::WaitError> {
            panic!("synthetic policy does not retry")
        }
    }

    struct FakeTransport {
        responses: VecDeque<Result<Vec<u8>, SyntheticError>>,
        commands: Vec<u16>,
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
            self.commands.push(u16::from_le_bytes(
                packet.request()[2..4].try_into().expect("command code"),
            ));
            self.responses
                .pop_front()
                .expect("synthetic response for every command")
        }
    }

    struct FakeEvents {
        events: VecDeque<Result<EnrollmentEvent, SyntheticError>>,
    }

    impl FakeEvents {
        fn new(events: impl IntoIterator<Item = EnrollmentEvent>) -> Self {
            Self {
                events: events.into_iter().map(Ok).collect(),
            }
        }
    }

    impl EnrollmentEventSource for FakeEvents {
        type Error = SyntheticError;

        fn next_event(&mut self) -> Result<EnrollmentEvent, Self::Error> {
            self.events.pop_front().expect("synthetic enrollment event")
        }
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "t1bridge-standard-enrollment-test-{}-{sequence}",
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

    fn owner() -> Username {
        Username::new("synthetic-owner").unwrap()
    }

    fn id(value: [u8; 16]) -> IdentityId {
        IdentityId::new(value).unwrap()
    }

    fn daemon_info() -> Vec<u8> {
        let mut response = vec![0_u8; DAEMON_INFO_SIZE];
        response[..4].copy_from_slice(&1_u32.to_le_bytes());
        response[4..8].copy_from_slice(
            &u32::try_from(t1_bridge::commands::MAX_IDENTITIES)
                .expect("identity limit fits u32")
                .to_le_bytes(),
        );
        response
    }

    fn calibrated_daemon_info() -> Vec<u8> {
        let mut response = daemon_info();
        response[22] = 1;
        response
    }

    fn states() -> Vec<u8> {
        [
            USER.cast_unsigned().to_le_bytes(),
            SECURELY_LOADED_STATE_BITS.to_le_bytes(),
        ]
        .concat()
    }

    fn master_states() -> Vec<u8> {
        [u32::MAX.to_le_bytes(), 1_u32.to_le_bytes()].concat()
    }

    fn identity(identifier: [u8; 16]) -> [u8; IDENTITY_V1_SIZE] {
        let mut response = [0_u8; IDENTITY_V1_SIZE];
        response[..4].copy_from_slice(&USER.to_le_bytes());
        response[4..].copy_from_slice(&identifier);
        response
    }

    fn identities(identifiers: &[[u8; 16]]) -> Vec<u8> {
        identifiers
            .iter()
            .flat_map(|identifier| identity(*identifier))
            .collect()
    }

    fn encode_i32s(values: &[i32]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect()
    }

    fn event(status: u32, in_value: u64, payload: &[u8]) -> EnrollmentEvent {
        let mut data = Vec::with_capacity(MESA_MESSAGE_HEADER_SIZE + payload.len());
        data.extend_from_slice(&0_u64.to_le_bytes());
        data.extend_from_slice(&status.to_le_bytes());
        data.extend_from_slice(&MESA_MESSAGE_TYPE_V1.to_le_bytes());
        data.extend_from_slice(&0_u64.to_le_bytes());
        data.extend_from_slice(&in_value.to_le_bytes());
        data.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        data.extend_from_slice(payload);
        EnrollmentEvent::ServiceStatus(ServiceStatusEvent {
            service: MESA_SERVICE_MESSAGE,
            data,
            reference_timestamp: 0,
            continuous_time_delta: 0,
        })
    }

    fn status_event(value: u64) -> EnrollmentEvent {
        event(MESA_ENROLLMENT_STATUS, value, &[])
    }

    fn completion_event() -> EnrollmentEvent {
        event(MESA_ENROLLMENT_COMPLETE, 0, &identity(NEW))
    }

    fn preparation(before: &[[u8; 16]]) -> Vec<Vec<u8>> {
        vec![Vec::new(), daemon_info(), states(), identities(before)]
    }

    fn policy() -> Vec<Vec<u8>> {
        vec![
            daemon_info(),
            states(),
            encode_i32s(&[300, -1, -1, 1, 1, 1, 1]),
            encode_i32s(&[1, 1, 1, 0, 1, 1, 1, 0]),
        ]
    }

    fn persistence(after: &[[u8; 16]]) -> Vec<Vec<u8>> {
        let user_blob = b"synthetic encrypted user";
        let master_blob = b"synthetic encrypted master";
        vec![
            u32::try_from(user_blob.len())
                .unwrap()
                .to_le_bytes()
                .to_vec(),
            user_blob.to_vec(),
            Vec::new(),
            u32::try_from(master_blob.len())
                .unwrap()
                .to_le_bytes()
                .to_vec(),
            master_blob.to_vec(),
            Vec::new(),
            identities(after),
        ]
    }

    fn successful_responses(
        before: &[[u8; 16]],
        fresh: &[[u8; 16]],
        after: &[[u8; 16]],
        progress_events: usize,
    ) -> Vec<Vec<u8>> {
        let mut responses = preparation(before);
        responses.extend(policy());
        responses.push(Vec::new());
        responses.extend(std::iter::repeat_n(Vec::new(), progress_events));
        responses.push(identities(fresh));
        responses.extend(persistence(after));
        responses
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

    fn restore_responses(pre_restore_states: Vec<u8>) -> Vec<Vec<u8>> {
        vec![
            Vec::new(),
            Vec::new(),
            daemon_info(),
            pre_restore_states,
            Vec::new(),
            daemon_info(),
            master_states(),
            Vec::new(),
            daemon_info(),
            states(),
            identities(&[LEGACY]),
            0_u32.to_le_bytes().to_vec(),
        ]
    }

    #[test]
    fn active_legacy_pair_is_policy_reasserted_restored_and_preserved_before_enrollment() {
        let directory = TestDirectory::new();
        let store = CatacombPairStore::new(directory.0.join("store"));
        store.commit(USER_BLOB, MASTER_BLOB).unwrap();

        let current_user_policy = encode_i32s(&[1, 0, -1, 1, 0, 0, 0, 0]);
        let mut responses = vec![
            MODULE_SERIAL.to_vec(),
            calibrated_daemon_info(),
            calibrated_daemon_info(),
            current_user_policy.clone(),
            Vec::new(),
            current_user_policy,
        ];
        responses.extend(restore_responses(master_states()));
        responses.extend(policy().into_iter().skip(2));
        responses.push(Vec::new());
        responses.push(identities(&[LEGACY, NEW]));
        responses.extend(persistence(&[NEW, LEGACY]));
        let mut transport = FakeTransport::new(responses);

        let prepared =
            prepare_standard_enrollment(&mut transport, &store, user(), &fdr_record()).unwrap();
        assert!(prepared.committed_metadata.is_none());
        assert!(prepared.active_pair.is_some());

        let mut retry = NoRetry;
        let mut events = FakeEvents::new([completion_event()]);
        let result = run_reserved_standard_enrollment(
            &mut transport,
            &mut retry,
            &mut events,
            prepared.transaction,
            user(),
            owner(),
            FingerLabel::RightMiddle,
            prepared.committed_metadata,
            prepared.active_pair,
            &CREDENTIAL,
            None,
            &mut |_, _, _, _| Ok(IdentityMatchOutcome::NoMatch),
            &mut || {},
            &mut || true,
        )
        .unwrap();

        assert_eq!(result.identity, id(NEW));
        assert_eq!(
            &transport.commands[..18],
            [
                0x22, 0x28, 0x28, 0x2e, 0x2f, 0x2e, 0x42, 0x31, 0x28, 0x3c, 0x40, 0x28, 0x3c, 0x40,
                0x28, 0x3c, 0x42, 0x27,
            ]
        );
        let enrollment_start = transport
            .commands
            .iter()
            .position(|command| *command == 0x03)
            .unwrap();
        assert!(enrollment_start > 17);

        let pair = store.load().unwrap();
        let metadata = decode_metadata(pair.metadata().unwrap()).unwrap();
        assert_eq!(
            metadata.identities,
            [
                IdentityMetadataEntry {
                    id: id(LEGACY),
                    finger: None,
                },
                IdentityMetadataEntry {
                    id: id(NEW),
                    finger: Some(FingerLabel::RightMiddle),
                },
            ]
        );
    }

    #[test]
    fn missing_metadata_preserves_legacy_and_labels_only_the_new_identity_atomically() {
        let directory = TestDirectory::new();
        let store = CatacombPairStore::new(directory.0.join("store"));
        let transaction = store.begin_transaction().unwrap();
        let mut transport = FakeTransport::new(successful_responses(
            &[LEGACY],
            &[LEGACY, NEW],
            &[LEGACY, NEW],
            6,
        ));
        let mut retry = NoRetry;
        let mut events = FakeEvents::new([
            status_event(0),
            status_event(0x64),
            status_event(0x65),
            status_event(0x67),
            status_event(0x68),
            status_event(0xca),
            status_event(0x163),
            completion_event(),
        ]);
        let mut progress = Vec::new();
        let mut report = |event: EnrollProgress| {
            progress.push((event.completed_stage(), event.total_stages()));
        };
        let mut started = 0;

        let result = run_reserved_standard_enrollment(
            &mut transport,
            &mut retry,
            &mut events,
            transaction,
            user(),
            owner(),
            FingerLabel::RightIndex,
            None,
            None,
            &CREDENTIAL,
            Some(&mut report),
            &mut |_, _, _, _| Ok(IdentityMatchOutcome::NoMatch),
            &mut || started += 1,
            &mut || true,
        )
        .unwrap();

        assert_eq!(result.identity, id(NEW));
        assert_eq!(started, 1);
        assert_eq!(progress, [(1, 100), (40, 100), (100, 100)]);
        assert_eq!(
            transport.commands,
            [
                0x31, 0x28, 0x3c, 0x42, 0x28, 0x3c, 0x43, 0x2e, 0x03, 0x0e, 0x0e, 0x0e, 0x0e, 0x0e,
                0x0e, 0x42, 0x3d, 0x3e, 0x3f, 0x3d, 0x3e, 0x3f, 0x42,
            ]
        );
        let pair = store.load().unwrap();
        let metadata = decode_metadata(pair.metadata().unwrap()).unwrap();
        assert_eq!(metadata.owner, owner());
        assert_eq!(
            metadata.identities,
            [
                IdentityMetadataEntry {
                    id: id(LEGACY),
                    finger: None,
                },
                IdentityMetadataEntry {
                    id: id(NEW),
                    finger: Some(FingerLabel::RightIndex),
                },
            ]
        );
    }

    #[test]
    fn matching_existing_finger_stops_before_enrollment_or_persistence() {
        let directory = TestDirectory::new();
        let store = CatacombPairStore::new(directory.0.join("store"));
        let transaction = store.begin_transaction().unwrap();
        let mut responses = preparation(&[LEGACY]);
        responses.extend(policy());
        let mut transport = FakeTransport::new(responses);
        let mut retry = NoRetry;
        let mut events = FakeEvents::new([]);
        let mut started = 0;
        let mut checked = 0;

        let error = run_reserved_standard_enrollment(
            &mut transport,
            &mut retry,
            &mut events,
            transaction,
            user(),
            owner(),
            FingerLabel::RightLittle,
            None,
            None,
            &CREDENTIAL,
            None,
            &mut |_, _, checked_user, identities| {
                assert_eq!(checked_user, user());
                assert_eq!(identities.len(), 1);
                checked += 1;
                Ok(IdentityMatchOutcome::Matched(LEGACY))
            },
            &mut || started += 1,
            &mut || true,
        )
        .unwrap_err();

        assert!(matches!(error, StandardEnrollmentError::DuplicateIdentity));
        assert_eq!(started, 1);
        assert_eq!(checked, 1);
        assert!(!transport.commands.contains(&0x03));
        assert!(store.load().is_err());
    }

    #[test]
    fn duplicate_check_cancel_and_error_stop_before_enrollment_or_persistence() {
        for fail_check in [false, true] {
            let directory = TestDirectory::new();
            let store = CatacombPairStore::new(directory.0.join("store"));
            let transaction = store.begin_transaction().unwrap();
            let mut responses = preparation(&[LEGACY]);
            responses.extend(policy());
            let mut transport = FakeTransport::new(responses);
            let mut retry = NoRetry;
            let mut events = FakeEvents::new([]);
            let mut started = 0;

            let error = run_reserved_standard_enrollment(
                &mut transport,
                &mut retry,
                &mut events,
                transaction,
                user(),
                owner(),
                FingerLabel::RightLittle,
                None,
                None,
                &CREDENTIAL,
                None,
                &mut |_, _, _, _| {
                    if fail_check {
                        Err(MatchWorkflowError::NoEnrolledIdentities)
                    } else {
                        Ok(IdentityMatchOutcome::Cancelled)
                    }
                },
                &mut || started += 1,
                &mut || true,
            )
            .unwrap_err();

            if fail_check {
                assert!(matches!(
                    error,
                    StandardEnrollmentError::DuplicateCheck(
                        MatchWorkflowError::NoEnrolledIdentities
                    )
                ));
            } else {
                assert!(matches!(
                    error,
                    StandardEnrollmentError::EnrollmentCancelled
                ));
            }
            assert_eq!(started, 1);
            assert!(!transport.commands.contains(&0x03));
            assert!(store.load().is_err());
        }
    }

    #[test]
    fn three_existing_fingers_report_capacity_before_ui_match_or_mutation() {
        let directory = TestDirectory::new();
        let store = CatacombPairStore::new(directory.0.join("store"));
        let transaction = store.begin_transaction().unwrap();
        let mut responses = preparation(&[LEGACY, EXISTING_LABELED, COLLATERAL]);
        responses.extend([daemon_info(), states()]);
        let mut transport = FakeTransport::new(responses);
        let mut retry = NoRetry;
        let mut events = FakeEvents::new([]);
        let mut started = 0;
        let mut checked = 0;

        let error = run_reserved_standard_enrollment(
            &mut transport,
            &mut retry,
            &mut events,
            transaction,
            user(),
            owner(),
            FingerLabel::RightLittle,
            None,
            None,
            &CREDENTIAL,
            None,
            &mut |_, _, _, _| {
                checked += 1;
                Ok(IdentityMatchOutcome::NoMatch)
            },
            &mut || started += 1,
            &mut || true,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            StandardEnrollmentError::IdentityCapacityReached
        ));
        assert_eq!(started, 0);
        assert_eq!(checked, 0);
        assert_eq!(transport.commands, [0x31, 0x28, 0x3c, 0x42, 0x28, 0x3c]);
        assert!(store.load().is_err());
    }

    #[test]
    fn present_metadata_preserves_existing_entries_and_appends_only_the_new_label() {
        let directory = TestDirectory::new();
        let store = CatacombPairStore::new(directory.0.join("store"));
        let transaction = store.begin_transaction().unwrap();
        let committed = IdentityMetadata::new(
            owner(),
            vec![
                IdentityMetadataEntry {
                    id: id(LEGACY),
                    finger: None,
                },
                IdentityMetadataEntry {
                    id: id(EXISTING_LABELED),
                    finger: Some(FingerLabel::LeftThumb),
                },
            ],
        )
        .unwrap();
        let mut transport = FakeTransport::new(successful_responses(
            &[EXISTING_LABELED, LEGACY],
            &[NEW, LEGACY, EXISTING_LABELED],
            &[EXISTING_LABELED, NEW, LEGACY],
            0,
        ));
        let mut retry = NoRetry;
        let mut events = FakeEvents::new([completion_event()]);

        let result = run_reserved_standard_enrollment(
            &mut transport,
            &mut retry,
            &mut events,
            transaction,
            user(),
            owner(),
            FingerLabel::RightLittle,
            Some(committed),
            None,
            &CREDENTIAL,
            None,
            &mut |_, _, _, _| Ok(IdentityMatchOutcome::NoMatch),
            &mut || {},
            &mut || true,
        )
        .unwrap();

        assert_eq!(result.identity, id(NEW));
        let pair = store.load().unwrap();
        let metadata = decode_metadata(pair.metadata().unwrap()).unwrap();
        assert_eq!(
            metadata.identities,
            [
                IdentityMetadataEntry {
                    id: id(LEGACY),
                    finger: None,
                },
                IdentityMetadataEntry {
                    id: id(EXISTING_LABELED),
                    finger: Some(FingerLabel::LeftThumb),
                },
                IdentityMetadataEntry {
                    id: id(NEW),
                    finger: Some(FingerLabel::RightLittle),
                },
            ]
        );
    }

    #[test]
    fn metadata_mismatch_stops_before_policy_enrollment_or_persistence() {
        let directory = TestDirectory::new();
        let store = CatacombPairStore::new(directory.0.join("store"));
        let transaction = store.begin_transaction().unwrap();
        let mut responses = preparation(&[LEGACY]);
        responses.extend([daemon_info(), states()]);
        let mut transport = FakeTransport::new(responses);
        let mut retry = NoRetry;
        let mut events = FakeEvents::new([]);
        let committed = IdentityMetadata::new(
            owner(),
            vec![IdentityMetadataEntry {
                id: id(COLLATERAL),
                finger: Some(FingerLabel::LeftThumb),
            }],
        )
        .unwrap();

        let error = run_reserved_standard_enrollment(
            &mut transport,
            &mut retry,
            &mut events,
            transaction,
            user(),
            owner(),
            FingerLabel::RightIndex,
            Some(committed),
            None,
            &CREDENTIAL,
            None,
            &mut |_, _, _, _| Ok(IdentityMatchOutcome::NoMatch),
            &mut || {},
            &mut || true,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            StandardEnrollmentError::Catalog(CatalogError::IdentitySetMismatch)
        ));
        assert_eq!(transport.commands, [0x31, 0x28, 0x3c, 0x42, 0x28, 0x3c]);
        assert!(store.load().is_err());
    }

    #[test]
    fn postcommit_verification_rejects_any_collateral_identity_change() {
        let directory = TestDirectory::new();
        let store = CatacombPairStore::new(directory.0.join("store"));
        let transaction = store.begin_transaction().unwrap();
        let mut transport = FakeTransport::new(successful_responses(
            &[LEGACY],
            &[LEGACY, NEW],
            &[LEGACY, NEW, COLLATERAL],
            0,
        ));
        let mut retry = NoRetry;
        let mut events = FakeEvents::new([completion_event()]);

        let error = run_reserved_standard_enrollment(
            &mut transport,
            &mut retry,
            &mut events,
            transaction,
            user(),
            owner(),
            FingerLabel::RightIndex,
            None,
            None,
            &CREDENTIAL,
            None,
            &mut |_, _, _, _| Ok(IdentityMatchOutcome::NoMatch),
            &mut || {},
            &mut || true,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            StandardEnrollmentError::PostCommitIdentitySetChanged
        ));
        let pair = store.load().unwrap();
        let metadata = decode_metadata(pair.metadata().unwrap()).unwrap();
        assert_eq!(metadata.identities.len(), 2);
        assert!(
            metadata
                .identities
                .iter()
                .all(|entry| entry.id != id(COLLATERAL))
        );
    }
}

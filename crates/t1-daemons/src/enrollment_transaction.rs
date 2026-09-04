//! Durable Mesa enrollment inside one prepared SEP/ACM lease.

#[cfg(feature = "auth-broker-service")]
pub(crate) mod standard_enrollment;

use t1_bridge::control::{BiometricTransport, ensure_fdr_calibration_loaded};
use t1_bridge::enroll_workflow::{
    EnrollmentEventSource, EnrollmentOutcome, EnrollmentProgress, run_enrollment,
};
use t1_bridge::policy::{BiometricUserId, SystemPolicyTarget};
use t1_bridge::policy_workflow::{
    UserPolicyRetryRuntime, enable_system_touch_id, enable_user_touch_id,
};
use t1_bridge::user_workflow::{
    list_user_identities, prepare_user, read_catacomb_states, rebind_empty_user,
};

use crate::catacomb_restore::recover_ambiguous_pair;
use crate::catacomb_session::backup_catacomb_pair_with_transaction;
use crate::catacomb_store::{CatacombPairStore, CatacombPairTransaction, CatacombRecoveryOutcome};
use crate::enrollment_lifecycle::{
    EnrollmentPreparationError, EnrollmentTransactionError, EnrollmentTransactionSuccess,
};
use crate::standard_fingerprint_protocol::MAX_OWNER_IDENTITIES;

const SECURELY_LOADED_STATE_BITS: u32 = 3;

/// Recovers/reserves paired storage and loads FDR on one already-versioned
/// `BridgeXPC` transport under the fixed external SEP lock.
pub(crate) fn prepare_enrollment_transaction<'store, Transport>(
    transport: &mut Transport,
    store: &'store CatacombPairStore,
    user_id: BiometricUserId,
    fdr_record: &[u8],
) -> Result<CatacombPairTransaction<'store>, EnrollmentPreparationError<Transport::Error>>
where
    Transport: BiometricTransport,
{
    match recover_ambiguous_pair(transport, store, user_id, fdr_record)
        .map_err(EnrollmentPreparationError::Recovery)?
    {
        CatacombRecoveryOutcome::Clean | CatacombRecoveryOutcome::Promoted => {}
        CatacombRecoveryOutcome::Quarantined => {
            return Err(EnrollmentPreparationError::RecoveryBlocked);
        }
    }
    let transaction = store
        .begin_transaction()
        .map_err(EnrollmentPreparationError::StorageReservation)?;
    ensure_fdr_calibration_loaded(transport, fdr_record)
        .map_err(EnrollmentPreparationError::Calibration)?;
    Ok(transaction)
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub(crate) fn run_reserved_enrollment<Transport, Retry, Events>(
    transport: &mut Transport,
    retry_runtime: &mut Retry,
    events: &mut Events,
    transaction: CatacombPairTransaction<'_>,
    user_id: BiometricUserId,
    credential: &[u8],
    progress: Option<&mut dyn FnMut(EnrollmentProgress)>,
    before_start: &mut dyn FnMut(),
    mesa_completed: &mut dyn FnMut() -> bool,
) -> Result<
    EnrollmentTransactionSuccess,
    EnrollmentTransactionError<Transport::Error, Retry::WaitError, Events::Error>,
>
where
    Transport: BiometricTransport,
    Retry: UserPolicyRetryRuntime<Transport::Error>,
    Events: EnrollmentEventSource,
{
    let mut identities =
        prepare_user(transport, user_id).map_err(EnrollmentTransactionError::User)?;
    let mut states = read_catacomb_states(transport).map_err(EnrollmentTransactionError::User)?;
    if !catacomb_is_secure(&states, user_id) {
        identities =
            rebind_empty_user(transport, user_id).map_err(EnrollmentTransactionError::User)?;
        states = read_catacomb_states(transport).map_err(EnrollmentTransactionError::User)?;
    }
    if !catacomb_is_secure(&states, user_id) {
        return Err(EnrollmentTransactionError::CatacombNotSecurelyLoaded);
    }
    if identities.len() >= usize::from(MAX_OWNER_IDENTITIES) {
        return Err(EnrollmentTransactionError::IdentityCapacityReached);
    }

    enable_system_touch_id(
        transport,
        SystemPolicyTarget::TouchIdFeatures,
        Some(credential),
    )
    .map_err(EnrollmentTransactionError::SystemPolicy)?;
    enable_user_touch_id(
        transport,
        retry_runtime,
        i64::from(user_id.as_raw()),
        Some(credential),
    )
    .map_err(EnrollmentTransactionError::UserPolicy)?;

    before_start();
    let outcome = run_enrollment(
        transport,
        events,
        i64::from(user_id.as_raw()),
        Some(credential),
        progress,
    )
    .map_err(EnrollmentTransactionError::Enrollment)?;
    let EnrollmentOutcome::Completed(identity) = outcome else {
        return Err(EnrollmentTransactionError::EnrollmentTimedOut);
    };
    if !mesa_completed() {
        return Err(EnrollmentTransactionError::EnrollmentCancelled);
    }

    let catacombs = backup_catacomb_pair_with_transaction(transport, transaction, user_id)
        .map_err(EnrollmentTransactionError::Persistence)?;
    let committed = list_user_identities(transport, user_id)
        .map_err(EnrollmentTransactionError::PostCommitIdentityVerification)?;
    if !committed
        .iter()
        .any(|candidate| candidate.identifier() == identity)
    {
        return Err(EnrollmentTransactionError::IdentityMissingAfterCommit);
    }

    Ok(EnrollmentTransactionSuccess {
        identity,
        catacombs,
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

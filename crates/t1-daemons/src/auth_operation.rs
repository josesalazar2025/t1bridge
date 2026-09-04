//! Transport-independent inner Touch ID authentication operation.

use core::fmt;

use t1_bridge::control::{BiometricTransport, ControlError, ensure_fdr_calibration_loaded};
use t1_bridge::match_workflow::{
    IdentityMatchOutcome, MatchEventSource, MatchOutcome, MatchWorkflowError,
    match_fingerprint_identified,
};
use t1_bridge::mesa::{IDENTITY_V1_SIZE, Identity};
use t1_bridge::policy::{ACM_CONTEXT_EXTERNAL_FORM_SIZE, BiometricUserId, PolicyError};
use t1_bridge::policy_workflow::{
    PolicyWorkflowError, UserPolicyRetryRuntime, reassert_user_policy,
};
use t1_bridge::user_workflow::{UserWorkflowError, prepare_user};
use t1_platform::secret;

#[cfg(feature = "auth-broker-service")]
use crate::catacomb_restore::restore_catacomb_pair_for_enrollment;
use crate::catacomb_restore::{CatacombRestoreError, restore_catacomb_pair};
use crate::catacomb_store::{CatacombPairStore, CatacombStoreError};

/// A redaction-safe inner authentication failure.
pub enum AuthenticationOperationError<TransportError, WaitError, EventError> {
    /// FDR calibration validation or loading failed.
    Calibration(ControlError<TransportError>),
    /// A durable restore was requested without its caller-owned ACM context.
    MissingCredential,
    /// The supplied ACM context had an invalid structural length.
    Credential(PolicyError),
    /// The durable pair failed validation before policy or catacomb mutation.
    Store(CatacombStoreError),
    /// Reasserting the current per-user policy failed.
    Policy(PolicyWorkflowError<TransportError, WaitError>),
    /// Restoring or validating the durable pair failed.
    Restore(CatacombRestoreError<TransportError>),
    /// Selecting and preparing the already-live user failed.
    User(UserWorkflowError<TransportError>),
    /// Starting, observing, or cancelling fingerprint matching failed.
    Match(MatchWorkflowError<TransportError, EventError>),
}

/// Result of one inner authentication operation.
pub type AuthenticationOperationResult<TransportError, WaitError, EventError> =
    Result<MatchOutcome, AuthenticationOperationError<TransportError, WaitError, EventError>>;

/// Result of one inner authentication operation that retains Mesa's matched
/// opaque identity for standard fingerprint consumers.
pub type IdentifiedAuthenticationOperationResult<TransportError, WaitError, EventError> = Result<
    IdentityMatchOutcome,
    AuthenticationOperationError<TransportError, WaitError, EventError>,
>;

/// A validated authentication identity set and whether it was restored during
/// the current transport lease.
pub(crate) struct PreparedAuthenticationUser {
    identities: Vec<Identity>,
    #[cfg(feature = "auth-broker-service")]
    restored_in_this_lease: bool,
}

impl PreparedAuthenticationUser {
    /// Returns the validated identities that may be passed to matching or
    /// identity mutation.
    pub(crate) fn identities(&self) -> &[Identity] {
        &self.identities
    }

    /// Reports that durable state became live during this lease.
    ///
    /// Sensor matching must use a fresh lease after this transition. Mesa can
    /// accept Match Start while withholding sensor callbacks when restore and
    /// matching share the first post-boot lease.
    #[cfg(feature = "auth-broker-service")]
    pub(crate) const fn restored_in_this_lease(&self) -> bool {
        self.restored_in_this_lease
    }
}

impl<TransportError, WaitError, EventError> fmt::Debug
    for AuthenticationOperationError<TransportError, WaitError, EventError>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Calibration(error) => formatter.debug_tuple("Calibration").field(error).finish(),
            Self::MissingCredential => formatter.write_str("MissingCredential"),
            Self::Credential(error) => formatter.debug_tuple("Credential").field(error).finish(),
            Self::Store(error) => formatter.debug_tuple("Store").field(error).finish(),
            Self::Policy(error) => formatter.debug_tuple("Policy").field(error).finish(),
            Self::Restore(error) => formatter.debug_tuple("Restore").field(error).finish(),
            Self::User(error) => formatter.debug_tuple("User").field(error).finish(),
            Self::Match(error) => formatter.debug_tuple("Match").field(error).finish(),
        }
    }
}

impl<TransportError, WaitError, EventError> fmt::Display
    for AuthenticationOperationError<TransportError, WaitError, EventError>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Calibration(error) => error.fmt(formatter),
            Self::MissingCredential => {
                formatter.write_str("durable authentication requires an ACM credential")
            }
            Self::Credential(error) => error.fmt(formatter),
            Self::Store(error) => error.fmt(formatter),
            Self::Policy(error) => error.fmt(formatter),
            Self::Restore(error) => error.fmt(formatter),
            Self::User(error) => error.fmt(formatter),
            Self::Match(error) => error.fmt(formatter),
        }
    }
}

impl<TransportError, WaitError, EventError> std::error::Error
    for AuthenticationOperationError<TransportError, WaitError, EventError>
where
    TransportError: std::error::Error + 'static,
    WaitError: std::error::Error + 'static,
    EventError: 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Calibration(error) => Some(error),
            Self::MissingCredential => None,
            Self::Credential(error) => Some(error),
            Self::Store(error) => Some(error),
            Self::Policy(error) => Some(error),
            Self::Restore(error) => Some(error),
            Self::User(error) => Some(error),
            Self::Match(error) => Some(error),
        }
    }
}

/// Runs one inner authentication operation after external lifecycles exist.
///
/// Calibration is validated and made live first. With a durable pair, the
/// caller must provide a structurally valid ACM credential. The store is
/// preflighted before live mutation, the exact current user policy is
/// reasserted, and then a valid live identity is confirmed or the complete
/// durable master/user pair is restored.
/// The restored identities pass directly to matching; the user is not selected
/// again. Without a durable pair, the live user is prepared before matching.
///
/// Relay ownership, exclusive SEP access, ACM creation/destruction, clocks,
/// sockets, and match cancellation remain with their existing callers and
/// workflows.
///
/// # Errors
///
/// Stops on the first calibration, credential, store, policy, restore, user,
/// or match failure. Match-start ambiguity and cancellation behavior are
/// preserved by `match_fingerprint`.
pub fn authenticate_user<Transport, RetryRuntime, Events>(
    transport: &mut Transport,
    retry_runtime: &mut RetryRuntime,
    events: &mut Events,
    fdr_calibration: &[u8],
    user_id: BiometricUserId,
    durable_pair: Option<&CatacombPairStore>,
    credential_set: Option<&[u8]>,
) -> AuthenticationOperationResult<Transport::Error, RetryRuntime::WaitError, Events::Error>
where
    Transport: BiometricTransport,
    RetryRuntime: UserPolicyRetryRuntime<Transport::Error>,
    Events: MatchEventSource,
{
    ensure_fdr_calibration_loaded(transport, fdr_calibration)
        .map_err(AuthenticationOperationError::Calibration)?;

    authenticate_user_after_calibration(
        transport,
        retry_runtime,
        events,
        user_id,
        durable_pair,
        credential_set,
        &mut || {},
        &mut |_| {},
    )
}

/// Runs policy reassertion, paired restore, and matching after the caller has
/// already made FDR live on this `BridgeXPC` connection.
///
/// `before_match` runs immediately before match validation/start. `after_match`
/// runs only after a normal outcome and its required terminal Cancel have both
/// completed. Callers use these boundaries to keep cosmetic presentation
/// strictly around matching and inside the ACM/SEP lease.
///
/// # Errors
///
/// Returns the same policy, store, restore, user, or match errors as
/// [`authenticate_user`], excluding calibration because the caller owns it.
#[allow(clippy::too_many_arguments)]
pub fn authenticate_user_after_calibration<
    Transport,
    RetryRuntime,
    Events,
    BeforeMatch,
    AfterMatch,
>(
    transport: &mut Transport,
    retry_runtime: &mut RetryRuntime,
    events: &mut Events,
    user_id: BiometricUserId,
    durable_pair: Option<&CatacombPairStore>,
    credential_set: Option<&[u8]>,
    before_match: &mut BeforeMatch,
    after_match: &mut AfterMatch,
) -> AuthenticationOperationResult<Transport::Error, RetryRuntime::WaitError, Events::Error>
where
    Transport: BiometricTransport,
    RetryRuntime: UserPolicyRetryRuntime<Transport::Error>,
    Events: MatchEventSource,
    BeforeMatch: FnMut() + ?Sized,
    AfterMatch: FnMut(MatchOutcome) + ?Sized,
{
    identify_user_after_calibration(
        transport,
        retry_runtime,
        events,
        user_id,
        durable_pair,
        credential_set,
        before_match,
        &mut |outcome| after_match(legacy_outcome(outcome)),
    )
    .map(legacy_outcome)
}

/// Runs policy reassertion, paired restore, and identity-bearing matching after
/// the caller has already made FDR live on this `BridgeXPC` connection.
///
/// This is the standard-fingerprint view of
/// [`authenticate_user_after_calibration`]. Both entry points share this one
/// restore and match sequence; the legacy entry point only discards the opaque
/// identifier after successful cleanup.
///
/// # Errors
///
/// Returns the same policy, store, restore, user, or match errors as
/// [`authenticate_user_after_calibration`].
#[allow(clippy::too_many_arguments)]
pub fn identify_user_after_calibration<Transport, RetryRuntime, Events, BeforeMatch, AfterMatch>(
    transport: &mut Transport,
    retry_runtime: &mut RetryRuntime,
    events: &mut Events,
    user_id: BiometricUserId,
    durable_pair: Option<&CatacombPairStore>,
    credential_set: Option<&[u8]>,
    before_match: &mut BeforeMatch,
    after_match: &mut AfterMatch,
) -> IdentifiedAuthenticationOperationResult<Transport::Error, RetryRuntime::WaitError, Events::Error>
where
    Transport: BiometricTransport,
    RetryRuntime: UserPolicyRetryRuntime<Transport::Error>,
    Events: MatchEventSource,
    BeforeMatch: FnMut() + ?Sized,
    AfterMatch: FnMut(IdentityMatchOutcome) + ?Sized,
{
    let prepared = restore_user_after_calibration(
        transport,
        retry_runtime,
        user_id,
        durable_pair,
        credential_set,
    )?;

    before_match();
    let outcome = match_prepared_identities(transport, events, user_id, prepared.identities())
        .map_err(AuthenticationOperationError::Match)?;
    after_match(outcome);
    Ok(outcome)
}

/// Reasserts policy and confirms or restores the complete durable identity set
/// after FDR calibration is already live, without starting a sensor match.
///
/// Standard deletion uses this exact pre-match half of the shared
/// authentication sequence before reserving and applying its mutation.
///
/// # Errors
///
/// Returns the same credential, policy, store, restore, or user failures as
/// [`identify_user_after_calibration`] before its presentation boundary.
pub(crate) fn restore_user_after_calibration<Transport, RetryRuntime, EventError>(
    transport: &mut Transport,
    retry_runtime: &mut RetryRuntime,
    user_id: BiometricUserId,
    durable_pair: Option<&CatacombPairStore>,
    credential_set: Option<&[u8]>,
) -> Result<
    PreparedAuthenticationUser,
    AuthenticationOperationError<Transport::Error, RetryRuntime::WaitError, EventError>,
>
where
    Transport: BiometricTransport,
    RetryRuntime: UserPolicyRetryRuntime<Transport::Error>,
{
    match durable_pair {
        Some(store) => {
            let credential_set = require_credential(credential_set)?;

            // Preflight the complete durable generation before changing live
            // state. The restore workflow reloads it so its own validation and
            // master-first ownership remain intact.
            drop(store.load().map_err(AuthenticationOperationError::Store)?);

            reassert_user_policy(
                transport,
                retry_runtime,
                i64::from(user_id.as_raw()),
                Some(credential_set),
            )
            .map_err(AuthenticationOperationError::Policy)?;

            let restored = restore_catacomb_pair(transport, store, user_id)
                .map_err(AuthenticationOperationError::Restore)?;

            Ok(PreparedAuthenticationUser {
                identities: restored.identities().to_vec(),
                #[cfg(feature = "auth-broker-service")]
                restored_in_this_lease: !restored.already_loaded(),
            })
        }
        None => prepare_user(transport, user_id)
            .map(|identities| PreparedAuthenticationUser {
                identities,
                #[cfg(feature = "auth-broker-service")]
                restored_in_this_lease: false,
            })
            .map_err(AuthenticationOperationError::User),
    }
}

/// Preserves the proven enrollment preparation order: policy first, followed
/// by the complete durable master-and-user restore.
#[cfg(feature = "auth-broker-service")]
pub(crate) fn restore_user_for_enrollment_after_calibration<Transport, RetryRuntime, EventError>(
    transport: &mut Transport,
    retry_runtime: &mut RetryRuntime,
    user_id: BiometricUserId,
    durable_pair: Option<&CatacombPairStore>,
    credential_set: Option<&[u8]>,
) -> Result<
    Vec<Identity>,
    AuthenticationOperationError<Transport::Error, RetryRuntime::WaitError, EventError>,
>
where
    Transport: BiometricTransport,
    RetryRuntime: UserPolicyRetryRuntime<Transport::Error>,
{
    match durable_pair {
        Some(store) => {
            let credential_set = require_credential(credential_set)?;

            drop(store.load().map_err(AuthenticationOperationError::Store)?);

            reassert_user_policy(
                transport,
                retry_runtime,
                i64::from(user_id.as_raw()),
                Some(credential_set),
            )
            .map_err(AuthenticationOperationError::Policy)?;

            Ok(
                restore_catacomb_pair_for_enrollment(transport, store, user_id)
                    .map_err(AuthenticationOperationError::Restore)?
                    .identities()
                    .to_vec(),
            )
        }
        None => prepare_user(transport, user_id).map_err(AuthenticationOperationError::User),
    }
}

fn require_credential<TransportError, WaitError, EventError>(
    credential_set: Option<&[u8]>,
) -> Result<&[u8], AuthenticationOperationError<TransportError, WaitError, EventError>> {
    let credential_set = credential_set.ok_or(AuthenticationOperationError::MissingCredential)?;
    if credential_set.len() != ACM_CONTEXT_EXTERNAL_FORM_SIZE {
        return Err(AuthenticationOperationError::Credential(
            PolicyError::InvalidCredentialLength {
                actual: credential_set.len(),
            },
        ));
    }
    Ok(credential_set)
}

pub(crate) fn match_prepared_identities<Transport, Events>(
    transport: &mut Transport,
    events: &mut Events,
    user_id: BiometricUserId,
    identities: &[Identity],
) -> Result<IdentityMatchOutcome, MatchWorkflowError<Transport::Error, Events::Error>>
where
    Transport: BiometricTransport,
    Events: MatchEventSource,
{
    let mut encoded = Vec::with_capacity(identities.len() * IDENTITY_V1_SIZE);
    for identity in identities {
        encoded.extend_from_slice(&identity.user_id().to_le_bytes());
        encoded.extend_from_slice(&identity.identifier());
    }

    let result = match_fingerprint_identified(transport, events, user_id, &encoded);
    secret::wipe(&mut encoded);
    result
}

const fn legacy_outcome(outcome: IdentityMatchOutcome) -> MatchOutcome {
    match outcome {
        IdentityMatchOutcome::Matched(_) => MatchOutcome::Matched,
        IdentityMatchOutcome::NoMatch => MatchOutcome::NoMatch,
        IdentityMatchOutcome::Cancelled => MatchOutcome::Cancelled,
        IdentityMatchOutcome::TimedOut => MatchOutcome::TimedOut,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::fs;
    use std::path::PathBuf;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;
    use t1_bridge::biometric::{COMMAND_HEADER_SIZE, DAEMON_INFO_SIZE};
    use t1_bridge::calibration::MODULE_SERIAL_NUMBER_SIZE;
    use t1_bridge::match_workflow::MatchEvent;
    use t1_bridge::mesa::{
        MESA_MATCH_RESULT, MESA_MATCH_RESULT_V1_SIZE, MESA_MESSAGE_HEADER_SIZE,
        MESA_MESSAGE_TYPE_V1, MESA_SERVICE_MESSAGE, ServiceStatusEvent,
    };

    const USER: i32 = 501;
    const MODULE_SERIAL: &[u8; MODULE_SERIAL_NUMBER_SIZE] = b"SYNTHETICMODULE001";
    const OTHER_MODULE: &[u8; MODULE_SERIAL_NUMBER_SIZE] = b"SYNTHETICMODULE002";
    const IDENTIFIER: [u8; 16] = [
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe,
        0x0f,
    ];
    const CREDENTIAL: [u8; ACM_CONTEXT_EXTERNAL_FORM_SIZE] = [0x5a; 16];
    const USER_BLOB: &[u8] = b"synthetic encrypted user catacomb";
    const MASTER_BLOB: &[u8] = b"synthetic encrypted master catacomb";

    static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct SyntheticTransportError;

    impl fmt::Display for SyntheticTransportError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("private transport material")
        }
    }

    impl std::error::Error for SyntheticTransportError {}

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct SyntheticWaitError;

    impl fmt::Display for SyntheticWaitError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("private wait material")
        }
    }

    impl std::error::Error for SyntheticWaitError {}

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct SyntheticEventError;

    impl fmt::Display for SyntheticEventError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("private event material")
        }
    }

    impl std::error::Error for SyntheticEventError {}

    struct FakeTransport {
        responses: VecDeque<Result<Vec<u8>, SyntheticTransportError>>,
        commands: Vec<(u16, Vec<u8>)>,
        command_count: Rc<Cell<usize>>,
    }

    impl FakeTransport {
        fn new(responses: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self {
                responses: responses.into_iter().map(Ok).collect(),
                commands: Vec::new(),
                command_count: Rc::new(Cell::new(0)),
            }
        }

        fn codes(&self) -> Vec<u16> {
            self.commands.iter().map(|(code, _)| *code).collect()
        }
    }

    impl BiometricTransport for FakeTransport {
        type Error = SyntheticTransportError;

        fn execute(
            &mut self,
            packet: &t1_bridge::commands::CommandPacket,
        ) -> Result<Vec<u8>, Self::Error> {
            let request = packet.request();
            self.commands.push((
                u16::from_le_bytes(request[2..4].try_into().unwrap()),
                request[COMMAND_HEADER_SIZE..].to_vec(),
            ));
            self.command_count.set(self.commands.len());
            self.responses.pop_front().expect("synthetic response")
        }
    }

    struct FakeRetryRuntime;

    impl UserPolicyRetryRuntime<SyntheticTransportError> for FakeRetryRuntime {
        type WaitError = SyntheticWaitError;

        fn native_status(&self, _: &SyntheticTransportError) -> Option<i64> {
            None
        }

        fn wait(&mut self, _: Duration) -> Result<(), Self::WaitError> {
            Err(SyntheticWaitError)
        }
    }

    struct FakeEvents {
        events: VecDeque<Result<MatchEvent, SyntheticEventError>>,
        calls: usize,
    }

    impl FakeEvents {
        fn new(events: impl IntoIterator<Item = MatchEvent>) -> Self {
            Self {
                events: events.into_iter().map(Ok).collect(),
                calls: 0,
            }
        }
    }

    impl MatchEventSource for FakeEvents {
        type Error = SyntheticEventError;

        fn next_event(&mut self) -> Result<MatchEvent, Self::Error> {
            self.calls += 1;
            self.events.pop_front().expect("synthetic match event")
        }
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "t1bridge-auth-operation-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn store(&self) -> CatacombPairStore {
            let store = CatacombPairStore::new(self.0.join("store"));
            store.commit(USER_BLOB, MASTER_BLOB).unwrap();
            store
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

    fn daemon_info(calibration_loaded: bool, component_count: u32) -> Vec<u8> {
        let mut response = vec![0_u8; DAEMON_INFO_SIZE];
        response[..4].copy_from_slice(&component_count.to_le_bytes());
        response[22] = u8::from(calibration_loaded);
        response
    }

    fn configuration(values: [i32; 8]) -> Vec<u8> {
        values.into_iter().flat_map(i32::to_le_bytes).collect()
    }

    fn states(entries: &[(u32, u32)]) -> Vec<u8> {
        entries
            .iter()
            .flat_map(|(user_id, state)| {
                user_id.to_le_bytes().into_iter().chain(state.to_le_bytes())
            })
            .collect()
    }

    fn identity(identifier: [u8; 16]) -> Vec<u8> {
        let mut identity = Vec::with_capacity(IDENTITY_V1_SIZE);
        identity.extend_from_slice(&USER.to_le_bytes());
        identity.extend_from_slice(&identifier);
        identity
    }

    fn fdr_record(module_serial: &[u8; MODULE_SERIAL_NUMBER_SIZE]) -> Vec<u8> {
        let mut calibration = vec![0_u8; 96];
        let calibration_size = u32::try_from(calibration.len()).unwrap();
        calibration[4..8].copy_from_slice(&calibration_size.to_le_bytes());
        calibration[16..20].copy_from_slice(b"CALB");
        calibration[32..50].copy_from_slice(module_serial);

        let im4p = der_sequence(&[
            der(0x16, b"IM4P"),
            der(0x16, b"FSCl"),
            der(0x16, b"1.0"),
            der(0x04, &calibration),
        ]);
        let img4 = der_sequence(&[der(0x16, b"IMG4"), im4p]);
        let fdrd = der_sequence(&[der(0x16, b"fdrd"), der(0x04, &img4)]);
        der_sequence(&[der(0x16, b"comb"), fdrd])
    }

    fn der_sequence(children: &[Vec<u8>]) -> Vec<u8> {
        der(0x30, &children.concat())
    }

    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut encoded = vec![tag];
        if content.len() < 0x80 {
            encoded.push(u8::try_from(content.len()).unwrap());
        } else {
            encoded.extend_from_slice(&[0x81, u8::try_from(content.len()).unwrap()]);
        }
        encoded.extend_from_slice(content);
        encoded
    }

    fn callback_match(identifier: [u8; 16]) -> MatchEvent {
        let mut payload = vec![0_u8; MESA_MATCH_RESULT_V1_SIZE];
        payload[..4].copy_from_slice(&USER.to_le_bytes());
        payload[4..20].copy_from_slice(&identifier);

        let mut data = vec![0_u8; MESA_MESSAGE_HEADER_SIZE];
        data[8..12].copy_from_slice(&MESA_MATCH_RESULT.to_le_bytes());
        data[12..16].copy_from_slice(&MESA_MESSAGE_TYPE_V1.to_le_bytes());
        data[32..40].copy_from_slice(&(payload.len() as u64).to_le_bytes());
        data.extend_from_slice(&payload);
        MatchEvent::Callback(ServiceStatusEvent {
            service: MESA_SERVICE_MESSAGE,
            data,
            reference_timestamp: 0,
            continuous_time_delta: 0,
        })
    }

    fn calibration_responses() -> Vec<Vec<u8>> {
        vec![
            MODULE_SERIAL.to_vec(),
            daemon_info(true, 0),
            daemon_info(true, 0),
        ]
    }

    fn live_responses() -> Vec<Vec<u8>> {
        let mut responses = calibration_responses();
        responses.extend([
            Vec::new(),
            daemon_info(true, 1),
            states(&[(USER.cast_unsigned(), 3)]),
            identity(IDENTIFIER),
            Vec::new(),
            Vec::new(),
        ]);
        responses
    }

    fn durable_responses() -> Vec<Vec<u8>> {
        let mut responses = calibration_responses();
        let current = configuration([1, 1, 1, 0, 0, 0, 0, 0]);
        responses.extend([
            current.clone(),
            Vec::new(),
            current,
            Vec::new(),
            Vec::new(),
            daemon_info(true, 2),
            Vec::new(),
            Vec::new(),
            daemon_info(true, 2),
            states(&[(u32::MAX, 1)]),
            Vec::new(),
            daemon_info(true, 2),
            states(&[(u32::MAX, 1), (USER.cast_unsigned(), 3)]),
            identity(IDENTIFIER),
            0_u32.to_le_bytes().to_vec(),
            Vec::new(),
            Vec::new(),
        ]);
        responses
    }

    #[test]
    fn durable_authentication_uses_exact_order_and_restored_identity() {
        let directory = TestDirectory::new();
        let store = directory.store();
        let mut transport = FakeTransport::new(durable_responses());
        let mut runtime = FakeRetryRuntime;
        let mut events = FakeEvents::new([callback_match(IDENTIFIER)]);

        let outcome = authenticate_user(
            &mut transport,
            &mut runtime,
            &mut events,
            &fdr_record(MODULE_SERIAL),
            user(),
            Some(&store),
            Some(&CREDENTIAL),
        )
        .unwrap();

        assert_eq!(outcome, MatchOutcome::Matched);
        assert_eq!(events.calls, 1);
        assert_eq!(
            transport.codes(),
            [
                0x22, 0x28, 0x28, 0x2e, 0x2f, 0x2e, 0x42, 0x31, 0x28, 0x3c, 0x40, 0x28, 0x3c, 0x40,
                0x28, 0x3c, 0x42, 0x27, 0x04, 0x0c,
            ]
        );
        assert_eq!(&transport.commands[4].1[28..44], &CREDENTIAL);
        assert_eq!(
            transport
                .codes()
                .into_iter()
                .filter(|code| *code == 0x31)
                .count(),
            1
        );
    }

    #[test]
    #[cfg(feature = "auth-broker-service")]
    fn durable_preparation_reports_a_restore_before_any_match_command() {
        let directory = TestDirectory::new();
        let store = directory.store();
        let mut responses = durable_responses();
        responses.drain(..3);
        let mut transport = FakeTransport::new(responses);
        let mut runtime = FakeRetryRuntime;

        let prepared = restore_user_after_calibration::<_, _, std::convert::Infallible>(
            &mut transport,
            &mut runtime,
            user(),
            Some(&store),
            Some(&CREDENTIAL),
        )
        .unwrap();

        assert!(prepared.restored_in_this_lease());
        assert_eq!(prepared.identities().len(), 1);
        assert!(!transport.codes().contains(&0x04));
        assert_eq!(
            transport.codes(),
            [
                0x2e, 0x2f, 0x2e, 0x42, 0x31, 0x28, 0x3c, 0x40, 0x28, 0x3c, 0x40, 0x28, 0x3c, 0x42,
                0x27,
            ]
        );
    }

    #[test]
    fn match_presentation_hooks_bracket_start_callback_and_terminal_cancel() {
        let directory = TestDirectory::new();
        let store = directory.store();
        let mut responses = durable_responses();
        responses.drain(..3);
        let mut transport = FakeTransport::new(responses);
        let command_count = Rc::clone(&transport.command_count);
        let published_at = Cell::new(None);
        let feedback_at = Cell::new(None);
        let mut before_match = || published_at.set(Some(command_count.get()));
        let mut after_match = |outcome| {
            assert_eq!(outcome, MatchOutcome::Matched);
            feedback_at.set(Some(command_count.get()));
        };
        let mut runtime = FakeRetryRuntime;
        let mut events = FakeEvents::new([callback_match(IDENTIFIER)]);

        assert_eq!(
            authenticate_user_after_calibration(
                &mut transport,
                &mut runtime,
                &mut events,
                user(),
                Some(&store),
                Some(&CREDENTIAL),
                &mut before_match,
                &mut after_match,
            )
            .unwrap(),
            MatchOutcome::Matched
        );

        assert_eq!(published_at.get(), Some(15));
        assert_eq!(transport.codes()[15], 0x04);
        assert_eq!(transport.codes()[16], 0x0c);
        assert_eq!(feedback_at.get(), Some(17));
    }

    #[test]
    fn identity_bearing_authentication_preserves_the_matched_identifier() {
        let directory = TestDirectory::new();
        let store = directory.store();
        let mut responses = durable_responses();
        responses.drain(..3);
        let mut transport = FakeTransport::new(responses);
        let mut runtime = FakeRetryRuntime;
        let mut events = FakeEvents::new([callback_match(IDENTIFIER)]);
        let mut observed = None;

        let outcome = identify_user_after_calibration(
            &mut transport,
            &mut runtime,
            &mut events,
            user(),
            Some(&store),
            Some(&CREDENTIAL),
            &mut || {},
            &mut |outcome| observed = Some(outcome),
        )
        .unwrap();

        assert_eq!(outcome, IdentityMatchOutcome::Matched(IDENTIFIER));
        assert_eq!(observed, Some(outcome));
        assert_eq!(transport.codes()[15..], [0x04, 0x0c]);
    }

    #[test]
    fn durable_authentication_uses_proven_live_identity_fast_path() {
        let directory = TestDirectory::new();
        let store = directory.store();
        let mut responses = calibration_responses();
        let current = configuration([1, 1, 1, 0, 0, 0, 0, 0]);
        responses.extend([
            current.clone(),
            Vec::new(),
            current,
            identity(IDENTIFIER),
            Vec::new(),
            Vec::new(),
        ]);
        let mut transport = FakeTransport::new(responses);
        let mut runtime = FakeRetryRuntime;
        let mut events = FakeEvents::new([callback_match(IDENTIFIER)]);

        let outcome = authenticate_user(
            &mut transport,
            &mut runtime,
            &mut events,
            &fdr_record(MODULE_SERIAL),
            user(),
            Some(&store),
            Some(&CREDENTIAL),
        )
        .unwrap();

        assert_eq!(outcome, MatchOutcome::Matched);
        assert_eq!(
            transport.codes(),
            [0x22, 0x28, 0x28, 0x2e, 0x2f, 0x2e, 0x42, 0x04, 0x0c]
        );
    }

    #[test]
    fn live_authentication_preserves_all_typed_match_outcomes() {
        for (event, expected) in [
            (callback_match(IDENTIFIER), MatchOutcome::Matched),
            (callback_match([0x99; 16]), MatchOutcome::NoMatch),
            (MatchEvent::Cancelled, MatchOutcome::Cancelled),
            (MatchEvent::TimedOut, MatchOutcome::TimedOut),
        ] {
            let mut transport = FakeTransport::new(live_responses());
            let mut runtime = FakeRetryRuntime;
            let mut events = FakeEvents::new([event]);

            let outcome = authenticate_user(
                &mut transport,
                &mut runtime,
                &mut events,
                &fdr_record(MODULE_SERIAL),
                user(),
                None,
                None,
            )
            .unwrap();

            assert_eq!(outcome, expected);
            assert_eq!(
                transport.codes(),
                [0x22, 0x28, 0x28, 0x31, 0x28, 0x3c, 0x42, 0x04, 0x0c]
            );
        }
    }

    #[test]
    fn durable_restore_requires_a_valid_credential_before_policy_or_store() {
        for credential in [None, Some(&[0_u8; 15][..])] {
            let directory = TestDirectory::new();
            let store = directory.store();
            let mut transport = FakeTransport::new(calibration_responses());
            let mut runtime = FakeRetryRuntime;
            let mut events = FakeEvents::new([]);

            let result = authenticate_user(
                &mut transport,
                &mut runtime,
                &mut events,
                &fdr_record(MODULE_SERIAL),
                user(),
                Some(&store),
                credential,
            );

            assert!(matches!(
                result,
                Err(AuthenticationOperationError::MissingCredential
                    | AuthenticationOperationError::Credential(_))
            ));
            assert_eq!(transport.codes(), [0x22, 0x28, 0x28]);
            assert_eq!(events.calls, 0);
        }
    }

    #[test]
    fn bad_calibration_and_store_stop_before_later_mutation() {
        let directory = TestDirectory::new();
        let missing_store = CatacombPairStore::new(directory.0.join("missing"));
        let mut transport = FakeTransport::new([MODULE_SERIAL.to_vec()]);
        let mut runtime = FakeRetryRuntime;
        let mut events = FakeEvents::new([]);

        assert!(matches!(
            authenticate_user(
                &mut transport,
                &mut runtime,
                &mut events,
                &fdr_record(OTHER_MODULE),
                user(),
                Some(&missing_store),
                Some(&CREDENTIAL),
            ),
            Err(AuthenticationOperationError::Calibration(_))
        ));
        assert_eq!(transport.codes(), [0x22]);

        let mut transport = FakeTransport::new(calibration_responses());
        assert!(matches!(
            authenticate_user(
                &mut transport,
                &mut runtime,
                &mut events,
                &fdr_record(MODULE_SERIAL),
                user(),
                Some(&missing_store),
                Some(&CREDENTIAL),
            ),
            Err(AuthenticationOperationError::Store(
                CatacombStoreError::MissingPair
            ))
        ));
        assert_eq!(transport.codes(), [0x22, 0x28, 0x28]);
        assert_eq!(events.calls, 0);
    }

    #[test]
    fn policy_failure_stops_before_restore_and_match() {
        let directory = TestDirectory::new();
        let store = directory.store();
        let mut responses = durable_responses();
        responses[3] = vec![0_u8; 31];
        responses.truncate(4);
        let mut transport = FakeTransport::new(responses);
        let mut runtime = FakeRetryRuntime;
        let mut events = FakeEvents::new([]);

        assert!(matches!(
            authenticate_user(
                &mut transport,
                &mut runtime,
                &mut events,
                &fdr_record(MODULE_SERIAL),
                user(),
                Some(&store),
                Some(&CREDENTIAL),
            ),
            Err(AuthenticationOperationError::Policy(_))
        ));
        assert_eq!(transport.codes(), [0x22, 0x28, 0x28, 0x2e]);
        assert_eq!(events.calls, 0);
    }

    #[test]
    fn nested_diagnostics_redact_transport_wait_and_event_details() {
        let errors = [
            format!(
                "{:?}",
                AuthenticationOperationError::<_, SyntheticWaitError, SyntheticEventError>::Calibration(
                    ControlError::Transport(SyntheticTransportError),
                )
            ),
            format!(
                "{:?}",
                AuthenticationOperationError::<SyntheticTransportError, SyntheticWaitError, _>::Match(
                    MatchWorkflowError::Event(SyntheticEventError),
                )
            ),
        ];

        for rendered in errors {
            assert!(!rendered.contains("private transport material"));
            assert!(!rendered.contains("private wait material"));
            assert!(!rendered.contains("private event material"));
        }
    }
}

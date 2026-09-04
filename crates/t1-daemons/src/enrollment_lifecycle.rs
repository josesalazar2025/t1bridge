//! Enrollment transaction composition across relay, SEP, Mesa, and storage.

use core::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use t1_bridge::control::ControlError;
use t1_bridge::enroll_workflow::EnrollmentError;
use t1_bridge::mesa::IdentityIdentifier;
use t1_bridge::policy::ACM_CONTEXT_EXTERNAL_FORM_SIZE;
use t1_bridge::policy_workflow::{PolicyWorkflowError, SystemPolicyWorkflowError};
use t1_bridge::user_workflow::UserWorkflowError;

use crate::catacomb_restore::CatacombRestoreError;
use crate::catacomb_session::{CatacombBackup, CatacombSessionError};
use crate::catacomb_store::{CatacombPairStore, CatacombRecoveryError, CatacombStoreError};
use crate::enrollment_owner::{EnrollmentOwner, EnrollmentOwnerError, EnrollmentOwnerStore};

/// Result of acquiring and cleaning up one exclusive SEP/ACM lease.
pub enum EnrollmentLeaseOutcome<T, PreparationError, E> {
    /// Acquisition and cleanup both succeeded.
    Completed(T),
    /// Caller-owned BridgeXPC/storage/FDR preparation failed after exclusive
    /// lock acquisition but before SEP/session/keybag/ACM acquisition.
    PreparationFailed(PreparationError),
    /// Exclusive SEP, keybag validation/creation, or ACM acquisition failed
    /// before the operation closure ran.
    AcquisitionFailed(E),
    /// The operation ran, but releasing ACM or SEP failed afterward.
    CleanupFailed { operation: T, error: E },
}

impl<T, PreparationError, E> fmt::Debug for EnrollmentLeaseOutcome<T, PreparationError, E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Completed(_) => formatter.write_str("Completed([redacted])"),
            Self::PreparationFailed(_) => formatter.write_str("PreparationFailed([redacted])"),
            Self::AcquisitionFailed(_) => formatter.write_str("AcquisitionFailed([redacted])"),
            Self::CleanupFailed { .. } => formatter.write_str("CleanupFailed([redacted])"),
        }
    }
}

/// Runtime boundary for the relay handoff and exclusive enrollment lease.
///
/// The lease implementation must acquire bounded exclusive SEP ownership,
/// reuse the valid promoted keybag, acquire an authorized enrollment ACM
/// context, and release ACM before SEP on every closure exit. Invalid or
/// ambiguous keybag state is an acquisition failure.
pub trait EnrollmentLeaseRuntime {
    type Error;

    fn with_prepared_enrollment_lease<Prepared, PreparationError, T>(
        &mut self,
        prepare: impl FnOnce() -> Result<Prepared, PreparationError>,
        operation: impl FnOnce(&mut Prepared, &[u8]) -> T,
    ) -> EnrollmentLeaseOutcome<T, PreparationError, Self::Error>;
}

/// Relay control around an enrollment operation, independent of SEP/ACM.
pub trait EnrollmentRelayRuntime {
    type Error;

    /// Reports whether the shared keybag relay is healthy before handoff.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe health-check failure.
    fn relay_is_active(&mut self) -> Result<bool, Self::Error>;

    /// Stops the shared relay before acquiring exclusive SEP ownership.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe stop failure. Even failure may race with a
    /// successful stop, so the coordinator will still attempt restart.
    fn stop_relay(&mut self) -> Result<(), Self::Error>;

    /// Restarts the shared relay after any attempted stop.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe recovery failure.
    fn start_relay(&mut self) -> Result<(), Self::Error>;
}

/// Runs caller-owned work after a healthy relay has stopped and drops all of
/// that work before the mandatory relay restart.
///
/// This is the production ordering boundary for opening and closing
/// `BridgeXPC`: the connection is created by `operation`, after relay stop,
/// and is necessarily dropped before `start_relay` is called. Restart failure
/// retains highest precedence, including over an operation panic.
///
/// # Errors
///
/// Returns a relay health, stop, operation, or mandatory restart failure.
pub fn with_enrollment_relay_handoff<Runtime, Operation, Success, OperationError>(
    runtime: &mut Runtime,
    operation: Operation,
) -> Result<Success, EnrollmentLifecycleError<Runtime::Error, OperationError>>
where
    Runtime: EnrollmentRelayRuntime,
    Operation: FnOnce(&mut Runtime) -> Result<Success, OperationError>,
{
    let relay_active =
        runtime
            .relay_is_active()
            .map_err(|error| EnrollmentLifecycleError::Runtime {
                stage: EnrollmentLifecycleStage::RelayHealth,
                error,
            })?;
    if !relay_active {
        return Err(EnrollmentLifecycleError::RelayInactive);
    }

    let primary = catch_unwind(AssertUnwindSafe(|| match runtime.stop_relay() {
        Ok(()) => operation(runtime).map_err(EnrollmentLifecycleError::Operation),
        Err(error) => Err(EnrollmentLifecycleError::Runtime {
            stage: EnrollmentLifecycleStage::RelayStop,
            error,
        }),
    }));

    let recovery = catch_unwind(AssertUnwindSafe(|| runtime.start_relay()));
    match recovery {
        Err(payload) => resume_unwind(payload),
        Ok(Err(error)) => Err(EnrollmentLifecycleError::Runtime {
            stage: EnrollmentLifecycleStage::RelayRecovery,
            error,
        }),
        Ok(Ok(())) => match primary {
            Ok(primary) => primary,
            Err(payload) => resume_unwind(payload),
        },
    }
}

fn with_enrollment_lease<
    Runtime,
    Prepared,
    Prepare,
    Operation,
    Success,
    PreparationError,
    OperationError,
>(
    runtime: &mut Runtime,
    prepare: Prepare,
    operation: Operation,
) -> Result<
    Success,
    EnrollmentLifecycleError<
        Runtime::Error,
        EnrollmentOperationError<PreparationError, OperationError>,
    >,
>
where
    Runtime: EnrollmentLeaseRuntime,
    Prepare: FnOnce() -> Result<Prepared, PreparationError>,
    Operation: FnOnce(&mut Prepared, &[u8]) -> Result<Success, OperationError>,
{
    match runtime.with_prepared_enrollment_lease(prepare, |prepared, credential| {
        if credential.len() != ACM_CONTEXT_EXTERNAL_FORM_SIZE {
            return Err(EnrollmentLifecycleError::InvalidCredential);
        }
        operation(prepared, credential)
            .map_err(EnrollmentOperationError::Transaction)
            .map_err(EnrollmentLifecycleError::Operation)
    }) {
        EnrollmentLeaseOutcome::Completed(operation) => operation,
        EnrollmentLeaseOutcome::PreparationFailed(error) => Err(
            EnrollmentLifecycleError::Operation(EnrollmentOperationError::Preparation(error)),
        ),
        EnrollmentLeaseOutcome::AcquisitionFailed(error) => {
            Err(EnrollmentLifecycleError::Runtime {
                stage: EnrollmentLifecycleStage::ExclusiveSepAndAcm,
                error,
            })
        }
        EnrollmentLeaseOutcome::CleanupFailed { operation, error } => match operation {
            Ok(_) => Err(EnrollmentLifecycleError::Runtime {
                stage: EnrollmentLifecycleStage::LeaseCleanup,
                error,
            }),
            Err(primary) => Err(primary),
        },
    }
}

/// Runtime boundary that failed around enrollment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentLifecycleStage {
    RelayHealth,
    RelayStop,
    ExclusiveSepAndAcm,
    LeaseCleanup,
    RelayRecovery,
}

impl fmt::Display for EnrollmentLifecycleStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RelayHealth => "keybag relay health check",
            Self::RelayStop => "keybag relay stop",
            Self::ExclusiveSepAndAcm => "exclusive SEP and ACM acquisition",
            Self::LeaseCleanup => "exclusive SEP and ACM cleanup",
            Self::RelayRecovery => "keybag relay recovery",
        })
    }
}

/// Redaction-safe lifecycle failure around one enrollment operation.
pub enum EnrollmentLifecycleError<RuntimeError, OperationError> {
    RelayInactive,
    Runtime {
        stage: EnrollmentLifecycleStage,
        error: RuntimeError,
    },
    InvalidCredential,
    Operation(OperationError),
}

impl<RuntimeError, OperationError> fmt::Debug
    for EnrollmentLifecycleError<RuntimeError, OperationError>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RelayInactive => formatter.write_str("RelayInactive"),
            Self::Runtime { stage, .. } => formatter
                .debug_struct("Runtime")
                .field("stage", stage)
                .field("error", &"[redacted]")
                .finish(),
            Self::InvalidCredential => formatter.write_str("InvalidCredential"),
            Self::Operation(_) => formatter.write_str("Operation([redacted])"),
        }
    }
}

impl<RuntimeError, OperationError> fmt::Display
    for EnrollmentLifecycleError<RuntimeError, OperationError>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RelayInactive => {
                formatter.write_str("keybag relay is not active before enrollment")
            }
            Self::Runtime { stage, .. } => write!(formatter, "enrollment {stage} failed"),
            Self::InvalidCredential => {
                formatter.write_str("enrollment ACM lease returned an invalid credential")
            }
            Self::Operation(_) => formatter.write_str("inner enrollment transaction failed"),
        }
    }
}

impl<RuntimeError, OperationError> std::error::Error
    for EnrollmentLifecycleError<RuntimeError, OperationError>
{
}

/// Successful durable enrollment result.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EnrollmentTransactionSuccess {
    pub identity: IdentityIdentifier,
    pub catacombs: CatacombBackup,
}

pub enum EnrollmentOperationError<PreparationError, TransactionError> {
    Preparation(PreparationError),
    Transaction(TransactionError),
}

impl<PreparationError, TransactionError> fmt::Debug
    for EnrollmentOperationError<PreparationError, TransactionError>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Preparation(_) => "Preparation([redacted])",
            Self::Transaction(_) => "Transaction([redacted])",
        })
    }
}

pub enum EnrollmentPreparationError<TransportError> {
    Recovery(CatacombRecoveryError<CatacombRestoreError<TransportError>>),
    RecoveryBlocked,
    StorageReservation(CatacombStoreError),
    Calibration(ControlError<TransportError>),
}

impl<TransportError> fmt::Debug for EnrollmentPreparationError<TransportError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Recovery(_) => "Recovery([redacted])",
            Self::RecoveryBlocked => "RecoveryBlocked",
            Self::StorageReservation(_) => "StorageReservation([redacted])",
            Self::Calibration(_) => "Calibration([redacted])",
        })
    }
}

impl fmt::Debug for EnrollmentTransactionSuccess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnrollmentTransactionSuccess")
            .field("identity", &"[redacted]")
            .field("catacombs", &self.catacombs)
            .finish()
    }
}

/// Failure inside the exclusive enrollment transaction.
pub enum EnrollmentTransactionError<TransportError, WaitError, EventError> {
    User(UserWorkflowError<TransportError>),
    CatacombNotSecurelyLoaded,
    IdentityCapacityReached,
    SystemPolicy(SystemPolicyWorkflowError<TransportError>),
    UserPolicy(PolicyWorkflowError<TransportError, WaitError>),
    Enrollment(EnrollmentError<TransportError, EventError>),
    EnrollmentTimedOut,
    EnrollmentCancelled,
    Persistence(CatacombSessionError<TransportError>),
    PostCommitIdentityVerification(UserWorkflowError<TransportError>),
    IdentityMissingAfterCommit,
}

impl<TransportError, WaitError, EventError> fmt::Debug
    for EnrollmentTransactionError<TransportError, WaitError, EventError>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::User(error) => formatter.debug_tuple("User").field(error).finish(),
            Self::CatacombNotSecurelyLoaded => formatter.write_str("CatacombNotSecurelyLoaded"),
            Self::IdentityCapacityReached => formatter.write_str("IdentityCapacityReached"),
            Self::SystemPolicy(error) => {
                formatter.debug_tuple("SystemPolicy").field(error).finish()
            }
            Self::UserPolicy(error) => formatter.debug_tuple("UserPolicy").field(error).finish(),
            Self::Enrollment(error) => formatter.debug_tuple("Enrollment").field(error).finish(),
            Self::EnrollmentTimedOut => formatter.write_str("EnrollmentTimedOut"),
            Self::EnrollmentCancelled => formatter.write_str("EnrollmentCancelled"),
            Self::Persistence(error) => formatter.debug_tuple("Persistence").field(error).finish(),
            Self::PostCommitIdentityVerification(error) => formatter
                .debug_tuple("PostCommitIdentityVerification")
                .field(error)
                .finish(),
            Self::IdentityMissingAfterCommit => formatter.write_str("IdentityMissingAfterCommit"),
        }
    }
}

impl<TransportError, WaitError, EventError> fmt::Display
    for EnrollmentTransactionError<TransportError, WaitError, EventError>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::User(_) => formatter.write_str("enrollment user preparation failed"),
            Self::CatacombNotSecurelyLoaded => {
                formatter.write_str("enrollment user catacomb is not securely loaded")
            }
            Self::IdentityCapacityReached => {
                formatter.write_str("enrollment user is at identity capacity")
            }
            Self::SystemPolicy(_) => formatter.write_str("enrollment system policy failed"),
            Self::UserPolicy(_) => formatter.write_str("enrollment user policy failed"),
            Self::Enrollment(_) => formatter.write_str("Mesa enrollment failed"),
            Self::EnrollmentTimedOut => formatter.write_str("Mesa enrollment timed out"),
            Self::EnrollmentCancelled => formatter.write_str("Mesa enrollment was cancelled"),
            Self::Persistence(_) => formatter.write_str("catacomb persistence failed"),
            Self::PostCommitIdentityVerification(_) => {
                formatter.write_str("post-commit identity verification failed; revalidate storage")
            }
            Self::IdentityMissingAfterCommit => formatter
                .write_str("enrolled identity is absent after catacomb commit; revalidate storage"),
        }
    }
}

impl<TransportError, WaitError, EventError> std::error::Error
    for EnrollmentTransactionError<TransportError, WaitError, EventError>
{
}

/// Failure to durably establish the one Linux owner before biometric mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentOwnerPreflightError {
    Owner(EnrollmentOwnerError),
    UnownedBiometricState,
}

impl fmt::Display for EnrollmentOwnerPreflightError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Owner(error) => error.fmt(formatter),
            Self::UnownedBiometricState => {
                formatter.write_str("existing biometric state has no recorded owner")
            }
        }
    }
}

impl std::error::Error for EnrollmentOwnerPreflightError {}

/// Durably establishes or revalidates the one Linux enrollment owner.
///
/// Missing owner state is claimable only when the catacomb namespace is
/// provably empty. The same owner may safely repeat this preflight before the
/// complete transaction; a different or unknowable owner fails closed.
///
/// # Errors
///
/// Returns a redaction-safe owner-storage failure or refuses biometric state
/// whose original Linux owner cannot be established.
pub fn claim_enrollment_owner(
    store: &CatacombPairStore,
    owner_store: &EnrollmentOwnerStore,
    owner: EnrollmentOwner,
) -> Result<(), EnrollmentOwnerPreflightError> {
    match owner_store.load() {
        Ok(existing) => {
            if existing != owner {
                return Err(EnrollmentOwnerPreflightError::Owner(
                    EnrollmentOwnerError::DifferentOwner,
                ));
            }
            owner_store
                .claim(owner)
                .map_err(EnrollmentOwnerPreflightError::Owner)?;
        }
        Err(EnrollmentOwnerError::MissingOwner) => {
            let empty = store.is_empty_for_first_owner().unwrap_or(false);
            if empty {
                owner_store
                    .claim(owner)
                    .map_err(EnrollmentOwnerPreflightError::Owner)?;
            } else {
                // Another enrollment may have won the owner claim and begun a
                // transaction after our first read. Re-read before refusing
                // so same-owner concurrency remains safe and useful.
                match owner_store.load() {
                    Ok(existing) if existing == owner => {
                        owner_store
                            .claim(owner)
                            .map_err(EnrollmentOwnerPreflightError::Owner)?;
                    }
                    Ok(_) => {
                        return Err(EnrollmentOwnerPreflightError::Owner(
                            EnrollmentOwnerError::DifferentOwner,
                        ));
                    }
                    Err(EnrollmentOwnerError::MissingOwner) => {
                        return Err(EnrollmentOwnerPreflightError::UnownedBiometricState);
                    }
                    Err(error) => return Err(EnrollmentOwnerPreflightError::Owner(error)),
                }
            }
        }
        Err(error) => return Err(EnrollmentOwnerPreflightError::Owner(error)),
    }
    Ok(())
}

/// Runs enrollment after the healthy relay has already been stopped.
///
/// The caller's preparation runs after the fixed external lock is acquired and
/// before native SEP/keybag/ACM acquisition. The product closure runs with the
/// prepared resource and authorized credential. Cleanup failure retains lower
/// precedence than a preparation or product failure.
///
/// # Errors
///
/// Returns a recovery, storage, calibration, SEP/ACM, enrollment, persistence,
/// cleanup, or post-commit verification failure.
pub fn run_enrollment_transaction_after_handoff<
    Runtime,
    Prepared,
    Prepare,
    Operation,
    Success,
    PreparationError,
    OperationError,
>(
    runtime: &mut Runtime,
    prepare: Prepare,
    operation: Operation,
) -> Result<
    Success,
    EnrollmentLifecycleError<
        Runtime::Error,
        EnrollmentOperationError<PreparationError, OperationError>,
    >,
>
where
    Runtime: EnrollmentLeaseRuntime,
    Prepare: FnOnce() -> Result<Prepared, PreparationError>,
    Operation: FnOnce(&mut Prepared, &[u8]) -> Result<Success, OperationError>,
{
    with_enrollment_lease(runtime, prepare, operation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::enrollment_transaction::{prepare_enrollment_transaction, run_reserved_enrollment};
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::PathBuf;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicU64, Ordering};
    use t1_bridge::biometric::DAEMON_INFO_SIZE;
    use t1_bridge::calibration::MODULE_SERIAL_NUMBER_SIZE;
    use t1_bridge::commands::CommandPacket;
    use t1_bridge::commands::MAX_IDENTITIES;
    use t1_bridge::control::BiometricTransport;
    use t1_bridge::enroll_workflow::{EnrollmentEvent, EnrollmentEventSource};
    use t1_bridge::mesa::{
        IDENTITY_V1_SIZE, MESA_ENROLLMENT_COMPLETE, MESA_MESSAGE_HEADER_SIZE, MESA_MESSAGE_TYPE_V1,
        MESA_SERVICE_MESSAGE, ServiceStatusEvent,
    };
    use t1_bridge::policy::BiometricUserId;
    use t1_bridge::policy_workflow::UserPolicyRetryRuntime;

    const CREDENTIAL: [u8; ACM_CONTEXT_EXTERNAL_FORM_SIZE] = [0x5a; 16];
    const SECURELY_LOADED_STATE_BITS: u32 = 3;
    const USER: i32 = 501;
    const MODULE_SERIAL: &[u8; MODULE_SERIAL_NUMBER_SIZE] = b"TESTMODULE00000001";
    const IDENTITY: IdentityIdentifier = [
        0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe,
        0x0f,
    ];
    static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum RuntimeFailure {
        Health,
        Stop,
        Acquire,
        Cleanup,
        Restart,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct OperationFailure;

    impl fmt::Display for OperationFailure {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("private synthetic operation detail")
        }
    }

    impl std::error::Error for OperationFailure {}

    struct UnusedTransport;

    impl BiometricTransport for UnusedTransport {
        type Error = OperationFailure;

        fn execute(&mut self, _packet: &CommandPacket) -> Result<Vec<u8>, Self::Error> {
            panic!("lifecycle tests do not execute biometric commands")
        }
    }

    enum LeaseBehavior {
        Completed,
        AcquireFailed,
        CleanupFailed,
    }

    struct FakeRuntime {
        calls: Vec<&'static str>,
        relay_active: Result<bool, RuntimeFailure>,
        stop: Result<(), RuntimeFailure>,
        stop_panics: bool,
        restart: Result<(), RuntimeFailure>,
        lease: LeaseBehavior,
        credential: Vec<u8>,
    }

    impl FakeRuntime {
        fn healthy() -> Self {
            Self {
                calls: Vec::new(),
                relay_active: Ok(true),
                stop: Ok(()),
                stop_panics: false,
                restart: Ok(()),
                lease: LeaseBehavior::Completed,
                credential: CREDENTIAL.to_vec(),
            }
        }
    }

    impl EnrollmentLeaseRuntime for FakeRuntime {
        type Error = RuntimeFailure;

        fn with_prepared_enrollment_lease<Prepared, PreparationError, T>(
            &mut self,
            prepare: impl FnOnce() -> Result<Prepared, PreparationError>,
            operation: impl FnOnce(&mut Prepared, &[u8]) -> T,
        ) -> EnrollmentLeaseOutcome<T, PreparationError, Self::Error> {
            self.calls.push("sep-exclusive");
            if matches!(self.lease, LeaseBehavior::AcquireFailed) {
                return EnrollmentLeaseOutcome::AcquisitionFailed(RuntimeFailure::Acquire);
            }
            let mut prepared = match prepare() {
                Ok(prepared) => prepared,
                Err(error) => return EnrollmentLeaseOutcome::PreparationFailed(error),
            };
            self.calls.push("keybag-reuse-promoted");
            self.calls.push("acm-authorized-enrollment");
            let result = operation(&mut prepared, &self.credential);
            self.calls.push("acm-release");
            self.calls.push("sep-release");
            match self.lease {
                LeaseBehavior::Completed => EnrollmentLeaseOutcome::Completed(result),
                LeaseBehavior::CleanupFailed => EnrollmentLeaseOutcome::CleanupFailed {
                    operation: result,
                    error: RuntimeFailure::Cleanup,
                },
                LeaseBehavior::AcquireFailed => unreachable!(),
            }
        }
    }

    impl EnrollmentRelayRuntime for FakeRuntime {
        type Error = RuntimeFailure;

        fn relay_is_active(&mut self) -> Result<bool, Self::Error> {
            self.calls.push("relay-health");
            self.relay_active
        }

        fn stop_relay(&mut self) -> Result<(), Self::Error> {
            self.calls.push("relay-stop");
            assert!(!self.stop_panics, "synthetic stop panic");
            self.stop
        }

        fn start_relay(&mut self) -> Result<(), Self::Error> {
            self.calls.push("relay-start");
            self.restart
        }
    }

    #[test]
    fn exact_lease_order_reuses_the_promoted_keybag() {
        let mut runtime = FakeRuntime::healthy();
        let result = with_enrollment_lease(
            &mut runtime,
            || Ok::<_, OperationFailure>(UnusedTransport),
            |_, credential| {
                assert_eq!(credential, CREDENTIAL);
                Ok::<(), OperationFailure>(())
            },
        );
        assert!(result.is_ok());
        assert_eq!(
            runtime.calls,
            [
                "sep-exclusive",
                "keybag-reuse-promoted",
                "acm-authorized-enrollment",
                "acm-release",
                "sep-release",
            ]
        );
    }

    #[test]
    fn bridge_session_is_opened_after_stop_and_closed_before_restart() {
        let mut runtime = FakeRuntime::healthy();
        let result = with_enrollment_relay_handoff(&mut runtime, |runtime| {
            runtime.calls.push("bridgexpc-open");
            runtime.calls.push("bridgexpc-close");
            Ok::<_, OperationFailure>(())
        });

        assert!(result.is_ok());
        assert_eq!(
            runtime.calls,
            [
                "relay-health",
                "relay-stop",
                "bridgexpc-open",
                "bridgexpc-close",
                "relay-start",
            ]
        );
    }

    #[test]
    fn health_and_stop_failures_bound_mutation_and_recovery() {
        let mut runtime = FakeRuntime::healthy();
        runtime.relay_active = Ok(false);
        assert!(matches!(
            with_enrollment_relay_handoff(&mut runtime, |_| Ok::<(), OperationFailure>(())),
            Err(EnrollmentLifecycleError::RelayInactive)
        ));
        assert_eq!(runtime.calls, ["relay-health"]);

        let mut runtime = FakeRuntime::healthy();
        runtime.relay_active = Err(RuntimeFailure::Health);
        assert!(matches!(
            with_enrollment_relay_handoff(&mut runtime, |_| Ok::<(), OperationFailure>(())),
            Err(EnrollmentLifecycleError::Runtime {
                stage: EnrollmentLifecycleStage::RelayHealth,
                ..
            })
        ));
        assert_eq!(runtime.calls, ["relay-health"]);

        let mut runtime = FakeRuntime::healthy();
        runtime.stop = Err(RuntimeFailure::Stop);
        assert!(matches!(
            with_enrollment_relay_handoff(&mut runtime, |_| Ok::<(), OperationFailure>(())),
            Err(EnrollmentLifecycleError::Runtime {
                stage: EnrollmentLifecycleStage::RelayStop,
                ..
            })
        ));
        assert_eq!(runtime.calls, ["relay-health", "relay-stop", "relay-start"]);
    }

    #[test]
    fn acquisition_and_credential_failures_bound_the_lease() {
        let mut runtime = FakeRuntime::healthy();
        runtime.lease = LeaseBehavior::AcquireFailed;
        assert!(matches!(
            with_enrollment_lease(
                &mut runtime,
                || Ok::<_, OperationFailure>(UnusedTransport),
                |_, _| Ok::<(), OperationFailure>(()),
            ),
            Err(EnrollmentLifecycleError::Runtime {
                stage: EnrollmentLifecycleStage::ExclusiveSepAndAcm,
                ..
            })
        ));
        assert_eq!(runtime.calls, ["sep-exclusive"]);

        let mut runtime = FakeRuntime::healthy();
        runtime.credential.pop();
        assert!(matches!(
            with_enrollment_lease(
                &mut runtime,
                || Ok::<_, OperationFailure>(UnusedTransport),
                |_, _| Ok::<(), OperationFailure>(()),
            ),
            Err(EnrollmentLifecycleError::InvalidCredential)
        ));
        assert_eq!(
            runtime.calls,
            [
                "sep-exclusive",
                "keybag-reuse-promoted",
                "acm-authorized-enrollment",
                "acm-release",
                "sep-release",
            ]
        );
    }

    #[test]
    fn cleanup_failure_never_masks_operation_failure() {
        let mut runtime = FakeRuntime::healthy();
        runtime.lease = LeaseBehavior::CleanupFailed;
        assert!(matches!(
            with_enrollment_lease(
                &mut runtime,
                || Ok::<_, OperationFailure>(UnusedTransport),
                |_, _| Err::<(), _>(OperationFailure),
            ),
            Err(EnrollmentLifecycleError::Operation(
                EnrollmentOperationError::Transaction(OperationFailure)
            ))
        ));

        let mut runtime = FakeRuntime::healthy();
        runtime.lease = LeaseBehavior::CleanupFailed;
        assert!(matches!(
            with_enrollment_lease(
                &mut runtime,
                || Ok::<_, OperationFailure>(UnusedTransport),
                |_, _| Ok::<(), OperationFailure>(()),
            ),
            Err(EnrollmentLifecycleError::Runtime {
                stage: EnrollmentLifecycleStage::LeaseCleanup,
                ..
            })
        ));
    }

    #[test]
    fn relay_restart_failure_overrides_every_earlier_outcome() {
        for operation_fails in [false, true] {
            let mut runtime = FakeRuntime::healthy();
            runtime.restart = Err(RuntimeFailure::Restart);
            let result = with_enrollment_relay_handoff(&mut runtime, |_| {
                if operation_fails {
                    Err(OperationFailure)
                } else {
                    Ok(())
                }
            });
            assert!(matches!(
                result,
                Err(EnrollmentLifecycleError::Runtime {
                    stage: EnrollmentLifecycleStage::RelayRecovery,
                    ..
                })
            ));
            assert_eq!(runtime.calls.last(), Some(&"relay-start"));
        }
    }

    #[test]
    fn panic_after_relay_stop_attempts_restart_before_resuming_unwind() {
        let mut runtime = FakeRuntime::healthy();
        let panic = catch_unwind(AssertUnwindSafe(|| {
            let _ = with_enrollment_relay_handoff(&mut runtime, |_| {
                panic!("synthetic operation panic")
            })
                as Result<(), EnrollmentLifecycleError<RuntimeFailure, OperationFailure>>;
        }));

        assert!(panic.is_err());
        assert_eq!(runtime.calls.last(), Some(&"relay-start"));
    }

    #[test]
    fn panic_during_relay_stop_attempts_restart_before_resuming_unwind() {
        let mut runtime = FakeRuntime::healthy();
        runtime.stop_panics = true;
        let panic = catch_unwind(AssertUnwindSafe(|| {
            with_enrollment_relay_handoff(&mut runtime, |_| Ok::<(), OperationFailure>(()))
        }));

        assert!(panic.is_err());
        assert_eq!(runtime.calls, ["relay-health", "relay-stop", "relay-start"]);
    }

    #[test]
    fn relay_restart_failure_overrides_an_operation_panic() {
        let mut runtime = FakeRuntime::healthy();
        runtime.restart = Err(RuntimeFailure::Restart);

        let result =
            with_enrollment_relay_handoff(&mut runtime, |_| panic!("synthetic operation panic"))
                as Result<(), EnrollmentLifecycleError<RuntimeFailure, OperationFailure>>;

        assert!(matches!(
            result,
            Err(EnrollmentLifecycleError::Runtime {
                stage: EnrollmentLifecycleStage::RelayRecovery,
                error: RuntimeFailure::Restart,
            })
        ));
        assert_eq!(runtime.calls.last(), Some(&"relay-start"));
    }

    #[test]
    fn lifecycle_errors_do_not_render_runtime_or_operation_details() {
        let runtime = EnrollmentLifecycleError::<&str, &str>::Runtime {
            stage: EnrollmentLifecycleStage::LeaseCleanup,
            error: "private-runtime-marker",
        };
        let operation =
            EnrollmentLifecycleError::<&str, &str>::Operation("private-operation-marker");
        let verification =
            EnrollmentTransactionError::<&str, &str, &str>::PostCommitIdentityVerification(
                UserWorkflowError::Transport("private-verification-marker"),
            );
        assert!(!format!("{runtime:?} {runtime}").contains("private-runtime-marker"));
        assert!(!format!("{operation:?} {operation}").contains("private-operation-marker"));
        assert!(format!("{verification}").contains("revalidate storage"));
        assert!(
            !format!("{verification:?} {verification}").contains("private-verification-marker")
        );
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "t1bridge-enrollment-lifecycle-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create synthetic test directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure synthetic test directory");
            Self(path)
        }

        fn owner_store(&self, store_path: &PathBuf) -> EnrollmentOwnerStore {
            let metadata = fs::metadata(&self.0).expect("test directory metadata");
            EnrollmentOwnerStore::for_test(store_path, metadata.uid(), metadata.gid())
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct ProductTransport {
        responses: VecDeque<Result<Vec<u8>, OperationFailure>>,
        commands: Vec<u16>,
        store_path: PathBuf,
        reservation_seen_before_first_command: bool,
        command_count: Rc<Cell<usize>>,
        lease_started_at_command: Rc<Cell<Option<usize>>>,
        teardown_seen: Rc<Cell<bool>>,
        cleanup_saw_teardown: Rc<Cell<Option<bool>>>,
    }

    impl ProductTransport {
        fn new(responses: impl IntoIterator<Item = Vec<u8>>, store_path: PathBuf) -> Self {
            Self {
                responses: responses.into_iter().map(Ok).collect(),
                commands: Vec::new(),
                store_path,
                reservation_seen_before_first_command: false,
                command_count: Rc::new(Cell::new(0)),
                lease_started_at_command: Rc::new(Cell::new(None)),
                teardown_seen: Rc::new(Cell::new(false)),
                cleanup_saw_teardown: Rc::new(Cell::new(None)),
            }
        }
    }

    impl BiometricTransport for ProductTransport {
        type Error = OperationFailure;

        fn execute(&mut self, packet: &CommandPacket) -> Result<Vec<u8>, Self::Error> {
            if self.commands.is_empty() {
                self.reservation_seen_before_first_command = fs::read_dir(&self.store_path)
                    .expect("reserved store exists before first command")
                    .filter_map(Result::ok)
                    .filter_map(|entry| entry.file_name().into_string().ok())
                    .any(|name| name.starts_with(".stage-"));
            }
            self.commands.push(u16::from_le_bytes(
                packet.request()[2..4]
                    .try_into()
                    .expect("command code bytes"),
            ));
            self.command_count.set(self.commands.len());
            self.responses
                .pop_front()
                .expect("one synthetic response per command")
        }
    }

    struct ProductRuntime {
        calls: Vec<&'static str>,
        restart: Result<(), RuntimeFailure>,
        teardown_seen: Rc<Cell<bool>>,
        cleanup_saw_teardown: Rc<Cell<Option<bool>>>,
    }

    impl EnrollmentLeaseRuntime for ProductRuntime {
        type Error = RuntimeFailure;

        fn with_prepared_enrollment_lease<Prepared, PreparationError, T>(
            &mut self,
            prepare: impl FnOnce() -> Result<Prepared, PreparationError>,
            operation: impl FnOnce(&mut Prepared, &[u8]) -> T,
        ) -> EnrollmentLeaseOutcome<T, PreparationError, Self::Error> {
            self.calls.push("external-fixed-lock");
            let mut prepared = match prepare() {
                Ok(prepared) => prepared,
                Err(error) => return EnrollmentLeaseOutcome::PreparationFailed(error),
            };
            self.calls.push("sep-session");
            self.calls.push("keybag-reuse-promoted");
            self.calls.push("acm-authorized-enrollment");
            let result = operation(&mut prepared, &CREDENTIAL);
            self.cleanup_saw_teardown
                .set(Some(self.teardown_seen.get()));
            self.calls.push("acm-release");
            self.calls.push("sep-release");
            drop(prepared);
            self.calls.push("prepared-bridge-close");
            self.calls.push("external-fixed-lock-release");
            EnrollmentLeaseOutcome::Completed(result)
        }
    }

    impl EnrollmentRelayRuntime for ProductRuntime {
        type Error = RuntimeFailure;

        fn relay_is_active(&mut self) -> Result<bool, Self::Error> {
            self.calls.push("relay-health");
            Ok(true)
        }

        fn stop_relay(&mut self) -> Result<(), Self::Error> {
            self.calls.push("relay-stop");
            Ok(())
        }

        fn start_relay(&mut self) -> Result<(), Self::Error> {
            self.calls.push("relay-start");
            self.restart
        }
    }

    struct NoRetry;

    impl UserPolicyRetryRuntime<OperationFailure> for NoRetry {
        type WaitError = OperationFailure;

        fn native_status(&self, _error: &OperationFailure) -> Option<i64> {
            None
        }

        fn wait(&mut self, _delay: core::time::Duration) -> Result<(), Self::WaitError> {
            panic!("matching synthetic policy never retries")
        }
    }

    struct ProductEvents {
        events: VecDeque<Result<EnrollmentEvent, OperationFailure>>,
    }

    struct TestEnrollmentTeardown(Rc<Cell<bool>>);

    impl Drop for TestEnrollmentTeardown {
        fn drop(&mut self) {
            self.0.set(true);
        }
    }

    type ProductError = EnrollmentLifecycleError<
        RuntimeFailure,
        EnrollmentOperationError<
            EnrollmentPreparationError<OperationFailure>,
            EnrollmentTransactionError<OperationFailure, OperationFailure, OperationFailure>,
        >,
    >;

    impl EnrollmentEventSource for ProductEvents {
        type Error = OperationFailure;

        fn next_event(&mut self) -> Result<EnrollmentEvent, Self::Error> {
            self.events
                .pop_front()
                .expect("one synthetic enrollment event")
        }
    }

    struct ProductFixture {
        _directory: TestDirectory,
        store: CatacombPairStore,
        owner_store: EnrollmentOwnerStore,
        runtime: ProductRuntime,
        transport: ProductTransport,
        retry: NoRetry,
        events: ProductEvents,
        user_blob: Vec<u8>,
        master_blob: Vec<u8>,
    }

    impl ProductFixture {
        fn with_postcommit_response(
            response: Result<Vec<u8>, OperationFailure>,
            restart: Result<(), RuntimeFailure>,
        ) -> Self {
            let directory = TestDirectory::new();
            let store_path = directory.0.join("store");
            let store = CatacombPairStore::new(&store_path);
            let owner_store = directory.owner_store(&store_path);
            let user_blob = b"synthetic encrypted user".to_vec();
            let master_blob = b"synthetic encrypted master".to_vec();
            let mut responses = successful_product_responses(&user_blob, &master_blob);
            responses.pop().expect("post-commit response exists");
            let mut transport = ProductTransport::new(responses, store_path);
            transport.responses.push_back(response);
            Self {
                _directory: directory,
                store,
                owner_store,
                runtime: ProductRuntime {
                    calls: Vec::new(),
                    restart,
                    teardown_seen: Rc::clone(&transport.teardown_seen),
                    cleanup_saw_teardown: Rc::clone(&transport.cleanup_saw_teardown),
                },
                transport,
                retry: NoRetry,
                events: ProductEvents {
                    events: [Ok(completion_event())].into_iter().collect(),
                },
                user_blob,
                master_blob,
            }
        }

        fn run(&mut self) -> Result<EnrollmentTransactionSuccess, ProductError> {
            claim_enrollment_owner(
                &self.store,
                &self.owner_store,
                EnrollmentOwner::new(42_000).unwrap(),
            )
            .expect("synthetic owner preflight succeeds");
            let result = with_enrollment_relay_handoff(&mut self.runtime, |runtime| {
                run_product_transaction(
                    runtime,
                    &mut self.transport,
                    &mut self.retry,
                    &mut self.events,
                    &self.store,
                    &fdr_record(),
                    BiometricUserId::new(i64::from(USER)).unwrap(),
                    &mut || {},
                    &mut || true,
                )
            });
            flatten_test_handoff(result)
        }

        fn assert_promoted_pair_loads(&self) {
            let pair = self.store.load().expect("promoted pair remains loadable");
            assert_eq!(pair.user(), self.user_blob);
            assert_eq!(pair.master(), self.master_blob);
        }
    }

    fn flatten_test_handoff(
        result: Result<
            EnrollmentTransactionSuccess,
            EnrollmentLifecycleError<RuntimeFailure, ProductError>,
        >,
    ) -> Result<EnrollmentTransactionSuccess, ProductError> {
        match result {
            Ok(success) => Ok(success),
            Err(EnrollmentLifecycleError::Operation(inner)) => Err(inner),
            Err(EnrollmentLifecycleError::RelayInactive) => {
                Err(EnrollmentLifecycleError::RelayInactive)
            }
            Err(EnrollmentLifecycleError::Runtime { stage, error }) => {
                Err(EnrollmentLifecycleError::Runtime { stage, error })
            }
            Err(EnrollmentLifecycleError::InvalidCredential) => {
                Err(EnrollmentLifecycleError::InvalidCredential)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn run_product_transaction(
        runtime: &mut ProductRuntime,
        transport: &mut ProductTransport,
        retry: &mut NoRetry,
        events: &mut ProductEvents,
        store: &CatacombPairStore,
        fdr_record: &[u8],
        user_id: BiometricUserId,
        before_start: &mut dyn FnMut(),
        mesa_completed: &mut dyn FnMut() -> bool,
    ) -> Result<EnrollmentTransactionSuccess, ProductError> {
        let transport = RefCell::new(transport);
        run_enrollment_transaction_after_handoff(
            runtime,
            || {
                prepare_enrollment_transaction(
                    &mut **transport.borrow_mut(),
                    store,
                    user_id,
                    fdr_record,
                )
                .map(Some)
            },
            |transaction, credential| {
                let mut transport = transport.borrow_mut();
                transport
                    .lease_started_at_command
                    .set(Some(transport.commands.len()));
                let _teardown = TestEnrollmentTeardown(Rc::clone(&transport.teardown_seen));
                run_reserved_enrollment(
                    &mut **transport,
                    retry,
                    events,
                    transaction
                        .take()
                        .expect("prepared transaction is available"),
                    user_id,
                    credential,
                    None,
                    before_start,
                    mesa_completed,
                )
            },
        )
    }

    #[test]
    fn reconciled_path_orders_storage_calibration_lease_ui_completion_and_persistence() {
        let directory = TestDirectory::new();
        let store_path = directory.0.join("store");
        let store = CatacombPairStore::new(&store_path);
        let user_blob = b"synthetic encrypted user".to_vec();
        let master_blob = b"synthetic encrypted master".to_vec();
        let transport = ProductTransport::new(
            successful_product_responses(&user_blob, &master_blob),
            store_path,
        );
        let command_count = Rc::clone(&transport.command_count);
        let lease_started_at_command = Rc::clone(&transport.lease_started_at_command);
        let teardown_seen = Rc::clone(&transport.teardown_seen);
        let cleanup_saw_teardown = Rc::clone(&transport.cleanup_saw_teardown);
        let mut transport = transport;
        let mut runtime = ProductRuntime {
            calls: Vec::new(),
            restart: Ok(()),
            teardown_seen: Rc::clone(&teardown_seen),
            cleanup_saw_teardown: Rc::clone(&cleanup_saw_teardown),
        };
        let mut retry = NoRetry;
        let mut events = ProductEvents {
            events: [Ok(completion_event())].into_iter().collect(),
        };
        let ui_published_at = Cell::new(None);
        let cancellation_closed_at = Cell::new(None);
        let mut publish_ui = || ui_published_at.set(Some(command_count.get()));
        let mut close_cancellation = || {
            cancellation_closed_at.set(Some(command_count.get()));
            true
        };
        let result = run_product_transaction(
            &mut runtime,
            &mut transport,
            &mut retry,
            &mut events,
            &store,
            &fdr_record(),
            BiometricUserId::new(i64::from(USER)).unwrap(),
            &mut publish_ui,
            &mut close_cancellation,
        )
        .expect("reconciled synthetic enrollment succeeds");

        assert_eq!(result.identity, IDENTITY);
        assert!(transport.reservation_seen_before_first_command);
        assert_eq!(lease_started_at_command.get(), Some(3));
        assert_eq!(
            transport.commands,
            [
                0x22, 0x28, 0x28, 0x31, 0x28, 0x3c, 0x42, 0x28, 0x3c, 0x43, 0x2e, 0x03, 0x42, 0x3d,
                0x3e, 0x3f, 0x3d, 0x3e, 0x3f, 0x42,
            ]
        );
        assert_eq!(ui_published_at.get(), Some(11));
        assert_eq!(transport.commands[11], 0x03);
        assert_eq!(cancellation_closed_at.get(), Some(13));
        assert_eq!(transport.commands[13], 0x3d);
        assert_eq!(
            runtime.calls,
            [
                "external-fixed-lock",
                "sep-session",
                "keybag-reuse-promoted",
                "acm-authorized-enrollment",
                "acm-release",
                "sep-release",
                "prepared-bridge-close",
                "external-fixed-lock-release",
            ]
        );
        assert_eq!(cleanup_saw_teardown.get(), Some(true));
    }

    #[test]
    fn precompletion_cancellation_stops_before_persistence() {
        let directory = TestDirectory::new();
        let store_path = directory.0.join("store");
        let store = CatacombPairStore::new(&store_path);
        let mut responses = successful_product_responses(
            b"synthetic encrypted user",
            b"synthetic encrypted master",
        );
        responses.truncate(13);
        let mut transport = ProductTransport::new(responses, store_path);
        let mut runtime = ProductRuntime {
            calls: Vec::new(),
            restart: Ok(()),
            teardown_seen: Rc::clone(&transport.teardown_seen),
            cleanup_saw_teardown: Rc::clone(&transport.cleanup_saw_teardown),
        };
        let mut retry = NoRetry;
        let mut events = ProductEvents {
            events: [Ok(completion_event())].into_iter().collect(),
        };

        let error = run_product_transaction(
            &mut runtime,
            &mut transport,
            &mut retry,
            &mut events,
            &store,
            &fdr_record(),
            BiometricUserId::new(i64::from(USER)).unwrap(),
            &mut || {},
            &mut || false,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            EnrollmentLifecycleError::Operation(EnrollmentOperationError::Transaction(
                EnrollmentTransactionError::EnrollmentCancelled
            ))
        ));
        assert_eq!(transport.commands.len(), 13);
        assert!(store.load().is_err());
    }

    #[test]
    fn different_linux_owner_stops_before_lifecycle_or_storage_mutation() {
        let fixture =
            ProductFixture::with_postcommit_response(Ok(identity_record().to_vec()), Ok(()));
        fixture
            .owner_store
            .claim(EnrollmentOwner::new(42_001).unwrap())
            .expect("record different synthetic owner");
        let before = fs::read_dir(&fixture.transport.store_path)
            .expect("list owner state")
            .map(|entry| entry.expect("owner entry").file_name())
            .collect::<Vec<_>>();

        let error = claim_enrollment_owner(
            &fixture.store,
            &fixture.owner_store,
            EnrollmentOwner::new(42_000).unwrap(),
        )
        .unwrap_err();

        assert!(matches!(
            error,
            EnrollmentOwnerPreflightError::Owner(EnrollmentOwnerError::DifferentOwner)
        ));
        assert!(fixture.runtime.calls.is_empty());
        assert!(fixture.transport.commands.is_empty());
        let after = fs::read_dir(&fixture.transport.store_path)
            .expect("list owner state")
            .map(|entry| entry.expect("owner entry").file_name())
            .collect::<Vec<_>>();
        assert_eq!(after, before);
        assert_eq!(
            fixture.owner_store.load(),
            Ok(EnrollmentOwner::new(42_001).unwrap())
        );
    }

    #[test]
    fn missing_owner_never_claims_existing_or_pending_biometric_state() {
        for pending in [false, true] {
            let directory = TestDirectory::new();
            let store_path = directory.0.join("store");
            let store = CatacombPairStore::new(&store_path);
            if pending {
                let mut transaction = store.begin_transaction().unwrap();
                transaction.reserve_recovery().unwrap();
                transaction.write_user(b"synthetic pending user").unwrap();
                transaction
                    .write_master(b"synthetic pending master")
                    .unwrap();
            } else {
                store
                    .commit(b"synthetic active user", b"synthetic active master")
                    .unwrap();
            }
            let owner_store = directory.owner_store(&store_path);
            let error =
                claim_enrollment_owner(&store, &owner_store, EnrollmentOwner::new(42_000).unwrap())
                    .unwrap_err();

            assert!(matches!(
                error,
                EnrollmentOwnerPreflightError::UnownedBiometricState
            ));
            assert!(matches!(
                owner_store.load(),
                Err(EnrollmentOwnerError::MissingOwner)
            ));
            if pending {
                assert!(matches!(
                    store.begin_transaction(),
                    Err(CatacombStoreError::PendingExport)
                ));
            } else {
                assert_eq!(store.load().unwrap().user(), b"synthetic active user");
            }
        }
    }

    #[test]
    fn unsafe_owner_storage_stops_before_every_hardware_lifecycle() {
        let fixture =
            ProductFixture::with_postcommit_response(Ok(identity_record().to_vec()), Ok(()));
        fs::create_dir(&fixture.transport.store_path).expect("create synthetic owner directory");
        fs::set_permissions(
            &fixture.transport.store_path,
            fs::Permissions::from_mode(0o755),
        )
        .expect("make synthetic owner directory unsafe");

        let error = claim_enrollment_owner(
            &fixture.store,
            &fixture.owner_store,
            EnrollmentOwner::new(42_000).unwrap(),
        )
        .unwrap_err();

        assert!(matches!(
            error,
            EnrollmentOwnerPreflightError::Owner(EnrollmentOwnerError::UnsafeStorage)
        ));
        assert!(fixture.runtime.calls.is_empty());
        assert!(fixture.transport.commands.is_empty());
    }

    #[test]
    fn first_owner_is_retained_after_ambiguous_hardware_failure() {
        let mut fixture = ProductFixture::with_postcommit_response(Err(OperationFailure), Ok(()));

        assert!(fixture.run().is_err());
        assert_eq!(
            fixture.owner_store.load(),
            Ok(EnrollmentOwner::new(42_000).unwrap())
        );
    }

    #[test]
    fn postcommit_transport_failure_requires_revalidation_without_losing_pair() {
        let mut fixture = ProductFixture::with_postcommit_response(Err(OperationFailure), Ok(()));

        let error = fixture.run().unwrap_err();

        assert!(matches!(
            error,
            EnrollmentLifecycleError::Operation(EnrollmentOperationError::Transaction(
                EnrollmentTransactionError::PostCommitIdentityVerification(
                    UserWorkflowError::Transport(OperationFailure)
                )
            ))
        ));
        fixture.assert_promoted_pair_loads();
        assert_eq!(fixture.runtime.calls.last(), Some(&"relay-start"));
    }

    #[test]
    fn malformed_postcommit_identity_list_requires_revalidation_without_losing_pair() {
        let mut fixture = ProductFixture::with_postcommit_response(Ok(vec![0]), Ok(()));

        let error = fixture.run().unwrap_err();

        assert!(matches!(
            error,
            EnrollmentLifecycleError::Operation(EnrollmentOperationError::Transaction(
                EnrollmentTransactionError::PostCommitIdentityVerification(
                    UserWorkflowError::Command(_)
                )
            ))
        ));
        fixture.assert_promoted_pair_loads();
        assert_eq!(fixture.runtime.calls.last(), Some(&"relay-start"));
    }

    #[test]
    fn wrong_or_missing_postcommit_identity_requires_revalidation_without_losing_pair() {
        let mut wrong_user = identity_record();
        wrong_user[..4].copy_from_slice(&(USER + 1).to_le_bytes());
        let mut fixture = ProductFixture::with_postcommit_response(Ok(wrong_user.to_vec()), Ok(()));

        let error = fixture.run().unwrap_err();
        assert!(matches!(
            error,
            EnrollmentLifecycleError::Operation(EnrollmentOperationError::Transaction(
                EnrollmentTransactionError::PostCommitIdentityVerification(
                    UserWorkflowError::IdentityForWrongUser
                )
            ))
        ));
        fixture.assert_promoted_pair_loads();
        assert_eq!(fixture.runtime.calls.last(), Some(&"relay-start"));

        let mut fixture = ProductFixture::with_postcommit_response(Ok(Vec::new()), Ok(()));
        let error = fixture.run().unwrap_err();
        assert!(matches!(
            error,
            EnrollmentLifecycleError::Operation(EnrollmentOperationError::Transaction(
                EnrollmentTransactionError::IdentityMissingAfterCommit
            ))
        ));
        fixture.assert_promoted_pair_loads();
        assert_eq!(fixture.runtime.calls.last(), Some(&"relay-start"));
    }

    #[test]
    fn relay_restart_failure_overrides_postcommit_verification_failure() {
        let mut fixture = ProductFixture::with_postcommit_response(
            Err(OperationFailure),
            Err(RuntimeFailure::Restart),
        );

        let error = fixture.run().unwrap_err();

        assert!(matches!(
            error,
            EnrollmentLifecycleError::Runtime {
                stage: EnrollmentLifecycleStage::RelayRecovery,
                error: RuntimeFailure::Restart,
            }
        ));
        fixture.assert_promoted_pair_loads();
        assert_eq!(fixture.runtime.calls.last(), Some(&"relay-start"));
    }

    #[test]
    fn incomplete_recovery_blocks_enrollment_without_touching_hardware() {
        let directory = TestDirectory::new();
        let store_path = directory.0.join("store");
        let store = CatacombPairStore::new(&store_path);
        {
            let mut transaction = store.begin_transaction().unwrap();
            transaction.reserve_recovery().unwrap();
            transaction.write_user(b"synthetic pending user").unwrap();
        }
        let mut transport = ProductTransport::new([], store_path);
        let mut runtime = ProductRuntime {
            calls: Vec::new(),
            restart: Ok(()),
            teardown_seen: Rc::clone(&transport.teardown_seen),
            cleanup_saw_teardown: Rc::clone(&transport.cleanup_saw_teardown),
        };
        let mut retry = NoRetry;
        let mut events = ProductEvents {
            events: VecDeque::new(),
        };

        let error = run_product_transaction(
            &mut runtime,
            &mut transport,
            &mut retry,
            &mut events,
            &store,
            &fdr_record(),
            BiometricUserId::new(i64::from(USER)).unwrap(),
            &mut || {},
            &mut || true,
        )
        .unwrap_err();

        assert!(matches!(
            error,
            EnrollmentLifecycleError::Operation(EnrollmentOperationError::Preparation(
                EnrollmentPreparationError::RecoveryBlocked
            ))
        ));
        assert!(transport.commands.is_empty());
        assert!(matches!(
            store.begin_transaction(),
            Err(CatacombStoreError::PendingExport)
        ));
        assert_eq!(runtime.calls, ["external-fixed-lock"]);
    }

    #[test]
    fn validated_recovery_promotes_before_a_fresh_enrollment_export() {
        let directory = TestDirectory::new();
        let store_path = directory.0.join("store");
        let store = CatacombPairStore::new(&store_path);
        {
            let mut transaction = store.begin_transaction().unwrap();
            transaction.reserve_recovery().unwrap();
            transaction.write_user(b"synthetic recovered user").unwrap();
            transaction
                .write_master(b"synthetic recovered master")
                .unwrap();
        }
        let enrolled_user = b"synthetic enrolled user".to_vec();
        let enrolled_master = b"synthetic enrolled master".to_vec();
        let mut responses = successful_recovery_responses();
        responses.extend(successful_product_responses(
            &enrolled_user,
            &enrolled_master,
        ));
        let mut transport = ProductTransport::new(responses, store_path);
        let mut runtime = ProductRuntime {
            calls: Vec::new(),
            restart: Ok(()),
            teardown_seen: Rc::clone(&transport.teardown_seen),
            cleanup_saw_teardown: Rc::clone(&transport.cleanup_saw_teardown),
        };
        let mut retry = NoRetry;
        let mut events = ProductEvents {
            events: [Ok(completion_event())].into_iter().collect(),
        };

        let result = run_product_transaction(
            &mut runtime,
            &mut transport,
            &mut retry,
            &mut events,
            &store,
            &fdr_record(),
            BiometricUserId::new(i64::from(USER)).unwrap(),
            &mut || {},
            &mut || true,
        )
        .expect("validated recovery allows a fresh enrollment");

        assert_eq!(result.identity, IDENTITY);
        assert_eq!(transport.commands[0..4], [0x22, 0x28, 0x28, 0x31]);
        assert!(transport.responses.is_empty());
        let pair = store.load().unwrap();
        assert_eq!(pair.user(), enrolled_user);
        assert_eq!(pair.master(), enrolled_master);
    }

    #[test]
    fn unsafe_storage_recovery_precedes_every_biometric_command() {
        let directory = TestDirectory::new();
        let store_path = directory.0.join("not-a-directory");
        fs::write(&store_path, b"synthetic blocker").unwrap();
        let store = CatacombPairStore::new(&store_path);
        let mut transport = ProductTransport::new([], store_path);
        let mut runtime = ProductRuntime {
            calls: Vec::new(),
            restart: Ok(()),
            teardown_seen: Rc::clone(&transport.teardown_seen),
            cleanup_saw_teardown: Rc::clone(&transport.cleanup_saw_teardown),
        };
        let mut retry = NoRetry;
        let mut events = ProductEvents {
            events: VecDeque::new(),
        };

        let error = run_product_transaction(
            &mut runtime,
            &mut transport,
            &mut retry,
            &mut events,
            &store,
            &fdr_record(),
            BiometricUserId::new(i64::from(USER)).unwrap(),
            &mut || {},
            &mut || true,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            EnrollmentLifecycleError::Operation(EnrollmentOperationError::Preparation(
                EnrollmentPreparationError::Recovery(CatacombRecoveryError::Store(
                    CatacombStoreError::UnsafeStorage
                ))
            ))
        ));
        assert!(transport.commands.is_empty());
        assert_eq!(runtime.calls, ["external-fixed-lock"]);
    }

    fn successful_product_responses(user_blob: &[u8], master_blob: &[u8]) -> Vec<Vec<u8>> {
        vec![
            MODULE_SERIAL.to_vec(),
            daemon_info(),
            daemon_info(),
            Vec::new(),
            daemon_info(),
            catacomb_states(),
            Vec::new(),
            daemon_info(),
            catacomb_states(),
            encode_i32s(&[300, -1, -1, 1, 1, 1, 1]),
            encode_i32s(&[1, 1, 1, 0, 1, 1, 1, 0]),
            Vec::new(),
            identity_record().to_vec(),
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
            identity_record().to_vec(),
        ]
    }

    fn successful_recovery_responses() -> Vec<Vec<u8>> {
        vec![
            MODULE_SERIAL.to_vec(),
            daemon_info(),
            daemon_info(),
            Vec::new(),
            recovery_daemon_info(),
            Vec::new(),
            Vec::new(),
            recovery_daemon_info(),
            recovery_catacomb_states(&[(u32::MAX, 1)]),
            Vec::new(),
            recovery_daemon_info(),
            recovery_catacomb_states(&[(u32::MAX, 1), (USER as u32, 3)]),
            identity_record().to_vec(),
            0_u32.to_le_bytes().to_vec(),
        ]
    }

    fn recovery_daemon_info() -> Vec<u8> {
        let mut response = daemon_info();
        response[0..4].copy_from_slice(&2_u32.to_le_bytes());
        response
    }

    fn recovery_catacomb_states(entries: &[(u32, u32)]) -> Vec<u8> {
        entries
            .iter()
            .flat_map(|(user_id, state)| {
                user_id.to_le_bytes().into_iter().chain(state.to_le_bytes())
            })
            .collect()
    }

    fn daemon_info() -> Vec<u8> {
        let mut response = vec![0; DAEMON_INFO_SIZE];
        response[0..4].copy_from_slice(&1_u32.to_le_bytes());
        response[4..8].copy_from_slice(
            &u32::try_from(MAX_IDENTITIES)
                .expect("identity limit fits u32")
                .to_le_bytes(),
        );
        response[22] = 1;
        response
    }

    fn catacomb_states() -> Vec<u8> {
        let mut response = Vec::with_capacity(8);
        response.extend_from_slice(&(USER as u32).to_le_bytes());
        response.extend_from_slice(&SECURELY_LOADED_STATE_BITS.to_le_bytes());
        response
    }

    fn encode_i32s(values: &[i32]) -> Vec<u8> {
        let mut response = Vec::with_capacity(values.len() * 4);
        for value in values {
            response.extend_from_slice(&value.to_le_bytes());
        }
        response
    }

    fn identity_record() -> [u8; IDENTITY_V1_SIZE] {
        let mut record = [0; IDENTITY_V1_SIZE];
        record[..4].copy_from_slice(&USER.to_le_bytes());
        record[4..].copy_from_slice(&IDENTITY);
        record
    }

    fn completion_event() -> EnrollmentEvent {
        let payload = identity_record();
        let mut data = Vec::with_capacity(MESA_MESSAGE_HEADER_SIZE + payload.len());
        data.extend_from_slice(&0_u64.to_le_bytes());
        data.extend_from_slice(&MESA_ENROLLMENT_COMPLETE.to_le_bytes());
        data.extend_from_slice(&MESA_MESSAGE_TYPE_V1.to_le_bytes());
        data.extend_from_slice(&0_u64.to_le_bytes());
        data.extend_from_slice(&0_u64.to_le_bytes());
        data.extend_from_slice(&(payload.len() as u64).to_le_bytes());
        data.extend_from_slice(&payload);
        EnrollmentEvent::ServiceStatus(ServiceStatusEvent {
            service: MESA_SERVICE_MESSAGE,
            data,
            reference_timestamp: 0,
            continuous_time_delta: 0,
        })
    }

    fn fdr_record() -> Vec<u8> {
        let mut calibration = vec![0; 96];
        let calibration_size = u32::try_from(calibration.len()).expect("calibration size fits u32");
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
            encoded.push(u8::try_from(content.len()).expect("short DER length fits u8"));
        } else {
            encoded.push(0x81);
            encoded.push(u8::try_from(content.len()).expect("test DER length fits u8"));
        }
        encoded.extend_from_slice(content);
        encoded
    }
}

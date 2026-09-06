//! Operation-scoped access to the SEP product session.

use std::fmt;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

/// A cancellation signal that may be shared with the thread running an SEP operation.
#[derive(Clone, Default)]
pub struct SepCancellation {
    cancelled: Arc<AtomicBool>,
}

impl SepCancellation {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

impl fmt::Debug for SepCancellation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SepCancellation")
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

/// Synchronous cancellation source sampled between bounded SEP receive waits.
pub trait SepCancellationSource {
    #[must_use]
    fn is_cancelled(&self) -> bool;
}

impl SepCancellationSource for SepCancellation {
    fn is_cancelled(&self) -> bool {
        self.is_cancelled()
    }
}

/// The externalized ACM credential, borrowed only for the authorized callback.
///
/// The reference cannot escape the callback. Callers must not copy credential
/// bytes into a value that outlives the operation.
#[derive(Clone, Copy)]
pub struct AuthorizedCredential<'credential>(&'credential [u8; 16]);

impl AuthorizedCredential<'_> {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        self.0
    }
}

impl fmt::Debug for AuthorizedCredential<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorizedCredential([REDACTED])")
    }
}

/// Static, redacted failure classes from an SEP operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SepOperationError {
    RemoteRejected,
    InvalidArgument,
    Clock,
    Timeout,
    Cancelled,
    Lock,
    Entropy,
    Usb,
    Session,
    Acm,
    Teardown,
    Callback,
    Keybag,
    Persistence,
    State,
    NativeBoundary,
}

impl SepOperationError {
    fn from_status(status: i32) -> Self {
        match status {
            1 => Self::RemoteRejected,
            -100 => Self::InvalidArgument,
            -101 => Self::Clock,
            -102 => Self::Timeout,
            -103 => Self::Cancelled,
            -104 => Self::Lock,
            -105 => Self::Entropy,
            -106 => Self::Usb,
            -107 => Self::Session,
            -108 => Self::Acm,
            -109 => Self::Teardown,
            -110 => Self::Callback,
            -111 => Self::Keybag,
            -112 => Self::Persistence,
            -113 => Self::State,
            _ => Self::NativeBoundary,
        }
    }
}

impl fmt::Display for SepOperationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RemoteRejected => "SEP operation was rejected",
            Self::InvalidArgument => "SEP operation input was invalid",
            Self::Clock => "SEP operation clock failed",
            Self::Timeout => "SEP operation timed out",
            Self::Cancelled => "SEP operation was cancelled",
            Self::Lock => "SEP access lock failed",
            Self::Entropy => "SEP operation entropy failed",
            Self::Usb => "SEP device acquisition failed",
            Self::Session => "SEP product session failed",
            Self::Acm => "SEP authorization context failed",
            Self::Teardown => "SEP operation teardown failed",
            Self::Callback => "SEP authorized callback failed",
            Self::Keybag => "SEP keybag operation failed",
            Self::Persistence => "SEP keybag persistence failed",
            Self::State => "SEP keybag state was unavailable or unsafe",
            Self::NativeBoundary => "SEP native boundary failed",
        })
    }
}

impl std::error::Error for SepOperationError {}

/// Maximum receive poll used by the notification relay.
pub const MAX_NOTIFICATION_RELAY_POLL: Duration = Duration::from_secs(1);

/// Holds a shared, existing-only keybag lease and drains `BridgeOS` notifications.
///
/// Readiness runs exactly once after safe persisted state has been loaded, made
/// system, unlocked, validated, and the receive-only loop is ready. This call
/// then blocks until `cancellation` is set or an error occurs. It never creates,
/// serializes, rewrites, or exports an ACM credential.
///
/// # Errors
///
/// Returns a static error for unsafe or absent state, acquisition/protocol
/// failure, invalid time bounds, cancellation before readiness, or teardown.
pub fn run_existing_keybag_notification_relay<F>(
    acquisition_timeout: Duration,
    poll_interval: Duration,
    cancellation: &impl SepCancellationSource,
    ready: F,
) -> Result<(), SepOperationError>
where
    F: FnOnce() -> bool,
{
    let acquisition_timeout_ms = duration_millis(acquisition_timeout)?;
    let poll_timeout_ms = duration_millis(poll_interval)?;
    if poll_interval > MAX_NOTIFICATION_RELAY_POLL {
        return Err(SepOperationError::InvalidArgument);
    }
    let cancellation_predicate = || cancellation.is_cancelled();
    let (status, ready_called) = crate::ffi::run_sep_notification_relay(
        acquisition_timeout_ms,
        poll_timeout_ms,
        &cancellation_predicate,
        ready,
    );
    crate::diagnostics::native(
        crate::diagnostics::Component::Sep,
        crate::diagnostics::Stage::SepLease,
        status,
    );
    if status != 0 {
        return Err(SepOperationError::from_status(status));
    }
    if !ready_called {
        return Err(SepOperationError::NativeBoundary);
    }
    Ok(())
}

/// How the persistent biometric keybag was obtained for enrollment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeybagDisposition {
    Reused,
    CreatedFromAbsence,
}

#[derive(Clone, Copy)]
#[repr(i32)]
enum KeybagMode {
    ReusePromotedExistingOnly = 0,
    CreateIfAbsent = 1,
}

#[derive(Clone, Copy)]
#[repr(i32)]
enum KeybagAuthorization {
    Authentication = 0,
    Enrollment = 1,
}

/// Result of an enrollment lease, preserving an operation result across cleanup failure.
pub enum KeybagLeaseOutcome<T> {
    Completed {
        operation: T,
        keybag: KeybagDisposition,
    },
    AcquisitionFailed(SepOperationError),
    CleanupFailed {
        operation: T,
        keybag: KeybagDisposition,
        error: SepOperationError,
    },
}

/// Result of preparing caller resources under the fixed SEP lock, then using
/// the already-promoted keybag in one native SEP/ACM operation.
pub enum PreparedKeybagLeaseOutcome<T, PreparationError> {
    Completed {
        operation: T,
        keybag: KeybagDisposition,
    },
    PreparationFailed(PreparationError),
    AcquisitionFailed(SepOperationError),
    CleanupFailed {
        operation: T,
        keybag: KeybagDisposition,
        error: SepOperationError,
    },
}

impl<T> fmt::Debug for KeybagLeaseOutcome<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Completed { keybag, .. } => formatter
                .debug_struct("Completed")
                .field("operation", &"[redacted]")
                .field("keybag", keybag)
                .finish(),
            Self::AcquisitionFailed(error) => formatter
                .debug_tuple("AcquisitionFailed")
                .field(error)
                .finish(),
            Self::CleanupFailed { keybag, error, .. } => formatter
                .debug_struct("CleanupFailed")
                .field("operation", &"[redacted]")
                .field("keybag", keybag)
                .field("error", error)
                .finish(),
        }
    }
}

impl<T, PreparationError> fmt::Debug for PreparedKeybagLeaseOutcome<T, PreparationError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Completed { keybag, .. } => formatter
                .debug_struct("Completed")
                .field("operation", &"[redacted]")
                .field("keybag", keybag)
                .finish(),
            Self::PreparationFailed(_) => formatter.write_str("PreparationFailed([redacted])"),
            Self::AcquisitionFailed(error) => formatter
                .debug_tuple("AcquisitionFailed")
                .field(error)
                .finish(),
            Self::CleanupFailed { keybag, error, .. } => formatter
                .debug_struct("CleanupFailed")
                .field("operation", &"[redacted]")
                .field("keybag", keybag)
                .field("error", error)
                .finish(),
        }
    }
}

/// Reuses the valid existing keybag left promoted by a healthy relay handoff,
/// then lends an authorized ACM credential while the keybag and SEP lease are
/// live.
///
/// This post-handoff path never creates, loads, promotes, or unlocks a keybag.
/// Missing, unsafe, or ambiguous state fails closed before SEP device
/// acquisition.
/// The native request always uses the fixed internal `BridgeOS` biometric
/// protocol identity, never a Linux account UID.
pub fn with_enrollment_keybag<T, F>(
    timeout: Duration,
    cancellation: &SepCancellation,
    callback: F,
) -> KeybagLeaseOutcome<T>
where
    F: for<'credential> FnOnce(KeybagDisposition, AuthorizedCredential<'credential>) -> T,
{
    with_keybag(
        KeybagMode::ReusePromotedExistingOnly,
        KeybagAuthorization::Enrollment,
        timeout,
        cancellation,
        callback,
    )
}

/// Reuses the valid keybag left promoted by a healthy relay handoff, then lends
/// an authorized ACM credential while the promoted keybag and SEP lease are
/// live. This same-boot path retains the persisted secret but never loads,
/// promotes, or unlocks the keybag again.
///
/// The native request always uses the fixed internal `BridgeOS` biometric
/// protocol identity, never a Linux account UID.
///
/// # Errors
///
/// Returns a static error for missing, malformed, or unsafe state; acquisition,
/// protocol, cancellation, callback, or teardown failure.
pub fn with_existing_keybag<T, F>(
    timeout: Duration,
    cancellation: &SepCancellation,
    callback: F,
) -> Result<T, SepOperationError>
where
    F: for<'credential> FnOnce(AuthorizedCredential<'credential>) -> T,
{
    let timeout_ms = duration_millis(timeout)?;
    let (status, output) = crate::ffi::run_sep_keybag(
        KeybagMode::ReusePromotedExistingOnly as i32,
        KeybagAuthorization::Authentication as i32,
        timeout_ms,
        &cancellation.cancelled,
        |disposition, credential| {
            if disposition != 0 {
                return None;
            }
            Some(callback(AuthorizedCredential(credential)))
        },
    );
    crate::diagnostics::native(
        crate::diagnostics::Component::Sep,
        crate::diagnostics::Stage::SepLease,
        status,
    );
    if status != 0 {
        return Err(SepOperationError::from_status(status));
    }
    match output {
        Some((0, Some(operation))) => Ok(operation),
        _ => Err(SepOperationError::NativeBoundary),
    }
}

/// Prepares caller-owned protocol resources under the fixed exclusive SEP
/// lock, then reuses the already-promoted existing keybag in the same bounded
/// native operation.
///
/// Ordering is fixed: durable keybag validation, `prepare`, SEP device/session,
/// keybag/ACM authorization, `operation`, ACM/SEP cleanup, prepared-value drop,
/// then fixed-lock release. The original deadline and cancellation source cover
/// lock acquisition, preparation, and SEP acquisition. `operation` receives a
/// mutable loan of the prepared value, which cannot escape this call.
pub fn with_prepared_existing_keybag<Prepared, PreparationError, T, Prepare, Operation>(
    timeout: Duration,
    cancellation: &SepCancellation,
    prepare: Prepare,
    operation: Operation,
) -> PreparedKeybagLeaseOutcome<T, PreparationError>
where
    Prepare: FnOnce() -> Result<Prepared, PreparationError>,
    Operation: for<'credential> FnOnce(&mut Prepared, AuthorizedCredential<'credential>) -> T,
{
    with_prepared_keybag(
        KeybagAuthorization::Authentication,
        timeout,
        cancellation,
        prepare,
        operation,
    )
}

/// Prepares caller-owned protocol resources, then lends an ACM credential
/// carrying the verified Touch ID enrollment policy.
pub fn with_prepared_enrollment_keybag<Prepared, PreparationError, T, Prepare, Operation>(
    timeout: Duration,
    cancellation: &SepCancellation,
    prepare: Prepare,
    operation: Operation,
) -> PreparedKeybagLeaseOutcome<T, PreparationError>
where
    Prepare: FnOnce() -> Result<Prepared, PreparationError>,
    Operation: for<'credential> FnOnce(&mut Prepared, AuthorizedCredential<'credential>) -> T,
{
    with_prepared_keybag(
        KeybagAuthorization::Enrollment,
        timeout,
        cancellation,
        prepare,
        operation,
    )
}

fn with_prepared_keybag<Prepared, PreparationError, T, Prepare, Operation>(
    authorization: KeybagAuthorization,
    timeout: Duration,
    cancellation: &SepCancellation,
    prepare: Prepare,
    operation: Operation,
) -> PreparedKeybagLeaseOutcome<T, PreparationError>
where
    Prepare: FnOnce() -> Result<Prepared, PreparationError>,
    Operation: for<'credential> FnOnce(&mut Prepared, AuthorizedCredential<'credential>) -> T,
{
    let Ok(timeout_ms) = duration_millis(timeout) else {
        return PreparedKeybagLeaseOutcome::AcquisitionFailed(SepOperationError::InvalidArgument);
    };
    let (status, preparation_error, output, prepared_released) =
        crate::ffi::run_sep_prepared_keybag(
            KeybagMode::ReusePromotedExistingOnly as i32,
            authorization as i32,
            timeout_ms,
            &cancellation.cancelled,
            prepare,
            |prepared, disposition, credential| {
                (disposition == 0).then(|| operation(prepared, AuthorizedCredential(credential)))
            },
        );
    let output = output
        .and_then(|(disposition, operation)| operation.map(|operation| (disposition, operation)));
    crate::diagnostics::native(
        crate::diagnostics::Component::Sep,
        crate::diagnostics::Stage::SepLease,
        status,
    );
    prepared_lease_outcome(status, preparation_error, output, prepared_released)
}

/// Creates and persists the biometric keybag only when durable state is absent.
///
/// Durable existing state fails before USB acquisition. The caller must start
/// the relay to load that state; an unexpectedly inactive relay must not replay
/// the mutating load and promotion sequence through this bootstrap path.
pub fn with_bootstrap_keybag<T, F>(
    timeout: Duration,
    cancellation: &SepCancellation,
    callback: F,
) -> KeybagLeaseOutcome<T>
where
    F: for<'credential> FnOnce(KeybagDisposition, AuthorizedCredential<'credential>) -> T,
{
    with_keybag(
        KeybagMode::CreateIfAbsent,
        KeybagAuthorization::Authentication,
        timeout,
        cancellation,
        callback,
    )
}

fn with_keybag<T, F>(
    mode: KeybagMode,
    authorization: KeybagAuthorization,
    timeout: Duration,
    cancellation: &SepCancellation,
    callback: F,
) -> KeybagLeaseOutcome<T>
where
    F: for<'credential> FnOnce(KeybagDisposition, AuthorizedCredential<'credential>) -> T,
{
    let Ok(timeout_ms) = duration_millis(timeout) else {
        return KeybagLeaseOutcome::AcquisitionFailed(SepOperationError::InvalidArgument);
    };
    let (status, output) = crate::ffi::run_sep_keybag(
        mode as i32,
        authorization as i32,
        timeout_ms,
        &cancellation.cancelled,
        |disposition, credential| {
            let disposition = disposition_from_raw(disposition)?;
            Some(callback(disposition, AuthorizedCredential(credential)))
        },
    );
    crate::diagnostics::native(
        crate::diagnostics::Component::Sep,
        crate::diagnostics::Stage::SepLease,
        status,
    );
    lease_outcome(
        status,
        output.and_then(|(disposition, operation)| operation.map(|value| (disposition, value))),
    )
}

fn disposition_from_raw(raw: i32) -> Option<KeybagDisposition> {
    match raw {
        0 => Some(KeybagDisposition::Reused),
        1 => Some(KeybagDisposition::CreatedFromAbsence),
        _ => None,
    }
}

fn lease_outcome<T>(status: i32, output: Option<(i32, T)>) -> KeybagLeaseOutcome<T> {
    let output = output
        .and_then(|(raw, operation)| disposition_from_raw(raw).map(|keybag| (operation, keybag)));
    match (status, output) {
        (0, Some((operation, keybag))) => KeybagLeaseOutcome::Completed { operation, keybag },
        (0, None) => KeybagLeaseOutcome::AcquisitionFailed(SepOperationError::NativeBoundary),
        (status, Some((operation, keybag))) => KeybagLeaseOutcome::CleanupFailed {
            operation,
            keybag,
            error: SepOperationError::from_status(status),
        },
        (status, None) => {
            KeybagLeaseOutcome::AcquisitionFailed(SepOperationError::from_status(status))
        }
    }
}

fn prepared_lease_outcome<T, PreparationError>(
    status: i32,
    preparation_error: Option<PreparationError>,
    output: Option<(i32, T)>,
    prepared_released: bool,
) -> PreparedKeybagLeaseOutcome<T, PreparationError> {
    if let Some(error) = preparation_error {
        return PreparedKeybagLeaseOutcome::PreparationFailed(error);
    }
    if !prepared_released {
        return PreparedKeybagLeaseOutcome::AcquisitionFailed(SepOperationError::NativeBoundary);
    }
    match lease_outcome(status, output) {
        KeybagLeaseOutcome::Completed { operation, keybag } => {
            PreparedKeybagLeaseOutcome::Completed { operation, keybag }
        }
        KeybagLeaseOutcome::AcquisitionFailed(error) => {
            PreparedKeybagLeaseOutcome::AcquisitionFailed(error)
        }
        KeybagLeaseOutcome::CleanupFailed {
            operation,
            keybag,
            error,
        } => PreparedKeybagLeaseOutcome::CleanupFailed {
            operation,
            keybag,
            error,
        },
    }
}

/// Runs one low-level SEP probe session and lends its authorized ACM credential.
///
/// The native owner holds the fixed process-external lock, session, and ACM
/// context for exactly this synchronous call. It destroys the context, wipes
/// the credential, closes all descriptors, and releases the lock before this
/// function returns. The credential reference cannot outlive the callback.
/// The caller-selected audit UID is retained only for native protocol probes;
/// product keybag lifecycles must use [`with_enrollment_keybag`] or
/// [`with_existing_keybag`].
///
/// # Errors
///
/// Returns a static [`SepOperationError`] when the deadline is invalid, the
/// operation is cancelled, native acquisition or protocol work fails, or
/// teardown cannot complete cleanly.
pub fn with_authorized_credential<T, F>(
    timeout: Duration,
    audit_uid: u32,
    cancellation: &SepCancellation,
    callback: F,
) -> Result<T, SepOperationError>
where
    F: for<'credential> FnOnce(AuthorizedCredential<'credential>) -> T,
{
    let timeout_ms = duration_millis(timeout)?;
    let (status, output) = crate::ffi::run_sep_authorized(
        timeout_ms,
        audit_uid,
        &cancellation.cancelled,
        |credential| callback(AuthorizedCredential(credential)),
    );
    crate::diagnostics::native(
        crate::diagnostics::Component::Sep,
        crate::diagnostics::Stage::SepLease,
        status,
    );
    if status != 0 {
        return Err(SepOperationError::from_status(status));
    }
    output.ok_or(SepOperationError::NativeBoundary)
}

fn duration_millis(timeout: Duration) -> Result<u32, SepOperationError> {
    if timeout.is_zero() {
        return Err(SepOperationError::InvalidArgument);
    }
    let rounded = timeout
        .as_millis()
        .checked_add(u128::from(
            !timeout.subsec_nanos().is_multiple_of(1_000_000),
        ))
        .ok_or(SepOperationError::InvalidArgument)?;
    u32::try_from(rounded).map_err(|_| SepOperationError::InvalidArgument)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn cancellation_is_shared_and_one_way() {
        let cancellation = SepCancellation::new();
        let second_owner = cancellation.clone();

        assert!(!cancellation.is_cancelled());
        second_owner.cancel();
        assert!(cancellation.is_cancelled());
    }

    #[test]
    fn timeout_conversion_is_bounded_and_rounds_up() {
        assert_eq!(duration_millis(Duration::from_nanos(1)), Ok(1));
        assert_eq!(
            duration_millis(Duration::from_millis(u64::from(u32::MAX))),
            Ok(u32::MAX)
        );
        assert_eq!(
            duration_millis(Duration::ZERO),
            Err(SepOperationError::InvalidArgument)
        );
        assert_eq!(
            duration_millis(Duration::from_millis(u64::from(u32::MAX) + 1)),
            Err(SepOperationError::InvalidArgument)
        );
    }

    #[test]
    fn relay_poll_bound_is_one_second() {
        assert_eq!(MAX_NOTIFICATION_RELAY_POLL, Duration::from_secs(1));
        assert_eq!(duration_millis(MAX_NOTIFICATION_RELAY_POLL), Ok(1000));
    }

    #[test]
    fn native_keybag_modes_match_the_c_boundary() {
        assert_eq!(KeybagMode::ReusePromotedExistingOnly as i32, 0);
        assert_eq!(KeybagMode::CreateIfAbsent as i32, 1);
    }

    #[test]
    fn relay_rejects_unbounded_poll_before_native_acquisition() {
        let cancellation = SepCancellation::new();
        let ready = Cell::new(false);

        assert_eq!(
            run_existing_keybag_notification_relay(
                Duration::from_secs(1),
                MAX_NOTIFICATION_RELAY_POLL + Duration::from_millis(1),
                &cancellation,
                || {
                    ready.set(true);
                    true
                },
            ),
            Err(SepOperationError::InvalidArgument)
        );
        assert!(!ready.get());
    }

    #[test]
    fn relay_cancellation_before_acquisition_never_reports_ready() {
        let cancellation = SepCancellation::new();
        let ready = Cell::new(false);

        cancellation.cancel();
        assert_eq!(
            run_existing_keybag_notification_relay(
                Duration::from_secs(1),
                Duration::from_millis(25),
                &cancellation,
                || {
                    ready.set(true);
                    true
                },
            ),
            Err(SepOperationError::Cancelled)
        );
        assert!(!ready.get());
    }

    #[test]
    fn errors_and_credentials_are_redacted() {
        let bytes = [0xa5; 16];
        let credential = AuthorizedCredential(&bytes);

        assert_eq!(
            format!("{credential:?}"),
            "AuthorizedCredential([REDACTED])"
        );
        assert_eq!(
            SepOperationError::from_status(12345).to_string(),
            "SEP native boundary failed"
        );
        assert!(!SepOperationError::Acm.to_string().contains("12345"));
    }

    #[test]
    fn lease_outcome_preserves_operation_only_after_callback() {
        assert!(matches!(
            lease_outcome(0, Some((1, 37))),
            KeybagLeaseOutcome::Completed {
                operation: 37,
                keybag: KeybagDisposition::CreatedFromAbsence
            }
        ));
        assert!(matches!(
            lease_outcome(-109, Some((0, 41))),
            KeybagLeaseOutcome::CleanupFailed {
                operation: 41,
                keybag: KeybagDisposition::Reused,
                error: SepOperationError::Teardown
            }
        ));
        assert!(matches!(
            lease_outcome::<u8>(0, None),
            KeybagLeaseOutcome::AcquisitionFailed(SepOperationError::NativeBoundary)
        ));
        assert!(matches!(
            lease_outcome(0, Some((9, 1_u8))),
            KeybagLeaseOutcome::AcquisitionFailed(SepOperationError::NativeBoundary)
        ));
    }

    #[test]
    fn prepared_outcome_preserves_each_failure_domain() {
        assert!(matches!(
            prepared_lease_outcome::<u8, _>(-110, Some("prepare"), None, true),
            PreparedKeybagLeaseOutcome::PreparationFailed("prepare")
        ));
        assert!(matches!(
            prepared_lease_outcome::<u8, ()>(0, None, Some((0, 7)), true),
            PreparedKeybagLeaseOutcome::Completed {
                operation: 7,
                keybag: KeybagDisposition::Reused
            }
        ));
        assert!(matches!(
            prepared_lease_outcome::<u8, ()>(-109, None, Some((0, 9)), true),
            PreparedKeybagLeaseOutcome::CleanupFailed {
                operation: 9,
                keybag: KeybagDisposition::Reused,
                error: SepOperationError::Teardown
            }
        ));
        assert!(matches!(
            prepared_lease_outcome::<u8, ()>(0, None, Some((0, 1)), false),
            PreparedKeybagLeaseOutcome::AcquisitionFailed(SepOperationError::NativeBoundary)
        ));
    }
}

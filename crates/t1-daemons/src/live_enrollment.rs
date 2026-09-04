//! Fixed production composition for one broker-authorized enrollment.

use std::cell::RefCell;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use t1_bridge::live_operation::{
    LiveBridgeConnection, LiveClientPreparationError, LivePolicyRetryRuntime,
    PreparedLiveBridgeConnection,
};
use t1_bridge::policy::BiometricUserId;
use t1_platform::sep::SepCancellation;

use crate::auth_protocol::{BIOMETRIC_USER_ID, Purpose};
use crate::auth_session::ActiveAuthentication;
use crate::catacomb_store::{CatacombPairStore, CatacombPairTransaction};
use crate::enrollment_lifecycle::{
    EnrollmentTransactionSuccess, claim_enrollment_owner, run_enrollment_transaction_after_handoff,
    with_enrollment_relay_handoff,
};
use crate::enrollment_owner::{EnrollmentOwner, EnrollmentOwnerStore};
use crate::enrollment_transaction::{prepare_enrollment_transaction, run_reserved_enrollment};
use crate::keybag_relay::SystemctlKeybagRelay;
use crate::machine_data::read_machine_calibration;
use crate::overlay::{DEFAULT_STATE_PATH, OverlaySession, OverlayState};
use crate::request_ids::LinuxRequestIdSource;
use crate::sep_lifecycle::{KeybagRelayControl, SepEnrollmentLeaseRuntime, bootstrap_keybag};
use crate::xart_live::ValidatedNcmInterface;

const STATE_DIRECTORY: &str = "/var/lib/t1bridge/touch-id/catacombs";
const RELAY_CONTROL_TIMEOUT: Duration = Duration::from_secs(30);
const SEP_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const ENROLLMENT_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const CANCELLATION_POLL: Duration = Duration::from_millis(25);

struct PreparedLiveEnrollment<'store> {
    connection: PreparedLiveBridgeConnection,
    transaction: Option<CatacombPairTransaction<'store>>,
}

struct EnrollmentOverlayTeardown<'session>(&'session RefCell<Option<OverlaySession>>);

impl Drop for EnrollmentOverlayTeardown<'_> {
    fn drop(&mut self) {
        drop(self.0.borrow_mut().take());
    }
}

/// Payload-free failure from one complete live enrollment composition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiveEnrollmentError {
    InvalidOperation,
    Cancelled,
    Calibration,
    DeviceDiscovery,
    Connection,
    RequestIds,
    OperationSetup,
    RelayControl,
    OwnerClaim,
    RelayHealth,
    KeybagBootstrap,
    RelayStart,
    RelayVerification,
    RelayRecovery,
    Enrollment,
    CancellationMonitor,
}

impl fmt::Display for LiveEnrollmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidOperation => "broker enrollment operation is invalid",
            Self::Cancelled => "enrollment was cancelled",
            Self::Calibration => "enrollment calibration is unavailable",
            Self::DeviceDiscovery => "T1 biometric device discovery failed",
            Self::Connection => "T1 biometric connection failed",
            Self::RequestIds => "biometric request identifiers are unavailable",
            Self::OperationSetup => "biometric operation setup failed",
            Self::RelayControl => "keybag relay control setup failed",
            Self::OwnerClaim => "enrollment owner preflight failed",
            Self::RelayHealth => "keybag relay health check failed",
            Self::KeybagBootstrap => "protected keybag bootstrap failed",
            Self::RelayStart => "keybag relay start failed",
            Self::RelayVerification => "keybag relay verification failed",
            Self::RelayRecovery => "keybag relay recovery failed",
            Self::Enrollment => "enrollment transaction failed",
            Self::CancellationMonitor => "enrollment cancellation monitor failed",
        })
    }
}

impl std::error::Error for LiveEnrollmentError {}

/// Runs one enrollment selected and authenticated by the active broker session.
///
/// All paths, identities, timeouts, service actions, and hardware endpoints are
/// fixed or come from the broker's kernel-credential-derived typed operation.
/// The candidate UID is used only for the local durable owner claim; the SEP
/// lifecycle supplies `BridgeOS`'s fixed internal biometric protocol identity.
/// Cosmetic overlay failures never change the biometric result.
///
/// # Errors
///
/// Returns only a payload-free stage failure. Hardware, storage, identifiers,
/// callback contents, and protected state are never included in diagnostics.
#[allow(clippy::too_many_lines)]
pub fn run_live_enrollment(
    active: &ActiveAuthentication,
) -> Result<EnrollmentTransactionSuccess, LiveEnrollmentError> {
    if active.purpose() != Purpose::Enrollment {
        return Err(LiveEnrollmentError::InvalidOperation);
    }
    let candidate = active
        .enrollment_owner_candidate()
        .ok_or(LiveEnrollmentError::InvalidOperation)?;
    let owner = EnrollmentOwner::new(candidate.user_id())
        .map_err(|_| LiveEnrollmentError::InvalidOperation)?;
    if active.is_cancelled() {
        return Err(LiveEnrollmentError::Cancelled);
    }

    let calibration = read_machine_calibration().map_err(|_| LiveEnrollmentError::Calibration)?;
    let interface =
        ValidatedNcmInterface::discover().map_err(|_| LiveEnrollmentError::DeviceDiscovery)?;
    let store = CatacombPairStore::new(STATE_DIRECTORY);
    let owner_store = EnrollmentOwnerStore::new(STATE_DIRECTORY);
    let mut relay = SystemctlKeybagRelay::new(RELAY_CONTROL_TIMEOUT)
        .map_err(|_| LiveEnrollmentError::RelayControl)?;

    let result = with_cancellation_bridge(
        || active.is_cancelled(),
        |sep_cancellation| {
            prepare_owner_and_relay(
                &mut relay,
                || {
                    claim_enrollment_owner(&store, &owner_store, owner)
                        .map_err(|_| LiveEnrollmentError::OwnerClaim)?;
                    if active.is_cancelled() {
                        Err(LiveEnrollmentError::Cancelled)
                    } else {
                        Ok(())
                    }
                },
                || {
                    bootstrap_keybag(SEP_OPERATION_TIMEOUT, sep_cancellation)
                        .map(|_| ())
                        .inspect_err(|error| {
                            eprintln!("t1-touchid-auth: {error}");
                        })
                },
            )?;
            if active.is_cancelled() {
                return Err(LiveEnrollmentError::Cancelled);
            }

            match with_enrollment_relay_handoff(&mut relay, |_| {
                if active.is_cancelled() {
                    return Err(LiveEnrollmentError::Cancelled);
                }
                let user_id = BiometricUserId::new(i64::from(BIOMETRIC_USER_ID))
                    .map_err(|_| LiveEnrollmentError::OperationSetup)?;
                let mut lease =
                    SepEnrollmentLeaseRuntime::new(SEP_OPERATION_TIMEOUT, sep_cancellation.clone());
                match run_enrollment_transaction_after_handoff(
                    &mut lease,
                    || {
                        if active.is_cancelled() {
                            return Err(LiveEnrollmentError::Cancelled);
                        }
                        let connection = LiveBridgeConnection::connect(interface.kernel_index())
                            .map_err(|_| LiveEnrollmentError::Connection)?;
                        let request_ids = LinuxRequestIdSource::open()
                            .map_err(|_| LiveEnrollmentError::RequestIds)?;
                        let mut transaction = None;
                        let connection = connection
                            .prepare(request_ids, |transport| {
                                transaction = Some(
                                    prepare_enrollment_transaction(
                                        transport,
                                        &store,
                                        user_id,
                                        calibration.as_bytes(),
                                    )
                                    .map_err(|_| LiveEnrollmentError::Enrollment)?,
                                );
                                Ok(())
                            })
                            .map_err(|error| match error {
                                LiveClientPreparationError::Connection(_) => {
                                    LiveEnrollmentError::OperationSetup
                                }
                                LiveClientPreparationError::Preparation(error) => error,
                            })?;
                        Ok(PreparedLiveEnrollment {
                            connection,
                            transaction,
                        })
                    },
                    |prepared, credential| {
                        (|| {
                            let request_ids = LinuxRequestIdSource::open()
                                .map_err(|_| LiveEnrollmentError::RequestIds)?;
                            let operation = prepared
                                .connection
                                .start_operation(request_ids)
                                .map_err(|_| LiveEnrollmentError::OperationSetup)?;
                            let (mut transport, mut events) = operation
                                .into_adapters(ENROLLMENT_TIMEOUT, || active.is_cancelled())
                                .map_err(|_| LiveEnrollmentError::OperationSetup)?;
                            let transaction = prepared
                                .transaction
                                .take()
                                .ok_or(LiveEnrollmentError::OperationSetup)?;
                            let mut retry_runtime = LivePolicyRetryRuntime::new();
                            let overlay = RefCell::new(None);
                            let _teardown = EnrollmentOverlayTeardown(&overlay);
                            let mut before_start = || {
                                *overlay.borrow_mut() = OverlaySession::activate_optional(
                                    DEFAULT_STATE_PATH,
                                    OverlayState::Enrollment,
                                );
                            };
                            let mut progress =
                                |value: t1_bridge::enroll_workflow::EnrollmentProgress| {
                                    if let Some(overlay) = overlay.borrow().as_ref() {
                                        overlay.update_progress(
                                            u32::try_from(value.value()).unwrap_or(u32::MAX),
                                        );
                                    }
                                };
                            run_reserved_enrollment(
                                &mut transport,
                                &mut retry_runtime,
                                &mut events,
                                transaction,
                                user_id,
                                credential,
                                Some(&mut progress),
                                &mut before_start,
                                &mut || active.close_cancellation(),
                            )
                            .map_err(|_| LiveEnrollmentError::Enrollment)
                        })()
                    },
                ) {
                    Err(crate::enrollment_lifecycle::EnrollmentLifecycleError::Operation(
                        crate::enrollment_lifecycle::EnrollmentOperationError::Preparation(
                            LiveEnrollmentError::Cancelled,
                        )
                        | crate::enrollment_lifecycle::EnrollmentOperationError::Transaction(
                            LiveEnrollmentError::Cancelled,
                        ),
                    )) => Err(LiveEnrollmentError::Cancelled),
                    Err(crate::enrollment_lifecycle::EnrollmentLifecycleError::Operation(
                        crate::enrollment_lifecycle::EnrollmentOperationError::Preparation(error)
                        | crate::enrollment_lifecycle::EnrollmentOperationError::Transaction(error),
                    )) => Err(error),
                    Err(_) => Err(LiveEnrollmentError::Enrollment),
                    Ok(success) => Ok(success),
                }
            }) {
                Ok(success) => Ok(success),
                Err(crate::enrollment_lifecycle::EnrollmentLifecycleError::Operation(error)) => {
                    Err(error)
                }
                Err(crate::enrollment_lifecycle::EnrollmentLifecycleError::Runtime {
                    stage: crate::enrollment_lifecycle::EnrollmentLifecycleStage::RelayRecovery,
                    ..
                }) => Err(LiveEnrollmentError::RelayRecovery),
                Err(_) => Err(LiveEnrollmentError::Enrollment),
            }
        },
    )?;

    match result {
        Err(LiveEnrollmentError::RelayRecovery) => Err(LiveEnrollmentError::RelayRecovery),
        Err(_) if active.is_cancelled() => Err(LiveEnrollmentError::Cancelled),
        result => result,
    }
}

fn prepare_owner_and_relay<Relay, Claim, Bootstrap, BootstrapError>(
    relay: &mut Relay,
    claim: Claim,
    bootstrap: Bootstrap,
) -> Result<(), LiveEnrollmentError>
where
    Relay: KeybagRelayControl,
    Claim: FnOnce() -> Result<(), LiveEnrollmentError>,
    Bootstrap: FnOnce() -> Result<(), BootstrapError>,
{
    claim()?;
    prepare_relay(relay, bootstrap)
}

fn prepare_relay<Relay, Bootstrap, BootstrapError>(
    relay: &mut Relay,
    bootstrap: Bootstrap,
) -> Result<(), LiveEnrollmentError>
where
    Relay: KeybagRelayControl,
    Bootstrap: FnOnce() -> Result<(), BootstrapError>,
{
    if relay
        .is_active()
        .map_err(|_| LiveEnrollmentError::RelayHealth)?
    {
        return Ok(());
    }
    bootstrap().map_err(|_| LiveEnrollmentError::KeybagBootstrap)?;
    relay.start().map_err(|_| LiveEnrollmentError::RelayStart)?;
    if !relay
        .is_active()
        .map_err(|_| LiveEnrollmentError::RelayVerification)?
    {
        return Err(LiveEnrollmentError::RelayVerification);
    }
    Ok(())
}

fn with_cancellation_bridge<T, Cancelled, Operation>(
    cancelled: Cancelled,
    operation: Operation,
) -> Result<T, LiveEnrollmentError>
where
    Cancelled: Fn() -> bool + Send + Sync,
    Operation: FnOnce(&SepCancellation) -> T,
{
    let sep_cancellation = SepCancellation::new();
    let finished = Arc::new(AtomicBool::new(false));
    thread::scope(|scope| {
        let monitor_finished = Arc::clone(&finished);
        let monitor_cancellation = sep_cancellation.clone();
        let monitor = scope.spawn(move || {
            while !monitor_finished.load(Ordering::Acquire) {
                if cancelled() {
                    monitor_cancellation.cancel();
                    break;
                }
                thread::park_timeout(CANCELLATION_POLL);
            }
        });
        let monitor_thread = monitor.thread().clone();
        let stop = MonitorStop {
            finished,
            monitor_thread,
        };
        let result = operation(&sep_cancellation);
        drop(stop);
        monitor
            .join()
            .map_err(|_| LiveEnrollmentError::CancellationMonitor)?;
        Ok(result)
    })
}

struct MonitorStop {
    finished: Arc<AtomicBool>,
    monitor_thread: thread::Thread,
}

impl Drop for MonitorStop {
    fn drop(&mut self) {
        self.finished.store(true, Ordering::Release);
        self.monitor_thread.unpark();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use std::sync::atomic::AtomicUsize;
    use std::time::Instant;

    struct FakeRelay {
        health: Vec<Result<bool, ()>>,
        health_index: usize,
        starts: usize,
        start_result: Result<(), ()>,
    }

    impl FakeRelay {
        fn new(health: impl IntoIterator<Item = Result<bool, ()>>) -> Self {
            Self {
                health: health.into_iter().collect(),
                health_index: 0,
                starts: 0,
                start_result: Ok(()),
            }
        }
    }

    impl KeybagRelayControl for FakeRelay {
        type Error = ();

        fn is_active(&mut self) -> Result<bool, Self::Error> {
            let result = self.health[self.health_index];
            self.health_index += 1;
            result
        }

        fn stop(&mut self) -> Result<(), Self::Error> {
            unreachable!("relay preparation never stops an inactive relay")
        }

        fn start(&mut self) -> Result<(), Self::Error> {
            self.starts += 1;
            self.start_result
        }
    }

    #[test]
    fn active_relay_skips_bootstrap_and_start() {
        let mut relay = FakeRelay::new([Ok(true)]);
        let bootstraps = AtomicUsize::new(0);
        assert_eq!(
            prepare_relay(&mut relay, || {
                bootstraps.fetch_add(1, Ordering::Relaxed);
                Ok::<(), Infallible>(())
            }),
            Ok(())
        );
        assert_eq!(bootstraps.load(Ordering::Relaxed), 0);
        assert_eq!(relay.starts, 0);
        assert_eq!(relay.health_index, 1);
    }

    #[test]
    fn inactive_relay_bootstraps_starts_and_verifies() {
        let mut relay = FakeRelay::new([Ok(false), Ok(true)]);
        let bootstraps = AtomicUsize::new(0);
        assert_eq!(
            prepare_relay(&mut relay, || {
                bootstraps.fetch_add(1, Ordering::Relaxed);
                Ok::<(), Infallible>(())
            }),
            Ok(())
        );
        assert_eq!(bootstraps.load(Ordering::Relaxed), 1);
        assert_eq!(relay.starts, 1);
        assert_eq!(relay.health_index, 2);
    }

    #[test]
    fn relay_preparation_failures_stop_at_the_exact_stage() {
        let mut health_failure = FakeRelay::new([Err(())]);
        assert_eq!(
            prepare_relay(&mut health_failure, || Ok::<(), ()>(())),
            Err(LiveEnrollmentError::RelayHealth)
        );

        let mut bootstrap_failure = FakeRelay::new([Ok(false)]);
        assert_eq!(
            prepare_relay(&mut bootstrap_failure, || Err::<(), ()>(())),
            Err(LiveEnrollmentError::KeybagBootstrap)
        );
        assert_eq!(bootstrap_failure.starts, 0);

        let mut start_failure = FakeRelay::new([Ok(false)]);
        start_failure.start_result = Err(());
        assert_eq!(
            prepare_relay(&mut start_failure, || Ok::<(), ()>(())),
            Err(LiveEnrollmentError::RelayStart)
        );

        let mut verification_failure = FakeRelay::new([Ok(false), Ok(false)]);
        assert_eq!(
            prepare_relay(&mut verification_failure, || Ok::<(), ()>(())),
            Err(LiveEnrollmentError::RelayVerification)
        );
    }

    #[test]
    fn owner_claim_failure_prevents_relay_or_bootstrap_work() {
        let mut relay = FakeRelay::new([Ok(false)]);
        let bootstraps = AtomicUsize::new(0);
        assert_eq!(
            prepare_owner_and_relay(
                &mut relay,
                || Err(LiveEnrollmentError::OwnerClaim),
                || {
                    bootstraps.fetch_add(1, Ordering::Relaxed);
                    Ok::<(), Infallible>(())
                },
            ),
            Err(LiveEnrollmentError::OwnerClaim)
        );
        assert_eq!(relay.health_index, 0);
        assert_eq!(relay.starts, 0);
        assert_eq!(bootstraps.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn cancellation_bridge_reaches_sep_and_stops_cleanly() {
        let cancelled = AtomicBool::new(false);
        let observed = with_cancellation_bridge(
            || cancelled.load(Ordering::Acquire),
            |sep_cancellation| {
                cancelled.store(true, Ordering::Release);
                let deadline = Instant::now() + Duration::from_secs(1);
                while !sep_cancellation.is_cancelled() && Instant::now() < deadline {
                    thread::yield_now();
                }
                sep_cancellation.is_cancelled()
            },
        );
        assert_eq!(observed, Ok(true));
    }
}

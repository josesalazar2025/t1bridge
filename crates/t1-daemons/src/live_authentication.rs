#![cfg(feature = "auth-broker-service")]

//! Fixed production composition for one broker-authorized authentication.

use std::cell::RefCell;
use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use t1_bridge::control::ensure_fdr_calibration_loaded;
use t1_bridge::live_operation::{
    LiveBridgeConnection, LiveClientPreparationError, LivePolicyRetryRuntime,
    PreparedLiveBridgeConnection,
};
use t1_bridge::match_workflow::MatchOutcome;
use t1_platform::sep::{
    PreparedKeybagLeaseOutcome, SepCancellation, with_prepared_existing_keybag,
};

use crate::auth_feedback::apply_authentication_feedback;
use crate::auth_lifecycle::{
    AuthenticationLifecycleError, AuthenticationLifecycleStage, with_authentication_relay_handoff,
};
use crate::auth_protocol::{MAX_MATCH_TIMEOUT, Purpose};
use crate::auth_session::{
    ActiveAuthentication, AuthenticationCompletion, AuthenticationProductInputs,
    AuthenticationSessionFailure, run_authentication_product,
};
use crate::catacomb_store::CatacombPairStore;
use crate::enrollment_owner::EnrollmentOwnerStore;
use crate::keybag_relay::SystemctlKeybagRelay;
use crate::machine_data::read_machine_calibration;
use crate::overlay::{DEFAULT_STATE_PATH, OverlaySession};
use crate::request_ids::LinuxRequestIdSource;
use crate::xart_live::ValidatedNcmInterface;

const STATE_DIRECTORY: &str = "/var/lib/t1bridge/touch-id/catacombs";
const RELAY_CONTROL_TIMEOUT: Duration = Duration::from_secs(30);
const SEP_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const CANCELLATION_POLL: Duration = Duration::from_millis(25);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LiveAuthenticationSetupError {
    Calibration,
    DeviceDiscovery,
    Connection,
    RequestIds,
    OperationSetup,
    RelayControl,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CancellationMonitorError;

/// Runs one post-enrollment match selected and authenticated by the broker.
///
/// Only `AUTHENTICATE` and `APPROVE` are accepted. The Linux authorization
/// owner is reloaded from fixed, root-private state before relay, SEP, or
/// biometric hardware work begins, but its UID is never sent to `BridgeOS`. The
/// SEP lifecycle supplies its fixed internal protocol identity by construction.
/// Callback and SEP cancellation both derive from the same token-associated
/// broker event. The fixed ordering is relay stop, external SEP lock, `BridgeXPC`
/// HELLO/version/FDR preparation, existing-keybag ACM authorization, policy and
/// paired restore, match-scoped overlay, Start/callback/terminal Cancel,
/// feedback/overlay teardown, ACM/SEP release, `BridgeXPC` close, lock release,
/// then mandatory relay restart. Overlay state remains best-effort presentation
/// and cannot change the returned completion.
#[must_use]
pub fn run_live_authentication(active: &ActiveAuthentication) -> AuthenticationCompletion {
    run_with_owner_and_cancellation(
        active,
        || EnrollmentOwnerStore::new(STATE_DIRECTORY).load(),
        |sep_cancellation| run_live_product(active, sep_cancellation),
    )
}

fn run_live_product(
    active: &ActiveAuthentication,
    sep_cancellation: &SepCancellation,
) -> Result<AuthenticationCompletion, LiveAuthenticationSetupError> {
    let calibration =
        read_machine_calibration().map_err(|_| LiveAuthenticationSetupError::Calibration)?;
    let interface = ValidatedNcmInterface::discover()
        .map_err(|_| LiveAuthenticationSetupError::DeviceDiscovery)?;
    let mut relay = SystemctlKeybagRelay::new(RELAY_CONTROL_TIMEOUT)
        .map_err(|_| LiveAuthenticationSetupError::RelayControl)?;

    match with_authentication_relay_handoff(&mut relay, |_| {
        if active.is_cancelled() {
            return Ok(cancelled_completion(active));
        }
        let outcome = with_prepared_existing_keybag(
            SEP_OPERATION_TIMEOUT,
            sep_cancellation,
            || {
                if active.is_cancelled() {
                    return Err(LiveAuthenticationSetupError::OperationSetup);
                }
                let connection = LiveBridgeConnection::connect(interface.kernel_index())
                    .map_err(|_| LiveAuthenticationSetupError::Connection)?;
                let request_ids = LinuxRequestIdSource::open()
                    .map_err(|_| LiveAuthenticationSetupError::RequestIds)?;
                connection
                    .prepare(request_ids, |transport| {
                        ensure_fdr_calibration_loaded(transport, calibration.as_bytes())
                            .map(|_| ())
                            .map_err(|_| LiveAuthenticationSetupError::Calibration)
                    })
                    .map_err(|error| match error {
                        LiveClientPreparationError::Connection(_) => {
                            LiveAuthenticationSetupError::OperationSetup
                        }
                        LiveClientPreparationError::Preparation(error) => error,
                    })
            },
            |prepared, credential| run_prepared_product(active, prepared, credential.as_bytes()),
        );
        match outcome {
            PreparedKeybagLeaseOutcome::Completed { operation, .. } => operation,
            PreparedKeybagLeaseOutcome::PreparationFailed(error) => Err(error),
            PreparedKeybagLeaseOutcome::AcquisitionFailed(_)
            | PreparedKeybagLeaseOutcome::CleanupFailed { .. } => Ok(failed_completion(
                active,
                AuthenticationSessionFailure::ExclusiveSepAndAcm,
            )),
        }
    }) {
        Ok(completion) => Ok(completion),
        Err(AuthenticationLifecycleError::Operation(error)) => Err(error),
        Err(AuthenticationLifecycleError::RelayInactive) => Ok(failed_completion(
            active,
            AuthenticationSessionFailure::RelayInactive,
        )),
        Err(AuthenticationLifecycleError::Runtime { stage, .. }) => {
            let failure = match stage {
                AuthenticationLifecycleStage::RelayHealth => {
                    AuthenticationSessionFailure::RelayHealth
                }
                AuthenticationLifecycleStage::RelayStop => AuthenticationSessionFailure::RelayStop,
                AuthenticationLifecycleStage::RelayRecovery => {
                    AuthenticationSessionFailure::RelayRecovery
                }
            };
            Ok(failed_completion(active, failure))
        }
    }
}

fn run_prepared_product(
    active: &ActiveAuthentication,
    prepared: &mut PreparedLiveBridgeConnection,
    credential: &[u8],
) -> Result<AuthenticationCompletion, LiveAuthenticationSetupError> {
    let request_ids =
        LinuxRequestIdSource::open().map_err(|_| LiveAuthenticationSetupError::RequestIds)?;
    let operation = prepared
        .start_operation(request_ids)
        .map_err(|_| LiveAuthenticationSetupError::OperationSetup)?;
    let (mut transport, mut events) = operation
        .into_adapters(MAX_MATCH_TIMEOUT, || active.is_cancelled())
        .map_err(|_| LiveAuthenticationSetupError::OperationSetup)?;
    let mut retry_runtime = LivePolicyRetryRuntime::new();
    let store = CatacombPairStore::new(STATE_DIRECTORY);
    let overlay = RefCell::new(None);
    let mut before_match = || {
        *overlay.borrow_mut() =
            OverlaySession::activate_optional(DEFAULT_STATE_PATH, active.initial_overlay_state());
    };
    let mut after_match = |outcome| {
        let mut overlay = overlay.borrow_mut();
        let _: Result<MatchOutcome, Infallible> =
            apply_authentication_feedback(Ok(outcome), overlay.as_mut());
    };
    let mut teardown_presentation = || {
        drop(overlay.borrow_mut().take());
    };

    Ok(run_authentication_product(
        active,
        credential,
        AuthenticationProductInputs {
            transport: &mut transport,
            retry_runtime: &mut retry_runtime,
            events: &mut events,
            durable_pair: Some(&store),
            before_match: &mut before_match,
            after_match: &mut after_match,
            teardown_presentation: &mut teardown_presentation,
        },
    ))
}

fn run_with_owner_and_cancellation<Owner, OwnerState, OwnerError, Worker, WorkerError>(
    active: &ActiveAuthentication,
    load_owner: Owner,
    worker: Worker,
) -> AuthenticationCompletion
where
    Owner: FnOnce() -> Result<OwnerState, OwnerError>,
    Worker: FnOnce(&SepCancellation) -> Result<AuthenticationCompletion, WorkerError>,
{
    if !matches!(active.purpose(), Purpose::Authenticate | Purpose::Approve) {
        return failed_completion(active, AuthenticationSessionFailure::Operation);
    }
    if active.is_cancelled() {
        return cancelled_completion(active);
    }
    let Ok(_owner) = load_owner() else {
        return failed_completion(active, AuthenticationSessionFailure::InvalidOperationUser);
    };
    if active.is_cancelled() {
        return cancelled_completion(active);
    }

    let result = with_cancellation_bridge(active, worker);
    match result {
        Ok(Ok(completion)) if active.is_cancelled() && completion.result().is_ok() => {
            cancelled_completion(active)
        }
        Ok(Ok(completion)) => completion,
        Ok(Err(_)) | Err(CancellationMonitorError) => {
            failed_completion(active, AuthenticationSessionFailure::Operation)
        }
    }
}

fn cancelled_completion(active: &ActiveAuthentication) -> AuthenticationCompletion {
    active.completion_for_worker(Ok(MatchOutcome::Cancelled))
}

fn failed_completion(
    active: &ActiveAuthentication,
    failure: AuthenticationSessionFailure,
) -> AuthenticationCompletion {
    active.completion_for_worker(Err(failure))
}

fn with_cancellation_bridge<T>(
    active: &ActiveAuthentication,
    operation: impl FnOnce(&SepCancellation) -> T,
) -> Result<T, CancellationMonitorError> {
    let sep_cancellation = SepCancellation::new();
    let finished = Arc::new(AtomicBool::new(false));
    thread::scope(|scope| {
        let monitor_finished = Arc::clone(&finished);
        let monitor_cancellation = sep_cancellation.clone();
        let monitor = scope.spawn(move || {
            while !monitor_finished.load(Ordering::Acquire) {
                if active.is_cancelled() {
                    monitor_cancellation.cancel();
                    break;
                }
                thread::park_timeout(CANCELLATION_POLL);
            }
        });
        let stop = MonitorStop {
            finished,
            monitor_thread: monitor.thread().clone(),
        };
        let result = operation(&sep_cancellation);
        drop(stop);
        monitor.join().map_err(|_| CancellationMonitorError)?;
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
    use std::sync::atomic::AtomicU32;
    use std::time::Instant;

    use crate::auth_protocol::{
        APPROVE_REQUEST, AUTHENTICATE_REQUEST, AccessPolicy, ENROLL_REQUEST, PeerAddressFamily,
        PeerMetadata, Response,
    };
    use crate::auth_session::{BrokerSessionCoordinator, SessionDecision};

    const OWNER_UID: u32 = 42_000;

    fn active_for(request: &[u8]) -> (BrokerSessionCoordinator, ActiveAuthentication) {
        let mut coordinator = BrokerSessionCoordinator::default();
        let peer = PeerMetadata {
            address_family: PeerAddressFamily::Local,
            user_id: OWNER_UID,
            group_id: 42_001,
        };
        let policy = AccessPolicy::new(OWNER_UID).expect("synthetic owner is non-root");
        let SessionDecision::Start(active) = coordinator.dispatch(peer, policy, request) else {
            panic!("synthetic authorized request must start")
        };
        (coordinator, active)
    }

    #[test]
    fn linux_owner_is_revalidated_but_not_forwarded_to_the_worker() {
        for (request, owner_uid) in [
            (AUTHENTICATE_REQUEST.as_slice(), OWNER_UID),
            (APPROVE_REQUEST.as_slice(), OWNER_UID + 1),
        ] {
            let (mut coordinator, active) = active_for(request);
            let owner_calls = AtomicU32::new(0);
            let completion = run_with_owner_and_cancellation(
                &active,
                || {
                    owner_calls.fetch_add(1, Ordering::Relaxed);
                    Ok::<_, Infallible>(owner_uid)
                },
                |_| Ok::<_, Infallible>(active.completion_for_worker(Ok(MatchOutcome::Matched))),
            );

            assert_eq!(owner_calls.load(Ordering::Relaxed), 1);
            assert_eq!(completion.result(), Ok(MatchOutcome::Matched));
            assert_eq!(coordinator.finish_for(&active, &completion), Response::Okay);
        }
    }

    #[test]
    fn enrollment_is_rejected_before_owner_or_worker_access() {
        let (_coordinator, active) = active_for(ENROLL_REQUEST);
        let owner_calls = AtomicU32::new(0);
        let worker_calls = AtomicU32::new(0);
        let completion = run_with_owner_and_cancellation(
            &active,
            || {
                owner_calls.fetch_add(1, Ordering::Relaxed);
                Ok::<_, Infallible>(OWNER_UID)
            },
            |_| {
                worker_calls.fetch_add(1, Ordering::Relaxed);
                Ok::<_, Infallible>(active.completion_for_worker(Ok(MatchOutcome::Matched)))
            },
        );

        assert_eq!(owner_calls.load(Ordering::Relaxed), 0);
        assert_eq!(worker_calls.load(Ordering::Relaxed), 0);
        assert_eq!(
            completion.result(),
            Err(AuthenticationSessionFailure::Operation)
        );
    }

    #[test]
    fn owner_failure_stops_before_relay_sep_or_hardware_worker() {
        let (_coordinator, active) = active_for(AUTHENTICATE_REQUEST);
        let worker_calls = AtomicU32::new(0);
        let completion = run_with_owner_and_cancellation(
            &active,
            || Err::<u32, _>(()),
            |_| {
                worker_calls.fetch_add(1, Ordering::Relaxed);
                Ok::<_, Infallible>(active.completion_for_worker(Ok(MatchOutcome::Matched)))
            },
        );

        assert_eq!(worker_calls.load(Ordering::Relaxed), 0);
        assert_eq!(
            completion.result(),
            Err(AuthenticationSessionFailure::InvalidOperationUser)
        );
    }

    #[test]
    fn preexisting_cancellation_skips_owner_and_worker() {
        let (mut coordinator, active) = active_for(APPROVE_REQUEST);
        assert!(coordinator.client_disconnected(&active));
        let owner_calls = AtomicU32::new(0);
        let worker_calls = AtomicU32::new(0);
        let completion = run_with_owner_and_cancellation(
            &active,
            || {
                owner_calls.fetch_add(1, Ordering::Relaxed);
                Ok::<_, Infallible>(OWNER_UID)
            },
            |_| {
                worker_calls.fetch_add(1, Ordering::Relaxed);
                Ok::<_, Infallible>(active.completion_for_worker(Ok(MatchOutcome::Matched)))
            },
        );

        assert_eq!(owner_calls.load(Ordering::Relaxed), 0);
        assert_eq!(worker_calls.load(Ordering::Relaxed), 0);
        assert_eq!(completion.result(), Ok(MatchOutcome::Cancelled));
    }

    #[test]
    fn broker_cancellation_reaches_sep_and_overrides_a_late_match() {
        let (mut coordinator, active) = active_for(AUTHENTICATE_REQUEST);
        let completion = run_with_owner_and_cancellation(
            &active,
            || Ok::<_, Infallible>(OWNER_UID),
            |sep_cancellation| {
                assert!(coordinator.client_disconnected(&active));
                let deadline = Instant::now() + Duration::from_secs(1);
                while !sep_cancellation.is_cancelled() && Instant::now() < deadline {
                    thread::yield_now();
                }
                assert!(sep_cancellation.is_cancelled());
                Ok::<_, Infallible>(active.completion_for_worker(Ok(MatchOutcome::Matched)))
            },
        );

        assert_eq!(completion.result(), Ok(MatchOutcome::Cancelled));
    }

    #[test]
    fn mandatory_relay_recovery_failure_beats_concurrent_cancellation() {
        let (mut coordinator, active) = active_for(AUTHENTICATE_REQUEST);
        let completion = run_with_owner_and_cancellation(
            &active,
            || Ok::<_, Infallible>(OWNER_UID),
            |_| {
                assert!(coordinator.client_disconnected(&active));
                Ok::<_, Infallible>(
                    active.completion_for_worker(Err(AuthenticationSessionFailure::RelayRecovery)),
                )
            },
        );

        assert_eq!(
            completion.result(),
            Err(AuthenticationSessionFailure::RelayRecovery)
        );
    }

    #[test]
    fn setup_failure_is_a_typed_operation_failure_and_monitor_stops_promptly() {
        let (_coordinator, active) = active_for(AUTHENTICATE_REQUEST);
        let started = Instant::now();
        let completion = run_with_owner_and_cancellation(
            &active,
            || Ok::<_, Infallible>(OWNER_UID),
            |_| Err::<AuthenticationCompletion, _>(LiveAuthenticationSetupError::Connection),
        );

        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(
            completion.result(),
            Err(AuthenticationSessionFailure::Operation)
        );
    }
}

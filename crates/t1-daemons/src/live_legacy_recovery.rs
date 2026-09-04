#![cfg(feature = "legacy-recovery")]

//! Live, device-validated activation of one preserved legacy generation.

use core::fmt;
use std::fs;
use std::time::Duration;

use t1_bridge::live_operation::{
    LiveBridgeConnection, LiveClientPreparationError, PreparedLiveBridgeConnection,
};
use t1_bridge::policy::BiometricUserId;
use t1_platform::sep::{
    PreparedKeybagLeaseOutcome, SepCancellation, with_prepared_existing_keybag,
};

use crate::auth_lifecycle::{
    AuthenticationLifecycleError, AuthenticationLifecycleStage, AuthenticationRelayRuntime,
    with_authentication_relay_handoff,
};
use crate::auth_protocol::BIOMETRIC_USER_ID;
use crate::catacomb_restore::recover_ambiguous_pair;
use crate::catacomb_store::{
    CatacombPairStore, CatacombRecoveryOutcome, LegacyRecoveryReservationError,
};
use crate::keybag_relay::SystemctlKeybagRelay;
use crate::machine_data::{MachineCalibration, read_machine_calibration};
use crate::request_ids::LinuxRequestIdSource;
use crate::xart_live::ValidatedNcmInterface;

const STATE_DIRECTORY: &str = "/var/lib/t1bridge/touch-id/catacombs";
const RELAY_CONTROL_TIMEOUT: Duration = Duration::from_secs(30);
const SEP_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const RECOVERY_OPERATION_TIMEOUT: Duration = Duration::from_secs(60);
const ROOT_UID: u32 = 0;

/// Fixed, redacted result from the root recovery command.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LiveLegacyRecoveryStatus {
    Recovered,
    Quarantined,
    Denied,
    Error,
}

impl LiveLegacyRecoveryStatus {
    #[must_use]
    pub const fn is_success(self) -> bool {
        matches!(self, Self::Recovered)
    }
}

impl fmt::Display for LiveLegacyRecoveryStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Recovered => "status recovered",
            Self::Quarantined => "status quarantined",
            Self::Denied => "status denied",
            Self::Error => "status error",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LiveLegacyRecoveryError {
    DeviceDiscovery,
    Connection,
    RequestIds,
    OperationSetup,
}

struct LiveEnvironment {
    calibration: MachineCalibration,
    interface: ValidatedNcmInterface,
}

/// Activates only the uniquely eligible preserved legacy generation.
///
/// The fixed sequence is root validation, durable legacy reservation, relay
/// health and stop, exclusive SEP lease, versioned Bridge connection, forced
/// calibrated master-first/user-second device validation, atomic marker
/// promotion, SEP cleanup, and mandatory relay restart. No path, generation,
/// identity, or cleanup selector is accepted. The separate recovery archive is
/// never opened or changed by this command.
#[must_use]
pub fn run_live_legacy_recovery() -> LiveLegacyRecoveryStatus {
    if effective_uid() != Ok(ROOT_UID) {
        return LiveLegacyRecoveryStatus::Denied;
    }
    let store = CatacombPairStore::new(STATE_DIRECTORY);
    if let Err(status) = require_reservation(store.reserve_unique_inactive_legacy_recovery()) {
        return status;
    }
    let Ok(environment) = live_environment() else {
        return LiveLegacyRecoveryStatus::Quarantined;
    };
    let Ok(mut relay) = SystemctlKeybagRelay::new(RELAY_CONTROL_TIMEOUT) else {
        return LiveLegacyRecoveryStatus::Quarantined;
    };
    let cancellation = SepCancellation::new();
    with_recovery_relay_handoff(&mut relay, |_| {
        let outcome = with_prepared_existing_keybag(
            SEP_OPERATION_TIMEOUT,
            &cancellation,
            || prepare_connection(&environment),
            |prepared, _credential| recover_prepared(prepared, &store, &environment.calibration),
        );
        match outcome {
            PreparedKeybagLeaseOutcome::Completed { operation, .. } => operation,
            PreparedKeybagLeaseOutcome::PreparationFailed(error) => Err(error),
            PreparedKeybagLeaseOutcome::AcquisitionFailed(_)
            | PreparedKeybagLeaseOutcome::CleanupFailed { .. } => {
                Ok(LiveLegacyRecoveryStatus::Error)
            }
        }
    })
}

fn with_recovery_relay_handoff<Runtime, OperationError>(
    runtime: &mut Runtime,
    operation: impl FnOnce(&mut Runtime) -> Result<LiveLegacyRecoveryStatus, OperationError>,
) -> LiveLegacyRecoveryStatus
where
    Runtime: AuthenticationRelayRuntime,
{
    match with_authentication_relay_handoff(runtime, operation) {
        Ok(status) => status,
        Err(AuthenticationLifecycleError::Runtime {
            stage: AuthenticationLifecycleStage::RelayRecovery,
            ..
        }) => LiveLegacyRecoveryStatus::Error,
        Err(
            AuthenticationLifecycleError::RelayInactive
            | AuthenticationLifecycleError::Runtime { .. }
            | AuthenticationLifecycleError::Operation(_),
        ) => LiveLegacyRecoveryStatus::Quarantined,
    }
}

fn require_reservation(
    reservation: Result<
        crate::catacomb_store::LegacyRecoveryReservation,
        LegacyRecoveryReservationError,
    >,
) -> Result<(), LiveLegacyRecoveryStatus> {
    match reservation {
        Ok(_) => Ok(()),
        Err(LegacyRecoveryReservationError::Refused) => Err(LiveLegacyRecoveryStatus::Quarantined),
        Err(LegacyRecoveryReservationError::Store(_)) => Err(LiveLegacyRecoveryStatus::Error),
    }
}

fn live_environment() -> Result<LiveEnvironment, LiveLegacyRecoveryError> {
    Ok(LiveEnvironment {
        calibration: read_machine_calibration()
            .map_err(|_| LiveLegacyRecoveryError::OperationSetup)?,
        interface: ValidatedNcmInterface::discover()
            .map_err(|_| LiveLegacyRecoveryError::DeviceDiscovery)?,
    })
}

fn prepare_connection(
    environment: &LiveEnvironment,
) -> Result<PreparedLiveBridgeConnection, LiveLegacyRecoveryError> {
    let connection = LiveBridgeConnection::connect(environment.interface.kernel_index())
        .map_err(|_| LiveLegacyRecoveryError::Connection)?;
    let request_ids =
        LinuxRequestIdSource::open().map_err(|_| LiveLegacyRecoveryError::RequestIds)?;
    connection
        .prepare(request_ids, |_| Ok(()))
        .map_err(|error| match error {
            LiveClientPreparationError::Connection(_) => LiveLegacyRecoveryError::Connection,
            LiveClientPreparationError::Preparation(error) => error,
        })
}

fn recover_prepared(
    prepared: &mut PreparedLiveBridgeConnection,
    store: &CatacombPairStore,
    calibration: &MachineCalibration,
) -> Result<LiveLegacyRecoveryStatus, LiveLegacyRecoveryError> {
    let request_ids =
        LinuxRequestIdSource::open().map_err(|_| LiveLegacyRecoveryError::RequestIds)?;
    let operation = prepared
        .start_operation(request_ids)
        .map_err(|_| LiveLegacyRecoveryError::OperationSetup)?;
    let (mut transport, _events) = operation
        .into_adapters(RECOVERY_OPERATION_TIMEOUT, || false)
        .map_err(|_| LiveLegacyRecoveryError::OperationSetup)?;

    let user_id = BiometricUserId::new(i64::from(BIOMETRIC_USER_ID))
        .map_err(|_| LiveLegacyRecoveryError::OperationSetup)?;
    match recover_ambiguous_pair(&mut transport, store, user_id, calibration.as_bytes()) {
        Ok(CatacombRecoveryOutcome::Promoted) => Ok(LiveLegacyRecoveryStatus::Recovered),
        Ok(CatacombRecoveryOutcome::Quarantined) | Err(_) => {
            Ok(LiveLegacyRecoveryStatus::Quarantined)
        }
        Ok(CatacombRecoveryOutcome::Clean) => Ok(LiveLegacyRecoveryStatus::Error),
    }
}

fn effective_uid() -> Result<u32, ()> {
    let status = fs::read_to_string("/proc/self/status").map_err(|_| ())?;
    parse_effective_uid(&status)
}

fn parse_effective_uid(status: &str) -> Result<u32, ()> {
    status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .and_then(|line| line.split_ascii_whitespace().nth(1))
        .ok_or(())?
        .parse()
        .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct SyntheticFailure;

    struct FakeRelay {
        calls: Vec<&'static str>,
        active: Result<bool, SyntheticFailure>,
        stop: Result<(), SyntheticFailure>,
        start: Result<(), SyntheticFailure>,
    }

    impl FakeRelay {
        fn healthy() -> Self {
            Self {
                calls: Vec::new(),
                active: Ok(true),
                stop: Ok(()),
                start: Ok(()),
            }
        }
    }

    impl AuthenticationRelayRuntime for FakeRelay {
        type Error = SyntheticFailure;

        fn relay_is_active(&mut self) -> Result<bool, Self::Error> {
            self.calls.push("health");
            self.active
        }

        fn stop_relay(&mut self) -> Result<(), Self::Error> {
            self.calls.push("stop");
            self.stop
        }

        fn start_relay(&mut self) -> Result<(), Self::Error> {
            self.calls.push("start");
            self.start
        }
    }

    #[test]
    fn output_is_fixed_and_redacted() {
        assert_eq!(
            LiveLegacyRecoveryStatus::Recovered.to_string(),
            "status recovered"
        );
        assert_eq!(
            LiveLegacyRecoveryStatus::Quarantined.to_string(),
            "status quarantined"
        );
        assert_eq!(
            LiveLegacyRecoveryStatus::Denied.to_string(),
            "status denied"
        );
        assert_eq!(LiveLegacyRecoveryStatus::Error.to_string(), "status error");
        assert!(LiveLegacyRecoveryStatus::Recovered.is_success());
        assert!(!LiveLegacyRecoveryStatus::Quarantined.is_success());
    }

    #[test]
    fn effective_uid_parser_uses_only_the_effective_field() {
        assert_eq!(
            parse_effective_uid("Name:\ttest\nUid:\t1000\t0\t1000\t1000\n"),
            Ok(0)
        );
        assert_eq!(parse_effective_uid("Uid:\t0\t1000\t0\t0\n"), Ok(1000));
        assert_eq!(parse_effective_uid("Uid:\t0\n"), Err(()));
        assert_eq!(parse_effective_uid("Name:\ttest\n"), Err(()));
    }

    #[test]
    fn relay_restart_brackets_recovery_and_restart_failure_overrides_success() {
        let mut healthy = FakeRelay::healthy();
        assert_eq!(
            with_recovery_relay_handoff(&mut healthy, |runtime| {
                runtime.calls.push("recover");
                Ok::<_, SyntheticFailure>(LiveLegacyRecoveryStatus::Recovered)
            }),
            LiveLegacyRecoveryStatus::Recovered
        );
        assert_eq!(healthy.calls, ["health", "stop", "recover", "start"]);

        let mut failed_restart = FakeRelay {
            start: Err(SyntheticFailure),
            ..FakeRelay::healthy()
        };
        assert_eq!(
            with_recovery_relay_handoff(&mut failed_restart, |runtime| {
                runtime.calls.push("recover");
                Ok::<_, SyntheticFailure>(LiveLegacyRecoveryStatus::Recovered)
            }),
            LiveLegacyRecoveryStatus::Error
        );
        assert_eq!(failed_restart.calls, ["health", "stop", "recover", "start"]);
    }

    #[test]
    fn stop_failure_still_restarts_without_running_recovery() {
        let mut relay = FakeRelay {
            stop: Err(SyntheticFailure),
            ..FakeRelay::healthy()
        };
        assert_eq!(
            with_recovery_relay_handoff(&mut relay, |runtime| {
                runtime.calls.push("recover");
                Ok::<_, SyntheticFailure>(LiveLegacyRecoveryStatus::Recovered)
            }),
            LiveLegacyRecoveryStatus::Quarantined
        );
        assert_eq!(relay.calls, ["health", "stop", "start"]);
    }

    #[test]
    fn reservation_refusal_and_storage_failure_have_distinct_fixed_results() {
        assert_eq!(
            require_reservation(Err(LegacyRecoveryReservationError::Refused)),
            Err(LiveLegacyRecoveryStatus::Quarantined)
        );
        assert_eq!(
            require_reservation(Err(LegacyRecoveryReservationError::Store(
                crate::catacomb_store::CatacombStoreError::StorageUnavailable,
            ))),
            Err(LiveLegacyRecoveryStatus::Error)
        );
    }
}

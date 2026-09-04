//! Production process boundary for the existing-only keybag relay.

use std::fmt;
use std::time::Duration;

use t1_platform::sep::{SepOperationError, run_existing_keybag_notification_relay};

use crate::service_lifecycle::{ServiceLifecycle, ServiceLifecycleError};

const ACQUISITION_TIMEOUT: Duration = Duration::from_secs(30);
const CANCELLATION_POLL: Duration = Duration::from_secs(1);

/// Static, redacted production relay failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeybagRelayDaemonError {
    Lifecycle(ServiceLifecycleError),
    Relay(SepOperationError),
}

impl fmt::Display for KeybagRelayDaemonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Lifecycle(ServiceLifecycleError::Install) => "keybag relay process setup failed",
            Self::Lifecycle(ServiceLifecycleError::Readiness) => "keybag relay readiness failed",
            Self::Lifecycle(ServiceLifecycleError::Restore) => {
                "keybag relay process cleanup failed"
            }
            Self::Relay(_) => "keybag relay operation failed",
        })
    }
}

impl std::error::Error for KeybagRelayDaemonError {}

/// Holds the shared existing-keybag lease until SIGINT or SIGTERM.
///
/// # Errors
///
/// Returns a static error when signal setup, existing-state activation,
/// readiness notification, notification transport, or cleanup fails.
pub fn run() -> Result<(), KeybagRelayDaemonError> {
    let lifecycle = ServiceLifecycle::install().map_err(KeybagRelayDaemonError::Lifecycle)?;
    let relay_result = run_existing_keybag_notification_relay(
        ACQUISITION_TIMEOUT,
        CANCELLATION_POLL,
        &lifecycle,
        || lifecycle.notify_ready().is_ok(),
    );
    let restore_result = lifecycle.restore();
    combine_results(relay_result, restore_result)
}

fn combine_results(
    relay: Result<(), SepOperationError>,
    restore: Result<(), ServiceLifecycleError>,
) -> Result<(), KeybagRelayDaemonError> {
    match (relay, restore) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(SepOperationError::Callback), _) => Err(KeybagRelayDaemonError::Lifecycle(
            ServiceLifecycleError::Readiness,
        )),
        (Err(error), _) => Err(KeybagRelayDaemonError::Relay(error)),
        (Ok(()), Err(error)) => Err(KeybagRelayDaemonError::Lifecycle(error)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_failure_is_never_success() {
        assert_eq!(
            combine_results(Ok(()), Err(ServiceLifecycleError::Restore)),
            Err(KeybagRelayDaemonError::Lifecycle(
                ServiceLifecycleError::Restore
            ))
        );
        assert_eq!(
            combine_results(Err(SepOperationError::Teardown), Ok(())),
            Err(KeybagRelayDaemonError::Relay(SepOperationError::Teardown))
        );
    }

    #[test]
    fn diagnostics_do_not_expose_native_detail() {
        let error = KeybagRelayDaemonError::Relay(SepOperationError::Usb);
        assert_eq!(error.to_string(), "keybag relay operation failed");
        assert!(!error.to_string().contains('/'));
    }

    #[test]
    fn readiness_callback_failure_has_a_process_level_error() {
        assert_eq!(
            combine_results(Err(SepOperationError::Callback), Ok(())),
            Err(KeybagRelayDaemonError::Lifecycle(
                ServiceLifecycleError::Readiness
            ))
        );
    }
}

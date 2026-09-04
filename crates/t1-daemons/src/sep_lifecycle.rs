//! Production SEP/keybag lease adapters for the Touch ID lifecycles.

use std::time::Duration;

use t1_platform::sep::{
    KeybagDisposition, KeybagLeaseOutcome, PreparedKeybagLeaseOutcome, SepCancellation,
    SepOperationError, with_bootstrap_keybag, with_prepared_enrollment_keybag,
};

use crate::auth_lifecycle::AuthenticationRelayRuntime;
use crate::enrollment_lifecycle::{
    EnrollmentLeaseOutcome, EnrollmentLeaseRuntime, EnrollmentRelayRuntime,
};

/// Minimal control surface for the one shared keybag relay service.
pub trait KeybagRelayControl {
    type Error;

    /// Reports whether the relay is ready to hand off its shared lease.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe control-plane failure.
    fn is_active(&mut self) -> Result<bool, Self::Error>;

    /// Stops the relay and waits for its shared lease to be released.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe control-plane failure.
    fn stop(&mut self) -> Result<(), Self::Error>;

    /// Starts the relay and waits for it to become ready.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe control-plane failure.
    fn start(&mut self) -> Result<(), Self::Error>;
}

/// Native SEP/keybag/ACM enrollment lease used after relay handoff.
pub struct SepEnrollmentLeaseRuntime {
    timeout: Duration,
    cancellation: SepCancellation,
}

impl SepEnrollmentLeaseRuntime {
    #[must_use]
    pub const fn new(timeout: Duration, cancellation: SepCancellation) -> Self {
        Self {
            timeout,
            cancellation,
        }
    }
}

impl EnrollmentLeaseRuntime for SepEnrollmentLeaseRuntime {
    type Error = SepOperationError;

    fn with_prepared_enrollment_lease<Prepared, PreparationError, T>(
        &mut self,
        prepare: impl FnOnce() -> Result<Prepared, PreparationError>,
        operation: impl FnOnce(&mut Prepared, &[u8]) -> T,
    ) -> EnrollmentLeaseOutcome<T, PreparationError, Self::Error> {
        match with_prepared_enrollment_keybag(
            self.timeout,
            &self.cancellation,
            prepare,
            |prepared, credential| operation(prepared, credential.as_bytes()),
        ) {
            PreparedKeybagLeaseOutcome::Completed { operation, .. } => {
                EnrollmentLeaseOutcome::Completed(operation)
            }
            PreparedKeybagLeaseOutcome::PreparationFailed(error) => {
                EnrollmentLeaseOutcome::PreparationFailed(error)
            }
            PreparedKeybagLeaseOutcome::AcquisitionFailed(error) => {
                EnrollmentLeaseOutcome::AcquisitionFailed(error)
            }
            PreparedKeybagLeaseOutcome::CleanupFailed {
                operation, error, ..
            } => EnrollmentLeaseOutcome::CleanupFailed { operation, error },
        }
    }
}

impl<Relay> EnrollmentRelayRuntime for Relay
where
    Relay: KeybagRelayControl,
{
    type Error = Relay::Error;

    fn relay_is_active(&mut self) -> Result<bool, Self::Error> {
        self.is_active()
    }

    fn stop_relay(&mut self) -> Result<(), Self::Error> {
        self.stop()
    }

    fn start_relay(&mut self) -> Result<(), Self::Error> {
        self.start()
    }
}

impl<Relay> AuthenticationRelayRuntime for Relay
where
    Relay: KeybagRelayControl,
{
    type Error = Relay::Error;

    fn relay_is_active(&mut self) -> Result<bool, Self::Error> {
        self.is_active()
    }

    fn stop_relay(&mut self) -> Result<(), Self::Error> {
        self.stop()
    }

    fn start_relay(&mut self) -> Result<(), Self::Error> {
        self.start()
    }
}

/// Creates the protected `T1Bridge` keybag only when it is absent.
///
/// This bootstrap runs before the shared relay can be healthy on the first
/// enrollment. A later enrollment transaction still requires the healthy
/// relay, performs its normal handoff, and reuses the durable keybag.
/// The platform supplies `BridgeOS`'s fixed biometric protocol identity; no
/// Linux account identity is accepted by this API.
///
/// # Errors
///
/// Returns a static native SEP/keybag acquisition, persistence, cancellation,
/// or cleanup failure. A cleanup failure is not reported as success even when
/// the new state reached durable storage.
pub fn bootstrap_keybag(
    timeout: Duration,
    cancellation: &SepCancellation,
) -> Result<KeybagDisposition, SepOperationError> {
    match with_bootstrap_keybag(timeout, cancellation, |disposition, _| disposition) {
        KeybagLeaseOutcome::Completed { operation, .. } => Ok(operation),
        KeybagLeaseOutcome::AcquisitionFailed(error)
        | KeybagLeaseOutcome::CleanupFailed { error, .. } => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;

    #[derive(Default)]
    struct FakeRelay {
        active: bool,
        calls: Vec<&'static str>,
    }

    impl KeybagRelayControl for FakeRelay {
        type Error = Infallible;

        fn is_active(&mut self) -> Result<bool, Self::Error> {
            self.calls.push("active");
            Ok(self.active)
        }

        fn stop(&mut self) -> Result<(), Self::Error> {
            self.calls.push("stop");
            self.active = false;
            Ok(())
        }

        fn start(&mut self) -> Result<(), Self::Error> {
            self.calls.push("start");
            self.active = true;
            Ok(())
        }
    }

    #[test]
    fn relay_control_is_forwarded_without_transport_or_sep_state() {
        let mut relay = FakeRelay {
            active: true,
            calls: Vec::new(),
        };

        assert!(AuthenticationRelayRuntime::relay_is_active(&mut relay).unwrap());
        AuthenticationRelayRuntime::stop_relay(&mut relay).unwrap();
        AuthenticationRelayRuntime::start_relay(&mut relay).unwrap();
        assert_eq!(relay.calls, ["active", "stop", "start"]);
        assert!(relay.active);
    }
}

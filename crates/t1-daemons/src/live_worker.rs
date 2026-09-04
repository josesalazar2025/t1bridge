//! Production routing for broker-authorized Touch ID work.

use t1_bridge::match_workflow::MatchOutcome;

use crate::auth_daemon::{AuthDaemonError, BrokerWorker, StandardBrokerWorker, run_with_workers};
use crate::auth_protocol::Purpose;
use crate::auth_session::{
    ActiveAuthentication, AuthenticationCompletion, AuthenticationSessionFailure,
};
use crate::live_authentication::run_live_authentication;
use crate::live_enrollment::{LiveEnrollmentError, run_live_enrollment};
use crate::live_standard_fingerprint::run_live_standard_operation;
use crate::standard_fingerprint_protocol::EnrollProgress;

#[derive(Clone, Copy, Debug, Default)]
struct ProductionWorker;

impl BrokerWorker for ProductionWorker {
    fn run(&self, active: ActiveAuthentication) -> AuthenticationCompletion {
        match active.purpose() {
            Purpose::Authenticate | Purpose::Approve => run_live_authentication(&active),
            Purpose::Enrollment => {
                let result = match run_live_enrollment(&active) {
                    Ok(_) => Ok(MatchOutcome::Matched),
                    Err(LiveEnrollmentError::Cancelled) => Ok(MatchOutcome::Cancelled),
                    Err(error) => {
                        eprintln!("t1-touchid-auth: {error}");
                        Err(AuthenticationSessionFailure::Operation)
                    }
                };
                active.completion_for_worker(result)
            }
        }
    }
}

impl StandardBrokerWorker for ProductionWorker {
    fn run(
        &self,
        active: &crate::auth_session::ActiveStandardOperation,
        progress: &mut dyn FnMut(EnrollProgress),
    ) -> crate::auth_session::StandardCompletion {
        run_live_standard_operation(active, progress)
    }
}

/// Runs the systemd-activated broker with the fixed production worker.
///
/// # Errors
///
/// Returns a static broker lifecycle failure.
pub fn run() -> Result<(), AuthDaemonError> {
    run_with_workers(ProductionWorker, ProductionWorker)
}

//! Development-only standard fingerprint smoke harness.

use std::process::ExitCode;
use std::time::Duration;

use t1_daemons::auth_protocol::AccessPolicy;
use t1_daemons::auth_scheduler::{BrokerServiceScheduler, ScheduledStandardOperation};
use t1_daemons::catacomb_store::CatacombPairStore;
use t1_daemons::enrollment_owner::{EnrollmentOwnerError, EnrollmentOwnerStore};
use t1_daemons::live_standard_fingerprint::run_live_standard_operation;
use t1_daemons::nss_account::resolve_standard_account;
use t1_daemons::standard_catalog_store::load_committed_catalog_for_account;
use t1_daemons::standard_fingerprint_protocol::{EnrollProgress, Username};
use t1_daemons::standard_identity_catalog::StandardIdentityCatalog;
use t1_daemons::standard_operation_authority::ResolvedStandardAccount;
use t1_daemons::standard_smoke::{
    StandardSmokeEnvironment, StandardSmokeEnvironmentError, StandardSmokeReport,
    StandardSmokeStatus, StandardSmokeWorkerResult, execute_standard_smoke,
    parse_standard_smoke_command,
};

const STATE_DIRECTORY: &str = "/var/lib/t1bridge/touch-id/catacombs";
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);
const NOW: Duration = Duration::ZERO;

struct ProductionSmokeEnvironment {
    pair_store: CatacombPairStore,
    owner_store: EnrollmentOwnerStore,
}

impl ProductionSmokeEnvironment {
    fn new() -> Self {
        Self {
            pair_store: CatacombPairStore::new(STATE_DIRECTORY),
            owner_store: EnrollmentOwnerStore::new(STATE_DIRECTORY),
        }
    }

    fn recorded_owner(&self) -> Result<Option<AccessPolicy>, StandardSmokeEnvironmentError> {
        match self.owner_store.access_policy() {
            Ok(policy) => Ok(Some(policy)),
            Err(EnrollmentOwnerError::MissingOwner) => Ok(None),
            Err(_) => Err(StandardSmokeEnvironmentError),
        }
    }
}

impl StandardSmokeEnvironment for ProductionSmokeEnvironment {
    fn resolve_account(
        &mut self,
        username: &Username,
    ) -> Result<ResolvedStandardAccount, StandardSmokeEnvironmentError> {
        resolve_standard_account(username).map_err(|_| StandardSmokeEnvironmentError)
    }

    fn load_catalog(
        &mut self,
        account: &ResolvedStandardAccount,
    ) -> Result<StandardIdentityCatalog, StandardSmokeEnvironmentError> {
        load_committed_catalog_for_account(&self.pair_store, &self.owner_store, account)
            .map_err(|_| StandardSmokeEnvironmentError)
    }

    fn run_worker(
        &mut self,
        scheduled: &ScheduledStandardOperation,
        progress: &mut dyn FnMut(EnrollProgress),
    ) -> StandardSmokeWorkerResult {
        let completion = run_live_standard_operation(scheduled.operation(), progress);
        StandardSmokeWorkerResult {
            response: completion.result().clone(),
            cancel_before_finish: false,
        }
    }
}

fn main() -> ExitCode {
    let Ok(report) = run() else {
        eprintln!("status error");
        return ExitCode::FAILURE;
    };
    if report_failed(report) {
        eprintln!("status error");
        return ExitCode::FAILURE;
    }
    println!("{report}");
    ExitCode::SUCCESS
}

const fn report_failed(report: StandardSmokeReport) -> bool {
    matches!(
        report,
        StandardSmokeReport::Status(StandardSmokeStatus::Error)
    )
}

fn run() -> Result<t1_daemons::standard_smoke::StandardSmokeReport, ()> {
    let arguments = std::env::args_os()
        .skip(1)
        .map(|argument| argument.into_string().map_err(|_| ()))
        .collect::<Result<Vec<_>, _>>()?;
    let argument_refs = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    let command = parse_standard_smoke_command(&argument_refs).map_err(|_| ())?;

    let mut environment = ProductionSmokeEnvironment::new();
    let recorded_owner = environment.recorded_owner().map_err(|_| ())?;
    let mut scheduler = BrokerServiceScheduler::new(NOW, IDLE_TIMEOUT).map_err(|_| ())?;
    let mut progress = |event: EnrollProgress| {
        println!(
            "status enroll-stage {}/{}",
            event.completed_stage(),
            event.total_stages()
        );
    };
    execute_standard_smoke(
        &mut scheduler,
        command,
        recorded_owner,
        NOW,
        &mut environment,
        &mut progress,
    )
    .map_err(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_error_is_the_only_reported_process_failure() {
        assert!(report_failed(StandardSmokeReport::Status(
            StandardSmokeStatus::Error
        )));
        assert!(!report_failed(StandardSmokeReport::Status(
            StandardSmokeStatus::NoMatch
        )));
        assert!(!report_failed(StandardSmokeReport::Count(0)));
    }
}

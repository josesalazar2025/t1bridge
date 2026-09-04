//! Root-only zero-argument legacy generation recovery command.

use std::process::ExitCode;

use t1_daemons::live_legacy_recovery::{LiveLegacyRecoveryStatus, run_live_legacy_recovery};

fn main() -> ExitCode {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let status = if arguments.next().is_none() {
        run_live_legacy_recovery()
    } else {
        LiveLegacyRecoveryStatus::Error
    };
    println!("{status}");
    if status.is_success() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

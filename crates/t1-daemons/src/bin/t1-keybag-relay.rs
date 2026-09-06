use std::process::ExitCode;

fn main() -> ExitCode {
    match t1_platform::diagnostics::observe(
        t1_platform::diagnostics::Component::Sep,
        t1_platform::diagnostics::Stage::Relay,
        t1_daemons::keybag_relay_daemon::run,
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("t1-keybag-relay: {error}");
            ExitCode::FAILURE
        }
    }
}

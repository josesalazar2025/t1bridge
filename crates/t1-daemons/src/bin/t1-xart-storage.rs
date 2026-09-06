use std::process::ExitCode;

fn main() -> ExitCode {
    match t1_platform::diagnostics::observe(
        t1_platform::diagnostics::Component::Xart,
        t1_platform::diagnostics::Stage::Startup,
        t1_daemons::xart_daemon::run,
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("t1-xart-storage: {error}");
            ExitCode::FAILURE
        }
    }
}

use std::process::ExitCode;

fn main() -> ExitCode {
    let arguments: Vec<_> = std::env::args_os().skip(1).collect();
    match arguments.as_slice() {
        [] => {}
        [flag] if flag == "--diagnostics" => t1_platform::diagnostics::enable(),
        [flag] if flag == "--help" => {
            println!(
                "Usage: t1-touchid-auth [--diagnostics]\nOpt-in payload-free broker diagnostics. Run via the systemd service."
            );
            return ExitCode::SUCCESS;
        }
        _ => {
            eprintln!("Usage: t1-touchid-auth [--diagnostics]");
            return ExitCode::from(2);
        }
    }
    match t1_platform::diagnostics::observe(
        t1_platform::diagnostics::Component::Broker,
        t1_platform::diagnostics::Stage::Startup,
        t1_daemons::live_worker::run,
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("t1-touchid-auth: {error}");
            ExitCode::FAILURE
        }
    }
}

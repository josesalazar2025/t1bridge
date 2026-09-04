use std::process::ExitCode;

fn main() -> ExitCode {
    match t1_daemons::keybag_relay_daemon::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("t1-keybag-relay: {error}");
            ExitCode::FAILURE
        }
    }
}

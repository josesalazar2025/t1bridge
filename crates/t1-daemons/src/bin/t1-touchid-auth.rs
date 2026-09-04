use std::process::ExitCode;

fn main() -> ExitCode {
    match t1_daemons::live_worker::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("t1-touchid-auth: {error}");
            ExitCode::FAILURE
        }
    }
}

use std::process::ExitCode;

fn main() -> ExitCode {
    match t1_touchbar_hw::service::run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("t1-touchbar-hw: {error}");
            ExitCode::FAILURE
        }
    }
}

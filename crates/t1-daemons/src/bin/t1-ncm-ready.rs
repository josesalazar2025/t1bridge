use std::process::ExitCode;

fn main() -> ExitCode {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let Some(expected_interface) = arguments.next() else {
        eprintln!("t1-ncm-ready: exactly one interface argument is required");
        return ExitCode::FAILURE;
    };
    if arguments.next().is_some() {
        eprintln!("t1-ncm-ready: exactly one interface argument is required");
        return ExitCode::FAILURE;
    }
    match t1_platform::diagnostics::observe(
        t1_platform::diagnostics::Component::Ncm,
        t1_platform::diagnostics::Stage::Startup,
        || t1_daemons::xart_live::prepare_ncm_link(&expected_interface),
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("t1-ncm-ready: {error}");
            ExitCode::FAILURE
        }
    }
}

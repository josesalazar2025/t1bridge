use std::process::ExitCode;

use t1_daemons::auth_client::{TouchIdClientError, TouchIdCommand};

fn main() -> ExitCode {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let command = arguments.next();
    let command = match (command.as_deref(), arguments.next()) {
        (Some(argument), None) => TouchIdCommand::parse(argument),
        _ => None,
    };
    let result = command
        .ok_or(TouchIdClientError::InvalidCommand)
        .and_then(t1_daemons::auth_client::run);
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("t1-touchid: {error}");
            ExitCode::FAILURE
        }
    }
}

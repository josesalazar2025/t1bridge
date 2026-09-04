use std::process::ExitCode;

use t1_daemons::pam_client::{self, PamClientError, PamPurpose};

fn main() -> ExitCode {
    match parse_arguments().and_then(|(user_id, purpose)| pam_client::run(user_id, purpose)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("t1-pam-auth: {error}");
            ExitCode::FAILURE
        }
    }
}

fn parse_arguments() -> Result<(u32, PamPurpose), PamClientError> {
    let mut arguments = std::env::args();
    let _program = arguments.next();
    let user_id = arguments.next().ok_or(PamClientError::InvalidUser)?;
    let purpose = arguments.next().ok_or(PamClientError::InvalidUser)?;
    if arguments.next().is_some() {
        return Err(PamClientError::InvalidUser);
    }

    let parsed_user_id = user_id
        .parse::<u32>()
        .ok()
        .filter(|parsed| *parsed != 0 && parsed.to_string() == user_id)
        .ok_or(PamClientError::InvalidUser)?;
    let parsed_purpose = PamPurpose::parse(&purpose).ok_or(PamClientError::InvalidUser)?;
    Ok((parsed_user_id, parsed_purpose))
}

//! Fixed PAM-side authentication adapter.

use core::fmt;

use crate::auth_client::{TouchIdClientError, TouchIdCommand};
use crate::enrollment_owner::{EnrollmentOwner, EnrollmentOwnerError, EnrollmentOwnerStore};

const STATE_DIRECTORY: &str = "/var/lib/t1bridge/touch-id/catacombs";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PamPurpose {
    Authenticate,
    Approve,
}

impl PamPurpose {
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "authenticate" => Some(Self::Authenticate),
            "approve" => Some(Self::Approve),
            _ => None,
        }
    }

    const fn command(self) -> TouchIdCommand {
        match self {
            Self::Authenticate => TouchIdCommand::Authenticate,
            Self::Approve => TouchIdCommand::Approve,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PamClientError {
    InvalidUser,
    OwnerUnavailable,
    DifferentOwner,
    Authentication,
}

impl fmt::Display for PamClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidUser => "PAM target user is invalid",
            Self::OwnerUnavailable => "Touch ID enrollment owner is unavailable",
            Self::DifferentOwner => "PAM target does not own the Touch ID enrollment",
            Self::Authentication => "Touch ID authentication did not succeed",
        })
    }
}

impl std::error::Error for PamClientError {}

/// Authenticates one PAM target against the fixed root-private enrollment owner.
///
/// # Errors
///
/// Any missing, unsafe, corrupt, mismatched, or failed state is a non-success.
/// The PAM module maps every error to `PAM_IGNORE`, preserving the caller's
/// existing password stack.
pub fn run(target_user_id: u32, purpose: PamPurpose) -> Result<(), PamClientError> {
    run_with(
        target_user_id,
        purpose,
        || {
            EnrollmentOwnerStore::new(STATE_DIRECTORY)
                .load()
                .map(EnrollmentOwner::as_raw)
        },
        crate::auth_client::run,
    )
}

fn run_with<Owner, Authenticate>(
    target_user_id: u32,
    purpose: PamPurpose,
    owner: Owner,
    authenticate: Authenticate,
) -> Result<(), PamClientError>
where
    Owner: FnOnce() -> Result<u32, EnrollmentOwnerError>,
    Authenticate: FnOnce(TouchIdCommand) -> Result<(), TouchIdClientError>,
{
    if target_user_id == 0 {
        return Err(PamClientError::InvalidUser);
    }
    let owner = owner().map_err(|_| PamClientError::OwnerUnavailable)?;
    if owner != target_user_id {
        return Err(PamClientError::DifferentOwner);
    }
    authenticate(purpose.command()).map_err(|_| PamClientError::Authentication)
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: u32 = 42_000;

    #[test]
    fn parses_only_the_two_fixed_purposes() {
        assert_eq!(
            PamPurpose::parse("authenticate"),
            Some(PamPurpose::Authenticate)
        );
        assert_eq!(PamPurpose::parse("approve"), Some(PamPurpose::Approve));
        assert_eq!(PamPurpose::parse("enroll"), None);
        assert_eq!(PamPurpose::parse(""), None);
    }

    #[test]
    fn exact_owner_and_success_are_both_required() {
        for (target, stored, client, expected) in [
            (0, Ok(OWNER), Ok(()), Err(PamClientError::InvalidUser)),
            (
                OWNER,
                Err(EnrollmentOwnerError::MissingOwner),
                Ok(()),
                Err(PamClientError::OwnerUnavailable),
            ),
            (
                OWNER + 1,
                Ok(OWNER),
                Ok(()),
                Err(PamClientError::DifferentOwner),
            ),
            (
                OWNER,
                Ok(OWNER),
                Err(TouchIdClientError::Denied),
                Err(PamClientError::Authentication),
            ),
            (OWNER, Ok(OWNER), Ok(()), Ok(())),
        ] {
            assert_eq!(
                run_with(target, PamPurpose::Authenticate, || stored, |_| client),
                expected
            );
        }
    }

    #[test]
    fn preserves_the_pam_presentation_purpose() {
        for (purpose, expected) in [
            (PamPurpose::Authenticate, TouchIdCommand::Authenticate),
            (PamPurpose::Approve, TouchIdCommand::Approve),
        ] {
            let mut observed = None;
            assert_eq!(
                run_with(
                    OWNER,
                    purpose,
                    || Ok(OWNER),
                    |command| {
                        observed = Some(command);
                        Ok(())
                    }
                ),
                Ok(())
            );
            assert_eq!(observed, Some(expected));
        }
    }
}

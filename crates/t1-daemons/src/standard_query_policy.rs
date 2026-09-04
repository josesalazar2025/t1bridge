//! Pure standard-client visibility and match-result policy.
//!
//! Live callers retain ownership of canonical-account revalidation, broker
//! admission, hardware sequencing, cancellation, and deadlines. They pass the
//! identity-bearing result from `identify_user_after_calibration` into these
//! evaluators, so this module does not duplicate the Mesa match sequence.

use std::fmt;

use t1_bridge::match_workflow::IdentityMatchOutcome;

use crate::standard_fingerprint_protocol::{Identity, IdentityId};
use crate::standard_identity_catalog::StandardIdentityCatalog;

/// Returns the complete standard-visible identity list.
///
/// Unlabeled legacy recovery anchors remain hidden by the catalog contract.
#[must_use]
pub fn list_identities(catalog: &StandardIdentityCatalog) -> Vec<Identity> {
    catalog.labeled_identities()
}

/// Validates one requested Verify identity before the live match sequence.
///
/// This preflight keeps absent and unlabeled legacy IDs from starting hardware
/// work. The returned identity is always safe to expose to a standard client.
/// Canonical-account revalidation remains the caller's responsibility.
///
/// # Errors
///
/// Refuses an absent or unlabeled requested identity.
pub fn validate_verify_request(
    catalog: &StandardIdentityCatalog,
    requested: IdentityId,
) -> Result<Identity, QueryPolicyError> {
    find_labeled(catalog, requested).ok_or(QueryPolicyError::RequestedIdentityNotLabeled)
}

/// Applies exact standard Verify semantics to one identity-bearing match.
///
/// The requested ID must already be a labeled standard identity. A Mesa match
/// succeeds only when it names that exact ID; matches of another labeled or
/// unlabeled identity become `NoMatch` without exposing the other identity.
/// The caller remains responsible for canonical-account revalidation before
/// starting the shared live match sequence.
///
/// # Errors
///
/// Refuses an absent or unlabeled requested identity before interpreting the
/// match result.
pub fn evaluate_verify(
    catalog: &StandardIdentityCatalog,
    requested: IdentityId,
    outcome: IdentityMatchOutcome,
) -> Result<StandardMatchOutcome, QueryPolicyError> {
    let requested_identity = validate_verify_request(catalog, requested)?;

    Ok(match outcome {
        IdentityMatchOutcome::Matched(matched) if matched == requested.as_bytes() => {
            StandardMatchOutcome::Matched(requested_identity)
        }
        IdentityMatchOutcome::Matched(_) | IdentityMatchOutcome::NoMatch => {
            StandardMatchOutcome::NoMatch
        }
        IdentityMatchOutcome::Cancelled => StandardMatchOutcome::Cancelled,
        IdentityMatchOutcome::TimedOut => StandardMatchOutcome::TimedOut,
    })
}

/// Applies standard Identify visibility to one identity-bearing match.
///
/// A match succeeds only when the exact Mesa identity has an explicit standard
/// finger label. Matches of an unlabeled legacy or unknown identity become
/// `NoMatch`, so neither can cross the standard boundary. The caller remains
/// responsible for canonical-account revalidation before starting the shared
/// live match sequence.
#[must_use]
pub fn evaluate_identify(
    catalog: &StandardIdentityCatalog,
    outcome: IdentityMatchOutcome,
) -> StandardMatchOutcome {
    match outcome {
        IdentityMatchOutcome::Matched(matched) => catalog
            .labeled_identities()
            .into_iter()
            .find(|identity| identity.id.as_bytes() == matched)
            .map_or(StandardMatchOutcome::NoMatch, StandardMatchOutcome::Matched),
        IdentityMatchOutcome::NoMatch => StandardMatchOutcome::NoMatch,
        IdentityMatchOutcome::Cancelled => StandardMatchOutcome::Cancelled,
        IdentityMatchOutcome::TimedOut => StandardMatchOutcome::TimedOut,
    }
}

fn find_labeled(catalog: &StandardIdentityCatalog, id: IdentityId) -> Option<Identity> {
    catalog
        .labeled_identities()
        .into_iter()
        .find(|identity| identity.id == id)
}

/// Standard-visible terminal match result.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum StandardMatchOutcome {
    Matched(Identity),
    NoMatch,
    Cancelled,
    TimedOut,
}

impl fmt::Debug for StandardMatchOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Matched(_) => formatter.write_str("Matched(<redacted>)"),
            Self::NoMatch => formatter.write_str("NoMatch"),
            Self::Cancelled => formatter.write_str("Cancelled"),
            Self::TimedOut => formatter.write_str("TimedOut"),
        }
    }
}

/// Payload-free standard query-policy failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueryPolicyError {
    RequestedIdentityNotLabeled,
}

impl fmt::Display for QueryPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestedIdentityNotLabeled => {
                formatter.write_str("requested standard identity is not labeled")
            }
        }
    }
}

impl std::error::Error for QueryPolicyError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_metadata::{IdentityMetadata, IdentityMetadataEntry};
    use crate::standard_fingerprint_protocol::{FingerLabel, Username};

    fn owner() -> Username {
        Username::new("synthetic-owner").unwrap()
    }

    fn id(value: u8) -> IdentityId {
        IdentityId::new([value; 16]).unwrap()
    }

    fn catalog() -> StandardIdentityCatalog {
        let metadata = IdentityMetadata::new(
            owner(),
            vec![
                IdentityMetadataEntry {
                    id: id(1),
                    finger: None,
                },
                IdentityMetadataEntry {
                    id: id(2),
                    finger: Some(FingerLabel::LeftIndex),
                },
                IdentityMetadataEntry {
                    id: id(3),
                    finger: Some(FingerLabel::RightThumb),
                },
            ],
        )
        .unwrap();
        StandardIdentityCatalog::reconcile(Some(metadata), owner(), &[id(1), id(2), id(3)]).unwrap()
    }

    fn identity(value: u8, finger: FingerLabel) -> Identity {
        Identity {
            id: id(value),
            finger,
        }
    }

    #[test]
    fn list_returns_only_explicitly_labeled_identities() {
        assert_eq!(
            list_identities(&catalog()),
            vec![
                identity(2, FingerLabel::LeftIndex),
                identity(3, FingerLabel::RightThumb),
            ]
        );
    }

    #[test]
    fn verify_succeeds_only_for_the_exact_requested_labeled_identity() {
        let catalog = catalog();
        assert_eq!(
            validate_verify_request(&catalog, id(2)),
            Ok(identity(2, FingerLabel::LeftIndex))
        );
        assert_eq!(
            evaluate_verify(
                &catalog,
                id(2),
                IdentityMatchOutcome::Matched(id(2).as_bytes()),
            ),
            Ok(StandardMatchOutcome::Matched(identity(
                2,
                FingerLabel::LeftIndex,
            )))
        );
        assert_eq!(
            evaluate_verify(
                &catalog,
                id(2),
                IdentityMatchOutcome::Matched(id(3).as_bytes()),
            ),
            Ok(StandardMatchOutcome::NoMatch)
        );
    }

    #[test]
    fn verify_never_exposes_an_unlabeled_match() {
        assert_eq!(
            evaluate_verify(
                &catalog(),
                id(2),
                IdentityMatchOutcome::Matched(id(1).as_bytes()),
            ),
            Ok(StandardMatchOutcome::NoMatch)
        );
    }

    #[test]
    fn verify_refuses_unlabeled_and_absent_requested_identities() {
        for requested in [id(1), id(4)] {
            assert_eq!(
                validate_verify_request(&catalog(), requested),
                Err(QueryPolicyError::RequestedIdentityNotLabeled)
            );
            assert_eq!(
                evaluate_verify(
                    &catalog(),
                    requested,
                    IdentityMatchOutcome::Matched(requested.as_bytes()),
                ),
                Err(QueryPolicyError::RequestedIdentityNotLabeled)
            );
        }
    }

    #[test]
    fn verify_preserves_nonmatching_terminal_outcomes() {
        for (input, expected) in [
            (IdentityMatchOutcome::NoMatch, StandardMatchOutcome::NoMatch),
            (
                IdentityMatchOutcome::Cancelled,
                StandardMatchOutcome::Cancelled,
            ),
            (
                IdentityMatchOutcome::TimedOut,
                StandardMatchOutcome::TimedOut,
            ),
        ] {
            assert_eq!(evaluate_verify(&catalog(), id(2), input), Ok(expected));
        }
    }

    #[test]
    fn identify_returns_the_exact_labeled_identity() {
        assert_eq!(
            evaluate_identify(&catalog(), IdentityMatchOutcome::Matched(id(3).as_bytes()),),
            StandardMatchOutcome::Matched(identity(3, FingerLabel::RightThumb))
        );
    }

    #[test]
    fn identify_hides_unlabeled_and_unknown_matches() {
        for matched in [id(1), id(4)] {
            assert_eq!(
                evaluate_identify(
                    &catalog(),
                    IdentityMatchOutcome::Matched(matched.as_bytes()),
                ),
                StandardMatchOutcome::NoMatch
            );
        }
    }

    #[test]
    fn identify_preserves_nonmatching_terminal_outcomes() {
        for (input, expected) in [
            (IdentityMatchOutcome::NoMatch, StandardMatchOutcome::NoMatch),
            (
                IdentityMatchOutcome::Cancelled,
                StandardMatchOutcome::Cancelled,
            ),
            (
                IdentityMatchOutcome::TimedOut,
                StandardMatchOutcome::TimedOut,
            ),
        ] {
            assert_eq!(evaluate_identify(&catalog(), input), expected);
        }
    }

    #[test]
    fn diagnostics_do_not_expose_identity_or_finger_data() {
        let outcome = StandardMatchOutcome::Matched(identity(2, FingerLabel::LeftIndex));
        let diagnostic = format!("{outcome:?}");
        assert_eq!(diagnostic, "Matched(<redacted>)");
        assert!(!diagnostic.contains("LeftIndex"));
        assert!(!diagnostic.contains("2, 2, 2"));

        let error = QueryPolicyError::RequestedIdentityNotLabeled;
        let diagnostic = format!("{error:?}: {error}");
        assert!(!diagnostic.contains("synthetic-owner"));
        assert!(!diagnostic.contains("020202"));
    }
}

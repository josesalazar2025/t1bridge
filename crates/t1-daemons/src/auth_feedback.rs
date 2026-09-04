//! Best-effort cosmetic feedback for completed authentication attempts.

use core::convert::Infallible;

use t1_bridge::match_workflow::MatchOutcome;

use crate::auth_protocol::Purpose;
use crate::overlay::{OverlaySession, OverlayState};

/// Cosmetic authentication feedback that cannot determine authentication.
pub trait AuthenticationFeedback {
    /// A presentation-only failure ignored by the authentication path.
    type Error;

    /// Applies one presentation-only action.
    ///
    /// # Errors
    ///
    /// Returns a cosmetic failure that the authentication path must ignore.
    fn apply(&mut self, action: FeedbackAction) -> Result<(), Self::Error>;
}

/// One presentation-only action after a biometric outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeedbackAction {
    ShowRetry,
    PauseAfterRetry,
    ShowSuccess,
    PauseAfterSuccess,
}

impl AuthenticationFeedback for OverlaySession {
    type Error = Infallible;

    fn apply(&mut self, action: FeedbackAction) -> Result<(), Self::Error> {
        match action {
            FeedbackAction::ShowRetry => self.try_again(),
            FeedbackAction::PauseAfterRetry => Self::pause_for_retry_feedback(),
            FeedbackAction::ShowSuccess => self.success(),
            FeedbackAction::PauseAfterSuccess => Self::pause_for_success_feedback(),
        }
        Ok(())
    }
}

/// Selects the distinct initial overlay state for one broker purpose.
#[must_use]
pub const fn initial_overlay_state(purpose: Purpose) -> OverlayState {
    match purpose {
        Purpose::Authenticate => OverlayState::Authenticate,
        Purpose::Approve => OverlayState::Approve,
        Purpose::Enrollment => OverlayState::Enrollment,
    }
}

/// Applies best-effort UI feedback without changing biometric authority.
///
/// A confirmed match shows success, while a confirmed no-match shows retry.
/// Cancellation, timeout, and operation errors show neither. Every feedback
/// failure is ignored, and the original typed result is returned unchanged.
///
/// # Errors
///
/// Returns only the unchanged operation error supplied by `result`; cosmetic
/// feedback errors are never authoritative.
pub fn apply_authentication_feedback<Feedback, OperationError>(
    result: Result<MatchOutcome, OperationError>,
    feedback: Option<&mut Feedback>,
) -> Result<MatchOutcome, OperationError>
where
    Feedback: AuthenticationFeedback,
{
    if let (Ok(outcome), Some(feedback)) = (&result, feedback) {
        match outcome {
            MatchOutcome::Matched => {
                let _ = feedback
                    .apply(FeedbackAction::ShowSuccess)
                    .and_then(|()| feedback.apply(FeedbackAction::PauseAfterSuccess));
            }
            MatchOutcome::NoMatch => {
                let _ = feedback
                    .apply(FeedbackAction::ShowRetry)
                    .and_then(|()| feedback.apply(FeedbackAction::PauseAfterRetry));
            }
            MatchOutcome::Cancelled | MatchOutcome::TimedOut => {}
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct OperationError;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct CosmeticError;

    struct FakeFeedback {
        calls: Vec<&'static str>,
        fail_first: bool,
    }

    impl FakeFeedback {
        fn available() -> Self {
            Self {
                calls: Vec::new(),
                fail_first: false,
            }
        }

        fn failing() -> Self {
            Self {
                calls: Vec::new(),
                fail_first: true,
            }
        }

        fn record(&mut self, call: &'static str) -> Result<(), CosmeticError> {
            self.calls.push(call);
            if self.fail_first && self.calls.len() == 1 {
                Err(CosmeticError)
            } else {
                Ok(())
            }
        }
    }

    impl AuthenticationFeedback for FakeFeedback {
        type Error = CosmeticError;

        fn apply(&mut self, action: FeedbackAction) -> Result<(), Self::Error> {
            self.record(match action {
                FeedbackAction::ShowRetry => "retry",
                FeedbackAction::PauseAfterRetry => "pause-retry",
                FeedbackAction::ShowSuccess => "success",
                FeedbackAction::PauseAfterSuccess => "pause-success",
            })
        }
    }

    #[test]
    fn confirmed_results_select_exact_feedback_without_changing_outcome() {
        for (outcome, expected_calls) in [
            (
                MatchOutcome::Matched,
                [Some("success"), Some("pause-success")],
            ),
            (MatchOutcome::NoMatch, [Some("retry"), Some("pause-retry")]),
            (MatchOutcome::Cancelled, [None, None]),
            (MatchOutcome::TimedOut, [None, None]),
        ] {
            let mut feedback = FakeFeedback::available();
            assert_eq!(
                apply_authentication_feedback::<_, OperationError>(
                    Ok(outcome),
                    Some(&mut feedback)
                ),
                Ok(outcome)
            );
            assert_eq!(
                feedback.calls,
                expected_calls.into_iter().flatten().collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn cosmetic_absence_and_failure_never_change_authoritative_result() {
        assert_eq!(
            apply_authentication_feedback::<FakeFeedback, OperationError>(
                Ok(MatchOutcome::Matched),
                None
            ),
            Ok(MatchOutcome::Matched)
        );

        let mut feedback = FakeFeedback::failing();
        assert_eq!(
            apply_authentication_feedback::<_, OperationError>(
                Ok(MatchOutcome::Matched),
                Some(&mut feedback)
            ),
            Ok(MatchOutcome::Matched)
        );
        assert_eq!(feedback.calls, ["success"]);

        let mut feedback = FakeFeedback::available();
        assert_eq!(
            apply_authentication_feedback(Err(OperationError), Some(&mut feedback)),
            Err(OperationError)
        );
        assert!(feedback.calls.is_empty());
    }

    #[test]
    fn approval_uses_its_distinct_initial_state() {
        assert_eq!(
            initial_overlay_state(Purpose::Authenticate),
            OverlayState::Authenticate
        );
        assert_eq!(
            initial_overlay_state(Purpose::Approve),
            OverlayState::Approve
        );
        assert_eq!(
            initial_overlay_state(Purpose::Enrollment),
            OverlayState::Enrollment
        );
    }
}

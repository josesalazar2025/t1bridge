//! Fixed privileged Touch ID broker cancellation transaction.

use crate::touchid_cancel_ffi;

/// Authoritative result of delivering the one fixed cancellation request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CancelTouchIdOutcome {
    Delivered,
    Denied,
}

/// Redacted transport, validation, timeout, or protocol failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CancelTouchIdError;

/// Sends exactly one cancellation request to the fixed root broker under its
/// native 500 ms total deadline.
pub(crate) fn cancel_touch_id() -> Result<CancelTouchIdOutcome, CancelTouchIdError> {
    decode_result(touchid_cancel_ffi::cancel())
}

fn decode_result(result: i32) -> Result<CancelTouchIdOutcome, CancelTouchIdError> {
    match result {
        0 => Ok(CancelTouchIdOutcome::Delivered),
        1 => Ok(CancelTouchIdOutcome::Denied),
        _ => Err(CancelTouchIdError),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_the_two_native_terminal_outcomes() {
        assert_eq!(decode_result(0), Ok(CancelTouchIdOutcome::Delivered));
        assert_eq!(decode_result(1), Ok(CancelTouchIdOutcome::Denied));
        for error in -109..=-100 {
            assert_eq!(decode_result(error), Err(CancelTouchIdError));
        }
        assert_eq!(decode_result(2), Err(CancelTouchIdError));
    }
}

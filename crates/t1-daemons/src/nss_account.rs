//! Exact canonical NSS resolution for standard fingerprint requests.

use core::fmt;
use std::ffi::{CStr, CString, c_int};

use crate::nss_account_ffi;
use crate::standard_fingerprint_protocol::Username;
use crate::standard_operation_authority::{ResolvedStandardAccount, StandardAuthorityError};

/// Payload-free canonical account-resolution failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NssAccountError {
    /// The native boundary rejected an invalid argument.
    InvalidInput,
    /// NSS returned an operational failure, including a bounded-buffer limit.
    LookupFailed,
    /// NSS has no account for the asserted canonical name.
    NotFound,
    /// NSS returned a canonical name different from the asserted name.
    NonCanonical,
    /// The resolved account is UID zero.
    Root,
    /// The resolved UID cannot be carried in the broker contract.
    Unrepresentable,
    /// NSS or the native boundary returned an invalid result contract.
    InvalidResult,
    /// The native boundary returned an unknown status.
    NativeBoundary,
}

impl fmt::Display for NssAccountError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidInput => "NSS account input is invalid",
            Self::LookupFailed => "NSS account lookup failed",
            Self::NotFound => "NSS account was not found",
            Self::NonCanonical => "NSS account name is not canonical",
            Self::Root => "NSS account must be non-root",
            Self::Unrepresentable => "NSS account identifier is unsupported",
            Self::InvalidResult => "NSS account result is invalid",
            Self::NativeBoundary => "NSS account native boundary failed",
        })
    }
}

impl std::error::Error for NssAccountError {}

/// Resolves one prevalidated username to its exact canonical non-root account.
///
/// The native boundary uses one fixed-buffer `getpwnam_r` call. It performs no
/// retry, logging, environment inspection, privilege inference, or client UID
/// parsing.
///
/// # Errors
///
/// Returns a static, payload-free error for every rejected NSS result.
pub fn resolve_standard_account(
    username: &Username,
) -> Result<ResolvedStandardAccount, NssAccountError> {
    resolve_with(username, nss_account_ffi::resolve)
}

fn resolve_with(
    username: &Username,
    lookup: impl FnOnce(&CStr) -> (c_int, u32),
) -> Result<ResolvedStandardAccount, NssAccountError> {
    let native_name = CString::new(username.as_str()).map_err(|_| NssAccountError::InvalidInput)?;
    let (status, user_id) = lookup(&native_name);
    if status != nss_account_ffi::STATUS_OK {
        return Err(error_from_status(status));
    }
    ResolvedStandardAccount::new(username, username, user_id).map_err(|error| match error {
        StandardAuthorityError::NonCanonicalAccount => NssAccountError::NonCanonical,
        StandardAuthorityError::RootTarget => NssAccountError::Root,
    })
}

const fn error_from_status(status: c_int) -> NssAccountError {
    match status {
        nss_account_ffi::STATUS_INVALID_INPUT => NssAccountError::InvalidInput,
        nss_account_ffi::STATUS_LOOKUP_FAILED => NssAccountError::LookupFailed,
        nss_account_ffi::STATUS_NOT_FOUND => NssAccountError::NotFound,
        nss_account_ffi::STATUS_NON_CANONICAL => NssAccountError::NonCanonical,
        nss_account_ffi::STATUS_ROOT => NssAccountError::Root,
        nss_account_ffi::STATUS_UNREPRESENTABLE => NssAccountError::Unrepresentable,
        nss_account_ffi::STATUS_INVALID_RESULT => NssAccountError::InvalidResult,
        _ => NssAccountError::NativeBoundary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn username(value: &str) -> Username {
        Username::new(value).unwrap()
    }

    #[test]
    fn safe_wrapper_retains_the_exact_canonical_name_and_non_root_uid() {
        let asserted = username("synthetic-owner");
        let resolved = resolve_with(&asserted, |native| {
            assert_eq!(native.to_bytes(), b"synthetic-owner");
            (nss_account_ffi::STATUS_OK, 42_000)
        })
        .unwrap();

        assert_eq!(resolved.canonical_username(), &asserted);
        assert_eq!(resolved.user_id(), 42_000);
    }

    #[test]
    fn every_native_rejection_maps_to_one_payload_free_error() {
        for (status, expected) in [
            (
                nss_account_ffi::STATUS_INVALID_INPUT,
                NssAccountError::InvalidInput,
            ),
            (
                nss_account_ffi::STATUS_LOOKUP_FAILED,
                NssAccountError::LookupFailed,
            ),
            (nss_account_ffi::STATUS_NOT_FOUND, NssAccountError::NotFound),
            (
                nss_account_ffi::STATUS_NON_CANONICAL,
                NssAccountError::NonCanonical,
            ),
            (nss_account_ffi::STATUS_ROOT, NssAccountError::Root),
            (
                nss_account_ffi::STATUS_UNREPRESENTABLE,
                NssAccountError::Unrepresentable,
            ),
            (
                nss_account_ffi::STATUS_INVALID_RESULT,
                NssAccountError::InvalidResult,
            ),
            (c_int::MAX, NssAccountError::NativeBoundary),
        ] {
            let asserted = username("private-synthetic-name");
            let error = resolve_with(&asserted, |_| (status, u32::MAX)).unwrap_err();
            assert_eq!(error, expected);
            assert!(!format!("{error:?} {error}").contains(asserted.as_str()));
        }
    }

    #[test]
    fn native_success_still_rejects_root_before_authority_construction() {
        let asserted = username("synthetic-root");
        assert_eq!(
            resolve_with(&asserted, |_| (nss_account_ffi::STATUS_OK, 0)),
            Err(NssAccountError::Root)
        );
    }
}

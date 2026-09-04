//! Safe ownership boundary for dynamically discovered Apple EFI roots.

use std::fmt;
use std::os::fd::OwnedFd;

use crate::ffi;

/// Maximum number of EFI roots one discovery pass can return.
pub const ROOT_LIMIT: usize = 64;

/// Static failure from bounded device discovery or read-only mount handling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidArgument,
    EnumerationFailed,
    CandidateLimit,
    NamespaceFailed,
    InspectionFailed,
    CleanupFailed,
    Unknown,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidArgument => "invalid preserved-EFI discovery argument",
            Self::EnumerationFailed => "preserved-EFI device discovery failed",
            Self::CandidateLimit => "preserved-EFI candidate limit exceeded",
            Self::NamespaceFailed => "private preserved-EFI mount setup failed",
            Self::InspectionFailed => "preserved-EFI inspection failed",
            Self::CleanupFailed => "preserved-EFI cleanup failed",
            Self::Unknown => "unknown preserved-EFI discovery failure",
        })
    }
}

impl std::error::Error for Error {}

/// Returns whether this process has the root authority required by discovery.
#[must_use]
pub fn is_root() -> bool {
    ffi::preserved_efi_is_root()
}

/// Discovers every currently attached FAT ESP containing `EFI/APPLE`.
///
/// The native boundary performs bounded libudev enumeration, deterministic
/// device-number ordering, private read-only mounting, source filtering, and
/// complete cleanup. Only owned root directory descriptors cross into Rust.
///
/// # Errors
///
/// Returns a static, identifier-free category. No descriptor is transferred on
/// failure.
pub fn discover_roots() -> Result<Vec<OwnedFd>, Error> {
    let (status, roots) = ffi::discover_preserved_efi_roots(ROOT_LIMIT);
    check(status)?;
    roots.ok_or(Error::InspectionFailed)
}

fn check(status: i32) -> Result<(), Error> {
    match status {
        0 => Ok(()),
        1 => Err(Error::InvalidArgument),
        2 => Err(Error::EnumerationFailed),
        3 => Err(Error::CandidateLimit),
        4 => Err(Error::NamespaceFailed),
        5 => Err(Error::InspectionFailed),
        6 => Err(Error::CleanupFailed),
        _ => Err(Error::Unknown),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_every_native_status_and_unknown_values() {
        let expected = [
            Ok(()),
            Err(Error::InvalidArgument),
            Err(Error::EnumerationFailed),
            Err(Error::CandidateLimit),
            Err(Error::NamespaceFailed),
            Err(Error::InspectionFailed),
            Err(Error::CleanupFailed),
        ];
        for (status, expected) in (0_i32..).zip(expected) {
            assert_eq!(check(status), expected);
        }
        assert_eq!(check(-1), Err(Error::Unknown));
        assert_eq!(check(7), Err(Error::Unknown));
        assert_eq!(check(i32::MAX), Err(Error::Unknown));
    }
}

//! Safe access to one preserved Apple EFI firmware-data record.

use std::fmt;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};

use crate::ffi;

/// Static, redaction-safe failure from preserved-EFI inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidArgument,
    InvalidRoot,
    ComponentUnavailable,
    SourceUnavailable,
    InvalidSource,
    InspectionFailed,
    Unknown,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidArgument => "invalid preserved-EFI argument",
            Self::InvalidRoot => "preserved-EFI root is invalid",
            Self::ComponentUnavailable => "required preserved-EFI component is unavailable",
            Self::SourceUnavailable => "preserved firmware-data source is unavailable",
            Self::InvalidSource => "preserved firmware-data source is invalid",
            Self::InspectionFailed => "preserved firmware-data inspection failed",
            Self::Unknown => "unknown preserved-EFI inspection failure",
        })
    }
}

impl std::error::Error for Error {}

/// One validated, already-open firmware-data record from a preserved EFI root.
pub struct OpenedPreservedFdr {
    descriptor: OwnedFd,
    size: u64,
}

impl OpenedPreservedFdr {
    /// Borrows the validated regular-file descriptor.
    #[must_use]
    pub fn descriptor(&self) -> BorrowedFd<'_> {
        self.descriptor.as_fd()
    }

    /// Returns the size validated at the native inspection boundary.
    #[must_use]
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Transfers the open record and its validated size to the caller.
    #[must_use]
    pub fn into_parts(self) -> (OwnedFd, u64) {
        (self.descriptor, self.size)
    }
}

impl fmt::Debug for OpenedPreservedFdr {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpenedPreservedFdr([redacted])")
    }
}

/// Opens the fixed firmware-data record below an already-open EFI root.
///
/// The native boundary performs descriptor-relative traversal and returns one
/// owned descriptor only after validating the complete source.
///
/// # Errors
///
/// Returns a static error when the root, fixed component chain, source, or
/// inspection result is invalid or unavailable.
pub fn open_fdr(root: BorrowedFd<'_>) -> Result<OpenedPreservedFdr, Error> {
    let (status, opened) = ffi::open_preserved_fdr(root.as_raw_fd());
    crate::diagnostics::native(
        crate::diagnostics::Component::Efi,
        crate::diagnostics::Stage::EfiOpen,
        status,
    );
    check(status)?;
    let (descriptor, size) = opened.ok_or(Error::InspectionFailed)?;
    Ok(OpenedPreservedFdr { descriptor, size })
}

/// Opens a regular FDR backup or the fixed FDR descendant of an EFI directory.
///
/// # Errors
/// Rejects relative paths, symlink components, special files, and empty data.
/// Diagnostics never include the supplied path.
pub fn open_backup(path: &std::path::Path) -> Result<OpenedPreservedFdr, Error> {
    use std::os::unix::ffi::OsStrExt;

    let path =
        std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|_| Error::InvalidArgument)?;
    let (status, opened) = ffi::open_preserved_backup(&path);
    crate::diagnostics::native(
        crate::diagnostics::Component::Efi,
        crate::diagnostics::Stage::EfiOpen,
        status,
    );
    check(status)?;
    let (descriptor, size) = opened.ok_or(Error::InspectionFailed)?;
    Ok(OpenedPreservedFdr { descriptor, size })
}

fn check(status: i32) -> Result<(), Error> {
    match status {
        0 => Ok(()),
        1 => Err(Error::InvalidArgument),
        2 => Err(Error::InvalidRoot),
        3 => Err(Error::ComponentUnavailable),
        4 => Err(Error::SourceUnavailable),
        5 => Err(Error::InvalidSource),
        6 => Err(Error::InspectionFailed),
        _ => Err(Error::Unknown),
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    use super::*;

    #[test]
    fn maps_every_native_status_and_unknown_values() {
        let expected = [
            Ok(()),
            Err(Error::InvalidArgument),
            Err(Error::InvalidRoot),
            Err(Error::ComponentUnavailable),
            Err(Error::SourceUnavailable),
            Err(Error::InvalidSource),
            Err(Error::InspectionFailed),
        ];
        for (status, expected) in (0_i32..).zip(expected) {
            assert_eq!(check(status), expected);
        }
        assert_eq!(check(-1), Err(Error::Unknown));
        assert_eq!(check(7), Err(Error::Unknown));
        assert_eq!(check(i32::MAX), Err(Error::Unknown));
    }

    #[test]
    fn debug_output_does_not_disclose_descriptor_or_size() {
        let (stream, _peer) = UnixStream::pair().expect("create synthetic descriptor pair");
        let raw_descriptor = stream.as_raw_fd();
        let opened = OpenedPreservedFdr {
            descriptor: stream.into(),
            size: 0x0123_4567_89ab_cdef,
        };

        assert_eq!(format!("{opened:?}"), "OpenedPreservedFdr([redacted])");
        assert_ne!(raw_descriptor, -1);
    }

    #[test]
    fn accessors_borrow_and_then_transfer_owned_parts() {
        let (stream, _peer) = UnixStream::pair().expect("create synthetic descriptor pair");
        let expected_descriptor = stream.as_raw_fd();
        let opened = OpenedPreservedFdr {
            descriptor: stream.into(),
            size: 4096,
        };

        assert_eq!(opened.descriptor().as_raw_fd(), expected_descriptor);
        assert_eq!(opened.size(), 4096);
        let (descriptor, size) = opened.into_parts();
        assert_eq!(descriptor.as_raw_fd(), expected_descriptor);
        assert_eq!(size, 4096);
    }

    #[test]
    fn open_fdr_rejects_a_non_directory_root() {
        let (stream, _peer) = UnixStream::pair().expect("create synthetic descriptor pair");

        assert!(matches!(open_fdr(stream.as_fd()), Err(Error::InvalidRoot)));
    }
}

//! Race-safe filesystem operations for durable machine-data import.

use std::ffi::CString;
use std::fmt;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::ptr::NonNull;

use crate::ffi;

/// One directory name and its exact required permission mode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryComponent<'a> {
    name: &'a str,
    mode: u32,
}

impl<'a> DirectoryComponent<'a> {
    /// Describes one component below a trusted directory descriptor.
    #[must_use]
    pub const fn new(name: &'a str, mode: u32) -> Self {
        Self { name, mode }
    }
}

/// Validated state of the fixed calibration destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DestinationState {
    Absent,
    Valid,
    Invalid,
}

/// Validated state of the fixed same-directory temporary name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrphanState {
    Absent,
    Validated,
    Unsafe,
}

/// Static, redaction-safe native filesystem failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Another process holds the nonblocking directory reservation.
    AlreadyRunning,
    /// Validation, mutation, or the native contract failed.
    Failed,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AlreadyRunning => "another import is already running",
            Self::Failed => "import storage operation failed",
        })
    }
}

impl std::error::Error for Error {}

/// Exclusive reservation of the fixed destination and its parent directory.
///
/// Dropping this value closes every native descriptor and releases the
/// nonblocking directory lock. Names and record bytes are never retained by C.
pub struct Reservation {
    raw: NonNull<ffi::RawImportFs>,
}

impl Reservation {
    /// Traverses components without following links, validates their ownership
    /// and exact modes, and acquires one nonblocking exclusive directory lock.
    ///
    /// # Errors
    ///
    /// Returns a typed static failure if validation or reservation fails.
    pub fn reserve(
        anchor: BorrowedFd<'_>,
        components: &[DirectoryComponent<'_>],
        record_size: usize,
        record_limit: usize,
    ) -> Result<Self, Error> {
        let names = components
            .iter()
            .map(|component| CString::new(component.name).map_err(|_| Error::Failed))
            .collect::<Result<Vec<_>, _>>()?;
        let raw_components = names
            .iter()
            .zip(components)
            .map(|(name, component)| ffi::RawImportFsComponent {
                name: name.as_ptr(),
                mode: component.mode,
            })
            .collect::<Vec<_>>();
        let (status, raw) = ffi::reserve_import_fs(
            anchor.as_raw_fd(),
            &raw_components,
            record_size,
            record_limit,
        );
        if let Err(error) = check(status) {
            if !raw.is_null() {
                ffi::close_import_fs(raw);
            }
            return Err(error);
        }
        let raw = NonNull::new(raw).ok_or(Error::Failed)?;
        Ok(Self { raw })
    }

    /// Compares the complete fixed destination with the expected record.
    ///
    /// # Errors
    ///
    /// Returns a static failure if inspection cannot complete safely.
    pub fn inspect_destination(&mut self, expected: &[u8]) -> Result<DestinationState, Error> {
        let (status, state) = ffi::inspect_import_destination(self.raw.as_ptr(), expected);
        check(status)?;
        match state {
            0 => Ok(DestinationState::Absent),
            1 => Ok(DestinationState::Valid),
            2 => Ok(DestinationState::Invalid),
            _ => Err(Error::Failed),
        }
    }

    /// Inspects only the fixed same-directory temporary name.
    ///
    /// # Errors
    ///
    /// Returns a static failure if inspection cannot complete safely.
    pub fn inspect_orphan(&mut self) -> Result<OrphanState, Error> {
        let (status, state) = ffi::inspect_import_orphan(self.raw.as_ptr());
        check(status)?;
        match state {
            0 => Ok(OrphanState::Absent),
            1 => Ok(OrphanState::Validated),
            2 => Ok(OrphanState::Unsafe),
            _ => Err(Error::Failed),
        }
    }

    /// Removes the exact orphan previously validated by this reservation.
    ///
    /// # Errors
    ///
    /// Returns a static failure if it changed or removal fails.
    pub fn remove_validated_orphan(&mut self) -> Result<(), Error> {
        check(ffi::remove_import_orphan(self.raw.as_ptr()))
    }

    /// Creates the fixed private temporary file without replacing an object.
    ///
    /// # Errors
    ///
    /// Returns a static failure if exact private creation fails.
    pub fn create_private_temporary(&mut self) -> Result<(), Error> {
        check(ffi::create_import_temporary(self.raw.as_ptr()))
    }

    /// Writes the complete reserved record to the temporary file.
    ///
    /// # Errors
    ///
    /// Returns a static failure unless every byte is written exactly once.
    pub fn write_temporary(&mut self, record: &[u8]) -> Result<(), Error> {
        check(ffi::write_import_temporary(self.raw.as_ptr(), record))
    }

    /// Synchronizes the complete temporary file.
    ///
    /// # Errors
    ///
    /// Returns a static failure if the file is incomplete or sync fails.
    pub fn sync_temporary(&mut self) -> Result<(), Error> {
        check(ffi::sync_import_temporary(self.raw.as_ptr()))
    }

    /// Promotes the temporary file without replacing a destination.
    ///
    /// # Errors
    ///
    /// Returns a static failure if promotion conflicts or fails.
    pub fn rename_temporary(&mut self) -> Result<(), Error> {
        check(ffi::rename_import_temporary(self.raw.as_ptr()))
    }

    /// Synchronizes the locked destination directory after promotion.
    ///
    /// # Errors
    ///
    /// Returns a static failure when directory durability is not proven.
    pub fn sync_destination_directory(&mut self) -> Result<(), Error> {
        check(ffi::sync_import_directory(self.raw.as_ptr()))
    }
}

impl fmt::Debug for Reservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Reservation([redacted])")
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        ffi::close_import_fs(self.raw.as_ptr());
    }
}

fn check(status: i32) -> Result<(), Error> {
    match status {
        0 => Ok(()),
        6 => Err(Error::AlreadyRunning),
        _ => Err(Error::Failed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_busy_and_collapses_native_detail() {
        assert_eq!(check(0), Ok(()));
        assert_eq!(check(6), Err(Error::AlreadyRunning));
        for status in (1..=18).filter(|status| *status != 6) {
            assert_eq!(check(status), Err(Error::Failed));
        }
        assert_eq!(check(999), Err(Error::Failed));
    }
}

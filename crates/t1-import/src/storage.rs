//! Concrete protected storage for the validated machine calibration record.

use std::fmt;
use std::fs::File;
use std::os::fd::AsFd;

use t1_platform::import_fs::{self, DirectoryComponent, Reservation};

use crate::commit::{DestinationState, ImportCommitStorage, OrphanState, StorageFailure};
use crate::fdr::MAX_FDR_RECORD_SIZE;

const STANDARD_DIRECTORY_MODE: u32 = 0o755;
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;

const MACHINE_DATA_COMPONENTS: [DirectoryComponent<'static>; 4] = [
    DirectoryComponent::new("var", STANDARD_DIRECTORY_MODE),
    DirectoryComponent::new("lib", STANDARD_DIRECTORY_MODE),
    DirectoryComponent::new("t1bridge", PRIVATE_DIRECTORY_MODE),
    DirectoryComponent::new("machine-data", PRIVATE_DIRECTORY_MODE),
];

/// Production adapter for `/var/lib/t1bridge/machine-data/calibration.fscl`.
///
/// The fixed path has no machine identifier. Construction opens only the
/// trusted filesystem root; the native reservation later traverses each fixed
/// component without following links and requires root ownership.
pub struct MachineDataStorage {
    anchor: File,
    reservation: Option<Reservation>,
}

impl fmt::Debug for MachineDataStorage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MachineDataStorage([redacted])")
    }
}

impl MachineDataStorage {
    /// Opens the trusted filesystem root without creating or repairing state.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe failure if the root cannot be opened or
    /// inspected. Directory validation occurs when the commit is reserved.
    pub fn open() -> Result<Self, StorageFailure> {
        let anchor = File::open("/").map_err(|_| StorageFailure::Failed)?;
        Ok(Self {
            anchor,
            reservation: None,
        })
    }

    fn reservation(&mut self) -> Result<&mut Reservation, StorageFailure> {
        self.reservation.as_mut().ok_or(StorageFailure::Failed)
    }
}

impl ImportCommitStorage for MachineDataStorage {
    fn reserve_destination(&mut self, record_size: usize) -> Result<(), StorageFailure> {
        drop(self.reservation.take());
        self.reservation = Some(
            Reservation::reserve(
                self.anchor.as_fd(),
                &MACHINE_DATA_COMPONENTS,
                record_size,
                MAX_FDR_RECORD_SIZE,
            )
            .map_err(map_error)?,
        );
        Ok(())
    }

    fn inspect_destination(
        &mut self,
        expected_record: &[u8],
    ) -> Result<DestinationState, StorageFailure> {
        self.reservation()?
            .inspect_destination(expected_record)
            .map(|state| match state {
                import_fs::DestinationState::Absent => DestinationState::Absent,
                import_fs::DestinationState::Valid => DestinationState::Valid,
                import_fs::DestinationState::Invalid => DestinationState::Invalid,
            })
            .map_err(map_error)
    }

    fn inspect_orphan(&mut self) -> Result<OrphanState, StorageFailure> {
        self.reservation()?
            .inspect_orphan()
            .map(|state| match state {
                import_fs::OrphanState::Absent => OrphanState::Absent,
                import_fs::OrphanState::Validated => OrphanState::Validated,
                import_fs::OrphanState::Unsafe => OrphanState::Unsafe,
            })
            .map_err(map_error)
    }

    fn remove_validated_orphan(&mut self) -> Result<(), StorageFailure> {
        self.reservation()?
            .remove_validated_orphan()
            .map_err(map_error)
    }

    fn create_private_temporary(&mut self) -> Result<(), StorageFailure> {
        self.reservation()?
            .create_private_temporary()
            .map_err(map_error)
    }

    fn write_temporary(&mut self, record: &[u8]) -> Result<(), StorageFailure> {
        self.reservation()?
            .write_temporary(record)
            .map_err(map_error)
    }

    fn sync_temporary(&mut self) -> Result<(), StorageFailure> {
        self.reservation()?.sync_temporary().map_err(map_error)
    }

    fn rename_temporary(&mut self) -> Result<(), StorageFailure> {
        self.reservation()?.rename_temporary().map_err(map_error)
    }

    fn sync_destination_directory(&mut self) -> Result<(), StorageFailure> {
        self.reservation()?
            .sync_destination_directory()
            .map_err(map_error)
    }
}

fn map_error(error: import_fs::Error) -> StorageFailure {
    if error == import_fs::Error::AlreadyRunning {
        StorageFailure::AlreadyRunning
    } else {
        StorageFailure::Failed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_the_nonblocking_reservation_result() {
        assert_eq!(
            map_error(import_fs::Error::AlreadyRunning),
            StorageFailure::AlreadyRunning
        );
        assert_eq!(map_error(import_fs::Error::Failed), StorageFailure::Failed);
    }
}

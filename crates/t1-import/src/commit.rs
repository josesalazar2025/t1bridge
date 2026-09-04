//! Durable installation state machine for one validated calibration record.

use std::fmt;

use crate::fdr::FdrCalibrationRecord;

/// State of the exact destination after validation against the selected record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DestinationState {
    /// No object occupies the destination.
    Absent,
    /// The destination is a complete, private copy of the selected record.
    Valid,
    /// An object exists but does not satisfy every destination invariant.
    Invalid,
}

/// State of the one exact `T1Bridge` temporary name beside the destination.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OrphanState {
    /// No object occupies the temporary name.
    Absent,
    /// The object satisfies every invariant required for safe removal.
    Validated,
    /// An object exists but at least one removal invariant is not proven.
    Unsafe,
}

/// Redaction-safe failure returned by an injected storage implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageFailure {
    /// Another process holds the one nonblocking import reservation.
    AlreadyRunning,
    /// Storage validation or mutation failed without exposing local details.
    Failed,
}

/// Storage operations required by the durable import coordinator.
///
/// This trait intentionally does not include an operation that deletes or
/// replaces the destination. A live adapter must keep a race-safe reservation
/// for the exact destination and its parent directory across the whole call.
/// All inspection must reject symlinks rather than follow them.
pub trait ImportCommitStorage {
    /// Reserves the exact destination without mutating filesystem contents.
    ///
    /// The reservation must cover a record of `record_size` bytes and bind all
    /// later operations to the same destination and parent directory.
    ///
    /// # Errors
    ///
    /// Returns an opaque failure if those guarantees cannot be established.
    fn reserve_destination(&mut self, record_size: usize) -> Result<(), StorageFailure>;

    /// Revalidates the destination against the complete selected record.
    ///
    /// # Errors
    ///
    /// Returns an opaque failure if inspection cannot complete safely.
    fn inspect_destination(
        &mut self,
        expected_record: &[u8],
    ) -> Result<DestinationState, StorageFailure>;

    /// Inspects only the exact `T1Bridge` temporary name in the reserved directory.
    ///
    /// [`OrphanState::Validated`] requires the exact name and directory, a
    /// regular root-owned private file, and proof that no symlink was followed.
    ///
    /// # Errors
    ///
    /// Returns an opaque failure if every property cannot be inspected safely.
    fn inspect_orphan(&mut self) -> Result<OrphanState, StorageFailure>;

    /// Removes the orphan previously returned as [`OrphanState::Validated`].
    ///
    /// # Errors
    ///
    /// Returns an opaque failure if removal does not complete.
    fn remove_validated_orphan(&mut self) -> Result<(), StorageFailure>;

    /// Creates a new private temporary file in the reserved destination directory.
    ///
    /// # Errors
    ///
    /// Returns an opaque failure if private same-directory creation fails.
    fn create_private_temporary(&mut self) -> Result<(), StorageFailure>;

    /// Writes the complete selected record to the private temporary file.
    ///
    /// # Errors
    ///
    /// Returns an opaque failure if the complete write does not finish.
    fn write_temporary(&mut self, record: &[u8]) -> Result<(), StorageFailure>;

    /// Synchronizes the complete temporary file.
    ///
    /// # Errors
    ///
    /// Returns an opaque failure if file synchronization does not finish.
    fn sync_temporary(&mut self) -> Result<(), StorageFailure>;

    /// Atomically renames the synchronized temporary file to the destination.
    ///
    /// # Errors
    ///
    /// Returns an opaque failure if atomic rename does not finish.
    fn rename_temporary(&mut self) -> Result<(), StorageFailure>;

    /// Synchronizes the reserved destination directory after promotion or
    /// revalidation of an existing destination.
    ///
    /// # Errors
    ///
    /// Returns an opaque failure if directory synchronization does not finish.
    fn sync_destination_directory(&mut self) -> Result<(), StorageFailure>;
}

/// Successful result of an import commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitOutcome {
    /// The record was written, renamed, and made durable.
    Installed,
    /// A complete valid destination already held the selected record.
    AlreadyInstalled,
}

/// Redaction-safe failure from the durable import coordinator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CommitError {
    /// Another import attempt already owns the destination reservation.
    AlreadyRunning,
    /// The destination could not be reserved without mutation.
    ReservationFailed,
    /// The destination could not be inspected.
    DestinationInspectionFailed,
    /// An existing destination failed validation and was left untouched.
    InvalidDestination,
    /// The exact temporary name could not be inspected.
    OrphanInspectionFailed,
    /// An object at the temporary name was not proven safe to remove.
    UnsafeOrphan,
    /// A fully validated orphan could not be removed.
    OrphanRemovalFailed,
    /// A private same-directory temporary file could not be created.
    TemporaryCreationFailed,
    /// The complete record could not be written to the temporary file.
    TemporaryWriteFailed,
    /// The temporary file could not be synchronized.
    TemporarySyncFailed,
    /// The synchronized temporary file could not be atomically renamed.
    RenameFailed,
    /// Destination-directory durability is not proven.
    DurabilityUncertain,
}

impl fmt::Display for CommitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AlreadyRunning => "another import is already running",
            Self::ReservationFailed => "import destination reservation failed",
            Self::DestinationInspectionFailed => "import destination inspection failed",
            Self::InvalidDestination => "import destination is invalid",
            Self::OrphanInspectionFailed => "import temporary-file inspection failed",
            Self::UnsafeOrphan => "import temporary file is not safe to remove",
            Self::OrphanRemovalFailed => "validated import temporary file could not be removed",
            Self::TemporaryCreationFailed => "private import temporary file could not be created",
            Self::TemporaryWriteFailed => "import temporary file write failed",
            Self::TemporarySyncFailed => "import temporary file synchronization failed",
            Self::RenameFailed => "import destination replacement failed",
            Self::DurabilityUncertain => "import destination durability is uncertain",
        })
    }
}

impl std::error::Error for CommitError {}

/// Durably installs one validated device-bound calibration record.
///
/// `record` can only be constructed by the complete FDR selection and hardware
/// association validator. Invoking this function is the mutation authority;
/// the selected bytes are cleared before it returns.
///
/// A valid existing destination is revalidated without replacement, any exact
/// validated orphan is cleaned up, and the directory is synchronized before
/// success.
/// An unsafe orphan or invalid destination is always left untouched. Once
/// rename succeeds, the destination is never deleted: a subsequent directory
/// synchronization failure returns [`CommitError::DurabilityUncertain`].
///
/// # Errors
///
/// Returns a static, redaction-safe error when an invariant is not proven or
/// any storage operation fails.
pub fn commit_fdr_calibration<S: ImportCommitStorage>(
    storage: &mut S,
    record: FdrCalibrationRecord,
) -> Result<CommitOutcome, CommitError> {
    let mut bytes = TemporaryBytes::new(record.into_bytes());
    let result = commit_validated(storage, bytes.as_slice());
    bytes.wipe();
    result
}

fn commit_validated<S: ImportCommitStorage>(
    storage: &mut S,
    record: &[u8],
) -> Result<CommitOutcome, CommitError> {
    storage.reserve_destination(record.len()).map_err(|error| {
        if error == StorageFailure::AlreadyRunning {
            CommitError::AlreadyRunning
        } else {
            CommitError::ReservationFailed
        }
    })?;

    let destination = storage
        .inspect_destination(record)
        .map_err(|_| CommitError::DestinationInspectionFailed)?;
    match destination {
        DestinationState::Invalid => return Err(CommitError::InvalidDestination),
        DestinationState::Absent | DestinationState::Valid => {}
    }

    cleanup_orphan(storage)?;

    if destination == DestinationState::Valid {
        storage
            .sync_destination_directory()
            .map_err(|_| CommitError::DurabilityUncertain)?;
        return Ok(CommitOutcome::AlreadyInstalled);
    }

    storage
        .create_private_temporary()
        .map_err(|_| CommitError::TemporaryCreationFailed)?;
    storage
        .write_temporary(record)
        .map_err(|_| CommitError::TemporaryWriteFailed)?;
    storage
        .sync_temporary()
        .map_err(|_| CommitError::TemporarySyncFailed)?;
    storage
        .rename_temporary()
        .map_err(|_| CommitError::RenameFailed)?;
    storage
        .sync_destination_directory()
        .map_err(|_| CommitError::DurabilityUncertain)?;
    Ok(CommitOutcome::Installed)
}

fn cleanup_orphan<S: ImportCommitStorage>(storage: &mut S) -> Result<(), CommitError> {
    match storage
        .inspect_orphan()
        .map_err(|_| CommitError::OrphanInspectionFailed)?
    {
        OrphanState::Absent => {}
        OrphanState::Unsafe => return Err(CommitError::UnsafeOrphan),
        OrphanState::Validated => storage
            .remove_validated_orphan()
            .map_err(|_| CommitError::OrphanRemovalFailed)?,
    }
    Ok(())
}

struct TemporaryBytes(Vec<u8>);

impl TemporaryBytes {
    const fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn wipe(&mut self) {
        self.0.fill(0);
    }
}

impl Drop for TemporaryBytes {
    fn drop(&mut self) {
        self.wipe();
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::fdr::select_fdr_calibration;
    use t1_bridge::bplist::{self, Value};
    use t1_bridge::calibration::MODULE_SERIAL_NUMBER_SIZE;

    const MODULE_SERIAL: &[u8; MODULE_SERIAL_NUMBER_SIZE] = b"SYNTHETICMODULE001";

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Operation {
        Reserve,
        InspectDestination,
        InspectOrphan,
        RemoveOrphan,
        CreateTemporary,
        WriteTemporary,
        SyncTemporary,
        RenameTemporary,
        SyncDirectory,
    }

    struct Storage {
        destination: DestinationState,
        orphan: OrphanState,
        fail: Option<Operation>,
        failure: StorageFailure,
        operations: Vec<Operation>,
        expected_record: Vec<u8>,
    }

    impl Storage {
        fn new(record: &[u8]) -> Self {
            Self {
                destination: DestinationState::Absent,
                orphan: OrphanState::Absent,
                fail: None,
                failure: StorageFailure::Failed,
                operations: Vec::new(),
                expected_record: record.to_vec(),
            }
        }

        fn operation(&mut self, operation: Operation) -> Result<(), StorageFailure> {
            self.operations.push(operation);
            if self.fail == Some(operation) {
                Err(self.failure)
            } else {
                Ok(())
            }
        }
    }

    impl ImportCommitStorage for Storage {
        fn reserve_destination(&mut self, record_size: usize) -> Result<(), StorageFailure> {
            assert_eq!(record_size, self.expected_record.len());
            self.operation(Operation::Reserve)
        }

        fn inspect_destination(
            &mut self,
            expected_record: &[u8],
        ) -> Result<DestinationState, StorageFailure> {
            assert_eq!(expected_record, self.expected_record);
            self.operation(Operation::InspectDestination)?;
            Ok(self.destination)
        }

        fn inspect_orphan(&mut self) -> Result<OrphanState, StorageFailure> {
            self.operation(Operation::InspectOrphan)?;
            Ok(self.orphan)
        }

        fn remove_validated_orphan(&mut self) -> Result<(), StorageFailure> {
            assert_eq!(self.orphan, OrphanState::Validated);
            self.operation(Operation::RemoveOrphan)
        }

        fn create_private_temporary(&mut self) -> Result<(), StorageFailure> {
            self.operation(Operation::CreateTemporary)
        }

        fn write_temporary(&mut self, record: &[u8]) -> Result<(), StorageFailure> {
            assert_eq!(record, self.expected_record);
            self.operation(Operation::WriteTemporary)
        }

        fn sync_temporary(&mut self) -> Result<(), StorageFailure> {
            self.operation(Operation::SyncTemporary)
        }

        fn rename_temporary(&mut self) -> Result<(), StorageFailure> {
            self.operation(Operation::RenameTemporary)
        }

        fn sync_destination_directory(&mut self) -> Result<(), StorageFailure> {
            self.operation(Operation::SyncDirectory)
        }
    }

    fn record() -> FdrCalibrationRecord {
        let calibration = calibration_blob(MODULE_SERIAL);
        let im4p = der_sequence(&[
            der(0x16, b"IM4P"),
            der(0x16, b"FSCl"),
            der(0x16, b"1.0"),
            der(0x04, &calibration),
        ]);
        let img4 = der_sequence(&[der(0x16, b"IMG4"), im4p]);
        let fdrd = der_sequence(&[der(0x16, b"fdrd"), der(0x04, &img4)]);
        let outer = der_sequence(&[der(0x16, b"comb"), fdrd]);
        let key = "FSCl-SYNTHETICMODULE001".to_owned();
        let plist = bplist::encode(&Value::Dictionary(BTreeMap::from([(
            key,
            Value::Data(outer),
        )])))
        .unwrap();
        select_fdr_calibration(&plist, MODULE_SERIAL).unwrap()
    }

    fn calibration_blob(module_serial: &[u8; MODULE_SERIAL_NUMBER_SIZE]) -> Vec<u8> {
        let mut calibration = vec![0_u8; 96];
        let length = u32::try_from(calibration.len()).unwrap();
        calibration[4..8].copy_from_slice(&length.to_le_bytes());
        calibration[16..20].copy_from_slice(b"CALB");
        calibration[32..50].copy_from_slice(module_serial);
        calibration
    }

    fn der_sequence(children: &[Vec<u8>]) -> Vec<u8> {
        der(0x30, &children.concat())
    }

    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut output = vec![tag];
        if content.len() < 0x80 {
            output.push(u8::try_from(content.len()).unwrap());
        } else {
            output.extend_from_slice(&[0x81, u8::try_from(content.len()).unwrap()]);
        }
        output.extend_from_slice(content);
        output
    }

    #[test]
    fn installs_in_the_exact_durable_order() {
        let selected = record();
        let mut storage = Storage::new(selected.as_bytes());
        assert_eq!(
            commit_fdr_calibration(&mut storage, selected),
            Ok(CommitOutcome::Installed)
        );
        assert_eq!(
            storage.operations,
            [
                Operation::Reserve,
                Operation::InspectDestination,
                Operation::InspectOrphan,
                Operation::CreateTemporary,
                Operation::WriteTemporary,
                Operation::SyncTemporary,
                Operation::RenameTemporary,
                Operation::SyncDirectory,
            ]
        );
    }

    #[test]
    fn revalidates_an_existing_destination_without_mutation() {
        let selected = record();
        let mut storage = Storage::new(selected.as_bytes());
        storage.destination = DestinationState::Valid;
        assert_eq!(
            commit_fdr_calibration(&mut storage, selected),
            Ok(CommitOutcome::AlreadyInstalled)
        );
        assert_eq!(
            storage.operations,
            [
                Operation::Reserve,
                Operation::InspectDestination,
                Operation::InspectOrphan,
                Operation::SyncDirectory,
            ]
        );
    }

    #[test]
    fn invalid_destination_is_left_untouched() {
        let selected = record();
        let mut storage = Storage::new(selected.as_bytes());
        storage.destination = DestinationState::Invalid;
        assert_eq!(
            commit_fdr_calibration(&mut storage, selected),
            Err(CommitError::InvalidDestination)
        );
        assert_eq!(
            storage.operations,
            [Operation::Reserve, Operation::InspectDestination]
        );
    }

    #[test]
    fn removes_only_a_fully_validated_orphan() {
        let selected = record();
        let mut storage = Storage::new(selected.as_bytes());
        storage.orphan = OrphanState::Validated;
        assert_eq!(
            commit_fdr_calibration(&mut storage, selected),
            Ok(CommitOutcome::Installed)
        );
        assert_eq!(storage.operations[3], Operation::RemoveOrphan);

        let selected = record();
        let mut storage = Storage::new(selected.as_bytes());
        storage.destination = DestinationState::Valid;
        storage.orphan = OrphanState::Validated;
        assert_eq!(
            commit_fdr_calibration(&mut storage, selected),
            Ok(CommitOutcome::AlreadyInstalled)
        );
        assert_eq!(
            &storage.operations[2..],
            [
                Operation::InspectOrphan,
                Operation::RemoveOrphan,
                Operation::SyncDirectory,
            ]
        );

        let selected = record();
        let mut storage = Storage::new(selected.as_bytes());
        storage.orphan = OrphanState::Unsafe;
        assert_eq!(
            commit_fdr_calibration(&mut storage, selected),
            Err(CommitError::UnsafeOrphan)
        );
        assert_eq!(
            storage.operations,
            [
                Operation::Reserve,
                Operation::InspectDestination,
                Operation::InspectOrphan,
            ]
        );
    }

    #[test]
    fn every_storage_failure_stops_before_the_next_operation() {
        let cases = [
            (Operation::Reserve, CommitError::ReservationFailed),
            (
                Operation::InspectDestination,
                CommitError::DestinationInspectionFailed,
            ),
            (
                Operation::InspectOrphan,
                CommitError::OrphanInspectionFailed,
            ),
            (
                Operation::CreateTemporary,
                CommitError::TemporaryCreationFailed,
            ),
            (Operation::WriteTemporary, CommitError::TemporaryWriteFailed),
            (Operation::SyncTemporary, CommitError::TemporarySyncFailed),
            (Operation::RenameTemporary, CommitError::RenameFailed),
        ];
        for (operation, expected) in cases {
            let selected = record();
            let mut storage = Storage::new(selected.as_bytes());
            storage.fail = Some(operation);
            assert_eq!(
                commit_fdr_calibration(&mut storage, selected),
                Err(expected)
            );
            assert_eq!(storage.operations.last(), Some(&operation));
        }

        let selected = record();
        let mut storage = Storage::new(selected.as_bytes());
        storage.orphan = OrphanState::Validated;
        storage.fail = Some(Operation::RemoveOrphan);
        assert_eq!(
            commit_fdr_calibration(&mut storage, selected),
            Err(CommitError::OrphanRemovalFailed)
        );
        assert_eq!(storage.operations.last(), Some(&Operation::RemoveOrphan));
    }

    #[test]
    fn a_busy_reservation_is_not_collapsed_into_a_storage_failure() {
        let selected = record();
        let mut storage = Storage::new(selected.as_bytes());
        storage.fail = Some(Operation::Reserve);
        storage.failure = StorageFailure::AlreadyRunning;

        assert_eq!(
            commit_fdr_calibration(&mut storage, selected),
            Err(CommitError::AlreadyRunning)
        );
        assert_eq!(storage.operations, [Operation::Reserve]);
    }

    #[test]
    fn post_rename_sync_failure_is_typed_as_uncertain_and_never_rolled_back() {
        let selected = record();
        let mut storage = Storage::new(selected.as_bytes());
        storage.fail = Some(Operation::SyncDirectory);
        assert_eq!(
            commit_fdr_calibration(&mut storage, selected),
            Err(CommitError::DurabilityUncertain)
        );
        assert_eq!(
            &storage.operations[storage.operations.len() - 2..],
            [Operation::RenameTemporary, Operation::SyncDirectory]
        );

        storage.destination = DestinationState::Valid;
        storage.operations.clear();
        assert_eq!(
            commit_fdr_calibration(&mut storage, record()),
            Err(CommitError::DurabilityUncertain)
        );
        assert_eq!(storage.operations.last(), Some(&Operation::SyncDirectory));

        storage.fail = None;
        storage.operations.clear();
        assert_eq!(
            commit_fdr_calibration(&mut storage, record()),
            Ok(CommitOutcome::AlreadyInstalled)
        );
        assert_eq!(
            storage.operations,
            [
                Operation::Reserve,
                Operation::InspectDestination,
                Operation::InspectOrphan,
                Operation::SyncDirectory,
            ]
        );
    }

    #[test]
    fn temporary_bytes_and_errors_are_redaction_safe() {
        let mut bytes = TemporaryBytes::new(vec![0xa5; 32]);
        bytes.wipe();
        assert!(bytes.as_slice().iter().all(|byte| *byte == 0));

        for error in [
            CommitError::AlreadyRunning,
            CommitError::ReservationFailed,
            CommitError::DestinationInspectionFailed,
            CommitError::InvalidDestination,
            CommitError::OrphanInspectionFailed,
            CommitError::UnsafeOrphan,
            CommitError::OrphanRemovalFailed,
            CommitError::TemporaryCreationFailed,
            CommitError::TemporaryWriteFailed,
            CommitError::TemporarySyncFailed,
            CommitError::RenameFailed,
            CommitError::DurabilityUncertain,
        ] {
            let rendered = format!("{error:?} {error}");
            assert!(!rendered.contains("SYNTHETIC"));
            assert!(!rendered.contains('/'));
        }
    }
}

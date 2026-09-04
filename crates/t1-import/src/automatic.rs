//! One-shot automatic import policy for first boot and explicit retries.

use std::fmt;

use t1_bridge::calibration::MODULE_SERIAL_NUMBER_SIZE;

use crate::commit::{CommitError, CommitOutcome, ImportCommitStorage, commit_fdr_calibration};
use crate::fdr::{FdrCalibrationRecord, MatchingRecordSelectionError, select_matching_record};

/// Label exposed by a desktop integration after a failed attempt.
pub const RETRY_ACTION_LABEL: &str = "Retry setup";

/// Hardware features named by the single failure notification.
pub const AFFECTED_FEATURES: [&str; 4] = [
    "Touch Bar, including Esc and the function-key row",
    "Touch ID",
    "FaceTime camera",
    "ambient-light sensor",
];

/// Redaction-safe failure while obtaining records matched to the live sensor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceError {
    /// The live sensor association could not be queried.
    HardwareUnavailable,
    /// No preserved local Apple source was available.
    AppleDataUnavailable,
    /// A preserved source could not be read safely.
    AppleDataUnreadable,
    /// Preserved Apple data failed structural or association validation.
    AppleDataInvalid,
}

impl fmt::Display for SourceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::HardwareUnavailable => "the T1 sensor is unavailable",
            Self::AppleDataUnavailable => "preserved Apple machine data was not found",
            Self::AppleDataUnreadable => "preserved Apple machine data could not be read safely",
            Self::AppleDataInvalid => "preserved Apple machine data is invalid for this hardware",
        })
    }
}

impl std::error::Error for SourceError {}

/// Supplies every record already validated against one live sensor association.
pub trait MatchingRecordSource {
    /// Performs one bounded read-only discovery and validation pass.
    ///
    /// # Errors
    ///
    /// Returns a static category that contains no path, hardware association,
    /// record bytes, identifier, or underlying system diagnostic.
    fn read_matching_records(&mut self) -> Result<Vec<FdrCalibrationRecord>, SourceError>;
}

/// One short-lived read-only session with the physical T1 sensor.
///
/// The production implementation owns all transport state and must not expose
/// the association through a command line, environment, cache, configuration,
/// or diagnostic. Closing consumes the session so it cannot be reused for the
/// subsequent storage commit.
pub trait LiveAssociationSession {
    /// Reads the fixed-width Mesa module association once.
    ///
    /// # Errors
    ///
    /// Returns only a redaction-safe source category.
    fn read_association(&mut self) -> Result<[u8; MODULE_SERIAL_NUMBER_SIZE], SourceError>;

    /// Closes the read-only hardware session before preserved sources are read.
    ///
    /// # Errors
    ///
    /// Returns only a redaction-safe source category.
    fn close(self) -> Result<(), SourceError>;
}

/// Opens the dynamically verified physical T1 for a read-only association query.
pub trait LiveAssociationSource {
    type Session: LiveAssociationSession;

    /// Opens one fresh session without accepting caller-supplied association
    /// data.
    ///
    /// # Errors
    ///
    /// Returns only a redaction-safe source category.
    fn open_read_only(&mut self) -> Result<Self::Session, SourceError>;
}

/// Reads every preserved local record matching one ephemeral live association.
pub trait PreservedRecordReader {
    /// Performs one bounded read-only source pass.
    ///
    /// Implementations must use the association only during this call and must
    /// not log, persist, cache, or return it.
    ///
    /// # Errors
    ///
    /// Returns only a redaction-safe source category.
    fn read_matching_records(
        &mut self,
        association: &[u8; MODULE_SERIAL_NUMBER_SIZE],
    ) -> Result<Vec<FdrCalibrationRecord>, SourceError>;
}

/// Direct live-sensor association followed by preserved-source evaluation.
///
/// The sensor session is always consumed before any preserved source is read,
/// and therefore before [`attempt_automatic_import`] can mutate protected
/// storage. The association exists only in one stack-owned fixed array and is
/// cleared before this method returns.
pub struct DirectMatchingRecordSource<Live, Preserved> {
    live: Live,
    preserved: Preserved,
}

impl<Live, Preserved> DirectMatchingRecordSource<Live, Preserved> {
    #[must_use]
    pub const fn new(live: Live, preserved: Preserved) -> Self {
        Self { live, preserved }
    }

    /// Returns the owned adapters for caller-controlled teardown or reuse.
    #[must_use]
    pub fn into_inner(self) -> (Live, Preserved) {
        (self.live, self.preserved)
    }
}

impl<Live, Preserved> MatchingRecordSource for DirectMatchingRecordSource<Live, Preserved>
where
    Live: LiveAssociationSource,
    Preserved: PreservedRecordReader,
{
    fn read_matching_records(&mut self) -> Result<Vec<FdrCalibrationRecord>, SourceError> {
        let mut session = self.live.open_read_only()?;
        let association_result = session.read_association();
        let close_result = session.close();

        let mut association = association_result?;
        if let Err(error) = close_result {
            association.fill(0);
            return Err(error);
        }

        let result = self.preserved.read_matching_records(&association);
        association.fill(0);
        result
    }
}

/// Redaction-safe failure from one automatic import attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AutomaticImportError {
    /// Live hardware or preserved-source acquisition failed.
    Source(SourceError),
    /// Matching preserved copies were absent or disagreed.
    Selection(MatchingRecordSelectionError),
    /// Durable protected-storage commit failed.
    Commit(CommitError),
}

impl fmt::Display for AutomaticImportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(error) => error.fmt(formatter),
            Self::Selection(error) => error.fmt(formatter),
            Self::Commit(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for AutomaticImportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Source(error) => Some(error),
            Self::Selection(error) => Some(error),
            Self::Commit(error) => Some(error),
        }
    }
}

/// Runs exactly one automatic import attempt.
///
/// The source is read once. Byte-identical matching copies collapse to one;
/// conflicting copies stop before storage access. A selected record is passed
/// once to the idempotent durable commit coordinator. This function contains
/// no retry loop, notification transport, or source mutation.
///
/// # Errors
///
/// Returns the specific redaction-safe failure category for the desktop's
/// single retry notification.
pub fn attempt_automatic_import<R, S>(
    source: &mut R,
    storage: &mut S,
) -> Result<CommitOutcome, AutomaticImportError>
where
    R: MatchingRecordSource,
    S: ImportCommitStorage,
{
    let records = source
        .read_matching_records()
        .map_err(AutomaticImportError::Source)?;
    let record = select_matching_record(records).map_err(AutomaticImportError::Selection)?;
    commit_fdr_calibration(storage, record).map_err(AutomaticImportError::Commit)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commit::{DestinationState, OrphanState, StorageFailure};
    use std::cell::RefCell;
    use std::rc::Rc;

    struct Source {
        calls: usize,
        records: Vec<FdrCalibrationRecord>,
        failure: Option<SourceError>,
    }

    impl MatchingRecordSource for Source {
        fn read_matching_records(&mut self) -> Result<Vec<FdrCalibrationRecord>, SourceError> {
            self.calls += 1;
            if let Some(error) = self.failure {
                return Err(error);
            }
            Ok(std::mem::take(&mut self.records))
        }
    }

    #[derive(Default)]
    struct Storage {
        calls: usize,
        destination_valid: bool,
    }

    impl ImportCommitStorage for Storage {
        fn reserve_destination(&mut self, _: usize) -> Result<(), StorageFailure> {
            self.calls += 1;
            Ok(())
        }

        fn inspect_destination(&mut self, _: &[u8]) -> Result<DestinationState, StorageFailure> {
            self.calls += 1;
            Ok(if self.destination_valid {
                DestinationState::Valid
            } else {
                DestinationState::Absent
            })
        }

        fn inspect_orphan(&mut self) -> Result<OrphanState, StorageFailure> {
            self.calls += 1;
            Ok(OrphanState::Absent)
        }

        fn remove_validated_orphan(&mut self) -> Result<(), StorageFailure> {
            unreachable!("the test storage has no orphan")
        }

        fn create_private_temporary(&mut self) -> Result<(), StorageFailure> {
            self.calls += 1;
            Ok(())
        }

        fn write_temporary(&mut self, _: &[u8]) -> Result<(), StorageFailure> {
            self.calls += 1;
            Ok(())
        }

        fn sync_temporary(&mut self) -> Result<(), StorageFailure> {
            self.calls += 1;
            Ok(())
        }

        fn rename_temporary(&mut self) -> Result<(), StorageFailure> {
            self.calls += 1;
            self.destination_valid = true;
            Ok(())
        }

        fn sync_destination_directory(&mut self) -> Result<(), StorageFailure> {
            self.calls += 1;
            Ok(())
        }
    }

    fn source(records: &[&[u8]]) -> Source {
        Source {
            calls: 0,
            records: records
                .iter()
                .map(|bytes| FdrCalibrationRecord::from_validated_test_bytes(bytes))
                .collect(),
            failure: None,
        }
    }

    struct LiveSource {
        calls: Rc<RefCell<Vec<&'static str>>>,
        open_failure: Option<SourceError>,
        association_failure: Option<SourceError>,
        close_failure: Option<SourceError>,
    }

    struct LiveSession {
        calls: Rc<RefCell<Vec<&'static str>>>,
        association_failure: Option<SourceError>,
        close_failure: Option<SourceError>,
    }

    impl LiveAssociationSource for LiveSource {
        type Session = LiveSession;

        fn open_read_only(&mut self) -> Result<Self::Session, SourceError> {
            self.calls.borrow_mut().push("open");
            if let Some(error) = self.open_failure {
                return Err(error);
            }
            Ok(LiveSession {
                calls: Rc::clone(&self.calls),
                association_failure: self.association_failure,
                close_failure: self.close_failure,
            })
        }
    }

    impl LiveAssociationSession for LiveSession {
        fn read_association(&mut self) -> Result<[u8; MODULE_SERIAL_NUMBER_SIZE], SourceError> {
            self.calls.borrow_mut().push("association");
            if let Some(error) = self.association_failure {
                return Err(error);
            }
            Ok(*b"SYNTHETICMODULE001")
        }

        fn close(self) -> Result<(), SourceError> {
            self.calls.borrow_mut().push("close");
            self.close_failure.map_or(Ok(()), Err)
        }
    }

    struct PreservedSource {
        calls: Rc<RefCell<Vec<&'static str>>>,
        records: Vec<FdrCalibrationRecord>,
    }

    impl PreservedRecordReader for PreservedSource {
        fn read_matching_records(
            &mut self,
            association: &[u8; MODULE_SERIAL_NUMBER_SIZE],
        ) -> Result<Vec<FdrCalibrationRecord>, SourceError> {
            assert_eq!(association, b"SYNTHETICMODULE001");
            self.calls.borrow_mut().push("preserved");
            Ok(std::mem::take(&mut self.records))
        }
    }

    fn direct_source(
        calls: &Rc<RefCell<Vec<&'static str>>>,
    ) -> DirectMatchingRecordSource<LiveSource, PreservedSource> {
        DirectMatchingRecordSource::new(
            LiveSource {
                calls: Rc::clone(calls),
                open_failure: None,
                association_failure: None,
                close_failure: None,
            },
            PreservedSource {
                calls: Rc::clone(calls),
                records: vec![FdrCalibrationRecord::from_validated_test_bytes(
                    b"SYNTHETIC-RECORD",
                )],
            },
        )
    }

    #[test]
    fn direct_source_closes_hardware_before_reading_preserved_data() {
        let calls = Rc::new(RefCell::new(Vec::new()));
        let mut source = direct_source(&calls);

        let records = source.read_matching_records().unwrap();

        assert_eq!(records.len(), 1);
        assert_eq!(
            calls.borrow().as_slice(),
            ["open", "association", "close", "preserved"]
        );
    }

    #[test]
    fn association_and_close_failures_never_read_preserved_data() {
        for (association_failure, close_failure) in [
            (Some(SourceError::HardwareUnavailable), None),
            (None, Some(SourceError::HardwareUnavailable)),
        ] {
            let calls = Rc::new(RefCell::new(Vec::new()));
            let mut source = direct_source(&calls);
            source.live.association_failure = association_failure;
            source.live.close_failure = close_failure;

            assert_eq!(
                source.read_matching_records(),
                Err(SourceError::HardwareUnavailable)
            );
            assert!(!calls.borrow().contains(&"preserved"));
            assert_eq!(calls.borrow().last(), Some(&"close"));
        }
    }

    #[test]
    fn one_attempt_reads_once_collapses_duplicates_and_commits_once() {
        let mut source = source(&[b"SYNTHETIC-RECORD", b"SYNTHETIC-RECORD"]);
        let mut storage = Storage::default();
        assert_eq!(
            attempt_automatic_import(&mut source, &mut storage),
            Ok(CommitOutcome::Installed)
        );
        assert_eq!(source.calls, 1);
        assert_eq!(storage.calls, 8);
    }

    #[test]
    fn conflicting_copies_stop_before_storage_access() {
        let mut source = source(&[b"SYNTHETIC-ONE", b"SYNTHETIC-TWO"]);
        let mut storage = Storage::default();
        assert_eq!(
            attempt_automatic_import(&mut source, &mut storage),
            Err(AutomaticImportError::Selection(
                MatchingRecordSelectionError::ConflictingRecords { count: 2 }
            ))
        );
        assert_eq!(source.calls, 1);
        assert_eq!(storage.calls, 0);
    }

    #[test]
    fn a_user_retry_is_one_new_idempotent_attempt() {
        let mut storage = Storage::default();
        let mut first = source(&[b"SYNTHETIC-RECORD"]);
        assert_eq!(
            attempt_automatic_import(&mut first, &mut storage),
            Ok(CommitOutcome::Installed)
        );

        let calls_after_first = storage.calls;
        let mut retry = source(&[b"SYNTHETIC-RECORD"]);
        assert_eq!(
            attempt_automatic_import(&mut retry, &mut storage),
            Ok(CommitOutcome::AlreadyInstalled)
        );
        assert_eq!(retry.calls, 1);
        assert_eq!(storage.calls - calls_after_first, 4);
    }

    #[test]
    fn source_failures_do_not_access_storage_or_leak_details() {
        for failure in [
            SourceError::HardwareUnavailable,
            SourceError::AppleDataUnavailable,
            SourceError::AppleDataUnreadable,
            SourceError::AppleDataInvalid,
        ] {
            let mut source = Source {
                calls: 0,
                records: Vec::new(),
                failure: Some(failure),
            };
            let mut storage = Storage::default();
            let error = attempt_automatic_import(&mut source, &mut storage).unwrap_err();
            assert_eq!(error, AutomaticImportError::Source(failure));
            assert_eq!(source.calls, 1);
            assert_eq!(storage.calls, 0);
            let diagnostic = format!("{error:?} {error}");
            assert!(!diagnostic.contains("SYNTHETIC"));
        }
    }
}

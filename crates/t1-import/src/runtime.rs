//! Composition seams for protected import from automatic system discovery or
//! caller-owned preserved roots.

use std::fmt;
use std::os::fd::OwnedFd;

use crate::automatic::{
    AutomaticImportError, DirectMatchingRecordSource, LiveAssociationSource,
    attempt_automatic_import,
};
use crate::commit::{CommitOutcome, ImportCommitStorage};
use crate::preserved::{
    EnumeratedPreservedRecordReader, FilesystemPreservedSourceEnumeration,
    SystemPreservedSourceEnumeration,
};
use crate::session::LiveT1AssociationSource;
use crate::storage::MachineDataStorage;

/// Failure from opening protected storage or executing one bounded import.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtectedImportError {
    /// The fixed root-owned destination could not be opened safely.
    StorageUnavailable,
    /// Source selection or durable commit failed.
    Import(AutomaticImportError),
}

impl fmt::Display for ProtectedImportError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StorageUnavailable => {
                formatter.write_str("protected machine-data storage is unavailable")
            }
            Self::Import(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ProtectedImportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::StorageUnavailable => None,
            Self::Import(error) => Some(error),
        }
    }
}

/// Performs one protected import from caller-discovered, already-open roots.
///
/// This is the production live-session and storage composition, not a complete
/// CLI or ESP discovery provider. It accepts no paths, hardware association,
/// identifiers, configuration, or environment input. Root order is retained,
/// every root is consumed by the descriptor-relative validated reader, and the
/// destination is the fixed protected machine-data location.
///
/// # Errors
///
/// Returns only redaction-safe storage, source, selection, or commit failures.
pub fn attempt_protected_import_from_open_roots<I>(
    roots: I,
) -> Result<CommitOutcome, ProtectedImportError>
where
    I: IntoIterator<Item = OwnedFd>,
{
    let storage =
        MachineDataStorage::open().map_err(|_| ProtectedImportError::StorageUnavailable)?;
    attempt_import_from_open_roots(LiveT1AssociationSource, storage, roots)
        .map_err(ProtectedImportError::Import)
}

/// Performs one automatic protected import from currently attached Apple ESPs.
///
/// Device discovery and source mounting are deferred until after the live T1
/// association session has closed. No path, identifier, configuration, or
/// caller-supplied association participates in selection.
///
/// # Errors
///
/// Returns only redaction-safe storage, source, selection, or commit failures.
pub fn attempt_protected_import() -> Result<CommitOutcome, ProtectedImportError> {
    let mut storage =
        MachineDataStorage::open().map_err(|_| ProtectedImportError::StorageUnavailable)?;
    let preserved = EnumeratedPreservedRecordReader::new(SystemPreservedSourceEnumeration::new());
    let mut source = DirectMatchingRecordSource::new(LiveT1AssociationSource, preserved);
    attempt_automatic_import(&mut source, &mut storage).map_err(ProtectedImportError::Import)
}

/// Composes one live-association source and commit store with open ESP roots.
///
/// This injection seam exists for behavior tests and callers that already own
/// governed root descriptors. The normal administrative command uses
/// [`attempt_protected_import`] for automatic system discovery.
///
/// # Errors
///
/// Returns the automatic importer's redaction-safe source, selection, or
/// commit failure without adding path or identifier context.
pub fn attempt_import_from_open_roots<Live, Storage, Roots>(
    live: Live,
    mut storage: Storage,
    roots: Roots,
) -> Result<CommitOutcome, AutomaticImportError>
where
    Live: LiveAssociationSource,
    Storage: ImportCommitStorage,
    Roots: IntoIterator<Item = OwnedFd>,
{
    let enumeration = FilesystemPreservedSourceEnumeration::new(roots.into_iter());
    let preserved = EnumeratedPreservedRecordReader::new(enumeration);
    let mut source = DirectMatchingRecordSource::new(live, preserved);
    attempt_automatic_import(&mut source, &mut storage)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::BTreeMap;
    use std::fs::{self, File};
    use std::io;
    use std::os::fd::OwnedFd;
    use std::path::PathBuf;
    use std::rc::Rc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use t1_bridge::bplist::{self, Value};
    use t1_bridge::calibration::MODULE_SERIAL_NUMBER_SIZE;

    use crate::automatic::{LiveAssociationSession, SourceError};
    use crate::commit::{DestinationState, OrphanState, StorageFailure};

    use super::*;

    const ASSOCIATION: &[u8; MODULE_SERIAL_NUMBER_SIZE] = b"SYNTHETICMODULE001";
    const OTHER_ASSOCIATION: &[u8; MODULE_SERIAL_NUMBER_SIZE] = b"SYNTHETICMODULE002";
    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct Root {
        path: PathBuf,
    }

    impl Root {
        fn with_fdr(bytes: &[u8]) -> Self {
            for _ in 0..100 {
                let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "t1bridge-runtime-test-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => {
                        let parent = path.join("EFI/APPLE/EMBEDDEDOS");
                        fs::create_dir_all(&parent).unwrap();
                        fs::write(parent.join("FDRData"), bytes).unwrap();
                        return Self { path };
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("could not create test root: {error}"),
                }
            }
            panic!("could not allocate a test root");
        }

        fn open(&self) -> OwnedFd {
            File::open(&self.path).unwrap().into()
        }
    }

    impl Drop for Root {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.path).unwrap();
        }
    }

    struct Live {
        association: Result<[u8; MODULE_SERIAL_NUMBER_SIZE], SourceError>,
    }

    struct Session {
        association: Result<[u8; MODULE_SERIAL_NUMBER_SIZE], SourceError>,
    }

    impl LiveAssociationSource for Live {
        type Session = Session;

        fn open_read_only(&mut self) -> Result<Self::Session, SourceError> {
            Ok(Session {
                association: self.association,
            })
        }
    }

    impl LiveAssociationSession for Session {
        fn read_association(&mut self) -> Result<[u8; MODULE_SERIAL_NUMBER_SIZE], SourceError> {
            self.association
        }

        fn close(self) -> Result<(), SourceError> {
            Ok(())
        }
    }

    struct Storage {
        record: Option<Vec<u8>>,
        calls: Rc<Cell<usize>>,
    }

    impl Storage {
        fn new(calls: Rc<Cell<usize>>) -> Self {
            Self {
                record: None,
                calls,
            }
        }

        fn called(&self) {
            self.calls.set(self.calls.get() + 1);
        }
    }

    impl ImportCommitStorage for Storage {
        fn reserve_destination(&mut self, _: usize) -> Result<(), StorageFailure> {
            self.called();
            Ok(())
        }

        fn inspect_destination(
            &mut self,
            expected: &[u8],
        ) -> Result<DestinationState, StorageFailure> {
            self.called();
            Ok(match self.record.as_deref() {
                None => DestinationState::Absent,
                Some(current) if current == expected => DestinationState::Valid,
                Some(_) => DestinationState::Invalid,
            })
        }

        fn inspect_orphan(&mut self) -> Result<OrphanState, StorageFailure> {
            self.called();
            Ok(OrphanState::Absent)
        }

        fn remove_validated_orphan(&mut self) -> Result<(), StorageFailure> {
            unreachable!("test storage has no orphan")
        }

        fn create_private_temporary(&mut self) -> Result<(), StorageFailure> {
            self.called();
            Ok(())
        }

        fn write_temporary(&mut self, record: &[u8]) -> Result<(), StorageFailure> {
            self.called();
            self.record = Some(record.to_vec());
            Ok(())
        }

        fn sync_temporary(&mut self) -> Result<(), StorageFailure> {
            self.called();
            Ok(())
        }

        fn rename_temporary(&mut self) -> Result<(), StorageFailure> {
            self.called();
            Ok(())
        }

        fn sync_destination_directory(&mut self) -> Result<(), StorageFailure> {
            self.called();
            Ok(())
        }
    }

    #[test]
    fn imports_the_only_live_matched_record_from_open_roots() {
        let nonmatching = Root::with_fdr(&fdr_data(OTHER_ASSOCIATION, 1));
        let matching = Root::with_fdr(&fdr_data(ASSOCIATION, 2));
        let storage_calls = Rc::new(Cell::new(0));

        let outcome = attempt_import_from_open_roots(
            Live {
                association: Ok(*ASSOCIATION),
            },
            Storage::new(Rc::clone(&storage_calls)),
            [nonmatching.open(), matching.open()],
        )
        .unwrap();

        assert_eq!(outcome, CommitOutcome::Installed);
        assert!(storage_calls.get() > 0);
    }

    #[test]
    fn conflicting_matching_roots_fail_before_storage_mutation() {
        let first = Root::with_fdr(&fdr_data(ASSOCIATION, 1));
        let second = Root::with_fdr(&fdr_data(ASSOCIATION, 2));
        let storage_calls = Rc::new(Cell::new(0));

        let error = attempt_import_from_open_roots(
            Live {
                association: Ok(*ASSOCIATION),
            },
            Storage::new(Rc::clone(&storage_calls)),
            [first.open(), second.open()],
        )
        .unwrap_err();

        assert!(matches!(error, AutomaticImportError::Selection(_)));
        assert_eq!(storage_calls.get(), 0);
    }

    #[test]
    fn hardware_failure_prevents_preserved_root_inspection() {
        let empty = Root::with_fdr(b"not FDR data");
        let storage_calls = Rc::new(Cell::new(0));

        let error = attempt_import_from_open_roots(
            Live {
                association: Err(SourceError::HardwareUnavailable),
            },
            Storage::new(Rc::clone(&storage_calls)),
            [empty.open()],
        )
        .unwrap_err();

        assert_eq!(
            error,
            AutomaticImportError::Source(SourceError::HardwareUnavailable)
        );
        assert_eq!(storage_calls.get(), 0);
    }

    fn fdr_data(association: &[u8; MODULE_SERIAL_NUMBER_SIZE], marker: u8) -> Vec<u8> {
        let key = format!("FSCl-{}", std::str::from_utf8(association).unwrap());
        bplist::encode(&Value::Dictionary(BTreeMap::from([(
            key,
            Value::Data(fdr_record(association, marker)),
        )])))
        .unwrap()
    }

    fn fdr_record(association: &[u8; MODULE_SERIAL_NUMBER_SIZE], marker: u8) -> Vec<u8> {
        let mut calibration = vec![0_u8; 96];
        calibration[4..8].copy_from_slice(&96_u32.to_le_bytes());
        calibration[16..20].copy_from_slice(b"CALB");
        calibration[32..50].copy_from_slice(association);
        calibration[64] = marker;
        let im4p = der_sequence(&[
            der(0x16, b"IM4P"),
            der(0x16, b"FSCl"),
            der(0x16, b"1.0"),
            der(0x04, &calibration),
        ]);
        let img4 = der_sequence(&[der(0x16, b"IMG4"), im4p]);
        let fdrd = der_sequence(&[der(0x16, b"fdrd"), der(0x04, &img4)]);
        der_sequence(&[der(0x16, b"comb"), fdrd])
    }

    fn der_sequence(children: &[Vec<u8>]) -> Vec<u8> {
        der(0x30, &children.concat())
    }

    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut encoded = vec![tag];
        if content.len() < 128 {
            encoded.push(u8::try_from(content.len()).unwrap());
        } else {
            let bytes = content.len().to_be_bytes();
            let first = bytes.iter().position(|byte| *byte != 0).unwrap();
            encoded.push(0x80 | u8::try_from(bytes.len() - first).unwrap());
            encoded.extend_from_slice(&bytes[first..]);
        }
        encoded.extend_from_slice(content);
        encoded
    }
}

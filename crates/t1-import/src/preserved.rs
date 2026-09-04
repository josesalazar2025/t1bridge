//! Bounded validation of already-open preserved FDR sources.

use std::fs::File;
use std::io::{Read, Seek};
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;

use t1_bridge::calibration::MODULE_SERIAL_NUMBER_SIZE;
use t1_platform::preserved_efi::{Error as PreservedEfiError, open_fdr};
use t1_platform::preserved_efi_discovery::{Error as PreservedEfiDiscoveryError, discover_roots};

use crate::automatic::{PreservedRecordReader, SourceError};
use crate::discovery::MAX_CANDIDATES;
use crate::fdr::{self, FdrCalibrationRecord};
use crate::operation::{ImportError, read_direct_fdr_calibration};
use crate::walk::WalkError;

/// One already-open, path-free preserved FDR source.
pub struct PreservedFdrSource<R> {
    reader: R,
    byte_len: u64,
}

impl<R> PreservedFdrSource<R> {
    /// Wraps an already-open reader and its exact declared byte length.
    #[must_use]
    pub const fn new(reader: R, byte_len: u64) -> Self {
        Self { reader, byte_len }
    }
}

/// Enumerates already-open preserved FDR sources without exposing their paths.
pub trait PreservedSourceEnumeration {
    /// Seekable reader owned by each yielded source.
    type Reader: Read + Seek;

    /// Yields the next already-open source in caller-defined order.
    ///
    /// # Errors
    ///
    /// Returns only a redaction-safe source category.
    fn next_source(&mut self) -> Result<Option<PreservedFdrSource<Self::Reader>>, SourceError>;
}

/// Opens one explicitly selected backup only after the live session closes.
pub struct BackupSourceEnumeration<'a> {
    path: Option<&'a Path>,
}

impl<'a> BackupSourceEnumeration<'a> {
    #[must_use]
    pub const fn new(path: &'a Path) -> Self {
        Self { path: Some(path) }
    }
}

impl PreservedSourceEnumeration for BackupSourceEnumeration<'_> {
    type Reader = File;

    fn next_source(&mut self) -> Result<Option<PreservedFdrSource<File>>, SourceError> {
        let Some(path) = self.path.take() else {
            return Ok(None);
        };
        let opened =
            t1_platform::preserved_efi::open_backup(path).map_err(map_preserved_efi_error)?;
        let (descriptor, byte_len) = opened.into_parts();
        Ok(Some(PreservedFdrSource::new(
            File::from(descriptor),
            byte_len,
        )))
    }
}

/// Opens the fixed `FDRData` descendant of caller-opened preserved ESP roots.
///
/// Roots and sources remain descriptor-owned throughout this adapter. No path
/// is accepted or returned, and at most [`MAX_CANDIDATES`] roots are inspected.
pub struct FilesystemPreservedSourceEnumeration<I> {
    roots: I,
    root_count: usize,
    terminal: bool,
}

/// Lazily discovers currently attached Apple EFI roots in production.
///
/// Discovery is deferred until the first source request so the enclosing
/// automatic policy can query and close the live sensor session first.
#[derive(Default)]
pub struct SystemPreservedSourceEnumeration {
    attempted: bool,
    roots: Option<FilesystemPreservedSourceEnumeration<std::vec::IntoIter<OwnedFd>>>,
}

impl SystemPreservedSourceEnumeration {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            attempted: false,
            roots: None,
        }
    }
}

impl PreservedSourceEnumeration for SystemPreservedSourceEnumeration {
    type Reader = File;

    fn next_source(&mut self) -> Result<Option<PreservedFdrSource<File>>, SourceError> {
        if !self.attempted {
            self.attempted = true;
            let roots = discover_roots().map_err(map_discovery_error)?;
            self.roots = Some(FilesystemPreservedSourceEnumeration::new(roots.into_iter()));
        }
        self.roots
            .as_mut()
            .ok_or(SourceError::AppleDataUnreadable)?
            .next_source()
    }
}

fn map_discovery_error(error: PreservedEfiDiscoveryError) -> SourceError {
    match error {
        PreservedEfiDiscoveryError::CandidateLimit
        | PreservedEfiDiscoveryError::InvalidArgument => SourceError::AppleDataInvalid,
        PreservedEfiDiscoveryError::EnumerationFailed
        | PreservedEfiDiscoveryError::NamespaceFailed
        | PreservedEfiDiscoveryError::InspectionFailed
        | PreservedEfiDiscoveryError::CleanupFailed
        | PreservedEfiDiscoveryError::Unknown => SourceError::AppleDataUnreadable,
    }
}

impl<I> FilesystemPreservedSourceEnumeration<I> {
    /// Takes ownership of preserved ESP root descriptors in caller-defined
    /// order.
    #[must_use]
    pub const fn new(roots: I) -> Self {
        Self {
            roots,
            root_count: 0,
            terminal: false,
        }
    }

    /// Returns the remaining owned root enumeration.
    #[must_use]
    pub fn into_inner(self) -> I {
        self.roots
    }
}

impl<I> PreservedSourceEnumeration for FilesystemPreservedSourceEnumeration<I>
where
    I: Iterator<Item = OwnedFd>,
{
    type Reader = File;

    fn next_source(&mut self) -> Result<Option<PreservedFdrSource<File>>, SourceError> {
        if self.terminal {
            return Ok(None);
        }

        let Some(root) = self.roots.next() else {
            self.terminal = true;
            return Ok(None);
        };

        if self.root_count == MAX_CANDIDATES {
            self.terminal = true;
            return Err(SourceError::AppleDataInvalid);
        }
        self.root_count += 1;

        let opened = open_fdr(root.as_fd()).map_err(|error| {
            self.terminal = true;
            map_preserved_efi_error(error)
        })?;
        let (descriptor, byte_len) = opened.into_parts();
        Ok(Some(PreservedFdrSource::new(
            File::from(descriptor),
            byte_len,
        )))
    }
}

fn map_preserved_efi_error(error: PreservedEfiError) -> SourceError {
    match error {
        PreservedEfiError::InvalidArgument
        | PreservedEfiError::InvalidRoot
        | PreservedEfiError::InvalidSource
        | PreservedEfiError::Unknown => SourceError::AppleDataInvalid,
        PreservedEfiError::ComponentUnavailable
        | PreservedEfiError::SourceUnavailable
        | PreservedEfiError::InspectionFailed => SourceError::AppleDataUnreadable,
    }
}

/// Adapts already-open preserved sources to the automatic importer.
pub struct EnumeratedPreservedRecordReader<E> {
    enumeration: E,
}

impl<E> EnumeratedPreservedRecordReader<E> {
    /// Creates a bounded preserved-record reader.
    #[must_use]
    pub const fn new(enumeration: E) -> Self {
        Self { enumeration }
    }

    /// Returns the owned enumeration adapter.
    #[must_use]
    pub fn into_inner(self) -> E {
        self.enumeration
    }
}

impl<E> PreservedRecordReader for EnumeratedPreservedRecordReader<E>
where
    E: PreservedSourceEnumeration,
{
    fn read_matching_records(
        &mut self,
        association: &[u8; MODULE_SERIAL_NUMBER_SIZE],
    ) -> Result<Vec<FdrCalibrationRecord>, SourceError> {
        let mut records = Vec::new();
        let mut source_count = 0_usize;

        while let Some(source) = self.enumeration.next_source()? {
            if source_count == MAX_CANDIDATES {
                return Err(SourceError::AppleDataInvalid);
            }
            source_count += 1;

            let PreservedFdrSource {
                mut reader,
                byte_len,
            } = source;
            match read_direct_fdr_calibration(&mut reader, byte_len, association) {
                Ok(record) => records.push(record),
                Err(ImportError::Fdr(fdr::Error::MissingModuleRecord)) => {}
                Err(error) => return Err(map_import_error(error)),
            }
        }

        if source_count == 0 {
            Err(SourceError::AppleDataUnavailable)
        } else {
            Ok(records)
        }
    }
}

fn map_import_error(error: ImportError) -> SourceError {
    match error {
        ImportError::Reader(_)
        | ImportError::SourceSizeMismatch { .. }
        | ImportError::AllocationFailed
        | ImportError::Walk(WalkError::Reader(_) | WalkError::AllocationFailed) => {
            SourceError::AppleDataUnreadable
        }
        ImportError::InvalidSourceSize { .. }
        | ImportError::UnsupportedSource
        | ImportError::Walk(_)
        | ImportError::Fdr(_) => SourceError::AppleDataInvalid,
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::{BTreeMap, VecDeque};
    use std::fs;
    use std::io::{self, Cursor, Read, Seek, SeekFrom};
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};
    use std::rc::Rc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use t1_bridge::bplist::{self, Value};

    use super::*;

    const MODULE_SERIAL: &[u8; MODULE_SERIAL_NUMBER_SIZE] = b"SYNTHETICMODULE001";
    const OTHER_MODULE: &[u8; MODULE_SERIAL_NUMBER_SIZE] = b"SYNTHETICMODULE002";
    const FDR_COMPONENTS: [&str; 4] = ["EFI", "APPLE", "EMBEDDEDOS", "FDRData"];

    static NEXT_TEMP_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TempRoot {
        path: PathBuf,
    }

    impl TempRoot {
        fn new() -> Self {
            for _ in 0..100 {
                let sequence = NEXT_TEMP_DIRECTORY.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir().join(format!(
                    "t1bridge-preserved-efi-test-{}-{sequence}",
                    std::process::id()
                ));
                match fs::create_dir(&path) {
                    Ok(()) => return Self { path },
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(error) => panic!("could not create test directory: {error}"),
                }
            }
            panic!("could not allocate a unique test directory");
        }

        fn create_parent_components(&self) -> PathBuf {
            let parent = FDR_COMPONENTS[..FDR_COMPONENTS.len() - 1]
                .iter()
                .fold(self.path.clone(), |path, component| path.join(component));
            fs::create_dir_all(&parent).unwrap();
            parent
        }

        fn write_fdr(&self, bytes: &[u8]) {
            let parent = self.create_parent_components();
            fs::write(parent.join(FDR_COMPONENTS[FDR_COMPONENTS.len() - 1]), bytes).unwrap();
        }

        fn open(&self) -> OwnedFd {
            File::open(&self.path).unwrap().into()
        }

        fn as_path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.path).unwrap();
        }
    }

    struct Enumeration<R> {
        sources: VecDeque<Result<PreservedFdrSource<R>, SourceError>>,
        calls: Rc<Cell<usize>>,
    }

    impl<R> PreservedSourceEnumeration for Enumeration<R>
    where
        R: Read + Seek,
    {
        type Reader = R;

        fn next_source(&mut self) -> Result<Option<PreservedFdrSource<R>>, SourceError> {
            self.calls.set(self.calls.get() + 1);
            self.sources.pop_front().transpose()
        }
    }

    struct TrackingReader {
        inner: Cursor<Vec<u8>>,
        operations: Rc<Cell<usize>>,
    }

    impl TrackingReader {
        fn new(bytes: Vec<u8>, operations: Rc<Cell<usize>>) -> Self {
            Self {
                inner: Cursor::new(bytes),
                operations,
            }
        }
    }

    impl Read for TrackingReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.operations.set(self.operations.get() + 1);
            self.inner.read(buffer)
        }
    }

    impl Seek for TrackingReader {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.operations.set(self.operations.get() + 1);
            self.inner.seek(position)
        }
    }

    struct BrokenReader;

    impl Read for BrokenReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::Other))
        }
    }

    impl Seek for BrokenReader {
        fn seek(&mut self, _: SeekFrom) -> io::Result<u64> {
            Err(io::Error::from(io::ErrorKind::Other))
        }
    }

    fn enumeration<R>(
        sources: impl IntoIterator<Item = Result<PreservedFdrSource<R>, SourceError>>,
    ) -> (Enumeration<R>, Rc<Cell<usize>>) {
        let calls = Rc::new(Cell::new(0));
        (
            Enumeration {
                sources: sources.into_iter().collect(),
                calls: Rc::clone(&calls),
            },
            calls,
        )
    }

    fn source(bytes: Vec<u8>) -> PreservedFdrSource<Cursor<Vec<u8>>> {
        let byte_len = u64::try_from(bytes.len()).unwrap();
        PreservedFdrSource::new(Cursor::new(bytes), byte_len)
    }

    fn read<R>(
        sources: impl IntoIterator<Item = Result<PreservedFdrSource<R>, SourceError>>,
    ) -> Result<Vec<FdrCalibrationRecord>, SourceError>
    where
        R: Read + Seek,
    {
        let (enumeration, _) = enumeration(sources);
        EnumeratedPreservedRecordReader::new(enumeration).read_matching_records(MODULE_SERIAL)
    }

    #[test]
    fn reports_unavailable_when_no_source_is_yielded() {
        let sources = Vec::<Result<PreservedFdrSource<Cursor<Vec<u8>>>, SourceError>>::new();
        assert_eq!(read(sources), Err(SourceError::AppleDataUnavailable));
    }

    #[test]
    fn filesystem_enumeration_reports_unavailable_for_zero_roots() {
        let roots = Vec::<OwnedFd>::new();
        let enumeration = FilesystemPreservedSourceEnumeration::new(roots.into_iter());
        let mut reader = EnumeratedPreservedRecordReader::new(enumeration);

        assert_eq!(
            reader.read_matching_records(MODULE_SERIAL),
            Err(SourceError::AppleDataUnavailable)
        );
    }

    #[test]
    fn filesystem_enumeration_preserves_matching_source_order() {
        let nonmatching = TempRoot::new();
        nonmatching.write_fdr(&fdr_data(OTHER_MODULE, 1));
        let first = TempRoot::new();
        first.write_fdr(&fdr_data(MODULE_SERIAL, 2));
        let second = TempRoot::new();
        second.write_fdr(&fdr_data(MODULE_SERIAL, 3));
        let roots = vec![nonmatching.open(), first.open(), second.open()];
        let enumeration = FilesystemPreservedSourceEnumeration::new(roots.into_iter());
        let mut reader = EnumeratedPreservedRecordReader::new(enumeration);

        let records = reader.read_matching_records(MODULE_SERIAL).unwrap();

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].as_bytes(), fdr_record(MODULE_SERIAL, 2));
        assert_eq!(records[1].as_bytes(), fdr_record(MODULE_SERIAL, 3));
    }

    #[test]
    fn filesystem_enumeration_accepts_exactly_sixty_four_roots() {
        let root = TempRoot::new();
        root.write_fdr(&fdr_data(OTHER_MODULE, 1));
        let roots = (0..MAX_CANDIDATES).map(|_| root.open()).collect::<Vec<_>>();
        let enumeration = FilesystemPreservedSourceEnumeration::new(roots.into_iter());
        let mut reader = EnumeratedPreservedRecordReader::new(enumeration);

        assert!(
            reader
                .read_matching_records(MODULE_SERIAL)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn filesystem_enumeration_rejects_root_sixty_five_before_opening_it() {
        let valid = TempRoot::new();
        valid.write_fdr(&fdr_data(OTHER_MODULE, 1));
        let missing_components = TempRoot::new();
        let mut roots = (0..MAX_CANDIDATES)
            .map(|_| valid.open())
            .collect::<Vec<_>>();
        roots.push(missing_components.open());
        let mut enumeration = FilesystemPreservedSourceEnumeration::new(roots.into_iter());

        for _ in 0..MAX_CANDIDATES {
            assert!(matches!(enumeration.next_source(), Ok(Some(_))));
        }
        assert!(matches!(
            enumeration.next_source(),
            Err(SourceError::AppleDataInvalid)
        ));
        assert!(matches!(enumeration.next_source(), Ok(None)));
    }

    #[test]
    fn filesystem_enumeration_redacts_final_component_failures() {
        let missing = TempRoot::new();
        missing.create_parent_components();
        let mut missing_enumeration =
            FilesystemPreservedSourceEnumeration::new(vec![missing.open()].into_iter());
        assert!(matches!(
            missing_enumeration.next_source(),
            Err(SourceError::AppleDataUnreadable)
        ));
        assert!(matches!(missing_enumeration.next_source(), Ok(None)));

        let symlinked = TempRoot::new();
        let symlink_parent = symlinked.create_parent_components();
        fs::write(symlinked.as_path().join("fixture-data"), b"fixture").unwrap();
        symlink(
            symlinked.as_path().join("fixture-data"),
            symlink_parent.join(FDR_COMPONENTS[FDR_COMPONENTS.len() - 1]),
        )
        .unwrap();
        let mut symlink_enumeration =
            FilesystemPreservedSourceEnumeration::new(vec![symlinked.open()].into_iter());
        assert!(matches!(
            symlink_enumeration.next_source(),
            Err(SourceError::AppleDataInvalid)
        ));
        assert!(matches!(symlink_enumeration.next_source(), Ok(None)));

        let directory = TempRoot::new();
        let directory_parent = directory.create_parent_components();
        fs::create_dir(directory_parent.join(FDR_COMPONENTS[FDR_COMPONENTS.len() - 1])).unwrap();
        let mut directory_enumeration =
            FilesystemPreservedSourceEnumeration::new(vec![directory.open()].into_iter());
        assert!(matches!(
            directory_enumeration.next_source(),
            Err(SourceError::AppleDataInvalid)
        ));
        assert!(matches!(directory_enumeration.next_source(), Ok(None)));
    }

    #[test]
    fn filesystem_source_and_caller_root_have_independent_ownership() {
        let root = TempRoot::new();
        let expected = fdr_data(MODULE_SERIAL, 1);
        root.write_fdr(&expected);
        let caller_root = File::open(root.as_path()).unwrap();
        let enumerated_root = OwnedFd::from(caller_root.try_clone().unwrap());
        let mut enumeration =
            FilesystemPreservedSourceEnumeration::new(vec![enumerated_root].into_iter());

        let mut source = enumeration.next_source().unwrap().unwrap();
        drop(enumeration);
        assert!(caller_root.metadata().unwrap().is_dir());

        let mut actual = Vec::new();
        source.reader.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn skips_valid_nonmatching_sources() {
        let records = read([Ok(source(fdr_data(OTHER_MODULE, 1)))]).unwrap();
        assert!(records.is_empty());
    }

    #[test]
    fn rejects_a_malformed_record_claiming_the_live_association() {
        let key = format!("FSCl-{}", std::str::from_utf8(MODULE_SERIAL).unwrap());
        let malformed =
            bplist::encode(&Value::Dictionary(BTreeMap::from([(key, Value::Null)]))).unwrap();

        assert_eq!(
            read([Ok(source(malformed))]),
            Err(SourceError::AppleDataInvalid)
        );
    }

    #[test]
    fn retains_matching_records_unchanged_and_in_source_order() {
        let first = fdr_record(MODULE_SERIAL, 1);
        let second = fdr_record(MODULE_SERIAL, 2);
        let (enumeration, calls) = enumeration([
            Ok(source(fdr_data(MODULE_SERIAL, 1))),
            Ok(source(fdr_data(MODULE_SERIAL, 2))),
        ]);
        let mut reader = EnumeratedPreservedRecordReader::new(enumeration);

        let records = reader.read_matching_records(MODULE_SERIAL).unwrap();

        assert_eq!(records.len(), 2);
        assert_eq!(records[0].as_bytes(), first);
        assert_eq!(records[1].as_bytes(), second);
        assert_eq!(calls.get(), 3);
    }

    #[test]
    fn classifies_malformed_and_inconsistent_sources() {
        assert_eq!(
            read([Ok(source(b"not an FDR source".to_vec()))]),
            Err(SourceError::AppleDataInvalid)
        );

        let bytes = fdr_data(MODULE_SERIAL, 1);
        let declared = u64::try_from(bytes.len()).unwrap() + 1;
        assert_eq!(
            read([Ok(PreservedFdrSource::new(Cursor::new(bytes), declared))]),
            Err(SourceError::AppleDataUnreadable)
        );
        assert_eq!(
            read([Ok(PreservedFdrSource::new(BrokenReader, 8))]),
            Err(SourceError::AppleDataUnreadable)
        );
    }

    #[test]
    fn propagates_redacted_enumeration_failures() {
        let failure = Err(SourceError::AppleDataUnreadable);
        let sources = [failure]
            .into_iter()
            .collect::<Vec<Result<PreservedFdrSource<Cursor<Vec<u8>>>, SourceError>>>();
        assert_eq!(read(sources), Err(SourceError::AppleDataUnreadable));
    }

    #[test]
    fn rejects_a_sixty_fifth_source_without_reading_it() {
        let bytes = fdr_data(OTHER_MODULE, 1);
        let mut operation_counts = Vec::new();
        let mut sources = Vec::new();
        for _ in 0..=MAX_CANDIDATES {
            let operations = Rc::new(Cell::new(0));
            operation_counts.push(Rc::clone(&operations));
            sources.push(Ok(PreservedFdrSource::new(
                TrackingReader::new(bytes.clone(), operations),
                u64::try_from(bytes.len()).unwrap(),
            )));
        }
        let (enumeration, calls) = enumeration(sources);
        let mut reader = EnumeratedPreservedRecordReader::new(enumeration);

        assert_eq!(
            reader.read_matching_records(MODULE_SERIAL),
            Err(SourceError::AppleDataInvalid)
        );
        assert_eq!(calls.get(), MAX_CANDIDATES + 1);
        assert!(
            operation_counts[..MAX_CANDIDATES]
                .iter()
                .all(|count| count.get() > 0)
        );
        assert_eq!(operation_counts[MAX_CANDIDATES].get(), 0);
    }

    fn fdr_data(module_serial: &[u8; MODULE_SERIAL_NUMBER_SIZE], marker: u8) -> Vec<u8> {
        let key = format!("FSCl-{}", std::str::from_utf8(module_serial).unwrap());
        bplist::encode(&Value::Dictionary(BTreeMap::from([(
            key,
            Value::Data(fdr_record(module_serial, marker)),
        )])))
        .unwrap()
    }

    fn fdr_record(module_serial: &[u8; MODULE_SERIAL_NUMBER_SIZE], marker: u8) -> Vec<u8> {
        let mut calibration = vec![0_u8; 96];
        let length = u32::try_from(calibration.len()).unwrap();
        calibration[4..8].copy_from_slice(&length.to_le_bytes());
        calibration[16..20].copy_from_slice(b"CALB");
        calibration[32..50].copy_from_slice(module_serial);
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

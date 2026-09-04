//! Protected access to the imported factory calibration record.

use std::fmt;
use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use t1_bridge::commands::MAX_CALIBRATION_DATA_SIZE;
use t1_platform::secret;

pub const MACHINE_CALIBRATION_PATH: &str = "/var/lib/t1bridge/machine-data/calibration.fscl";

const CALIBRATION_MODE: u32 = 0o600;
const O_CLOEXEC: i32 = 0o20_00000;
const O_NOFOLLOW: i32 = 0o4_00000;

/// Static, path- and content-redacted calibration storage failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MachineDataError {
    Missing,
    UnsafeStorage,
    InvalidSize,
    Unavailable,
}

impl fmt::Display for MachineDataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Missing => "T1Bridge calibration is not installed",
            Self::UnsafeStorage => "T1Bridge calibration storage is unsafe",
            Self::InvalidSize => "T1Bridge calibration has an invalid size",
            Self::Unavailable => "T1Bridge calibration is unavailable",
        })
    }
}

impl std::error::Error for MachineDataError {}

/// One root-private imported record whose bytes are cleared on drop.
pub struct MachineCalibration(Vec<u8>);

impl MachineCalibration {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for MachineCalibration {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MachineCalibration([redacted])")
    }
}

impl Drop for MachineCalibration {
    fn drop(&mut self) {
        secret::wipe(&mut self.0);
    }
}

/// Opens and reads the fixed imported calibration record.
///
/// # Errors
///
/// Refuses missing, linked, non-regular, non-root-owned, non-private, empty,
/// oversized, replaced, or unreadable state without exposing its contents.
pub fn read_machine_calibration() -> Result<MachineCalibration, MachineDataError> {
    read_calibration(Path::new(MACHINE_CALIBRATION_PATH), 0)
}

fn read_calibration(
    path: &Path,
    expected_uid: u32,
) -> Result<MachineCalibration, MachineDataError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_CLOEXEC | O_NOFOLLOW)
        .open(path)
        .map_err(|error| map_open_error(&error))?;
    let before = file.metadata().map_err(|_| MachineDataError::Unavailable)?;
    let size = validate_metadata(&before, expected_uid)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| MachineDataError::Unavailable)?;
    file.read_to_end(&mut bytes)
        .map_err(|_| MachineDataError::Unavailable)?;
    let after = file.metadata().map_err(|_| MachineDataError::Unavailable)?;
    if !same_file(&before, &after) || bytes.len() != size {
        secret::wipe(&mut bytes);
        return Err(MachineDataError::Unavailable);
    }
    Ok(MachineCalibration(bytes))
}

fn map_open_error(error: &io::Error) -> MachineDataError {
    if error.kind() == io::ErrorKind::NotFound {
        MachineDataError::Missing
    } else if error.raw_os_error() == Some(40) {
        // Linux ELOOP from O_NOFOLLOW on a final symlink.
        MachineDataError::UnsafeStorage
    } else {
        MachineDataError::Unavailable
    }
}

fn validate_metadata(
    metadata: &std::fs::Metadata,
    expected_uid: u32,
) -> Result<usize, MachineDataError> {
    if !metadata.file_type().is_file()
        || metadata.uid() != expected_uid
        || metadata.mode() & 0o777 != CALIBRATION_MODE
        || metadata.nlink() != 1
    {
        return Err(MachineDataError::UnsafeStorage);
    }
    let size = usize::try_from(metadata.len()).map_err(|_| MachineDataError::InvalidSize)?;
    if size == 0 || size > MAX_CALIBRATION_DATA_SIZE {
        return Err(MachineDataError::InvalidSize);
    }
    Ok(size)
}

fn same_file(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.len() == after.len()
        && before.uid() == after.uid()
        && before.mode() == after.mode()
        && before.nlink() == after.nlink()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "t1bridge-machine-data-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn record(&self) -> PathBuf {
            self.0.join("calibration.fscl")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write_record(directory: &TestDirectory, bytes: &[u8]) -> PathBuf {
        let path = directory.record();
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(CALIBRATION_MODE)).unwrap();
        path
    }

    #[test]
    fn reads_one_private_regular_record() {
        let directory = TestDirectory::new();
        let path = write_record(&directory, b"synthetic calibration");
        let uid = fs::metadata(&path).unwrap().uid();

        let record = read_calibration(&path, uid).unwrap();

        assert_eq!(record.as_bytes(), b"synthetic calibration");
        assert_eq!(format!("{record:?}"), "MachineCalibration([redacted])");
    }

    #[test]
    fn rejects_links_modes_owners_and_sizes() {
        let directory = TestDirectory::new();
        let path = write_record(&directory, b"record");
        let uid = fs::metadata(&path).unwrap().uid();

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(matches!(
            read_calibration(&path, uid),
            Err(MachineDataError::UnsafeStorage)
        ));
        fs::set_permissions(&path, fs::Permissions::from_mode(CALIBRATION_MODE)).unwrap();
        assert!(matches!(
            read_calibration(&path, uid.wrapping_add(1)),
            Err(MachineDataError::UnsafeStorage)
        ));

        fs::write(&path, []).unwrap();
        assert!(matches!(
            read_calibration(&path, uid),
            Err(MachineDataError::InvalidSize)
        ));

        fs::remove_file(&path).unwrap();
        let target = directory.0.join("target");
        fs::write(&target, b"record").unwrap();
        symlink(&target, &path).unwrap();
        assert!(matches!(
            read_calibration(&path, uid),
            Err(MachineDataError::UnsafeStorage)
        ));
    }

    #[test]
    fn missing_and_error_output_are_redacted() {
        let directory = TestDirectory::new();
        assert!(matches!(
            read_calibration(&directory.record(), 0),
            Err(MachineDataError::Missing)
        ));
        for error in [
            MachineDataError::Missing,
            MachineDataError::UnsafeStorage,
            MachineDataError::InvalidSize,
            MachineDataError::Unavailable,
        ] {
            let rendered = format!("{error:?} {error}");
            assert!(!rendered.contains("/var"));
            assert!(!rendered.contains("fscl"));
        }
    }
}

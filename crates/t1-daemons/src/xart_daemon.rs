//! Production process boundary for the device-scoped xART storage service.

use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File};
use std::io::Read;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::PathBuf;

use crate::service_lifecycle::notify_ready_once;
use crate::xart_live::{DynamicXartListener, XartListenerError, XartLiveError};
use crate::xart_store::XartStore;

const STORE_DIRECTORY: &str = "/var/lib/t1bridge/touch-id/xart";
const ROOT_PATH: &str = "/";
const UUID_DIRECTORY: &str = "/dev/disk/by-uuid";
const MOUNTINFO_PATH: &str = "/proc/self/mountinfo";
const MAX_VOLUME_ENTRIES: usize = 256;
const MAX_MOUNTINFO_BYTES: u64 = 1_048_576;

/// Static, identifier-free production daemon failure.
#[derive(Debug)]
pub enum XartDaemonError {
    RootVolumeUnavailable,
    RootVolumeAmbiguous,
    Readiness,
    Listener(XartLiveError),
}

impl fmt::Display for XartDaemonError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootVolumeUnavailable => {
                formatter.write_str("root filesystem volume identity is unavailable")
            }
            Self::RootVolumeAmbiguous => {
                formatter.write_str("root filesystem volume identity is ambiguous")
            }
            Self::Readiness => formatter.write_str("xART listener readiness failed"),
            Self::Listener(error) => write!(formatter, "xART listener failed: {error}"),
        }
    }
}

impl std::error::Error for XartDaemonError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Listener(error) => Some(error),
            Self::RootVolumeUnavailable | Self::RootVolumeAmbiguous | Self::Readiness => None,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct RootVolumeId([u8; 16]);

impl fmt::Debug for RootVolumeId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RootVolumeId(<redacted>)")
    }
}

#[derive(Clone, Copy)]
struct VolumeCandidate {
    device: u64,
    id: RootVolumeId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectionDisposition {
    Continue,
    Exit,
}

/// Runs the production xART service until its device-bound listener fails.
///
/// Udev and systemd own device arrival, removal, and process lifetime. This
/// process performs no discovery polling. Every admitted save is durable
/// before its response, so process shutdown has no pending state to flush.
///
/// # Errors
///
/// Returns a static failure if root volume identity cannot be resolved, the
/// validated device listener cannot start, or its binding becomes unusable.
pub fn run() -> Result<(), XartDaemonError> {
    let volume_id = discover_root_volume_id()?;
    let store = XartStore::new(STORE_DIRECTORY, volume_id.0, false);
    let listener = DynamicXartListener::discover_and_bind().map_err(XartDaemonError::Listener)?;
    notify_ready_once().map_err(|_| XartDaemonError::Readiness)?;
    listener
        .use_blocking_accept()
        .map_err(XartDaemonError::Listener)?;

    loop {
        match listener.serve_next(&store) {
            Ok(()) => {}
            Err(error) if disposition(&error) == ConnectionDisposition::Continue => {
                eprintln!("t1-xart-storage: {error}");
            }
            Err(error) => return Err(XartDaemonError::Listener(error)),
        }
    }
}

fn disposition(error: &XartLiveError) -> ConnectionDisposition {
    match error {
        XartLiveError::Admission(_) | XartLiveError::Connection(_) => {
            ConnectionDisposition::Continue
        }
        XartLiveError::Listener(XartListenerError::Interrupted) => ConnectionDisposition::Continue,
        XartLiveError::Listener(_) | XartLiveError::Activation(_) => ConnectionDisposition::Exit,
    }
}

fn discover_root_volume_id() -> Result<RootVolumeId, XartDaemonError> {
    let root_device = fs::metadata(ROOT_PATH)
        .map_err(|_| XartDaemonError::RootVolumeUnavailable)?
        .dev();
    let entries =
        fs::read_dir(UUID_DIRECTORY).map_err(|_| XartDaemonError::RootVolumeUnavailable)?;
    let mut candidates = Vec::new();
    for (index, entry) in entries.enumerate() {
        if index >= MAX_VOLUME_ENTRIES {
            return Err(XartDaemonError::RootVolumeUnavailable);
        }
        let entry = entry.map_err(|_| XartDaemonError::RootVolumeUnavailable)?;
        let link_metadata = fs::symlink_metadata(entry.path())
            .map_err(|_| XartDaemonError::RootVolumeUnavailable)?;
        if !link_metadata.file_type().is_symlink() {
            continue;
        }
        let target_metadata =
            fs::metadata(entry.path()).map_err(|_| XartDaemonError::RootVolumeUnavailable)?;
        if !target_metadata.file_type().is_block_device() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().and_then(parse_uuid) else {
            continue;
        };
        candidates.push(VolumeCandidate {
            device: target_metadata.rdev(),
            id: name,
        });
    }
    match select_root_volume_id(root_device, &candidates) {
        Ok(id) => Ok(id),
        Err(XartDaemonError::RootVolumeUnavailable) => {
            let backing_device = discover_root_backing_device()?;
            select_root_volume_id(backing_device, &candidates)
        }
        Err(error) => Err(error),
    }
}

fn discover_root_backing_device() -> Result<u64, XartDaemonError> {
    let metadata =
        fs::metadata(MOUNTINFO_PATH).map_err(|_| XartDaemonError::RootVolumeUnavailable)?;
    if metadata.len() > MAX_MOUNTINFO_BYTES {
        return Err(XartDaemonError::RootVolumeUnavailable);
    }
    let mut mountinfo = Vec::new();
    File::open(MOUNTINFO_PATH)
        .map_err(|_| XartDaemonError::RootVolumeUnavailable)?
        .take(MAX_MOUNTINFO_BYTES + 1)
        .read_to_end(&mut mountinfo)
        .map_err(|_| XartDaemonError::RootVolumeUnavailable)?;
    if u64::try_from(mountinfo.len()).unwrap_or(u64::MAX) > MAX_MOUNTINFO_BYTES {
        return Err(XartDaemonError::RootVolumeUnavailable);
    }
    let source = root_mount_source(&mountinfo)?;
    let source_metadata =
        fs::metadata(source).map_err(|_| XartDaemonError::RootVolumeUnavailable)?;
    if !source_metadata.file_type().is_block_device() {
        return Err(XartDaemonError::RootVolumeUnavailable);
    }
    Ok(source_metadata.rdev())
}

fn root_mount_source(mountinfo: &[u8]) -> Result<PathBuf, XartDaemonError> {
    let mut source = None;
    for line in mountinfo.split(|byte| *byte == b'\n') {
        let fields = line
            .split(u8::is_ascii_whitespace)
            .filter(|field| !field.is_empty())
            .collect::<Vec<_>>();
        if fields.get(4).copied() != Some(b"/".as_slice()) {
            continue;
        }
        let separator = fields
            .iter()
            .position(|field| *field == b"-")
            .ok_or(XartDaemonError::RootVolumeUnavailable)?;
        let encoded = fields
            .get(separator + 2)
            .ok_or(XartDaemonError::RootVolumeUnavailable)?;
        let decoded = decode_mount_field(encoded)?;
        let path = PathBuf::from(OsString::from_vec(decoded));
        if !path.is_absolute() {
            return Err(XartDaemonError::RootVolumeUnavailable);
        }
        if source.replace(path).is_some() {
            return Err(XartDaemonError::RootVolumeAmbiguous);
        }
    }
    source.ok_or(XartDaemonError::RootVolumeUnavailable)
}

fn decode_mount_field(encoded: &[u8]) -> Result<Vec<u8>, XartDaemonError> {
    let mut decoded = Vec::with_capacity(encoded.len());
    let mut index = 0;
    while index < encoded.len() {
        if encoded[index] != b'\\' {
            if encoded[index] == 0 {
                return Err(XartDaemonError::RootVolumeUnavailable);
            }
            decoded.push(encoded[index]);
            index += 1;
            continue;
        }
        let escape = encoded
            .get(index + 1..index + 4)
            .ok_or(XartDaemonError::RootVolumeUnavailable)?;
        let value = match escape {
            b"040" => b' ',
            b"011" => b'\t',
            b"012" => b'\n',
            b"134" => b'\\',
            _ => return Err(XartDaemonError::RootVolumeUnavailable),
        };
        decoded.push(value);
        index += 4;
    }
    Ok(decoded)
}

fn select_root_volume_id(
    root_device: u64,
    candidates: &[VolumeCandidate],
) -> Result<RootVolumeId, XartDaemonError> {
    let mut selected = None;
    for candidate in candidates
        .iter()
        .copied()
        .filter(|candidate| candidate.device == root_device)
    {
        if selected.replace(candidate.id).is_some() {
            return Err(XartDaemonError::RootVolumeAmbiguous);
        }
    }
    selected.ok_or(XartDaemonError::RootVolumeUnavailable)
}

fn parse_uuid(value: &str) -> Option<RootVolumeId> {
    if value.len() != 36 {
        return None;
    }
    let bytes = value.as_bytes();
    for separator in [8, 13, 18, 23] {
        if bytes.get(separator) != Some(&b'-') {
            return None;
        }
    }
    let mut parsed = [0_u8; 16];
    let mut source = 0;
    for destination in &mut parsed {
        while bytes.get(source) == Some(&b'-') {
            source += 1;
        }
        let high = hex(*bytes.get(source)?)?;
        let low = hex(*bytes.get(source + 1)?)?;
        *destination = high << 4 | low;
        source += 2;
    }
    if source != bytes.len() {
        return None;
    }
    Some(RootVolumeId(parsed))
}

const fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xart_service::PeerAdmissionError;
    use crate::xart_session::{XartConnectionError, XartSessionError};

    fn id(value: &str) -> RootVolumeId {
        parse_uuid(value).expect("valid synthetic UUID")
    }

    #[test]
    fn canonical_uuid_parser_preserves_wire_byte_order() {
        assert_eq!(
            id("00112233-4455-6677-8899-aabbccddeeff"),
            RootVolumeId([
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ])
        );
        assert_eq!(
            id("AABBCCDD-EEFF-0011-2233-445566778899"),
            RootVolumeId([
                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                0x88, 0x99,
            ])
        );
    }

    #[test]
    fn malformed_or_noncanonical_volume_names_are_not_candidates() {
        for value in [
            "",
            "00112233445566778899aabbccddeeff",
            "00112233-4455-6677-8899-aabbccddeefg",
            "00112233_4455-6677-8899-aabbccddeeff",
            "1234-ABCD",
        ] {
            assert_eq!(parse_uuid(value), None);
        }
    }

    #[test]
    fn root_device_requires_exactly_one_matching_volume() {
        let first = VolumeCandidate {
            device: 17,
            id: id("00112233-4455-6677-8899-aabbccddeeff"),
        };
        let other = VolumeCandidate {
            device: 29,
            id: id("11223344-5566-7788-99aa-bbccddeeff00"),
        };
        assert_eq!(
            select_root_volume_id(17, &[other, first]).unwrap(),
            first.id
        );
        assert!(matches!(
            select_root_volume_id(41, &[first, other]),
            Err(XartDaemonError::RootVolumeUnavailable)
        ));
        assert!(matches!(
            select_root_volume_id(17, &[first, first]),
            Err(XartDaemonError::RootVolumeAmbiguous)
        ));
    }

    #[test]
    fn root_mount_source_uses_the_exact_root_record_and_decodes_kernel_escapes() {
        let mountinfo = b"21 20 8:1 / /boot rw - ext4 /dev/synthetic-boot rw\n\
22 20 0:41 /subvolume / rw,relatime - btrfs /dev/mapper/synthetic\\040root rw\n";
        assert_eq!(
            root_mount_source(mountinfo).unwrap(),
            PathBuf::from("/dev/mapper/synthetic root")
        );
    }

    #[test]
    fn missing_duplicate_or_malformed_root_mount_evidence_fails_closed() {
        let duplicate = b"21 20 8:1 / / rw - ext4 /dev/synthetic-a rw\n\
22 20 8:2 / / rw - ext4 /dev/synthetic-b rw\n";
        assert!(matches!(
            root_mount_source(duplicate),
            Err(XartDaemonError::RootVolumeAmbiguous)
        ));
        assert!(matches!(
            root_mount_source(b"21 20 8:1 / /boot rw - ext4 /dev/synthetic rw\n"),
            Err(XartDaemonError::RootVolumeUnavailable)
        ));
        assert!(matches!(
            root_mount_source(b"21 20 8:1 / / rw - ext4 relative-source rw\n"),
            Err(XartDaemonError::RootVolumeUnavailable)
        ));
        assert!(matches!(
            root_mount_source(b"21 20 8:1 / / rw - ext4 /dev/bad\\999escape rw\n"),
            Err(XartDaemonError::RootVolumeUnavailable)
        ));
    }

    #[test]
    fn connection_failures_continue_but_listener_failures_exit() {
        let admission = XartLiveError::Admission(PeerAdmissionError::UnexpectedPeer);
        let session = XartLiveError::Connection(XartConnectionError::Session(
            XartSessionError::ExpectedPeerHello,
        ));
        assert_eq!(disposition(&admission), ConnectionDisposition::Continue);
        assert_eq!(disposition(&session), ConnectionDisposition::Continue);
        assert_eq!(
            disposition(&XartLiveError::Listener(XartListenerError::Interrupted)),
            ConnectionDisposition::Continue
        );
        assert_eq!(
            disposition(&XartLiveError::Listener(XartListenerError::WouldBlock)),
            ConnectionDisposition::Exit
        );
    }

    #[test]
    fn errors_and_debug_output_never_include_volume_identifiers() {
        let private = id("00112233-4455-6677-8899-aabbccddeeff");
        assert_eq!(format!("{private:?}"), "RootVolumeId(<redacted>)");
        assert_eq!(
            XartDaemonError::RootVolumeUnavailable.to_string(),
            "root filesystem volume identity is unavailable"
        );
    }
}

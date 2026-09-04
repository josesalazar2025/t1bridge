use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::thread::{self, JoinHandle};
use std::time::Duration;

pub const OVERLAY_STATE_PATH: &str = "/run/t1bridge/touch-id-state.json";

const MAX_RECORD_BYTES: u64 = 1_024;
const WATCH_INTERVAL: Duration = Duration::from_millis(100);
const O_NONBLOCK: i32 = 0o4_000;
const O_NOFOLLOW: i32 = 0o400_000;
const O_PATH: i32 = 0o10_000_000;

const VERSION_FIELD: &str = "version";
const PID_FIELD: &str = "pid";
const STATE_FIELD: &str = "state";
const PROGRESS_FIELD: &str = "progress";
const V1_FIELD_COUNT: usize = 3;
const V2_FIELD_COUNT: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OverlayState {
    Enrollment,
    Authenticate,
    Approve,
    Retry,
    Success,
}

impl OverlayState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enrollment => "enrollment",
            Self::Authenticate => "authenticate",
            Self::Approve => "approve",
            Self::Retry => "retry",
            Self::Success => "success",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "enrollment" => Some(Self::Enrollment),
            "authenticate" => Some(Self::Authenticate),
            "approve" => Some(Self::Approve),
            "retry" => Some(Self::Retry),
            "success" => Some(Self::Success),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProducerPid(i128);

impl ProducerPid {
    #[must_use]
    pub const fn get(self) -> i128 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CosmeticOverlay {
    pub producer_pid: ProducerPid,
    pub state: OverlayState,
    pub enrollment_progress: Option<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DecodedValue<'a> {
    Integer(i128),
    String(&'a str),
    Other,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedField<'a> {
    pub name: &'a str,
    pub value: DecodedValue<'a>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedOverlayRecord<'a> {
    pub fields: &'a [DecodedField<'a>],
}

pub trait ProcessLiveness {
    fn is_live(&mut self, pid: ProducerPid) -> bool;
}

impl<F> ProcessLiveness for F
where
    F: FnMut(ProducerPid) -> bool,
{
    fn is_live(&mut self, pid: ProducerPid) -> bool {
        self(pid)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoOverlayDiagnostic {
    UnsafeFileType,
    RecordTooLarge,
    ReadFailed,
    MissingFinalNewline,
    MalformedJson,
    IncorrectFieldCount,
    UnknownField,
    DuplicateField,
    InvalidFieldType,
    UnsupportedVersion,
    InvalidPid,
    UnknownState,
    DeadProducer,
}

impl fmt::Display for NoOverlayDiagnostic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnsafeFileType => "Touch ID overlay state is not a safe regular file",
            Self::RecordTooLarge => "Touch ID overlay record exceeds its size limit",
            Self::ReadFailed => "Touch ID overlay record could not be read",
            Self::MissingFinalNewline => "Touch ID overlay record is not newline terminated",
            Self::MalformedJson => "Touch ID overlay record is malformed JSON",
            Self::IncorrectFieldCount => "Touch ID overlay record has the wrong field count",
            Self::UnknownField => "Touch ID overlay record has an unknown field",
            Self::DuplicateField => "Touch ID overlay record repeats a field",
            Self::InvalidFieldType => "Touch ID overlay record has an invalid field type",
            Self::UnsupportedVersion => "Touch ID overlay record has an unsupported version",
            Self::InvalidPid => "Touch ID overlay record has an invalid producer process",
            Self::UnknownState => "Touch ID overlay record has an unknown state",
            Self::DeadProducer => "Touch ID overlay producer is not live",
        };
        formatter.write_str(message)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OverlayValidation {
    Overlay(CosmeticOverlay),
    NoOverlay(NoOverlayDiagnostic),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OverlayObservation {
    Missing,
    Overlay(CosmeticOverlay),
    NoOverlay(NoOverlayDiagnostic),
}

impl OverlayObservation {
    #[must_use]
    pub const fn overlay(self) -> Option<CosmeticOverlay> {
        match self {
            Self::Overlay(overlay) => Some(overlay),
            Self::Missing | Self::NoOverlay(_) => None,
        }
    }
}

/// Validates already-decoded fields for the cosmetic overlay.
///
/// The returned overlay contains presentation state only. It carries no
/// authentication result and must not be used to authorize an operation.
pub fn validate_overlay_record(
    record: DecodedOverlayRecord<'_>,
    liveness: &mut impl ProcessLiveness,
) -> OverlayValidation {
    if !matches!(record.fields.len(), V1_FIELD_COUNT | V2_FIELD_COUNT) {
        return OverlayValidation::NoOverlay(NoOverlayDiagnostic::IncorrectFieldCount);
    }

    let mut version = None;
    let mut pid = None;
    let mut state = None;
    let mut progress = None;
    for field in record.fields {
        match field.name {
            VERSION_FIELD if version.replace(field.value).is_none() => {}
            PID_FIELD if pid.replace(field.value).is_none() => {}
            STATE_FIELD if state.replace(field.value).is_none() => {}
            PROGRESS_FIELD if progress.replace(field.value).is_none() => {}
            VERSION_FIELD | PID_FIELD | STATE_FIELD | PROGRESS_FIELD => {
                return OverlayValidation::NoOverlay(NoOverlayDiagnostic::DuplicateField);
            }
            _ => return OverlayValidation::NoOverlay(NoOverlayDiagnostic::UnknownField),
        }
    }

    let (Some(version), Some(pid), Some(state)) = (version, pid, state) else {
        return OverlayValidation::NoOverlay(NoOverlayDiagnostic::IncorrectFieldCount);
    };
    let DecodedValue::Integer(version) = version else {
        return OverlayValidation::NoOverlay(NoOverlayDiagnostic::InvalidFieldType);
    };
    let DecodedValue::Integer(pid) = pid else {
        return OverlayValidation::NoOverlay(NoOverlayDiagnostic::InvalidFieldType);
    };
    if pid <= 0 || pid > i128::from(i32::MAX) {
        return OverlayValidation::NoOverlay(NoOverlayDiagnostic::InvalidPid);
    }
    let DecodedValue::String(state) = state else {
        return OverlayValidation::NoOverlay(NoOverlayDiagnostic::InvalidFieldType);
    };
    let Some(state) = OverlayState::parse(state) else {
        return OverlayValidation::NoOverlay(NoOverlayDiagnostic::UnknownState);
    };

    let enrollment_progress = match version {
        1 if record.fields.len() == V1_FIELD_COUNT && progress.is_none() => None,
        2 if record.fields.len() == V2_FIELD_COUNT && state == OverlayState::Enrollment => {
            let Some(DecodedValue::Integer(progress)) = progress else {
                return OverlayValidation::NoOverlay(NoOverlayDiagnostic::InvalidFieldType);
            };
            let Ok(progress) = u8::try_from(progress) else {
                return OverlayValidation::NoOverlay(NoOverlayDiagnostic::InvalidFieldType);
            };
            if progress > 100 {
                return OverlayValidation::NoOverlay(NoOverlayDiagnostic::InvalidFieldType);
            }
            Some(progress)
        }
        1 | 2 => {
            return OverlayValidation::NoOverlay(NoOverlayDiagnostic::IncorrectFieldCount);
        }
        _ => return OverlayValidation::NoOverlay(NoOverlayDiagnostic::UnsupportedVersion),
    };

    let producer_pid = ProducerPid(pid);
    if !liveness.is_live(producer_pid) {
        return OverlayValidation::NoOverlay(NoOverlayDiagnostic::DeadProducer);
    }

    OverlayValidation::Overlay(CosmeticOverlay {
        producer_pid,
        state,
        enrollment_progress,
    })
}

/// Reads the fixed cosmetic overlay state without following a symlink or
/// reading a non-regular file.
#[must_use]
pub fn read_overlay_state() -> OverlayObservation {
    OverlayFileReader::new().read()
}

#[derive(Clone, Debug)]
struct OverlayFileReader {
    path: PathBuf,
}

impl OverlayFileReader {
    fn new() -> Self {
        Self {
            path: PathBuf::from(OVERLAY_STATE_PATH),
        }
    }

    #[cfg(test)]
    fn at_path(path: PathBuf) -> Self {
        Self { path }
    }

    fn read(&self) -> OverlayObservation {
        match self.read_bytes() {
            Ok(Some(bytes)) => parse_overlay_bytes(&bytes, &mut ProcLiveness),
            Ok(None) => OverlayObservation::Missing,
            Err(diagnostic) => OverlayObservation::NoOverlay(diagnostic),
        }
    }

    fn read_bytes(&self) -> Result<Option<Vec<u8>>, NoOverlayDiagnostic> {
        let path_metadata = match fs::symlink_metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(NoOverlayDiagnostic::ReadFailed),
        };
        if !path_metadata.file_type().is_file() {
            return Err(NoOverlayDiagnostic::UnsafeFileType);
        }

        let path_handle = OpenOptions::new()
            .read(true)
            .custom_flags(O_PATH | O_NOFOLLOW)
            .open(&self.path)
            .map_err(|_| NoOverlayDiagnostic::ReadFailed)?;
        let pinned_metadata = path_handle
            .metadata()
            .map_err(|_| NoOverlayDiagnostic::ReadFailed)?;
        if !pinned_metadata.file_type().is_file() {
            return Err(NoOverlayDiagnostic::UnsafeFileType);
        }
        if pinned_metadata.len() > MAX_RECORD_BYTES {
            return Err(NoOverlayDiagnostic::RecordTooLarge);
        }

        // O_PATH acquires the inode without invoking a device or blocking on a
        // FIFO. Reopening that pinned regular inode avoids a pathname race.
        let pinned_path = Path::new("/proc/self/fd").join(path_handle.as_raw_fd().to_string());
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(O_NONBLOCK)
            .open(pinned_path)
            .map_err(|_| NoOverlayDiagnostic::ReadFailed)?;
        let opened_metadata = file
            .metadata()
            .map_err(|_| NoOverlayDiagnostic::ReadFailed)?;
        if !opened_metadata.file_type().is_file()
            || opened_metadata.dev() != pinned_metadata.dev()
            || opened_metadata.ino() != pinned_metadata.ino()
        {
            return Err(NoOverlayDiagnostic::UnsafeFileType);
        }

        let mut bytes = Vec::with_capacity(usize::try_from(pinned_metadata.len()).unwrap_or(1_024));
        File::by_ref(&mut file)
            .take(MAX_RECORD_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| NoOverlayDiagnostic::ReadFailed)?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_RECORD_BYTES {
            return Err(NoOverlayDiagnostic::RecordTooLarge);
        }
        Ok(Some(bytes))
    }
}

struct ProcLiveness;

impl ProcessLiveness for ProcLiveness {
    fn is_live(&mut self, pid: ProducerPid) -> bool {
        Path::new("/proc")
            .join(pid.get().to_string())
            .metadata()
            .is_ok_and(|metadata| metadata.is_dir())
    }
}

/// Background reader for cosmetic state. Filesystem I/O never runs on the
/// hardware-input loop.
pub struct OverlayWatcher {
    updates: Receiver<OverlayObservation>,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl OverlayWatcher {
    #[must_use]
    pub fn start() -> Self {
        Self::start_with_reader(OverlayFileReader::new(), WATCH_INTERVAL)
    }

    fn start_with_reader(reader: OverlayFileReader, interval: Duration) -> Self {
        let (sender, updates) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let mut previous = None;
            while !worker_stop.load(Ordering::Relaxed) {
                let observation = reader.read();
                if previous != Some(observation) {
                    if let OverlayObservation::NoOverlay(diagnostic) = observation {
                        eprintln!("t1-touchbar: {diagnostic}");
                    }
                    if sender.send(observation).is_err() {
                        break;
                    }
                    previous = Some(observation);
                }
                thread::sleep(interval);
            }
        });
        Self {
            updates,
            stop,
            worker: Some(worker),
        }
    }

    /// Drains queued transitions and returns only the newest observation.
    #[must_use]
    pub fn take_latest(&self) -> Option<OverlayObservation> {
        let mut latest = None;
        while let Ok(update) = self.updates.try_recv() {
            latest = Some(update);
        }
        latest
    }
}

impl Drop for OverlayWatcher {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn parse_overlay_bytes(bytes: &[u8], liveness: &mut impl ProcessLiveness) -> OverlayObservation {
    if !bytes.ends_with(b"\n") {
        return OverlayObservation::NoOverlay(NoOverlayDiagnostic::MissingFinalNewline);
    }
    let Ok(text) = std::str::from_utf8(bytes) else {
        return OverlayObservation::NoOverlay(NoOverlayDiagnostic::MalformedJson);
    };
    let Ok(fields) = JsonRecordParser::new(text).parse() else {
        return OverlayObservation::NoOverlay(NoOverlayDiagnostic::MalformedJson);
    };
    match validate_overlay_record(DecodedOverlayRecord { fields: &fields }, liveness) {
        OverlayValidation::Overlay(overlay) => OverlayObservation::Overlay(overlay),
        OverlayValidation::NoOverlay(diagnostic) => OverlayObservation::NoOverlay(diagnostic),
    }
}

struct JsonRecordParser<'input> {
    input: &'input str,
    position: usize,
}

impl<'input> JsonRecordParser<'input> {
    const fn new(input: &'input str) -> Self {
        Self { input, position: 0 }
    }

    fn parse(mut self) -> Result<Vec<DecodedField<'input>>, ()> {
        self.whitespace();
        self.byte(b'{')?;
        self.whitespace();
        let mut fields = Vec::new();
        if self.consume(b'}') {
            self.finish()?;
            return Ok(fields);
        }
        loop {
            self.whitespace();
            let name = self.string()?;
            self.whitespace();
            self.byte(b':')?;
            self.whitespace();
            let value = self.value()?;
            fields.push(DecodedField { name, value });
            self.whitespace();
            if self.consume(b'}') {
                self.finish()?;
                return Ok(fields);
            }
            self.byte(b',')?;
        }
    }

    fn finish(&mut self) -> Result<(), ()> {
        self.whitespace();
        if self.position == self.input.len() {
            Ok(())
        } else {
            Err(())
        }
    }

    fn value(&mut self) -> Result<DecodedValue<'input>, ()> {
        match self.peek() {
            Some(b'"') => self.string().map(DecodedValue::String),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(b't') => self.literal(b"true").map(|()| DecodedValue::Other),
            Some(b'f') => self.literal(b"false").map(|()| DecodedValue::Other),
            Some(b'n') => self.literal(b"null").map(|()| DecodedValue::Other),
            _ => Err(()),
        }
    }

    fn number(&mut self) -> Result<DecodedValue<'input>, ()> {
        let start = self.position;
        self.consume(b'-');
        if self.consume(b'0') {
            if matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(());
            }
        } else {
            self.digits(true)?;
        }
        let mut integer = true;
        if self.consume(b'.') {
            integer = false;
            self.digits(true)?;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            integer = false;
            self.position += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.position += 1;
            }
            self.digits(true)?;
        }
        if !integer {
            return Ok(DecodedValue::Other);
        }
        self.input[start..self.position]
            .parse::<i128>()
            .map(DecodedValue::Integer)
            .map_err(|_| ())
    }

    fn digits(&mut self, require_one: bool) -> Result<(), ()> {
        let start = self.position;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.position += 1;
        }
        if require_one && start == self.position {
            Err(())
        } else {
            Ok(())
        }
    }

    fn string(&mut self) -> Result<&'input str, ()> {
        self.byte(b'"')?;
        let start = self.position;
        while let Some(byte) = self.peek() {
            match byte {
                b'"' => {
                    let value = &self.input[start..self.position];
                    self.position += 1;
                    return Ok(value);
                }
                b'\\' | 0x00..=0x1f => return Err(()),
                _ => self.position += 1,
            }
        }
        Err(())
    }

    fn literal(&mut self, expected: &[u8]) -> Result<(), ()> {
        if self
            .input
            .as_bytes()
            .get(self.position..self.position + expected.len())
            == Some(expected)
        {
            self.position += expected.len();
            Ok(())
        } else {
            Err(())
        }
    }

    fn whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.position += 1;
        }
    }

    fn byte(&mut self, expected: u8) -> Result<(), ()> {
        if self.consume(expected) {
            Ok(())
        } else {
            Err(())
        }
    }

    fn consume(&mut self, expected: u8) -> bool {
        if self.peek() == Some(expected) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.as_bytes().get(self.position).copied()
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn fields(state: &str) -> [DecodedField<'_>; V1_FIELD_COUNT] {
        [
            DecodedField {
                name: VERSION_FIELD,
                value: DecodedValue::Integer(1),
            },
            DecodedField {
                name: PID_FIELD,
                value: DecodedValue::Integer(42),
            },
            DecodedField {
                name: STATE_FIELD,
                value: DecodedValue::String(state),
            },
        ]
    }

    fn validate(fields: &[DecodedField<'_>], live: bool) -> OverlayValidation {
        validate_overlay_record(DecodedOverlayRecord { fields }, &mut |_| live)
    }

    #[test]
    fn accepts_all_five_exact_v1_states() {
        for (name, expected) in [
            ("enrollment", OverlayState::Enrollment),
            ("authenticate", OverlayState::Authenticate),
            ("approve", OverlayState::Approve),
            ("retry", OverlayState::Retry),
            ("success", OverlayState::Success),
        ] {
            assert_eq!(
                validate(&fields(name), true),
                OverlayValidation::Overlay(CosmeticOverlay {
                    producer_pid: ProducerPid(42),
                    state: expected,
                    enrollment_progress: None,
                })
            );
            assert_eq!(expected.as_str(), name);
        }
    }

    #[test]
    fn accepts_bounded_v2_enrollment_progress_only() {
        let progress = |value| {
            [
                DecodedField {
                    name: VERSION_FIELD,
                    value: DecodedValue::Integer(2),
                },
                DecodedField {
                    name: PID_FIELD,
                    value: DecodedValue::Integer(42),
                },
                DecodedField {
                    name: STATE_FIELD,
                    value: DecodedValue::String("enrollment"),
                },
                DecodedField {
                    name: PROGRESS_FIELD,
                    value: DecodedValue::Integer(value),
                },
            ]
        };
        assert_eq!(
            validate(&progress(64), true),
            OverlayValidation::Overlay(CosmeticOverlay {
                producer_pid: ProducerPid(42),
                state: OverlayState::Enrollment,
                enrollment_progress: Some(64),
            })
        );
        for invalid in [-1, 101] {
            assert_eq!(
                validate(&progress(invalid), true),
                OverlayValidation::NoOverlay(NoOverlayDiagnostic::InvalidFieldType)
            );
        }

        let mut non_enrollment = progress(50);
        non_enrollment[2].value = DecodedValue::String("authenticate");
        assert_eq!(
            validate(&non_enrollment, true),
            OverlayValidation::NoOverlay(NoOverlayDiagnostic::IncorrectFieldCount)
        );
    }

    #[test]
    fn accepts_fields_in_any_order() {
        let mut fields = fields("authenticate");
        fields.reverse();
        assert!(matches!(
            validate(&fields, true),
            OverlayValidation::Overlay(CosmeticOverlay {
                state: OverlayState::Authenticate,
                ..
            })
        ));
    }

    #[test]
    fn enforces_the_exact_field_set() {
        let complete = fields("authenticate");
        assert_eq!(
            validate(&complete[..2], true),
            OverlayValidation::NoOverlay(NoOverlayDiagnostic::IncorrectFieldCount)
        );

        let mut extra = complete.to_vec();
        extra.push(DecodedField {
            name: "private-extra-field",
            value: DecodedValue::Other,
        });
        assert_eq!(
            validate(&extra, true),
            OverlayValidation::NoOverlay(NoOverlayDiagnostic::UnknownField)
        );

        let mut unknown = complete;
        unknown[2].name = "private-unknown-field";
        assert_eq!(
            validate(&unknown, true),
            OverlayValidation::NoOverlay(NoOverlayDiagnostic::UnknownField)
        );

        let mut duplicate = complete;
        duplicate[2].name = VERSION_FIELD;
        assert_eq!(
            validate(&duplicate, true),
            OverlayValidation::NoOverlay(NoOverlayDiagnostic::DuplicateField)
        );
    }

    #[test]
    fn rejects_every_field_type_mismatch() {
        for index in 0..V1_FIELD_COUNT {
            let mut malformed = fields("success");
            malformed[index].value = DecodedValue::Other;
            assert_eq!(
                validate(&malformed, true),
                OverlayValidation::NoOverlay(NoOverlayDiagnostic::InvalidFieldType)
            );
        }
    }

    #[test]
    fn rejects_unknown_version_without_liveness_check() {
        let mut fields = fields("authenticate");
        fields[0].value = DecodedValue::Integer(3);
        let calls = Cell::new(0);
        let mut liveness = |_: ProducerPid| {
            calls.set(calls.get() + 1);
            true
        };

        assert_eq!(
            validate_overlay_record(DecodedOverlayRecord { fields: &fields }, &mut liveness),
            OverlayValidation::NoOverlay(NoOverlayDiagnostic::UnsupportedVersion)
        );
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn rejects_non_positive_pids_without_liveness_check() {
        for invalid_pid in [0, -1] {
            let mut fields = fields("authenticate");
            fields[1].value = DecodedValue::Integer(invalid_pid);
            let calls = Cell::new(0);
            let mut liveness = |_: ProducerPid| {
                calls.set(calls.get() + 1);
                true
            };

            assert_eq!(
                validate_overlay_record(DecodedOverlayRecord { fields: &fields }, &mut liveness),
                OverlayValidation::NoOverlay(NoOverlayDiagnostic::InvalidPid)
            );
            assert_eq!(calls.get(), 0);
        }
    }

    #[test]
    fn rejects_unknown_state_without_liveness_check() {
        let calls = Cell::new(0);
        let mut liveness = |_: ProducerPid| {
            calls.set(calls.get() + 1);
            true
        };

        assert_eq!(
            validate_overlay_record(
                DecodedOverlayRecord {
                    fields: &fields("private-state"),
                },
                &mut liveness
            ),
            OverlayValidation::NoOverlay(NoOverlayDiagnostic::UnknownState)
        );
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn dead_producer_is_typed_no_overlay() {
        let mut observed_pid = None;
        let mut liveness = |pid: ProducerPid| {
            observed_pid = Some(pid);
            false
        };

        assert_eq!(
            validate_overlay_record(
                DecodedOverlayRecord {
                    fields: &fields("success"),
                },
                &mut liveness
            ),
            OverlayValidation::NoOverlay(NoOverlayDiagnostic::DeadProducer)
        );
        assert_eq!(observed_pid, Some(ProducerPid(42)));
    }

    #[test]
    fn success_is_only_a_cosmetic_state() {
        let outcome = validate(&fields("success"), true);
        assert_eq!(
            outcome,
            OverlayValidation::Overlay(CosmeticOverlay {
                producer_pid: ProducerPid(42),
                state: OverlayState::Success,
                enrollment_progress: None,
            })
        );
    }

    #[test]
    fn diagnostics_do_not_echo_decoded_names_or_values() {
        let private = [
            DecodedField {
                name: VERSION_FIELD,
                value: DecodedValue::Integer(1),
            },
            DecodedField {
                name: PID_FIELD,
                value: DecodedValue::Integer(42),
            },
            DecodedField {
                name: "private-field-name",
                value: DecodedValue::String("private-field-value"),
            },
        ];
        let OverlayValidation::NoOverlay(diagnostic) = validate(&private, true) else {
            panic!("unknown field must not produce an overlay");
        };

        assert_eq!(
            diagnostic.to_string(),
            "Touch ID overlay record has an unknown field"
        );
        assert!(!diagnostic.to_string().contains("private"));
    }

    fn parse(bytes: &[u8], live: bool) -> OverlayObservation {
        parse_overlay_bytes(bytes, &mut |_| live)
    }

    #[test]
    fn parser_accepts_whitespace_and_field_order_but_enforces_exact_schema() {
        let pid = std::process::id();
        let ordered =
            format!("{{\n  \"state\": \"enrollment\", \"pid\": {pid}, \"version\": 1\n}}\n");
        assert_eq!(
            parse(ordered.as_bytes(), true),
            OverlayObservation::Overlay(CosmeticOverlay {
                producer_pid: ProducerPid(i128::from(pid)),
                state: OverlayState::Enrollment,
                enrollment_progress: None,
            })
        );

        for invalid in [
            b"{\"version\":1,\"pid\":42,\"state\":\"authenticate\",\"extra\":null}\n".as_slice(),
            b"{\"version\":1,\"pid\":42,\"state\":\"authenticate\",}\n".as_slice(),
            b"{\"version\":1,\"pid\":42,\"state\":\"authenticate\"}".as_slice(),
            b"[]\n".as_slice(),
        ] {
            assert!(!matches!(
                parse(invalid, true),
                OverlayObservation::Overlay(_)
            ));
        }
    }

    #[test]
    fn parser_rejects_fractional_fields_unknown_states_and_stale_producers() {
        assert_eq!(
            parse(
                b"{\"version\":1.0,\"pid\":42,\"state\":\"authenticate\"}\n",
                true
            ),
            OverlayObservation::NoOverlay(NoOverlayDiagnostic::InvalidFieldType)
        );
        assert_eq!(
            parse(
                b"{\"version\":1,\"pid\":42,\"state\":\"not-a-v1-state\"}\n",
                true
            ),
            OverlayObservation::NoOverlay(NoOverlayDiagnostic::UnknownState)
        );
        assert_eq!(
            parse(b"{\"version\":1,\"pid\":42,\"state\":\"success\"}\n", false),
            OverlayObservation::NoOverlay(NoOverlayDiagnostic::DeadProducer)
        );
    }

    fn temporary_path(name: &str) -> PathBuf {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "t1bridge-overlay-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("create synthetic directory");
        directory.join(name)
    }

    fn remove_temporary_path(path: &Path) {
        let directory = path.parent().expect("synthetic parent");
        if let Ok(metadata) = fs::symlink_metadata(path) {
            if metadata.file_type().is_dir() {
                fs::remove_dir(path).expect("remove synthetic directory entry");
            } else {
                fs::remove_file(path).expect("remove synthetic file entry");
            }
        }
        fs::remove_dir(directory).expect("remove synthetic directory");
    }

    #[test]
    fn file_reader_accepts_a_live_regular_record() {
        let path = temporary_path("state.json");
        let pid = std::process::id();
        fs::write(
            &path,
            format!("{{\"version\":1,\"pid\":{pid},\"state\":\"approve\"}}\n"),
        )
        .expect("write synthetic record");

        assert_eq!(
            OverlayFileReader::at_path(path.clone()).read(),
            OverlayObservation::Overlay(CosmeticOverlay {
                producer_pid: ProducerPid(i128::from(pid)),
                state: OverlayState::Approve,
                enrollment_progress: None,
            })
        );
        remove_temporary_path(&path);
    }

    #[test]
    fn file_reader_accepts_live_v2_enrollment_progress() {
        let path = temporary_path("state.json");
        let pid = std::process::id();
        fs::write(
            &path,
            format!("{{\"version\":2,\"pid\":{pid},\"state\":\"enrollment\",\"progress\":64}}\n"),
        )
        .expect("write synthetic v2 record");

        assert_eq!(
            OverlayFileReader::at_path(path.clone()).read(),
            OverlayObservation::Overlay(CosmeticOverlay {
                producer_pid: ProducerPid(i128::from(pid)),
                state: OverlayState::Enrollment,
                enrollment_progress: Some(64),
            })
        );
        remove_temporary_path(&path);
    }

    #[test]
    fn file_reader_never_follows_a_symlink_or_accepts_a_directory() {
        let target = temporary_path("target.json");
        let directory = target.parent().unwrap().to_path_buf();
        let link = directory.join("state.json");
        fs::write(
            &target,
            format!(
                "{{\"version\":1,\"pid\":{},\"state\":\"success\"}}\n",
                std::process::id()
            ),
        )
        .expect("write synthetic target");
        symlink(&target, &link).expect("create synthetic symlink");

        assert_eq!(
            OverlayFileReader::at_path(link.clone()).read(),
            OverlayObservation::NoOverlay(NoOverlayDiagnostic::UnsafeFileType)
        );
        fs::remove_file(&link).expect("remove synthetic symlink");
        fs::remove_file(&target).expect("remove synthetic target");

        let state_directory = directory.join("state-directory");
        fs::create_dir(&state_directory).expect("create synthetic state directory");
        assert_eq!(
            OverlayFileReader::at_path(state_directory.clone()).read(),
            OverlayObservation::NoOverlay(NoOverlayDiagnostic::UnsafeFileType)
        );
        fs::remove_dir(&state_directory).expect("remove synthetic state directory");
        fs::remove_dir(&directory).expect("remove synthetic directory");
    }

    #[test]
    fn watcher_reports_only_observation_transitions() {
        let path = temporary_path("state.json");
        let reader = OverlayFileReader::at_path(path.clone());
        let watcher = OverlayWatcher::start_with_reader(reader, Duration::from_millis(5));

        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        let first = loop {
            if let Some(observation) = watcher.take_latest() {
                break observation;
            }
            assert!(std::time::Instant::now() < deadline);
            thread::yield_now();
        };
        assert_eq!(first, OverlayObservation::Missing);
        assert!(watcher.take_latest().is_none());

        let pid = std::process::id();
        fs::write(
            &path,
            format!("{{\"version\":1,\"pid\":{pid},\"state\":\"retry\"}}\n"),
        )
        .expect("write synthetic transition");
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        let update = loop {
            if let Some(observation) = watcher.take_latest() {
                break observation;
            }
            assert!(std::time::Instant::now() < deadline);
            thread::yield_now();
        };
        assert!(matches!(
            update,
            OverlayObservation::Overlay(CosmeticOverlay {
                state: OverlayState::Retry,
                ..
            })
        ));
        drop(watcher);
        remove_temporary_path(&path);
    }
}

//! Cosmetic Touch ID overlay state and broker cancellation semantics.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::auth_protocol::OperationToken;

pub const DEFAULT_STATE_PATH: &str = "/run/t1bridge/touch-id-state.json";
pub const CANCEL_TIMEOUT: Duration = Duration::from_millis(500);
pub const RETRY_FEEDBACK: Duration = Duration::from_millis(550);
pub const SUCCESS_FEEDBACK: Duration = Duration::from_millis(450);

const O_NOFOLLOW: i32 = 0o4_00000;
const STATE_FILE_MODE: u32 = 0o644;
const MESA_ENROLLMENT_PROGRESS_MIN: u32 = 0x64;
const MESA_ENROLLMENT_PROGRESS_MAX: u32 = 0x163;
const TEMPORARY_FILE_ATTEMPTS: usize = 64;

static TEMPORARY_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// One state from the v1 cosmetic overlay protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

    #[cfg(test)]
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

/// Failure to publish or remove cosmetic state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OverlayError {
    StorageUnavailable,
    LiveForeignOwner(u32),
}

impl fmt::Display for OverlayError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StorageUnavailable => formatter.write_str("Touch ID overlay storage unavailable"),
            Self::LiveForeignOwner(pid) => {
                write!(formatter, "Touch ID overlay is owned by live process {pid}")
            }
        }
    }
}

impl std::error::Error for OverlayError {}

#[derive(Clone, Copy)]
enum OverlayFailureStage {
    InitialPublication,
    StateUpdate,
    Cleanup,
}

impl OverlayFailureStage {
    const fn as_str(self) -> &'static str {
        match self {
            Self::InitialPublication => "initial-publication",
            Self::StateUpdate => "state-update",
            Self::Cleanup => "cleanup",
        }
    }
}

fn report_overlay_failure(stage: OverlayFailureStage, error: OverlayError) {
    let kind = match error {
        OverlayError::StorageUnavailable => "storage-unavailable",
        OverlayError::LiveForeignOwner(_) => "live-producer-conflict",
    };
    let _ = writeln!(
        io::stderr().lock(),
        "t1bridge overlay: stage={} result={kind}",
        stage.as_str()
    );
}

/// Return Apple's enrollment percentage for diagnostics.
///
/// The value is deliberately not written into the Touch Bar state file.
#[must_use]
pub fn enrollment_percent(input: u32) -> Option<u32> {
    (MESA_ENROLLMENT_PROGRESS_MIN..=MESA_ENROLLMENT_PROGRESS_MAX)
        .contains(&input)
        .then(|| (input - MESA_ENROLLMENT_PROGRESS_MIN) * 100 / 255)
}

/// Owns one cosmetic overlay for one biometric operation.
///
/// Publishing failures must never change the biometric result. Callers may use
/// [`Self::activate_optional`] when the overlay is purely best effort.
#[derive(Debug)]
pub struct OverlaySession {
    state_path: PathBuf,
    initial_state: OverlayState,
    pid: u32,
    active: bool,
}

impl OverlaySession {
    pub fn new(state_path: impl Into<PathBuf>, initial_state: OverlayState) -> Self {
        Self {
            state_path: state_path.into(),
            initial_state,
            pid: std::process::id(),
            active: false,
        }
    }

    /// Starts an optional cosmetic session, returning `None` on any state-file
    /// failure so authentication or enrollment can continue unaffected.
    pub fn activate_optional(
        state_path: impl Into<PathBuf>,
        initial_state: OverlayState,
    ) -> Option<Self> {
        let mut session = Self::new(state_path, initial_state);
        match session.start() {
            Ok(()) => Some(session),
            Err(error) => {
                report_overlay_failure(OverlayFailureStage::InitialPublication, error);
                None
            }
        }
    }

    /// Claims the state file and publishes the initial state.
    ///
    /// Calling this more than once on the same session is harmless.
    ///
    /// # Errors
    ///
    /// Returns an error if the state file belongs to another live producer or
    /// cannot be atomically and durably replaced.
    pub fn start(&mut self) -> Result<(), OverlayError> {
        self.start_with_liveness(process_is_live)
    }

    /// Best-effort transition to the retry state.
    pub fn try_again(&self) {
        self.safe_update(OverlayState::Retry, None);
    }

    /// Best-effort transition to the success state.
    pub fn success(&self) {
        self.safe_update(OverlayState::Success, None);
    }

    /// Publishes one validated native enrollment-progress update.
    pub fn update_progress(&self, input: u32) {
        if let Some(percent) = enrollment_percent(input) {
            self.safe_update(
                OverlayState::Enrollment,
                Some(u8::try_from(percent).unwrap_or(100)),
            );
        }
    }

    /// Publishes one validated standard-fingerprint enrollment stage.
    pub fn update_standard_progress(&self, completed: u8, total: u8) {
        if completed == 0 || total == 0 || completed > total {
            return;
        }
        let percent = u32::from(completed) * 100 / u32::from(total);
        self.safe_update(
            OverlayState::Enrollment,
            Some(u8::try_from(percent).unwrap_or(100)),
        );
    }

    /// No separate physical saving state is evidenced by the reference stack.
    pub const fn saving(&self) {}

    /// The prompt remains until the durable biometric operation completes.
    pub const fn complete(&self) {}

    pub fn pause_for_retry_feedback() {
        std::thread::sleep(RETRY_FEEDBACK);
    }

    pub fn pause_for_success_feedback() {
        std::thread::sleep(SUCCESS_FEEDBACK);
    }

    /// Removes the state file only while this process still owns it.
    ///
    /// # Errors
    ///
    /// Returns an error when owned state cannot be removed or the containing
    /// directory cannot be synchronized. Foreign or malformed state is left
    /// untouched.
    pub fn restore(&mut self) -> Result<(), OverlayError> {
        if !self.active {
            return Ok(());
        }

        let result = match read_owner_pid(&self.state_path) {
            Ok(Some(pid)) if pid == self.pid => match fs::remove_file(&self.state_path) {
                Ok(()) => sync_parent_directory(&self.state_path),
                Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(_) => Err(OverlayError::StorageUnavailable),
            },
            Ok(_) | Err(_) => Ok(()),
        };
        self.active = false;
        result
    }

    fn start_with_liveness(
        &mut self,
        is_live: impl FnOnce(u32) -> bool,
    ) -> Result<(), OverlayError> {
        if self.active {
            return Ok(());
        }
        if let Ok(Some(pid)) = read_owner_pid(&self.state_path)
            && pid != self.pid
            && is_live(pid)
        {
            return Err(OverlayError::LiveForeignOwner(pid));
        }
        replace_state(
            &self.state_path,
            self.pid,
            self.initial_state,
            (self.initial_state == OverlayState::Enrollment).then_some(0),
        )?;
        self.active = true;
        Ok(())
    }

    fn safe_update(&self, state: OverlayState, progress: Option<u8>) {
        if self.active
            && let Err(error) = replace_state(&self.state_path, self.pid, state, progress)
        {
            report_overlay_failure(OverlayFailureStage::StateUpdate, error);
        }
    }
}

impl Drop for OverlaySession {
    fn drop(&mut self) {
        if let Err(error) = self.restore() {
            report_overlay_failure(OverlayFailureStage::Cleanup, error);
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct OverlayRecord {
    pid: u32,
    state: OverlayState,
    progress: Option<u8>,
}

fn process_is_live(pid: u32) -> bool {
    pid != 0 && Path::new("/proc").join(pid.to_string()).exists()
}

fn replace_state(
    path: &Path,
    pid: u32,
    state: OverlayState,
    progress: Option<u8>,
) -> Result<(), OverlayError> {
    let payload = if let Some(progress) = progress.filter(|progress| *progress <= 100) {
        format!(
            "{{\"version\":2,\"pid\":{pid},\"state\":\"{}\",\"progress\":{progress}}}\n",
            state.as_str()
        )
    } else {
        format!(
            "{{\"version\":1,\"pid\":{pid},\"state\":\"{}\"}}\n",
            state.as_str()
        )
    };
    let (mut temporary, temporary_path) = create_temporary(path, pid)?;
    let result = (|| {
        temporary
            .write_all(payload.as_bytes())
            .map_err(|_| OverlayError::StorageUnavailable)?;
        temporary
            .set_permissions(fs::Permissions::from_mode(STATE_FILE_MODE))
            .map_err(|_| OverlayError::StorageUnavailable)?;
        temporary
            .sync_all()
            .map_err(|_| OverlayError::StorageUnavailable)?;
        drop(temporary);
        fs::rename(&temporary_path, path).map_err(|_| OverlayError::StorageUnavailable)?;
        sync_parent_directory(path)
    })();

    if result.is_err() {
        let _ = fs::remove_file(temporary_path);
    }
    result
}

fn create_temporary(path: &Path, pid: u32) -> Result<(File, PathBuf), OverlayError> {
    let parent = path.parent().ok_or(OverlayError::StorageUnavailable)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(OverlayError::StorageUnavailable)?;

    for _ in 0..TEMPORARY_FILE_ATTEMPTS {
        let sequence = TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let temporary_path = parent.join(format!(".{name}.{pid}.{sequence}.tmp"));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(STATE_FILE_MODE)
            .custom_flags(O_NOFOLLOW)
            .open(&temporary_path)
        {
            Ok(file) => return Ok((file, temporary_path)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(OverlayError::StorageUnavailable),
        }
    }
    Err(OverlayError::StorageUnavailable)
}

fn sync_parent_directory(path: &Path) -> Result<(), OverlayError> {
    let parent = path.parent().ok_or(OverlayError::StorageUnavailable)?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| OverlayError::StorageUnavailable)
}

#[cfg(test)]
fn read_record(path: &Path) -> Result<Option<OverlayRecord>, OverlayError> {
    let value = match fs::read_to_string(path) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(OverlayError::StorageUnavailable),
    };
    Ok(parse_record(&value))
}

fn read_owner_pid(path: &Path) -> Result<Option<u32>, OverlayError> {
    let value = match fs::read_to_string(path) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(OverlayError::StorageUnavailable),
    };
    Ok(parse_owner_pid(&value))
}

fn parse_owner_pid(value: &str) -> Option<u32> {
    let body = value.trim().strip_prefix('{')?.strip_suffix('}')?;
    let mut pid = None;
    for member in body.split(',') {
        let Some((key, value)) = member.split_once(':') else {
            continue;
        };
        if key.trim() == "\"pid\"" {
            if pid.is_some() {
                return None;
            }
            pid = value.trim().parse::<u32>().ok().filter(|pid| *pid > 0);
        }
    }
    pid
}

#[cfg(test)]
fn parse_record(value: &str) -> Option<OverlayRecord> {
    let value = value.trim();
    let body = value.strip_prefix('{')?.strip_suffix('}')?;
    let mut version = None;
    let mut pid = None;
    let mut state = None;
    let mut progress = None;

    for member in body.split(',') {
        let (key, value) = member.split_once(':')?;
        match key.trim() {
            "\"version\"" if version.is_none() => version = value.trim().parse::<u32>().ok(),
            "\"pid\"" if pid.is_none() => pid = value.trim().parse::<u32>().ok(),
            "\"state\"" if state.is_none() => {
                let state_name = value.trim().strip_prefix('"')?.strip_suffix('"')?;
                state = OverlayState::parse(state_name);
            }
            "\"progress\"" if progress.is_none() => progress = value.trim().parse::<u8>().ok(),
            _ => return None,
        }
    }

    let version = version?;
    let state = state?;
    let valid_schema = match version {
        1 => progress.is_none(),
        2 => state == OverlayState::Enrollment && progress.is_some_and(|value| value <= 100),
        _ => false,
    };
    (valid_schema && pid.is_some_and(|pid| pid > 0)).then_some(OverlayRecord {
        pid: pid?,
        state,
        progress,
    })
}

/// One active authentication's token-associated cancellation delivery.
#[derive(Default)]
pub struct CancellationSlot {
    registration: Mutex<Option<CancellationRegistration>>,
}

struct CancellationRegistration {
    token: OperationToken,
    event: Arc<AtomicBool>,
}

impl fmt::Debug for CancellationSlot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CancellationSlot")
            .field(
                "active",
                &self
                    .registration
                    .lock()
                    .is_ok_and(|registration| registration.is_some()),
            )
            .finish()
    }
}

/// Attempted to install a second active authentication event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CancellationAlreadyActive;

impl fmt::Display for CancellationAlreadyActive {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an authentication cancellation event is already active")
    }
}

impl std::error::Error for CancellationAlreadyActive {}

impl CancellationSlot {
    /// Publishes an active operation's cancellation event.
    ///
    /// # Errors
    ///
    /// Returns an error if an operation is already active or the slot is
    /// unavailable after a synchronization failure.
    pub fn install(
        &self,
        token: OperationToken,
        event: Arc<AtomicBool>,
    ) -> Result<(), CancellationAlreadyActive> {
        let mut current = self
            .registration
            .lock()
            .map_err(|_| CancellationAlreadyActive)?;
        if current.is_some() {
            return Err(CancellationAlreadyActive);
        }
        *current = Some(CancellationRegistration { token, event });
        Ok(())
    }

    /// Clears the slot only if it still contains this operation's event.
    pub fn clear(&self, token: OperationToken, event: &Arc<AtomicBool>) {
        if let Ok(mut current) = self.registration.lock()
            && current.as_ref().is_some_and(|installed| {
                installed.token == token && Arc::ptr_eq(&installed.event, event)
            })
        {
            *current = None;
        }
    }

    /// Atomically closes one exact registration and reports whether no
    /// cancellation had already been delivered.
    ///
    /// Delivery uses the same mutex, so a cancellation is wholly before this
    /// cutoff (event set, returns `false`) or wholly after it (delivery fails,
    /// returns `true`). Synchronization uncertainty fails closed.
    #[must_use]
    pub fn close(&self, token: OperationToken, event: &Arc<AtomicBool>) -> bool {
        let Ok(mut current) = self.registration.lock() else {
            return false;
        };
        let Some(installed) = current.as_ref() else {
            return false;
        };
        if installed.token != token || !Arc::ptr_eq(&installed.event, event) {
            return false;
        }
        let accepted = installed.event.load(Ordering::Acquire);
        *current = None;
        !accepted
    }

    /// Delivers cancellation only to the worker registered for `token`.
    ///
    /// This mechanism does not authorize or acknowledge cancellation. The
    /// broker state machine owns both decisions.
    #[must_use]
    pub fn deliver(&self, token: OperationToken) -> bool {
        let Ok(current) = self.registration.lock() else {
            return false;
        };
        let Some(registration) = current.as_ref() else {
            return false;
        };
        if registration.token != token {
            return false;
        }
        registration.event.store(true, Ordering::Release);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    use crate::auth_protocol::{
        AUTHENTICATE_REQUEST, AccessPolicy, BrokerDecision, BrokerState, Operation,
        OperationResult, PeerAddressFamily, PeerMetadata,
    };

    static TEST_DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = TEST_DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "t1bridge-overlay-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create synthetic test directory");
            Self(path)
        }

        fn state_path(&self) -> PathBuf {
            self.0.join("state.json")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn read_state(path: &Path) -> OverlayRecord {
        read_record(path)
            .expect("read synthetic state")
            .expect("state exists")
    }

    fn start_operation(state: &mut BrokerState) -> Operation {
        let peer = PeerMetadata {
            address_family: PeerAddressFamily::Local,
            user_id: 42_000,
            group_id: 42_001,
        };
        let policy = AccessPolicy::new(peer.user_id).unwrap();
        let BrokerDecision::Start(operation) =
            state.handle_packet(peer, policy, AUTHENTICATE_REQUEST)
        else {
            panic!("synthetic authentication must start")
        };
        operation
    }

    #[test]
    fn native_enrollment_progress_maps_to_bounded_percent() {
        assert_eq!(enrollment_percent(0x64), Some(0));
        assert_eq!(enrollment_percent(0xe4), Some(50));
        assert_eq!(enrollment_percent(0x163), Some(100));
        assert_eq!(enrollment_percent(0x63), None);
        assert_eq!(enrollment_percent(0x164), None);
    }

    #[test]
    fn enrollment_publishes_progress_and_cleans_up() {
        let directory = TestDirectory::new();
        let path = directory.state_path();
        let mut session = OverlaySession::new(&path, OverlayState::Enrollment);
        session.start().expect("start overlay");
        assert_eq!(
            fs::read_to_string(&path).expect("read initial enrollment state"),
            format!(
                "{{\"version\":2,\"pid\":{},\"state\":\"enrollment\",\"progress\":0}}\n",
                std::process::id()
            )
        );
        assert_eq!(
            read_state(&path),
            OverlayRecord {
                pid: std::process::id(),
                state: OverlayState::Enrollment,
                progress: Some(0),
            }
        );

        session.update_progress(0xe4);
        session.saving();
        session.complete();
        assert_eq!(read_state(&path).progress, Some(50));

        session.update_standard_progress(4, 5);
        assert_eq!(
            fs::read_to_string(&path).expect("read standard enrollment progress"),
            format!(
                "{{\"version\":2,\"pid\":{},\"state\":\"enrollment\",\"progress\":80}}\n",
                std::process::id()
            )
        );
        assert_eq!(read_state(&path).progress, Some(80));
        session.update_standard_progress(0, 5);
        assert_eq!(read_state(&path).progress, Some(80));

        session.restore().expect("restore overlay");
        assert!(!path.exists());
    }

    #[test]
    fn authentication_retry_and_success_are_best_effort() {
        let directory = TestDirectory::new();
        let path = directory.state_path();
        let mut session = OverlaySession::new(&path, OverlayState::Authenticate);
        session.start().expect("start overlay");
        session.try_again();
        assert_eq!(read_state(&path).state, OverlayState::Retry);
        session.success();
        assert_eq!(read_state(&path).state, OverlayState::Success);
        session.restore().expect("restore overlay");
    }

    #[test]
    fn approval_uses_distinct_initial_state() {
        let directory = TestDirectory::new();
        let path = directory.state_path();
        let mut session = OverlaySession::new(&path, OverlayState::Approve);
        session.start().expect("start overlay");
        assert_eq!(read_state(&path).state, OverlayState::Approve);
        session.restore().expect("restore overlay");
    }

    #[test]
    fn atomic_state_has_exact_schema_newline_and_mode() {
        let directory = TestDirectory::new();
        let path = directory.state_path();
        let mut session = OverlaySession::new(&path, OverlayState::Authenticate);
        session.start().expect("start overlay");

        let text = fs::read_to_string(&path).expect("read state text");
        assert_eq!(
            text,
            format!(
                "{{\"version\":1,\"pid\":{},\"state\":\"authenticate\"}}\n",
                std::process::id()
            )
        );
        let mode = fs::metadata(&path)
            .expect("state metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, STATE_FILE_MODE);
        assert_eq!(
            fs::read_dir(&directory.0)
                .expect("list test directory")
                .count(),
            1
        );
        session.restore().expect("restore overlay");
    }

    #[test]
    fn live_foreign_owner_is_neither_overwritten_nor_removed() {
        let directory = TestDirectory::new();
        let path = directory.state_path();
        let foreign_pid = std::process::id().saturating_add(1);
        fs::write(
            &path,
            format!("{{\"version\":1,\"pid\":{foreign_pid},\"state\":\"authenticate\"}}\n"),
        )
        .expect("write foreign state");

        let mut session = OverlaySession::new(&path, OverlayState::Enrollment);
        assert_eq!(
            session.start_with_liveness(|pid| pid == foreign_pid),
            Err(OverlayError::LiveForeignOwner(foreign_pid))
        );
        assert_eq!(read_state(&path).pid, foreign_pid);
        session.restore().expect("inactive restore is harmless");
        assert_eq!(read_state(&path).pid, foreign_pid);
    }

    #[test]
    fn live_foreign_owner_is_honored_even_for_a_newer_state_schema() {
        let directory = TestDirectory::new();
        let path = directory.state_path();
        let foreign_pid = std::process::id().saturating_add(1);
        fs::write(
            &path,
            format!("{{\"version\":2,\"pid\":{foreign_pid},\"state\":\"future\",\"extra\":1}}\n"),
        )
        .expect("write newer foreign state");

        let mut session = OverlaySession::new(&path, OverlayState::Enrollment);
        assert_eq!(
            session.start_with_liveness(|pid| pid == foreign_pid),
            Err(OverlayError::LiveForeignOwner(foreign_pid))
        );
        assert_eq!(
            parse_owner_pid(&fs::read_to_string(&path).unwrap()),
            Some(foreign_pid)
        );
    }

    #[test]
    fn cleanup_does_not_remove_replaced_foreign_state() {
        let directory = TestDirectory::new();
        let path = directory.state_path();
        let mut session = OverlaySession::new(&path, OverlayState::Authenticate);
        session.start().expect("start overlay");
        let foreign_pid = std::process::id().saturating_add(1);
        fs::write(
            &path,
            format!("{{\"version\":1,\"pid\":{foreign_pid},\"state\":\"approve\"}}\n"),
        )
        .expect("replace with foreign state");

        session.restore().expect("restore leaves foreign state");
        assert_eq!(read_state(&path).pid, foreign_pid);
    }

    #[test]
    fn cosmetic_failures_do_not_block_the_operation() {
        let directory = TestDirectory::new();
        let missing = directory.0.join("missing").join("state.json");
        assert!(OverlaySession::activate_optional(&missing, OverlayState::Authenticate).is_none());

        let path = directory.state_path();
        let mut session = OverlaySession::new(&path, OverlayState::Authenticate);
        session.start().expect("start overlay");
        fs::remove_file(&path).expect("remove state to inject update failure");
        fs::create_dir(&path).expect("replace state path with directory");
        session.try_again();
        session.success();
        session
            .restore()
            .expect("malformed replacement is left alone");
    }

    #[test]
    fn malformed_and_unknown_state_records_are_ignored() {
        assert_eq!(parse_record("not json"), None);
        assert_eq!(
            parse_record("{\"version\":2,\"pid\":7,\"state\":\"authenticate\"}"),
            None
        );
        assert_eq!(
            parse_record("{\"version\":1,\"pid\":7,\"state\":\"other\"}"),
            None
        );
        assert_eq!(
            parse_record("{\"version\":1,\"pid\":7,\"state\":\"success\",\"extra\":1}"),
            None
        );
    }

    #[test]
    fn cancellation_delivery_requires_the_registered_operation_token() {
        let mut state = BrokerState::default();
        let first = start_operation(&mut state);
        state.finish(first.token, OperationResult::Failed).unwrap();
        let second = start_operation(&mut state);
        let slot = CancellationSlot::default();
        let event = Arc::new(AtomicBool::new(false));
        slot.install(second.token, Arc::clone(&event))
            .expect("install event");

        assert!(!slot.deliver(first.token));
        assert!(!event.load(Ordering::Acquire));
        assert!(slot.deliver(second.token));
        assert!(event.load(Ordering::Acquire));

        slot.clear(first.token, &event);
        assert!(slot.deliver(second.token));
        slot.clear(second.token, &event);
        assert!(!slot.deliver(second.token));
    }

    #[test]
    fn cancellation_slot_does_not_replace_an_active_operation() {
        let mut state = BrokerState::default();
        let operation = start_operation(&mut state);
        let slot = CancellationSlot::default();
        let first = Arc::new(AtomicBool::new(false));
        let second = Arc::new(AtomicBool::new(false));
        slot.install(operation.token, Arc::clone(&first))
            .expect("install first event");
        assert_eq!(
            slot.install(operation.token, Arc::clone(&second)),
            Err(CancellationAlreadyActive)
        );
        slot.clear(operation.token, &second);
        assert!(slot.deliver(operation.token));
        assert!(first.load(Ordering::Acquire));
        assert!(!second.load(Ordering::Acquire));
    }
}

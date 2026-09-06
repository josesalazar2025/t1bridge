//! Read-only, identifier-free inspection for the administrative status command.

use std::fmt;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use t1_daemons::xart_live::{ValidatedNcmInterface, XartListenerError};
use t1_platform::diagnostics::{Component, Outcome, Stage};

const USB_DEVICES: &str = "/sys/bus/usb/devices";
const TOUCHBAR_DRM: &str = "/dev/dri/touchbar";
const KEYBAG_STATE: &str = "/var/lib/t1bridge/touch-id/keybag.state";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const JOURNALCTL: &str = "/usr/bin/journalctl";
const SYSTEMCTL_TIMEOUT: Duration = Duration::from_secs(2);
const JOURNAL_INSPECTION_TIMEOUT: Duration = Duration::from_secs(3);
const WAIT_SLICE: Duration = Duration::from_millis(10);
const ATTRIBUTE_LIMIT: u64 = 16;
const USB_ENTRY_LIMIT: usize = 4_096;
const JOURNAL_OUTPUT_LIMIT: u64 = 65_536;
const DIAGNOSTIC_LINE_PREFIX: &str = "t1bridge-diagnostic ";

/// Complete fixed-row administrative status report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatusReport {
    usb_configuration: UsbConfigurationState,
    drm: AvailabilityState,
    ncm: AvailabilityState,
    xart: ReadinessState,
    xart_admission_evidence: XartAdmissionEvidence,
    keybag: KeybagState,
    broker: ReadinessState,
    touchbar: ReadinessState,
}

impl fmt::Display for StatusReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "usb-configuration: {}", self.usb_configuration)?;
        writeln!(formatter, "drm: {}", self.drm)?;
        writeln!(formatter, "ncm: {}", self.ncm)?;
        writeln!(formatter, "xart: {}", self.xart)?;
        writeln!(
            formatter,
            "xart-admission: {}",
            self.xart_admission_evidence
        )?;
        writeln!(formatter, "keybag: {}", self.keybag)?;
        writeln!(formatter, "broker: {}", self.broker)?;
        write!(formatter, "touchbar: {}", self.touchbar)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UsbConfigurationState {
    Selected,
    Unexpected,
    Unavailable,
}

impl fmt::Display for UsbConfigurationState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Selected => "selected",
            Self::Unexpected => "unexpected",
            Self::Unavailable => "unavailable",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AvailabilityState {
    Ready,
    Unavailable,
}

impl fmt::Display for AvailabilityState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Ready => "ready",
            Self::Unavailable => "unavailable",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadinessState {
    Ready,
    NotReady,
}

impl From<bool> for ReadinessState {
    fn from(ready: bool) -> Self {
        if ready { Self::Ready } else { Self::NotReady }
    }
}

impl fmt::Display for ReadinessState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Ready => "ready",
            Self::NotReady => "not-ready",
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeybagState {
    Ready,
    NotReady,
    NotEnrolled,
}

impl fmt::Display for KeybagState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Ready => "ready",
            Self::NotReady => "not-ready",
            Self::NotEnrolled => "not-enrolled",
        })
    }
}

/// Evidence, gathered from this boot's own diagnostic records, of whether
/// xART has ever admitted an inbound session.
///
/// This is read-only and firewall-agnostic: it never inspects, changes, or
/// names any firewall configuration, and it never claims a socket is
/// "reachable" from a listener state alone. A listener with no recorded
/// admission is unremarkable before diagnostics are enabled or before any
/// enrollment or match has been attempted; only an attempted operation with
/// zero recorded admissions is worth a hint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum XartAdmissionEvidence {
    /// No diagnostic records exist for this boot. Diagnostics may be
    /// disabled, or this boot may be too new for any to have been written.
    DiagnosticsUnavailable,
    /// Diagnostic records exist, but no enrollment or match was attempted.
    Unused,
    /// An enrollment or match was attempted, but xART never recorded an
    /// admitted session for it.
    NeverAdmitted,
    /// xART recorded at least one admitted session this boot.
    Admitted,
}

impl fmt::Display for XartAdmissionEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DiagnosticsUnavailable => "diagnostics unavailable",
            Self::Unused => "not yet attempted this boot",
            Self::NeverAdmitted => {
                "listening; inbound reachability unverified -- an operation was \
                 attempted but xART never admitted a session for it; check that \
                 inbound TCP 61500 on the discovered T1 interface can reach this host"
            }
            Self::Admitted => "admission confirmed",
        })
    }
}

/// Static failure from a read-only component inspection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatusError {
    UsbInspection,
    DrmInspection,
    NcmInspection,
    KeybagInspection,
    ServiceInspection,
    DiagnosticsInspection,
}

impl fmt::Display for StatusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UsbInspection => "USB state could not be inspected",
            Self::DrmInspection => "DRM state could not be inspected",
            Self::NcmInspection => "NCM state could not be inspected",
            Self::KeybagInspection => "keybag state could not be inspected",
            Self::ServiceInspection => "service state could not be inspected",
            Self::DiagnosticsInspection => "diagnostic records could not be inspected",
        })
    }
}

impl std::error::Error for StatusError {}

trait StatusSource {
    fn usb_configuration(&mut self) -> Result<UsbConfigurationState, StatusError>;
    fn drm(&mut self) -> Result<AvailabilityState, StatusError>;
    fn ncm(&mut self) -> Result<AvailabilityState, StatusError>;
    fn keybag_exists(&mut self) -> Result<bool, StatusError>;
    fn service_ready(&mut self, service: Service) -> Result<bool, StatusError>;
    fn xart_admission_evidence(&mut self) -> Result<XartAdmissionEvidence, StatusError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Service {
    Xart,
    Keybag,
    Broker,
    Touchbar,
}

impl Service {
    const fn unit(self) -> &'static str {
        match self {
            Self::Xart => "t1-xart-storage@*.service",
            Self::Keybag => "t1bridge-keybag.service",
            Self::Broker => "t1-touchid-auth.socket",
            Self::Touchbar => "t1-touchbar-hw.service",
        }
    }
}

struct SystemStatusSource;

impl StatusSource for SystemStatusSource {
    fn usb_configuration(&mut self) -> Result<UsbConfigurationState, StatusError> {
        inspect_usb_configuration(Path::new(USB_DEVICES))
    }

    fn drm(&mut self) -> Result<AvailabilityState, StatusError> {
        inspect_drm(Path::new(TOUCHBAR_DRM))
    }

    fn ncm(&mut self) -> Result<AvailabilityState, StatusError> {
        match ValidatedNcmInterface::discover() {
            Ok(_) => Ok(AvailabilityState::Ready),
            Err(XartListenerError::DeviceNotFound) => Ok(AvailabilityState::Unavailable),
            Err(_) => Err(StatusError::NcmInspection),
        }
    }

    fn keybag_exists(&mut self) -> Result<bool, StatusError> {
        inspect_keybag(Path::new(KEYBAG_STATE))
    }

    fn service_ready(&mut self, service: Service) -> Result<bool, StatusError> {
        inspect_service(service)
    }

    fn xart_admission_evidence(&mut self) -> Result<XartAdmissionEvidence, StatusError> {
        inspect_xart_admission_evidence()
    }
}

/// Performs one strictly read-only system inspection.
///
/// Unavailable hardware and inactive services are reportable states. Only an
/// inability to inspect a required source returns an error. No socket, service,
/// device, or link is opened for activation or changed by this operation.
///
/// # Errors
///
/// Returns a static component category if an inspection cannot be completed.
pub fn inspect() -> Result<StatusReport, StatusError> {
    inspect_with(&mut SystemStatusSource)
}

fn inspect_with(source: &mut impl StatusSource) -> Result<StatusReport, StatusError> {
    let usb_configuration = source.usb_configuration()?;
    let drm = source.drm()?;
    let ncm = source.ncm()?;
    let xart = source.service_ready(Service::Xart)?.into();
    let xart_admission_evidence = source.xart_admission_evidence()?;
    let keybag_exists = source.keybag_exists()?;
    let keybag_service = source.service_ready(Service::Keybag)?;
    let keybag = match (keybag_exists, keybag_service) {
        (false, _) => KeybagState::NotEnrolled,
        (true, true) => KeybagState::Ready,
        (true, false) => KeybagState::NotReady,
    };
    let broker = source.service_ready(Service::Broker)?.into();
    let touchbar = source.service_ready(Service::Touchbar)?.into();
    Ok(StatusReport {
        usb_configuration,
        drm,
        ncm,
        xart,
        xart_admission_evidence,
        keybag,
        broker,
        touchbar,
    })
}

fn inspect_usb_configuration(root: &Path) -> Result<UsbConfigurationState, StatusError> {
    let entries = fs::read_dir(root).map_err(|_| StatusError::UsbInspection)?;
    let mut configuration = None;
    for (index, entry) in entries.enumerate() {
        if index >= USB_ENTRY_LIMIT {
            return Err(StatusError::UsbInspection);
        }
        let entry = entry.map_err(|_| StatusError::UsbInspection)?;
        let path = entry.path();
        let Some(vendor) = read_optional_attribute(&path.join("idVendor"))? else {
            continue;
        };
        if vendor != "05ac" {
            continue;
        }
        let Some(product) = read_optional_attribute(&path.join("idProduct"))? else {
            return Err(StatusError::UsbInspection);
        };
        if product != "8600" {
            continue;
        }
        if configuration.is_some() {
            return Err(StatusError::UsbInspection);
        }
        configuration = Some(
            read_optional_attribute(&path.join("bConfigurationValue"))?
                .ok_or(StatusError::UsbInspection)?,
        );
    }
    Ok(match configuration.as_deref() {
        Some("2") => UsbConfigurationState::Selected,
        Some(_) => UsbConfigurationState::Unexpected,
        None => UsbConfigurationState::Unavailable,
    })
}

fn read_optional_attribute(path: &Path) -> Result<Option<String>, StatusError> {
    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(StatusError::UsbInspection),
    };
    let mut bytes = Vec::new();
    file.by_ref()
        .take(ATTRIBUTE_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| StatusError::UsbInspection)?;
    if bytes.len() as u64 > ATTRIBUTE_LIMIT {
        return Err(StatusError::UsbInspection);
    }
    let value = std::str::from_utf8(&bytes).map_err(|_| StatusError::UsbInspection)?;
    let value = value.strip_suffix('\n').unwrap_or(value);
    if value.is_empty() || value.contains(char::is_whitespace) {
        return Err(StatusError::UsbInspection);
    }
    Ok(Some(value.to_owned()))
}

fn inspect_drm(path: &Path) -> Result<AvailabilityState, StatusError> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.file_type().is_char_device() => Ok(AvailabilityState::Ready),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(AvailabilityState::Unavailable),
        Ok(_) | Err(_) => Err(StatusError::DrmInspection),
    }
}

fn inspect_keybag(path: &Path) -> Result<bool, StatusError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if private_root_file(&metadata) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Ok(_) | Err(_) => Err(StatusError::KeybagInspection),
    }
}

#[cfg(target_family = "unix")]
fn private_root_file(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    metadata.file_type().is_file()
        && metadata.uid() == 0
        && metadata.gid() == 0
        && metadata.mode() & 0o7777 == 0o600
        && metadata.nlink() == 1
}

fn inspect_service(service: Service) -> Result<bool, StatusError> {
    let deadline = Instant::now()
        .checked_add(SYSTEMCTL_TIMEOUT)
        .ok_or(StatusError::ServiceInspection)?;
    let mut child = Command::new(SYSTEMCTL)
        .args(["is-active", "--quiet", service.unit()])
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| StatusError::ServiceInspection)?;
    let status = wait_for_child(&mut child, deadline, StatusError::ServiceInspection)?;
    match status.code() {
        Some(0) => Ok(true),
        Some(3 | 4) => Ok(false),
        _ => Err(StatusError::ServiceInspection),
    }
}

fn wait_for_child(
    child: &mut Child,
    deadline: Instant,
    error: StatusError,
) -> Result<ExitStatus, StatusError> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(WAIT_SLICE),
            Ok(None) | Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error);
            }
        }
    }
}

/// Reads this boot's own diagnostic records and classifies xART admission
/// evidence from them.
///
/// Read-only: this runs `journalctl` scoped to the current boot and a fixed
/// line-prefix filter, and never inspects, names, or changes any firewall
/// configuration. A bounded amount of output is read; exceeding it is an
/// inspection failure rather than an unbounded read.
fn inspect_xart_admission_evidence() -> Result<XartAdmissionEvidence, StatusError> {
    let deadline = Instant::now()
        .checked_add(JOURNAL_INSPECTION_TIMEOUT)
        .ok_or(StatusError::DiagnosticsInspection)?;
    let mut child = Command::new(JOURNALCTL)
        .args([
            "-b",
            "--no-pager",
            "-o",
            "cat",
            "--grep",
            &format!("^{DIAGNOSTIC_LINE_PREFIX}"),
        ])
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| StatusError::DiagnosticsInspection)?;
    let status = wait_for_child(&mut child, deadline, StatusError::DiagnosticsInspection)?;
    if !status.success() {
        return Err(StatusError::DiagnosticsInspection);
    }
    let mut stdout = child
        .stdout
        .take()
        .ok_or(StatusError::DiagnosticsInspection)?;
    let mut bytes = Vec::new();
    stdout
        .by_ref()
        .take(JOURNAL_OUTPUT_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| StatusError::DiagnosticsInspection)?;
    if bytes.len() as u64 > JOURNAL_OUTPUT_LIMIT {
        return Err(StatusError::DiagnosticsInspection);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| StatusError::DiagnosticsInspection)?;
    Ok(classify_xart_admission_evidence(text.lines()))
}

/// Classifies xART admission evidence from already-read diagnostic lines.
///
/// Any operation attempt is recognized from the broker's own `enroll` or
/// `match` phase beginning; xART admission is recognized from its
/// `session-admission` phase succeeding. Neither is correlated to a specific
/// attempt -- this reports whether either happened at all this boot, which is
/// enough to distinguish "nothing tried yet" from "tried repeatedly with zero
/// admissions" without tracking per-attempt state.
fn classify_xart_admission_evidence<'a>(
    lines: impl Iterator<Item = &'a str>,
) -> XartAdmissionEvidence {
    let attempt_component = format!("component={}", Component::Broker.label());
    let enroll_begin = format!(
        "phase={} result={}",
        Stage::Enroll.label(),
        Outcome::Begin.label()
    );
    let match_begin = format!(
        "phase={} result={}",
        Stage::Match.label(),
        Outcome::Begin.label()
    );
    let admission_ok = format!(
        "component={} phase={} result={}",
        Component::Xart.label(),
        Stage::SessionAdmission.label(),
        Outcome::Ok.label()
    );

    let mut saw_any_record = false;
    let mut attempted = false;
    let mut admitted = false;
    for line in lines {
        let Some(line) = line.strip_prefix(DIAGNOSTIC_LINE_PREFIX) else {
            continue;
        };
        saw_any_record = true;
        if line.contains(&attempt_component)
            && (line.contains(&enroll_begin) || line.contains(&match_begin))
        {
            attempted = true;
        }
        if line.contains(&admission_ok) {
            admitted = true;
        }
    }

    if !saw_any_record {
        XartAdmissionEvidence::DiagnosticsUnavailable
    } else if admitted {
        XartAdmissionEvidence::Admitted
    } else if attempted {
        XartAdmissionEvidence::NeverAdmitted
    } else {
        XartAdmissionEvidence::Unused
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[derive(Clone)]
    struct FakeSource {
        usb: Result<UsbConfigurationState, StatusError>,
        drm: Result<AvailabilityState, StatusError>,
        ncm: Result<AvailabilityState, StatusError>,
        keybag_exists: Result<bool, StatusError>,
        services: BTreeMap<&'static str, Result<bool, StatusError>>,
        xart_admission_evidence: Result<XartAdmissionEvidence, StatusError>,
    }

    impl StatusSource for FakeSource {
        fn usb_configuration(&mut self) -> Result<UsbConfigurationState, StatusError> {
            self.usb
        }

        fn drm(&mut self) -> Result<AvailabilityState, StatusError> {
            self.drm
        }

        fn ncm(&mut self) -> Result<AvailabilityState, StatusError> {
            self.ncm
        }

        fn keybag_exists(&mut self) -> Result<bool, StatusError> {
            self.keybag_exists
        }

        fn service_ready(&mut self, service: Service) -> Result<bool, StatusError> {
            self.services[service.unit()]
        }

        fn xart_admission_evidence(&mut self) -> Result<XartAdmissionEvidence, StatusError> {
            self.xart_admission_evidence
        }
    }

    fn source() -> FakeSource {
        FakeSource {
            usb: Ok(UsbConfigurationState::Selected),
            drm: Ok(AvailabilityState::Ready),
            ncm: Ok(AvailabilityState::Ready),
            keybag_exists: Ok(true),
            services: [
                (Service::Xart.unit(), Ok(true)),
                (Service::Keybag.unit(), Ok(true)),
                (Service::Broker.unit(), Ok(true)),
                (Service::Touchbar.unit(), Ok(true)),
            ]
            .into_iter()
            .collect(),
            xart_admission_evidence: Ok(XartAdmissionEvidence::Admitted),
        }
    }

    fn temporary_directory() -> PathBuf {
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("t1bridge-status-{}-{sequence}", std::process::id()));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn fixed_rows_report_healthy_state_without_identifiers() {
        let report = inspect_with(&mut source()).unwrap();
        assert_eq!(
            report.to_string(),
            "usb-configuration: selected\n\
             drm: ready\n\
             ncm: ready\n\
             xart: ready\n\
             xart-admission: admission confirmed\n\
             keybag: ready\n\
             broker: ready\n\
             touchbar: ready"
        );
    }

    #[test]
    fn ordinary_unavailable_states_still_produce_a_report() {
        let mut source = source();
        source.usb = Ok(UsbConfigurationState::Unavailable);
        source.drm = Ok(AvailabilityState::Unavailable);
        source.ncm = Ok(AvailabilityState::Unavailable);
        source.keybag_exists = Ok(false);
        source
            .services
            .values_mut()
            .for_each(|state| *state = Ok(false));
        source.xart_admission_evidence = Ok(XartAdmissionEvidence::DiagnosticsUnavailable);

        assert_eq!(
            inspect_with(&mut source).unwrap().to_string(),
            "usb-configuration: unavailable\n\
             drm: unavailable\n\
             ncm: unavailable\n\
             xart: not-ready\n\
             xart-admission: diagnostics unavailable\n\
             keybag: not-enrolled\n\
             broker: not-ready\n\
             touchbar: not-ready"
        );
    }

    #[test]
    fn inspection_failure_is_not_flattened_into_unavailable() {
        let mut source = source();
        source.ncm = Err(StatusError::NcmInspection);
        assert_eq!(inspect_with(&mut source), Err(StatusError::NcmInspection));
    }

    #[test]
    fn xart_admission_inspection_failure_is_not_flattened_into_unavailable() {
        let mut source = source();
        source.xart_admission_evidence = Err(StatusError::DiagnosticsInspection);
        assert_eq!(
            inspect_with(&mut source),
            Err(StatusError::DiagnosticsInspection)
        );
    }

    #[test]
    fn classifier_reports_no_evidence_at_all_as_diagnostics_unavailable() {
        assert_eq!(
            classify_xart_admission_evidence(std::iter::empty()),
            XartAdmissionEvidence::DiagnosticsUnavailable
        );
        // Unrelated journal noise around the diagnostic lines doesn't count.
        let lines = ["", "some other unrelated log line", "  "];
        assert_eq!(
            classify_xart_admission_evidence(lines.into_iter()),
            XartAdmissionEvidence::DiagnosticsUnavailable
        );
    }

    #[test]
    fn classifier_reports_startup_only_records_as_unused() {
        let lines = [
            "t1bridge-diagnostic v=1 component=broker phase=startup result=begin code=none command=none",
            "t1bridge-diagnostic v=1 component=broker phase=startup result=ok code=none command=none",
        ];
        assert_eq!(
            classify_xart_admission_evidence(lines.into_iter()),
            XartAdmissionEvidence::Unused
        );
    }

    #[test]
    fn classifier_reports_an_attempt_with_no_admission_as_never_admitted() {
        let lines = [
            "t1bridge-diagnostic v=1 component=broker phase=enroll result=begin code=none command=none",
            "t1bridge-diagnostic v=1 component=broker phase=transaction result=begin code=none command=0x03",
            "t1bridge-diagnostic v=1 component=broker phase=transaction result=error code=1 command=0x03",
            "t1bridge-diagnostic v=1 component=broker phase=enroll result=error code=none command=none",
        ];
        assert_eq!(
            classify_xart_admission_evidence(lines.into_iter()),
            XartAdmissionEvidence::NeverAdmitted
        );
    }

    #[test]
    fn classifier_reports_a_recorded_admission_as_admitted_even_with_other_session_errors() {
        let lines = [
            "t1bridge-diagnostic v=1 component=broker phase=enroll result=begin code=none command=none",
            "t1bridge-diagnostic v=1 component=xart phase=session-admission result=begin code=none command=none",
            "t1bridge-diagnostic v=1 component=xart phase=session-admission result=ok code=none command=none",
            "t1bridge-diagnostic v=1 component=xart phase=xart-session result=begin code=none command=none",
            "t1bridge-diagnostic v=1 component=xart phase=xart-session result=error code=none command=none",
            "t1bridge-diagnostic v=1 component=broker phase=enroll result=ok code=none command=none",
        ];
        assert_eq!(
            classify_xart_admission_evidence(lines.into_iter()),
            XartAdmissionEvidence::Admitted
        );
    }

    #[test]
    fn classifier_recognizes_match_attempts_too() {
        let lines = [
            "t1bridge-diagnostic v=1 component=broker phase=match result=begin code=none command=none",
            "t1bridge-diagnostic v=1 component=broker phase=match result=ok code=none command=none",
        ];
        assert_eq!(
            classify_xart_admission_evidence(lines.into_iter()),
            XartAdmissionEvidence::NeverAdmitted
        );
    }

    #[test]
    fn unexpected_configuration_and_inactive_keybag_are_reportable() {
        let mut source = source();
        source.usb = Ok(UsbConfigurationState::Unexpected);
        source.services.insert(Service::Keybag.unit(), Ok(false));
        let report = inspect_with(&mut source).unwrap();
        assert_eq!(report.usb_configuration, UsbConfigurationState::Unexpected);
        assert_eq!(report.keybag, KeybagState::NotReady);
    }

    #[test]
    fn usb_discovery_is_dynamic_bounded_and_ambiguity_fails() {
        let root = temporary_directory();
        let unrelated = root.join("synthetic-a");
        let t1 = root.join("synthetic-b");
        fs::create_dir(&unrelated).unwrap();
        fs::create_dir(&t1).unwrap();
        fs::write(unrelated.join("idVendor"), "1234\n").unwrap();
        fs::write(t1.join("idVendor"), "05ac\n").unwrap();
        fs::write(t1.join("idProduct"), "8600\n").unwrap();
        fs::write(t1.join("bConfigurationValue"), "2\n").unwrap();
        assert_eq!(
            inspect_usb_configuration(&root),
            Ok(UsbConfigurationState::Selected)
        );
        fs::write(t1.join("bConfigurationValue"), "1\n").unwrap();
        assert_eq!(
            inspect_usb_configuration(&root),
            Ok(UsbConfigurationState::Unexpected)
        );
        fs::write(t1.join("bConfigurationValue"), "2\n").unwrap();

        let duplicate = root.join("synthetic-c");
        fs::create_dir(&duplicate).unwrap();
        fs::write(duplicate.join("idVendor"), "05ac\n").unwrap();
        fs::write(duplicate.join("idProduct"), "8600\n").unwrap();
        fs::write(duplicate.join("bConfigurationValue"), "2\n").unwrap();
        assert_eq!(
            inspect_usb_configuration(&root),
            Err(StatusError::UsbInspection)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn usb_discovery_rejects_unbounded_or_noncanonical_attributes() {
        for value in ["05ac 8600\n", "00000000000000000"] {
            let root = temporary_directory();
            let device = root.join("synthetic-device");
            fs::create_dir(&device).unwrap();
            fs::write(device.join("idVendor"), value).unwrap();
            assert_eq!(
                inspect_usb_configuration(&root),
                Err(StatusError::UsbInspection)
            );
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn drm_requires_a_character_device_and_missing_is_reportable() {
        let root = temporary_directory();
        let path = root.join("touchbar");
        assert_eq!(inspect_drm(&path), Ok(AvailabilityState::Unavailable));
        fs::write(&path, "synthetic").unwrap();
        assert_eq!(inspect_drm(&path), Err(StatusError::DrmInspection));
        fs::remove_file(&path).unwrap();
        symlink("/dev/null", &path).unwrap();
        assert_eq!(inspect_drm(&path), Ok(AvailabilityState::Ready));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn keybag_missing_is_reportable_and_unsafe_objects_fail() {
        let root = temporary_directory();
        let path = root.join("keybag.state");
        assert_eq!(inspect_keybag(&path), Ok(false));
        fs::write(&path, "synthetic").unwrap();
        assert_eq!(inspect_keybag(&path), Err(StatusError::KeybagInspection));
        fs::remove_file(&path).unwrap();
        symlink("synthetic-target", &path).unwrap();
        assert_eq!(inspect_keybag(&path), Err(StatusError::KeybagInspection));
        fs::remove_dir_all(root).unwrap();
    }
}

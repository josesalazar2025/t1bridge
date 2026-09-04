//! Guarded, identifier-free same-boot cycling of one validated T1 device.

use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::io::{self, Read, Write};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use t1_platform::usb_cycle_guard::{self, Guard};

const USB_DEVICES: &str = "/sys/bus/usb/devices";
const CFGSELECTOR_DRIVER: &str = "/sys/bus/usb/drivers/t1bridge-cfgselector";
const SYSTEMCTL: &str = "/usr/bin/systemctl";
const ATTRIBUTE_LIMIT: usize = 64;
const ATTRIBUTE_READ_LIMIT: u64 = 65;
const USB_ENTRY_LIMIT: usize = 4_096;
const SERVICE_TIMEOUT: Duration = Duration::from_secs(45);
const DEVICE_TIMEOUT: Duration = Duration::from_secs(15);
const WAIT_SLICE: Duration = Duration::from_millis(50);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    HardwareUnavailable,
    UnexpectedHardware,
    Busy,
    NoActiveOperation,
    CancellationTimeout,
    ServiceControl,
    UnbindFailed,
    RebindFailed,
    ReappearanceTimeout,
    Interrupted,
    RecoveryFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::HardwareUnavailable => "the T1 device is unavailable",
            Self::UnexpectedHardware => "the T1 device state is not safe to cycle",
            Self::Busy => "another T1 hardware operation is active",
            Self::NoActiveOperation => {
                "no active standard fingerprint operation is ready for loss validation"
            }
            Self::CancellationTimeout => {
                "the active fingerprint operation did not release after device loss"
            }
            Self::ServiceControl => "dependent services could not be controlled",
            Self::UnbindFailed => "the guarded T1 removal failed",
            Self::RebindFailed => "the guarded T1 reappearance failed",
            Self::ReappearanceTimeout => "the T1 did not return in the expected state",
            Self::Interrupted => "the guarded T1 cycle was interrupted",
            Self::RecoveryFailed => "the T1 cycle could not restore a known-good state",
        })
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Report;

impl fmt::Display for Report {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("status cycled")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LiveLossReport;

impl fmt::Display for LiveLossReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("status live-loss-cycled")
    }
}

#[derive(Clone, Eq, PartialEq)]
struct DeviceKey(String);

impl fmt::Debug for DeviceKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DeviceKey(REDACTED)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DevicePhase {
    Operational,
    Quiesced,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Service {
    Fprintd,
    Broker,
    AuthenticationSocket,
    FingerprintSocket,
    Keybag,
    Touchbar,
    TouchbarSocket,
    Xart,
    Ncm,
}

impl Service {
    const COUNT: usize = 9;

    const STOP_ORDER: [Self; Self::COUNT] = [
        Self::Fprintd,
        Self::AuthenticationSocket,
        Self::FingerprintSocket,
        Self::Broker,
        Self::TouchbarSocket,
        Self::Touchbar,
        Self::Keybag,
        Self::Xart,
        Self::Ncm,
    ];

    const START_ORDER: [Self; Self::COUNT] = [
        Self::Ncm,
        Self::Xart,
        Self::Keybag,
        Self::AuthenticationSocket,
        Self::FingerprintSocket,
        Self::Broker,
        Self::Fprintd,
        Self::TouchbarSocket,
        Self::Touchbar,
    ];

    const LIVE_OPERATION_REQUIRED: [Self; 8] = [
        Self::Fprintd,
        Self::Broker,
        Self::AuthenticationSocket,
        Self::FingerprintSocket,
        Self::TouchbarSocket,
        Self::Touchbar,
        Self::Xart,
        Self::Ncm,
    ];

    const STEADY_START_ORDER: [Self; 8] = [
        Self::Ncm,
        Self::Xart,
        Self::Keybag,
        Self::AuthenticationSocket,
        Self::FingerprintSocket,
        Self::Fprintd,
        Self::TouchbarSocket,
        Self::Touchbar,
    ];

    const fn unit(self) -> &'static str {
        match self {
            Self::Fprintd => "fprintd.service",
            Self::Broker => "t1-touchid-auth.service",
            Self::AuthenticationSocket => "t1-touchid-auth.socket",
            Self::FingerprintSocket => "t1bridge-fingerprint.socket",
            Self::Keybag => "t1bridge-keybag.service",
            Self::Touchbar => "t1-touchbar-hw.service",
            Self::TouchbarSocket => "t1-touchbar-hw.socket",
            Self::Xart => "t1-xart-storage@*.service",
            Self::Ncm => "t1-ncm-ready@*.service",
        }
    }

    const fn index(self) -> usize {
        self as usize
    }

    const fn restart_after_cycle(self) -> bool {
        match self {
            Self::Ncm | Self::Xart | Self::Keybag => true,
            Self::Fprintd
            | Self::Broker
            | Self::AuthenticationSocket
            | Self::FingerprintSocket
            | Self::Touchbar
            | Self::TouchbarSocket => false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ServiceSnapshot([bool; Service::COUNT]);

impl ServiceSnapshot {
    const fn active(self, service: Service) -> bool {
        self.0[service.index()]
    }
}

trait CycleOps {
    fn inspect_device(&mut self) -> Result<DeviceKey, Error>;
    fn service_active(&mut self, service: Service) -> Result<bool, Error>;
    fn stop_service(&mut self, service: Service) -> Result<(), Error>;
    fn start_service(&mut self, service: Service) -> Result<(), Error>;
    fn restart_service(&mut self, service: Service) -> Result<(), Error>;
    fn reset_failed(&mut self, service: Service) -> Result<(), Error>;
    fn acquire_cycle_guard(&mut self) -> Result<(), Error>;
    fn acquire_sep_guard(&mut self) -> Result<(), Error>;
    fn active_sep_operation(&mut self) -> Result<bool, Error>;
    fn wait_for_sep_guard(&mut self) -> Result<(), Error>;
    fn release_sep_guard(&mut self);
    fn interrupted(&self) -> bool;
    fn unbind(&mut self, device: &DeviceKey) -> Result<(), Error>;
    fn unbind_live(&mut self, device: &DeviceKey) -> Result<(), Error>;
    fn wait_removed(&mut self, device: &DeviceKey) -> Result<(), Error>;
    fn bind(&mut self, device: &DeviceKey) -> Result<(), Error>;
    fn wait_reappeared(&mut self, device: &DeviceKey) -> Result<(), Error>;
    fn ensure_rebound(&mut self, device: &DeviceKey) -> Result<(), Error>;
    fn wait_operational(&mut self, device: &DeviceKey) -> Result<(), Error>;
}

struct SystemCycleOps {
    guard: Option<Guard>,
}

impl SystemCycleOps {
    const fn new() -> Self {
        Self { guard: None }
    }
}

impl CycleOps for SystemCycleOps {
    fn inspect_device(&mut self) -> Result<DeviceKey, Error> {
        inspect_unique_device(Path::new(USB_DEVICES), DevicePhase::Operational)
    }

    fn service_active(&mut self, service: Service) -> Result<bool, Error> {
        systemctl_is_active(service)
    }

    fn stop_service(&mut self, service: Service) -> Result<(), Error> {
        systemctl_change("stop", service, false)
    }

    fn start_service(&mut self, service: Service) -> Result<(), Error> {
        if matches!(service, Service::Xart | Service::Ncm) {
            wait_for_service_state(service, true)
        } else {
            systemctl_change("start", service, true)
        }
    }

    fn restart_service(&mut self, service: Service) -> Result<(), Error> {
        systemctl_change("restart", service, true)
    }

    fn reset_failed(&mut self, service: Service) -> Result<(), Error> {
        systemctl_reset_failed(service)
    }

    fn acquire_cycle_guard(&mut self) -> Result<(), Error> {
        let guard = Guard::acquire().map_err(map_guard_error)?;
        self.guard = Some(guard);
        Ok(())
    }

    fn acquire_sep_guard(&mut self) -> Result<(), Error> {
        self.guard
            .as_mut()
            .ok_or(Error::RecoveryFailed)?
            .acquire_sep()
            .map_err(map_guard_error)
    }

    fn active_sep_operation(&mut self) -> Result<bool, Error> {
        match self.acquire_sep_guard() {
            Err(Error::Busy) => Ok(true),
            Ok(()) => {
                self.release_sep_guard();
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    fn wait_for_sep_guard(&mut self) -> Result<(), Error> {
        let deadline = Instant::now()
            .checked_add(DEVICE_TIMEOUT)
            .ok_or(Error::UnexpectedHardware)?;
        loop {
            match self.acquire_sep_guard() {
                Ok(()) => return Ok(()),
                Err(Error::Busy) if Instant::now() < deadline => thread::sleep(WAIT_SLICE),
                Err(Error::Busy) => return Err(Error::CancellationTimeout),
                Err(error) => return Err(error),
            }
        }
    }

    fn release_sep_guard(&mut self) {
        if let Some(guard) = self.guard.as_mut() {
            guard.release_sep();
        }
    }

    fn interrupted(&self) -> bool {
        self.guard.as_ref().is_some_and(Guard::interrupted)
    }

    fn unbind(&mut self, device: &DeviceKey) -> Result<(), Error> {
        if inspect_unique_device(Path::new(USB_DEVICES), DevicePhase::Quiesced).as_ref()
            != Ok(device)
        {
            return Err(Error::UnbindFailed);
        }
        write_driver_control("unbind", device).map_err(|_| Error::UnbindFailed)
    }

    fn unbind_live(&mut self, device: &DeviceKey) -> Result<(), Error> {
        if inspect_unique_device(Path::new(USB_DEVICES), DevicePhase::Operational).as_ref()
            != Ok(device)
        {
            return Err(Error::UnbindFailed);
        }
        write_driver_control("unbind", device).map_err(|_| Error::UnbindFailed)
    }

    fn wait_removed(&mut self, device: &DeviceKey) -> Result<(), Error> {
        wait_until(DEVICE_TIMEOUT, || {
            device_is_unconfigured(Path::new(USB_DEVICES), device)
        })
        .map_err(|_| Error::UnbindFailed)
    }

    fn bind(&mut self, device: &DeviceKey) -> Result<(), Error> {
        validate_rebind_target(Path::new(USB_DEVICES), device).map_err(|_| Error::RebindFailed)?;
        write_driver_control("bind", device).map_err(|_| Error::RebindFailed)
    }

    fn wait_reappeared(&mut self, device: &DeviceKey) -> Result<(), Error> {
        wait_until(DEVICE_TIMEOUT, || {
            inspect_unique_device(Path::new(USB_DEVICES), DevicePhase::Quiesced)
                .map(|observed| observed == *device)
        })
        .map_err(|_| Error::ReappearanceTimeout)
    }

    fn ensure_rebound(&mut self, device: &DeviceKey) -> Result<(), Error> {
        if inspect_unique_device(Path::new(USB_DEVICES), DevicePhase::Quiesced).as_ref()
            == Ok(device)
        {
            return Ok(());
        }
        validate_rebind_target(Path::new(USB_DEVICES), device)
            .map_err(|_| Error::RecoveryFailed)?;
        write_driver_control("bind", device).map_err(|_| Error::RecoveryFailed)?;
        wait_until(DEVICE_TIMEOUT, || {
            inspect_unique_device(Path::new(USB_DEVICES), DevicePhase::Quiesced)
                .map(|observed| observed == *device)
        })
        .map_err(|_| Error::RecoveryFailed)
    }

    fn wait_operational(&mut self, device: &DeviceKey) -> Result<(), Error> {
        wait_until(DEVICE_TIMEOUT, || {
            inspect_unique_device(Path::new(USB_DEVICES), DevicePhase::Operational)
                .map(|observed| observed == *device)
        })
        .map_err(|_| Error::RecoveryFailed)
    }
}

fn map_guard_error(error: usb_cycle_guard::Error) -> Error {
    match error {
        usb_cycle_guard::Error::Busy => Error::Busy,
        usb_cycle_guard::Error::InvalidLock | usb_cycle_guard::Error::System => {
            Error::UnexpectedHardware
        }
    }
}

/// Performs the guarded same-boot cycle.
///
/// # Errors
///
/// Returns a fixed, identifier-free category when validation, exclusion,
/// cycling, reappearance, or restoration cannot complete safely.
pub fn run() -> Result<Report, Error> {
    run_with(&mut SystemCycleOps::new())
}

fn run_with(ops: &mut impl CycleOps) -> Result<Report, Error> {
    let device = ops.inspect_device()?;
    ops.acquire_cycle_guard()?;
    let snapshot = snapshot_services(ops)?;
    let mut services_changed = false;
    let mut needs_device_recovery = false;

    let primary = (|| {
        services_changed = true;
        stop_services(ops)?;
        ops.acquire_sep_guard()?;
        if ops.interrupted() {
            return Err(Error::Interrupted);
        }
        needs_device_recovery = true;
        ops.unbind(&device)?;
        ops.wait_removed(&device)?;
        if ops.interrupted() {
            return Err(Error::Interrupted);
        }
        ops.bind(&device)?;
        ops.wait_reappeared(&device)?;
        needs_device_recovery = false;
        if ops.interrupted() {
            return Err(Error::Interrupted);
        }
        Ok(())
    })();

    let device_recovery = if needs_device_recovery {
        ops.ensure_rebound(&device)
    } else {
        Ok(())
    };
    ops.release_sep_guard();
    let service_recovery = if services_changed {
        restore_services(ops, snapshot)
    } else {
        Ok(())
    };

    let operational_recovery = if services_changed && service_recovery.is_ok() {
        ops.wait_operational(&device)
    } else {
        Ok(())
    };

    if device_recovery.is_err() || service_recovery.is_err() || operational_recovery.is_err() {
        return Err(Error::RecoveryFailed);
    }
    primary.map(|()| Report)
}

/// Removes and restores the validated T1 while one standard fingerprint
/// operation owns SEP, so libfprint's device-loss behavior can be observed.
///
/// # Errors
///
/// Returns a fixed, identifier-free category when the live-operation
/// precondition, removal, cancellation, reappearance, or recovery fails.
pub fn run_live_loss() -> Result<LiveLossReport, Error> {
    run_live_loss_with(&mut SystemCycleOps::new())
}

fn run_live_loss_with(ops: &mut impl CycleOps) -> Result<LiveLossReport, Error> {
    let device = ops.inspect_device()?;
    ops.acquire_cycle_guard()?;
    require_live_operation(ops)?;

    let mut needs_device_recovery = false;
    let mut sep_acquired = false;
    let primary = (|| {
        if ops.interrupted() {
            return Err(Error::Interrupted);
        }
        needs_device_recovery = true;
        ops.unbind_live(&device)?;
        ops.wait_removed(&device)?;
        if ops.interrupted() {
            return Err(Error::Interrupted);
        }
        ops.wait_for_sep_guard()?;
        sep_acquired = true;
        if ops.interrupted() {
            return Err(Error::Interrupted);
        }
        ops.bind(&device)?;
        ops.wait_reappeared(&device)?;
        needs_device_recovery = false;
        Ok(())
    })();

    if primary.is_err() && needs_device_recovery {
        let mut recovery_failed = force_stop_services(ops).is_err();
        if !sep_acquired {
            match ops.acquire_sep_guard() {
                Ok(()) => sep_acquired = true,
                Err(_) => recovery_failed = true,
            }
        }
        if sep_acquired && ops.ensure_rebound(&device).is_err() {
            recovery_failed = true;
        }
        if sep_acquired {
            ops.release_sep_guard();
        }
        recovery_failed |= start_steady_services(ops).is_err();
        recovery_failed |= ops.wait_operational(&device).is_err();
        if recovery_failed {
            return Err(Error::RecoveryFailed);
        }
        return primary.map(|()| LiveLossReport);
    }

    if sep_acquired {
        ops.release_sep_guard();
    }
    if primary.is_err()
        || start_steady_services(ops).is_err()
        || ops.wait_operational(&device).is_err()
    {
        return primary
            .map(|()| LiveLossReport)
            .and(Err(Error::RecoveryFailed));
    }
    Ok(LiveLossReport)
}

fn require_live_operation(ops: &mut impl CycleOps) -> Result<(), Error> {
    for service in Service::LIVE_OPERATION_REQUIRED {
        if !ops.service_active(service)? {
            return Err(Error::NoActiveOperation);
        }
    }
    if ops.service_active(Service::Keybag)? || !ops.active_sep_operation()? {
        return Err(Error::NoActiveOperation);
    }
    Ok(())
}

fn snapshot_services(ops: &mut impl CycleOps) -> Result<ServiceSnapshot, Error> {
    let mut states = [false; Service::COUNT];
    for service in Service::STOP_ORDER {
        states[service.index()] = ops.service_active(service)?;
    }
    Ok(ServiceSnapshot(states))
}

fn stop_services(ops: &mut impl CycleOps) -> Result<(), Error> {
    for service in Service::STOP_ORDER {
        ops.stop_service(service)?;
    }
    Ok(())
}

fn force_stop_services(ops: &mut impl CycleOps) -> Result<(), Error> {
    let mut failed = false;
    for service in Service::STOP_ORDER {
        failed |= ops.stop_service(service).is_err();
    }
    if failed {
        Err(Error::RecoveryFailed)
    } else {
        Ok(())
    }
}

fn start_steady_services(ops: &mut impl CycleOps) -> Result<(), Error> {
    let mut failed = ops.reset_failed(Service::Broker).is_err();
    for service in Service::STEADY_START_ORDER {
        let result = if service.restart_after_cycle() {
            ops.restart_service(service)
        } else {
            ops.start_service(service)
        };
        failed |= result.is_err();
    }
    if failed {
        Err(Error::RecoveryFailed)
    } else {
        Ok(())
    }
}

fn restore_services(ops: &mut impl CycleOps, snapshot: ServiceSnapshot) -> Result<(), Error> {
    let mut failed = false;
    for service in Service::STOP_ORDER {
        if !snapshot.active(service) {
            failed |= ops.stop_service(service).is_err();
        }
    }
    for service in Service::START_ORDER {
        if snapshot.active(service) {
            failed |= ops.start_service(service).is_err();
        }
    }
    if failed {
        Err(Error::RecoveryFailed)
    } else {
        Ok(())
    }
}

fn inspect_unique_device(root: &Path, phase: DevicePhase) -> Result<DeviceKey, Error> {
    let entries = fs::read_dir(root).map_err(|_| Error::HardwareUnavailable)?;
    let mut selected = None;
    for (index, entry) in entries.enumerate() {
        if index >= USB_ENTRY_LIMIT {
            return Err(Error::UnexpectedHardware);
        }
        let entry = entry.map_err(|_| Error::UnexpectedHardware)?;
        let path = entry.path();
        let Some(vendor) = read_optional_attribute(&path.join("idVendor"))? else {
            continue;
        };
        if vendor != "05ac" {
            continue;
        }
        let Some(product) = read_optional_attribute(&path.join("idProduct"))? else {
            return Err(Error::UnexpectedHardware);
        };
        if product != "8600" {
            continue;
        }
        if selected.is_some() {
            return Err(Error::UnexpectedHardware);
        }
        selected = Some(validate_device(&path, phase)?);
    }
    selected.ok_or(Error::HardwareUnavailable)
}

fn validate_device(path: &Path, phase: DevicePhase) -> Result<DeviceKey, Error> {
    let key = path
        .file_name()
        .and_then(OsStr::to_str)
        .filter(|name| valid_device_key(name))
        .ok_or(Error::UnexpectedHardware)?;
    if read_required_attribute(&path.join("bConfigurationValue"))? != "2" {
        return Err(Error::UnexpectedHardware);
    }
    if driver_name(path)? != "t1bridge-cfgselector" {
        return Err(Error::UnexpectedHardware);
    }

    let expected = [
        ("00", "0", Some("uvcvideo")),
        ("01", "0", Some("uvcvideo")),
        ("02", "0", Some("usbhid")),
        ("03", "0", Some("appletbdrm")),
        ("04", "0", Some("apple_t1_ncm")),
        ("05", "1", Some("apple_t1_ncm")),
        ("06", "0", Some("usbhid")),
        (
            "07",
            "0",
            match phase {
                DevicePhase::Operational => Some("usbfs"),
                DevicePhase::Quiesced => None,
            },
        ),
    ];
    let mut observed = [false; 8];
    let interface_prefix = format!("{key}:");
    let entries = fs::read_dir(path).map_err(|_| Error::UnexpectedHardware)?;
    for entry in entries {
        let entry = entry.map_err(|_| Error::UnexpectedHardware)?;
        let name = entry.file_name();
        let name = name.to_str().ok_or(Error::UnexpectedHardware)?;
        if !name.starts_with(&interface_prefix) {
            continue;
        }
        let entry_path = entry.path();
        let Some(interface) = read_optional_attribute(&entry_path.join("bInterfaceNumber"))? else {
            continue;
        };
        let position = expected
            .iter()
            .position(|(number, _, _)| *number == interface)
            .ok_or(Error::UnexpectedHardware)?;
        let observed_driver = optional_driver_name(&entry_path)?;
        if observed[position]
            || read_alternate_setting(&entry_path.join("bAlternateSetting"))?
                != expected[position].1
            || observed_driver.as_deref() != expected[position].2
        {
            return Err(Error::UnexpectedHardware);
        }
        observed[position] = true;
    }
    if observed.iter().any(|present| !present) {
        return Err(Error::UnexpectedHardware);
    }
    Ok(DeviceKey(key.to_owned()))
}

fn validate_rebind_target(root: &Path, expected: &DeviceKey) -> Result<(), Error> {
    let entries = fs::read_dir(root).map_err(|_| Error::RecoveryFailed)?;
    let mut matched = None;
    for (index, entry) in entries.enumerate() {
        if index >= USB_ENTRY_LIMIT {
            return Err(Error::RecoveryFailed);
        }
        let entry = entry.map_err(|_| Error::RecoveryFailed)?;
        let path = entry.path();
        let vendor =
            read_optional_attribute(&path.join("idVendor")).map_err(|_| Error::RecoveryFailed)?;
        if vendor.as_deref() != Some("05ac") {
            continue;
        }
        match read_optional_attribute(&path.join("idProduct"))
            .map_err(|_| Error::RecoveryFailed)?
            .as_deref()
        {
            Some("8600") => {}
            Some(_) => continue,
            None => return Err(Error::RecoveryFailed),
        }
        if matched.is_some() {
            return Err(Error::RecoveryFailed);
        }
        let key = path
            .file_name()
            .and_then(OsStr::to_str)
            .filter(|name| valid_device_key(name))
            .ok_or(Error::RecoveryFailed)?;
        matched = Some(DeviceKey(key.to_owned()));
    }
    if matched.as_ref() != Some(expected) {
        return Err(Error::RecoveryFailed);
    }
    let path = root.join(&expected.0);
    match fs::symlink_metadata(path.join("driver")) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) | Err(_) => Err(Error::RecoveryFailed),
    }
}

fn valid_device_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= ATTRIBUTE_LIMIT
        && key
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'-' | b'.'))
}

fn driver_name(path: &Path) -> Result<String, Error> {
    optional_driver_name(path)?.ok_or(Error::UnexpectedHardware)
}

fn optional_driver_name(path: &Path) -> Result<Option<String>, Error> {
    let target = match fs::read_link(path.join("driver")) {
        Ok(target) => target,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(Error::UnexpectedHardware),
    };
    target
        .file_name()
        .and_then(OsStr::to_str)
        .filter(|name| !name.is_empty() && !name.contains(char::is_whitespace))
        .map(str::to_owned)
        .map(Some)
        .ok_or(Error::UnexpectedHardware)
}

fn read_required_attribute(path: &Path) -> Result<String, Error> {
    read_optional_attribute(path)?.ok_or(Error::UnexpectedHardware)
}

fn read_alternate_setting(path: &Path) -> Result<String, Error> {
    let value = read_optional_raw_attribute(path)?.ok_or(Error::UnexpectedHardware)?;
    match value.as_str() {
        " 0" => Ok("0".to_owned()),
        " 1" => Ok("1".to_owned()),
        _ => Err(Error::UnexpectedHardware),
    }
}

fn read_optional_attribute(path: &Path) -> Result<Option<String>, Error> {
    let Some(value) = read_optional_raw_attribute(path)? else {
        return Ok(None);
    };
    if value.is_empty() || value.contains(char::is_whitespace) {
        return Err(Error::UnexpectedHardware);
    }
    Ok(Some(value))
}

fn read_optional_raw_attribute(path: &Path) -> Result<Option<String>, Error> {
    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(Error::UnexpectedHardware),
    };
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(ATTRIBUTE_READ_LIMIT)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::UnexpectedHardware)?;
    if bytes.len() > ATTRIBUTE_LIMIT {
        return Err(Error::UnexpectedHardware);
    }
    let value = std::str::from_utf8(&bytes).map_err(|_| Error::UnexpectedHardware)?;
    let value = value.strip_suffix('\n').unwrap_or(value);
    Ok(Some(value.to_owned()))
}

fn device_is_unconfigured(root: &Path, device: &DeviceKey) -> Result<bool, Error> {
    let path = root.join(&device.0);
    match fs::symlink_metadata(path.join("driver")) {
        Ok(_) => return Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(_) => return Err(Error::UnbindFailed),
    }
    let interface_prefix = format!("{}:", device.0);
    for entry in fs::read_dir(path).map_err(|_| Error::UnbindFailed)? {
        let entry = entry.map_err(|_| Error::UnbindFailed)?;
        let name = entry.file_name();
        let name = name.to_str().ok_or(Error::UnbindFailed)?;
        if name.starts_with(&interface_prefix) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn write_driver_control(operation: &str, device: &DeviceKey) -> io::Result<()> {
    let path = Path::new(CFGSELECTOR_DRIVER).join(operation);
    let mut control = fs::OpenOptions::new().write(true).open(path)?;
    control.write_all(device.0.as_bytes())?;
    control.flush()
}

fn wait_until(
    timeout: Duration,
    mut condition: impl FnMut() -> Result<bool, Error>,
) -> Result<(), Error> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(Error::UnexpectedHardware)?;
    loop {
        match condition() {
            Ok(true) => return Ok(()),
            Ok(false) | Err(Error::HardwareUnavailable | Error::UnexpectedHardware)
                if Instant::now() < deadline =>
            {
                thread::sleep(WAIT_SLICE);
            }
            Ok(false) => return Err(Error::ReappearanceTimeout),
            Err(error) => return Err(error),
        }
    }
}

fn systemctl_is_active(service: Service) -> Result<bool, Error> {
    let status = run_systemctl(["is-active", "--quiet", service.unit()])?;
    match status.code() {
        Some(0) => Ok(true),
        Some(3 | 4) => Ok(false),
        _ => Err(Error::ServiceControl),
    }
}

fn systemctl_change(action: &str, service: Service, active: bool) -> Result<(), Error> {
    let _status = run_systemctl([action, service.unit()])?;
    wait_for_service_state(service, active)
}

fn systemctl_reset_failed(service: Service) -> Result<(), Error> {
    let status = run_systemctl(["reset-failed", service.unit()])?;
    if status.success() {
        Ok(())
    } else {
        Err(Error::ServiceControl)
    }
}

fn wait_for_service_state(service: Service, active: bool) -> Result<(), Error> {
    let deadline = Instant::now()
        .checked_add(SERVICE_TIMEOUT)
        .ok_or(Error::ServiceControl)?;
    loop {
        if systemctl_is_active(service)? == active {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(Error::ServiceControl);
        }
        thread::sleep(WAIT_SLICE);
    }
}

fn run_systemctl<const N: usize>(arguments: [&str; N]) -> Result<ExitStatus, Error> {
    let deadline = Instant::now()
        .checked_add(SERVICE_TIMEOUT)
        .ok_or(Error::ServiceControl)?;
    let mut child = Command::new(SYSTEMCTL)
        .args(arguments)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| Error::ServiceControl)?;
    wait_for_child(&mut child, deadline)
}

fn wait_for_child(child: &mut Child, deadline: Instant) -> Result<ExitStatus, Error> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(WAIT_SLICE),
            Ok(None) | Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Error::ServiceControl);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    struct FakeOps {
        events: Vec<String>,
        services: [bool; Service::COUNT],
        active_operation: bool,
        failure: Option<&'static str>,
        interrupted_at: Option<&'static str>,
        rebound: bool,
    }

    impl FakeOps {
        fn healthy() -> Self {
            Self {
                events: Vec::new(),
                services: [true; Service::COUNT],
                active_operation: true,
                failure: None,
                interrupted_at: None,
                rebound: false,
            }
        }

        fn event(&mut self, event: &str) -> Result<(), Error> {
            self.events.push(event.to_owned());
            match self.failure {
                Some(failure) if failure == event => Err(match event {
                    "unbind" => Error::UnbindFailed,
                    "bind" => Error::RebindFailed,
                    "wait-reappeared" => Error::ReappearanceTimeout,
                    "wait-sep-release" => Error::CancellationTimeout,
                    "ensure-rebound" => Error::RecoveryFailed,
                    _ => Error::ServiceControl,
                }),
                _ => Ok(()),
            }
        }
    }

    impl CycleOps for FakeOps {
        fn inspect_device(&mut self) -> Result<DeviceKey, Error> {
            self.event("inspect")?;
            Ok(DeviceKey("synthetic-1".to_owned()))
        }

        fn service_active(&mut self, service: Service) -> Result<bool, Error> {
            Ok(self.services[service.index()])
        }

        fn stop_service(&mut self, service: Service) -> Result<(), Error> {
            self.event(&format!("stop:{}", service.unit()))?;
            self.services[service.index()] = false;
            Ok(())
        }

        fn start_service(&mut self, service: Service) -> Result<(), Error> {
            self.event(&format!("start:{}", service.unit()))?;
            self.services[service.index()] = true;
            Ok(())
        }

        fn restart_service(&mut self, service: Service) -> Result<(), Error> {
            self.event(&format!("restart:{}", service.unit()))?;
            self.services[service.index()] = true;
            Ok(())
        }

        fn reset_failed(&mut self, service: Service) -> Result<(), Error> {
            self.event(&format!("reset-failed:{}", service.unit()))
        }

        fn acquire_cycle_guard(&mut self) -> Result<(), Error> {
            self.event("cycle-lock")
        }

        fn acquire_sep_guard(&mut self) -> Result<(), Error> {
            self.event("sep-lock")
        }

        fn active_sep_operation(&mut self) -> Result<bool, Error> {
            self.event("active-operation")?;
            Ok(self.active_operation)
        }

        fn wait_for_sep_guard(&mut self) -> Result<(), Error> {
            self.event("wait-sep-release")
        }

        fn release_sep_guard(&mut self) {
            self.events.push("sep-unlock".to_owned());
        }

        fn interrupted(&self) -> bool {
            self.interrupted_at
                .is_some_and(|event| self.events.last().is_some_and(|last| last == event))
        }

        fn unbind(&mut self, _: &DeviceKey) -> Result<(), Error> {
            self.event("unbind")
        }

        fn unbind_live(&mut self, _: &DeviceKey) -> Result<(), Error> {
            self.event("unbind-live")
        }

        fn wait_removed(&mut self, _: &DeviceKey) -> Result<(), Error> {
            self.event("wait-removed")
        }

        fn bind(&mut self, _: &DeviceKey) -> Result<(), Error> {
            self.event("bind")
        }

        fn wait_reappeared(&mut self, _: &DeviceKey) -> Result<(), Error> {
            self.event("wait-reappeared")
        }

        fn ensure_rebound(&mut self, _: &DeviceKey) -> Result<(), Error> {
            self.event("ensure-rebound")?;
            self.rebound = true;
            Ok(())
        }

        fn wait_operational(&mut self, _: &DeviceKey) -> Result<(), Error> {
            self.event("wait-operational")
        }
    }

    fn temporary_directory() -> PathBuf {
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "t1bridge-usb-cycle-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    fn synthetic_device(root: &Path, name: &str) -> PathBuf {
        let device = root.join(name);
        fs::create_dir(&device).unwrap();
        fs::write(device.join("idVendor"), "05ac\n").unwrap();
        fs::write(device.join("idProduct"), "8600\n").unwrap();
        fs::write(device.join("bConfigurationValue"), "2\n").unwrap();
        let drivers = root.join("drivers");
        fs::create_dir_all(&drivers).unwrap();
        let selector = drivers.join("t1bridge-cfgselector");
        fs::create_dir_all(&selector).unwrap();
        symlink(&selector, device.join("driver")).unwrap();
        for (number, alternate, driver) in [
            ("00", " 0", "uvcvideo"),
            ("01", " 0", "uvcvideo"),
            ("02", " 0", "usbhid"),
            ("03", " 0", "appletbdrm"),
            ("04", " 0", "apple_t1_ncm"),
            ("05", " 1", "apple_t1_ncm"),
            ("06", " 0", "usbhid"),
            ("07", " 0", "usbfs"),
        ] {
            let interface = device.join(format!("{name}:2.{number}"));
            fs::create_dir(&interface).unwrap();
            fs::write(interface.join("bInterfaceNumber"), format!("{number}\n")).unwrap();
            fs::write(
                interface.join("bAlternateSetting"),
                format!("{alternate}\n"),
            )
            .unwrap();
            let driver_path = drivers.join(driver);
            fs::create_dir_all(&driver_path).unwrap();
            symlink(driver_path, interface.join("driver")).unwrap();
        }
        device
    }

    #[test]
    fn successful_cycle_orders_exclusion_mutation_and_restoration() {
        let mut ops = FakeOps::healthy();
        assert_eq!(run_with(&mut ops), Ok(Report));
        let unbind = ops
            .events
            .iter()
            .position(|event| event == "unbind")
            .unwrap();
        let sep_lock = ops
            .events
            .iter()
            .position(|event| event == "sep-lock")
            .unwrap();
        let sep_unlock = ops
            .events
            .iter()
            .position(|event| event == "sep-unlock")
            .unwrap();
        let first_start = ops
            .events
            .iter()
            .position(|event| event.starts_with("start:"))
            .unwrap();
        assert!(sep_lock < unbind);
        assert!(unbind < sep_unlock);
        assert!(sep_unlock < first_start);
        assert_eq!(
            ops.events.last().map(String::as_str),
            Some("wait-operational")
        );
        assert!(ops.services.into_iter().all(|active| active));
    }

    #[test]
    fn removal_requires_the_selector_and_every_interface_to_be_gone() {
        let root = temporary_directory();
        let name = "999-999.999";
        let device_path = synthetic_device(&root, name);
        let device = DeviceKey(name.to_owned());

        assert_eq!(device_is_unconfigured(&root, &device), Ok(false));
        fs::remove_file(device_path.join("driver")).unwrap();
        assert_eq!(device_is_unconfigured(&root, &device), Ok(false));

        let interface_prefix = format!("{name}:");
        let interfaces = fs::read_dir(&device_path)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .and_then(OsStr::to_str)
                    .is_some_and(|name| name.starts_with(&interface_prefix))
            })
            .collect::<Vec<_>>();
        for interface in interfaces {
            fs::remove_dir_all(interface).unwrap();
        }
        assert_eq!(device_is_unconfigured(&root, &device), Ok(true));

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn interruption_after_removal_rebinds_before_restoring_services() {
        let mut ops = FakeOps::healthy();
        ops.interrupted_at = Some("wait-removed");
        assert_eq!(run_with(&mut ops), Err(Error::Interrupted));
        let recovery = ops
            .events
            .iter()
            .position(|event| event == "ensure-rebound")
            .unwrap();
        let sep_unlock = ops
            .events
            .iter()
            .position(|event| event == "sep-unlock")
            .unwrap();
        assert!(recovery < sep_unlock);
        assert!(ops.rebound);
        assert!(ops.services.into_iter().all(|active| active));
    }

    #[test]
    fn primary_cycle_failure_is_retained_after_successful_recovery() {
        for (failure, expected) in [
            ("unbind", Error::UnbindFailed),
            ("bind", Error::RebindFailed),
            ("wait-reappeared", Error::ReappearanceTimeout),
        ] {
            let mut ops = FakeOps::healthy();
            ops.failure = Some(failure);
            assert_eq!(run_with(&mut ops), Err(expected));
            assert!(ops.rebound);
            assert!(ops.services.into_iter().all(|active| active));
        }
    }

    #[test]
    fn uncertain_device_recovery_overrides_the_primary_error() {
        let mut ops = FakeOps::healthy();
        ops.failure = Some("ensure-rebound");
        ops.interrupted_at = Some("wait-removed");
        assert_eq!(run_with(&mut ops), Err(Error::RecoveryFailed));
    }

    #[test]
    fn partial_service_failure_restores_every_prior_active_unit() {
        let mut ops = FakeOps::healthy();
        ops.failure = Some("stop:t1-touchid-auth.service");
        assert_eq!(run_with(&mut ops), Err(Error::ServiceControl));
        assert!(!ops.events.iter().any(|event| event == "unbind"));
        assert!(ops.services.into_iter().all(|active| active));
    }

    #[test]
    fn restoration_failure_is_a_hard_recovery_failure() {
        let mut ops = FakeOps::healthy();
        ops.failure = Some("start:fprintd.service");
        assert_eq!(run_with(&mut ops), Err(Error::RecoveryFailed));
    }

    #[test]
    fn inactive_services_remain_inactive_after_a_successful_cycle() {
        let mut ops = FakeOps::healthy();
        ops.services[Service::Fprintd.index()] = false;
        ops.services[Service::Touchbar.index()] = false;
        let expected = ops.services;
        assert_eq!(run_with(&mut ops), Ok(Report));
        assert_eq!(ops.services, expected);
    }

    fn live_operation() -> FakeOps {
        let mut ops = FakeOps::healthy();
        ops.services[Service::Keybag.index()] = false;
        ops
    }

    fn steady_services_are_active(ops: &FakeOps) -> bool {
        Service::STEADY_START_ORDER
            .into_iter()
            .all(|service| ops.services[service.index()])
    }

    #[test]
    fn live_loss_waits_for_operation_release_before_rebind() {
        let mut ops = live_operation();
        assert_eq!(run_live_loss_with(&mut ops), Ok(LiveLossReport));
        let unbind = ops
            .events
            .iter()
            .position(|event| event == "unbind-live")
            .unwrap();
        let released = ops
            .events
            .iter()
            .position(|event| event == "wait-sep-release")
            .unwrap();
        let bind = ops.events.iter().position(|event| event == "bind").unwrap();
        let sep_unlock = ops
            .events
            .iter()
            .position(|event| event == "sep-unlock")
            .unwrap();
        let first_start = ops
            .events
            .iter()
            .position(|event| event.starts_with("restart:"))
            .unwrap();
        assert!(unbind < released);
        assert!(released < bind);
        assert!(bind < sep_unlock);
        assert!(sep_unlock < first_start);
        assert!(!ops.events.iter().any(|event| event.starts_with("stop:")));
        assert_eq!(
            ops.events
                .iter()
                .filter(|event| event.starts_with("restart:"))
                .map(String::as_str)
                .collect::<Vec<_>>(),
            vec![
                "restart:t1-ncm-ready@*.service",
                "restart:t1-xart-storage@*.service",
                "restart:t1bridge-keybag.service",
            ]
        );
        assert!(steady_services_are_active(&ops));
    }

    #[test]
    fn live_loss_requires_exact_active_operation_evidence() {
        let mut no_operation = live_operation();
        no_operation.active_operation = false;
        assert_eq!(
            run_live_loss_with(&mut no_operation),
            Err(Error::NoActiveOperation)
        );
        assert!(
            !no_operation
                .events
                .iter()
                .any(|event| event == "unbind-live")
        );

        let mut relay_still_active = FakeOps::healthy();
        assert_eq!(
            run_live_loss_with(&mut relay_still_active),
            Err(Error::NoActiveOperation)
        );
        assert!(
            !relay_still_active
                .events
                .iter()
                .any(|event| event == "active-operation")
        );
    }

    #[test]
    fn cancellation_timeout_recovers_before_returning_the_primary_error() {
        let mut ops = live_operation();
        ops.failure = Some("wait-sep-release");
        assert_eq!(
            run_live_loss_with(&mut ops),
            Err(Error::CancellationTimeout)
        );
        assert!(ops.rebound);
        assert!(steady_services_are_active(&ops));
        assert!(!ops.services[Service::Broker.index()]);
        assert!(
            ops.events
                .iter()
                .any(|event| event == "reset-failed:t1-touchid-auth.service")
        );
    }

    #[test]
    fn steady_service_restart_failure_is_a_hard_recovery_failure() {
        let mut ops = live_operation();
        ops.failure = Some("restart:t1-xart-storage@*.service");

        assert_eq!(run_live_loss_with(&mut ops), Err(Error::RecoveryFailed));
        assert!(ops.events.iter().any(|event| event == "bind"));
        assert!(
            ops.events
                .iter()
                .any(|event| event == "restart:t1bridge-keybag.service")
        );
    }

    #[test]
    fn interrupted_live_loss_recovers_under_sep_exclusion() {
        let mut ops = live_operation();
        ops.interrupted_at = Some("wait-removed");
        assert_eq!(run_live_loss_with(&mut ops), Err(Error::Interrupted));
        let stop = ops
            .events
            .iter()
            .position(|event| event.starts_with("stop:"))
            .unwrap();
        let sep_lock = ops
            .events
            .iter()
            .position(|event| event == "sep-lock")
            .unwrap();
        let recovery = ops
            .events
            .iter()
            .position(|event| event == "ensure-rebound")
            .unwrap();
        assert!(stop < sep_lock);
        assert!(sep_lock < recovery);
        assert!(ops.rebound);
        assert!(steady_services_are_active(&ops));
    }

    #[test]
    fn uncertain_live_loss_recovery_is_a_hard_failure() {
        let mut ops = live_operation();
        ops.interrupted_at = Some("wait-removed");
        ops.failure = Some("ensure-rebound");
        assert_eq!(run_live_loss_with(&mut ops), Err(Error::RecoveryFailed));
    }

    #[test]
    fn validates_exact_configuration_driver_map_and_unique_device() {
        let root = temporary_directory();
        let device = synthetic_device(&root, "999-999.999");
        let key = DeviceKey("999-999.999".to_owned());
        assert_eq!(
            validate_device(&device, DevicePhase::Operational),
            Ok(key.clone())
        );
        assert!(inspect_unique_device(&root, DevicePhase::Operational).is_ok());

        let sep_driver = device.join("999-999.999:2.07/driver");
        fs::remove_file(&sep_driver).unwrap();
        assert_eq!(
            validate_device(&device, DevicePhase::Quiesced),
            Ok(key.clone())
        );
        assert_eq!(
            validate_device(&device, DevicePhase::Operational),
            Err(Error::UnexpectedHardware)
        );
        symlink(root.join("drivers/usbfs"), sep_driver).unwrap();

        fs::write(device.join("bConfigurationValue"), "1\n").unwrap();
        assert_eq!(
            inspect_unique_device(&root, DevicePhase::Operational),
            Err(Error::UnexpectedHardware)
        );
        fs::write(device.join("bConfigurationValue"), "2\n").unwrap();
        fs::write(device.join("999-999.999:2.03/bInterfaceNumber"), "04\n").unwrap();
        assert_eq!(
            inspect_unique_device(&root, DevicePhase::Operational),
            Err(Error::UnexpectedHardware)
        );
        fs::write(device.join("999-999.999:2.03/bInterfaceNumber"), "03\n").unwrap();

        fs::remove_file(device.join("driver")).unwrap();
        assert_eq!(validate_rebind_target(&root, &key), Ok(()));
        symlink(
            root.join("drivers/t1bridge-cfgselector"),
            device.join("driver"),
        )
        .unwrap();
        let _duplicate = synthetic_device(&root, "998-998.998");
        assert_eq!(
            inspect_unique_device(&root, DevicePhase::Operational),
            Err(Error::UnexpectedHardware)
        );
        fs::remove_file(root.join("998-998.998/idProduct")).unwrap();
        assert_eq!(
            validate_rebind_target(&root, &key),
            Err(Error::RecoveryFailed)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn device_keys_and_errors_are_identifier_free() {
        assert_eq!(
            format!("{:?}", DeviceKey("synthetic-secret".to_owned())),
            "DeviceKey(REDACTED)"
        );
        for error in [
            Error::HardwareUnavailable,
            Error::UnexpectedHardware,
            Error::Busy,
            Error::NoActiveOperation,
            Error::CancellationTimeout,
            Error::ServiceControl,
            Error::UnbindFailed,
            Error::RebindFailed,
            Error::ReappearanceTimeout,
            Error::Interrupted,
            Error::RecoveryFailed,
        ] {
            assert!(!error.to_string().contains("synthetic"));
        }
    }

    #[test]
    #[ignore = "requires one live supported T1 in the selected configuration"]
    fn live_preflight_accepts_the_exact_hardware_contract() {
        assert!(inspect_unique_device(Path::new(USB_DEVICES), DevicePhase::Operational).is_ok());
    }
}

//! Narrow access to dynamically discovered Linux brightness classes.

use std::error::Error;
use std::fmt;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

const DISPLAY_CLASS: &str = "/sys/class/backlight";
const LED_CLASS: &str = "/sys/class/leds";
const KEYBOARD_BACKLIGHT_FUNCTION: &str = "kbd_backlight";
const MAX_ATTRIBUTE_LENGTH: u64 = 20;
const BRIGHTNESS_STEPS: u32 = 16;

/// A fixed brightness-control category exposed to the typed renderer IPC.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrightnessKind {
    Display,
    Keyboard,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrightnessStep {
    Down,
    Up,
}

/// Redaction-safe discovery or I/O failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrightnessError {
    Unavailable,
    Ambiguous,
    InvalidAttribute,
    Io,
}

impl fmt::Display for BrightnessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unavailable => "brightness control is unavailable",
            Self::Ambiguous => "brightness control discovery is ambiguous",
            Self::InvalidAttribute => "brightness control attribute is invalid",
            Self::Io => "brightness control I/O failed",
        })
    }
}

impl Error for BrightnessError {}

struct BrightnessDevice {
    name: String,
    maximum: u32,
    brightness_path: PathBuf,
}

impl BrightnessDevice {
    fn open(path: &Path, name: String) -> Result<Self, BrightnessError> {
        let maximum = read_maximum(&path.join("max_brightness"))?;
        let brightness_path = path.join("brightness");
        let attribute = File::open(&brightness_path).map_err(|_| BrightnessError::Io)?;
        if !attribute
            .metadata()
            .map_err(|_| BrightnessError::Io)?
            .file_type()
            .is_file()
        {
            return Err(BrightnessError::InvalidAttribute);
        }
        Ok(Self {
            name,
            maximum,
            brightness_path,
        })
    }
}

/// One bounded value ready for delivery through logind's admitted-session API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BrightnessSetting<'device> {
    pub kind: BrightnessKind,
    pub device_name: &'device str,
    pub value: u32,
}

/// The independently optional display and keyboard-backlight controls.
pub struct SystemBrightnessControls {
    display: Option<BrightnessDevice>,
    keyboard: Option<BrightnessDevice>,
}

impl fmt::Debug for SystemBrightnessControls {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SystemBrightnessControls")
            .field("display", &self.display.is_some())
            .field("keyboard", &self.keyboard.is_some())
            .finish()
    }
}

impl SystemBrightnessControls {
    /// Discovers each class independently. A missing or ambiguous class remains
    /// unavailable without preventing the other class or Touch Bar service.
    #[must_use]
    pub fn discover() -> Self {
        Self::discover_in(Path::new(DISPLAY_CLASS), Path::new(LED_CLASS))
    }

    fn discover_in(display_root: &Path, led_root: &Path) -> Self {
        Self {
            display: discover_unique(display_root, |_| true).ok(),
            keyboard: discover_unique(led_root, is_keyboard_backlight).ok(),
        }
    }

    #[must_use]
    pub const fn available(&self, kind: BrightnessKind) -> bool {
        match kind {
            BrightnessKind::Display => self.display.is_some(),
            BrightnessKind::Keyboard => self.keyboard.is_some(),
        }
    }

    /// Scales an absolute percentage for one already-discovered fixed class.
    ///
    /// # Errors
    ///
    /// Returns a static category when the class or percentage is invalid.
    pub fn setting(
        &self,
        kind: BrightnessKind,
        percentage: u8,
    ) -> Result<BrightnessSetting<'_>, BrightnessError> {
        if percentage > 100 {
            return Err(BrightnessError::InvalidAttribute);
        }
        let device = match kind {
            BrightnessKind::Display => self.display.as_ref(),
            BrightnessKind::Keyboard => self.keyboard.as_ref(),
        }
        .ok_or(BrightnessError::Unavailable)?;
        let value = (u64::from(device.maximum) * u64::from(percentage) + 50) / 100;
        Ok(BrightnessSetting {
            kind,
            device_name: &device.name,
            value: u32::try_from(value).map_err(|_| BrightnessError::InvalidAttribute)?,
        })
    }

    /// Reads the current hardware value and moves it by one of sixteen bounded
    /// steps. The privileged service owns this read so renderers need no sysfs
    /// access and cannot race a stale cached level into an absolute write.
    ///
    /// # Errors
    ///
    /// Returns a static category when the class or current value is invalid.
    pub fn step_setting(
        &self,
        kind: BrightnessKind,
        direction: BrightnessStep,
    ) -> Result<BrightnessSetting<'_>, BrightnessError> {
        let device = self.device(kind)?;
        let current = read_attribute(&device.brightness_path)?;
        if current > device.maximum {
            return Err(BrightnessError::InvalidAttribute);
        }
        let step = device.maximum.div_ceil(BRIGHTNESS_STEPS).max(1);
        let value = match direction {
            BrightnessStep::Down => current.saturating_sub(step),
            BrightnessStep::Up => current.saturating_add(step).min(device.maximum),
        };
        Ok(BrightnessSetting {
            kind,
            device_name: &device.name,
            value,
        })
    }

    /// Stops advertising one class after logind rejects its admitted-session write.
    pub fn disable(&mut self, kind: BrightnessKind) {
        match kind {
            BrightnessKind::Display => self.display = None,
            BrightnessKind::Keyboard => self.keyboard = None,
        }
    }

    fn device(&self, kind: BrightnessKind) -> Result<&BrightnessDevice, BrightnessError> {
        match kind {
            BrightnessKind::Display => self.display.as_ref(),
            BrightnessKind::Keyboard => self.keyboard.as_ref(),
        }
        .ok_or(BrightnessError::Unavailable)
    }
}

fn discover_unique(
    root: &Path,
    accepts: impl Fn(&str) -> bool,
) -> Result<BrightnessDevice, BrightnessError> {
    let entries = fs::read_dir(root).map_err(|_| BrightnessError::Unavailable)?;
    let mut candidate: Option<(PathBuf, String)> = None;
    for entry in entries {
        let entry = entry.map_err(|_| BrightnessError::Io)?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if name.starts_with('.') || !accepts(&name) {
            continue;
        }
        if candidate.replace((entry.path(), name)).is_some() {
            return Err(BrightnessError::Ambiguous);
        }
    }
    let (path, name) = candidate.ok_or(BrightnessError::Unavailable)?;
    BrightnessDevice::open(&path, name)
}

fn is_keyboard_backlight(name: &str) -> bool {
    name == KEYBOARD_BACKLIGHT_FUNCTION
        || name
            .rsplit_once(':')
            .is_some_and(|(_, function)| function == KEYBOARD_BACKLIGHT_FUNCTION)
}

fn read_maximum(path: &Path) -> Result<u32, BrightnessError> {
    let maximum = read_attribute(path)?;
    if maximum == 0 {
        Err(BrightnessError::InvalidAttribute)
    } else {
        Ok(maximum)
    }
}

fn read_attribute(path: &Path) -> Result<u32, BrightnessError> {
    let file = File::open(path).map_err(|_| BrightnessError::Io)?;
    let mut value = String::new();
    file.take(MAX_ATTRIBUTE_LENGTH + 1)
        .read_to_string(&mut value)
        .map_err(|_| BrightnessError::Io)?;
    if value.len() as u64 > MAX_ATTRIBUTE_LENGTH {
        return Err(BrightnessError::InvalidAttribute);
    }
    value
        .trim()
        .parse::<u32>()
        .map_err(|_| BrightnessError::InvalidAttribute)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(1);

    struct TestTree(PathBuf);

    impl TestTree {
        fn new() -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "t1bridge-brightness-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn class(&self, name: &str) -> PathBuf {
            let path = self.0.join(name);
            fs::create_dir(&path).unwrap();
            path
        }
    }

    impl Drop for TestTree {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn add_device(root: &Path, name: &str, maximum: &str) -> PathBuf {
        let device = root.join(name);
        fs::create_dir(&device).unwrap();
        fs::write(device.join("max_brightness"), maximum).unwrap();
        fs::write(device.join("brightness"), "0").unwrap();
        device
    }

    #[test]
    fn discovers_classes_independently_and_scales_absolute_percentages() {
        let tree = TestTree::new();
        let displays = tree.class("backlight");
        let leds = tree.class("leds");
        add_device(&displays, "display-device", "1023\n");
        add_device(&leds, "controller:white:kbd_backlight", "255\n");
        let _unrelated = add_device(&leds, "controller:white:capslock", "1\n");

        let controls = SystemBrightnessControls::discover_in(&displays, &leds);
        assert!(controls.available(BrightnessKind::Display));
        assert!(controls.available(BrightnessKind::Keyboard));

        assert_eq!(
            controls.setting(BrightnessKind::Display, 79).unwrap(),
            BrightnessSetting {
                kind: BrightnessKind::Display,
                device_name: "display-device",
                value: 808,
            }
        );
        assert_eq!(
            controls.setting(BrightnessKind::Keyboard, 50).unwrap(),
            BrightnessSetting {
                kind: BrightnessKind::Keyboard,
                device_name: "controller:white:kbd_backlight",
                value: 128,
            }
        );
    }

    #[test]
    fn absent_or_ambiguous_class_disables_only_that_control() {
        let tree = TestTree::new();
        let displays = tree.class("backlight");
        let leds = tree.class("leds");
        add_device(&displays, "first", "100\n");
        add_device(&displays, "second", "100\n");
        add_device(&leds, "controller:kbd_backlight", "10\n");

        let mut controls = SystemBrightnessControls::discover_in(&displays, &leds);
        assert!(!controls.available(BrightnessKind::Display));
        assert!(controls.available(BrightnessKind::Keyboard));
        assert_eq!(
            controls.setting(BrightnessKind::Display, 50),
            Err(BrightnessError::Unavailable)
        );
        assert!(controls.setting(BrightnessKind::Keyboard, 50).is_ok());
        controls.disable(BrightnessKind::Keyboard);
        assert!(!controls.available(BrightnessKind::Keyboard));
    }

    #[test]
    fn malformed_attributes_are_never_advertised() {
        let tree = TestTree::new();
        let displays = tree.class("backlight");
        let leds = tree.class("leds");
        add_device(&displays, "display", "0\n");
        add_device(&leds, "kbd_backlight", "not-a-number\n");

        let controls = SystemBrightnessControls::discover_in(&displays, &leds);
        assert!(!controls.available(BrightnessKind::Display));
        assert!(!controls.available(BrightnessKind::Keyboard));
    }

    #[test]
    fn relative_steps_read_the_live_value_and_clamp_at_both_ends() {
        let tree = TestTree::new();
        let displays = tree.class("backlight");
        let leds = tree.class("leds");
        let display = add_device(&displays, "display-device", "255\n");
        add_device(&leds, "kbd_backlight", "15\n");
        let controls = SystemBrightnessControls::discover_in(&displays, &leds);

        fs::write(display.join("brightness"), "100\n").unwrap();
        assert_eq!(
            controls
                .step_setting(BrightnessKind::Display, BrightnessStep::Down)
                .unwrap()
                .value,
            84
        );
        assert_eq!(
            controls
                .step_setting(BrightnessKind::Display, BrightnessStep::Up)
                .unwrap()
                .value,
            116
        );

        fs::write(display.join("brightness"), "4\n").unwrap();
        assert_eq!(
            controls
                .step_setting(BrightnessKind::Display, BrightnessStep::Down)
                .unwrap()
                .value,
            0
        );
        fs::write(display.join("brightness"), "250\n").unwrap();
        assert_eq!(
            controls
                .step_setting(BrightnessKind::Display, BrightnessStep::Up)
                .unwrap()
                .value,
            255
        );

        assert_eq!(
            controls
                .step_setting(BrightnessKind::Keyboard, BrightnessStep::Up)
                .unwrap()
                .value,
            1
        );
    }

    #[test]
    fn relative_steps_reject_malformed_or_out_of_range_live_values() {
        let tree = TestTree::new();
        let displays = tree.class("backlight");
        let leds = tree.class("leds");
        let display = add_device(&displays, "display-device", "100\n");
        let controls = SystemBrightnessControls::discover_in(&displays, &leds);

        fs::write(display.join("brightness"), "broken\n").unwrap();
        assert_eq!(
            controls.step_setting(BrightnessKind::Display, BrightnessStep::Up),
            Err(BrightnessError::InvalidAttribute)
        );
        fs::write(display.join("brightness"), "101\n").unwrap();
        assert_eq!(
            controls.step_setting(BrightnessKind::Display, BrightnessStep::Down),
            Err(BrightnessError::InvalidAttribute)
        );
    }
}

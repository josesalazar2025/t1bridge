//! Dependency-free Boot Camp-style default Touch Bar surface.

use std::{error::Error, fmt};

use crate::framebuffer::{FramebufferError, Rectangle, Rgb, Xrgb8888Frame};
use crate::gesture::{DisplayContact, Gesture};
use crate::stock_art::{self, Symbol};
use crate::stock_labels::{self, AlphaMask};

const NATIVE_WIDTH: u32 = 2_170;
const NATIVE_HEIGHT: u32 = 60;
const ACTIVE_RIGHT: u32 = NATIVE_WIDTH;
const FUNCTION_SLOT_COUNT: u32 = 13;
const PLATE_Y: u32 = 0;
const PLATE_HEIGHT: u32 = 60;
const PLATE_RADIUS: u32 = 8;

const BACKGROUND: Rgb = Rgb {
    red: 0,
    green: 0,
    blue: 0,
};
const PLATE: Rgb = Rgb {
    red: 53,
    green: 53,
    blue: 53,
};
const PRESSED_PLATE: Rgb = Rgb {
    red: 76,
    green: 76,
    blue: 76,
};
const LABEL: Rgb = Rgb {
    red: 242,
    green: 242,
    blue: 242,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FunctionKey {
    F1,
    F2,
    F3,
    F4,
    F5,
    F6,
    F7,
    F8,
    F9,
    F10,
    F11,
    F12,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StepDirection {
    Down,
    Up,
}

/// Independently available default-renderer controls.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StockCapabilities(u8);

impl StockCapabilities {
    pub const DISPLAY_BRIGHTNESS: Self = Self(1);
    pub const KEYBOARD_BACKLIGHT: Self = Self(2);
    pub const AUDIO: Self = Self(4);
    pub const MEDIA: Self = Self(8);

    #[must_use]
    pub const fn contains(self, capability: Self) -> bool {
        self.0 & capability.0 == capability.0
    }
}

impl std::ops::BitOr for StockCapabilities {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

/// Renderer-known desktop levels. The fixed Boot Camp face uses mute only;
/// the remaining values stay available to replacement renderers and providers.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StockLevels {
    pub display_brightness: Option<u8>,
    pub keyboard_backlight: Option<u8>,
    pub volume: Option<u8>,
    pub muted: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StockAction {
    Escape,
    Function(FunctionKey),
    StepDisplayBrightness(StepDirection),
    StepKeyboardBacklight(StepDirection),
    ToggleMute,
    StepVolume(StepDirection),
    MediaPrevious,
    MediaPlayPause,
    MediaNext,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StockSliceError {
    InvalidGeometry,
    FrameGeometryMismatch,
    Drawing(FramebufferError),
}

impl fmt::Display for StockSliceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidGeometry => "invalid stock bar geometry",
            Self::FrameGeometryMismatch => "stock bar frame geometry changed",
            Self::Drawing(_) => "stock bar drawing failed",
        })
    }
}

impl Error for StockSliceError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Drawing(error) => Some(error),
            Self::InvalidGeometry | Self::FrameGeometryMismatch => None,
        }
    }
}

impl From<FramebufferError> for StockSliceError {
    fn from(error: FramebufferError) -> Self {
        Self::Drawing(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Control {
    DisplayDown,
    DisplayUp,
    KeyboardDown,
    KeyboardUp,
    MediaPrevious,
    MediaPlayPause,
    MediaNext,
    Mute,
    VolumeDown,
    VolumeUp,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NativeControl {
    control: Control,
    x: u32,
    width: u32,
}

const NORMAL_CONTROLS: [NativeControl; 10] = [
    NativeControl {
        control: Control::DisplayDown,
        x: 194,
        width: 182,
    },
    NativeControl {
        control: Control::DisplayUp,
        x: 384,
        width: 182,
    },
    NativeControl {
        control: Control::KeyboardDown,
        x: 602,
        width: 182,
    },
    NativeControl {
        control: Control::KeyboardUp,
        x: 792,
        width: 182,
    },
    NativeControl {
        control: Control::MediaPrevious,
        x: 1_010,
        width: 182,
    },
    NativeControl {
        control: Control::MediaPlayPause,
        x: 1_200,
        width: 182,
    },
    NativeControl {
        control: Control::MediaNext,
        x: 1_390,
        width: 182,
    },
    NativeControl {
        control: Control::Mute,
        x: 1_608,
        width: 182,
    },
    NativeControl {
        control: Control::VolumeDown,
        x: 1_798,
        width: 182,
    },
    NativeControl {
        control: Control::VolumeUp,
        x: 1_988,
        width: 182,
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LaidOutControl {
    control: Control,
    bounds: Rectangle,
}

/// Pure fixed-geometry layout and hit testing for the maintained default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StockBar {
    width: u32,
    height: u32,
    capabilities: StockCapabilities,
}

impl StockBar {
    /// # Errors
    ///
    /// Rejects zero dimensions.
    pub const fn new(
        width: u32,
        height: u32,
        capabilities: StockCapabilities,
    ) -> Result<Self, StockSliceError> {
        if width == 0 || height == 0 {
            Err(StockSliceError::InvalidGeometry)
        } else {
            Ok(Self {
                width,
                height,
                capabilities,
            })
        }
    }

    #[must_use]
    pub const fn width(self) -> u32 {
        self.width
    }

    #[must_use]
    pub const fn height(self) -> u32 {
        self.height
    }

    #[must_use]
    pub(crate) fn escape_right(self) -> u32 {
        let bounds = self.escape_bounds();
        bounds.x.saturating_add(bounds.width)
    }

    /// # Errors
    ///
    /// Rejects a changed frame geometry or an internally invalid draw.
    pub fn render(
        self,
        frame: &mut Xrgb8888Frame<'_>,
        fn_held: bool,
        levels: StockLevels,
    ) -> Result<(), StockSliceError> {
        self.render_pressed(frame, fn_held, levels, None)
    }

    /// Draws the fixed surface with an optional actively pressed control.
    ///
    /// # Errors
    ///
    /// Rejects a changed frame geometry or an internally invalid draw.
    pub fn render_pressed(
        self,
        frame: &mut Xrgb8888Frame<'_>,
        fn_held: bool,
        levels: StockLevels,
        pressed: Option<StockAction>,
    ) -> Result<(), StockSliceError> {
        if frame.width() != self.width || frame.height() != self.height {
            return Err(StockSliceError::FrameGeometryMismatch);
        }
        frame.clear(BACKGROUND);
        if fn_held {
            self.render_function_row(frame, pressed)
        } else {
            self.render_normal_row(frame, levels, pressed)
        }
    }

    /// Maps a completed tap to one currently visible action.
    #[must_use]
    pub fn action_for_gesture(self, gesture: Gesture, fn_held: bool) -> Option<StockAction> {
        let Gesture::Tap(contact) = gesture else {
            return None;
        };
        self.action_at(contact, fn_held)
    }

    /// Maps an active display contact to the control beneath it.
    #[must_use]
    pub fn action_at(self, contact: DisplayContact, fn_held: bool) -> Option<StockAction> {
        if contact.x() >= f64::from(self.width) || contact.y() >= f64::from(self.height) {
            return None;
        }
        let x = display_coordinate(contact.x());
        let y = display_coordinate(contact.y());
        if fn_held {
            return self.function_hit_test(x, y);
        }
        if contains(self.escape_bounds(), x, y) {
            return Some(StockAction::Escape);
        }
        self.normal_controls()
            .into_iter()
            .find(|item| self.control_available(item.control) && contains(item.bounds, x, y))
            .map(|item| control_action(item.control))
    }

    fn render_normal_row(
        self,
        frame: &mut Xrgb8888Frame<'_>,
        _levels: StockLevels,
        pressed: Option<StockAction>,
    ) -> Result<(), StockSliceError> {
        self.draw_plate(frame, self.escape_bounds(), StockAction::Escape, pressed)?;
        stock_art::draw_label(frame, self.escape_bounds(), stock_labels::ESC, LABEL)?;
        for item in self.normal_controls() {
            if !self.control_visible(item.control) {
                continue;
            }
            let action = control_action(item.control);
            self.draw_plate(frame, item.bounds, action, pressed)?;
            let symbol = control_symbol(item.control);
            stock_art::draw_symbol(frame, item.bounds, symbol, LABEL)?;
        }
        Ok(())
    }

    fn render_function_row(
        self,
        frame: &mut Xrgb8888Frame<'_>,
        pressed: Option<StockAction>,
    ) -> Result<(), StockSliceError> {
        for slot in 0..FUNCTION_SLOT_COUNT {
            let bounds = self.function_slot(slot);
            if bounds.width == 0 {
                continue;
            }
            let action = function_action(slot).ok_or(StockSliceError::InvalidGeometry)?;
            self.draw_plate(frame, bounds, action, pressed)?;
            stock_art::draw_label(frame, bounds, function_label(action)?, LABEL)?;
        }
        Ok(())
    }

    fn draw_plate(
        self,
        frame: &mut Xrgb8888Frame<'_>,
        bounds: Rectangle,
        action: StockAction,
        pressed: Option<StockAction>,
    ) -> Result<(), StockSliceError> {
        stock_art::draw_rounded_plate(
            frame,
            bounds,
            self.scaled_y(PLATE_RADIUS).max(1),
            if pressed == Some(action) {
                PRESSED_PLATE
            } else {
                PLATE
            },
        )?;
        Ok(())
    }

    fn function_hit_test(self, x: u32, y: u32) -> Option<StockAction> {
        if x >= self.active_right() || y >= self.height {
            return None;
        }
        let slot = u32::try_from(
            u64::from(x) * u64::from(FUNCTION_SLOT_COUNT) / u64::from(self.active_right()),
        )
        .ok()?;
        let bounds = self.function_slot(slot);
        contains(bounds, x, y)
            .then(|| function_action(slot))
            .flatten()
    }

    fn escape_bounds(self) -> Rectangle {
        self.function_slot(0)
    }

    fn function_slot(self, slot: u32) -> Rectangle {
        let active_right = self.active_right();
        let left = ceiling_partition(slot, active_right, FUNCTION_SLOT_COUNT);
        let right = ceiling_partition(slot + 1, active_right, FUNCTION_SLOT_COUNT);
        let inset = self.scaled_x(5).min((right - left) / 2);
        let left_inset = if slot == 0 { 0 } else { inset };
        Rectangle {
            x: left + left_inset,
            y: self.scaled_y(PLATE_Y),
            width: (right - left).saturating_sub(left_inset + inset),
            height: self.scaled_y(PLATE_HEIGHT).max(1),
        }
    }

    fn normal_controls(self) -> Vec<LaidOutControl> {
        NORMAL_CONTROLS
            .into_iter()
            .map(|item| LaidOutControl {
                control: item.control,
                bounds: Rectangle {
                    x: self.scaled_x(item.x),
                    y: self.scaled_y(PLATE_Y),
                    width: self.scaled_x(item.width).max(1),
                    height: self.scaled_y(PLATE_HEIGHT).max(1),
                },
            })
            .collect()
    }

    const fn control_available(self, control: Control) -> bool {
        match control {
            Control::DisplayDown | Control::DisplayUp => self
                .capabilities
                .contains(StockCapabilities::DISPLAY_BRIGHTNESS),
            Control::KeyboardDown | Control::KeyboardUp => self
                .capabilities
                .contains(StockCapabilities::KEYBOARD_BACKLIGHT),
            Control::MediaPrevious | Control::MediaPlayPause | Control::MediaNext => {
                self.capabilities.contains(StockCapabilities::MEDIA)
            }
            Control::Mute | Control::VolumeDown | Control::VolumeUp => {
                self.capabilities.contains(StockCapabilities::AUDIO)
            }
        }
    }

    const fn control_visible(self, control: Control) -> bool {
        matches!(
            control,
            Control::MediaPrevious | Control::MediaPlayPause | Control::MediaNext
        ) || self.control_available(control)
    }

    fn active_right(self) -> u32 {
        scale(ACTIVE_RIGHT, self.width, NATIVE_WIDTH).max(1)
    }

    fn scaled_x(self, value: u32) -> u32 {
        scale(value, self.width, NATIVE_WIDTH)
    }

    fn scaled_y(self, value: u32) -> u32 {
        scale(value, self.height, NATIVE_HEIGHT)
    }
}

fn scale(value: u32, extent: u32, native_extent: u32) -> u32 {
    u32::try_from(
        (u64::from(value) * u64::from(extent) + u64::from(native_extent) / 2)
            / u64::from(native_extent),
    )
    .unwrap_or(extent)
}

fn ceiling_partition(index: u32, extent: u32, count: u32) -> u32 {
    let numerator = u64::from(index) * u64::from(extent);
    u32::try_from(numerator.div_ceil(u64::from(count))).unwrap_or(extent)
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn display_coordinate(value: f64) -> u32 {
    value as u32
}

fn contains(bounds: Rectangle, x: u32, y: u32) -> bool {
    x >= bounds.x
        && y >= bounds.y
        && x < bounds.x.saturating_add(bounds.width)
        && y < bounds.y.saturating_add(bounds.height)
}

const fn control_action(control: Control) -> StockAction {
    match control {
        Control::DisplayDown => StockAction::StepDisplayBrightness(StepDirection::Down),
        Control::DisplayUp => StockAction::StepDisplayBrightness(StepDirection::Up),
        Control::KeyboardDown => StockAction::StepKeyboardBacklight(StepDirection::Down),
        Control::KeyboardUp => StockAction::StepKeyboardBacklight(StepDirection::Up),
        Control::MediaPrevious => StockAction::MediaPrevious,
        Control::MediaPlayPause => StockAction::MediaPlayPause,
        Control::MediaNext => StockAction::MediaNext,
        Control::Mute => StockAction::ToggleMute,
        Control::VolumeDown => StockAction::StepVolume(StepDirection::Down),
        Control::VolumeUp => StockAction::StepVolume(StepDirection::Up),
    }
}

const fn control_symbol(control: Control) -> Symbol {
    match control {
        Control::DisplayDown => Symbol::DisplayDown,
        Control::DisplayUp => Symbol::DisplayUp,
        Control::KeyboardDown => Symbol::KeyboardDown,
        Control::KeyboardUp => Symbol::KeyboardUp,
        Control::MediaPrevious => Symbol::Previous,
        Control::MediaPlayPause => Symbol::PlayPause,
        Control::MediaNext => Symbol::Next,
        Control::Mute => Symbol::Mute,
        Control::VolumeDown => Symbol::VolumeDown,
        Control::VolumeUp => Symbol::VolumeUp,
    }
}

const fn function_action(slot: u32) -> Option<StockAction> {
    Some(match slot {
        0 => StockAction::Escape,
        1 => StockAction::Function(FunctionKey::F1),
        2 => StockAction::Function(FunctionKey::F2),
        3 => StockAction::Function(FunctionKey::F3),
        4 => StockAction::Function(FunctionKey::F4),
        5 => StockAction::Function(FunctionKey::F5),
        6 => StockAction::Function(FunctionKey::F6),
        7 => StockAction::Function(FunctionKey::F7),
        8 => StockAction::Function(FunctionKey::F8),
        9 => StockAction::Function(FunctionKey::F9),
        10 => StockAction::Function(FunctionKey::F10),
        11 => StockAction::Function(FunctionKey::F11),
        12 => StockAction::Function(FunctionKey::F12),
        _ => return None,
    })
}

fn function_label(action: StockAction) -> Result<AlphaMask, StockSliceError> {
    Ok(match action {
        StockAction::Escape => stock_labels::ESC,
        StockAction::Function(FunctionKey::F1) => stock_labels::F1,
        StockAction::Function(FunctionKey::F2) => stock_labels::F2,
        StockAction::Function(FunctionKey::F3) => stock_labels::F3,
        StockAction::Function(FunctionKey::F4) => stock_labels::F4,
        StockAction::Function(FunctionKey::F5) => stock_labels::F5,
        StockAction::Function(FunctionKey::F6) => stock_labels::F6,
        StockAction::Function(FunctionKey::F7) => stock_labels::F7,
        StockAction::Function(FunctionKey::F8) => stock_labels::F8,
        StockAction::Function(FunctionKey::F9) => stock_labels::F9,
        StockAction::Function(FunctionKey::F10) => stock_labels::F10,
        StockAction::Function(FunctionKey::F11) => stock_labels::F11,
        StockAction::Function(FunctionKey::F12) => stock_labels::F12,
        _ => return Err(StockSliceError::InvalidGeometry),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all() -> StockCapabilities {
        StockCapabilities::DISPLAY_BRIGHTNESS
            | StockCapabilities::KEYBOARD_BACKLIGHT
            | StockCapabilities::AUDIO
            | StockCapabilities::MEDIA
    }

    fn tap(x: f64, y: f64) -> Gesture {
        Gesture::Tap(DisplayContact::new(1, x, y).unwrap())
    }

    #[test]
    fn fn_row_is_escape_plus_twelve_uniform_slots_across_the_display() {
        let bar = StockBar::new(NATIVE_WIDTH, NATIVE_HEIGHT, all()).unwrap();
        let expected = [
            StockAction::Escape,
            StockAction::Function(FunctionKey::F1),
            StockAction::Function(FunctionKey::F2),
            StockAction::Function(FunctionKey::F3),
            StockAction::Function(FunctionKey::F4),
            StockAction::Function(FunctionKey::F5),
            StockAction::Function(FunctionKey::F6),
            StockAction::Function(FunctionKey::F7),
            StockAction::Function(FunctionKey::F8),
            StockAction::Function(FunctionKey::F9),
            StockAction::Function(FunctionKey::F10),
            StockAction::Function(FunctionKey::F11),
            StockAction::Function(FunctionKey::F12),
        ];
        for (slot, action) in expected.into_iter().enumerate() {
            let bounds = bar.function_slot(u32::try_from(slot).unwrap());
            assert_eq!(
                bar.action_for_gesture(tap(f64::from(bounds.x + bounds.width / 2), 30.0), true,),
                Some(action),
            );
        }
        assert_eq!(
            bar.action_for_gesture(tap(2_080.0, 30.0), true),
            Some(StockAction::Function(FunctionKey::F12))
        );
    }

    #[test]
    fn normal_row_uses_fixed_grouped_controls() {
        let bar = StockBar::new(NATIVE_WIDTH, NATIVE_HEIGHT, all()).unwrap();
        assert_eq!(bar.escape_bounds().x, 0);
        let items = bar.normal_controls();
        assert_eq!(items.len(), 10);
        assert_eq!(items[0].bounds.x, 194);
        assert_eq!(items[9].bounds.x + items[9].bounds.width, NATIVE_WIDTH);
        for item in items {
            let action = bar.action_at(
                DisplayContact::new(1, f64::from(item.bounds.x + item.bounds.width / 2), 30.0)
                    .unwrap(),
                false,
            );
            assert_eq!(action, Some(control_action(item.control)));
        }
    }

    #[test]
    fn media_capability_loss_keeps_fixed_chrome_but_disables_actions() {
        let full = StockBar::new(NATIVE_WIDTH, NATIVE_HEIGHT, all()).unwrap();
        let reduced = StockBar::new(
            NATIVE_WIDTH,
            NATIVE_HEIGHT,
            StockCapabilities::DISPLAY_BRIGHTNESS | StockCapabilities::KEYBOARD_BACKLIGHT,
        )
        .unwrap();
        assert_eq!(full.normal_controls(), reduced.normal_controls());
        assert!(reduced.control_visible(Control::MediaPrevious));
        assert!(!reduced.control_available(Control::MediaPrevious));
        let media = full.normal_controls()[4].bounds;
        let contact = DisplayContact::new(
            1,
            f64::from(media.x + media.width / 2),
            f64::from(media.y + media.height / 2),
        )
        .unwrap();
        assert_eq!(
            full.action_at(contact, false),
            Some(StockAction::MediaPrevious)
        );
        assert_eq!(reduced.action_at(contact, false), None);
    }

    #[test]
    fn rendering_is_antialiased_and_pressed_state_is_distinct() {
        let bar = StockBar::new(NATIVE_WIDTH, NATIVE_HEIGHT, all()).unwrap();
        let length = usize::try_from(NATIVE_WIDTH * NATIVE_HEIGHT * 4).unwrap();
        let mut normal = vec![0_u8; length];
        let mut pressed = vec![0_u8; length];
        Xrgb8888Frame::new(NATIVE_WIDTH, NATIVE_HEIGHT, NATIVE_WIDTH * 4, &mut normal)
            .and_then(|mut frame| {
                bar.render(&mut frame, false, StockLevels::default())
                    .map_err(|error| match error {
                        StockSliceError::Drawing(error) => error,
                        _ => FramebufferError::InvalidGeometry,
                    })
            })
            .unwrap();
        Xrgb8888Frame::new(NATIVE_WIDTH, NATIVE_HEIGHT, NATIVE_WIDTH * 4, &mut pressed)
            .and_then(|mut frame| {
                bar.render_pressed(
                    &mut frame,
                    false,
                    StockLevels::default(),
                    Some(StockAction::Escape),
                )
                .map_err(|error| match error {
                    StockSliceError::Drawing(error) => error,
                    _ => FramebufferError::InvalidGeometry,
                })
            })
            .unwrap();
        assert_ne!(normal, pressed);
        assert!(
            normal
                .iter()
                .any(|channel| !matches!(*channel, 0 | 53 | 242))
        );
    }

    #[test]
    fn geometry_mismatch_is_atomic() {
        let bar = StockBar::new(10, 2, StockCapabilities::default()).unwrap();
        let mut pixels = [0x5a; 72];
        let before = pixels;
        let mut frame = Xrgb8888Frame::new(9, 2, 36, &mut pixels).unwrap();
        assert_eq!(
            bar.render(&mut frame, false, StockLevels::default()),
            Err(StockSliceError::FrameGeometryMismatch),
        );
        assert_eq!(pixels, before);
    }
}

//! Renderer-owned cosmetic Touch ID status beside the physical sensor.

use crate::framebuffer::{FramebufferError, Rectangle, Rgb, Xrgb8888Frame};
use crate::gesture::Gesture;
use crate::overlay_labels;
use crate::overlay_state::OverlayState;
use crate::stock_art;
use crate::stock_labels::AlphaMask;

const STOCK_SLOT_COUNT: u32 = 13;
const NATIVE_HEIGHT: u32 = 60;
const NATIVE_RIGHT_MARGIN: u32 = 18;
const NATIVE_ARROW_WIDTH: u32 = 38;
const NATIVE_ARROW_GAP: u32 = 17;
const NATIVE_LEFT_PADDING: u32 = 28;
const NATIVE_CANCEL_SLOT_WIDTH: u32 = 54;
const NATIVE_CANCEL_CENTER_OFFSET: u32 = 29;
const MIN_OVERLAY_HEIGHT: u32 = 7;

const FOREGROUND: Rgb = Rgb {
    red: 220,
    green: 220,
    blue: 220,
};
const SUCCESS: Rgb = Rgb {
    red: 48,
    green: 209,
    blue: 88,
};
const ENROLLMENT_PROGRESS: Rgb = Rgb {
    red: 64,
    green: 156,
    blue: 255,
};
const ENROLLMENT_TRACK: Rgb = Rgb {
    red: 16,
    green: 39,
    blue: 64,
};

/// Pure layout for the cosmetic state shared by the built-in and custom bars.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TouchIdOverlay {
    width: u32,
    height: u32,
}

impl TouchIdOverlay {
    #[must_use]
    pub const fn new(width: u32, height: u32) -> Self {
        Self { width, height }
    }

    /// # Errors
    ///
    /// Returns an error if the frame geometry changed or bounded drawing fails.
    pub fn render(
        self,
        frame: &mut Xrgb8888Frame<'_>,
        state: Option<OverlayState>,
        fn_held: bool,
    ) -> Result<(), FramebufferError> {
        self.render_with_opacity(frame, state, fn_held, u8::MAX)
    }

    /// Draws a borderless cosmetic state at an explicit crossfade opacity.
    ///
    /// # Errors
    ///
    /// Returns an error if the frame geometry changed or bounded drawing fails.
    pub fn render_with_opacity(
        self,
        frame: &mut Xrgb8888Frame<'_>,
        state: Option<OverlayState>,
        _fn_held: bool,
        opacity: u8,
    ) -> Result<(), FramebufferError> {
        self.render_with_progress(frame, state, None, opacity)
    }

    /// Draws an overlay with optional enrollment progress in thousandths.
    ///
    /// # Errors
    ///
    /// Returns an error if the frame geometry changed or bounded drawing fails.
    pub fn render_with_progress(
        self,
        frame: &mut Xrgb8888Frame<'_>,
        state: Option<OverlayState>,
        progress_per_mille: Option<u16>,
        opacity: u8,
    ) -> Result<(), FramebufferError> {
        if frame.width() != self.width || frame.height() != self.height {
            return Err(FramebufferError::InvalidGeometry);
        }
        let Some(state) = state else {
            return Ok(());
        };
        if opacity == 0 {
            return Ok(());
        }
        let Some(bounds) = self.bounds(state) else {
            return Ok(());
        };

        let label = state_label(state);
        let desired_label_width = scale(label.width, self.height);
        let arrow_width = scale(NATIVE_ARROW_WIDTH, self.height);
        let arrow_gap = scale(NATIVE_ARROW_GAP, self.height);
        let right_margin = scale(NATIVE_RIGHT_MARGIN, self.height);
        let arrow_left = self.width - right_margin - arrow_width;
        let label_right = arrow_left.saturating_sub(arrow_gap);
        let label_width = desired_label_width.min(label_right.saturating_sub(bounds.x));
        if label_width == 0 {
            return Ok(());
        }
        let label_left = label_right - label_width;
        stock_art::draw_label_with_opacity(
            frame,
            Rectangle {
                x: label_left,
                y: 0,
                width: label_width,
                height: self.height,
            },
            label,
            FOREGROUND,
            opacity,
        )?;

        if state == OverlayState::Enrollment {
            let line_height = scale(3, self.height).max(1).min(self.height);
            let line = Rectangle {
                x: label_left,
                y: self.height - line_height,
                width: label_width,
                height: line_height,
            };
            frame.blend_rectangle(line, ENROLLMENT_TRACK, opacity)?;
            let progress = u32::from(progress_per_mille.unwrap_or(0).min(1_000));
            let filled = u32::try_from(u64::from(label_width) * u64::from(progress) / 1_000)
                .unwrap_or(label_width);
            if filled > 0 {
                frame.blend_rectangle(
                    Rectangle {
                        width: filled,
                        ..line
                    },
                    ENROLLMENT_PROGRESS,
                    opacity,
                )?;
            }
        }

        let mut indicator = indicator_mask(bounds, state, self.height);
        if opacity != u8::MAX {
            for alpha in &mut indicator {
                *alpha = u8::try_from((u16::from(*alpha) * u16::from(opacity) + 127) / 255)
                    .unwrap_or(u8::MAX);
            }
        }
        frame.blend_mask(
            bounds,
            &indicator,
            if state == OverlayState::Success {
                SUCCESS
            } else {
                FOREGROUND
            },
        )
    }

    #[must_use]
    pub fn bounds(self, state: OverlayState) -> Option<Rectangle> {
        if self.height < MIN_OVERLAY_HEIGHT || self.width == 0 {
            return None;
        }
        let label_width = scale(state_label(state).width, self.height);
        let cancel_width = if cancellable(state) {
            scale(NATIVE_CANCEL_SLOT_WIDTH, self.height)
        } else {
            0
        };
        let desired = scale(NATIVE_LEFT_PADDING, self.height)
            .checked_add(cancel_width)?
            .checked_add(label_width)?
            .checked_add(scale(NATIVE_ARROW_GAP, self.height))?
            .checked_add(scale(NATIVE_ARROW_WIDTH, self.height))?
            .checked_add(scale(NATIVE_RIGHT_MARGIN, self.height))?;
        let escape_right = self.width.div_ceil(STOCK_SLOT_COUNT);
        let left_limit = escape_right.checked_add(scale(4, self.height))?;
        let left = self.width.saturating_sub(desired).max(left_limit);
        Some(Rectangle {
            x: left,
            y: 0,
            width: self.width - left,
            height: self.height,
        })
    }

    /// Returns whether one completed tap on the custom-style cancel target
    /// requests typed cancellation.
    #[must_use]
    pub fn cancellation_for_gesture(
        self,
        gesture: Gesture,
        state: Option<OverlayState>,
        fn_held: bool,
    ) -> bool {
        let Some(state) = state.filter(|state| cancellable(*state)) else {
            return false;
        };
        let _ = fn_held;
        let Gesture::Tap(contact) = gesture else {
            return false;
        };
        let Some(bounds) = self.bounds(state) else {
            return false;
        };
        let center_x = bounds.x + scale(NATIVE_CANCEL_CENTER_OFFSET, self.height);
        let radius = scale(16, self.height).max(1);
        let dx = contact.x() - f64::from(center_x);
        let dy = contact.y() - f64::from(self.height) / 2.0;
        dx * dx + dy * dy <= f64::from(radius * radius)
    }

    #[must_use]
    pub fn covers_contact(
        self,
        contact: crate::gesture::DisplayContact,
        state: Option<OverlayState>,
        fn_held: bool,
    ) -> bool {
        let _ = fn_held;
        if state.is_none() || self.width == 0 || self.height < MIN_OVERLAY_HEIGHT {
            return false;
        }
        let escape_right = self.width.div_ceil(STOCK_SLOT_COUNT);
        contact.x() >= f64::from(escape_right)
            && contact.x() < f64::from(self.width)
            && contact.y() < f64::from(self.height)
    }
}

const fn cancellable(state: OverlayState) -> bool {
    matches!(
        state,
        OverlayState::Authenticate | OverlayState::Approve | OverlayState::Retry
    )
}

const fn state_label(state: OverlayState) -> AlphaMask {
    match state {
        OverlayState::Enrollment => overlay_labels::ENROLLMENT,
        OverlayState::Authenticate => overlay_labels::AUTHENTICATE,
        OverlayState::Approve => overlay_labels::APPROVE,
        OverlayState::Retry => overlay_labels::RETRY,
        OverlayState::Success => overlay_labels::SUCCESS,
    }
}

fn indicator_mask(bounds: Rectangle, state: OverlayState, height: u32) -> Vec<u8> {
    let mut mask = vec![
        0_u8;
        usize::try_from(u64::from(bounds.width) * u64::from(bounds.height))
            .unwrap_or(0)
    ];
    let scale_factor = f64::from(height) / f64::from(NATIVE_HEIGHT);
    let arrow_width = f64::from(NATIVE_ARROW_WIDTH) * scale_factor;
    let arrow_left =
        f64::from(bounds.width) - f64::from(NATIVE_RIGHT_MARGIN) * scale_factor - arrow_width;
    let center_y = f64::from(height) / 2.0;
    let cancel_center = f64::from(NATIVE_CANCEL_CENTER_OFFSET) * scale_factor;
    for y in 0..bounds.height {
        for x in 0..bounds.width {
            let sample_x = f64::from(x) + 0.5;
            let sample_y = f64::from(y) + 0.5;
            let covered = if state == OverlayState::Success {
                success_contains(
                    sample_x,
                    sample_y,
                    arrow_left,
                    arrow_width,
                    center_y,
                    scale_factor,
                )
            } else {
                arrow_contains(
                    sample_x,
                    sample_y,
                    arrow_left,
                    arrow_width,
                    center_y,
                    scale_factor,
                ) || (cancellable(state)
                    && cancel_contains(sample_x, sample_y, cancel_center, center_y, scale_factor))
            };
            if covered {
                let index = usize::try_from(u64::from(y) * u64::from(bounds.width) + u64::from(x))
                    .unwrap_or(0);
                mask[index] = 255;
            }
        }
    }
    mask
}

fn arrow_contains(x: f64, y: f64, left: f64, width: f64, center_y: f64, scale: f64) -> bool {
    let right = left + width;
    line_contains(x, y, left, center_y, right, center_y, 0.9 * scale)
        || line_contains(
            x,
            y,
            right - 8.0 * scale,
            center_y - 8.0 * scale,
            right,
            center_y,
            0.9 * scale,
        )
        || line_contains(
            x,
            y,
            right,
            center_y,
            right - 8.0 * scale,
            center_y + 8.0 * scale,
            0.9 * scale,
        )
}

fn cancel_contains(x: f64, y: f64, center_x: f64, center_y: f64, scale: f64) -> bool {
    let dx = x - center_x;
    let dy = y - center_y;
    let distance = (dx * dx + dy * dy).sqrt();
    (distance - 16.0 * scale).abs() <= 0.75 * scale
        || line_contains(
            x,
            y,
            center_x - 6.0 * scale,
            center_y - 6.0 * scale,
            center_x + 6.0 * scale,
            center_y + 6.0 * scale,
            1.1 * scale,
        )
        || line_contains(
            x,
            y,
            center_x + 6.0 * scale,
            center_y - 6.0 * scale,
            center_x - 6.0 * scale,
            center_y + 6.0 * scale,
            1.1 * scale,
        )
}

fn success_contains(x: f64, y: f64, left: f64, width: f64, center_y: f64, scale: f64) -> bool {
    let center_x = left + width / 2.0;
    let dx = x - center_x;
    let dy = y - center_y;
    let distance = (dx * dx + dy * dy).sqrt();
    (distance - 12.0 * scale).abs() <= scale
        || line_contains(
            x,
            y,
            center_x - 5.5 * scale,
            center_y,
            center_x - 1.5 * scale,
            center_y + 4.0 * scale,
            1.1 * scale,
        )
        || line_contains(
            x,
            y,
            center_x - 1.5 * scale,
            center_y + 4.0 * scale,
            center_x + 6.5 * scale,
            center_y - 4.5 * scale,
            1.1 * scale,
        )
}

fn line_contains(
    x: f64,
    y: f64,
    start_x: f64,
    start_y: f64,
    end_x: f64,
    end_y: f64,
    radius: f64,
) -> bool {
    let dx = end_x - start_x;
    let dy = end_y - start_y;
    let length_squared = dx * dx + dy * dy;
    let progress = (((x - start_x) * dx + (y - start_y) * dy) / length_squared).clamp(0.0, 1.0);
    let nearest_x = start_x + progress * dx;
    let nearest_y = start_y + progress * dy;
    let distance_x = x - nearest_x;
    let distance_y = y - nearest_y;
    distance_x * distance_x + distance_y * distance_y <= radius * radius
}

fn scale(value: u32, height: u32) -> u32 {
    u32::try_from((u64::from(value) * u64::from(height)).div_ceil(u64::from(NATIVE_HEIGHT)))
        .unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gesture::DisplayContact;
    use crate::stock_slice::{StockBar, StockCapabilities, StockLevels};

    fn stock_frame(width: u32, height: u32, fn_held: bool) -> Vec<u8> {
        let mut pixels =
            vec![0; usize::try_from(u64::from(width) * u64::from(height) * 4).unwrap()];
        let mut frame = Xrgb8888Frame::new(width, height, width * 4, &mut pixels).unwrap();
        StockBar::new(width, height, StockCapabilities::default())
            .unwrap()
            .render(&mut frame, fn_held, StockLevels::default())
            .unwrap();
        pixels
    }

    fn rendered(state: Option<OverlayState>, fn_held: bool) -> Vec<u8> {
        let width = 130;
        let height = 20;
        let mut pixels = stock_frame(width, height, fn_held);
        let mut frame = Xrgb8888Frame::new(width, height, width * 4, &mut pixels).unwrap();
        TouchIdOverlay::new(width, height)
            .render(&mut frame, state, fn_held)
            .unwrap();
        pixels
    }

    fn rendered_enrollment_progress(progress: u16) -> Vec<u8> {
        let width = 130;
        let height = 20;
        let mut pixels = stock_frame(width, height, false);
        let mut frame = Xrgb8888Frame::new(width, height, width * 4, &mut pixels).unwrap();
        TouchIdOverlay::new(width, height)
            .render_with_progress(
                &mut frame,
                Some(OverlayState::Enrollment),
                Some(progress),
                u8::MAX,
            )
            .unwrap();
        pixels
    }

    #[test]
    fn every_v1_state_has_a_distinct_visible_frame() {
        let baseline = rendered(None, false);
        let frames = [
            OverlayState::Enrollment,
            OverlayState::Authenticate,
            OverlayState::Approve,
            OverlayState::Retry,
            OverlayState::Success,
        ]
        .map(|state| rendered(Some(state), false));

        for frame in &frames {
            assert_ne!(frame, &baseline);
        }
        for left in 0..frames.len() {
            for right in left + 1..frames.len() {
                assert_ne!(frames[left], frames[right]);
            }
        }
    }

    #[test]
    fn overlay_is_borderless_and_remains_visible_while_fn_is_held() {
        let overlay = TouchIdOverlay::new(130, 20);
        let bounds = overlay
            .bounds(OverlayState::Enrollment)
            .expect("overlay fits");
        assert!(bounds.x > 10);
        assert_eq!(bounds.x + bounds.width, 130);
        assert_ne!(
            rendered(Some(OverlayState::Retry), true),
            rendered(None, true)
        );

        let baseline = rendered(None, false);
        let active = rendered(Some(OverlayState::Retry), false);
        let offset = usize::try_from(u64::from(bounds.x) * 4).unwrap();
        assert_eq!(&active[offset..offset + 4], &baseline[offset..offset + 4]);
    }

    #[test]
    fn enrollment_progress_grows_along_the_bottom_edge_only() {
        let empty = rendered_enrollment_progress(0);
        let partial = rendered_enrollment_progress(500);
        let complete = rendered_enrollment_progress(1_000);
        assert_ne!(empty, partial);
        assert_ne!(partial, complete);

        let line_top = 20 - scale(3, 20).max(1);
        for (index, (empty, complete)) in empty.iter().zip(&complete).enumerate() {
            if empty != complete {
                let pixel = index / 4;
                let y = u32::try_from(pixel / 130).unwrap();
                assert!(y >= line_top);
            }
        }
    }

    #[test]
    fn insufficient_geometry_is_a_no_op() {
        for (width, height) in [(1, 1), (13, 6)] {
            let mut pixels = vec![0x5a; usize::try_from(width * height * 4).unwrap()];
            let before = pixels.clone();
            let mut frame = Xrgb8888Frame::new(width, height, width * 4, &mut pixels).unwrap();
            TouchIdOverlay::new(width, height)
                .render(&mut frame, Some(OverlayState::Success), false)
                .unwrap();
            assert_eq!(pixels, before);
        }
    }

    #[test]
    fn geometry_mismatch_is_rejected_before_drawing() {
        let mut pixels = vec![0x5a; 100 * 20 * 4];
        let before = pixels.clone();
        let mut frame = Xrgb8888Frame::new(100, 20, 400, &mut pixels).unwrap();
        assert_eq!(
            TouchIdOverlay::new(130, 20).render(
                &mut frame,
                Some(OverlayState::Authenticate),
                false
            ),
            Err(FramebufferError::InvalidGeometry)
        );
        assert_eq!(pixels, before);
    }

    #[test]
    fn only_a_completed_cancel_target_tap_requests_cancellation() {
        let overlay = TouchIdOverlay::new(130, 20);
        let bounds = overlay.bounds(OverlayState::Authenticate).unwrap();
        let center = DisplayContact::new(
            1,
            f64::from(bounds.x + scale(NATIVE_CANCEL_CENTER_OFFSET, 20)),
            10.0,
        )
        .unwrap();
        let outside = DisplayContact::new(1, f64::from(bounds.x + bounds.width - 1), 10.0).unwrap();
        assert!(overlay.cancellation_for_gesture(
            Gesture::Tap(center),
            Some(OverlayState::Authenticate),
            false
        ));
        assert!(!overlay.cancellation_for_gesture(
            Gesture::Tap(outside),
            Some(OverlayState::Authenticate),
            false
        ));
        assert!(!overlay.cancellation_for_gesture(
            Gesture::Press(center),
            Some(OverlayState::Authenticate),
            false
        ));
        assert!(!overlay.cancellation_for_gesture(
            Gesture::Tap(center),
            Some(OverlayState::Enrollment),
            false
        ));
    }
}

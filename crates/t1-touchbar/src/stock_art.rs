//! Antialiased mask composition for the built-in Boot Camp-style surface.

use crate::framebuffer::{FramebufferError, Rectangle, Rgb, Xrgb8888Frame};
use crate::stock_icons;
use crate::stock_labels::AlphaMask;

const SAMPLE_GRID: u32 = 4;
const SAMPLE_COUNT: u32 = SAMPLE_GRID * SAMPLE_GRID;
const NATIVE_PLATE_HEIGHT: u32 = 60;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Symbol {
    DisplayDown,
    DisplayUp,
    KeyboardDown,
    KeyboardUp,
    Previous,
    PlayPause,
    Next,
    Mute,
    VolumeDown,
    VolumeUp,
}

pub(crate) fn draw_rounded_plate(
    frame: &mut Xrgb8888Frame<'_>,
    bounds: Rectangle,
    radius: u32,
    color: Rgb,
) -> Result<(), FramebufferError> {
    let width = bounds.width;
    let height = bounds.height;
    let radius = f64::from(radius.min(width / 2).min(height / 2));
    let mask = rasterize(width, height, |x, y| {
        let left = radius;
        let right = f64::from(width) - radius;
        let top = radius;
        let bottom = f64::from(height) - radius;
        if (x >= left && x <= right) || (y >= top && y <= bottom) {
            return true;
        }
        let center_x = if x < left { left } else { right };
        let center_y = if y < top { top } else { bottom };
        let dx = x - center_x;
        let dy = y - center_y;
        dx * dx + dy * dy <= radius * radius
    });
    frame.blend_mask(bounds, &mask, color)
}

pub(crate) fn draw_label(
    frame: &mut Xrgb8888Frame<'_>,
    bounds: Rectangle,
    label: AlphaMask,
    color: Rgb,
) -> Result<(), FramebufferError> {
    draw_label_with_opacity(frame, bounds, label, color, u8::MAX)
}

pub(crate) fn draw_label_with_opacity(
    frame: &mut Xrgb8888Frame<'_>,
    bounds: Rectangle,
    label: AlphaMask,
    color: Rgb,
    opacity: u8,
) -> Result<(), FramebufferError> {
    let width = scaled_dimension(label.width, bounds.height, bounds.width);
    let height = scaled_dimension(label.height, bounds.height, bounds.height);
    let mut pixels = resize_mask(label, width, height);
    if opacity != u8::MAX {
        for alpha in &mut pixels {
            *alpha = u8::try_from((u16::from(*alpha) * u16::from(opacity) + 127) / 255)
                .unwrap_or(u8::MAX);
        }
    }
    frame.blend_mask(
        Rectangle {
            x: bounds.x + (bounds.width - width) / 2,
            y: bounds.y + (bounds.height - height) / 2,
            width,
            height,
        },
        &pixels,
        color,
    )
}

pub(crate) fn draw_symbol(
    frame: &mut Xrgb8888Frame<'_>,
    bounds: Rectangle,
    symbol: Symbol,
    color: Rgb,
) -> Result<(), FramebufferError> {
    let mask = match symbol {
        Symbol::DisplayDown => stock_icons::DISPLAY_DOWN,
        Symbol::DisplayUp => stock_icons::DISPLAY_UP,
        Symbol::KeyboardDown => stock_icons::KEYBOARD_DOWN,
        Symbol::KeyboardUp => stock_icons::KEYBOARD_UP,
        Symbol::Previous => stock_icons::PREVIOUS,
        Symbol::PlayPause => stock_icons::PLAY_PAUSE,
        Symbol::Next => stock_icons::NEXT,
        Symbol::Mute => stock_icons::MUTE,
        Symbol::VolumeDown => stock_icons::VOLUME_DOWN,
        Symbol::VolumeUp => stock_icons::VOLUME_UP,
    };
    draw_label(frame, bounds, mask, color)
}

fn scaled_dimension(native: u32, plate_height: u32, maximum: u32) -> u32 {
    u32::try_from(
        (u64::from(native) * u64::from(plate_height)).div_ceil(u64::from(NATIVE_PLATE_HEIGHT)),
    )
    .unwrap_or(maximum)
    .clamp(1, maximum)
}

fn resize_mask(label: AlphaMask, width: u32, height: u32) -> Vec<u8> {
    let mut output = vec![0_u8; usize::try_from(u64::from(width) * u64::from(height)).unwrap_or(0)];
    for y in 0..height {
        let source_y = (u64::from(y) * u64::from(label.height) / u64::from(height))
            .min(u64::from(label.height - 1));
        for x in 0..width {
            let source_x = (u64::from(x) * u64::from(label.width) / u64::from(width))
                .min(u64::from(label.width - 1));
            let source = usize::try_from(source_y * u64::from(label.width) + source_x).unwrap_or(0);
            let destination =
                usize::try_from(u64::from(y) * u64::from(width) + u64::from(x)).unwrap_or(0);
            output[destination] = label.pixels[source];
        }
    }
    output
}

fn rasterize(width: u32, height: u32, contains: impl Fn(f64, f64) -> bool) -> Vec<u8> {
    let mut mask = vec![0_u8; usize::try_from(u64::from(width) * u64::from(height)).unwrap_or(0)];
    for y in 0..height {
        for x in 0..width {
            let mut covered = 0_u32;
            for sample_y in 0..SAMPLE_GRID {
                for sample_x in 0..SAMPLE_GRID {
                    let sample_x =
                        f64::from(x) + (f64::from(sample_x) + 0.5) / f64::from(SAMPLE_GRID);
                    let sample_y =
                        f64::from(y) + (f64::from(sample_y) + 0.5) / f64::from(SAMPLE_GRID);
                    covered += u32::from(contains(sample_x, sample_y));
                }
            }
            let index =
                usize::try_from(u64::from(y) * u64::from(width) + u64::from(x)).unwrap_or(0);
            mask[index] =
                u8::try_from((covered * 255 + SAMPLE_COUNT / 2) / SAMPLE_COUNT).unwrap_or(255);
        }
    }
    mask
}

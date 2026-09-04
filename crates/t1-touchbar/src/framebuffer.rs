//! Dependency-free drawing into negotiated DRM XRGB8888 frame buffers.

use std::{error::Error, fmt};

const BYTES_PER_PIXEL: u32 = 4;

/// One renderer-owned RGB color.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rgb {
    pub red: u8,
    pub green: u8,
    pub blue: u8,
}

/// One display-coordinate rectangle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rectangle {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

/// Why a negotiated frame or drawing operation was rejected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FramebufferError {
    InvalidGeometry,
    InvalidStride,
    InvalidLength,
    RectangleOutOfBounds,
}

impl fmt::Display for FramebufferError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidGeometry => "invalid negotiated framebuffer geometry",
            Self::InvalidStride => "framebuffer stride does not match negotiated geometry",
            Self::InvalidLength => "framebuffer length does not match negotiated geometry",
            Self::RectangleOutOfBounds => "drawing rectangle is outside the framebuffer",
        })
    }
}

impl Error for FramebufferError {}

/// A caller-owned frame with the exact negotiated XRGB8888 layout.
pub struct Xrgb8888Frame<'pixels> {
    width: u32,
    height: u32,
    stride: u32,
    pixels: &'pixels mut [u8],
}

impl fmt::Debug for Xrgb8888Frame<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Xrgb8888Frame")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("stride", &self.stride)
            .field("byte_length", &self.pixels.len())
            .finish_non_exhaustive()
    }
}

impl<'pixels> Xrgb8888Frame<'pixels> {
    /// Validates and borrows one negotiated frame buffer.
    ///
    /// # Errors
    ///
    /// Returns [`FramebufferError`] unless width and height are nonzero,
    /// `stride == width * 4`, and the byte slice has exactly
    /// `stride * height` bytes. All size calculations are checked.
    pub fn new(
        width: u32,
        height: u32,
        stride: u32,
        pixels: &'pixels mut [u8],
    ) -> Result<Self, FramebufferError> {
        if width == 0 || height == 0 {
            return Err(FramebufferError::InvalidGeometry);
        }
        let expected_stride = width
            .checked_mul(BYTES_PER_PIXEL)
            .ok_or(FramebufferError::InvalidGeometry)?;
        if stride != expected_stride {
            return Err(FramebufferError::InvalidStride);
        }
        let expected_length = u64::from(stride)
            .checked_mul(u64::from(height))
            .and_then(|length| usize::try_from(length).ok())
            .ok_or(FramebufferError::InvalidLength)?;
        if pixels.len() != expected_length {
            return Err(FramebufferError::InvalidLength);
        }

        Ok(Self {
            width,
            height,
            stride,
            pixels,
        })
    }

    #[must_use]
    pub fn width(&self) -> u32 {
        self.width
    }

    #[must_use]
    pub fn height(&self) -> u32 {
        self.height
    }

    #[must_use]
    pub fn stride(&self) -> u32 {
        self.stride
    }

    /// Borrows the complete encoded frame for later submission.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.pixels
    }

    /// Fills the complete frame with one color.
    pub fn clear(&mut self, color: Rgb) {
        let pixel = encode_pixel(color);
        for destination in self.pixels.as_chunks_mut::<4>().0 {
            destination.copy_from_slice(&pixel);
        }
    }

    /// Fills one positive, fully in-bounds rectangle without clipping.
    ///
    /// Validation completes before any pixel is changed.
    ///
    /// # Errors
    ///
    /// Returns [`FramebufferError::RectangleOutOfBounds`] for a zero-sized,
    /// overflowing, or out-of-bounds rectangle.
    pub fn fill_rectangle(
        &mut self,
        rectangle: Rectangle,
        color: Rgb,
    ) -> Result<(), FramebufferError> {
        if rectangle.width == 0 || rectangle.height == 0 {
            return Err(FramebufferError::RectangleOutOfBounds);
        }
        let right = rectangle
            .x
            .checked_add(rectangle.width)
            .ok_or(FramebufferError::RectangleOutOfBounds)?;
        let bottom = rectangle
            .y
            .checked_add(rectangle.height)
            .ok_or(FramebufferError::RectangleOutOfBounds)?;
        if right > self.width || bottom > self.height {
            return Err(FramebufferError::RectangleOutOfBounds);
        }

        let pixel = encode_pixel(color);
        let row_bytes = usize::try_from(u64::from(rectangle.width) * u64::from(BYTES_PER_PIXEL))
            .map_err(|_| FramebufferError::RectangleOutOfBounds)?;
        for y in rectangle.y..bottom {
            let start = u64::from(y)
                .checked_mul(u64::from(self.stride))
                .and_then(|offset| {
                    offset.checked_add(u64::from(rectangle.x) * u64::from(BYTES_PER_PIXEL))
                })
                .and_then(|offset| usize::try_from(offset).ok())
                .ok_or(FramebufferError::RectangleOutOfBounds)?;
            let end = start
                .checked_add(row_bytes)
                .ok_or(FramebufferError::RectangleOutOfBounds)?;
            let row = self
                .pixels
                .get_mut(start..end)
                .ok_or(FramebufferError::RectangleOutOfBounds)?;
            for destination in row.as_chunks_mut::<4>().0 {
                destination.copy_from_slice(&pixel);
            }
        }
        Ok(())
    }

    /// Alpha-blends one solid color over a positive in-bounds rectangle.
    ///
    /// # Errors
    ///
    /// Returns [`FramebufferError::RectangleOutOfBounds`] for invalid bounds.
    pub fn blend_rectangle(
        &mut self,
        rectangle: Rectangle,
        color: Rgb,
        alpha: u8,
    ) -> Result<(), FramebufferError> {
        if rectangle.width == 0 || rectangle.height == 0 {
            return Err(FramebufferError::RectangleOutOfBounds);
        }
        let right = rectangle
            .x
            .checked_add(rectangle.width)
            .ok_or(FramebufferError::RectangleOutOfBounds)?;
        let bottom = rectangle
            .y
            .checked_add(rectangle.height)
            .ok_or(FramebufferError::RectangleOutOfBounds)?;
        if right > self.width || bottom > self.height {
            return Err(FramebufferError::RectangleOutOfBounds);
        }
        if alpha == 0 {
            return Ok(());
        }
        if alpha == u8::MAX {
            return self.fill_rectangle(rectangle, color);
        }

        let alpha = u16::from(alpha);
        for y in rectangle.y..bottom {
            for x in rectangle.x..right {
                let offset =
                    usize::try_from(u64::from(y) * u64::from(self.stride) + u64::from(x) * 4)
                        .map_err(|_| FramebufferError::RectangleOutOfBounds)?;
                let pixel = self
                    .pixels
                    .get_mut(offset..offset + 4)
                    .ok_or(FramebufferError::RectangleOutOfBounds)?;
                pixel[0] = blend_channel(pixel[0], color.blue, alpha);
                pixel[1] = blend_channel(pixel[1], color.green, alpha);
                pixel[2] = blend_channel(pixel[2], color.red, alpha);
            }
        }
        Ok(())
    }

    /// Blends one tightly packed 8-bit alpha mask over an in-bounds rectangle.
    ///
    /// # Errors
    ///
    /// Returns [`FramebufferError::RectangleOutOfBounds`] when the rectangle
    /// is empty or outside the frame, or when the mask length is not exactly
    /// `width * height`.
    pub fn blend_mask(
        &mut self,
        rectangle: Rectangle,
        mask: &[u8],
        color: Rgb,
    ) -> Result<(), FramebufferError> {
        if rectangle.width == 0 || rectangle.height == 0 {
            return Err(FramebufferError::RectangleOutOfBounds);
        }
        let right = rectangle
            .x
            .checked_add(rectangle.width)
            .ok_or(FramebufferError::RectangleOutOfBounds)?;
        let bottom = rectangle
            .y
            .checked_add(rectangle.height)
            .ok_or(FramebufferError::RectangleOutOfBounds)?;
        let expected = usize::try_from(u64::from(rectangle.width) * u64::from(rectangle.height))
            .map_err(|_| FramebufferError::RectangleOutOfBounds)?;
        if right > self.width || bottom > self.height || mask.len() != expected {
            return Err(FramebufferError::RectangleOutOfBounds);
        }

        for (mask_y, y) in (rectangle.y..bottom).enumerate() {
            for (mask_x, x) in (rectangle.x..right).enumerate() {
                let alpha = u16::from(
                    mask[mask_y * usize::try_from(rectangle.width).unwrap_or(0) + mask_x],
                );
                if alpha == 0 {
                    continue;
                }
                let offset = usize::try_from(
                    u64::from(y) * u64::from(self.stride)
                        + u64::from(x) * u64::from(BYTES_PER_PIXEL),
                )
                .map_err(|_| FramebufferError::RectangleOutOfBounds)?;
                let pixel = self
                    .pixels
                    .get_mut(offset..offset + usize::try_from(BYTES_PER_PIXEL).unwrap_or(4))
                    .ok_or(FramebufferError::RectangleOutOfBounds)?;
                pixel[0] = blend_channel(pixel[0], color.blue, alpha);
                pixel[1] = blend_channel(pixel[1], color.green, alpha);
                pixel[2] = blend_channel(pixel[2], color.red, alpha);
            }
        }
        Ok(())
    }
}

fn blend_channel(background: u8, foreground: u8, alpha: u16) -> u8 {
    let inverse = 255 - alpha;
    u8::try_from((u16::from(background) * inverse + u16::from(foreground) * alpha + 127) / 255)
        .unwrap_or(foreground)
}

const fn encode_pixel(color: Rgb) -> [u8; BYTES_PER_PIXEL as usize] {
    [color.blue, color.green, color.red, 0]
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLACK: Rgb = Rgb {
        red: 0,
        green: 0,
        blue: 0,
    };
    const ACCENT: Rgb = Rgb {
        red: 0x11,
        green: 0x22,
        blue: 0x33,
    };

    #[test]
    fn validates_exact_negotiated_geometry_stride_and_length() {
        let mut exact = [0_u8; 24];
        let frame = Xrgb8888Frame::new(3, 2, 12, &mut exact).expect("exact frame");
        assert_eq!(frame.width(), 3);
        assert_eq!(frame.height(), 2);
        assert_eq!(frame.stride(), 12);

        let mut empty = [];
        assert_eq!(
            Xrgb8888Frame::new(0, 1, 0, &mut empty).unwrap_err(),
            FramebufferError::InvalidGeometry
        );
        assert_eq!(
            Xrgb8888Frame::new(u32::MAX, 1, 0, &mut empty).unwrap_err(),
            FramebufferError::InvalidGeometry
        );

        let mut wrong_stride = [0_u8; 24];
        assert_eq!(
            Xrgb8888Frame::new(3, 2, 16, &mut wrong_stride).unwrap_err(),
            FramebufferError::InvalidStride
        );

        let mut short = [0_u8; 23];
        assert_eq!(
            Xrgb8888Frame::new(3, 2, 12, &mut short).unwrap_err(),
            FramebufferError::InvalidLength
        );
        assert_eq!(
            Xrgb8888Frame::new(1, u32::MAX, 4, &mut empty).unwrap_err(),
            FramebufferError::InvalidLength
        );
    }

    #[test]
    fn alpha_masks_blend_exactly_and_validate_shape() {
        let mut pixels = vec![0_u8; 3 * 2 * 4];
        let mut frame = Xrgb8888Frame::new(3, 2, 12, &mut pixels).unwrap();
        frame.clear(Rgb {
            red: 10,
            green: 20,
            blue: 30,
        });
        frame
            .blend_mask(
                Rectangle {
                    x: 1,
                    y: 0,
                    width: 2,
                    height: 1,
                },
                &[0, 255],
                Rgb {
                    red: 110,
                    green: 120,
                    blue: 130,
                },
            )
            .unwrap();
        assert_eq!(&frame.as_bytes()[4..8], &[30, 20, 10, 0]);
        assert_eq!(&frame.as_bytes()[8..12], &[130, 120, 110, 0]);
        assert_eq!(
            frame.blend_mask(
                Rectangle {
                    x: 0,
                    y: 0,
                    width: 2,
                    height: 2,
                },
                &[0; 3],
                ACCENT,
            ),
            Err(FramebufferError::RectangleOutOfBounds)
        );
    }

    #[test]
    fn clear_writes_exact_little_endian_xrgb8888_pixels() {
        let mut pixels = [0xff_u8; 8];
        let mut frame = Xrgb8888Frame::new(2, 1, 8, &mut pixels).expect("frame");

        frame.clear(ACCENT);

        assert_eq!(frame.as_bytes(), [0x33, 0x22, 0x11, 0, 0x33, 0x22, 0x11, 0]);
    }

    #[test]
    fn rectangle_changes_only_covered_pixels() {
        let mut pixels = [0xff_u8; 24];
        let mut frame = Xrgb8888Frame::new(3, 2, 12, &mut pixels).expect("frame");
        frame.clear(BLACK);

        frame
            .fill_rectangle(
                Rectangle {
                    x: 1,
                    y: 0,
                    width: 1,
                    height: 2,
                },
                ACCENT,
            )
            .expect("in-bounds rectangle");

        assert_eq!(
            frame.as_bytes(),
            [
                0, 0, 0, 0, 0x33, 0x22, 0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x33, 0x22, 0x11, 0, 0, 0,
                0, 0,
            ]
        );
    }

    #[test]
    fn solid_rectangle_blends_without_touching_adjacent_pixels() {
        let mut pixels = [0_u8; 12];
        let mut frame = Xrgb8888Frame::new(3, 1, 12, &mut pixels).expect("frame");
        frame.clear(Rgb {
            red: 100,
            green: 80,
            blue: 60,
        });

        frame
            .blend_rectangle(
                Rectangle {
                    x: 1,
                    y: 0,
                    width: 1,
                    height: 1,
                },
                BLACK,
                128,
            )
            .expect("blend rectangle");

        assert_eq!(&frame.as_bytes()[0..4], &[60, 80, 100, 0]);
        assert_eq!(&frame.as_bytes()[4..8], &[30, 40, 50, 0]);
        assert_eq!(&frame.as_bytes()[8..12], &[60, 80, 100, 0]);
    }

    #[test]
    fn rectangle_may_touch_the_exact_right_and_bottom_edges() {
        let mut pixels = [0_u8; 24];
        let mut frame = Xrgb8888Frame::new(3, 2, 12, &mut pixels).expect("frame");

        frame
            .fill_rectangle(
                Rectangle {
                    x: 2,
                    y: 1,
                    width: 1,
                    height: 1,
                },
                ACCENT,
            )
            .expect("exact edge rectangle");

        assert_eq!(&frame.as_bytes()[20..24], &[0x33, 0x22, 0x11, 0]);
    }

    #[test]
    fn invalid_rectangles_are_rejected_before_any_mutation() {
        for rectangle in [
            Rectangle {
                x: 0,
                y: 0,
                width: 0,
                height: 1,
            },
            Rectangle {
                x: 0,
                y: 0,
                width: 1,
                height: 0,
            },
            Rectangle {
                x: 3,
                y: 0,
                width: 1,
                height: 1,
            },
            Rectangle {
                x: 0,
                y: 2,
                width: 1,
                height: 1,
            },
            Rectangle {
                x: u32::MAX,
                y: 0,
                width: 1,
                height: 1,
            },
            Rectangle {
                x: 0,
                y: u32::MAX,
                width: 1,
                height: 1,
            },
        ] {
            let mut pixels = [0x5a_u8; 24];
            let before = pixels;
            let mut frame = Xrgb8888Frame::new(3, 2, 12, &mut pixels).expect("frame");

            assert_eq!(
                frame.fill_rectangle(rectangle, ACCENT),
                Err(FramebufferError::RectangleOutOfBounds)
            );
            assert_eq!(frame.as_bytes(), before);
        }
    }
}

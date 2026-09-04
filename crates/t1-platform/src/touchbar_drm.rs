//! Safe ownership boundary for the dynamically discovered T1 DRM display.

use std::{error::Error, fmt, ptr::NonNull};

use crate::ffi;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TouchBarDamageRectangle {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TouchBarGeometry {
    width: u32,
    height: u32,
    stride: u32,
    byte_length: u64,
}

impl TouchBarGeometry {
    #[must_use]
    pub fn width(self) -> u32 {
        self.width
    }

    #[must_use]
    pub fn height(self) -> u32 {
        self.height
    }

    #[must_use]
    pub fn stride(self) -> u32 {
        self.stride
    }

    #[must_use]
    pub fn byte_length(self) -> u64 {
        self.byte_length
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TouchBarDrmError {
    InvalidArgument,
    Discovery,
    AmbiguousDevice,
    Open,
    WrongDevice,
    Resources,
    Connector,
    WrongGeometry,
    Buffer,
    Mapping,
    Present,
    Unknown,
}

impl TouchBarDrmError {
    fn from_status(status: i32) -> Result<(), Self> {
        match status {
            0 => Ok(()),
            1 => Err(Self::InvalidArgument),
            2 => Err(Self::Discovery),
            3 => Err(Self::AmbiguousDevice),
            4 => Err(Self::Open),
            5 => Err(Self::WrongDevice),
            6 => Err(Self::Resources),
            7 => Err(Self::Connector),
            8 => Err(Self::WrongGeometry),
            9 => Err(Self::Buffer),
            10 => Err(Self::Mapping),
            11 => Err(Self::Present),
            _ => Err(Self::Unknown),
        }
    }
}

impl fmt::Display for TouchBarDrmError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidArgument => "invalid Touch Bar DRM argument",
            Self::Discovery => "Touch Bar DRM device was not found",
            Self::AmbiguousDevice => "multiple Touch Bar DRM devices were found",
            Self::Open => "Touch Bar DRM device could not be opened",
            Self::WrongDevice => "Touch Bar DRM device identity changed during discovery",
            Self::Resources => "Touch Bar DRM resources could not be read",
            Self::Connector => "Touch Bar DRM connector could not be read",
            Self::WrongGeometry => "Touch Bar DRM geometry is unsupported",
            Self::Buffer => "Touch Bar DRM scanout buffer setup failed",
            Self::Mapping => "Touch Bar DRM scanout mapping failed",
            Self::Present => "Touch Bar DRM frame presentation failed",
            Self::Unknown => "unknown Touch Bar DRM failure",
        };
        formatter.write_str(message)
    }
}

impl Error for TouchBarDrmError {}

/// Exclusive ownership of one validated appletbdrm device and scanout buffer.
pub struct TouchBarDisplay {
    native: NonNull<ffi::RawTouchBarDrm>,
    geometry: TouchBarGeometry,
}

impl fmt::Debug for TouchBarDisplay {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TouchBarDisplay")
            .field("geometry", &self.geometry)
            .finish_non_exhaustive()
    }
}

impl TouchBarDisplay {
    /// Dynamically discovers and opens the only appletbdrm card.
    ///
    /// # Errors
    ///
    /// Returns [`TouchBarDrmError`] when discovery is absent or ambiguous,
    /// device identity changes during opening, KMS geometry is not the proven
    /// Touch Bar mode, or the scanout buffer cannot be created safely.
    pub fn open() -> Result<Self, TouchBarDrmError> {
        let (status, native, geometry) = ffi::open_touchbar_drm();
        TouchBarDrmError::from_status(status)?;
        let native = NonNull::new(native).ok_or(TouchBarDrmError::Unknown)?;
        Ok(Self {
            native,
            geometry: TouchBarGeometry {
                width: geometry.width,
                height: geometry.height,
                stride: geometry.stride,
                byte_length: geometry.byte_length,
            },
        })
    }

    #[must_use]
    pub fn geometry(&self) -> TouchBarGeometry {
        self.geometry
    }

    /// Presents one complete logical XRGB8888 frame.
    ///
    /// # Errors
    ///
    /// Returns [`TouchBarDrmError`] if the frame length is not the negotiated
    /// exact size or KMS cannot activate or dirty the framebuffer.
    pub fn present(&mut self, pixels: &[u8]) -> Result<(), TouchBarDrmError> {
        TouchBarDrmError::from_status(ffi::present_touchbar_drm(self.native.as_ptr(), pixels))
    }

    /// Presents the changed logical XRGB8888 regions from one complete frame.
    ///
    /// # Errors
    ///
    /// Returns [`TouchBarDrmError`] if the frame or any rectangle is invalid,
    /// or KMS cannot activate or dirty the framebuffer.
    pub fn present_rectangles(
        &mut self,
        pixels: &[u8],
        rectangles: &[TouchBarDamageRectangle],
    ) -> Result<(), TouchBarDrmError> {
        let native_rectangles = rectangles
            .iter()
            .map(|rectangle| ffi::RawTouchBarDrmDamageRectangle {
                x: rectangle.x,
                y: rectangle.y,
                width: rectangle.width,
                height: rectangle.height,
            })
            .collect::<Vec<_>>();
        TouchBarDrmError::from_status(ffi::present_touchbar_drm_rectangles(
            self.native.as_ptr(),
            pixels,
            &native_rectangles,
        ))
    }
}

impl Drop for TouchBarDisplay {
    fn drop(&mut self) {
        ffi::close_touchbar_drm(self.native.as_ptr());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_every_native_status_without_external_detail() {
        let expected = [
            TouchBarDrmError::InvalidArgument,
            TouchBarDrmError::Discovery,
            TouchBarDrmError::AmbiguousDevice,
            TouchBarDrmError::Open,
            TouchBarDrmError::WrongDevice,
            TouchBarDrmError::Resources,
            TouchBarDrmError::Connector,
            TouchBarDrmError::WrongGeometry,
            TouchBarDrmError::Buffer,
            TouchBarDrmError::Mapping,
            TouchBarDrmError::Present,
        ];
        assert_eq!(TouchBarDrmError::from_status(0), Ok(()));
        for (status, error) in (1_i32..).zip(expected) {
            assert_eq!(TouchBarDrmError::from_status(status), Err(error));
        }
        assert_eq!(
            TouchBarDrmError::from_status(i32::MAX),
            Err(TouchBarDrmError::Unknown)
        );
    }

    #[test]
    fn diagnostics_do_not_expose_a_device_path() {
        for error in [
            TouchBarDrmError::Discovery,
            TouchBarDrmError::Open,
            TouchBarDrmError::WrongDevice,
            TouchBarDrmError::Present,
        ] {
            assert!(!error.to_string().contains('/'));
        }
    }
}

//! Safe ownership of sealed renderer frames crossing the hardware IPC boundary.

use std::fmt;
use std::marker::PhantomData;
use std::os::fd::BorrowedFd;
use std::ptr::NonNull;
use std::rc::Rc;

use crate::ffi;

pub const MAX_FRAME_BYTES: u64 = 16 * 1024 * 1024;

/// Static, redaction-safe failure from frame-memory creation or acceptance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameMemfdError {
    InvalidArgument,
    SizeOutOfRange,
    Allocation,
    Creation,
    Sizing,
    Sealing,
    Ownership,
    InvalidFile,
    Mapping,
    Unknown,
}

impl fmt::Display for FrameMemfdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidArgument => "invalid frame memory argument",
            Self::SizeOutOfRange => "frame memory size is out of range",
            Self::Allocation => "frame memory allocation failed",
            Self::Creation => "frame memory creation failed",
            Self::Sizing => "frame memory sizing failed",
            Self::Sealing => "frame memory sealing failed",
            Self::Ownership => "frame memory ownership failed",
            Self::InvalidFile => "invalid frame memory file",
            Self::Mapping => "frame memory mapping failed",
            Self::Unknown => "unknown frame memory failure",
        })
    }
}

impl std::error::Error for FrameMemfdError {}

/// Owned renderer frame with a writable mapping and borrowed transfer fd.
///
/// The handle is intentionally thread-bound: its native ownership includes a
/// process-local writable mapping, and no `Send` or `Sync` assertion is needed
/// by the single-threaded renderer lifecycle.
pub struct RendererFrame {
    native: NonNull<ffi::RawFrameMemfdRenderer>,
    thread_bound: PhantomData<Rc<()>>,
}

impl RendererFrame {
    /// Creates an anonymous fixed-size frame ready for `SCM_RIGHTS` transfer.
    ///
    /// # Errors
    ///
    /// Returns a static error for a zero or excessive size, allocation,
    /// creation, exact-sizing, writable-mapping, or sealing failure.
    pub fn new(byte_length: u64) -> Result<Self, FrameMemfdError> {
        let (status, native) = ffi::create_frame_memfd_renderer(byte_length);
        check(status)?;
        let native = NonNull::new(native).ok_or(FrameMemfdError::Creation)?;
        Ok(Self {
            native,
            thread_bound: PhantomData,
        })
    }

    /// Borrows the sealed memfd for transfer without exposing raw ownership.
    #[must_use]
    pub fn descriptor(&self) -> BorrowedFd<'_> {
        ffi::frame_memfd_renderer_descriptor(&self.native)
    }

    /// Returns the exact validated mapping length.
    #[must_use]
    pub fn len(&self) -> usize {
        ffi::frame_memfd_renderer_length(&self.native)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Exclusively borrows the complete writable frame mapping.
    #[must_use]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        ffi::frame_memfd_renderer_bytes(&mut self.native)
    }
}

impl fmt::Debug for RendererFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RendererFrame")
            .field("length", &self.len())
            .finish_non_exhaustive()
    }
}

impl Drop for RendererFrame {
    fn drop(&mut self) {
        ffi::destroy_frame_memfd_renderer(self.native);
    }
}

/// Owned duplicate and read-only mapping of one accepted renderer frame.
///
/// The handle is intentionally thread-bound alongside the connection and
/// buffer-lifecycle state that establishes when the renderer must not write.
pub struct ReadOnlyFrame {
    native: NonNull<ffi::RawFrameMemfdReader>,
    thread_bound: PhantomData<Rc<()>>,
}

impl ReadOnlyFrame {
    /// Validates and duplicates one borrowed received descriptor.
    ///
    /// Acceptance requires an anonymous regular seal-capable file with the
    /// exact expected size and shrink, grow, and further-seal-change seals.
    /// The borrowed descriptor remains owned by the caller.
    ///
    /// # Errors
    ///
    /// Returns a static error when the size is out of range, duplication or
    /// validation fails, or a read-only mapping cannot be created.
    pub fn accept(
        received_descriptor: BorrowedFd<'_>,
        expected_byte_length: u64,
    ) -> Result<Self, FrameMemfdError> {
        let (status, native) =
            ffi::accept_frame_memfd_reader(received_descriptor, expected_byte_length);
        check(status)?;
        let native = NonNull::new(native).ok_or(FrameMemfdError::Ownership)?;
        Ok(Self {
            native,
            thread_bound: PhantomData,
        })
    }

    /// Returns the exact validated mapping length.
    #[must_use]
    pub fn len(&self) -> usize {
        ffi::frame_memfd_reader_length(&self.native)
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        false
    }

    /// Copies one possibly tearing frame snapshot into an exact-size slice.
    ///
    /// Native volatile reads ensure Rust never forms a shared reference to the
    /// mapping that remains externally writable by the renderer.
    ///
    /// # Errors
    ///
    /// Returns [`FrameMemfdError::InvalidArgument`] unless `destination` has
    /// exactly [`Self::len`] bytes. Rejection leaves it unchanged.
    pub fn copy_into(&self, destination: &mut [u8]) -> Result<(), FrameMemfdError> {
        check(ffi::copy_frame_memfd_reader(&self.native, destination))
    }
}

impl fmt::Debug for ReadOnlyFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReadOnlyFrame")
            .field("length", &self.len())
            .finish_non_exhaustive()
    }
}

impl Drop for ReadOnlyFrame {
    fn drop(&mut self) {
        ffi::destroy_frame_memfd_reader(self.native);
    }
}

fn check(status: i32) -> Result<(), FrameMemfdError> {
    match status {
        0 => Ok(()),
        1 => Err(FrameMemfdError::InvalidArgument),
        2 => Err(FrameMemfdError::SizeOutOfRange),
        3 => Err(FrameMemfdError::Allocation),
        4 => Err(FrameMemfdError::Creation),
        5 => Err(FrameMemfdError::Sizing),
        6 => Err(FrameMemfdError::Sealing),
        7 => Err(FrameMemfdError::Ownership),
        8 => Err(FrameMemfdError::InvalidFile),
        9 => Err(FrameMemfdError::Mapping),
        _ => Err(FrameMemfdError::Unknown),
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::{AsFd, AsRawFd};
    use std::os::unix::net::UnixStream;

    use super::*;

    const FRAME_LENGTH: u64 = 520_800;

    #[test]
    fn renderer_and_reader_share_exact_frame_content_and_own_lifetimes() {
        let mut renderer = RendererFrame::new(FRAME_LENGTH).expect("create renderer frame");
        let descriptor = renderer.descriptor().as_raw_fd();
        assert!(descriptor >= 0);
        assert_eq!(renderer.len(), 520_800);
        assert!(!renderer.is_empty());
        renderer.as_mut_slice()[42] = 0xa6;

        let reader = ReadOnlyFrame::accept(renderer.descriptor(), FRAME_LENGTH)
            .expect("accept renderer frame");
        assert_eq!(reader.len(), 520_800);
        assert!(!reader.is_empty());
        let mut snapshot = vec![0; reader.len()];
        reader.copy_into(&mut snapshot).expect("copy frame");
        assert_eq!(snapshot[42], 0xa6);

        drop(renderer);
        reader.copy_into(&mut snapshot).expect("copy owned frame");
        assert_eq!(snapshot[42], 0xa6);
        assert_eq!(
            format!("{reader:?}"),
            "ReadOnlyFrame { length: 520800, .. }"
        );
    }

    #[test]
    fn accepted_frame_observes_complete_renderer_mapping() {
        let mut renderer = RendererFrame::new(64).expect("create renderer frame");
        renderer.as_mut_slice().copy_from_slice(&[0x5c; 64]);
        let reader = ReadOnlyFrame::accept(renderer.descriptor(), 64).expect("accept frame");
        let mut snapshot = [0; 64];

        reader.copy_into(&mut snapshot).expect("copy frame");
        assert_eq!(snapshot, [0x5c; 64]);
        assert_eq!(renderer.as_mut_slice().len(), 64);

        let mut wrong = [0xa5; 63];
        assert_eq!(
            reader.copy_into(&mut wrong),
            Err(FrameMemfdError::InvalidArgument)
        );
        assert_eq!(wrong, [0xa5; 63]);
        let mut too_long = [0xa5; 65];
        assert_eq!(
            reader.copy_into(&mut too_long),
            Err(FrameMemfdError::InvalidArgument)
        );
        assert_eq!(too_long, [0xa5; 65]);
    }

    #[test]
    fn enforces_size_bounds_and_exact_received_length() {
        assert!(matches!(
            RendererFrame::new(0),
            Err(FrameMemfdError::SizeOutOfRange)
        ));
        assert!(matches!(
            RendererFrame::new(MAX_FRAME_BYTES + 1),
            Err(FrameMemfdError::SizeOutOfRange)
        ));

        let renderer = RendererFrame::new(64).expect("create renderer frame");
        assert!(matches!(
            ReadOnlyFrame::accept(renderer.descriptor(), 63),
            Err(FrameMemfdError::InvalidFile)
        ));
        assert!(matches!(
            ReadOnlyFrame::accept(renderer.descriptor(), 65),
            Err(FrameMemfdError::InvalidFile)
        ));
    }

    #[test]
    fn rejects_non_memfd_without_consuming_borrowed_descriptor() {
        let (stream, _peer) = UnixStream::pair().expect("create synthetic descriptor pair");
        let descriptor = stream.as_raw_fd();

        assert!(matches!(
            ReadOnlyFrame::accept(stream.as_fd(), 64),
            Err(FrameMemfdError::InvalidFile)
        ));
        assert_eq!(stream.as_raw_fd(), descriptor);
    }

    #[test]
    fn maps_every_native_status_and_redacts_diagnostics() {
        let expected = [
            Ok(()),
            Err(FrameMemfdError::InvalidArgument),
            Err(FrameMemfdError::SizeOutOfRange),
            Err(FrameMemfdError::Allocation),
            Err(FrameMemfdError::Creation),
            Err(FrameMemfdError::Sizing),
            Err(FrameMemfdError::Sealing),
            Err(FrameMemfdError::Ownership),
            Err(FrameMemfdError::InvalidFile),
            Err(FrameMemfdError::Mapping),
        ];
        for (status, expected) in (0_i32..).zip(expected) {
            assert_eq!(check(status), expected);
        }
        assert_eq!(check(-1), Err(FrameMemfdError::Unknown));
        assert_eq!(check(10), Err(FrameMemfdError::Unknown));
        for error in [FrameMemfdError::InvalidFile, FrameMemfdError::Unknown] {
            assert!(!error.to_string().contains('/'));
        }
    }
}

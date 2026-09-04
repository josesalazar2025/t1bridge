//! Safe ownership boundary for Touch Bar digitizer, Fn, and key synthesis I/O.

use std::{
    error::Error,
    fmt,
    os::fd::{AsRawFd, BorrowedFd},
    ptr::NonNull,
};

use crate::ffi;

pub const DIGITIZER_REPORT_SIZE: usize = 52;
const FN_BATCH_CAPACITY: usize = 32;
const DIGITIZER_READY: u32 = 1;
const FN_READY: u32 = 2;
const CLIENT_READABLE: u32 = 4;
const CLIENT_WRITABLE: u32 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TouchBarIoError {
    InvalidArgument,
    Discovery,
    AmbiguousDevice,
    Open,
    WrongFileType,
    WrongDevice,
    Io,
    Closed,
    MalformedInput,
    InsufficientCapacity,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeStatus {
    Complete,
    Idle,
    Resync,
}

impl NativeStatus {
    fn from_status(status: i32) -> Result<Self, TouchBarIoError> {
        match status {
            0 => Ok(Self::Complete),
            1 => Ok(Self::Idle),
            2 => Ok(Self::Resync),
            -1 => Err(TouchBarIoError::InvalidArgument),
            -2 => Err(TouchBarIoError::Discovery),
            -3 => Err(TouchBarIoError::AmbiguousDevice),
            -4 => Err(TouchBarIoError::Open),
            -5 => Err(TouchBarIoError::WrongFileType),
            -6 => Err(TouchBarIoError::WrongDevice),
            -7 => Err(TouchBarIoError::Io),
            -8 => Err(TouchBarIoError::Closed),
            -9 => Err(TouchBarIoError::MalformedInput),
            -10 => Err(TouchBarIoError::InsufficientCapacity),
            _ => Err(TouchBarIoError::Unknown),
        }
    }
}

impl fmt::Display for TouchBarIoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidArgument => "invalid Touch Bar I/O argument",
            Self::Discovery => "Touch Bar input device was not found",
            Self::AmbiguousDevice => "multiple Touch Bar input devices were found",
            Self::Open => "Touch Bar input device could not be opened",
            Self::WrongFileType => "Touch Bar input node has the wrong file type",
            Self::WrongDevice => "Touch Bar input device identity is invalid",
            Self::Io => "Touch Bar device I/O failed",
            Self::Closed => "Touch Bar input device closed",
            Self::MalformedInput => "Touch Bar input record is malformed",
            Self::InsufficientCapacity => "Touch Bar input batch exceeded its capacity",
            Self::Unknown => "unknown Touch Bar I/O failure",
        };
        formatter.write_str(message)
    }
}

impl Error for TouchBarIoError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DigitizerRead {
    Report([u8; DIGITIZER_REPORT_SIZE]),
    Idle,
}

/// Exclusive ownership of the dynamically discovered T1 hidraw digitizer.
pub struct TouchBarDigitizer {
    descriptor: std::os::fd::OwnedFd,
}

impl fmt::Debug for TouchBarDigitizer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TouchBarDigitizer")
            .finish_non_exhaustive()
    }
}

impl TouchBarDigitizer {
    /// Dynamically discovers and opens the unique validated digitizer.
    ///
    /// # Errors
    ///
    /// Returns [`TouchBarIoError`] if discovery, opening, or validation fails.
    pub fn open() -> Result<Self, TouchBarIoError> {
        let (status, descriptor) = ffi::open_touchbar_digitizer();
        match NativeStatus::from_status(status)? {
            NativeStatus::Complete => descriptor
                .map(|descriptor| Self { descriptor })
                .ok_or(TouchBarIoError::Unknown),
            NativeStatus::Idle | NativeStatus::Resync => Err(TouchBarIoError::Unknown),
        }
    }

    /// Waits for and reads one normalized 52-byte digitizer report.
    ///
    /// # Errors
    ///
    /// Returns [`TouchBarIoError`] for a closed device, malformed report, or I/O failure.
    pub fn read(&mut self, timeout_ms: u32) -> Result<DigitizerRead, TouchBarIoError> {
        let mut report = [0; DIGITIZER_REPORT_SIZE];
        match NativeStatus::from_status(ffi::read_touchbar_digitizer(
            self.descriptor.as_raw_fd(),
            timeout_ms,
            &mut report,
        ))? {
            NativeStatus::Complete => Ok(DigitizerRead::Report(report)),
            NativeStatus::Idle => Ok(DigitizerRead::Idle),
            NativeStatus::Resync => Err(TouchBarIoError::Unknown),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FnEdge {
    pub pressed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FnRead {
    Edges(Vec<FnEdge>),
    Idle,
    Resync,
}

/// Exclusive ownership of the dynamically discovered Fn input device.
pub struct TouchBarFnInput {
    descriptor: std::os::fd::OwnedFd,
}

impl fmt::Debug for TouchBarFnInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TouchBarFnInput")
            .finish_non_exhaustive()
    }
}

impl TouchBarFnInput {
    /// Dynamically discovers and opens the unique validated Apple SPI keyboard.
    ///
    /// # Errors
    ///
    /// Returns [`TouchBarIoError`] if discovery, opening, or validation fails.
    pub fn open() -> Result<Self, TouchBarIoError> {
        let (status, descriptor) = ffi::open_touchbar_fn();
        match NativeStatus::from_status(status)? {
            NativeStatus::Complete => descriptor
                .map(|descriptor| Self { descriptor })
                .ok_or(TouchBarIoError::Unknown),
            NativeStatus::Idle | NativeStatus::Resync => Err(TouchBarIoError::Unknown),
        }
    }

    /// Reads the current kernel Fn state for startup or resynchronization.
    ///
    /// # Errors
    ///
    /// Returns [`TouchBarIoError`] when the state query fails.
    pub fn pressed(&self) -> Result<bool, TouchBarIoError> {
        let (status, pressed) = ffi::touchbar_fn_state(self.descriptor.as_raw_fd());
        match NativeStatus::from_status(status)? {
            NativeStatus::Complete => Ok(pressed),
            NativeStatus::Idle | NativeStatus::Resync => Err(TouchBarIoError::Unknown),
        }
    }

    /// Drains one native batch of Fn press and release edges.
    ///
    /// # Errors
    ///
    /// Returns [`TouchBarIoError`] for a closed device, malformed input, or I/O failure.
    pub fn read(&mut self) -> Result<FnRead, TouchBarIoError> {
        let mut raw: [ffi::RawTouchBarFnEdge; FN_BATCH_CAPACITY] =
            std::array::from_fn(|_| ffi::RawTouchBarFnEdge { pressed: 0 });
        let (status, count) = ffi::read_touchbar_fn(self.descriptor.as_raw_fd(), &mut raw);
        match NativeStatus::from_status(status)? {
            NativeStatus::Complete if count <= raw.len() => Ok(FnRead::Edges(
                raw[..count]
                    .iter()
                    .map(|edge| FnEdge {
                        pressed: edge.pressed == 1,
                    })
                    .collect(),
            )),
            NativeStatus::Complete => Err(TouchBarIoError::Unknown),
            NativeStatus::Idle => Ok(FnRead::Idle),
            NativeStatus::Resync => Ok(FnRead::Resync),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadyInputs {
    pub digitizer: bool,
    pub function: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputWait {
    Ready(ReadyInputs),
    Idle,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ClientInterest {
    pub readable: bool,
    pub writable: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadyEvents {
    pub inputs: ReadyInputs,
    pub client_readable: bool,
    pub client_writable: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventWait {
    Ready(ReadyEvents),
    Idle,
}

/// Waits for either input source without consuming from either descriptor.
///
/// # Errors
///
/// Returns [`TouchBarIoError`] if polling fails or a device closes.
pub fn wait_inputs(
    digitizer: &TouchBarDigitizer,
    function: &TouchBarFnInput,
    timeout_ms: u32,
) -> Result<InputWait, TouchBarIoError> {
    let (status, ready) = ffi::wait_touchbar_inputs(
        digitizer.descriptor.as_raw_fd(),
        function.descriptor.as_raw_fd(),
        timeout_ms,
    );
    match NativeStatus::from_status(status)? {
        NativeStatus::Complete if ready != 0 && ready & !(DIGITIZER_READY | FN_READY) == 0 => {
            Ok(InputWait::Ready(ReadyInputs {
                digitizer: ready & DIGITIZER_READY != 0,
                function: ready & FN_READY != 0,
            }))
        }
        NativeStatus::Complete | NativeStatus::Resync => Err(TouchBarIoError::Unknown),
        NativeStatus::Idle => Ok(InputWait::Idle),
    }
}

/// Waits for hardware input and optional renderer socket readiness together.
///
/// # Errors
///
/// Returns [`TouchBarIoError`] if polling fails, a hardware device closes, or
/// the optional client has no requested readiness interest.
pub fn wait_events(
    digitizer: &TouchBarDigitizer,
    function: &TouchBarFnInput,
    client: Option<(BorrowedFd<'_>, ClientInterest)>,
    timeout_ms: u32,
) -> Result<EventWait, TouchBarIoError> {
    let (client_descriptor, client_interest) = match client {
        Some((descriptor, interest)) => {
            let mut bits = 0;
            if interest.readable {
                bits |= CLIENT_READABLE;
            }
            if interest.writable {
                bits |= CLIENT_WRITABLE;
            }
            (descriptor.as_raw_fd(), bits)
        }
        None => (-1, 0),
    };
    let (status, ready) = ffi::wait_touchbar_events(
        digitizer.descriptor.as_raw_fd(),
        function.descriptor.as_raw_fd(),
        client_descriptor,
        client_interest,
        timeout_ms,
    );
    match NativeStatus::from_status(status)? {
        NativeStatus::Complete
            if ready != 0
                && ready & !(DIGITIZER_READY | FN_READY | CLIENT_READABLE | CLIENT_WRITABLE)
                    == 0 =>
        {
            Ok(EventWait::Ready(ReadyEvents {
                inputs: ReadyInputs {
                    digitizer: ready & DIGITIZER_READY != 0,
                    function: ready & FN_READY != 0,
                },
                client_readable: ready & CLIENT_READABLE != 0,
                client_writable: ready & CLIENT_WRITABLE != 0,
            }))
        }
        NativeStatus::Complete | NativeStatus::Resync => Err(TouchBarIoError::Unknown),
        NativeStatus::Idle => Ok(EventWait::Idle),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
pub enum TouchBarKey {
    Escape = 0,
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

/// Exclusive ownership of the focused Escape/F1-F12 virtual keyboard.
pub struct TouchBarKeyboard {
    native: Option<NonNull<ffi::RawTouchBarKeyboard>>,
}

impl fmt::Debug for TouchBarKeyboard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TouchBarKeyboard")
            .finish_non_exhaustive()
    }
}

impl TouchBarKeyboard {
    /// Creates the focused virtual keyboard.
    ///
    /// # Errors
    ///
    /// Returns [`TouchBarIoError`] if uinput cannot be opened or configured.
    pub fn create() -> Result<Self, TouchBarIoError> {
        let (status, native) = ffi::create_touchbar_keyboard();
        match NativeStatus::from_status(status)? {
            NativeStatus::Complete => NonNull::new(native)
                .map(|native| Self {
                    native: Some(native),
                })
                .ok_or(TouchBarIoError::Unknown),
            NativeStatus::Idle | NativeStatus::Resync => Err(TouchBarIoError::Unknown),
        }
    }

    /// Emits one complete press/release tap for an allowlisted key.
    ///
    /// # Errors
    ///
    /// Returns [`TouchBarIoError`] if the event sequence cannot be written.
    pub fn tap(&mut self, key: TouchBarKey) -> Result<(), TouchBarIoError> {
        let native = self.native.ok_or(TouchBarIoError::Closed)?;
        match NativeStatus::from_status(ffi::tap_touchbar_key(native.as_ptr(), key as i32))? {
            NativeStatus::Complete => Ok(()),
            NativeStatus::Idle | NativeStatus::Resync => Err(TouchBarIoError::Unknown),
        }
    }

    /// Retries release of every key whose prior release was not confirmed.
    ///
    /// # Errors
    ///
    /// Returns [`TouchBarIoError`] if any release cannot be written.
    pub fn release_all(&mut self) -> Result<(), TouchBarIoError> {
        let native = self.native.ok_or(TouchBarIoError::Closed)?;
        match NativeStatus::from_status(ffi::release_touchbar_keys(native.as_ptr()))? {
            NativeStatus::Complete => Ok(()),
            NativeStatus::Idle | NativeStatus::Resync => Err(TouchBarIoError::Unknown),
        }
    }

    /// Releases held keys and consumes the virtual keyboard.
    ///
    /// # Errors
    ///
    /// Returns [`TouchBarIoError`] when release, destroy, or close fails.
    pub fn close(mut self) -> Result<(), TouchBarIoError> {
        let native = self.native.take().ok_or(TouchBarIoError::Closed)?;
        match NativeStatus::from_status(ffi::close_touchbar_keyboard(native.as_ptr()))? {
            NativeStatus::Complete => Ok(()),
            NativeStatus::Idle | NativeStatus::Resync => Err(TouchBarIoError::Unknown),
        }
    }
}

impl Drop for TouchBarKeyboard {
    fn drop(&mut self) {
        if let Some(native) = self.native.take() {
            let _ = ffi::close_touchbar_keyboard(native.as_ptr());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;

    #[test]
    fn maps_native_statuses_and_argument_failure() {
        assert_eq!(NativeStatus::from_status(0), Ok(NativeStatus::Complete));
        assert_eq!(NativeStatus::from_status(1), Ok(NativeStatus::Idle));
        assert_eq!(NativeStatus::from_status(2), Ok(NativeStatus::Resync));
        let expected = [
            TouchBarIoError::InvalidArgument,
            TouchBarIoError::Discovery,
            TouchBarIoError::AmbiguousDevice,
            TouchBarIoError::Open,
            TouchBarIoError::WrongFileType,
            TouchBarIoError::WrongDevice,
            TouchBarIoError::Io,
            TouchBarIoError::Closed,
            TouchBarIoError::MalformedInput,
            TouchBarIoError::InsufficientCapacity,
        ];
        for (status, error) in (-10_i32..=-1).rev().zip(expected) {
            assert_eq!(NativeStatus::from_status(status), Err(error));
        }
        assert_eq!(
            NativeStatus::from_status(i32::MIN),
            Err(TouchBarIoError::Unknown)
        );
    }

    #[test]
    fn input_wrappers_exclusively_own_their_descriptors() {
        let (digitizer, mut digitizer_peer) = UnixStream::pair().expect("digitizer pair");
        let wrapped = TouchBarDigitizer {
            descriptor: OwnedFd::from(digitizer),
        };
        drop(wrapped);
        let mut byte = [0_u8; 1];
        assert_eq!(digitizer_peer.read(&mut byte).expect("digitizer EOF"), 0);

        let (function, mut function_peer) = UnixStream::pair().expect("function pair");
        let wrapped = TouchBarFnInput {
            descriptor: OwnedFd::from(function),
        };
        drop(wrapped);
        assert_eq!(function_peer.read(&mut byte).expect("function EOF"), 0);
    }

    #[test]
    fn key_discriminants_match_the_native_allowlist() {
        let keys = [
            TouchBarKey::Escape,
            TouchBarKey::F1,
            TouchBarKey::F2,
            TouchBarKey::F3,
            TouchBarKey::F4,
            TouchBarKey::F5,
            TouchBarKey::F6,
            TouchBarKey::F7,
            TouchBarKey::F8,
            TouchBarKey::F9,
            TouchBarKey::F10,
            TouchBarKey::F11,
            TouchBarKey::F12,
        ];
        for (expected, key) in (0_i32..).zip(keys) {
            assert_eq!(key as i32, expected);
        }
    }
}

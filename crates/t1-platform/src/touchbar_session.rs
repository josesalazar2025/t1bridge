//! Active graphical-session admission and revocation for the Touch Bar service.

use std::ffi::{CStr, CString};
use std::fmt;
use std::marker::PhantomData;
use std::os::fd::BorrowedFd;
use std::ptr::NonNull;
use std::rc::Rc;

use crate::ffi;

/// Static, redaction-safe failure from session admission or monitoring.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TouchBarSessionError {
    InvalidArgument,
    Allocation,
    Monitor,
    Unavailable,
    PeerDenied,
    AlreadyAdmitted,
    NotAdmitted,
    Brightness,
    Unknown,
}

impl fmt::Display for TouchBarSessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidArgument => "invalid session argument",
            Self::Allocation => "session allocation failed",
            Self::Monitor => "session monitor failed",
            Self::Unavailable => "active session unavailable",
            Self::PeerDenied => "session peer denied",
            Self::AlreadyAdmitted => "session peer already admitted",
            Self::NotAdmitted => "session peer not admitted",
            Self::Brightness => "session brightness update failed",
            Self::Unknown => "unknown session failure",
        })
    }
}

impl std::error::Error for TouchBarSessionError {}

/// Poll inputs borrowed from a live session watch.
#[derive(Debug)]
pub struct SessionPollSource<'watch> {
    descriptor: BorrowedFd<'watch>,
    events: i32,
    timeout_monotonic_usec: Option<u64>,
}

impl SessionPollSource<'_> {
    /// Borrows the sd-login monitor descriptor.
    #[must_use]
    pub fn descriptor(&self) -> BorrowedFd<'_> {
        self.descriptor
    }

    /// Returns the native event mask requested from `poll(2)`.
    #[must_use]
    pub fn events(&self) -> i32 {
        self.events
    }

    /// Returns the absolute `CLOCK_MONOTONIC` deadline, or no deadline.
    #[must_use]
    pub fn timeout_monotonic_usec(&self) -> Option<u64> {
        self.timeout_monotonic_usec
    }
}

/// Result of flushing the monitor and revalidating an admitted peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[must_use]
pub enum SessionRevalidation {
    Retained,
    Revoked,
}

/// One fixed logind brightness subsystem available to the Touch Bar service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionBrightnessKind {
    Display,
    Keyboard,
}

impl SessionBrightnessKind {
    const fn subsystem(self) -> &'static CStr {
        match self {
            Self::Display => c"backlight",
            Self::Keyboard => c"leds",
        }
    }
}

/// Exclusive, thread-bound owner of one sd-login seat monitor and admission.
pub struct TouchBarSessionWatch {
    native: NonNull<ffi::RawTouchBarSessionWatch>,
    thread_bound: PhantomData<Rc<()>>,
}

impl fmt::Debug for TouchBarSessionWatch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TouchBarSessionWatch")
            .field("admitted", &self.is_admitted())
            .finish_non_exhaustive()
    }
}

impl TouchBarSessionWatch {
    /// Creates and initially flushes a monitor for systemd seat changes.
    ///
    /// # Errors
    ///
    /// Returns [`TouchBarSessionError`] if allocation or monitor setup fails.
    pub fn new() -> Result<Self, TouchBarSessionError> {
        let (status, native) = ffi::create_touchbar_session_watch();
        check(status)?;
        let native = NonNull::new(native).ok_or(TouchBarSessionError::Monitor)?;
        Ok(Self {
            native,
            thread_bound: PhantomData,
        })
    }

    /// Borrows the fd and readiness parameters for the sd-login monitor.
    ///
    /// A returned error clears any native admission. The service must release
    /// connection resources and synthesized keys before considering a new peer.
    ///
    /// # Errors
    ///
    /// Returns [`TouchBarSessionError::Monitor`] if the poll source is invalid.
    pub fn poll_source(&mut self) -> Result<SessionPollSource<'_>, TouchBarSessionError> {
        let (status, descriptor, events, timeout_usec) =
            ffi::touchbar_session_poll_source(&self.native);
        check(status)?;
        let descriptor = descriptor.ok_or(TouchBarSessionError::Monitor)?;
        Ok(SessionPollSource {
            descriptor,
            events,
            timeout_monotonic_usec: timeout_from_native(timeout_usec),
        })
    }

    /// Admits a kernel-derived non-root peer UID after two session snapshots.
    ///
    /// Group membership and `SO_PEERCRED` acquisition remain service concerns.
    /// Admission succeeds only for the active local non-remote Wayland/X11
    /// session on canonical `seat0`.
    ///
    /// # Errors
    ///
    /// Returns a static denial or operational error without session identity.
    pub fn admit(&mut self, peer_uid: u32) -> Result<(), TouchBarSessionError> {
        check(ffi::admit_touchbar_session(self.native.as_ptr(), peer_uid))
    }

    /// Flushes monitor changes and revalidates the exact admitted UID/session.
    ///
    /// [`SessionRevalidation::Revoked`] reports a confirmed seat transition.
    /// Any returned error also clears the native admission, so the service must
    /// perform the same connection and synthesized-key cleanup before retrying.
    ///
    /// # Errors
    ///
    /// Returns a static error if monitoring or session lookup cannot complete,
    /// or if no peer is currently admitted.
    pub fn refresh(&mut self) -> Result<SessionRevalidation, TouchBarSessionError> {
        revalidation_from_status(ffi::refresh_touchbar_session(self.native.as_ptr()))
    }

    /// Sets one dynamically discovered class device through the exact admitted
    /// logind session. Device names are values, never filesystem paths.
    ///
    /// # Errors
    ///
    /// Rejects an invalid name, missing admission, or failed logind operation.
    pub fn set_brightness(
        &mut self,
        kind: SessionBrightnessKind,
        device_name: &str,
        value: u32,
    ) -> Result<(), TouchBarSessionError> {
        let name = CString::new(device_name).map_err(|_| TouchBarSessionError::InvalidArgument)?;
        check(ffi::set_touchbar_session_brightness(
            self.native.as_ptr(),
            kind.subsystem(),
            &name,
            value,
        ))
    }

    /// Reports whether this monitor currently retains an admitted peer.
    #[must_use]
    pub fn is_admitted(&self) -> bool {
        ffi::touchbar_session_is_admitted(self.native.as_ptr())
    }

    /// Clears an admission after normal disconnect and retains the monitor.
    pub fn release(&mut self) {
        ffi::release_touchbar_session(self.native.as_ptr());
    }
}

impl Drop for TouchBarSessionWatch {
    fn drop(&mut self) {
        ffi::destroy_touchbar_session_watch(self.native.as_ptr());
    }
}

fn check(status: i32) -> Result<(), TouchBarSessionError> {
    match status {
        0 => Ok(()),
        1 => Err(TouchBarSessionError::InvalidArgument),
        2 => Err(TouchBarSessionError::Allocation),
        3 => Err(TouchBarSessionError::Monitor),
        4 => Err(TouchBarSessionError::Unavailable),
        5 => Err(TouchBarSessionError::PeerDenied),
        6 => Err(TouchBarSessionError::AlreadyAdmitted),
        7 => Err(TouchBarSessionError::NotAdmitted),
        9 => Err(TouchBarSessionError::Brightness),
        _ => Err(TouchBarSessionError::Unknown),
    }
}

fn revalidation_from_status(status: i32) -> Result<SessionRevalidation, TouchBarSessionError> {
    match status {
        0 => Ok(SessionRevalidation::Retained),
        8 => Ok(SessionRevalidation::Revoked),
        status => check(status).map(|()| SessionRevalidation::Retained),
    }
}

const fn timeout_from_native(timeout_usec: u64) -> Option<u64> {
    if timeout_usec == u64::MAX {
        None
    } else {
        Some(timeout_usec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_every_native_status_without_identity_detail() {
        let expected = [
            TouchBarSessionError::InvalidArgument,
            TouchBarSessionError::Allocation,
            TouchBarSessionError::Monitor,
            TouchBarSessionError::Unavailable,
            TouchBarSessionError::PeerDenied,
            TouchBarSessionError::AlreadyAdmitted,
            TouchBarSessionError::NotAdmitted,
        ];
        assert_eq!(check(0), Ok(()));
        for (status, error) in (1_i32..).zip(expected) {
            assert_eq!(check(status), Err(error));
            assert!(!error.to_string().contains('/'));
        }
        assert_eq!(check(8), Err(TouchBarSessionError::Unknown));
        assert_eq!(check(9), Err(TouchBarSessionError::Brightness));
        assert_eq!(check(i32::MAX), Err(TouchBarSessionError::Unknown));
    }

    #[test]
    fn maps_monitor_timeout_sentinel_without_clock_conversion() {
        assert_eq!(timeout_from_native(u64::MAX), None);
        assert_eq!(timeout_from_native(0), Some(0));
        assert_eq!(timeout_from_native(42), Some(42));
    }

    #[test]
    fn distinguishes_retention_revocation_and_revalidation_failure() {
        assert_eq!(
            revalidation_from_status(0),
            Ok(SessionRevalidation::Retained)
        );
        assert_eq!(
            revalidation_from_status(8),
            Ok(SessionRevalidation::Revoked)
        );
        assert_eq!(
            revalidation_from_status(3),
            Err(TouchBarSessionError::Monitor)
        );
        assert_eq!(
            revalidation_from_status(4),
            Err(TouchBarSessionError::Unavailable)
        );
    }
}

//! Exclusive locks and deferred signal observation for a guarded T1 USB cycle.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::ffi;

static PROCESS_GUARD_HELD: AtomicBool = AtomicBool::new(false);

/// Failure to acquire the cycle and SEP exclusion boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Busy,
    InvalidLock,
    System,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Busy => "another hardware operation is active",
            Self::InvalidLock => "hardware exclusion lock is unsafe",
            Self::System => "hardware exclusion could not be established",
        })
    }
}

impl std::error::Error for Error {}

/// Owns both exclusion locks and temporary signal handlers.
pub struct Guard {
    sep_acquired: bool,
}

impl Guard {
    /// Acquires the independent cycle lock and the shared SEP lock.
    ///
    /// # Errors
    ///
    /// Returns a fixed category when another operation owns either lock, a
    /// lock file is unsafe, or the native boundary cannot be established.
    pub fn acquire() -> Result<Self, Error> {
        if PROCESS_GUARD_HELD
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(Error::Busy);
        }
        let result = match ffi::acquire_usb_cycle_guard() {
            0 => Ok(Self {
                sep_acquired: false,
            }),
            1 => Err(Error::Busy),
            2 => Err(Error::InvalidLock),
            _ => Err(Error::System),
        };
        if result.is_err() {
            PROCESS_GUARD_HELD.store(false, Ordering::Release);
        }
        result
    }

    /// Acquires the shared SEP exclusion lock after dependent services stop.
    ///
    /// # Errors
    ///
    /// Returns a fixed category when an operation still owns SEP or the lock
    /// file is unsafe.
    pub fn acquire_sep(&mut self) -> Result<(), Error> {
        if self.sep_acquired {
            return Err(Error::InvalidLock);
        }
        match ffi::acquire_usb_cycle_sep_guard() {
            0 => {
                self.sep_acquired = true;
                Ok(())
            }
            1 => Err(Error::Busy),
            2 => Err(Error::InvalidLock),
            _ => Err(Error::System),
        }
    }

    /// Releases SEP while retaining cycle exclusion during service recovery.
    pub fn release_sep(&mut self) {
        if self.sep_acquired {
            ffi::release_usb_cycle_sep_guard();
            self.sep_acquired = false;
        }
    }

    /// Reports whether HUP, INT, or TERM arrived after acquisition.
    #[must_use]
    pub fn interrupted(&self) -> bool {
        ffi::usb_cycle_guard_interrupted()
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        ffi::release_usb_cycle_guard();
        PROCESS_GUARD_HELD.store(false, Ordering::Release);
    }
}

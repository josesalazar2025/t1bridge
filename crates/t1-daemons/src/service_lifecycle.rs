//! Owned process signal handling and systemd readiness for root services.

use std::fmt;
use std::marker::PhantomData;
use std::ptr::NonNull;
use std::rc::Rc;

use t1_platform::sep::SepCancellationSource;

use crate::service_lifecycle_ffi::{self, RawServiceLifecycle};

/// Static process-lifecycle failure without signal, socket, or path detail.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceLifecycleError {
    Install,
    Readiness,
    Restore,
}

impl fmt::Display for ServiceLifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Install => "service signal handlers could not be installed",
            Self::Readiness => "service readiness could not be reported",
            Self::Restore => "service signal handlers could not be restored",
        })
    }
}

impl std::error::Error for ServiceLifecycleError {}

/// Reports readiness for a service that uses the operating system's default
/// signal lifecycle.
///
/// # Errors
///
/// Returns a static error when no systemd notification socket accepts the
/// readiness message.
pub fn notify_ready_once() -> Result<(), ServiceLifecycleError> {
    if service_lifecycle_ffi::notify_ready_once() == 0 {
        Ok(())
    } else {
        Err(ServiceLifecycleError::Readiness)
    }
}

/// Thread-bound owner of the process SIGINT/SIGTERM dispositions.
pub struct ServiceLifecycle {
    native: Option<NonNull<RawServiceLifecycle>>,
    thread_bound: PhantomData<Rc<()>>,
}

impl ServiceLifecycle {
    /// Installs bounded-cancellation handlers, preserving prior dispositions.
    ///
    /// # Errors
    ///
    /// Returns a static error if handlers cannot be installed atomically or a
    /// lifecycle owner already exists in this process.
    pub fn install() -> Result<Self, ServiceLifecycleError> {
        let (status, native) = service_lifecycle_ffi::install();
        if status != 0 {
            return Err(ServiceLifecycleError::Install);
        }
        let native = NonNull::new(native).ok_or(ServiceLifecycleError::Install)?;
        Ok(Self {
            native: Some(native),
            thread_bound: PhantomData,
        })
    }

    /// Sends the fixed systemd readiness notification once.
    ///
    /// # Errors
    ///
    /// Returns a static error if no notification socket accepted readiness,
    /// cancellation already began, or readiness was already reported.
    pub fn notify_ready(&self) -> Result<(), ServiceLifecycleError> {
        let native = self.native.ok_or(ServiceLifecycleError::Readiness)?;
        if service_lifecycle_ffi::notify_ready(native.as_ptr()) == 0 {
            Ok(())
        } else {
            Err(ServiceLifecycleError::Readiness)
        }
    }

    /// Restores both prior signal dispositions and consumes this owner.
    ///
    /// # Errors
    ///
    /// Returns a static error if either disposition could not be restored.
    pub fn restore(mut self) -> Result<(), ServiceLifecycleError> {
        let native = self.native.take().ok_or(ServiceLifecycleError::Restore)?;
        if service_lifecycle_ffi::destroy(native.as_ptr()) == 0 {
            Ok(())
        } else {
            Err(ServiceLifecycleError::Restore)
        }
    }
}

impl SepCancellationSource for ServiceLifecycle {
    fn is_cancelled(&self) -> bool {
        self.native
            .is_none_or(|native| service_lifecycle_ffi::cancelled(native.as_ptr()))
    }
}

impl fmt::Debug for ServiceLifecycle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceLifecycle")
            .field("active", &self.native.is_some())
            .field("cancelled", &self.is_cancelled())
            .finish()
    }
}

impl Drop for ServiceLifecycle {
    fn drop(&mut self) {
        if let Some(native) = self.native.take() {
            let _ = service_lifecycle_ffi::destroy(native.as_ptr());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_are_static_and_redacted() {
        for error in [
            ServiceLifecycleError::Install,
            ServiceLifecycleError::Readiness,
            ServiceLifecycleError::Restore,
        ] {
            let message = error.to_string();
            assert!(!message.contains('/'));
            assert!(!message.contains("SIGINT"));
            assert!(!message.contains("SIGTERM"));
        }
    }
}

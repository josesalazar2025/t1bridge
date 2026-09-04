//! Keybag-relay handoff around one Touch ID authentication operation.

use core::fmt;
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

/// Runtime boundary for authentication relay control only.
///
/// `BridgeXPC` and SEP/keybag resources are deliberately caller-owned and cannot
/// be opened by this trait.
pub trait AuthenticationRelayRuntime {
    type Error;

    /// Reports whether the shared keybag relay is healthy before handoff.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe runtime failure.
    fn relay_is_active(&mut self) -> Result<bool, Self::Error>;

    /// Stops the shared relay before exclusive SEP acquisition.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe runtime failure. Even failure may race with a
    /// successful stop, so the coordinator will still attempt restart.
    fn stop_relay(&mut self) -> Result<(), Self::Error>;

    /// Restarts the shared keybag relay after any attempted stop.
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe recovery failure.
    fn start_relay(&mut self) -> Result<(), Self::Error>;
}

/// Stage of a caller-owned authentication lifecycle failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticationLifecycleStage {
    RelayHealth,
    RelayStop,
    RelayRecovery,
}

impl fmt::Display for AuthenticationLifecycleStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::RelayHealth => "keybag relay health check",
            Self::RelayStop => "keybag relay stop",
            Self::RelayRecovery => "keybag relay recovery",
        })
    }
}

/// A redaction-safe authentication lifecycle failure.
pub enum AuthenticationLifecycleError<RuntimeError, OperationError> {
    /// The shared keybag relay was not healthy before handoff.
    RelayInactive,
    /// The runtime failed at a lifecycle boundary.
    Runtime {
        stage: AuthenticationLifecycleStage,
        error: RuntimeError,
    },
    /// The inner authentication operation failed.
    Operation(OperationError),
}

impl<RuntimeError, OperationError> fmt::Debug
    for AuthenticationLifecycleError<RuntimeError, OperationError>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RelayInactive => formatter.write_str("RelayInactive"),
            Self::Runtime { stage, .. } => formatter
                .debug_struct("Runtime")
                .field("stage", stage)
                .field("error", &"[redacted]")
                .finish(),
            Self::Operation(_) => formatter.write_str("Operation([redacted])"),
        }
    }
}

impl<RuntimeError, OperationError> fmt::Display
    for AuthenticationLifecycleError<RuntimeError, OperationError>
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RelayInactive => {
                formatter.write_str("keybag relay is not active before authentication")
            }
            Self::Runtime { stage, .. } => write!(formatter, "authentication {stage} failed"),
            Self::Operation(_) => formatter.write_str("inner authentication operation failed"),
        }
    }
}

impl<RuntimeError, OperationError> std::error::Error
    for AuthenticationLifecycleError<RuntimeError, OperationError>
{
}

/// Runs caller-owned authentication setup after stopping the shared relay and
/// drops that setup before restarting the relay.
///
/// A healthy relay is required before mutation. Once relay stop is attempted,
/// restart is unconditionally attempted—even when stop reports failure. A
/// restart failure overrides every earlier outcome because shared keybag
/// service has not been recovered.
///
/// # Errors
///
/// Returns a redaction-safe relay, inner-operation, or mandatory-recovery
/// failure.
pub fn with_authentication_relay_handoff<Runtime, Operation, Success, OperationError>(
    runtime: &mut Runtime,
    operation: Operation,
) -> Result<Success, AuthenticationLifecycleError<Runtime::Error, OperationError>>
where
    Runtime: AuthenticationRelayRuntime,
    Operation: FnOnce(&mut Runtime) -> Result<Success, OperationError>,
{
    let relay_active =
        runtime
            .relay_is_active()
            .map_err(|error| AuthenticationLifecycleError::Runtime {
                stage: AuthenticationLifecycleStage::RelayHealth,
                error,
            })?;
    if !relay_active {
        return Err(AuthenticationLifecycleError::RelayInactive);
    }

    let primary = catch_unwind(AssertUnwindSafe(|| match runtime.stop_relay() {
        Ok(()) => operation(runtime).map_err(AuthenticationLifecycleError::Operation),
        Err(error) => Err(AuthenticationLifecycleError::Runtime {
            stage: AuthenticationLifecycleStage::RelayStop,
            error,
        }),
    }));

    let recovery = catch_unwind(AssertUnwindSafe(|| runtime.start_relay()));
    match recovery {
        Err(payload) => resume_unwind(payload),
        Ok(Err(error)) => Err(AuthenticationLifecycleError::Runtime {
            stage: AuthenticationLifecycleStage::RelayRecovery,
            error,
        }),
        Ok(Ok(())) => match primary {
            Ok(primary) => primary,
            Err(payload) => resume_unwind(payload),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum RuntimeFailure {
        Health,
        Stop,
        Restart,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct OperationFailure;

    struct FakeRuntime {
        calls: Vec<&'static str>,
        relay_active: Result<bool, RuntimeFailure>,
        stop: Result<(), RuntimeFailure>,
        restart: Result<(), RuntimeFailure>,
    }

    impl FakeRuntime {
        fn healthy() -> Self {
            Self {
                calls: Vec::new(),
                relay_active: Ok(true),
                stop: Ok(()),
                restart: Ok(()),
            }
        }
    }

    impl AuthenticationRelayRuntime for FakeRuntime {
        type Error = RuntimeFailure;

        fn relay_is_active(&mut self) -> Result<bool, Self::Error> {
            self.calls.push("relay-health");
            self.relay_active
        }

        fn stop_relay(&mut self) -> Result<(), Self::Error> {
            self.calls.push("relay-stop");
            self.stop
        }

        fn start_relay(&mut self) -> Result<(), Self::Error> {
            self.calls.push("relay-start");
            self.restart
        }
    }

    #[test]
    fn relay_handoff_brackets_all_caller_owned_resources() {
        let mut runtime = FakeRuntime::healthy();
        let result = with_authentication_relay_handoff(&mut runtime, |runtime| {
            runtime.calls.push("prepared-keybag-operation");
            Ok::<_, OperationFailure>(42)
        });

        assert_eq!(result.unwrap(), 42);
        assert_eq!(
            runtime.calls,
            [
                "relay-health",
                "relay-stop",
                "prepared-keybag-operation",
                "relay-start",
            ]
        );
    }

    #[test]
    fn an_attempted_stop_always_triggers_relay_recovery() {
        let mut runtime = FakeRuntime::healthy();
        runtime.stop = Err(RuntimeFailure::Stop);

        assert!(matches!(
            with_authentication_relay_handoff(&mut runtime, |_| Ok::<_, OperationFailure>(())),
            Err(AuthenticationLifecycleError::Runtime {
                stage: AuthenticationLifecycleStage::RelayStop,
                ..
            })
        ));
        assert_eq!(runtime.calls, ["relay-health", "relay-stop", "relay-start"]);
    }

    #[test]
    fn inactive_or_uncheckable_relay_stops_before_handoff() {
        let mut runtime = FakeRuntime::healthy();
        runtime.relay_active = Ok(false);
        assert!(matches!(
            with_authentication_relay_handoff(&mut runtime, |_| Ok::<_, OperationFailure>(())),
            Err(AuthenticationLifecycleError::RelayInactive)
        ));
        assert_eq!(runtime.calls, ["relay-health"]);

        let mut runtime = FakeRuntime::healthy();
        runtime.relay_active = Err(RuntimeFailure::Health);
        assert!(matches!(
            with_authentication_relay_handoff(&mut runtime, |_| Ok::<_, OperationFailure>(())),
            Err(AuthenticationLifecycleError::Runtime {
                stage: AuthenticationLifecycleStage::RelayHealth,
                ..
            })
        ));
        assert_eq!(runtime.calls, ["relay-health"]);
    }

    #[test]
    fn restart_failure_overrides_success_or_any_primary_failure() {
        for inner in [Ok(()), Err(OperationFailure)] {
            let mut runtime = FakeRuntime::healthy();
            runtime.restart = Err(RuntimeFailure::Restart);
            assert!(matches!(
                with_authentication_relay_handoff(&mut runtime, |_| inner),
                Err(AuthenticationLifecycleError::Runtime {
                    stage: AuthenticationLifecycleStage::RelayRecovery,
                    ..
                })
            ));
            assert_eq!(runtime.calls.last(), Some(&"relay-start"));
        }
    }

    #[test]
    fn diagnostics_and_source_chain_hide_runtime_and_operation_details() {
        let runtime_error: AuthenticationLifecycleError<&str, OperationFailure> =
            AuthenticationLifecycleError::Runtime {
                stage: AuthenticationLifecycleStage::RelayStop,
                error: "private runtime marker",
            };
        let operation_error: AuthenticationLifecycleError<RuntimeFailure, &str> =
            AuthenticationLifecycleError::Operation("private operation marker");

        for rendered in [
            format!("{runtime_error:?} {runtime_error}"),
            format!("{operation_error:?} {operation_error}"),
        ] {
            assert!(!rendered.contains("private runtime marker"));
            assert!(!rendered.contains("private operation marker"));
        }
        assert!(std::error::Error::source(&runtime_error).is_none());
        assert!(std::error::Error::source(&operation_error).is_none());
    }
}

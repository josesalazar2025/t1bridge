//! Transport-agnostic protected-policy update workflows.
//!
//! All timing and native-status classification stay with the caller. This
//! module owns read-before-write ordering, the existing bounded retry plan,
//! and mandatory readback verification.

use crate::commands::{
    CommandError, CommandPacket, set_system_configuration_command, set_user_configuration_command,
    system_configuration_command, user_configuration_command, validate_empty_response,
};
use crate::control::BiometricTransport;
use crate::policy::{
    BiometricUserId, PolicyError, PolicyUpdateDecision, PolicyUpdateObservation,
    SystemPolicyTarget, SystemProtectedConfiguration, UserPolicyRetry, UserProtectedConfiguration,
    parse_system_configuration, parse_user_configuration, user_touch_id_update,
    validate_system_configuration, verify_system_readback, verify_user_readback,
};
use core::convert::Infallible;
use core::fmt;
use core::time::Duration;

/// Classifies native setter failures and performs requested retry delays.
///
/// The workflow's [`UserPolicyRetry`] selects the exact bounded schedule. This
/// trait only maps a caller-owned transport failure to an optional signed
/// native status and acknowledges each requested delay deterministically.
pub trait UserPolicyRetryRuntime<TransportError> {
    /// Caller-owned deterministic wait failure.
    type WaitError;

    /// Returns a native status for policy-planner handling, or `None` when the
    /// original transport error must be propagated.
    fn native_status(&self, error: &TransportError) -> Option<i64>;

    /// Performs or records one exact delay selected by [`UserPolicyRetry`].
    ///
    /// # Errors
    ///
    /// Returns a redaction-safe caller-owned wait failure.
    fn wait(&mut self, delay: Duration) -> Result<(), Self::WaitError>;
}

/// Protected-policy workflow stage associated with a failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyWorkflowStage {
    /// Validate a caller-owned user, policy, or ACM credential.
    Validation,
    /// Read the current system protected configuration.
    SystemRead,
    /// Write the system protected configuration.
    SystemWrite,
    /// Read back the system protected configuration after a write.
    SystemReadback,
    /// Read the current per-user protected configuration.
    UserRead,
    /// Write the per-user protected configuration.
    UserWrite,
    /// Read back the per-user protected configuration after a write.
    UserReadback,
}

impl fmt::Display for PolicyWorkflowStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation => formatter.write_str("validation"),
            Self::SystemRead => formatter.write_str("system read"),
            Self::SystemWrite => formatter.write_str("system write"),
            Self::SystemReadback => formatter.write_str("system readback"),
            Self::UserRead => formatter.write_str("user read"),
            Self::UserWrite => formatter.write_str("user write"),
            Self::UserReadback => formatter.write_str("user readback"),
        }
    }
}

/// Redaction-safe protected-policy workflow failure.
pub enum PolicyWorkflowError<TransportError, WaitError> {
    /// A command packet or zero-capacity response was malformed.
    Command {
        /// Workflow stage that failed.
        stage: PolicyWorkflowStage,
        /// Structural packet or response failure.
        error: CommandError,
    },
    /// A fixed-layout policy record or readback failed validation.
    Policy {
        /// Workflow stage that failed.
        stage: PolicyWorkflowStage,
        /// Policy parser, input, or postcondition failure.
        error: PolicyError,
    },
    /// The caller-owned biometric transport failed without a classified
    /// native status.
    Transport {
        /// Workflow stage that failed.
        stage: PolicyWorkflowStage,
        /// Caller-owned transport failure.
        error: TransportError,
    },
    /// The deterministic retry runtime could not honor a requested delay.
    Wait(WaitError),
    /// The user-policy setter returned a classified non-retryable status.
    NativeStatus {
        /// Signed native status value.
        status: i64,
    },
}

/// System workflows never request a retry wait.
pub type SystemPolicyWorkflowError<TransportError> =
    PolicyWorkflowError<TransportError, Infallible>;

impl<TransportError, WaitError> fmt::Debug for PolicyWorkflowError<TransportError, WaitError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Command { stage, error } => formatter
                .debug_struct("Command")
                .field("stage", stage)
                .field("error", error)
                .finish(),
            Self::Policy { stage, error } => formatter
                .debug_struct("Policy")
                .field("stage", stage)
                .field("error", error)
                .finish(),
            Self::Transport { stage, .. } => formatter
                .debug_struct("Transport")
                .field("stage", stage)
                .field("error", &"[redacted]")
                .finish(),
            Self::Wait(_) => formatter.write_str("Wait([redacted])"),
            Self::NativeStatus { status } => formatter
                .debug_struct("NativeStatus")
                .field("status", status)
                .finish(),
        }
    }
}

impl<TransportError, WaitError> fmt::Display for PolicyWorkflowError<TransportError, WaitError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Command { stage, error } => {
                write!(
                    formatter,
                    "protected-policy {stage} command failed: {error}"
                )
            }
            Self::Policy { stage, error } => {
                write!(formatter, "protected-policy {stage} failed: {error}")
            }
            Self::Transport { stage, .. } => {
                write!(formatter, "protected-policy {stage} transport failed")
            }
            Self::Wait(_) => formatter.write_str("protected-policy retry wait failed"),
            Self::NativeStatus { status } => {
                write!(
                    formatter,
                    "user protected-policy update failed with status {status}"
                )
            }
        }
    }
}

impl<TransportError, WaitError> std::error::Error for PolicyWorkflowError<TransportError, WaitError>
where
    TransportError: std::error::Error + 'static,
    WaitError: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Command { error, .. } => Some(error),
            Self::Policy { error, .. } => Some(error),
            Self::Transport { .. } | Self::Wait(_) | Self::NativeStatus { .. } => None,
        }
    }
}

/// Enables one system Touch ID policy target with read-before-write/readback.
///
/// Existing mutable fields are validated before deciding whether a write is
/// needed. Unspecified fields remain owned by the existing command builder.
/// A malformed ACM credential is rejected before the setter is executed. An
/// already-matching policy returns after the initial read without a write.
///
/// # Errors
///
/// Returns a transport, command, configuration, credential, or readback
/// postcondition failure.
pub fn enable_system_touch_id<T: BiometricTransport>(
    transport: &mut T,
    target: SystemPolicyTarget,
    credential_set: Option<&[u8]>,
) -> Result<SystemProtectedConfiguration, SystemPolicyWorkflowError<T::Error>> {
    let before = read_system::<T, Infallible>(transport, PolicyWorkflowStage::SystemRead)?;
    validate_system_configuration(before).map_err(|error| PolicyWorkflowError::Policy {
        stage: PolicyWorkflowStage::SystemRead,
        error,
    })?;
    if system_matches(target, before) {
        return Ok(before);
    }

    let update = set_system_configuration_command(target, credential_set).map_err(|error| {
        PolicyWorkflowError::Command {
            stage: PolicyWorkflowStage::Validation,
            error,
        }
    })?;
    let response = execute::<T, Infallible>(transport, &update, PolicyWorkflowStage::SystemWrite)?;
    validate_empty_response(&response).map_err(|error| PolicyWorkflowError::Command {
        stage: PolicyWorkflowStage::SystemWrite,
        error,
    })?;

    let after = read_system::<T, Infallible>(transport, PolicyWorkflowStage::SystemReadback)?;
    verify_system_readback(target, after).map_err(|error| PolicyWorkflowError::Policy {
        stage: PolicyWorkflowStage::SystemReadback,
        error,
    })?;
    Ok(after)
}

/// Enables per-user unlock, identification, and login while preserving the
/// current requested Apple Pay policy.
///
/// A matching initial policy returns without mutation. Otherwise, the setter
/// packet is fully validated before execution and reused byte-for-byte across
/// the existing bounded `EBUSY` retry schedule.
///
/// # Errors
///
/// Returns a validation, transport, retry-wait, native-status, response, or
/// mandatory readback failure.
pub fn enable_user_touch_id<T, R>(
    transport: &mut T,
    retry_runtime: &mut R,
    user_id: i64,
    credential_set: Option<&[u8]>,
) -> Result<UserProtectedConfiguration, PolicyWorkflowError<T::Error, R::WaitError>>
where
    T: BiometricTransport,
    R: UserPolicyRetryRuntime<T::Error>,
{
    let user = validate_user::<T::Error, R::WaitError>(user_id)?;
    let before = read_user(transport, user, PolicyWorkflowStage::UserRead)?;
    let Some(requested) =
        user_touch_id_update(before).map_err(|error| PolicyWorkflowError::Policy {
            stage: PolicyWorkflowStage::UserRead,
            error,
        })?
    else {
        return Ok(before);
    };
    apply_user_policy(transport, retry_runtime, user, requested, credential_set)
}

/// Reapplies all four current requested per-user policy values unchanged.
///
/// This preserves Apple Pay and every other requested field while registering
/// the user through Mesa's native setter. The complete current record is read
/// before the update and the requested values are read back exactly afterward.
///
/// # Errors
///
/// Returns a validation, transport, retry-wait, native-status, response, or
/// mandatory readback failure.
pub fn reassert_user_policy<T, R>(
    transport: &mut T,
    retry_runtime: &mut R,
    user_id: i64,
    credential_set: Option<&[u8]>,
) -> Result<UserProtectedConfiguration, PolicyWorkflowError<T::Error, R::WaitError>>
where
    T: BiometricTransport,
    R: UserPolicyRetryRuntime<T::Error>,
{
    let user = validate_user::<T::Error, R::WaitError>(user_id)?;
    let before = read_user(transport, user, PolicyWorkflowStage::UserRead)?;
    apply_user_policy(
        transport,
        retry_runtime,
        user,
        before.requested_values(),
        credential_set,
    )
}

fn apply_user_policy<T, R>(
    transport: &mut T,
    retry_runtime: &mut R,
    user: BiometricUserId,
    requested: [i32; 4],
    credential_set: Option<&[u8]>,
) -> Result<UserProtectedConfiguration, PolicyWorkflowError<T::Error, R::WaitError>>
where
    T: BiometricTransport,
    R: UserPolicyRetryRuntime<T::Error>,
{
    let update =
        set_user_configuration_command(user, requested, credential_set).map_err(|error| {
            PolicyWorkflowError::Command {
                stage: PolicyWorkflowStage::Validation,
                error,
            }
        })?;
    let mut retry = UserPolicyRetry::default();
    let require_effective_equality = loop {
        let observation = match transport.execute(&update) {
            Ok(response) => PolicyUpdateObservation::Response {
                data_len: response.len(),
            },
            Err(error) => {
                let Some(status) = retry_runtime.native_status(&error) else {
                    return Err(PolicyWorkflowError::Transport {
                        stage: PolicyWorkflowStage::UserWrite,
                        error,
                    });
                };
                PolicyUpdateObservation::Failure { status }
            }
        };

        match retry.observe(observation) {
            PolicyUpdateDecision::RetryAfter(delay) => {
                retry_runtime
                    .wait(delay)
                    .map_err(PolicyWorkflowError::Wait)?;
            }
            PolicyUpdateDecision::ReadBack => break false,
            PolicyUpdateDecision::ReadBackAfterBusy => break true,
            PolicyUpdateDecision::RejectUnexpectedData { actual } => {
                return Err(PolicyWorkflowError::Command {
                    stage: PolicyWorkflowStage::UserWrite,
                    error: CommandError::UnexpectedResponseData { actual },
                });
            }
            PolicyUpdateDecision::Fail { status } => {
                return Err(PolicyWorkflowError::NativeStatus { status });
            }
        }
    };

    let after = read_user(transport, user, PolicyWorkflowStage::UserReadback)?;
    verify_user_readback(requested, after, require_effective_equality).map_err(|error| {
        PolicyWorkflowError::Policy {
            stage: PolicyWorkflowStage::UserReadback,
            error,
        }
    })?;
    Ok(after)
}

fn validate_user<TransportError, WaitError>(
    user_id: i64,
) -> Result<BiometricUserId, PolicyWorkflowError<TransportError, WaitError>> {
    BiometricUserId::new(user_id).map_err(|error| PolicyWorkflowError::Policy {
        stage: PolicyWorkflowStage::Validation,
        error,
    })
}

fn system_matches(target: SystemPolicyTarget, configuration: SystemProtectedConfiguration) -> bool {
    match target {
        SystemPolicyTarget::TouchId => configuration.touch_id_enabled == 1,
        SystemPolicyTarget::TouchIdFeatures => configuration.policy_values() == [1; 4],
    }
}

fn read_system<T, WaitError>(
    transport: &mut T,
    stage: PolicyWorkflowStage,
) -> Result<SystemProtectedConfiguration, PolicyWorkflowError<T::Error, WaitError>>
where
    T: BiometricTransport,
{
    let response = execute(transport, &system_configuration_command(), stage)?;
    parse_system_configuration(&response)
        .map_err(|error| PolicyWorkflowError::Policy { stage, error })
}

fn read_user<T, WaitError>(
    transport: &mut T,
    user: BiometricUserId,
    stage: PolicyWorkflowStage,
) -> Result<UserProtectedConfiguration, PolicyWorkflowError<T::Error, WaitError>>
where
    T: BiometricTransport,
{
    let response = execute(transport, &user_configuration_command(user), stage)?;
    parse_user_configuration(&response)
        .map_err(|error| PolicyWorkflowError::Policy { stage, error })
}

fn execute<T, WaitError>(
    transport: &mut T,
    packet: &CommandPacket,
    stage: PolicyWorkflowStage,
) -> Result<Vec<u8>, PolicyWorkflowError<T::Error, WaitError>>
where
    T: BiometricTransport,
{
    transport
        .execute(packet)
        .map_err(|error| PolicyWorkflowError::Transport { stage, error })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{EBUSY_STATUS, KIORETURN_TIMEOUT_STATUS, USER_POLICY_BUSY_RETRY_DELAYS};
    use std::collections::VecDeque;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct SyntheticTransportError {
        status: Option<i64>,
    }

    impl fmt::Display for SyntheticTransportError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("private transport marker")
        }
    }

    impl std::error::Error for SyntheticTransportError {}

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct SyntheticWaitError;

    impl fmt::Display for SyntheticWaitError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("private wait marker")
        }
    }

    impl std::error::Error for SyntheticWaitError {}

    struct FakeTransport {
        responses: VecDeque<Result<Vec<u8>, SyntheticTransportError>>,
        requests: Vec<Vec<u8>>,
        capacities: Vec<usize>,
    }

    impl FakeTransport {
        fn new(
            responses: impl IntoIterator<Item = Result<Vec<u8>, SyntheticTransportError>>,
        ) -> Self {
            Self {
                responses: responses.into_iter().collect(),
                requests: Vec::new(),
                capacities: Vec::new(),
            }
        }

        fn commands(&self) -> Vec<u16> {
            self.requests
                .iter()
                .map(|request| {
                    u16::from_le_bytes(request[2..4].try_into().expect("complete command"))
                })
                .collect()
        }
    }

    impl BiometricTransport for FakeTransport {
        type Error = SyntheticTransportError;

        fn execute(&mut self, packet: &CommandPacket) -> Result<Vec<u8>, Self::Error> {
            self.requests.push(packet.request().to_vec());
            self.capacities.push(packet.response_capacity());
            self.responses
                .pop_front()
                .expect("synthetic response for every command")
        }
    }

    struct FakeRetryRuntime {
        delays: Vec<Duration>,
        fail_wait_at: Option<usize>,
    }

    impl FakeRetryRuntime {
        const fn new() -> Self {
            Self {
                delays: Vec::new(),
                fail_wait_at: None,
            }
        }
    }

    impl UserPolicyRetryRuntime<SyntheticTransportError> for FakeRetryRuntime {
        type WaitError = SyntheticWaitError;

        fn native_status(&self, error: &SyntheticTransportError) -> Option<i64> {
            error.status
        }

        fn wait(&mut self, delay: Duration) -> Result<(), Self::WaitError> {
            self.delays.push(delay);
            if self.fail_wait_at == Some(self.delays.len()) {
                Err(SyntheticWaitError)
            } else {
                Ok(())
            }
        }
    }

    fn transport_error(status: Option<i64>) -> Result<Vec<u8>, SyntheticTransportError> {
        Err(SyntheticTransportError { status })
    }

    fn encode_i32s<const COUNT: usize>(values: [i32; COUNT]) -> Vec<u8> {
        values.into_iter().flat_map(i32::to_le_bytes).collect()
    }

    fn system(values: [i32; 7]) -> Vec<u8> {
        encode_i32s(values)
    }

    fn user(values: [i32; 8]) -> Vec<u8> {
        encode_i32s(values)
    }

    fn empty() -> Vec<u8> {
        Vec::new()
    }

    #[test]
    fn system_global_update_is_read_write_readback() {
        let before = [-1, -1, -1, -1, 0, 1, -1];
        let after = [-1, -1, -1, 1, 0, 1, -1];
        let mut transport =
            FakeTransport::new([Ok(system(before)), Ok(empty()), Ok(system(after))]);
        let result =
            enable_system_touch_id(&mut transport, SystemPolicyTarget::TouchId, None).unwrap();

        assert_eq!(result.touch_id_enabled, 1);
        assert_eq!(transport.commands(), [0x43, 0x44, 0x43]);
        assert_eq!(transport.capacities, [28, 0, 28]);
        assert_eq!(
            &transport.requests[1][8..36],
            encode_i32s([-1, -1, -1, 1, -1, -1, -1])
        );
        assert_eq!(&transport.requests[1][36..40], &1_u32.to_le_bytes());
    }

    #[test]
    fn system_features_update_uses_credential_and_exact_readback() {
        let before = [-1, -1, -1, 1, 0, -1, 0];
        let after = [-1, -1, -1, 1, 1, 1, 1];
        let credential = [0x5a; 16];
        let mut transport =
            FakeTransport::new([Ok(system(before)), Ok(empty()), Ok(system(after))]);
        let result = enable_system_touch_id(
            &mut transport,
            SystemPolicyTarget::TouchIdFeatures,
            Some(&credential),
        )
        .unwrap();

        assert_eq!(result.policy_values(), [1; 4]);
        assert_eq!(
            &transport.requests[1][8..36],
            encode_i32s([-1, -1, -1, 1, 1, 1, 1])
        );
        assert_eq!(&transport.requests[1][44..60], &credential);
    }

    #[test]
    fn matching_system_policy_skips_write_and_unknown_policy_fails() {
        let matching = [300, -1, -1, 1, 1, 1, 1];
        let mut transport = FakeTransport::new([Ok(system(matching))]);
        let result = enable_system_touch_id(
            &mut transport,
            SystemPolicyTarget::TouchIdFeatures,
            Some(&[0; 15]),
        )
        .unwrap();
        assert_eq!(result.policy_values(), [1; 4]);
        assert_eq!(transport.commands(), [0x43]);

        let mut transport = FakeTransport::new([Ok(system([300, -1, -1, 0, 7, 0, 0]))]);
        assert!(matches!(
            enable_system_touch_id(&mut transport, SystemPolicyTarget::TouchId, None),
            Err(PolicyWorkflowError::Policy {
                stage: PolicyWorkflowStage::SystemRead,
                error: PolicyError::UnrecognizedPolicyValue,
            })
        ));
        assert_eq!(transport.commands(), [0x43]);
    }

    #[test]
    fn system_credential_and_write_response_fail_before_readback() {
        let before = [-1; 7];
        let mut transport = FakeTransport::new([Ok(system(before))]);
        assert!(matches!(
            enable_system_touch_id(&mut transport, SystemPolicyTarget::TouchId, Some(&[0; 15])),
            Err(PolicyWorkflowError::Command {
                stage: PolicyWorkflowStage::Validation,
                ..
            })
        ));
        assert_eq!(transport.commands(), [0x43]);

        let mut transport = FakeTransport::new([Ok(system(before)), Ok(vec![0xaa])]);
        assert!(matches!(
            enable_system_touch_id(&mut transport, SystemPolicyTarget::TouchId, None),
            Err(PolicyWorkflowError::Command {
                stage: PolicyWorkflowStage::SystemWrite,
                ..
            })
        ));
        assert_eq!(transport.commands(), [0x43, 0x44]);
    }

    #[test]
    fn system_transport_and_readback_failures_never_claim_success() {
        let before = [-1; 7];
        let mut transport = FakeTransport::new([Ok(system(before)), transport_error(None)]);
        assert!(matches!(
            enable_system_touch_id(&mut transport, SystemPolicyTarget::TouchId, None),
            Err(PolicyWorkflowError::Transport {
                stage: PolicyWorkflowStage::SystemWrite,
                ..
            })
        ));

        let mut transport =
            FakeTransport::new([Ok(system(before)), Ok(empty()), Ok(system(before))]);
        assert!(matches!(
            enable_system_touch_id(&mut transport, SystemPolicyTarget::TouchId, None),
            Err(PolicyWorkflowError::Policy {
                stage: PolicyWorkflowStage::SystemReadback,
                error: PolicyError::PolicyReadbackMismatch,
            })
        ));

        let mut transport = FakeTransport::new([Ok(system(before)), Ok(empty()), Ok(vec![0; 27])]);
        assert!(matches!(
            enable_system_touch_id(&mut transport, SystemPolicyTarget::TouchId, None),
            Err(PolicyWorkflowError::Policy {
                stage: PolicyWorkflowStage::SystemReadback,
                error: PolicyError::InvalidConfigurationLength { .. },
            })
        ));
    }

    #[test]
    fn transport_failures_report_the_exact_read_stage() {
        let before = [-1; 7];
        let mut transport = FakeTransport::new([transport_error(None)]);
        assert!(matches!(
            enable_system_touch_id(&mut transport, SystemPolicyTarget::TouchId, None),
            Err(PolicyWorkflowError::Transport {
                stage: PolicyWorkflowStage::SystemRead,
                ..
            })
        ));

        let mut transport =
            FakeTransport::new([Ok(system(before)), Ok(empty()), transport_error(None)]);
        assert!(matches!(
            enable_system_touch_id(&mut transport, SystemPolicyTarget::TouchId, None),
            Err(PolicyWorkflowError::Transport {
                stage: PolicyWorkflowStage::SystemReadback,
                ..
            })
        ));

        let mut runtime = FakeRetryRuntime::new();
        let mut transport = FakeTransport::new([transport_error(None)]);
        assert!(matches!(
            enable_user_touch_id(&mut transport, &mut runtime, 501, None),
            Err(PolicyWorkflowError::Transport {
                stage: PolicyWorkflowStage::UserRead,
                ..
            })
        ));

        let current = [1, 1, 1, 0, 0, 0, 0, 0];
        let mut transport =
            FakeTransport::new([Ok(user(current)), Ok(empty()), transport_error(None)]);
        assert!(matches!(
            reassert_user_policy(&mut transport, &mut runtime, 501, None),
            Err(PolicyWorkflowError::Transport {
                stage: PolicyWorkflowStage::UserReadback,
                ..
            })
        ));
    }

    #[test]
    fn user_enable_preserves_apple_pay_and_reads_back_exact_request() {
        let before = [-1, 0, -1, 0, 0, 0, 0, 0];
        let after = [1, 1, 1, 0, 0, 0, 0, 0];
        let credential = [0x6b; 16];
        let mut transport = FakeTransport::new([Ok(user(before)), Ok(empty()), Ok(user(after))]);
        let mut runtime = FakeRetryRuntime::new();
        let result =
            enable_user_touch_id(&mut transport, &mut runtime, 501, Some(&credential)).unwrap();

        assert_eq!(result.requested_values(), [1, 1, 1, 0]);
        assert_eq!(transport.commands(), [0x2e, 0x2f, 0x2e]);
        assert_eq!(transport.capacities, [32, 0, 32]);
        assert_eq!(
            &transport.requests[1][8..28],
            encode_i32s([501, 1, 1, 1, 0])
        );
        assert_eq!(&transport.requests[1][36..52], &credential);
        assert!(runtime.delays.is_empty());
    }

    #[test]
    fn matching_user_skips_write_and_unknown_apple_pay_fails() {
        let matching = [1, 1, 1, -1, 0, 0, 0, 0];
        let mut transport = FakeTransport::new([Ok(user(matching))]);
        let mut runtime = FakeRetryRuntime::new();
        let result =
            enable_user_touch_id(&mut transport, &mut runtime, 501, Some(&[0; 15])).unwrap();
        assert_eq!(result.requested_values(), [1, 1, 1, -1]);
        assert_eq!(transport.commands(), [0x2e]);

        let mut transport = FakeTransport::new([Ok(user([0, 0, 0, 9, 0, 0, 0, 9]))]);
        assert!(matches!(
            enable_user_touch_id(&mut transport, &mut runtime, 501, None),
            Err(PolicyWorkflowError::Policy {
                stage: PolicyWorkflowStage::UserRead,
                error: PolicyError::UnrecognizedPolicyValue,
            })
        ));
        assert_eq!(transport.commands(), [0x2e]);
    }

    #[test]
    fn reassert_preserves_all_requested_fields() {
        let current = [1, 0, -1, 1, 0, 0, 0, 0];
        let mut transport = FakeTransport::new([Ok(user(current)), Ok(empty()), Ok(user(current))]);
        let mut runtime = FakeRetryRuntime::new();
        let result = reassert_user_policy(&mut transport, &mut runtime, 501, None).unwrap();

        assert_eq!(result.requested_values(), [1, 0, -1, 1]);
        assert_eq!(transport.commands(), [0x2e, 0x2f, 0x2e]);
        assert_eq!(
            &transport.requests[1][8..28],
            encode_i32s([501, 1, 0, -1, 1])
        );
        assert_eq!(&transport.requests[1][28..32], &1_u32.to_le_bytes());
    }

    #[test]
    fn user_busy_retries_identical_request_on_exact_schedule() {
        let current = [1, 1, 1, 0, 0, 0, 0, 0];
        let mut transport = FakeTransport::new([
            Ok(user(current)),
            transport_error(Some(EBUSY_STATUS)),
            transport_error(Some(EBUSY_STATUS)),
            Ok(empty()),
            Ok(user(current)),
        ]);
        let mut runtime = FakeRetryRuntime::new();
        let result =
            reassert_user_policy(&mut transport, &mut runtime, 501, Some(&[0x7c; 16])).unwrap();

        assert_eq!(result.effective_values(), [0; 4]);
        assert_eq!(runtime.delays, USER_POLICY_BUSY_RETRY_DELAYS[..2]);
        assert_eq!(transport.commands(), [0x2e, 0x2f, 0x2f, 0x2f, 0x2e]);
        assert_eq!(transport.requests[1], transport.requests[2]);
        assert_eq!(transport.requests[2], transport.requests[3]);
    }

    #[test]
    fn persistent_busy_requires_effective_readback_and_wait_failure_stops() {
        let current = [1, 1, 1, 0, 1, 1, 1, 0];
        let mut responses = vec![Ok(user(current))];
        responses.extend((0..4).map(|_| transport_error(Some(EBUSY_STATUS))));
        responses.push(Ok(user(current)));
        let mut transport = FakeTransport::new(responses);
        let mut runtime = FakeRetryRuntime::new();
        reassert_user_policy(&mut transport, &mut runtime, 501, None).unwrap();
        assert_eq!(runtime.delays, USER_POLICY_BUSY_RETRY_DELAYS);
        assert_eq!(transport.commands(), [0x2e, 0x2f, 0x2f, 0x2f, 0x2f, 0x2e]);

        for divergent in [[1, 1, 1, 0, 1, 0, 1, 0], [1, 0, 1, 0, 1, 0, 1, 0]] {
            let mut responses = vec![Ok(user(current))];
            responses.extend((0..4).map(|_| transport_error(Some(EBUSY_STATUS))));
            responses.push(Ok(user(divergent)));
            let mut transport = FakeTransport::new(responses);
            let mut runtime = FakeRetryRuntime::new();
            assert!(matches!(
                reassert_user_policy(&mut transport, &mut runtime, 501, None),
                Err(PolicyWorkflowError::Policy {
                    stage: PolicyWorkflowStage::UserReadback,
                    error: PolicyError::PolicyReadbackMismatch,
                })
            ));
        }

        let mut transport =
            FakeTransport::new([Ok(user(current)), transport_error(Some(EBUSY_STATUS))]);
        let mut runtime = FakeRetryRuntime {
            delays: Vec::new(),
            fail_wait_at: Some(1),
        };
        assert!(matches!(
            reassert_user_policy(&mut transport, &mut runtime, 501, None),
            Err(PolicyWorkflowError::Wait(SyntheticWaitError))
        ));
        assert_eq!(transport.commands(), [0x2e, 0x2f]);
    }

    #[test]
    fn non_busy_failure_short_circuits_an_active_busy_schedule() {
        let current = [1, 1, 1, 0, 1, 1, 1, 0];
        let mut transport = FakeTransport::new([
            Ok(user(current)),
            transport_error(Some(EBUSY_STATUS)),
            transport_error(Some(77)),
        ]);
        let mut runtime = FakeRetryRuntime::new();
        assert!(matches!(
            reassert_user_policy(&mut transport, &mut runtime, 501, None),
            Err(PolicyWorkflowError::NativeStatus { status: 77 })
        ));
        assert_eq!(runtime.delays, USER_POLICY_BUSY_RETRY_DELAYS[..1]);
        assert_eq!(transport.commands(), [0x2e, 0x2f, 0x2f]);
    }

    #[test]
    fn ambiguous_timeout_requires_matching_readback() {
        let before = [0, 0, 0, 0, 0, 0, 0, 0];
        let after = [1, 1, 1, 0, 0, 0, 0, 0];
        let mut transport = FakeTransport::new([
            Ok(user(before)),
            transport_error(Some(KIORETURN_TIMEOUT_STATUS)),
            Ok(user(after)),
        ]);
        let mut runtime = FakeRetryRuntime::new();
        let result = enable_user_touch_id(&mut transport, &mut runtime, 501, None).unwrap();
        assert_eq!(result.requested_values(), [1, 1, 1, 0]);

        let mut transport = FakeTransport::new([
            Ok(user(before)),
            transport_error(Some(KIORETURN_TIMEOUT_STATUS)),
            Ok(user(before)),
        ]);
        assert!(matches!(
            enable_user_touch_id(&mut transport, &mut runtime, 501, None),
            Err(PolicyWorkflowError::Policy {
                stage: PolicyWorkflowStage::UserReadback,
                error: PolicyError::PolicyReadbackMismatch,
            })
        ));
    }

    #[test]
    fn other_user_write_failures_and_data_are_not_retried() {
        let current = [1, 1, 1, 0, 0, 0, 0, 0];
        let mut runtime = FakeRetryRuntime::new();
        let mut transport = FakeTransport::new([Ok(user(current)), transport_error(Some(77))]);
        assert!(matches!(
            reassert_user_policy(&mut transport, &mut runtime, 501, None),
            Err(PolicyWorkflowError::NativeStatus { status: 77 })
        ));
        assert!(runtime.delays.is_empty());

        let mut transport = FakeTransport::new([Ok(user(current)), transport_error(None)]);
        assert!(matches!(
            reassert_user_policy(&mut transport, &mut runtime, 501, None),
            Err(PolicyWorkflowError::Transport {
                stage: PolicyWorkflowStage::UserWrite,
                ..
            })
        ));

        let mut transport = FakeTransport::new([Ok(user(current)), Ok(vec![0xaa])]);
        assert!(matches!(
            reassert_user_policy(&mut transport, &mut runtime, 501, None),
            Err(PolicyWorkflowError::Command {
                stage: PolicyWorkflowStage::UserWrite,
                ..
            })
        ));
        assert_eq!(transport.commands(), [0x2e, 0x2f]);
    }

    #[test]
    fn user_validation_initial_read_and_readback_fail_closed() {
        let mut transport = FakeTransport::new([]);
        let mut runtime = FakeRetryRuntime::new();
        assert!(matches!(
            enable_user_touch_id(&mut transport, &mut runtime, -1, None),
            Err(PolicyWorkflowError::Policy {
                stage: PolicyWorkflowStage::Validation,
                error: PolicyError::UserIdOutOfRange,
            })
        ));
        assert!(transport.requests.is_empty());

        let mut transport = FakeTransport::new([Ok(vec![0; 31])]);
        assert!(matches!(
            enable_user_touch_id(&mut transport, &mut runtime, 501, None),
            Err(PolicyWorkflowError::Policy {
                stage: PolicyWorkflowStage::UserRead,
                error: PolicyError::InvalidConfigurationLength { .. },
            })
        ));

        let current = [1, 0, -1, 1, 0, 0, 0, 0];
        let mut transport = FakeTransport::new([Ok(user(current))]);
        assert!(matches!(
            reassert_user_policy(&mut transport, &mut runtime, 501, Some(&[0; 15])),
            Err(PolicyWorkflowError::Command {
                stage: PolicyWorkflowStage::Validation,
                ..
            })
        ));
        assert_eq!(transport.commands(), [0x2e]);

        let mut transport = FakeTransport::new([Ok(user([1, 0, 7, 1, 0, 0, 0, 0]))]);
        assert!(matches!(
            reassert_user_policy(&mut transport, &mut runtime, 501, None),
            Err(PolicyWorkflowError::Command {
                stage: PolicyWorkflowStage::Validation,
                ..
            })
        ));
        assert_eq!(transport.commands(), [0x2e]);

        let mut transport = FakeTransport::new([Ok(user(current)), Ok(empty()), Ok(user([0; 8]))]);
        assert!(matches!(
            reassert_user_policy(&mut transport, &mut runtime, 501, None),
            Err(PolicyWorkflowError::Policy {
                stage: PolicyWorkflowStage::UserReadback,
                error: PolicyError::PolicyReadbackMismatch,
            })
        ));
    }

    #[test]
    fn errors_hide_transport_and_wait_details() {
        let transport_error: PolicyWorkflowError<SyntheticTransportError, SyntheticWaitError> =
            PolicyWorkflowError::Transport {
                stage: PolicyWorkflowStage::UserWrite,
                error: SyntheticTransportError { status: None },
            };
        let wait_error: PolicyWorkflowError<SyntheticTransportError, SyntheticWaitError> =
            PolicyWorkflowError::Wait(SyntheticWaitError);

        for rendered in [
            format!("{transport_error}"),
            format!("{transport_error:?}"),
            format!("{wait_error}"),
            format!("{wait_error:?}"),
        ] {
            assert!(!rendered.contains("private transport marker"));
            assert!(!rendered.contains("private wait marker"));
        }
        assert!(std::error::Error::source(&transport_error).is_none());
        assert!(std::error::Error::source(&wait_error).is_none());
    }
}

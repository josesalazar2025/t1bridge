//! Fixed-layout Mesa Touch ID policy records and update payloads.

use core::fmt;
use core::time::Duration;
use t1_platform::secret;

/// Encoded byte length of Mesa's system-wide protected configuration.
pub const SYSTEM_CONFIGURATION_SIZE: usize = 7 * 4;
/// Encoded byte length of Mesa's per-user protected configuration.
pub const USER_CONFIGURATION_SIZE: usize = 8 * 4;
/// Byte length of an ACM context external form.
pub const ACM_CONTEXT_EXTERNAL_FORM_SIZE: usize = 16;
/// Encoded byte length of Mesa's biometric authorization block.
pub const AUTHORIZATION_SIZE: usize = 40;
/// Encoded byte length of a per-user policy update payload, excluding its command header.
pub const USER_UPDATE_SIZE: usize = 5 * 4 + AUTHORIZATION_SIZE;
/// Encoded byte length of a system policy update payload, excluding its command header.
pub const SYSTEM_UPDATE_SIZE: usize = SYSTEM_CONFIGURATION_SIZE + AUTHORIZATION_SIZE;
/// Linux `EBUSY`, returned by Mesa while its runtime policy table settles.
pub const EBUSY_STATUS: i64 = 16;
/// `IOKit` timeout returned after Mesa may already have committed the update.
pub const KIORETURN_TIMEOUT_STATUS: i64 = -536_870_186;
/// Exact retry schedule used for an `EBUSY` per-user policy update.
pub const USER_POLICY_BUSY_RETRY_DELAYS: [Duration; 3] = [
    Duration::from_millis(50),
    Duration::from_millis(150),
    Duration::from_millis(300),
];

const POLICY_UNSPECIFIED: i32 = -1;
const POLICY_DISABLED: i32 = 0;
const POLICY_ENABLED: i32 = 1;

/// Mesa's system-wide Touch ID policy record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SystemProtectedConfiguration {
    /// Maximum lifetime of an unlock token.
    pub unlock_token_max_lifetime: i32,
    /// Reserved native field preserved for wire compatibility.
    pub reserved_1: i32,
    /// Reserved native field preserved for wire compatibility.
    pub reserved_2: i32,
    /// Global Touch ID policy.
    pub touch_id_enabled: i32,
    /// Unlock policy.
    pub unlock_enabled: i32,
    /// Identification policy.
    pub identification_enabled: i32,
    /// Login policy.
    pub login_enabled: i32,
}

impl SystemProtectedConfiguration {
    /// Returns the four policy fields that Mesa permits this client to update.
    #[must_use]
    pub const fn policy_values(self) -> [i32; 4] {
        [
            self.touch_id_enabled,
            self.unlock_enabled,
            self.identification_enabled,
            self.login_enabled,
        ]
    }
}

/// Mesa's per-user Touch ID policy record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserProtectedConfiguration {
    /// Requested unlock policy.
    pub unlock_enabled: i32,
    /// Requested identification policy.
    pub identification_enabled: i32,
    /// Requested login policy.
    pub login_enabled: i32,
    /// Requested Apple Pay policy.
    pub apple_pay_enabled: i32,
    /// Effective unlock policy.
    pub effective_unlock_enabled: i32,
    /// Effective identification policy.
    pub effective_identification_enabled: i32,
    /// Effective login policy.
    pub effective_login_enabled: i32,
    /// Effective Apple Pay policy.
    pub effective_apple_pay_enabled: i32,
}

impl UserProtectedConfiguration {
    /// Returns the four requested policy fields used by Mesa's setter.
    #[must_use]
    pub const fn requested_values(self) -> [i32; 4] {
        [
            self.unlock_enabled,
            self.identification_enabled,
            self.login_enabled,
            self.apple_pay_enabled,
        ]
    }

    /// Returns the four effective policy fields reported by live Mesa state.
    #[must_use]
    pub const fn effective_values(self) -> [i32; 4] {
        [
            self.effective_unlock_enabled,
            self.effective_identification_enabled,
            self.effective_login_enabled,
            self.effective_apple_pay_enabled,
        ]
    }
}

/// A validated non-negative Mesa biometric user identifier.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BiometricUserId(u32);

impl BiometricUserId {
    /// Validates the signed range accepted by the reference implementation.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::UserIdOutOfRange`] for negative values or values
    /// greater than `i32::MAX`.
    pub fn new(value: i64) -> Result<Self, PolicyError> {
        let value = u32::try_from(value).map_err(|_| PolicyError::UserIdOutOfRange)?;
        if value > i32::MAX.cast_unsigned() {
            return Err(PolicyError::UserIdOutOfRange);
        }
        Ok(Self(value))
    }

    /// Returns the identifier's wire value.
    #[must_use]
    pub const fn as_raw(self) -> u32 {
        self.0
    }
}

/// The exact system policy update performed by the reference implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SystemPolicyTarget {
    /// Enable only the global Touch ID flag.
    TouchId,
    /// Enable the global, unlock, identification, and login flags.
    TouchIdFeatures,
}

/// One observed result from the per-user policy setter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyUpdateObservation {
    /// The command returned a response with this byte length.
    Response { data_len: usize },
    /// The command failed with this signed native status.
    Failure { status: i64 },
}

/// The next safe action in a per-user policy update.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyUpdateDecision {
    /// Retry the identical request under the same authorization after a delay.
    RetryAfter(Duration),
    /// Read back the policy and validate it exactly.
    ReadBack,
    /// Read back an already-live policy after the bounded busy schedule.
    ReadBackAfterBusy,
    /// Stop because the setter returned unexpected data.
    RejectUnexpectedData { actual: usize },
    /// Stop and propagate the native failure status.
    Fail { status: i64 },
}

/// Bounded retry state for Mesa's per-user policy setter.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct UserPolicyRetry {
    busy_retries_used: usize,
}

impl UserPolicyRetry {
    /// Applies the reference retry and ambiguous-timeout contract.
    ///
    /// A successful empty response proceeds to mandatory readback. `EBUSY`
    /// retries use the exact bounded delay schedule, then require a stronger
    /// effective-policy readback. A timeout also proceeds to ordinary readback
    /// because Mesa may have committed before its reply timed out. No
    /// observation is itself proof that the requested policy is live; callers
    /// must still use [`verify_user_readback`].
    #[must_use]
    pub fn observe(&mut self, observation: PolicyUpdateObservation) -> PolicyUpdateDecision {
        match observation {
            PolicyUpdateObservation::Response { data_len: 0 }
            | PolicyUpdateObservation::Failure {
                status: KIORETURN_TIMEOUT_STATUS,
            } => PolicyUpdateDecision::ReadBack,
            PolicyUpdateObservation::Response { data_len } => {
                PolicyUpdateDecision::RejectUnexpectedData { actual: data_len }
            }
            PolicyUpdateObservation::Failure {
                status: EBUSY_STATUS,
            } => {
                let Some(delay) = USER_POLICY_BUSY_RETRY_DELAYS.get(self.busy_retries_used) else {
                    return PolicyUpdateDecision::ReadBackAfterBusy;
                };
                self.busy_retries_used += 1;
                PolicyUpdateDecision::RetryAfter(*delay)
            }
            PolicyUpdateObservation::Failure { status } => PolicyUpdateDecision::Fail { status },
        }
    }
}

/// Identifies which fixed-layout policy record failed validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConfigurationKind {
    /// System-wide protected configuration.
    System,
    /// Per-user protected configuration.
    User,
}

impl fmt::Display for ConfigurationKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::System => formatter.write_str("system protected-configuration"),
            Self::User => formatter.write_str("user protected-configuration"),
        }
    }
}

/// A malformed or unsafe policy record or update.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyError {
    /// A fixed-layout response was not its exact required length.
    InvalidConfigurationLength {
        /// Record being parsed.
        configuration: ConfigurationKind,
        /// Required byte length.
        expected: usize,
        /// Observed byte length.
        actual: usize,
    },
    /// An ACM context external form was not exactly 16 bytes.
    InvalidCredentialLength {
        /// Observed byte length.
        actual: usize,
    },
    /// A biometric user identifier was outside the accepted signed range.
    UserIdOutOfRange,
    /// A requested policy contained a value other than minus one, zero, or one.
    UnrecognizedPolicyValue,
    /// Mesa's readback did not preserve the requested policy values.
    PolicyReadbackMismatch,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfigurationLength {
                configuration,
                expected,
                actual,
            } => write!(
                formatter,
                "{configuration} response is {actual} bytes; expected {expected}"
            ),
            Self::InvalidCredentialLength { actual } => write!(
                formatter,
                "ACM credential set is {actual} bytes; expected {ACM_CONTEXT_EXTERNAL_FORM_SIZE}"
            ),
            Self::UserIdOutOfRange => formatter.write_str("biometric user ID is out of range"),
            Self::UnrecognizedPolicyValue => {
                formatter.write_str("refusing an unrecognized protected-configuration value")
            }
            Self::PolicyReadbackMismatch => {
                formatter.write_str("Mesa policy readback does not match the requested values")
            }
        }
    }
}

impl std::error::Error for PolicyError {}

/// Parses Mesa's exact seven-signed-integer system policy record.
///
/// # Errors
///
/// Returns an error unless `response` is exactly 28 bytes.
pub fn parse_system_configuration(
    response: &[u8],
) -> Result<SystemProtectedConfiguration, PolicyError> {
    require_length(
        response,
        SYSTEM_CONFIGURATION_SIZE,
        ConfigurationKind::System,
    )?;
    let values = decode_i32s::<7>(response);
    Ok(SystemProtectedConfiguration {
        unlock_token_max_lifetime: values[0],
        reserved_1: values[1],
        reserved_2: values[2],
        touch_id_enabled: values[3],
        unlock_enabled: values[4],
        identification_enabled: values[5],
        login_enabled: values[6],
    })
}

/// Parses Mesa's exact eight-signed-integer per-user policy record.
///
/// # Errors
///
/// Returns an error unless `response` is exactly 32 bytes.
pub fn parse_user_configuration(
    response: &[u8],
) -> Result<UserProtectedConfiguration, PolicyError> {
    require_length(response, USER_CONFIGURATION_SIZE, ConfigurationKind::User)?;
    let values = decode_i32s::<8>(response);
    Ok(UserProtectedConfiguration {
        unlock_enabled: values[0],
        identification_enabled: values[1],
        login_enabled: values[2],
        apple_pay_enabled: values[3],
        effective_unlock_enabled: values[4],
        effective_identification_enabled: values[5],
        effective_login_enabled: values[6],
        effective_apple_pay_enabled: values[7],
    })
}

/// Encodes Mesa's 40-byte native authorization block.
///
/// `None` is the native nil-options representation. A present credential is
/// opaque and must be exactly one 16-byte ACM context external form.
///
/// # Errors
///
/// Returns an error when a present credential is not exactly 16 bytes.
pub fn encode_authorization(
    credential_set: Option<&[u8]>,
) -> Result<[u8; AUTHORIZATION_SIZE], PolicyError> {
    let mut authorization = [0_u8; AUTHORIZATION_SIZE];
    let Some(credential_set) = credential_set else {
        authorization[0..4].copy_from_slice(&1_u32.to_le_bytes());
        return Ok(authorization);
    };
    if credential_set.len() != ACM_CONTEXT_EXTERNAL_FORM_SIZE {
        return Err(PolicyError::InvalidCredentialLength {
            actual: credential_set.len(),
        });
    }
    authorization[0..4].copy_from_slice(&0_u32.to_le_bytes());
    authorization[4..8].copy_from_slice(&16_u32.to_le_bytes());
    authorization[8..24].copy_from_slice(credential_set);
    Ok(authorization)
}

/// Encodes the exact 60-byte payload for Mesa's per-user policy setter.
///
/// # Errors
///
/// Returns an error for an unrecognized requested value or malformed
/// authorization credential.
pub fn encode_user_update(
    user_id: BiometricUserId,
    requested: [i32; 4],
    credential_set: Option<&[u8]>,
) -> Result<[u8; USER_UPDATE_SIZE], PolicyError> {
    validate_policy_values(requested)?;
    let mut authorization = encode_authorization(credential_set)?;
    let mut payload = [0_u8; USER_UPDATE_SIZE];
    payload[0..4].copy_from_slice(&user_id.0.to_le_bytes());
    for (offset, value) in requested.into_iter().enumerate() {
        let start = 4 + offset * 4;
        payload[start..start + 4].copy_from_slice(&value.to_le_bytes());
    }
    payload[20..].copy_from_slice(&authorization);
    if credential_set.is_some() {
        secret::wipe(&mut authorization);
    }
    Ok(payload)
}

/// Encodes one of the two exact 68-byte system policy update payloads.
///
/// # Errors
///
/// Returns an error when a present authorization credential is malformed.
pub fn encode_system_update(
    target: SystemPolicyTarget,
    credential_set: Option<&[u8]>,
) -> Result<[u8; SYSTEM_UPDATE_SIZE], PolicyError> {
    let values: [i32; 7] = match target {
        SystemPolicyTarget::TouchId => [-1, -1, -1, 1, -1, -1, -1],
        SystemPolicyTarget::TouchIdFeatures => [-1, -1, -1, 1, 1, 1, 1],
    };
    let mut authorization = encode_authorization(credential_set)?;
    let mut payload = [0_u8; SYSTEM_UPDATE_SIZE];
    for (offset, value) in values.into_iter().enumerate() {
        let start = offset * 4;
        payload[start..start + 4].copy_from_slice(&value.to_le_bytes());
    }
    payload[SYSTEM_CONFIGURATION_SIZE..].copy_from_slice(&authorization);
    if credential_set.is_some() {
        secret::wipe(&mut authorization);
    }
    Ok(payload)
}

/// Validates the mutable fields of a system policy before an update.
///
/// # Errors
///
/// Returns an error if any mutable field is not minus one, zero, or one.
pub fn validate_system_configuration(
    configuration: SystemProtectedConfiguration,
) -> Result<(), PolicyError> {
    validate_policy_values(configuration.policy_values())
}

/// Returns the per-user values needed to enable Touch ID while preserving Apple Pay.
///
/// `None` means the existing requested policy already matches the target.
///
/// # Errors
///
/// Returns an error rather than preserving an unrecognized Apple Pay value.
pub fn user_touch_id_update(
    configuration: UserProtectedConfiguration,
) -> Result<Option<[i32; 4]>, PolicyError> {
    if !is_policy_value(configuration.apple_pay_enabled) {
        return Err(PolicyError::UnrecognizedPolicyValue);
    }
    if configuration.requested_values()[0..3] == [1, 1, 1] {
        return Ok(None);
    }
    Ok(Some([1, 1, 1, configuration.apple_pay_enabled]))
}

/// Verifies Mesa's per-user policy readback after one setter workflow.
///
/// # Errors
///
/// Returns an error when any requested value differs. When
/// `require_effective_equality` is true, also requires every effective field
/// to equal its corresponding requested field.
pub fn verify_user_readback(
    requested: [i32; 4],
    readback: UserProtectedConfiguration,
    require_effective_equality: bool,
) -> Result<(), PolicyError> {
    if readback.requested_values() != requested
        || (require_effective_equality && readback.effective_values() != requested)
    {
        return Err(PolicyError::PolicyReadbackMismatch);
    }
    Ok(())
}

/// Verifies that Mesa enabled the system fields required by an update target.
///
/// # Errors
///
/// Returns an error when a required field is not enabled in the readback.
pub fn verify_system_readback(
    target: SystemPolicyTarget,
    readback: SystemProtectedConfiguration,
) -> Result<(), PolicyError> {
    let matches = match target {
        SystemPolicyTarget::TouchId => readback.touch_id_enabled == POLICY_ENABLED,
        SystemPolicyTarget::TouchIdFeatures => readback.policy_values() == [POLICY_ENABLED; 4],
    };
    if !matches {
        return Err(PolicyError::PolicyReadbackMismatch);
    }
    Ok(())
}

fn validate_policy_values(values: [i32; 4]) -> Result<(), PolicyError> {
    if values.into_iter().all(is_policy_value) {
        Ok(())
    } else {
        Err(PolicyError::UnrecognizedPolicyValue)
    }
}

const fn is_policy_value(value: i32) -> bool {
    matches!(value, POLICY_UNSPECIFIED | POLICY_DISABLED | POLICY_ENABLED)
}

fn require_length(
    response: &[u8],
    expected: usize,
    configuration: ConfigurationKind,
) -> Result<(), PolicyError> {
    if response.len() != expected {
        return Err(PolicyError::InvalidConfigurationLength {
            configuration,
            expected,
            actual: response.len(),
        });
    }
    Ok(())
}

fn decode_i32s<const COUNT: usize>(bytes: &[u8]) -> [i32; COUNT] {
    let mut values = [0_i32; COUNT];
    for (index, value) in values.iter_mut().enumerate() {
        let start = index * 4;
        let mut encoded = [0_u8; 4];
        encoded.copy_from_slice(&bytes[start..start + 4]);
        *value = i32::from_le_bytes(encoded);
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_i32s<const COUNT: usize>(values: [i32; COUNT]) -> Vec<u8> {
        values.into_iter().flat_map(i32::to_le_bytes).collect()
    }

    fn system_configuration(values: [i32; 7]) -> SystemProtectedConfiguration {
        parse_system_configuration(&encode_i32s(values)).unwrap()
    }

    fn user_configuration(values: [i32; 8]) -> UserProtectedConfiguration {
        parse_user_configuration(&encode_i32s(values)).unwrap()
    }

    #[test]
    fn parses_system_configuration_as_signed_little_endian() {
        let configuration = system_configuration([300, -1, -1, 1, 1, 0, -1]);
        assert_eq!(configuration.unlock_token_max_lifetime, 300);
        assert_eq!(configuration.reserved_1, -1);
        assert_eq!(configuration.reserved_2, -1);
        assert_eq!(configuration.policy_values(), [1, 1, 0, -1]);
    }

    #[test]
    fn rejects_non_exact_system_configuration_lengths() {
        for actual in [SYSTEM_CONFIGURATION_SIZE - 1, SYSTEM_CONFIGURATION_SIZE + 1] {
            assert_eq!(
                parse_system_configuration(&vec![0; actual]),
                Err(PolicyError::InvalidConfigurationLength {
                    configuration: ConfigurationKind::System,
                    expected: SYSTEM_CONFIGURATION_SIZE,
                    actual,
                })
            );
        }
    }

    #[test]
    fn parses_user_configuration_as_signed_little_endian() {
        let configuration = user_configuration([1, 0, -1, -1, 1, 0, 0, -1]);
        assert_eq!(configuration.requested_values(), [1, 0, -1, -1]);
        assert_eq!(configuration.effective_unlock_enabled, 1);
        assert_eq!(configuration.effective_identification_enabled, 0);
        assert_eq!(configuration.effective_login_enabled, 0);
        assert_eq!(configuration.effective_apple_pay_enabled, -1);
    }

    #[test]
    fn rejects_non_exact_user_configuration_lengths() {
        for actual in [USER_CONFIGURATION_SIZE - 1, USER_CONFIGURATION_SIZE + 1] {
            assert_eq!(
                parse_user_configuration(&vec![0; actual]),
                Err(PolicyError::InvalidConfigurationLength {
                    configuration: ConfigurationKind::User,
                    expected: USER_CONFIGURATION_SIZE,
                    actual,
                })
            );
        }
    }

    #[test]
    fn nil_authorization_matches_native_layout() {
        let authorization = encode_authorization(None).unwrap();
        assert_eq!(&authorization[0..4], &1_u32.to_le_bytes());
        assert_eq!(&authorization[4..], &[0_u8; 36]);
    }

    #[test]
    fn credential_authorization_matches_native_layout() {
        let credential = [0x5a; ACM_CONTEXT_EXTERNAL_FORM_SIZE];
        let authorization = encode_authorization(Some(&credential)).unwrap();
        assert_eq!(&authorization[0..4], &0_u32.to_le_bytes());
        assert_eq!(&authorization[4..8], &16_u32.to_le_bytes());
        assert_eq!(&authorization[8..24], &credential);
        assert_eq!(&authorization[24..], &[0_u8; 16]);
    }

    #[test]
    fn rejects_wrong_credential_lengths_without_retaining_bytes() {
        for credential in [&[0x11; 15][..], &[0x22; 17][..]] {
            let error = encode_authorization(Some(credential)).unwrap_err();
            assert_eq!(
                error,
                PolicyError::InvalidCredentialLength {
                    actual: credential.len()
                }
            );
            assert!(!format!("{error:?}").contains("11"));
            assert!(!format!("{error:?}").contains("22"));
        }
    }

    #[test]
    fn biometric_user_id_accepts_only_non_negative_signed_range() {
        assert_eq!(BiometricUserId::new(0).unwrap().as_raw(), 0);
        assert_eq!(
            BiometricUserId::new(i64::from(i32::MAX)).unwrap().as_raw(),
            i32::MAX.cast_unsigned()
        );
        assert_eq!(BiometricUserId::new(-1), Err(PolicyError::UserIdOutOfRange));
        assert_eq!(
            BiometricUserId::new(i64::from(i32::MAX) + 1),
            Err(PolicyError::UserIdOutOfRange)
        );
    }

    #[test]
    fn user_update_matches_native_layout() {
        let credential = [0x5a; ACM_CONTEXT_EXTERNAL_FORM_SIZE];
        let payload = encode_user_update(
            BiometricUserId::new(501).unwrap(),
            [1, 0, -1, 1],
            Some(&credential),
        )
        .unwrap();
        assert_eq!(payload.len(), USER_UPDATE_SIZE);
        assert_eq!(&payload[0..4], &501_u32.to_le_bytes());
        assert_eq!(&payload[4..20], encode_i32s([1, 0, -1, 1]));
        assert_eq!(
            &payload[20..],
            &encode_authorization(Some(&credential)).unwrap()
        );
    }

    #[test]
    fn user_update_rejects_unrecognized_policy_values() {
        assert_eq!(
            encode_user_update(BiometricUserId::new(501).unwrap(), [1, 0, 2, -1], None),
            Err(PolicyError::UnrecognizedPolicyValue)
        );
    }

    #[test]
    fn system_global_update_changes_only_touch_id() {
        let payload = encode_system_update(SystemPolicyTarget::TouchId, None).unwrap();
        assert_eq!(
            &payload[..SYSTEM_CONFIGURATION_SIZE],
            encode_i32s([-1, -1, -1, 1, -1, -1, -1])
        );
        assert_eq!(
            &payload[SYSTEM_CONFIGURATION_SIZE..],
            &encode_authorization(None).unwrap()
        );
    }

    #[test]
    fn system_features_update_enables_all_supported_flags() {
        let credential = [0x5a; ACM_CONTEXT_EXTERNAL_FORM_SIZE];
        let payload =
            encode_system_update(SystemPolicyTarget::TouchIdFeatures, Some(&credential)).unwrap();
        assert_eq!(
            &payload[..SYSTEM_CONFIGURATION_SIZE],
            encode_i32s([-1, -1, -1, 1, 1, 1, 1])
        );
        assert_eq!(
            &payload[SYSTEM_CONFIGURATION_SIZE..],
            &encode_authorization(Some(&credential)).unwrap()
        );
    }

    #[test]
    fn system_update_refuses_unknown_current_policy() {
        let recognized = system_configuration([300, -1, -1, -1, 0, 1, -1]);
        assert_eq!(validate_system_configuration(recognized), Ok(()));

        let unrecognized = system_configuration([300, -1, -1, -1, 0, 7, -1]);
        assert_eq!(
            validate_system_configuration(unrecognized),
            Err(PolicyError::UnrecognizedPolicyValue)
        );
    }

    #[test]
    fn user_touch_id_update_preserves_apple_pay() {
        let configuration = user_configuration([-1, 0, -1, 0, 0, 0, 0, 0]);
        assert_eq!(user_touch_id_update(configuration), Ok(Some([1, 1, 1, 0])));
    }

    #[test]
    fn user_touch_id_update_skips_match_and_rejects_unknown_apple_pay() {
        let matching = user_configuration([1, 1, 1, -1, 1, 1, 1, -1]);
        assert_eq!(user_touch_id_update(matching), Ok(None));

        let unknown = user_configuration([0, 0, 0, 9, 0, 0, 0, 9]);
        assert_eq!(
            user_touch_id_update(unknown),
            Err(PolicyError::UnrecognizedPolicyValue)
        );
    }

    #[test]
    fn readback_can_require_effective_policy_equality() {
        let user = user_configuration([1, 1, 1, 0, 0, 0, 0, 0]);
        assert_eq!(verify_user_readback([1, 1, 1, 0], user, false), Ok(()));
        assert_eq!(
            verify_user_readback([1, 1, 1, -1], user, false),
            Err(PolicyError::PolicyReadbackMismatch)
        );
        assert_eq!(
            verify_user_readback([1, 1, 1, 0], user, true),
            Err(PolicyError::PolicyReadbackMismatch)
        );
        assert_eq!(
            verify_user_readback(
                [1, 1, 1, 0],
                user_configuration([1, 1, 1, 0, 1, 1, 1, 0]),
                true,
            ),
            Ok(())
        );

        let global_only = system_configuration([300, -1, -1, 1, 0, 0, 0]);
        assert_eq!(
            verify_system_readback(SystemPolicyTarget::TouchId, global_only),
            Ok(())
        );
        assert_eq!(
            verify_system_readback(SystemPolicyTarget::TouchIdFeatures, global_only),
            Err(PolicyError::PolicyReadbackMismatch)
        );
    }

    #[test]
    fn user_policy_busy_retries_use_the_exact_bounded_schedule() {
        let mut retry = UserPolicyRetry::default();
        for delay in USER_POLICY_BUSY_RETRY_DELAYS {
            assert_eq!(
                retry.observe(PolicyUpdateObservation::Failure {
                    status: EBUSY_STATUS
                }),
                PolicyUpdateDecision::RetryAfter(delay)
            );
        }
        assert_eq!(
            retry.observe(PolicyUpdateObservation::Failure {
                status: EBUSY_STATUS
            }),
            PolicyUpdateDecision::ReadBackAfterBusy
        );
    }

    #[test]
    fn success_and_ambiguous_timeout_both_require_readback() {
        assert_eq!(
            UserPolicyRetry::default().observe(PolicyUpdateObservation::Response { data_len: 0 }),
            PolicyUpdateDecision::ReadBack
        );
        assert_eq!(
            UserPolicyRetry::default().observe(PolicyUpdateObservation::Failure {
                status: KIORETURN_TIMEOUT_STATUS
            }),
            PolicyUpdateDecision::ReadBack
        );
    }

    #[test]
    fn unexpected_data_and_other_failures_are_not_retried() {
        assert_eq!(
            UserPolicyRetry::default().observe(PolicyUpdateObservation::Response { data_len: 1 }),
            PolicyUpdateDecision::RejectUnexpectedData { actual: 1 }
        );
        assert_eq!(
            UserPolicyRetry::default().observe(PolicyUpdateObservation::Failure { status: -7 }),
            PolicyUpdateDecision::Fail { status: -7 }
        );
    }
}

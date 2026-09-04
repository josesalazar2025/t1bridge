//! Read-only biometric-service priming.

use core::fmt;

use crate::biometric::{ResponseError, parse_calibration_status};
use crate::commands::{
    CommandError, calibration_status_command, parse_sks_lock_state, sks_lock_state_command,
};
use crate::control::BiometricTransport;
use crate::policy::BiometricUserId;

/// The read-only command that failed while priming the biometric service.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrimeStage {
    /// Mesa calibration-status query.
    CalibrationStatus,
    /// Per-user Secure Key Store lock-state query.
    SksLockState,
}

impl fmt::Display for PrimeStage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::CalibrationStatus => "calibration status",
            Self::SksLockState => "SKS lock state",
        })
    }
}

/// Values observed by one read-only biometric-service prime.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrimeResult {
    /// Mesa's opaque one-byte calibration status.
    pub calibration_status: u8,
    /// Mesa's opaque per-user Secure Key Store lock state.
    pub sks_lock_state: u32,
}

/// A redaction-safe biometric-service priming failure.
pub enum PrimeError<TransportError> {
    /// The caller-owned transport failed at a read-only command boundary.
    Transport {
        /// Command that could not complete.
        stage: PrimeStage,
        /// Caller-owned error retained for programmatic handling only.
        error: TransportError,
    },
    /// Mesa returned a malformed calibration-status value.
    CalibrationStatus(ResponseError),
    /// Mesa returned a malformed SKS lock-state value.
    SksLockState(CommandError),
}

impl<TransportError> fmt::Debug for PrimeError<TransportError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport { stage, .. } => formatter
                .debug_struct("Transport")
                .field("stage", stage)
                .field("error", &"[redacted]")
                .finish(),
            Self::CalibrationStatus(error) => formatter
                .debug_tuple("CalibrationStatus")
                .field(error)
                .finish(),
            Self::SksLockState(error) => {
                formatter.debug_tuple("SksLockState").field(error).finish()
            }
        }
    }
}

impl<TransportError> fmt::Display for PrimeError<TransportError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport { stage, .. } => {
                write!(formatter, "biometric {stage} transport failed")
            }
            Self::CalibrationStatus(error) => error.fmt(formatter),
            Self::SksLockState(error) => error.fmt(formatter),
        }
    }
}

impl<TransportError> std::error::Error for PrimeError<TransportError> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::CalibrationStatus(error) => Some(error),
            Self::SksLockState(error) => Some(error),
            Self::Transport { .. } => None,
        }
    }
}

/// Primes Mesa with exactly two read-only queries in native order.
///
/// The calibration status is read first, followed by the requested user's SKS
/// lock state. No command in this workflow changes sensor, policy, user,
/// catacomb, enrollment, or matching state.
///
/// # Errors
///
/// Stops at the first transport or structural response failure.
pub fn prime_biometric_service<Transport: BiometricTransport>(
    transport: &mut Transport,
    user_id: BiometricUserId,
) -> Result<PrimeResult, PrimeError<Transport::Error>> {
    let calibration = transport
        .execute(&calibration_status_command())
        .map_err(|error| PrimeError::Transport {
            stage: PrimeStage::CalibrationStatus,
            error,
        })?;
    let calibration_status =
        parse_calibration_status(&calibration).map_err(PrimeError::CalibrationStatus)?;

    let lock_state = transport
        .execute(&sks_lock_state_command(user_id))
        .map_err(|error| PrimeError::Transport {
            stage: PrimeStage::SksLockState,
            error,
        })?;
    let sks_lock_state = parse_sks_lock_state(&lock_state).map_err(PrimeError::SksLockState)?;

    Ok(PrimeResult {
        calibration_status,
        sks_lock_state,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::biometric::COMMAND_HEADER_SIZE;
    use crate::commands::CommandPacket;
    use std::collections::VecDeque;

    const USER: i32 = 501;

    #[derive(Clone, Copy)]
    struct SensitiveTransportError;

    impl fmt::Debug for SensitiveTransportError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("private transport marker")
        }
    }

    struct FakeTransport {
        responses: VecDeque<Result<Vec<u8>, SensitiveTransportError>>,
        requests: Vec<Vec<u8>>,
    }

    impl FakeTransport {
        fn new(
            responses: impl IntoIterator<Item = Result<Vec<u8>, SensitiveTransportError>>,
        ) -> Self {
            Self {
                responses: responses.into_iter().collect(),
                requests: Vec::new(),
            }
        }

        fn command_codes(&self) -> Vec<u16> {
            self.requests
                .iter()
                .map(|request| u16::from_le_bytes(request[2..4].try_into().unwrap()))
                .collect()
        }
    }

    impl BiometricTransport for FakeTransport {
        type Error = SensitiveTransportError;

        fn execute(&mut self, packet: &CommandPacket) -> Result<Vec<u8>, Self::Error> {
            self.requests.push(packet.request().to_vec());
            self.responses.pop_front().expect("synthetic response")
        }
    }

    fn user() -> BiometricUserId {
        BiometricUserId::new(i64::from(USER)).unwrap()
    }

    #[test]
    fn queries_only_calibration_then_requested_user_lock_state() {
        let mut transport = FakeTransport::new([Ok(vec![0]), Ok(0x15_u32.to_le_bytes().to_vec())]);

        assert_eq!(
            prime_biometric_service(&mut transport, user()).unwrap(),
            PrimeResult {
                calibration_status: 0,
                sks_lock_state: 0x15,
            }
        );
        assert_eq!(transport.command_codes(), [0x1d, 0x27]);
        assert_eq!(
            &transport.requests[1][COMMAND_HEADER_SIZE..],
            &USER.to_le_bytes()
        );
    }

    #[test]
    fn every_failure_stops_before_the_next_query() {
        let mut transport = FakeTransport::new([Err(SensitiveTransportError)]);
        assert!(matches!(
            prime_biometric_service(&mut transport, user()),
            Err(PrimeError::Transport {
                stage: PrimeStage::CalibrationStatus,
                ..
            })
        ));
        assert_eq!(transport.command_codes(), [0x1d]);

        let mut transport = FakeTransport::new([Ok(Vec::new())]);
        assert!(matches!(
            prime_biometric_service(&mut transport, user()),
            Err(PrimeError::CalibrationStatus(_))
        ));
        assert_eq!(transport.command_codes(), [0x1d]);

        let mut transport = FakeTransport::new([Ok(vec![0]), Ok(vec![0; 3])]);
        assert!(matches!(
            prime_biometric_service(&mut transport, user()),
            Err(PrimeError::SksLockState(_))
        ));
        assert_eq!(transport.command_codes(), [0x1d, 0x27]);
    }

    #[test]
    fn transport_diagnostics_and_source_chain_are_redacted() {
        let error: PrimeError<SensitiveTransportError> = PrimeError::Transport {
            stage: PrimeStage::CalibrationStatus,
            error: SensitiveTransportError,
        };
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains("private transport marker"));
        assert!(std::error::Error::source(&error).is_none());
    }
}

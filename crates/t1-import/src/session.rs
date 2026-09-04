//! Short-lived production session for the live T1 module association.

use std::time::Duration;

use t1_bridge::calibration::MODULE_SERIAL_NUMBER_SIZE;
use t1_bridge::control::{BiometricTransport, read_module_serial};
use t1_bridge::live_operation::LiveBridgeConnection;
use t1_daemons::request_ids::LinuxRequestIdSource;
use t1_daemons::xart_live::ValidatedNcmInterface;

use crate::automatic::{LiveAssociationSession, LiveAssociationSource, SourceError};

const READ_ONLY_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);

/// Dynamically discovers the physical T1 for one read-only association query.
#[derive(Clone, Copy, Debug, Default)]
pub struct LiveT1AssociationSource;

/// One owned live connection that cannot outlive the association query.
pub struct LiveT1AssociationSession {
    connection: LiveBridgeConnection,
    consumed: bool,
}

impl std::fmt::Debug for LiveT1AssociationSession {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("LiveT1AssociationSession([redacted])")
    }
}

impl LiveAssociationSource for LiveT1AssociationSource {
    type Session = LiveT1AssociationSession;

    fn open_read_only(&mut self) -> Result<Self::Session, SourceError> {
        let interface =
            ValidatedNcmInterface::discover().map_err(|_| SourceError::HardwareUnavailable)?;
        let connection = LiveBridgeConnection::connect(interface.kernel_index())
            .map_err(|_| SourceError::HardwareUnavailable)?;
        Ok(LiveT1AssociationSession {
            connection,
            consumed: false,
        })
    }
}

impl LiveAssociationSession for LiveT1AssociationSession {
    fn read_association(&mut self) -> Result<[u8; MODULE_SERIAL_NUMBER_SIZE], SourceError> {
        let connection = &mut self.connection;
        read_association_once(&mut self.consumed, || {
            let request_ids =
                LinuxRequestIdSource::open().map_err(|_| SourceError::HardwareUnavailable)?;
            let operation = connection
                .start_operation(request_ids)
                .map_err(|_| SourceError::HardwareUnavailable)?;
            let (mut commands, events) = operation
                .into_adapters(READ_ONLY_OPERATION_TIMEOUT, || false)
                .map_err(|_| SourceError::HardwareUnavailable)?;
            let association = read_association_from_transport(&mut commands);
            drop(events);
            association
        })
    }

    fn close(self) -> Result<(), SourceError> {
        drop(self);
        Ok(())
    }
}

fn read_association_once<F>(
    consumed: &mut bool,
    query: F,
) -> Result<[u8; MODULE_SERIAL_NUMBER_SIZE], SourceError>
where
    F: FnOnce() -> Result<[u8; MODULE_SERIAL_NUMBER_SIZE], SourceError>,
{
    if std::mem::replace(consumed, true) {
        return Err(SourceError::HardwareUnavailable);
    }
    query()
}

fn read_association_from_transport<T: BiometricTransport>(
    transport: &mut T,
) -> Result<[u8; MODULE_SERIAL_NUMBER_SIZE], SourceError> {
    read_module_serial(transport)
        .map(|association| *association.as_bytes())
        .map_err(|_| SourceError::HardwareUnavailable)
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::VecDeque;

    use t1_bridge::commands::CommandPacket;

    use super::*;

    const ASSOCIATION: &[u8; MODULE_SERIAL_NUMBER_SIZE] = b"SYNTHETICMODULE001";

    #[derive(Clone, Copy, Debug)]
    struct TransportError;

    struct Transport {
        response: VecDeque<Result<Vec<u8>, TransportError>>,
        calls: usize,
    }

    impl BiometricTransport for Transport {
        type Error = TransportError;

        fn execute(&mut self, _: &CommandPacket) -> Result<Vec<u8>, Self::Error> {
            self.calls += 1;
            self.response.pop_front().expect("scripted response")
        }
    }

    #[test]
    fn reads_one_validated_association_without_rendering_it() {
        let mut transport = Transport {
            response: VecDeque::from([Ok(ASSOCIATION.to_vec())]),
            calls: 0,
        };

        let association = read_association_from_transport(&mut transport).unwrap();

        assert_eq!(association, *ASSOCIATION);
        assert_eq!(transport.calls, 1);
    }

    #[test]
    fn collapses_transport_and_response_failures_to_one_redacted_category() {
        for response in [
            Err(TransportError),
            Ok(b"private malformed association".to_vec()),
        ] {
            let mut transport = Transport {
                response: VecDeque::from([response]),
                calls: 0,
            };

            let error = read_association_from_transport(&mut transport).unwrap_err();

            assert_eq!(error, SourceError::HardwareUnavailable);
            assert_eq!(error.to_string(), "the T1 sensor is unavailable");
            assert_eq!(transport.calls, 1);
        }
    }

    #[test]
    fn one_session_rejects_a_second_query_before_starting_it() {
        let calls = Cell::new(0);
        let mut consumed = false;

        let first = read_association_once(&mut consumed, || {
            calls.set(calls.get() + 1);
            Ok(*ASSOCIATION)
        });
        let second = read_association_once(&mut consumed, || {
            calls.set(calls.get() + 1);
            Ok(*ASSOCIATION)
        });

        assert_eq!(first, Ok(*ASSOCIATION));
        assert_eq!(second, Err(SourceError::HardwareUnavailable));
        assert_eq!(calls.get(), 1);
    }
}

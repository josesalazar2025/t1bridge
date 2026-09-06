//! Observes existing fingerprint commands through the shared diagnostic format.

use t1_bridge::commands::CommandPacket;
use t1_bridge::control::BiometricTransport;
use t1_platform::diagnostics::{self, Component, Record};
use t1_platform::diagnostics::{Outcome, Stage as Phase};

const MAX_COMMANDS: usize = 256;

/// Observes existing commands only: no extra queries, retries or payload reads.
pub(crate) struct DiagnosticTransport<'a, T: BiometricTransport, Sink = fn(Record)> {
    inner: &'a mut T,
    phase: Phase,
    native_status: fn(&T::Error) -> Option<i64>,
    sink: Sink,
    enabled: bool,
    commands: usize,
}

impl<'a, T: BiometricTransport> DiagnosticTransport<'a, T> {
    pub(crate) fn new(
        inner: &'a mut T,
        phase: Phase,
        native_status: fn(&T::Error) -> Option<i64>,
    ) -> Self {
        Self {
            inner,
            phase,
            native_status,
            sink: diagnostics::emit,
            enabled: diagnostics::enabled(),
            commands: 0,
        }
    }
}

impl<T: BiometricTransport, Sink: FnMut(Record)> BiometricTransport
    for DiagnosticTransport<'_, T, Sink>
{
    type Error = T::Error;

    fn execute(&mut self, packet: &CommandPacket) -> Result<Vec<u8>, Self::Error> {
        if !self.enabled {
            return self.inner.execute(packet);
        }
        if self.commands == MAX_COMMANDS {
            (self.sink)(Record::new(
                Component::Broker,
                self.phase,
                Outcome::Limit,
                None,
            ));
            self.enabled = false;
            return self.inner.execute(packet);
        }
        self.commands += 1;
        let code = packet
            .request()
            .get(2..4)
            .map_or(0, |bytes| u16::from_le_bytes([bytes[0], bytes[1]]));
        (self.sink)(
            Record::new(Component::Broker, self.phase, Outcome::Begin, None).with_command(code),
        );
        let result = self.inner.execute(packet);
        (self.sink)(
            Record::new(
                Component::Broker,
                self.phase,
                if result.is_ok() {
                    Outcome::Ok
                } else {
                    Outcome::Error
                },
                result.as_ref().err().and_then(self.native_status),
            )
            .with_command(code),
        );
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use t1_bridge::commands::start_enrollment_command;
    use t1_bridge::policy::BiometricUserId;

    struct Fake {
        calls: usize,
        fail: bool,
    }

    struct PrivateError {
        status: Option<i64>,
        secret: &'static str,
    }

    impl BiometricTransport for Fake {
        type Error = PrivateError;

        fn execute(&mut self, _: &CommandPacket) -> Result<Vec<u8>, Self::Error> {
            self.calls += 1;
            if self.fail {
                Err(PrivateError {
                    status: Some(1),
                    secret: "PRIVATE-ERROR",
                })
            } else {
                Ok(b"PRIVATE-RESPONSE".to_vec())
            }
        }
    }

    #[test]
    fn opt_in_preserves_results_and_never_formats_private_material() {
        for enabled in [false, true] {
            for fail in [false, true] {
                let mut inner = Fake { calls: 0, fail };
                let mut records = Vec::new();
                let packet = start_enrollment_command(
                    BiometricUserId::new(1234).unwrap(),
                    Some(b"PRIVATE-12345678"),
                )
                .unwrap();
                let mut transport = DiagnosticTransport {
                    inner: &mut inner,
                    phase: Phase::Transaction,
                    native_status: |e: &PrivateError| e.status,
                    sink: |record: Record| records.push(record.to_string()),
                    enabled,
                    commands: 0,
                };
                match transport.execute(&packet) {
                    Ok(response) => assert_eq!(response, b"PRIVATE-RESPONSE"),
                    Err(error) => assert_eq!(error.secret, "PRIVATE-ERROR"),
                }
                assert_eq!(inner.calls, 1);
                assert_eq!(records.len(), if enabled { 2 } else { 0 });
                for line in &records {
                    assert!(!line.contains("PRIVATE"));
                    assert!(!line.contains("1234"));
                    assert!(line.contains("command=0x03"));
                }
                if enabled && fail {
                    assert!(records[1].contains("result=error code=1"));
                }
            }
        }
    }

    #[test]
    fn trace_limit_never_stops_transport() {
        let mut inner = Fake {
            calls: 0,
            fail: false,
        };
        let mut records = Vec::new();
        let packet = start_enrollment_command(BiometricUserId::new(1234).unwrap(), None).unwrap();
        let mut transport = DiagnosticTransport {
            inner: &mut inner,
            phase: Phase::Transaction,
            native_status: |e: &PrivateError| e.status,
            sink: |record: Record| records.push(record.to_string()),
            enabled: true,
            commands: 0,
        };
        for _ in 0..MAX_COMMANDS + 3 {
            assert!(transport.execute(&packet).is_ok());
        }
        assert_eq!(inner.calls, MAX_COMMANDS + 3);
        assert_eq!(records.len(), MAX_COMMANDS * 2 + 1);
        assert!(records.last().unwrap().contains("result=limit"));
    }
}

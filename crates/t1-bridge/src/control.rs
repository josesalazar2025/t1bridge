//! Validated, transport-agnostic `BiometricKit` control-plane operations.

use crate::biometric::{ModuleSerial, ResponseError, parse_daemon_info, parse_module_serial};
use crate::calibration::{CalibrationError, validate_fdr_calibration_record};
use crate::commands::{
    CalibrationSource, CommandError, CommandPacket, daemon_info_command, load_calibration_command,
    module_serial_command, validate_empty_response,
};
use crate::rpc::{
    RequestId, RpcError, parse_biometric_command_result, perform_biometric_command_request,
    set_client_version_request, validate_set_client_version_result,
};
use crate::session::{BridgeXpcSession, SessionError};
use core::fmt;
use std::io::{Read, Write};

/// Executes one already-encoded biometric command.
///
/// Live `BridgeXPC` request identifiers, timeouts, and socket ownership remain
/// transport policy. Tests can implement this trait without opening a socket.
pub trait BiometricTransport {
    /// Transport-specific failure retained for programmatic handling.
    type Error;

    /// Sends one packet and returns only its opaque response body.
    ///
    /// # Errors
    ///
    /// Returns the implementation's redaction-safe transport failure.
    fn execute(&mut self, packet: &CommandPacket) -> Result<Vec<u8>, Self::Error>;
}

/// Supplies unique request identifiers without choosing an entropy source.
pub trait RequestIdSource {
    /// Returns the next identifier, or `None` when safe generation is no
    /// longer possible.
    fn next_request_id(&mut self) -> Option<RequestId>;
}

impl<I: Iterator<Item = RequestId>> RequestIdSource for I {
    fn next_request_id(&mut self) -> Option<RequestId> {
        self.next()
    }
}

/// A live `BridgeXPC` biometric call failure.
#[derive(Debug)]
pub enum BridgeCommandError {
    /// The caller-owned identifier source was exhausted.
    RequestIdUnavailable,
    /// The negotiated stream or RPC envelope failed.
    Session(SessionError),
    /// The method-specific result failed validation.
    Rpc(RpcError),
    /// A biometric command was attempted before selecting client version two.
    ClientVersionNotSelected,
    /// Client version was already selected for this adapter.
    ClientVersionAlreadySelected,
}

impl fmt::Display for BridgeCommandError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestIdUnavailable => formatter.write_str("RPC request identifier unavailable"),
            Self::Session(error) => error.fmt(formatter),
            Self::Rpc(error) => error.fmt(formatter),
            Self::ClientVersionNotSelected => {
                formatter.write_str("BridgeXPC client version is not selected")
            }
            Self::ClientVersionAlreadySelected => {
                formatter.write_str("BridgeXPC client version is already selected")
            }
        }
    }
}

impl std::error::Error for BridgeCommandError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Session(error) => Some(error),
            Self::Rpc(error) => Some(error),
            Self::RequestIdUnavailable
            | Self::ClientVersionNotSelected
            | Self::ClientVersionAlreadySelected => None,
        }
    }
}

/// Biometric command adapter over an already-negotiated `BridgeXPC` session.
///
/// The caller supplies request identifiers and owns socket creation, binding,
/// routing, timeouts, and entropy acquisition.
pub struct SessionBiometricTransport<'a, S, I> {
    session: &'a mut BridgeXpcSession<S>,
    request_ids: I,
    client_version_selected: bool,
}

impl<'a, S: Read + Write, I: RequestIdSource> SessionBiometricTransport<'a, S, I> {
    /// Wraps a negotiated session without performing an RPC.
    #[must_use]
    pub const fn new(session: &'a mut BridgeXpcSession<S>, request_ids: I) -> Self {
        Self {
            session,
            request_ids,
            client_version_selected: false,
        }
    }

    /// Wraps a session whose client version was selected through the owning
    /// live-connection preparation boundary.
    #[must_use]
    pub(crate) const fn new_prepared(session: &'a mut BridgeXpcSession<S>, request_ids: I) -> Self {
        Self {
            session,
            request_ids,
            client_version_selected: true,
        }
    }

    /// Selects the native biometric client version exactly once.
    ///
    /// # Errors
    ///
    /// Returns an error when identifiers are exhausted, the session fails,
    /// the peer rejects version two, or the method was already called.
    pub fn select_client_version(&mut self) -> Result<(), BridgeCommandError> {
        if self.client_version_selected {
            return Err(BridgeCommandError::ClientVersionAlreadySelected);
        }
        let request_id = self.next_request_id()?;
        let result = self
            .session
            .call(&request_id, &set_client_version_request(2))
            .map_err(BridgeCommandError::Session)?;
        validate_set_client_version_result(&result).map_err(BridgeCommandError::Rpc)?;
        self.client_version_selected = true;
        Ok(())
    }

    /// Removes the oldest service-status callback acknowledged during an RPC.
    #[must_use]
    pub fn take_service_event(&mut self) -> Option<crate::mesa::ServiceStatusEvent> {
        self.session.take_service_event()
    }

    /// Receives and acknowledges one possible service-status callback.
    ///
    /// # Errors
    ///
    /// Returns a session failure for malformed framing, RPC data, or stream I/O.
    pub fn service_inbound_request(
        &mut self,
    ) -> Result<Option<crate::mesa::ServiceStatusEvent>, SessionError> {
        self.session.service_inbound_request()
    }

    fn next_request_id(&mut self) -> Result<RequestId, BridgeCommandError> {
        self.request_ids
            .next_request_id()
            .ok_or(BridgeCommandError::RequestIdUnavailable)
    }
}

impl<S: Read + Write, I: RequestIdSource> BiometricTransport
    for SessionBiometricTransport<'_, S, I>
{
    type Error = BridgeCommandError;

    fn execute(&mut self, packet: &CommandPacket) -> Result<Vec<u8>, Self::Error> {
        if !self.client_version_selected {
            return Err(BridgeCommandError::ClientVersionNotSelected);
        }
        let request_id = self.next_request_id()?;
        let result = self
            .session
            .call(&request_id, &perform_biometric_command_request(packet))
            .map_err(BridgeCommandError::Session)?;
        parse_biometric_command_result(packet, &result).map_err(BridgeCommandError::Rpc)
    }
}

/// Result of ensuring that this sensor's FDR calibration is live.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CalibrationLoad {
    /// Size of the complete signed outer `FSCl` record.
    pub record_size: usize,
    /// Whether Mesa reported calibration loaded before this operation.
    pub already_loaded: bool,
}

/// A redaction-safe control-plane failure.
pub enum ControlError<E> {
    /// The caller-owned transport failed.
    Transport(E),
    /// A command packet or fixed response was malformed.
    Command(CommandError),
    /// A small biometric response was malformed.
    Response(ResponseError),
    /// The FDR record was malformed or bound to another module.
    Calibration(CalibrationError),
    /// Mesa did not report calibration loaded after accepting the load.
    CalibrationNotLoaded,
}

impl<E> fmt::Debug for ControlError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(_) => formatter.write_str("Transport([redacted])"),
            Self::Command(error) => formatter.debug_tuple("Command").field(error).finish(),
            Self::Response(error) => formatter.debug_tuple("Response").field(error).finish(),
            Self::Calibration(error) => formatter.debug_tuple("Calibration").field(error).finish(),
            Self::CalibrationNotLoaded => formatter.write_str("CalibrationNotLoaded"),
        }
    }
}

impl<E> fmt::Display for ControlError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(_) => formatter.write_str("biometric transport failed"),
            Self::Command(error) => error.fmt(formatter),
            Self::Response(error) => error.fmt(formatter),
            Self::Calibration(error) => error.fmt(formatter),
            Self::CalibrationNotLoaded => {
                formatter.write_str("Mesa did not report calibration data loaded")
            }
        }
    }
}

impl<E> std::error::Error for ControlError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Command(error) => Some(error),
            Self::Response(error) => Some(error),
            Self::Calibration(error) => Some(error),
            Self::Transport(_) | Self::CalibrationNotLoaded => None,
        }
    }
}

impl<E> From<CommandError> for ControlError<E> {
    fn from(error: CommandError) -> Self {
        Self::Command(error)
    }
}

impl<E> From<ResponseError> for ControlError<E> {
    fn from(error: ResponseError) -> Self {
        Self::Response(error)
    }
}

impl<E> From<CalibrationError> for ControlError<E> {
    fn from(error: CalibrationError) -> Self {
        Self::Calibration(error)
    }
}

/// Reads and validates the opaque association of the connected Mesa module.
///
/// This operation issues exactly one read-only biometric command. The caller
/// owns the transport lifetime and must not log, persist, or expose the
/// returned value outside device-bound calibration selection or validation.
///
/// # Errors
///
/// Returns a redacted transport or fixed-response validation error.
pub fn read_module_serial<T: BiometricTransport>(
    transport: &mut T,
) -> Result<ModuleSerial, ControlError<T::Error>> {
    let response = execute(transport, &module_serial_command())?;
    parse_module_serial(&response).map_err(ControlError::Response)
}

/// Validates this sensor's signed FDR record and ensures Mesa has loaded it.
///
/// The complete outer record is validated before any mutating command. When
/// calibration is already live, no load is sent. A load is accepted only if a
/// second independent daemon-info read reports the runtime flag set.
///
/// # Errors
///
/// Returns a transport, packet, response, association, or postcondition error.
pub fn ensure_fdr_calibration_loaded<T: BiometricTransport>(
    transport: &mut T,
    record: &[u8],
) -> Result<CalibrationLoad, ControlError<T::Error>> {
    let module_serial = read_module_serial(transport)?;
    validate_fdr_calibration_record(record, module_serial.as_bytes())?;

    let initial_info = read_daemon_info(transport)?;
    if !initial_info.calibration_data_loaded {
        let load = load_calibration_command(CalibrationSource::Fdr, record)?;
        let response = execute(transport, &load)?;
        validate_empty_response(&response)?;
    }

    if !read_daemon_info(transport)?.calibration_data_loaded {
        return Err(ControlError::CalibrationNotLoaded);
    }

    Ok(CalibrationLoad {
        record_size: record.len(),
        already_loaded: initial_info.calibration_data_loaded,
    })
}

fn read_daemon_info<T: BiometricTransport>(
    transport: &mut T,
) -> Result<crate::biometric::DaemonInfo, ControlError<T::Error>> {
    let response = execute(transport, &daemon_info_command())?;
    parse_daemon_info(&response).map_err(ControlError::Response)
}

fn execute<T: BiometricTransport>(
    transport: &mut T,
    packet: &CommandPacket,
) -> Result<Vec<u8>, ControlError<T::Error>> {
    transport.execute(packet).map_err(ControlError::Transport)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::biometric::{COMMAND_HEADER_SIZE, DAEMON_INFO_SIZE};
    use crate::calibration::MODULE_SERIAL_NUMBER_SIZE;
    use crate::framing::{FRAME_BINARY_PLIST, FRAME_HELLO, Frame};
    use crate::rpc::{RpcEnvelope, decode_envelope, encode_reply};
    use std::collections::VecDeque;
    use std::io::{self, Cursor};

    const MODULE_SERIAL: &[u8; MODULE_SERIAL_NUMBER_SIZE] = b"SYNTHETICMODULE001";
    const OTHER_MODULE: &[u8; MODULE_SERIAL_NUMBER_SIZE] = b"SYNTHETICMODULE002";

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct SyntheticTransportError;

    impl fmt::Display for SyntheticTransportError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("sensitive transport detail")
        }
    }

    impl std::error::Error for SyntheticTransportError {}

    struct FakeTransport {
        responses: VecDeque<Result<Vec<u8>, SyntheticTransportError>>,
        commands: Vec<(u16, u16, usize, usize)>,
    }

    impl FakeTransport {
        fn new(responses: impl IntoIterator<Item = Vec<u8>>) -> Self {
            Self {
                responses: responses.into_iter().map(Ok).collect(),
                commands: Vec::new(),
            }
        }
    }

    impl BiometricTransport for FakeTransport {
        type Error = SyntheticTransportError;

        fn execute(&mut self, packet: &CommandPacket) -> Result<Vec<u8>, Self::Error> {
            let request = packet.request();
            let command = u16::from_le_bytes(request[2..4].try_into().unwrap());
            let value = u16::from_le_bytes(request[6..8].try_into().unwrap());
            self.commands.push((
                command,
                value,
                request.len() - COMMAND_HEADER_SIZE,
                packet.response_capacity(),
            ));
            self.responses.pop_front().expect("synthetic response")
        }
    }

    struct Duplex {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl Duplex {
        fn new(frames: &[Frame]) -> Self {
            let mut input = Vec::new();
            for frame in frames {
                input.extend_from_slice(&frame.encode().unwrap());
            }
            Self {
                input: Cursor::new(input),
                output: Vec::new(),
            }
        }
    }

    impl Read for Duplex {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            self.input.read(output)
        }
    }

    impl Write for Duplex {
        fn write(&mut self, input: &[u8]) -> io::Result<usize> {
            self.output.extend_from_slice(input);
            Ok(input.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn module_serial_query_is_one_read_only_command() {
        let mut transport = FakeTransport::new([MODULE_SERIAL.to_vec()]);

        let serial = read_module_serial(&mut transport).unwrap();

        assert_eq!(serial.as_bytes(), MODULE_SERIAL);
        assert_eq!(
            transport.commands,
            [(0x22, 0, 0, MODULE_SERIAL_NUMBER_SIZE)]
        );
    }

    #[test]
    fn module_serial_query_rejects_malformed_responses() {
        for response in [
            b"SYNTHETICMODULE01".to_vec(),
            b"SYNTHETICMODULE0010".to_vec(),
            b"SYNTHETICMODULE00!".to_vec(),
        ] {
            let mut transport = FakeTransport::new([response]);

            assert!(matches!(
                read_module_serial(&mut transport),
                Err(ControlError::Response(_))
            ));
            assert_eq!(
                transport.commands,
                [(0x22, 0, 0, MODULE_SERIAL_NUMBER_SIZE)]
            );
        }
    }

    #[test]
    fn module_serial_transport_failure_is_redacted() {
        let mut transport = FakeTransport {
            responses: VecDeque::from([Err(SyntheticTransportError)]),
            commands: Vec::new(),
        };

        let error = read_module_serial(&mut transport).unwrap_err();

        assert!(matches!(error, ControlError::Transport(_)));
        assert_eq!(
            transport.commands,
            [(0x22, 0, 0, MODULE_SERIAL_NUMBER_SIZE)]
        );
        assert_eq!(format!("{error:?}"), "Transport([redacted])");
        assert_eq!(error.to_string(), "biometric transport failed");
        assert!(std::error::Error::source(&error).is_none());
    }

    #[test]
    fn loads_validated_outer_fdr_and_verifies_runtime_state() {
        let record = fdr_record(MODULE_SERIAL);
        let mut transport = FakeTransport::new([
            MODULE_SERIAL.to_vec(),
            daemon_info(false),
            Vec::new(),
            daemon_info(true),
        ]);

        assert_eq!(
            ensure_fdr_calibration_loaded(&mut transport, &record).unwrap(),
            CalibrationLoad {
                record_size: record.len(),
                already_loaded: false,
            }
        );
        assert_eq!(
            transport.commands,
            [
                (0x22, 0, 0, MODULE_SERIAL_NUMBER_SIZE),
                (0x28, 0, 0, DAEMON_INFO_SIZE),
                (0x20, 3, record.len(), 0),
                (0x28, 0, 0, DAEMON_INFO_SIZE),
            ]
        );
    }

    #[test]
    fn already_loaded_path_is_read_only() {
        let record = fdr_record(MODULE_SERIAL);
        let mut transport =
            FakeTransport::new([MODULE_SERIAL.to_vec(), daemon_info(true), daemon_info(true)]);

        let result = ensure_fdr_calibration_loaded(&mut transport, &record).unwrap();
        assert!(result.already_loaded);
        assert_eq!(
            transport
                .commands
                .iter()
                .map(|command| command.0)
                .collect::<Vec<_>>(),
            [0x22, 0x28, 0x28]
        );
    }

    #[test]
    fn wrong_module_is_rejected_before_mutating_or_status_calls() {
        let record = fdr_record(OTHER_MODULE);
        let mut transport = FakeTransport::new([MODULE_SERIAL.to_vec()]);

        assert!(matches!(
            ensure_fdr_calibration_loaded(&mut transport, &record),
            Err(ControlError::Calibration(CalibrationError::DifferentModule))
        ));
        assert_eq!(transport.commands.len(), 1);
        assert_eq!(transport.commands[0].0, 0x22);
    }

    #[test]
    fn load_response_and_postcondition_fail_closed() {
        let record = fdr_record(MODULE_SERIAL);
        let mut unexpected =
            FakeTransport::new([MODULE_SERIAL.to_vec(), daemon_info(false), vec![1]]);
        assert!(matches!(
            ensure_fdr_calibration_loaded(&mut unexpected, &record),
            Err(ControlError::Command(
                CommandError::UnexpectedResponseData { actual: 1 }
            ))
        ));

        let mut not_loaded = FakeTransport::new([
            MODULE_SERIAL.to_vec(),
            daemon_info(false),
            Vec::new(),
            daemon_info(false),
        ]);
        assert!(matches!(
            ensure_fdr_calibration_loaded(&mut not_loaded, &record),
            Err(ControlError::CalibrationNotLoaded)
        ));
    }

    #[test]
    fn malformed_metadata_and_transport_errors_are_redacted() {
        let record = fdr_record(MODULE_SERIAL);
        let mut malformed =
            FakeTransport::new([MODULE_SERIAL.to_vec(), vec![0; DAEMON_INFO_SIZE - 1]]);
        assert!(matches!(
            ensure_fdr_calibration_loaded(&mut malformed, &record),
            Err(ControlError::Response(_))
        ));

        let mut failed = FakeTransport {
            responses: VecDeque::from([Err(SyntheticTransportError)]),
            commands: Vec::new(),
        };
        let error = ensure_fdr_calibration_loaded(&mut failed, &record).unwrap_err();
        let diagnostic = format!("{error:?} {error}");
        assert!(!diagnostic.contains("sensitive transport detail"));
        assert!(!diagnostic.contains("SYNTHETICMODULE"));
        assert!(std::error::Error::source(&error).is_none());
    }

    #[test]
    fn live_adapter_requires_version_and_validates_rpc_results() {
        let version_id = RequestId::from_uuid_v4_bytes([0x11; 16]);
        let command_id = RequestId::from_uuid_v4_bytes([0x22; 16]);
        let hello = Frame::new(
            FRAME_HELLO,
            br#"{"MaxSupportedProtocolVersion":1}"#.to_vec(),
        )
        .unwrap();
        let version_reply = Frame::new(
            FRAME_BINARY_PLIST,
            encode_reply(
                &version_id,
                &[
                    crate::bplist::Value::Integer(0),
                    crate::bplist::Value::Boolean(true),
                ],
            )
            .unwrap(),
        )
        .unwrap();
        let command_reply = Frame::new(
            FRAME_BINARY_PLIST,
            encode_reply(
                &command_id,
                &[
                    crate::bplist::Value::Integer(0),
                    crate::bplist::Value::Data(vec![0xa5]),
                ],
            )
            .unwrap(),
        )
        .unwrap();
        let mut session = BridgeXpcSession::connect(
            Duplex::new(&[hello, version_reply, command_reply]),
            "synthetic-client",
        )
        .unwrap();
        let ids = vec![version_id.clone(), command_id.clone()].into_iter();
        let mut adapter = SessionBiometricTransport::new(&mut session, ids);

        assert!(matches!(
            adapter.execute(&crate::commands::calibration_status_command()),
            Err(BridgeCommandError::ClientVersionNotSelected)
        ));
        adapter.select_client_version().unwrap();
        assert_eq!(
            adapter
                .execute(&crate::commands::calibration_status_command())
                .unwrap(),
            [0xa5]
        );
        assert!(matches!(
            adapter.select_client_version(),
            Err(BridgeCommandError::ClientVersionAlreadySelected)
        ));
        drop(adapter);

        let stream = session.into_inner();
        let frames = decode_frames(&stream.output);
        assert_eq!(frames.len(), 3);
        let RpcEnvelope::Request {
            request_id,
            payload,
        } = decode_envelope(&frames[1].body).unwrap()
        else {
            panic!("expected version request");
        };
        assert_eq!(request_id, version_id);
        assert_eq!(payload, set_client_version_request(2));
        let RpcEnvelope::Request { request_id, .. } = decode_envelope(&frames[2].body).unwrap()
        else {
            panic!("expected biometric request");
        };
        assert_eq!(request_id, command_id);
    }

    #[test]
    fn live_adapter_fails_closed_when_identifiers_are_exhausted() {
        let hello = Frame::new(
            FRAME_HELLO,
            br#"{"MaxSupportedProtocolVersion":1}"#.to_vec(),
        )
        .unwrap();
        let mut session = BridgeXpcSession::connect(Duplex::new(&[hello]), "client").unwrap();
        let mut adapter = SessionBiometricTransport::new(&mut session, std::iter::empty());
        assert!(matches!(
            adapter.select_client_version(),
            Err(BridgeCommandError::RequestIdUnavailable)
        ));
    }

    fn decode_frames(mut encoded: &[u8]) -> Vec<Frame> {
        let mut frames = Vec::new();
        while !encoded.is_empty() {
            let (frame, rest) = Frame::decode_prefix(encoded).unwrap();
            frames.push(frame);
            encoded = rest;
        }
        frames
    }

    fn daemon_info(loaded: bool) -> Vec<u8> {
        let mut response = vec![0_u8; DAEMON_INFO_SIZE];
        response[22] = u8::from(loaded);
        response
    }

    fn fdr_record(module_serial: &[u8; MODULE_SERIAL_NUMBER_SIZE]) -> Vec<u8> {
        let mut calibration = vec![0_u8; 96];
        let calibration_size = u32::try_from(calibration.len()).unwrap();
        calibration[4..8].copy_from_slice(&calibration_size.to_le_bytes());
        calibration[16..20].copy_from_slice(b"CALB");
        calibration[32..50].copy_from_slice(module_serial);

        let im4p = der_sequence(&[
            der(0x16, b"IM4P"),
            der(0x16, b"FSCl"),
            der(0x16, b"1.0"),
            der(0x04, &calibration),
        ]);
        let img4 = der_sequence(&[der(0x16, b"IMG4"), im4p]);
        let fdrd = der_sequence(&[der(0x16, b"fdrd"), der(0x04, &img4)]);
        der_sequence(&[der(0x16, b"comb"), fdrd])
    }

    fn der_sequence(children: &[Vec<u8>]) -> Vec<u8> {
        der(0x30, &children.concat())
    }

    fn der(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut encoded = vec![tag];
        if content.len() < 0x80 {
            encoded.push(u8::try_from(content.len()).unwrap());
        } else {
            encoded.push(0x81);
            encoded.push(u8::try_from(content.len()).unwrap());
        }
        encoded.extend_from_slice(content);
        encoded
    }
}

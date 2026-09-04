//! Deterministic Mesa biometric-user preparation and guarded rebind workflows.

use crate::biometric::{ResponseError, parse_daemon_info};
use crate::catacomb::{CatacombError, CatacombStateEntry, parse_catacomb_states};
use crate::commands::{
    CommandError, CommandPacket, catacomb_states_command, daemon_info_command, identities_command,
    remove_user_command, set_active_user_command, validate_empty_response,
    validate_identity_list_response,
};
use crate::control::BiometricTransport;
use crate::mesa::{IDENTITY_V1_SIZE, Identity, MesaError, parse_identity};
use crate::policy::BiometricUserId;
use core::fmt;

/// A redaction-safe biometric-user preparation or rebind failure.
pub enum UserWorkflowError<TransportError> {
    /// The caller-owned biometric transport failed.
    Transport(TransportError),
    /// A command could not be built or its empty/list response was malformed.
    Command(CommandError),
    /// Mesa returned malformed daemon metadata.
    Response(ResponseError),
    /// Mesa returned malformed catacomb component state.
    Catacomb(CatacombError),
    /// Mesa returned a malformed identity record.
    Mesa(MesaError),
    /// A valid identity belonged to a user other than the requested user.
    IdentityForWrongUser,
    /// Guarded rebind found one or more enrolled identities.
    RebindHasEnrolledIdentities,
}

impl<TransportError> fmt::Debug for UserWorkflowError<TransportError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(_) => formatter.write_str("Transport([redacted])"),
            Self::Command(error) => formatter.debug_tuple("Command").field(error).finish(),
            Self::Response(error) => formatter.debug_tuple("Response").field(error).finish(),
            Self::Catacomb(error) => formatter.debug_tuple("Catacomb").field(error).finish(),
            Self::Mesa(error) => formatter.debug_tuple("Mesa").field(error).finish(),
            Self::IdentityForWrongUser => formatter.write_str("IdentityForWrongUser"),
            Self::RebindHasEnrolledIdentities => formatter.write_str("RebindHasEnrolledIdentities"),
        }
    }
}

impl<TransportError> fmt::Display for UserWorkflowError<TransportError> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Transport(_) => formatter.write_str("biometric user transport failed"),
            Self::Command(error) => error.fmt(formatter),
            Self::Response(error) => error.fmt(formatter),
            Self::Catacomb(error) => error.fmt(formatter),
            Self::Mesa(error) => error.fmt(formatter),
            Self::IdentityForWrongUser => {
                formatter.write_str("Mesa returned an identity for another user")
            }
            Self::RebindHasEnrolledIdentities => {
                formatter.write_str("refusing to rebind a biometric user with enrolled identities")
            }
        }
    }
}

impl<TransportError> std::error::Error for UserWorkflowError<TransportError> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Command(error) => Some(error),
            Self::Response(error) => Some(error),
            Self::Catacomb(error) => Some(error),
            Self::Mesa(error) => Some(error),
            Self::Transport(_) | Self::IdentityForWrongUser | Self::RebindHasEnrolledIdentities => {
                None
            }
        }
    }
}

/// Refreshes Mesa's catacomb component map and returns its entry count.
///
/// Daemon metadata is read first because its bounded component count defines
/// the exact maximum state-response allocation.
///
/// # Errors
///
/// Returns a transport, command-construction, daemon-response, or catacomb-
/// state parsing failure.
pub fn refresh_catacomb_state<Transport: BiometricTransport>(
    transport: &mut Transport,
) -> Result<usize, UserWorkflowError<Transport::Error>> {
    read_catacomb_states(transport).map(|states| states.len())
}

/// Refreshes and returns Mesa's bounded catacomb component map.
///
/// User identifiers and state bits remain raw protocol values. Callers may use
/// them only for an explicitly defined recovery or enrollment decision.
///
/// # Errors
///
/// Returns a transport, command-construction, daemon-response, or catacomb-
/// state parsing failure.
pub fn read_catacomb_states<Transport: BiometricTransport>(
    transport: &mut Transport,
) -> Result<Vec<CatacombStateEntry>, UserWorkflowError<Transport::Error>> {
    let daemon_response = execute(transport, &daemon_info_command())?;
    let daemon_info = parse_daemon_info(&daemon_response).map_err(UserWorkflowError::Response)?;
    let states_command =
        catacomb_states_command(daemon_info.component_count).map_err(UserWorkflowError::Command)?;
    let states_response = execute(transport, &states_command)?;
    parse_catacomb_states(&states_response, daemon_info.component_count)
        .map_err(UserWorkflowError::Catacomb)
}

/// Selects one concrete user, refreshes catacomb state, and reads identities.
///
/// Every returned identity is structurally parsed and required to belong to
/// `user_id` before it is returned.
///
/// # Errors
///
/// Returns a transport, command, daemon, catacomb, identity, or association
/// failure.
pub fn prepare_user<Transport: BiometricTransport>(
    transport: &mut Transport,
    user_id: BiometricUserId,
) -> Result<Vec<Identity>, UserWorkflowError<Transport::Error>> {
    select_user(transport, i64::from(user_id.as_raw()))?;
    refresh_catacomb_state(transport)?;
    read_identities(transport, user_id)
}

/// Reads and association-checks the current identity list for one user.
///
/// Unlike [`prepare_user`], this does not select the user or refresh catacomb
/// state. It is intended for a post-commit invariant check while the same user
/// remains selected.
///
/// # Errors
///
/// Returns a transport, command, identity, or association failure.
pub fn list_user_identities<Transport: BiometricTransport>(
    transport: &mut Transport,
    user_id: BiometricUserId,
) -> Result<Vec<Identity>, UserWorkflowError<Transport::Error>> {
    read_identities(transport, user_id)
}

/// Recreates an empty Mesa user against the current Apple keybag association.
///
/// The identity list is fully parsed and association-checked before the first
/// mutating command. Any identity refuses the rebind. An empty user is removed,
/// the master component is selected and refreshed, then the concrete user is
/// prepared in native order.
///
/// # Errors
///
/// Returns a validation or protocol failure, or refuses when any enrolled
/// identity exists. Refusal and read-side validation occur before removal.
pub fn rebind_empty_user<Transport: BiometricTransport>(
    transport: &mut Transport,
    user_id: BiometricUserId,
) -> Result<Vec<Identity>, UserWorkflowError<Transport::Error>> {
    if !read_identities(transport, user_id)?.is_empty() {
        return Err(UserWorkflowError::RebindHasEnrolledIdentities);
    }

    let response = execute(transport, &remove_user_command(user_id))?;
    validate_empty_response(&response).map_err(UserWorkflowError::Command)?;
    select_user(transport, -1)?;
    refresh_catacomb_state(transport)?;
    prepare_user(transport, user_id)
}

/// Selects Mesa's master component before preparing one concrete user.
///
/// This mirrors native login and user-switch ordering without loading a saved
/// catacomb.
///
/// # Errors
///
/// Returns a transport, command, daemon, catacomb, identity, or association
/// failure.
pub fn refresh_user<Transport: BiometricTransport>(
    transport: &mut Transport,
    user_id: BiometricUserId,
) -> Result<Vec<Identity>, UserWorkflowError<Transport::Error>> {
    select_user(transport, -1)?;
    prepare_user(transport, user_id)
}

fn select_user<Transport: BiometricTransport>(
    transport: &mut Transport,
    user_id: i64,
) -> Result<(), UserWorkflowError<Transport::Error>> {
    let command = set_active_user_command(user_id).map_err(UserWorkflowError::Command)?;
    let response = execute(transport, &command)?;
    validate_empty_response(&response).map_err(UserWorkflowError::Command)
}

fn read_identities<Transport: BiometricTransport>(
    transport: &mut Transport,
    user_id: BiometricUserId,
) -> Result<Vec<Identity>, UserWorkflowError<Transport::Error>> {
    let response = execute(transport, &identities_command(user_id))?;
    validate_identity_list_response(&response).map_err(UserWorkflowError::Command)?;
    let records = response.as_chunks::<IDENTITY_V1_SIZE>().0;
    let identities = records
        .iter()
        .map(|record| parse_identity(record))
        .collect::<Result<Vec<_>, _>>()
        .map_err(UserWorkflowError::Mesa)?;
    let requested_user_id = user_id.as_raw().cast_signed();
    if identities
        .iter()
        .any(|identity| identity.user_id() != requested_user_id)
    {
        return Err(UserWorkflowError::IdentityForWrongUser);
    }
    Ok(identities)
}

fn execute<Transport: BiometricTransport>(
    transport: &mut Transport,
    packet: &CommandPacket,
) -> Result<Vec<u8>, UserWorkflowError<Transport::Error>> {
    transport
        .execute(packet)
        .map_err(UserWorkflowError::Transport)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::biometric::DAEMON_INFO_SIZE;
    use crate::commands::IDENTITY_LIST_CAPACITY;
    use crate::mesa::IdentityIdentifier;
    use std::collections::VecDeque;

    const USER: i32 = 501;
    const OTHER_USER: i32 = 502;
    const IDENTIFIER: IdentityIdentifier = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];

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
        commands: Vec<(u16, Vec<u8>, usize)>,
    }

    impl FakeTransport {
        fn new(
            responses: impl IntoIterator<Item = Result<Vec<u8>, SyntheticTransportError>>,
        ) -> Self {
            Self {
                responses: responses.into_iter().collect(),
                commands: Vec::new(),
            }
        }
    }

    impl BiometricTransport for FakeTransport {
        type Error = SyntheticTransportError;

        fn execute(&mut self, packet: &CommandPacket) -> Result<Vec<u8>, Self::Error> {
            let request = packet.request();
            self.commands.push((
                u16::from_le_bytes(request[2..4].try_into().unwrap()),
                request.to_vec(),
                packet.response_capacity(),
            ));
            self.responses.pop_front().expect("synthetic response")
        }
    }

    fn user() -> BiometricUserId {
        BiometricUserId::new(i64::from(USER)).unwrap()
    }

    fn daemon_info(component_count: u32) -> Vec<u8> {
        let mut response = vec![0_u8; DAEMON_INFO_SIZE];
        response[..4].copy_from_slice(&component_count.to_le_bytes());
        response[4..8].copy_from_slice(&5_u32.to_le_bytes());
        response
    }

    fn states(entries: &[(u32, u32)]) -> Vec<u8> {
        let mut response = Vec::with_capacity(entries.len() * 8);
        for (user_id, state) in entries {
            response.extend_from_slice(&user_id.to_le_bytes());
            response.extend_from_slice(&state.to_le_bytes());
        }
        response
    }

    fn identity(user_id: i32, identifier: IdentityIdentifier) -> Vec<u8> {
        let mut response = Vec::with_capacity(IDENTITY_V1_SIZE);
        response.extend_from_slice(&user_id.to_le_bytes());
        response.extend_from_slice(&identifier);
        response
    }

    fn command_codes(transport: &FakeTransport) -> Vec<u16> {
        transport
            .commands
            .iter()
            .map(|(command, _, _)| *command)
            .collect()
    }

    fn encoded_user(transport: &FakeTransport, index: usize) -> u32 {
        u32::from_le_bytes(transport.commands[index].1[8..12].try_into().unwrap())
    }

    #[test]
    fn refresh_reads_bounded_state_in_exact_order() {
        let mut transport = FakeTransport::new([
            Ok(daemon_info(2)),
            Ok(states(&[(u32::MAX, 1), (USER.cast_unsigned(), 3)])),
        ]);

        assert_eq!(refresh_catacomb_state(&mut transport).unwrap(), 2);
        assert_eq!(command_codes(&transport), vec![0x28, 0x3c]);
        assert_eq!(transport.commands[0].2, DAEMON_INFO_SIZE);
        assert_eq!(transport.commands[1].2, 3 * 8);
    }

    #[test]
    fn prepare_selects_refreshes_and_validates_identities() {
        let mut records = identity(USER, IDENTIFIER);
        records.extend_from_slice(&identity(USER, [0x22; 16]));
        let mut transport = FakeTransport::new([
            Ok(Vec::new()),
            Ok(daemon_info(1)),
            Ok(states(&[(USER.cast_unsigned(), 3)])),
            Ok(records),
        ]);

        let identities = prepare_user(&mut transport, user()).unwrap();
        assert_eq!(identities.len(), 2);
        assert!(identities.iter().all(|identity| identity.user_id() == USER));
        assert_eq!(command_codes(&transport), vec![0x31, 0x28, 0x3c, 0x42]);
        assert_eq!(encoded_user(&transport, 0), USER.cast_unsigned());
        assert_eq!(encoded_user(&transport, 3), USER.cast_unsigned());
        assert_eq!(transport.commands[3].2, IDENTITY_LIST_CAPACITY);
    }

    #[test]
    fn refresh_user_passes_through_master_before_concrete_user() {
        let mut transport = FakeTransport::new([
            Ok(Vec::new()),
            Ok(Vec::new()),
            Ok(daemon_info(0)),
            Ok(states(&[])),
            Ok(identity(USER, IDENTIFIER)),
        ]);

        assert_eq!(refresh_user(&mut transport, user()).unwrap().len(), 1);
        assert_eq!(
            command_codes(&transport),
            vec![0x31, 0x31, 0x28, 0x3c, 0x42]
        );
        assert_eq!(encoded_user(&transport, 0), u32::MAX);
        assert_eq!(encoded_user(&transport, 1), USER.cast_unsigned());
    }

    #[test]
    fn guarded_rebind_uses_exact_native_mutation_order() {
        let mut transport = FakeTransport::new([
            Ok(Vec::new()),
            Ok(Vec::new()),
            Ok(Vec::new()),
            Ok(daemon_info(0)),
            Ok(states(&[])),
            Ok(Vec::new()),
            Ok(daemon_info(0)),
            Ok(states(&[])),
            Ok(Vec::new()),
        ]);

        assert!(
            rebind_empty_user(&mut transport, user())
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            command_codes(&transport),
            vec![0x42, 0x48, 0x31, 0x28, 0x3c, 0x31, 0x28, 0x3c, 0x42]
        );
        assert_eq!(encoded_user(&transport, 0), USER.cast_unsigned());
        assert_eq!(encoded_user(&transport, 1), USER.cast_unsigned());
        assert_eq!(encoded_user(&transport, 2), u32::MAX);
        assert_eq!(encoded_user(&transport, 5), USER.cast_unsigned());
        assert_eq!(encoded_user(&transport, 8), USER.cast_unsigned());
    }

    #[test]
    fn guarded_rebind_refuses_any_valid_identity_before_mutation() {
        let mut transport = FakeTransport::new([Ok(identity(USER, IDENTIFIER))]);

        assert!(matches!(
            rebind_empty_user(&mut transport, user()),
            Err(UserWorkflowError::RebindHasEnrolledIdentities)
        ));
        assert_eq!(command_codes(&transport), vec![0x42]);
    }

    #[test]
    fn guarded_rebind_validates_all_identity_data_before_mutation() {
        for (response, expected) in [
            (vec![0; IDENTITY_V1_SIZE - 1], "shape"),
            (identity(USER, [0; 16]), "record"),
            (identity(OTHER_USER, IDENTIFIER), "association"),
        ] {
            let mut transport = FakeTransport::new([Ok(response)]);
            let error = rebind_empty_user(&mut transport, user()).unwrap_err();
            match expected {
                "shape" => assert!(matches!(error, UserWorkflowError::Command(_))),
                "record" => assert!(matches!(error, UserWorkflowError::Mesa(_))),
                "association" => {
                    assert!(matches!(error, UserWorkflowError::IdentityForWrongUser));
                }
                _ => unreachable!(),
            }
            assert_eq!(command_codes(&transport), vec![0x42]);
        }
    }

    #[test]
    fn each_failure_stops_before_the_next_command() {
        let mut select_failure = FakeTransport::new([Err(SyntheticTransportError)]);
        assert!(matches!(
            refresh_user(&mut select_failure, user()),
            Err(UserWorkflowError::Transport(_))
        ));
        assert_eq!(command_codes(&select_failure), vec![0x31]);

        let mut daemon_failure = FakeTransport::new([Ok(vec![0; DAEMON_INFO_SIZE - 1])]);
        assert!(matches!(
            refresh_catacomb_state(&mut daemon_failure),
            Err(UserWorkflowError::Response(_))
        ));
        assert_eq!(command_codes(&daemon_failure), vec![0x28]);

        let mut state_failure = FakeTransport::new([Ok(daemon_info(0)), Ok(vec![0; 1])]);
        assert!(matches!(
            refresh_catacomb_state(&mut state_failure),
            Err(UserWorkflowError::Catacomb(_))
        ));
        assert_eq!(command_codes(&state_failure), vec![0x28, 0x3c]);

        let mut remove_failure = FakeTransport::new([Ok(Vec::new()), Ok(vec![0xaa])]);
        assert!(matches!(
            rebind_empty_user(&mut remove_failure, user()),
            Err(UserWorkflowError::Command(_))
        ));
        assert_eq!(command_codes(&remove_failure), vec![0x42, 0x48]);
    }

    #[test]
    fn transport_errors_are_redacted_in_debug_display_and_source_chain() {
        let error = UserWorkflowError::Transport(SyntheticTransportError);
        for rendered in [format!("{error:?}"), error.to_string()] {
            assert!(!rendered.contains("sensitive"));
            assert!(!rendered.contains("detail"));
        }
        assert!(std::error::Error::source(&error).is_none());
    }
}

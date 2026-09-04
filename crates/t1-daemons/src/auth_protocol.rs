//! Pure wire protocol and state validation for Touch ID authentication.
//!
//! This module deliberately does not open sockets or obtain peer credentials.
//! A future transport adapter must supply metadata that it has independently
//! authenticated. Only an exact success response satisfies a client request.

use std::fmt;
use std::time::Duration;

/// Protocol version carried in every broker request.
pub const PROTOCOL_VERSION: u8 = 1;
/// Maximum sensor match window accepted from a client.
pub const MAX_MATCH_TIMEOUT: Duration = Duration::from_secs(30);
/// Outer client allowance for relay handoff and ACM setup before matching.
pub const SETUP_ALLOWANCE: Duration = Duration::from_secs(35);
/// `BridgeOS` biometric user identifier used by the supported protocol.
pub const BIOMETRIC_USER_ID: u32 = 501;

pub const AUTHENTICATE_REQUEST: &[u8; 8] = b"T1AUTH\x01\n";
pub const APPROVE_REQUEST: &[u8; 8] = b"T1APRV\x01\n";
pub const ENROLL_REQUEST: &[u8; 8] = b"T1ENRL\x01\n";
pub const CANCEL_REQUEST: &[u8; 8] = b"T1CNCL\x01\n";

pub const RESPONSE_OK: &[u8; 4] = b"OKAY";
pub const RESPONSE_DENIED: &[u8; 4] = b"DENY";
pub const RESPONSE_BUSY: &[u8; 4] = b"BUSY";
pub const RESPONSE_FAILURE: &[u8; 4] = b"FAIL";

const REQUEST_SIZE: usize = 8;
const RESPONSE_SIZE: usize = 4;
const ROOT_UID: u32 = 0;
const WORLD_WRITABLE: u32 = 0o002;

/// One typed request accepted by the authentication broker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Request {
    Authenticate,
    Approve,
    Enroll,
    Cancel,
}

impl Request {
    /// Returns the complete v1 packet for this request.
    #[must_use]
    pub const fn encode(self) -> &'static [u8; REQUEST_SIZE] {
        match self {
            Self::Authenticate => AUTHENTICATE_REQUEST,
            Self::Approve => APPROVE_REQUEST,
            Self::Enroll => ENROLL_REQUEST,
            Self::Cancel => CANCEL_REQUEST,
        }
    }
}

/// A fixed broker response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Response {
    Okay,
    Denied,
    Busy,
    Failure,
}

impl Response {
    /// Returns the complete v1 packet for this response.
    #[must_use]
    pub const fn encode(self) -> &'static [u8; RESPONSE_SIZE] {
        match self {
            Self::Okay => RESPONSE_OK,
            Self::Denied => RESPONSE_DENIED,
            Self::Busy => RESPONSE_BUSY,
            Self::Failure => RESPONSE_FAILURE,
        }
    }
}

/// Payload-redacted request decoding failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestError {
    WrongLength,
    WrongTerminator,
    UnsupportedVersion,
    UnsupportedAction,
}

impl fmt::Display for RequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WrongLength => "authentication request has the wrong length",
            Self::WrongTerminator => "authentication request has the wrong terminator",
            Self::UnsupportedVersion => "authentication request uses an unsupported version",
            Self::UnsupportedAction => "authentication request uses an unsupported action",
        })
    }
}

impl std::error::Error for RequestError {}

/// Payload-redacted response decoding failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseError {
    WrongLength,
    UnsupportedResponse,
}

impl fmt::Display for ResponseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WrongLength => "authentication response has the wrong length",
            Self::UnsupportedResponse => "authentication response is unsupported",
        })
    }
}

impl std::error::Error for ResponseError {}

/// Decode one complete request packet.
///
/// # Errors
///
/// Returns a payload-free error for a packet with the wrong size, terminator,
/// protocol version, or action.
pub fn decode_request(packet: &[u8]) -> Result<Request, RequestError> {
    if packet.len() != REQUEST_SIZE {
        return Err(RequestError::WrongLength);
    }
    if packet[REQUEST_SIZE - 1] != b'\n' {
        return Err(RequestError::WrongTerminator);
    }
    if packet[REQUEST_SIZE - 2] != PROTOCOL_VERSION {
        return Err(RequestError::UnsupportedVersion);
    }

    match &packet[..REQUEST_SIZE - 2] {
        b"T1AUTH" => Ok(Request::Authenticate),
        b"T1APRV" => Ok(Request::Approve),
        b"T1ENRL" => Ok(Request::Enroll),
        b"T1CNCL" => Ok(Request::Cancel),
        _ => Err(RequestError::UnsupportedAction),
    }
}

/// Decode one complete response packet.
///
/// # Errors
///
/// Returns a payload-free error unless the packet is exactly one known
/// four-byte response.
pub fn decode_response(packet: &[u8]) -> Result<Response, ResponseError> {
    if packet.len() != RESPONSE_SIZE {
        return Err(ResponseError::WrongLength);
    }

    match packet {
        b"OKAY" => Ok(Response::Okay),
        b"DENY" => Ok(Response::Denied),
        b"BUSY" => Ok(Response::Busy),
        b"FAIL" => Ok(Response::Failure),
        _ => Err(ResponseError::UnsupportedResponse),
    }
}

/// Address-family classification supplied by a transport adapter.
///
/// This is validation data, not a socket implementation. Netlink may be
/// required internally by hardware discovery, but it is never a valid family
/// for a broker client connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerAddressFamily {
    Local,
    InternetV6,
    Netlink,
    Other,
}

/// Peer metadata obtained and authenticated outside this module.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct PeerMetadata {
    pub address_family: PeerAddressFamily,
    pub user_id: u32,
    pub group_id: u32,
}

impl fmt::Debug for PeerMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PeerMetadata { credentials: <redacted> }")
    }
}

/// Metadata for the broker endpoint, obtained outside this module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointMetadata {
    pub kind: EndpointKind,
    pub owner_user_id: u32,
    pub mode: u32,
}

/// Filesystem object type reported for the broker endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointKind {
    LocalSocket,
    Other,
}

/// Returns whether caller-supplied endpoint metadata meets the client trust
/// contract: local socket, root-owned, and not writable by everyone.
#[must_use]
pub const fn endpoint_is_trusted(metadata: EndpointMetadata) -> bool {
    matches!(metadata.kind, EndpointKind::LocalSocket)
        && metadata.owner_user_id == ROOT_UID
        && metadata.mode & WORLD_WRITABLE == 0
}

/// Authorization policy sourced from the recorded enrollment owner.
///
/// Root is also admitted because privilege-elevating PAM consumers retain
/// root credentials. Both allowed Linux identities map to the protocol's
/// fixed `BridgeOS` biometric user. No workstation UID is compiled in.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessPolicy {
    enrollment_owner_user_id: u32,
}

impl AccessPolicy {
    /// Creates policy for the stored non-root enrollment owner.
    ///
    /// # Errors
    ///
    /// Rejects root as the enrollment owner because root is already handled
    /// explicitly and does not identify the owning non-root Linux account.
    pub const fn new(enrollment_owner_user_id: u32) -> Result<Self, PolicyError> {
        if enrollment_owner_user_id == ROOT_UID {
            Err(PolicyError::InvalidEnrollmentOwner)
        } else {
            Ok(Self {
                enrollment_owner_user_id,
            })
        }
    }

    /// Returns whether authenticated local peer metadata is admitted.
    ///
    /// Transport adapters use this before reading a request so an
    /// unauthorized peer cannot make the broker parse or act on its bytes.
    #[must_use]
    pub fn peer_is_authorized(self, peer: PeerMetadata) -> bool {
        self.biometric_user_for(peer).is_some()
    }

    fn biometric_user_for(self, peer: PeerMetadata) -> Option<u32> {
        if peer.address_family != PeerAddressFamily::Local {
            return None;
        }
        if peer.user_id == ROOT_UID || peer.user_id == self.enrollment_owner_user_id {
            Some(BIOMETRIC_USER_ID)
        } else {
            None
        }
    }

    /// Returns the recorded non-root enrollment owner for an independently
    /// resolved standard-protocol operation.
    #[must_use]
    pub(crate) const fn enrollment_owner_user_id(self) -> u32 {
        self.enrollment_owner_user_id
    }
}

/// Invalid dynamic access policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PolicyError {
    InvalidEnrollmentOwner,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("enrollment owner mapping is invalid")
    }
}

impl std::error::Error for PolicyError {}

/// Broker operation selected by the request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Purpose {
    Authenticate,
    Approve,
    Enrollment,
}

/// Kernel-authenticated non-root identity proposed as the durable enrollment
/// owner only after enrollment succeeds.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EnrollmentOwnerCandidate(u32);

impl EnrollmentOwnerCandidate {
    const fn new(user_id: u32) -> Option<Self> {
        if user_id == ROOT_UID {
            None
        } else {
            Some(Self(user_id))
        }
    }

    /// Returns the validated kernel user ID for a later durable owner claim.
    #[must_use]
    pub const fn user_id(self) -> u32 {
        self.0
    }
}

impl fmt::Debug for EnrollmentOwnerCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EnrollmentOwnerCandidate(<redacted>)")
    }
}

/// Opaque, process-local handle for an active operation.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct OperationToken(u64);

impl fmt::Debug for OperationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OperationToken(<redacted>)")
    }
}

/// Work emitted by the pure broker state machine for its hardware adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Operation {
    pub token: OperationToken,
    pub biometric_user_id: u32,
    pub purpose: Purpose,
    pub enrollment_owner_candidate: Option<EnrollmentOwnerCandidate>,
}

/// Result of validating one peer packet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerDecision {
    Start(Operation),
    Reply(Response),
}

/// Hardware-side completion reported to the broker state machine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OperationResult {
    Matched,
    NoMatch,
    Cancelled,
    Unavailable,
    Failed,
}

#[derive(Clone, Copy)]
struct ActiveOperation {
    token: OperationToken,
    cancelled: bool,
}

/// Pure single-operation broker arbitration.
pub struct BrokerState {
    active: Option<ActiveOperation>,
    next_token: u64,
}

/// Result of asking the one broker state for a fresh shared operation token.
pub(crate) enum TokenAdmission {
    Start(OperationToken),
    Busy,
    Failed,
}

impl Default for BrokerState {
    fn default() -> Self {
        Self {
            active: None,
            next_token: 1,
        }
    }
}

impl fmt::Debug for BrokerState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerState")
            .field("active", &self.active.is_some())
            .field(
                "cancellation_requested",
                &self.active.is_some_and(|active| active.cancelled),
            )
            .finish_non_exhaustive()
    }
}

impl BrokerState {
    /// Validates and dispatches one complete peer packet.
    ///
    /// Invalid metadata, malformed packets, and unsupported users are denied
    /// without changing the active operation. A valid authentication request
    /// starts at most one operation; a second one receives `BUSY`.
    #[must_use]
    pub fn handle_packet(
        &mut self,
        peer: PeerMetadata,
        policy: AccessPolicy,
        packet: &[u8],
    ) -> BrokerDecision {
        self.handle_packet_with_cancellation(peer, policy, packet, |_| false)
    }

    /// Validates and dispatches one packet with token-associated cancellation
    /// delivery.
    ///
    /// `deliver` is called only for an authorized cancellation of the current
    /// operation. Cancellation is recorded and acknowledged only when delivery
    /// succeeds. A caller that has no active delivery mechanism should use
    /// [`Self::handle_packet`], which denies cancellation.
    #[must_use]
    pub fn handle_packet_with_cancellation(
        &mut self,
        peer: PeerMetadata,
        policy: AccessPolicy,
        packet: &[u8],
        deliver: impl FnOnce(OperationToken) -> bool,
    ) -> BrokerDecision {
        let Some(biometric_user_id) = policy.biometric_user_for(peer) else {
            return BrokerDecision::Reply(Response::Denied);
        };
        let Ok(request) = decode_request(packet) else {
            return BrokerDecision::Reply(Response::Denied);
        };

        if request == Request::Cancel {
            return self.cancel_for_root(peer, deliver);
        }
        if request == Request::Enroll && peer.user_id == ROOT_UID {
            return BrokerDecision::Reply(Response::Denied);
        }

        let (purpose, enrollment_owner_candidate) = match request {
            Request::Authenticate => (Purpose::Authenticate, None),
            Request::Approve => (Purpose::Approve, None),
            Request::Enroll => (
                Purpose::Enrollment,
                EnrollmentOwnerCandidate::new(peer.user_id),
            ),
            Request::Cancel => unreachable!("cancellation handled above"),
        };
        self.start_operation(biometric_user_id, purpose, enrollment_owner_candidate)
    }

    /// Starts one already-decoded enrollment request when owner state is
    /// authoritatively missing.
    ///
    /// This narrow path still validates a local non-root kernel peer and shares
    /// the same active-operation and token authority as authentication.
    #[must_use]
    pub(crate) fn enroll_without_owner(&mut self, peer: PeerMetadata) -> BrokerDecision {
        if peer.address_family != PeerAddressFamily::Local {
            return BrokerDecision::Reply(Response::Denied);
        }
        let Some(candidate) = EnrollmentOwnerCandidate::new(peer.user_id) else {
            return BrokerDecision::Reply(Response::Denied);
        };
        self.start_operation(BIOMETRIC_USER_ID, Purpose::Enrollment, Some(candidate))
    }

    fn start_operation(
        &mut self,
        biometric_user_id: u32,
        purpose: Purpose,
        enrollment_owner_candidate: Option<EnrollmentOwnerCandidate>,
    ) -> BrokerDecision {
        let token = match self.start_token() {
            TokenAdmission::Start(token) => token,
            TokenAdmission::Busy => return BrokerDecision::Reply(Response::Busy),
            TokenAdmission::Failed => return BrokerDecision::Reply(Response::Failure),
        };
        BrokerDecision::Start(Operation {
            token,
            biometric_user_id,
            purpose,
            enrollment_owner_candidate,
        })
    }

    /// Routes one already-decoded cancellation when enrollment-owner storage
    /// is unavailable.
    ///
    /// Root's local kernel credential is sufficient cancellation authority;
    /// no missing owner mapping can start biometric work through this path.
    #[must_use]
    pub(crate) fn cancel_without_owner(
        &mut self,
        peer: PeerMetadata,
        deliver: impl FnOnce(OperationToken) -> bool,
    ) -> BrokerDecision {
        self.cancel_for_root(peer, deliver)
    }

    fn cancel_for_root(
        &mut self,
        peer: PeerMetadata,
        deliver: impl FnOnce(OperationToken) -> bool,
    ) -> BrokerDecision {
        if peer.address_family != PeerAddressFamily::Local || peer.user_id != ROOT_UID {
            return BrokerDecision::Reply(Response::Denied);
        }
        let Some(token) = self.active.as_ref().map(|active| active.token) else {
            return BrokerDecision::Reply(Response::Denied);
        };
        if self.cancel_token(token, deliver) {
            BrokerDecision::Reply(Response::Okay)
        } else {
            BrokerDecision::Reply(Response::Denied)
        }
    }

    /// Returns whether cancellation or client disconnect has been recorded for
    /// the named active operation. Unknown and stale tokens fail closed.
    #[must_use]
    pub fn is_cancelled(&self, token: OperationToken) -> bool {
        self.active
            .is_none_or(|active| active.token != token || active.cancelled)
    }

    /// Delivers and records that the request client disconnected.
    ///
    /// Returns false for a stale token or failed delivery without touching a
    /// newer operation.
    pub fn client_disconnected(
        &mut self,
        token: OperationToken,
        deliver: impl FnOnce(OperationToken) -> bool,
    ) -> bool {
        self.cancel_token(token, deliver)
    }

    /// Completes the named operation and returns its exact broker response.
    ///
    /// Cancellation always wins a race with a reported match. Unknown or stale
    /// tokens return `None` and cannot clear a newer operation.
    pub fn finish(&mut self, token: OperationToken, result: OperationResult) -> Option<Response> {
        let cancelled = self.finish_token(token)?;
        Some(if !cancelled && result == OperationResult::Matched {
            Response::Okay
        } else {
            Response::Failure
        })
    }

    pub(crate) fn start_token(&mut self) -> TokenAdmission {
        if self.active.is_some() {
            return TokenAdmission::Busy;
        }
        if self.next_token == 0 {
            return TokenAdmission::Failed;
        }

        let token = OperationToken(self.next_token);
        self.next_token = self.next_token.checked_add(1).unwrap_or(0);
        self.active = Some(ActiveOperation {
            token,
            cancelled: false,
        });
        TokenAdmission::Start(token)
    }

    pub(crate) fn cancel_token(
        &mut self,
        token: OperationToken,
        deliver: impl FnOnce(OperationToken) -> bool,
    ) -> bool {
        let Some(active_token) = self.active.as_ref().map(|active| active.token) else {
            return false;
        };
        if active_token != token || !deliver(token) {
            return false;
        }
        let Some(active) = self.active.as_mut() else {
            return false;
        };
        if active.token != token {
            return false;
        }
        active.cancelled = true;
        true
    }

    pub(crate) fn finish_token(&mut self, token: OperationToken) -> Option<bool> {
        let active = self.active?;
        if active.token != token {
            return None;
        }
        self.active = None;
        Some(active.cancelled)
    }
}

/// Client-selected biometric purpose. Cancellation is intentionally excluded:
/// an accepted cancellation is never an authentication success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientPurpose {
    Authenticate,
    Approve,
}

impl ClientPurpose {
    /// Returns the exact request packet for the selected purpose.
    #[must_use]
    pub const fn encode_request(self) -> &'static [u8; REQUEST_SIZE] {
        match self {
            Self::Authenticate => AUTHENTICATE_REQUEST,
            Self::Approve => APPROVE_REQUEST,
        }
    }
}

/// Client-side transport or trust failure supplied by a future adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientTransportFailure {
    BrokerUnavailable,
    DeadlineExceeded,
    UntrustedEndpoint,
    UntrustedPeer,
    SendFailed,
    ReceiveFailed,
}

/// Exact-success-only result of one client request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientOutcome {
    Authenticated,
    Failed(ClientFailure),
}

/// Bounded, payload-free client failure classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientFailure {
    BrokerUnavailable,
    DeadlineExceeded,
    UntrustedEndpoint,
    UntrustedPeer,
    SendFailed,
    ReceiveFailed,
    Denied,
    Busy,
    BrokerFailure,
    InvalidResponse,
}

/// Validate the client-provided sensor timeout.
///
/// # Errors
///
/// Rejects zero and values above thirty seconds before any transport work.
pub fn validate_match_timeout(timeout: Duration) -> Result<(), ClientFailure> {
    if timeout.is_zero() || timeout > MAX_MATCH_TIMEOUT {
        Err(ClientFailure::DeadlineExceeded)
    } else {
        Ok(())
    }
}

/// Returns the complete client watchdog after validating the match window.
///
/// # Errors
///
/// Rejects an invalid match timeout or an arithmetic overflow.
pub fn client_watchdog(timeout: Duration) -> Result<Duration, ClientFailure> {
    validate_match_timeout(timeout)?;
    timeout
        .checked_add(SETUP_ALLOWANCE)
        .ok_or(ClientFailure::DeadlineExceeded)
}

/// Map one transport result to the fail-closed client outcome.
///
/// Only an exact four-byte `OKAY` packet authenticates. Every broker status,
/// short or oversized packet, unknown packet, trust failure, timeout, and I/O
/// failure remains a failed biometric attempt for the caller.
#[must_use]
pub fn evaluate_client_response(result: Result<&[u8], ClientTransportFailure>) -> ClientOutcome {
    let response = match result {
        Ok(packet) => match decode_response(packet) {
            Ok(response) => response,
            Err(_) => return ClientOutcome::Failed(ClientFailure::InvalidResponse),
        },
        Err(failure) => {
            return ClientOutcome::Failed(match failure {
                ClientTransportFailure::BrokerUnavailable => ClientFailure::BrokerUnavailable,
                ClientTransportFailure::DeadlineExceeded => ClientFailure::DeadlineExceeded,
                ClientTransportFailure::UntrustedEndpoint => ClientFailure::UntrustedEndpoint,
                ClientTransportFailure::UntrustedPeer => ClientFailure::UntrustedPeer,
                ClientTransportFailure::SendFailed => ClientFailure::SendFailed,
                ClientTransportFailure::ReceiveFailed => ClientFailure::ReceiveFailed,
            });
        }
    };

    match response {
        Response::Okay => ClientOutcome::Authenticated,
        Response::Denied => ClientOutcome::Failed(ClientFailure::Denied),
        Response::Busy => ClientOutcome::Failed(ClientFailure::Busy),
        Response::Failure => ClientOutcome::Failed(ClientFailure::BrokerFailure),
    }
}

/// Result of the separate cancellation exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CancellationOutcome {
    Accepted,
    Denied,
}

/// Evaluate a cancellation response without treating it as authentication.
#[must_use]
pub fn evaluate_cancellation_response(
    result: Result<&[u8], ClientTransportFailure>,
) -> CancellationOutcome {
    match result.and_then(|packet| {
        decode_response(packet).map_err(|_| ClientTransportFailure::ReceiveFailed)
    }) {
        Ok(Response::Okay) => CancellationOutcome::Accepted,
        Ok(Response::Denied | Response::Busy | Response::Failure) | Err(_) => {
            CancellationOutcome::Denied
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER_UID: u32 = 42_000;
    const OWNER_GID: u32 = 42_001;

    fn policy() -> AccessPolicy {
        AccessPolicy::new(OWNER_UID).expect("synthetic enrollment owner")
    }

    fn peer(user_id: u32) -> PeerMetadata {
        PeerMetadata {
            address_family: PeerAddressFamily::Local,
            user_id,
            group_id: OWNER_GID,
        }
    }

    fn start(state: &mut BrokerState, request: Request) -> Operation {
        let BrokerDecision::Start(operation) =
            state.handle_packet(peer(OWNER_UID), policy(), request.encode())
        else {
            panic!("valid synthetic request starts")
        };
        operation
    }

    #[test]
    fn request_and_response_encodings_are_exact() {
        for (request, packet) in [
            (Request::Authenticate, AUTHENTICATE_REQUEST),
            (Request::Approve, APPROVE_REQUEST),
            (Request::Enroll, ENROLL_REQUEST),
            (Request::Cancel, CANCEL_REQUEST),
        ] {
            assert_eq!(request.encode(), packet);
            assert_eq!(decode_request(packet), Ok(request));
        }
        for (response, packet) in [
            (Response::Okay, RESPONSE_OK),
            (Response::Denied, RESPONSE_DENIED),
            (Response::Busy, RESPONSE_BUSY),
            (Response::Failure, RESPONSE_FAILURE),
        ] {
            assert_eq!(response.encode(), packet);
            assert_eq!(decode_response(packet), Ok(response));
        }
    }

    #[test]
    fn request_decoder_rejects_truncated_oversized_and_malformed_packets() {
        for length in 0..REQUEST_SIZE {
            assert_eq!(
                decode_request(&AUTHENTICATE_REQUEST[..length]),
                Err(RequestError::WrongLength)
            );
        }

        let mut oversized = AUTHENTICATE_REQUEST.to_vec();
        oversized.push(0);
        assert_eq!(decode_request(&oversized), Err(RequestError::WrongLength));

        let mut wrong_terminator = *AUTHENTICATE_REQUEST;
        wrong_terminator[7] = 0;
        assert_eq!(
            decode_request(&wrong_terminator),
            Err(RequestError::WrongTerminator)
        );

        let mut wrong_version = *AUTHENTICATE_REQUEST;
        wrong_version[6] = 2;
        assert_eq!(
            decode_request(&wrong_version),
            Err(RequestError::UnsupportedVersion)
        );

        let mut wrong_action = *AUTHENTICATE_REQUEST;
        wrong_action[..6].copy_from_slice(b"T1NOPE");
        assert_eq!(
            decode_request(&wrong_action),
            Err(RequestError::UnsupportedAction)
        );
    }

    #[test]
    fn response_decoder_rejects_truncated_oversized_and_unknown_packets() {
        for packet in [&b""[..], &b"O"[..], &b"OK"[..], &b"OKA"[..], &b"OKAYx"[..]] {
            assert_eq!(decode_response(packet), Err(ResponseError::WrongLength));
        }
        assert_eq!(
            decode_response(b"NOPE"),
            Err(ResponseError::UnsupportedResponse)
        );
    }

    #[test]
    fn errors_and_debug_output_do_not_echo_packets_or_credentials() {
        let marker = b"SYNTHETIC_SECRET_MARKER";
        let request_error = decode_request(marker).unwrap_err();
        let response_error = decode_response(marker).unwrap_err();
        assert!(!format!("{request_error:?} {request_error}").contains("SECRET"));
        assert!(!format!("{response_error:?} {response_error}").contains("SECRET"));
        assert!(!format!("{:?}", peer(OWNER_UID)).contains("42000"));
    }

    #[test]
    fn endpoint_trust_matches_the_fail_closed_client_contract() {
        let trusted = EndpointMetadata {
            kind: EndpointKind::LocalSocket,
            owner_user_id: ROOT_UID,
            mode: 0o660,
        };
        assert!(endpoint_is_trusted(trusted));
        assert!(!endpoint_is_trusted(EndpointMetadata {
            mode: 0o666,
            ..trusted
        }));
        assert!(!endpoint_is_trusted(EndpointMetadata {
            owner_user_id: OWNER_UID,
            ..trusted
        }));
        assert!(!endpoint_is_trusted(EndpointMetadata {
            kind: EndpointKind::Other,
            ..trusted
        }));
    }

    #[test]
    fn stored_owner_mapping_admits_only_root_and_the_enrollment_owner() {
        for allowed in [ROOT_UID, OWNER_UID] {
            let mut state = BrokerState::default();
            let BrokerDecision::Start(operation) =
                state.handle_packet(peer(allowed), policy(), AUTHENTICATE_REQUEST)
            else {
                panic!("allowed peer starts authentication")
            };
            assert_eq!(operation.biometric_user_id, BIOMETRIC_USER_ID);
        }

        let mut state = BrokerState::default();
        assert_eq!(
            state.handle_packet(peer(OWNER_UID + 1), policy(), AUTHENTICATE_REQUEST),
            BrokerDecision::Reply(Response::Denied)
        );
        assert_eq!(
            AccessPolicy::new(ROOT_UID),
            Err(PolicyError::InvalidEnrollmentOwner)
        );
    }

    #[test]
    fn nonlocal_peer_families_are_rejected_including_netlink() {
        for address_family in [
            PeerAddressFamily::InternetV6,
            PeerAddressFamily::Netlink,
            PeerAddressFamily::Other,
        ] {
            let metadata = PeerMetadata {
                address_family,
                ..peer(ROOT_UID)
            };
            let mut state = BrokerState::default();
            assert_eq!(
                state.handle_packet(metadata, policy(), AUTHENTICATE_REQUEST),
                BrokerDecision::Reply(Response::Denied)
            );
        }
    }

    #[test]
    fn approve_selects_distinct_ui_purpose() {
        let mut state = BrokerState::default();
        let operation = start(&mut state, Request::Approve);
        assert_eq!(operation.purpose, Purpose::Approve);
        assert_eq!(operation.enrollment_owner_candidate, None);
    }

    #[test]
    fn enrollment_admits_only_the_recorded_owner_and_carries_a_redacted_candidate() {
        let mut state = BrokerState::default();
        let operation = start(&mut state, Request::Enroll);
        assert_eq!(operation.purpose, Purpose::Enrollment);
        let candidate = operation
            .enrollment_owner_candidate
            .expect("enrollment carries its candidate owner");
        assert_eq!(candidate.user_id(), OWNER_UID);
        assert!(!format!("{candidate:?}").contains("42000"));

        let mut root_state = BrokerState::default();
        assert_eq!(
            root_state.handle_packet(peer(ROOT_UID), policy(), ENROLL_REQUEST),
            BrokerDecision::Reply(Response::Denied)
        );
        let mut other_state = BrokerState::default();
        assert_eq!(
            other_state.handle_packet(peer(OWNER_UID + 1), policy(), ENROLL_REQUEST),
            BrokerDecision::Reply(Response::Denied)
        );
    }

    #[test]
    fn missing_owner_enrollment_shares_busy_token_and_root_cancel_authority() {
        let mut state = BrokerState::default();
        let BrokerDecision::Start(operation) = state.enroll_without_owner(peer(OWNER_UID)) else {
            panic!("validated local non-root candidate starts enrollment")
        };
        assert_eq!(operation.purpose, Purpose::Enrollment);
        assert_eq!(
            operation
                .enrollment_owner_candidate
                .expect("candidate is retained")
                .user_id(),
            OWNER_UID
        );
        assert_eq!(
            state.handle_packet(peer(OWNER_UID), policy(), AUTHENTICATE_REQUEST),
            BrokerDecision::Reply(Response::Busy)
        );
        assert_eq!(
            state.cancel_without_owner(peer(ROOT_UID), |token| token == operation.token),
            BrokerDecision::Reply(Response::Okay)
        );
        assert_eq!(
            state.finish(operation.token, OperationResult::Matched),
            Some(Response::Failure),
            "root cancellation wins an enrollment completion race"
        );

        for rejected in [
            peer(ROOT_UID),
            PeerMetadata {
                address_family: PeerAddressFamily::InternetV6,
                ..peer(OWNER_UID)
            },
        ] {
            assert_eq!(
                BrokerState::default().enroll_without_owner(rejected),
                BrokerDecision::Reply(Response::Denied)
            );
        }
    }

    #[test]
    fn malformed_and_wrong_version_requests_never_start_work() {
        let mut wrong_version = *AUTHENTICATE_REQUEST;
        wrong_version[6] = 2;
        let mut wrong_action = *AUTHENTICATE_REQUEST;
        wrong_action[..6].copy_from_slice(b"T1NOPE");

        for packet in [&b""[..], &b"bad"[..], &wrong_version, &wrong_action] {
            let mut state = BrokerState::default();
            assert_eq!(
                state.handle_packet(peer(OWNER_UID), policy(), packet),
                BrokerDecision::Reply(Response::Denied)
            );
            assert!(format!("{state:?}").contains("active: false"));
        }
    }

    #[test]
    fn only_one_authentication_can_be_active() {
        let mut state = BrokerState::default();
        let operation = start(&mut state, Request::Authenticate);
        assert_eq!(
            state.handle_packet(peer(ROOT_UID), policy(), APPROVE_REQUEST),
            BrokerDecision::Reply(Response::Busy)
        );
        assert_eq!(
            state.finish(operation.token, OperationResult::Matched),
            Some(Response::Okay)
        );
    }

    #[test]
    fn only_root_can_cancel_an_active_operation() {
        let mut state = BrokerState::default();
        let operation = start(&mut state, Request::Authenticate);

        assert_eq!(
            state.handle_packet(peer(OWNER_UID), policy(), CANCEL_REQUEST),
            BrokerDecision::Reply(Response::Denied)
        );
        assert!(!state.is_cancelled(operation.token));

        assert_eq!(
            state.handle_packet_with_cancellation(peer(ROOT_UID), policy(), CANCEL_REQUEST, |_| {
                false
            },),
            BrokerDecision::Reply(Response::Denied)
        );
        assert!(!state.is_cancelled(operation.token));

        assert_eq!(
            state.handle_packet_with_cancellation(
                peer(ROOT_UID),
                policy(),
                CANCEL_REQUEST,
                |token| token == operation.token,
            ),
            BrokerDecision::Reply(Response::Okay)
        );
        assert!(state.is_cancelled(operation.token));

        assert_eq!(
            state.handle_packet_with_cancellation(
                peer(ROOT_UID),
                policy(),
                CANCEL_REQUEST,
                |token| token == operation.token,
            ),
            BrokerDecision::Reply(Response::Okay)
        );
        assert_eq!(
            state.finish(operation.token, OperationResult::Matched),
            Some(Response::Failure),
            "cancellation wins a race with a reported match"
        );
        assert_eq!(
            state.handle_packet(peer(ROOT_UID), policy(), CANCEL_REQUEST),
            BrokerDecision::Reply(Response::Denied)
        );
    }

    #[test]
    fn ownerless_cancellation_retains_root_local_and_delivery_checks() {
        let mut state = BrokerState::default();
        let operation = start(&mut state, Request::Authenticate);

        assert_eq!(
            state.cancel_without_owner(peer(OWNER_UID), |_| true),
            BrokerDecision::Reply(Response::Denied)
        );
        assert_eq!(
            state.cancel_without_owner(
                PeerMetadata {
                    address_family: PeerAddressFamily::InternetV6,
                    user_id: ROOT_UID,
                    group_id: 0,
                },
                |_| true,
            ),
            BrokerDecision::Reply(Response::Denied)
        );
        assert_eq!(
            state.cancel_without_owner(peer(ROOT_UID), |_| false),
            BrokerDecision::Reply(Response::Denied)
        );
        assert!(!state.is_cancelled(operation.token));
        assert_eq!(
            state.cancel_without_owner(peer(ROOT_UID), |token| token == operation.token),
            BrokerDecision::Reply(Response::Okay)
        );
        assert!(state.is_cancelled(operation.token));
    }

    #[test]
    fn disconnect_cancels_only_the_matching_operation() {
        let mut state = BrokerState::default();
        let first = start(&mut state, Request::Authenticate);
        assert!(!state.client_disconnected(first.token, |_| false));
        assert!(!state.is_cancelled(first.token));
        assert!(state.client_disconnected(first.token, |token| token == first.token));
        assert_eq!(
            state.finish(first.token, OperationResult::Matched),
            Some(Response::Failure)
        );

        let second = start(&mut state, Request::Authenticate);
        assert!(!state.client_disconnected(first.token, |_| true));
        assert!(!state.is_cancelled(second.token));
        assert_eq!(state.finish(first.token, OperationResult::Matched), None);
        assert_eq!(
            state.finish(second.token, OperationResult::Matched),
            Some(Response::Okay)
        );
    }

    #[test]
    fn token_exhaustion_fails_closed_without_reusing_a_stale_token() {
        let mut state = BrokerState {
            active: None,
            next_token: u64::MAX,
        };
        let last = start(&mut state, Request::Authenticate);
        assert_eq!(
            state.finish(last.token, OperationResult::Matched),
            Some(Response::Okay)
        );
        assert_eq!(
            state.handle_packet(peer(OWNER_UID), policy(), AUTHENTICATE_REQUEST),
            BrokerDecision::Reply(Response::Failure)
        );
        assert_eq!(state.finish(last.token, OperationResult::Matched), None);
    }

    #[test]
    fn every_nonmatch_backend_result_fails() {
        for result in [
            OperationResult::NoMatch,
            OperationResult::Cancelled,
            OperationResult::Unavailable,
            OperationResult::Failed,
        ] {
            let mut state = BrokerState::default();
            let operation = start(&mut state, Request::Authenticate);
            assert_eq!(
                state.finish(operation.token, result),
                Some(Response::Failure)
            );
        }
    }

    #[test]
    fn client_accepts_only_an_exact_success_packet() {
        assert_eq!(
            evaluate_client_response(Ok(RESPONSE_OK)),
            ClientOutcome::Authenticated
        );
        for packet in [&b""[..], &b"OK"[..], &b"OKAYextra"[..], &b"NOPE"[..]] {
            assert_eq!(
                evaluate_client_response(Ok(packet)),
                ClientOutcome::Failed(ClientFailure::InvalidResponse)
            );
        }
        assert_eq!(
            evaluate_client_response(Ok(RESPONSE_DENIED)),
            ClientOutcome::Failed(ClientFailure::Denied)
        );
        assert_eq!(
            evaluate_client_response(Ok(RESPONSE_BUSY)),
            ClientOutcome::Failed(ClientFailure::Busy)
        );
        assert_eq!(
            evaluate_client_response(Ok(RESPONSE_FAILURE)),
            ClientOutcome::Failed(ClientFailure::BrokerFailure)
        );
    }

    #[test]
    fn broker_unavailable_and_transport_errors_map_to_failure() {
        for (transport, failure) in [
            (
                ClientTransportFailure::BrokerUnavailable,
                ClientFailure::BrokerUnavailable,
            ),
            (
                ClientTransportFailure::DeadlineExceeded,
                ClientFailure::DeadlineExceeded,
            ),
            (
                ClientTransportFailure::UntrustedEndpoint,
                ClientFailure::UntrustedEndpoint,
            ),
            (
                ClientTransportFailure::UntrustedPeer,
                ClientFailure::UntrustedPeer,
            ),
            (
                ClientTransportFailure::SendFailed,
                ClientFailure::SendFailed,
            ),
            (
                ClientTransportFailure::ReceiveFailed,
                ClientFailure::ReceiveFailed,
            ),
        ] {
            assert_eq!(
                evaluate_client_response(Err(transport)),
                ClientOutcome::Failed(failure)
            );
        }
    }

    #[test]
    fn timeout_is_bounded_before_transport_work() {
        assert_eq!(
            validate_match_timeout(Duration::ZERO),
            Err(ClientFailure::DeadlineExceeded)
        );
        assert_eq!(validate_match_timeout(Duration::from_secs(1)), Ok(()));
        assert_eq!(validate_match_timeout(MAX_MATCH_TIMEOUT), Ok(()));
        assert_eq!(
            client_watchdog(MAX_MATCH_TIMEOUT),
            Ok(Duration::from_secs(65))
        );
        assert_eq!(
            validate_match_timeout(MAX_MATCH_TIMEOUT + Duration::from_nanos(1)),
            Err(ClientFailure::DeadlineExceeded)
        );
    }

    #[test]
    fn cancellation_acknowledgement_is_not_authentication() {
        assert_eq!(
            evaluate_cancellation_response(Ok(RESPONSE_OK)),
            CancellationOutcome::Accepted
        );
        for response in [RESPONSE_DENIED, RESPONSE_BUSY, RESPONSE_FAILURE] {
            assert_eq!(
                evaluate_cancellation_response(Ok(response)),
                CancellationOutcome::Denied
            );
        }
        assert_eq!(
            evaluate_cancellation_response(Ok(b"OK")),
            CancellationOutcome::Denied
        );
        assert_eq!(
            evaluate_cancellation_response(Err(ClientTransportFailure::BrokerUnavailable)),
            CancellationOutcome::Denied
        );
    }
}

//! Owner-bound standard fingerprint operations over the broker's one token.

use core::fmt;

use crate::auth_protocol::{
    AccessPolicy, BIOMETRIC_USER_ID, BrokerState, OperationToken, PeerAddressFamily, PeerMetadata,
    TokenAdmission,
};
use crate::standard_fingerprint_protocol::{
    FingerLabel, IdentityId, OperationKind, ServerMessage, TerminalOutcome, Username,
};

const ROOT_UID: u32 = 0;

/// A non-root account produced by exact canonical NSS resolution.
#[derive(Clone, Eq, PartialEq)]
pub struct ResolvedStandardAccount {
    canonical_username: Username,
    user_id: u32,
}

impl ResolvedStandardAccount {
    /// Accepts an asserted account only when NSS returned the exact same
    /// canonical name and a non-root UID.
    ///
    /// # Errors
    ///
    /// Returns a static error for a non-canonical name or UID zero.
    pub fn new(
        asserted: &Username,
        canonical: &Username,
        user_id: u32,
    ) -> Result<Self, StandardAuthorityError> {
        if asserted != canonical {
            return Err(StandardAuthorityError::NonCanonicalAccount);
        }
        if user_id == ROOT_UID {
            return Err(StandardAuthorityError::RootTarget);
        }
        Ok(Self {
            canonical_username: canonical.clone(),
            user_id,
        })
    }

    /// Exact canonical account name returned by NSS.
    #[must_use]
    pub const fn canonical_username(&self) -> &Username {
        &self.canonical_username
    }

    /// Returns the resolved UID for kernel-credential and owner comparison.
    #[must_use]
    pub const fn user_id(&self) -> u32 {
        self.user_id
    }
}

impl fmt::Debug for ResolvedStandardAccount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResolvedStandardAccount(<redacted>)")
    }
}

/// Failure before an account can enter broker authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StandardAuthorityError {
    /// NSS did not return the exact asserted canonical account name.
    NonCanonicalAccount,
    /// The resolved target was root rather than a non-root biometric owner.
    RootTarget,
}

impl fmt::Display for StandardAuthorityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NonCanonicalAccount => "standard fingerprint account is not canonical",
            Self::RootTarget => "standard fingerprint target must be non-root",
        })
    }
}

impl std::error::Error for StandardAuthorityError {}

/// One already-decoded standard operation with any username exactly resolved.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResolvedStandardOperation {
    /// Device-storage listing has no request username.
    ListIdentities,
    /// Enroll one labelled finger for the resolved account.
    Enroll {
        account: ResolvedStandardAccount,
        finger: FingerLabel,
    },
    /// Verify one exact opaque identity for the resolved account.
    Verify {
        account: ResolvedStandardAccount,
        identity: IdentityId,
    },
    /// Identify any enrolled identity for the resolved account.
    Identify { account: ResolvedStandardAccount },
    /// Delete one exact opaque identity for the resolved account.
    DeleteIdentity {
        account: ResolvedStandardAccount,
        identity: IdentityId,
    },
}

impl ResolvedStandardOperation {
    const fn target_user_id(&self) -> Option<u32> {
        match self {
            Self::ListIdentities => None,
            Self::Enroll { account, .. }
            | Self::Verify { account, .. }
            | Self::Identify { account }
            | Self::DeleteIdentity { account, .. } => Some(account.user_id()),
        }
    }

    const fn kind(&self) -> OperationKind {
        match self {
            Self::ListIdentities => OperationKind::ListIdentities,
            Self::Enroll { .. } => OperationKind::Enroll,
            Self::Verify { .. } => OperationKind::Verify,
            Self::Identify { .. } => OperationKind::Identify,
            Self::DeleteIdentity { .. } => OperationKind::DeleteIdentity,
        }
    }
}

/// Kernel peer authority bound to an accepted standard operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StandardPeerAuthority {
    /// A local UID-zero service asserted an exactly resolved non-root account.
    Root,
    /// The local non-root peer is the already recorded enrollment owner.
    RecordedOwner,
    /// No owner existed and this local non-root peer nominated itself.
    FirstOwnerNominee,
}

/// One exact standard operation bound to the broker's active token.
pub struct AuthorizedStandardOperation {
    token: OperationToken,
    biometric_user_id: u32,
    target_user_id: Option<u32>,
    authority: StandardPeerAuthority,
    nominated_first_owner: bool,
    operation: ResolvedStandardOperation,
}

impl AuthorizedStandardOperation {
    pub(crate) fn clone_for_worker(&self) -> Self {
        Self {
            token: self.token,
            biometric_user_id: self.biometric_user_id,
            target_user_id: self.target_user_id,
            authority: self.authority,
            nominated_first_owner: self.nominated_first_owner,
            operation: self.operation.clone(),
        }
    }

    pub(crate) const fn token(&self) -> OperationToken {
        self.token
    }

    /// Fixed internal biometric user selected by the broker.
    #[must_use]
    pub const fn biometric_user_id(&self) -> u32 {
        self.biometric_user_id
    }

    /// Resolved non-root target, or the optional recorded owner for List.
    #[must_use]
    pub const fn target_user_id(&self) -> Option<u32> {
        self.target_user_id
    }

    /// Kernel peer authority proven at admission.
    #[must_use]
    pub const fn authority(&self) -> StandardPeerAuthority {
        self.authority
    }

    /// Whether successful enrollment must durably establish the first owner.
    #[must_use]
    pub const fn nominates_first_owner(&self) -> bool {
        self.nominated_first_owner
    }

    /// Exact payload-bearing operation associated with this token.
    #[must_use]
    pub const fn operation(&self) -> &ResolvedStandardOperation {
        &self.operation
    }
}

impl fmt::Debug for AuthorizedStandardOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedStandardOperation")
            .field("token", &self.token)
            .field("biometric_user_id", &self.biometric_user_id)
            .field("target_user_id", &"<redacted>")
            .field("authority", &self.authority)
            .field("nominated_first_owner", &self.nominated_first_owner)
            .field("operation", &self.operation.kind())
            .finish_non_exhaustive()
    }
}

/// Typed immediate reply or one standard operation owning the shared token.
pub enum StandardBrokerDecision {
    /// Start the exact owner-bound operation.
    Start(AuthorizedStandardOperation),
    /// Return one typed terminal response without starting work.
    Reply(ServerMessage),
}

impl fmt::Debug for StandardBrokerDecision {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start(operation) => formatter.debug_tuple("Start").field(operation).finish(),
            Self::Reply(reply) => formatter.debug_tuple("Reply").field(reply).finish(),
        }
    }
}

impl BrokerState {
    /// Authorizes one resolved standard operation against the recorded owner
    /// and starts it on the same token used by legacy fixed requests.
    #[must_use]
    pub fn dispatch_standard(
        &mut self,
        peer: PeerMetadata,
        recorded_owner: Option<AccessPolicy>,
        operation: ResolvedStandardOperation,
    ) -> StandardBrokerDecision {
        let Some((target_user_id, authority, nominated_first_owner)) =
            authorize(peer, recorded_owner, &operation)
        else {
            return standard_reply(TerminalOutcome::Error);
        };

        if let Some(owner) = recorded_owner
            && operation
                .target_user_id()
                .is_some_and(|target| target != owner.enrollment_owner_user_id())
        {
            return standard_reply(
                if matches!(operation, ResolvedStandardOperation::Enroll { .. }) {
                    TerminalOutcome::SecondOwner
                } else {
                    TerminalOutcome::Error
                },
            );
        }

        let token = match self.start_token() {
            TokenAdmission::Start(token) => token,
            TokenAdmission::Busy => return standard_reply(TerminalOutcome::Busy),
            TokenAdmission::Failed => return standard_reply(TerminalOutcome::Error),
        };
        StandardBrokerDecision::Start(AuthorizedStandardOperation {
            token,
            biometric_user_id: BIOMETRIC_USER_ID,
            target_user_id,
            authority,
            nominated_first_owner,
            operation,
        })
    }

    /// Delivers same-connection cancellation to this exact standard token.
    pub fn cancel_standard(
        &mut self,
        operation: &AuthorizedStandardOperation,
        deliver: impl FnOnce(OperationToken) -> bool,
    ) -> bool {
        self.cancel_token(operation.token, deliver)
    }

    /// Delivers disconnect cancellation through the same exact token path.
    pub fn standard_client_disconnected(
        &mut self,
        operation: &AuthorizedStandardOperation,
        deliver: impl FnOnce(OperationToken) -> bool,
    ) -> bool {
        self.cancel_token(operation.token, deliver)
    }

    /// Finalizes one exact standard token with an operation-compatible typed
    /// response. Delivered cancellation always wins.
    ///
    /// A nonempty List completion requires both a bound recorded owner UID and
    /// its canonical owner name. An empty standard-identity list carries no
    /// owner name even when legacy biometric state has a recorded owner. The
    /// later storage/NSS adapter must verify any supplied name against the
    /// recorded UID because [`AccessPolicy`] intentionally retains no username.
    #[must_use]
    pub fn finish_standard(
        &mut self,
        operation: &AuthorizedStandardOperation,
        result: ServerMessage,
    ) -> Option<ServerMessage> {
        let compatible = result_is_compatible(operation, &result);
        let cancelled = self.finish_token(operation.token)?;
        if cancelled {
            Some(ServerMessage::Terminal(TerminalOutcome::Cancelled))
        } else if compatible {
            Some(result)
        } else {
            Some(ServerMessage::Terminal(TerminalOutcome::Error))
        }
    }
}

fn authorize(
    peer: PeerMetadata,
    recorded_owner: Option<AccessPolicy>,
    operation: &ResolvedStandardOperation,
) -> Option<(Option<u32>, StandardPeerAuthority, bool)> {
    if peer.address_family != PeerAddressFamily::Local {
        return None;
    }

    if operation == &ResolvedStandardOperation::ListIdentities {
        return match (peer.user_id, recorded_owner) {
            (ROOT_UID, owner) => Some((
                owner.map(AccessPolicy::enrollment_owner_user_id),
                StandardPeerAuthority::Root,
                false,
            )),
            (user_id, Some(owner)) if user_id == owner.enrollment_owner_user_id() => {
                Some((Some(user_id), StandardPeerAuthority::RecordedOwner, false))
            }
            _ => None,
        };
    }

    let target = operation.target_user_id()?;
    if peer.user_id != ROOT_UID && peer.user_id != target {
        return None;
    }
    match recorded_owner {
        Some(_owner) => {
            let authority = if peer.user_id == ROOT_UID {
                StandardPeerAuthority::Root
            } else {
                StandardPeerAuthority::RecordedOwner
            };
            Some((Some(target), authority, false))
        }
        None if matches!(operation, ResolvedStandardOperation::Enroll { .. }) => {
            let authority = if peer.user_id == ROOT_UID {
                StandardPeerAuthority::Root
            } else {
                StandardPeerAuthority::FirstOwnerNominee
            };
            Some((Some(target), authority, true))
        }
        None => None,
    }
}

fn standard_reply(outcome: TerminalOutcome) -> StandardBrokerDecision {
    StandardBrokerDecision::Reply(ServerMessage::Terminal(outcome))
}

fn result_is_compatible(operation: &AuthorizedStandardOperation, result: &ServerMessage) -> bool {
    let kind = operation.operation().kind();
    match result {
        ServerMessage::IdentityList { owner, identities } => {
            kind == OperationKind::ListIdentities
                && if identities.is_empty() {
                    owner.is_none()
                } else {
                    owner.is_some() && operation.target_user_id.is_some()
                }
        }
        ServerMessage::Terminal(
            TerminalOutcome::Cancelled
            | TerminalOutcome::DeviceLost
            | TerminalOutcome::Unsupported
            | TerminalOutcome::Error,
        ) => true,
        ServerMessage::Terminal(
            TerminalOutcome::Enrolled(_)
            | TerminalOutcome::Duplicate
            | TerminalOutcome::CapacityFull,
        ) => kind == OperationKind::Enroll,
        ServerMessage::Terminal(TerminalOutcome::Matched(actual)) => match operation.operation() {
            ResolvedStandardOperation::Verify { identity, .. } => identity == actual,
            ResolvedStandardOperation::Identify { .. } => true,
            _ => false,
        },
        ServerMessage::Terminal(TerminalOutcome::NoMatch) => {
            matches!(kind, OperationKind::Verify | OperationKind::Identify)
        }
        ServerMessage::Terminal(TerminalOutcome::Completed) => {
            kind == OperationKind::DeleteIdentity
        }
        ServerMessage::Capabilities(_)
        | ServerMessage::Opened
        | ServerMessage::EnrollProgress(_)
        | ServerMessage::Terminal(TerminalOutcome::Busy | TerminalOutcome::SecondOwner) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth_protocol::{
        AUTHENTICATE_REQUEST, AccessPolicy, BrokerDecision, OperationResult, PeerAddressFamily,
        Purpose, RESPONSE_BUSY, RESPONSE_DENIED, RESPONSE_FAILURE, RESPONSE_OK, Request, Response,
    };

    const OWNER: u32 = 42_000;
    const OTHER: u32 = 42_001;

    fn username(value: &str) -> Username {
        Username::new(value).unwrap()
    }

    fn account(name: &str, user_id: u32) -> ResolvedStandardAccount {
        let name = username(name);
        ResolvedStandardAccount::new(&name, &name, user_id).unwrap()
    }

    fn policy() -> AccessPolicy {
        AccessPolicy::new(OWNER).unwrap()
    }

    fn peer(user_id: u32) -> PeerMetadata {
        PeerMetadata {
            address_family: PeerAddressFamily::Local,
            user_id,
            group_id: 7,
        }
    }

    fn identity(seed: u8) -> IdentityId {
        IdentityId::new([seed; 16]).unwrap()
    }

    fn start(
        state: &mut BrokerState,
        peer: PeerMetadata,
        owner: Option<AccessPolicy>,
        operation: ResolvedStandardOperation,
    ) -> AuthorizedStandardOperation {
        let StandardBrokerDecision::Start(operation) =
            state.dispatch_standard(peer, owner, operation)
        else {
            panic!("standard operation starts")
        };
        operation
    }

    fn outcome(decision: &StandardBrokerDecision) -> TerminalOutcome {
        let StandardBrokerDecision::Reply(ServerMessage::Terminal(outcome)) = decision else {
            panic!("typed terminal reply")
        };
        *outcome
    }

    #[test]
    fn exact_canonical_resolution_rejects_aliases_and_root() {
        let asserted = username("alice");
        let canonical = username("alice.local");
        assert_eq!(
            ResolvedStandardAccount::new(&asserted, &canonical, OWNER),
            Err(StandardAuthorityError::NonCanonicalAccount)
        );
        assert_eq!(
            ResolvedStandardAccount::new(&asserted, &asserted, ROOT_UID),
            Err(StandardAuthorityError::RootTarget)
        );

        let account = ResolvedStandardAccount::new(&asserted, &asserted, OWNER).unwrap();
        assert_eq!(account.canonical_username(), &asserted);
        assert!(!format!("{account:?}").contains("alice"));
    }

    #[test]
    fn root_assertion_and_unprivileged_self_target_are_bound() {
        let mut root_state = BrokerState::default();
        let root = start(
            &mut root_state,
            peer(ROOT_UID),
            Some(policy()),
            ResolvedStandardOperation::Verify {
                account: account("owner", OWNER),
                identity: identity(0x11),
            },
        );
        assert_eq!(root.authority(), StandardPeerAuthority::Root);
        assert_eq!(root.target_user_id(), Some(OWNER));
        assert_eq!(root.biometric_user_id(), BIOMETRIC_USER_ID);

        let mut owner_state = BrokerState::default();
        let owner = start(
            &mut owner_state,
            peer(OWNER),
            Some(policy()),
            ResolvedStandardOperation::Identify {
                account: account("owner", OWNER),
            },
        );
        assert_eq!(owner.authority(), StandardPeerAuthority::RecordedOwner);
        assert_eq!(owner.target_user_id(), Some(OWNER));
    }

    #[test]
    fn unprivileged_cross_user_is_refused_without_claiming_token() {
        let mut state = BrokerState::default();
        assert_eq!(
            outcome(&state.dispatch_standard(
                peer(OWNER),
                Some(policy()),
                ResolvedStandardOperation::Verify {
                    account: account("other", OTHER),
                    identity: identity(0x11),
                },
            )),
            TerminalOutcome::Error
        );
        assert!(matches!(
            state.handle_packet(peer(OWNER), policy(), AUTHENTICATE_REQUEST),
            BrokerDecision::Start(_)
        ));
    }

    #[test]
    fn nonlocal_peers_are_refused_without_claiming_token() {
        for address_family in [
            PeerAddressFamily::InternetV6,
            PeerAddressFamily::Netlink,
            PeerAddressFamily::Other,
        ] {
            let mut state = BrokerState::default();
            assert_eq!(
                outcome(&state.dispatch_standard(
                    PeerMetadata {
                        address_family,
                        user_id: ROOT_UID,
                        group_id: 7,
                    },
                    Some(policy()),
                    ResolvedStandardOperation::ListIdentities,
                )),
                TerminalOutcome::Error
            );
            assert!(matches!(
                state.handle_packet(peer(OWNER), policy(), AUTHENTICATE_REQUEST),
                BrokerDecision::Start(_)
            ));
        }
    }

    #[test]
    fn second_owner_is_typed_and_does_not_mutate_broker_state() {
        let mut state = BrokerState::default();
        assert_eq!(
            outcome(&state.dispatch_standard(
                peer(ROOT_UID),
                Some(policy()),
                ResolvedStandardOperation::Enroll {
                    account: account("other", OTHER),
                    finger: FingerLabel::LeftThumb,
                },
            )),
            TerminalOutcome::SecondOwner
        );
        let operation = start(
            &mut state,
            peer(ROOT_UID),
            Some(policy()),
            ResolvedStandardOperation::ListIdentities,
        );
        assert_eq!(operation.target_user_id(), Some(OWNER));
    }

    #[test]
    fn non_enrollment_owner_mismatch_is_generic_and_never_claims_token() {
        for peer_user_id in [ROOT_UID, OTHER] {
            for operation in [
                ResolvedStandardOperation::Verify {
                    account: account("other", OTHER),
                    identity: identity(0x41),
                },
                ResolvedStandardOperation::Identify {
                    account: account("other", OTHER),
                },
                ResolvedStandardOperation::DeleteIdentity {
                    account: account("other", OTHER),
                    identity: identity(0x42),
                },
            ] {
                let mut state = BrokerState::default();
                assert_eq!(
                    outcome(&state.dispatch_standard(
                        peer(peer_user_id),
                        Some(policy()),
                        operation,
                    )),
                    TerminalOutcome::Error
                );
                assert!(matches!(
                    state.handle_packet(peer(OWNER), policy(), AUTHENTICATE_REQUEST),
                    BrokerDecision::Start(_)
                ));
            }
        }
    }

    #[test]
    fn missing_owner_enrollment_binds_first_owner_nominee() {
        for (user_id, authority) in [
            (ROOT_UID, StandardPeerAuthority::Root),
            (OWNER, StandardPeerAuthority::FirstOwnerNominee),
        ] {
            let mut state = BrokerState::default();
            let operation = start(
                &mut state,
                peer(user_id),
                None,
                ResolvedStandardOperation::Enroll {
                    account: account("owner", OWNER),
                    finger: FingerLabel::RightIndex,
                },
            );
            assert_eq!(operation.authority(), authority);
            assert_eq!(operation.target_user_id(), Some(OWNER));
            assert!(operation.nominates_first_owner());
        }
    }

    #[test]
    fn list_has_no_asserted_account_and_binds_optional_owner() {
        let mut no_owner = BrokerState::default();
        let operation = start(
            &mut no_owner,
            peer(ROOT_UID),
            None,
            ResolvedStandardOperation::ListIdentities,
        );
        assert_eq!(operation.target_user_id(), None);
        assert_eq!(
            operation.operation(),
            &ResolvedStandardOperation::ListIdentities
        );

        let result = ServerMessage::IdentityList {
            owner: None,
            identities: Vec::new(),
        };
        assert_eq!(
            no_owner.finish_standard(&operation, result.clone()),
            Some(result)
        );

        let mut recorded_owner = BrokerState::default();
        let operation = start(
            &mut recorded_owner,
            peer(ROOT_UID),
            Some(policy()),
            ResolvedStandardOperation::ListIdentities,
        );
        let result = ServerMessage::IdentityList {
            owner: None,
            identities: Vec::new(),
        };
        assert_eq!(
            recorded_owner.finish_standard(&operation, result.clone()),
            Some(result)
        );

        let operation = start(
            &mut recorded_owner,
            peer(ROOT_UID),
            Some(policy()),
            ResolvedStandardOperation::ListIdentities,
        );
        assert_eq!(
            recorded_owner.finish_standard(
                &operation,
                ServerMessage::IdentityList {
                    owner: Some(username("owner")),
                    identities: vec![crate::standard_fingerprint_protocol::Identity {
                        id: identity(0x51),
                        finger: FingerLabel::LeftIndex,
                    }],
                }
            ),
            Some(ServerMessage::IdentityList {
                owner: Some(username("owner")),
                identities: vec![crate::standard_fingerprint_protocol::Identity {
                    id: identity(0x51),
                    finger: FingerLabel::LeftIndex,
                }],
            })
        );

        let operation = start(
            &mut no_owner,
            peer(ROOT_UID),
            None,
            ResolvedStandardOperation::ListIdentities,
        );
        assert_eq!(
            no_owner.finish_standard(
                &operation,
                ServerMessage::IdentityList {
                    owner: Some(username("owner")),
                    identities: vec![crate::standard_fingerprint_protocol::Identity {
                        id: identity(0x52),
                        finger: FingerLabel::RightIndex,
                    }],
                }
            ),
            Some(ServerMessage::Terminal(TerminalOutcome::Error))
        );
    }

    #[test]
    fn exact_identity_and_finger_payloads_remain_bound_and_redacted() {
        let target = identity(0xa5);
        let mut state = BrokerState::default();
        let deletion = start(
            &mut state,
            peer(OWNER),
            Some(policy()),
            ResolvedStandardOperation::DeleteIdentity {
                account: account("owner", OWNER),
                identity: target,
            },
        );
        assert_eq!(
            deletion.operation(),
            &ResolvedStandardOperation::DeleteIdentity {
                account: account("owner", OWNER),
                identity: target,
            }
        );
        let debug = format!("{deletion:?}");
        assert!(!debug.contains("165"));
        assert!(!debug.contains("42000"));

        let mut state = BrokerState::default();
        let enrollment = start(
            &mut state,
            peer(OWNER),
            Some(policy()),
            ResolvedStandardOperation::Enroll {
                account: account("owner", OWNER),
                finger: FingerLabel::RightLittle,
            },
        );
        assert!(matches!(
            enrollment.operation(),
            ResolvedStandardOperation::Enroll {
                finger: FingerLabel::RightLittle,
                ..
            }
        ));
    }

    #[test]
    fn legacy_and_standard_share_one_busy_token_in_both_directions() {
        let mut state = BrokerState::default();
        let standard = start(
            &mut state,
            peer(OWNER),
            Some(policy()),
            ResolvedStandardOperation::Identify {
                account: account("owner", OWNER),
            },
        );
        assert!(matches!(
            state.handle_packet(peer(OWNER), policy(), AUTHENTICATE_REQUEST),
            BrokerDecision::Reply(Response::Busy)
        ));
        assert!(
            state
                .finish_standard(&standard, ServerMessage::Terminal(TerminalOutcome::NoMatch))
                .is_some()
        );

        let BrokerDecision::Start(legacy) =
            state.handle_packet(peer(OWNER), policy(), AUTHENTICATE_REQUEST)
        else {
            panic!("legacy operation starts")
        };
        assert_eq!(legacy.purpose, Purpose::Authenticate);
        assert_eq!(
            outcome(&state.dispatch_standard(
                peer(ROOT_UID),
                Some(policy()),
                ResolvedStandardOperation::ListIdentities,
            )),
            TerminalOutcome::Busy
        );
    }

    #[test]
    fn cancellation_and_disconnect_win_typed_standard_completion() {
        for disconnect in [false, true] {
            let mut state = BrokerState::default();
            let operation = start(
                &mut state,
                peer(OWNER),
                Some(policy()),
                ResolvedStandardOperation::DeleteIdentity {
                    account: account("owner", OWNER),
                    identity: identity(0x22),
                },
            );
            let delivered = if disconnect {
                state.standard_client_disconnected(&operation, |_| true)
            } else {
                state.cancel_standard(&operation, |_| true)
            };
            assert!(delivered);
            assert_eq!(
                state.finish_standard(
                    &operation,
                    ServerMessage::Terminal(TerminalOutcome::Completed)
                ),
                Some(ServerMessage::Terminal(TerminalOutcome::Cancelled))
            );
        }
    }

    #[test]
    fn verify_completion_must_match_the_exact_bound_identity() {
        let expected = identity(0x31);
        let mut state = BrokerState::default();
        let operation = start(
            &mut state,
            peer(OWNER),
            Some(policy()),
            ResolvedStandardOperation::Verify {
                account: account("owner", OWNER),
                identity: expected,
            },
        );
        assert_eq!(
            state.finish_standard(
                &operation,
                ServerMessage::Terminal(TerminalOutcome::Matched(identity(0x32)))
            ),
            Some(ServerMessage::Terminal(TerminalOutcome::Error))
        );

        let operation = start(
            &mut state,
            peer(OWNER),
            Some(policy()),
            ResolvedStandardOperation::Verify {
                account: account("owner", OWNER),
                identity: expected,
            },
        );
        assert_eq!(
            state.finish_standard(
                &operation,
                ServerMessage::Terminal(TerminalOutcome::Matched(expected))
            ),
            Some(ServerMessage::Terminal(TerminalOutcome::Matched(expected)))
        );
    }

    #[test]
    fn enrollment_only_failures_are_sanitized_for_every_other_operation() {
        for result in [TerminalOutcome::Duplicate, TerminalOutcome::CapacityFull] {
            for (operation, allowed) in [
                (ResolvedStandardOperation::ListIdentities, false),
                (
                    ResolvedStandardOperation::Enroll {
                        account: account("owner", OWNER),
                        finger: FingerLabel::RightLittle,
                    },
                    true,
                ),
                (
                    ResolvedStandardOperation::Verify {
                        account: account("owner", OWNER),
                        identity: identity(0x41),
                    },
                    false,
                ),
                (
                    ResolvedStandardOperation::Identify {
                        account: account("owner", OWNER),
                    },
                    false,
                ),
                (
                    ResolvedStandardOperation::DeleteIdentity {
                        account: account("owner", OWNER),
                        identity: identity(0x42),
                    },
                    false,
                ),
            ] {
                let mut state = BrokerState::default();
                let active = start(&mut state, peer(ROOT_UID), Some(policy()), operation);
                assert_eq!(
                    state.finish_standard(&active, ServerMessage::Terminal(result)),
                    Some(ServerMessage::Terminal(if allowed {
                        result
                    } else {
                        TerminalOutcome::Error
                    }))
                );
            }
        }
    }

    #[test]
    fn stale_standard_handle_cannot_cancel_or_finish_newer_token() {
        let mut broker = BrokerState::default();
        let stale = start(
            &mut broker,
            peer(ROOT_UID),
            Some(policy()),
            ResolvedStandardOperation::ListIdentities,
        );
        assert!(
            broker
                .finish_standard(
                    &stale,
                    ServerMessage::IdentityList {
                        owner: None,
                        identities: Vec::new(),
                    }
                )
                .is_some()
        );
        let current = start(
            &mut broker,
            peer(OWNER),
            Some(policy()),
            ResolvedStandardOperation::Identify {
                account: account("owner", OWNER),
            },
        );
        assert!(!broker.cancel_standard(&stale, |_| true));
        assert_eq!(
            broker.finish_standard(&stale, ServerMessage::Terminal(TerminalOutcome::Error)),
            None
        );
        assert_eq!(
            outcome(&broker.dispatch_standard(
                peer(ROOT_UID),
                Some(policy()),
                ResolvedStandardOperation::ListIdentities,
            )),
            TerminalOutcome::Busy
        );
        assert_eq!(
            broker.finish_standard(&current, ServerMessage::Terminal(TerminalOutcome::NoMatch)),
            Some(ServerMessage::Terminal(TerminalOutcome::NoMatch))
        );
    }

    #[test]
    fn legacy_wire_and_result_contract_is_byte_identical_after_refactor() {
        for (request, bytes) in [
            (Request::Authenticate, b"T1AUTH\x01\n".as_slice()),
            (Request::Approve, b"T1APRV\x01\n".as_slice()),
            (Request::Enroll, b"T1ENRL\x01\n".as_slice()),
            (Request::Cancel, b"T1CNCL\x01\n".as_slice()),
        ] {
            assert_eq!(request.encode(), bytes);
        }
        for (response, bytes) in [
            (Response::Okay, RESPONSE_OK.as_slice()),
            (Response::Denied, RESPONSE_DENIED.as_slice()),
            (Response::Busy, RESPONSE_BUSY.as_slice()),
            (Response::Failure, RESPONSE_FAILURE.as_slice()),
        ] {
            assert_eq!(response.encode(), bytes);
        }

        let mut state = BrokerState::default();
        let BrokerDecision::Start(operation) =
            state.handle_packet(peer(OWNER), policy(), AUTHENTICATE_REQUEST)
        else {
            panic!("legacy operation starts")
        };
        assert_eq!(
            state.finish(operation.token, OperationResult::Matched),
            Some(Response::Okay)
        );
    }
}

//! Authorized rendering-client ownership and revocation state.

use std::{error::Error, fmt};

/// Why a connection could not become the active rendering client.
#[derive(Clone, Eq, PartialEq)]
pub enum ClientAdmissionError<Reason> {
    Unauthorized(Reason),
    ActiveClientExists,
    RevocationCleanupPending,
}

impl<Reason> fmt::Debug for ClientAdmissionError<Reason> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unauthorized(_) => formatter.write_str("Unauthorized([redacted])"),
            Self::ActiveClientExists => formatter.write_str("ActiveClientExists"),
            Self::RevocationCleanupPending => formatter.write_str("RevocationCleanupPending"),
        }
    }
}

impl<Reason> fmt::Display for ClientAdmissionError<Reason> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Unauthorized(_) => "rendering client is not authorized",
            Self::ActiveClientExists => "a rendering client is already active",
            Self::RevocationCleanupPending => "revoked client cleanup is still pending",
        };
        formatter.write_str(message)
    }
}

impl<Reason> Error for ClientAdmissionError<Reason> {}

/// Identity-bound access to one state's pending revocation cleanup.
///
/// Dropping this guard without calling [`Self::confirm_cleanup`] keeps the
/// resources unconfirmed in their owning state so cleanup can be retried.
/// Because it borrows those resources directly, it cannot expose another
/// state's bundle.
#[must_use]
pub struct RevokedClient<'state, ConnectionId, Resources = ()> {
    connection_id: &'state ConnectionId,
    resources: &'state mut Resources,
    cleanup_confirmed: &'state mut bool,
}

impl<ConnectionId, Resources> fmt::Debug for RevokedClient<'_, ConnectionId, Resources> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RevokedClient([redacted])")
    }
}

impl<ConnectionId, Resources> RevokedClient<'_, ConnectionId, Resources> {
    /// Borrows the identifier of the connection being cleaned up.
    #[must_use]
    pub fn connection_id(&self) -> &ConnectionId {
        self.connection_id
    }

    /// Borrows the connection-bound state that must be cleaned up.
    #[must_use]
    pub fn resources(&self) -> &Resources {
        self.resources
    }

    /// Mutably borrows the connection-bound state for cleanup.
    #[must_use]
    pub fn resources_mut(&mut self) -> &mut Resources {
        self.resources
    }

    /// Confirms that this guard's resources have been cleaned.
    ///
    /// This confirmation is identity-bound to the borrowed state. The owner
    /// must then call [`ClientState::finish_revocation`] to drop the bundle and
    /// reopen admission.
    pub fn confirm_cleanup(self) {
        *self.cleanup_confirmed = true;
    }
}

#[derive(Eq, PartialEq)]
struct ActiveClient<ConnectionId, Resources> {
    connection_id: ConnectionId,
    resources: Resources,
}

/// Owns the single rendering-client lease for the seat containing the T1.
///
/// Kernel credentials, allowed-group membership, and active local session
/// ownership are deliberately checked by the injected admission seam. The live
/// adapter also owns revocation cleanup; every returned [`RevokedClient`] means
/// it must discard that connection's buffers and queued actions, release any
/// synthesized keys, confirm the guard, and then call
/// [`ClientState::finish_revocation`]. A
/// `ConnectionId` must identify one connection lifetime and must not be reused
/// while stale work for that lifetime can still arrive.
pub struct ClientState<ConnectionId, Resources = ()> {
    active: Option<ActiveClient<ConnectionId, Resources>>,
    pending: Option<ActiveClient<ConnectionId, Resources>>,
    pending_cleanup_confirmed: bool,
}

impl<ConnectionId, Resources> fmt::Debug for ClientState<ConnectionId, Resources> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientState")
            .field("has_active_client", &self.active.is_some())
            .field("revocation_cleanup_pending", &self.pending.is_some())
            .field(
                "revocation_cleanup_confirmed",
                &self.pending_cleanup_confirmed,
            )
            .finish()
    }
}

impl<ConnectionId, Resources> Default for ClientState<ConnectionId, Resources> {
    fn default() -> Self {
        Self {
            active: None,
            pending: None,
            pending_cleanup_confirmed: false,
        }
    }
}

impl<ConnectionId> ClientState<ConnectionId>
where
    ConnectionId: Eq,
{
    /// Runs the per-connection authorization check and admits one client.
    ///
    /// The callback must use kernel-supplied peer credentials to verify allowed
    /// group membership and ownership of the active local session on the seat
    /// containing the T1 devices. It runs even when another client is active,
    /// so every connection crosses the same authorization boundary.
    ///
    /// # Errors
    ///
    /// Returns [`ClientAdmissionError::Unauthorized`] when the injected check
    /// fails, [`ClientAdmissionError::ActiveClientExists`] when the one-client
    /// lease is already owned, or
    /// [`ClientAdmissionError::RevocationCleanupPending`] until the old client's
    /// cleanup is confirmed. No failure changes lease state.
    pub fn admit<Reason>(
        &mut self,
        connection_id: ConnectionId,
        authorize: impl FnOnce() -> Result<(), Reason>,
    ) -> Result<(), ClientAdmissionError<Reason>> {
        self.admit_with_resources(connection_id, authorize, || ())
    }
}

impl<ConnectionId, Resources> ClientState<ConnectionId, Resources>
where
    ConnectionId: Eq,
{
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Authorizes one connection and binds a fresh resource bundle to its lease.
    ///
    /// `make_resources` runs only after authorization succeeds and the lease is
    /// known to be free. This keeps buffers, queued actions, synthesized-key
    /// state, and any future connection-owned state from being created for a
    /// rejected client.
    ///
    /// # Errors
    ///
    /// Returns the same failures as [`ClientState::admit`], without constructing or
    /// installing resources.
    pub fn admit_with_resources<Reason>(
        &mut self,
        connection_id: ConnectionId,
        authorize: impl FnOnce() -> Result<(), Reason>,
        make_resources: impl FnOnce() -> Resources,
    ) -> Result<(), ClientAdmissionError<Reason>> {
        authorize().map_err(ClientAdmissionError::Unauthorized)?;
        if self.active.is_some() {
            return Err(ClientAdmissionError::ActiveClientExists);
        }
        if self.pending.is_some() {
            return Err(ClientAdmissionError::RevocationCleanupPending);
        }

        self.active = Some(ActiveClient {
            connection_id,
            resources: make_resources(),
        });
        Ok(())
    }

    /// Borrows resources only for the exact active connection.
    #[must_use]
    pub fn resources(&self, connection_id: &ConnectionId) -> Option<&Resources> {
        let active = self.active.as_ref()?;
        (&active.connection_id == connection_id).then_some(&active.resources)
    }

    /// Mutably borrows resources only for the exact active connection.
    #[must_use]
    pub fn resources_mut(&mut self, connection_id: &ConnectionId) -> Option<&mut Resources> {
        let active = self.active.as_mut()?;
        (&active.connection_id == connection_id).then_some(&mut active.resources)
    }

    /// Revokes the old client when the active local session changes.
    ///
    /// The active lease is removed immediately, but a replacement remains
    /// blocked until the caller finishes this state's cleanup.
    pub fn session_transition(&mut self) -> Option<RevokedClient<'_, ConnectionId, Resources>> {
        if self.pending.is_some() {
            return None;
        }
        self.pending = self.active.take();
        self.pending_cleanup_confirmed = false;
        self.pending_revocation()
    }

    /// Clears ownership only when the disconnect belongs to the active client.
    ///
    /// A late disconnect from a previously revoked connection cannot evict its
    /// replacement.
    pub fn disconnect(
        &mut self,
        connection_id: &ConnectionId,
    ) -> Option<RevokedClient<'_, ConnectionId, Resources>> {
        if self
            .active
            .as_ref()
            .is_none_or(|active| &active.connection_id != connection_id)
        {
            return None;
        }

        self.session_transition()
    }

    /// Reopens identity-bound access to a previously interrupted cleanup.
    ///
    /// Dropping this guard again leaves cleanup pending for another retry.
    pub fn pending_revocation(&mut self) -> Option<RevokedClient<'_, ConnectionId, Resources>> {
        if self.pending_cleanup_confirmed {
            return None;
        }
        let pending = self.pending.as_mut()?;
        Some(RevokedClient {
            connection_id: &pending.connection_id,
            resources: &mut pending.resources,
            cleanup_confirmed: &mut self.pending_cleanup_confirmed,
        })
    }

    /// Confirms that this state's pending bundle has been cleaned.
    ///
    /// The identity-bound cleanup guard must first call
    /// [`RevokedClient::confirm_cleanup`]. This method then removes and drops
    /// only this state's own resources; another state's guard cannot supply its
    /// confirmation.
    pub fn finish_revocation(&mut self) -> Option<ConnectionId> {
        if !self.pending_cleanup_confirmed {
            return None;
        }
        let ActiveClient {
            connection_id,
            resources,
        } = self.pending.take()?;
        drop(resources);
        self.pending_cleanup_confirmed = false;
        Some(connection_id)
    }

    #[must_use]
    pub fn has_active_client(&self) -> bool {
        self.active.is_some()
    }

    #[must_use]
    pub fn has_pending_revocation_cleanup(&self) -> bool {
        self.pending.is_some()
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::*;
    use crate::frame_state::{FrameLayout, FrameState, VerifiedBufferMetadata};

    #[test]
    fn authorization_runs_for_every_connection_attempt() {
        let mut state = ClientState::new();
        let checks = Cell::new(0);
        let authorize = || {
            checks.set(checks.get() + 1);
            Ok::<(), &'static str>(())
        };

        state.admit("first", authorize).expect("first client");
        assert_eq!(
            state.admit("second", authorize),
            Err(ClientAdmissionError::ActiveClientExists)
        );
        assert_eq!(checks.get(), 2);
    }

    #[test]
    fn unauthorized_connection_never_changes_ownership() {
        let mut state = ClientState::new();
        state
            .admit("active", || Ok::<(), &'static str>(()))
            .expect("active client");

        assert_eq!(
            state.admit("attacker", || Err("not the active local session")),
            Err(ClientAdmissionError::Unauthorized(
                "not the active local session"
            ))
        );
        assert!(state.has_active_client());
        let revoked = state.disconnect(&"active").expect("active client revoked");
        assert_eq!(revoked.connection_id(), &"active");
        revoked.confirm_cleanup();
        assert_eq!(state.finish_revocation(), Some("active"));
    }

    #[test]
    fn active_client_blocks_another_authorized_client() {
        let mut state = ClientState::new();
        state
            .admit("first", || Ok::<(), &'static str>(()))
            .expect("first client");

        assert_eq!(
            state.admit("second", || Ok::<(), &'static str>(())),
            Err(ClientAdmissionError::ActiveClientExists)
        );
        assert!(state.has_active_client());
    }

    #[test]
    fn session_transition_revokes_before_replacement_admission() {
        let mut state = ClientState::new();
        state
            .admit("old-session", || Ok::<(), &'static str>(()))
            .expect("old client");

        let revoked = state.session_transition().expect("old client revoked");
        assert_eq!(revoked.connection_id(), &"old-session");
        drop(revoked);
        assert!(!state.has_active_client());
        assert!(state.has_pending_revocation_cleanup());
        assert_eq!(state.finish_revocation(), None);
        assert_eq!(
            state.admit("new-session", || Ok::<(), &'static str>(())),
            Err(ClientAdmissionError::RevocationCleanupPending)
        );
        let revoked = state.pending_revocation().expect("cleanup retry");
        assert_eq!(revoked.connection_id(), &"old-session");
        revoked.confirm_cleanup();
        assert_eq!(state.finish_revocation(), Some("old-session"));

        state
            .admit("new-session", || Ok::<(), &'static str>(()))
            .expect("replacement client");
        assert!(state.has_active_client());
    }

    #[test]
    fn transition_without_a_client_is_idempotent() {
        let mut state = ClientState::<&str>::new();
        assert!(state.session_transition().is_none());
        assert!(state.session_transition().is_none());
    }

    #[test]
    fn stale_disconnect_cannot_evict_replacement() {
        let mut state = ClientState::new();
        state
            .admit("old", || Ok::<(), &'static str>(()))
            .expect("old client");
        let revoked = state.session_transition().expect("old client revoked");
        revoked.confirm_cleanup();
        assert_eq!(state.finish_revocation(), Some("old"));
        state
            .admit("new", || Ok::<(), &'static str>(()))
            .expect("new client");

        assert!(state.disconnect(&"old").is_none());
        assert!(state.has_active_client());
        let revoked = state.disconnect(&"new").expect("new client revoked");
        drop(revoked);
        assert!(!state.has_active_client());
        assert!(state.has_pending_revocation_cleanup());
        let revoked = state.pending_revocation().expect("new cleanup retained");
        revoked.confirm_cleanup();
        assert_eq!(state.finish_revocation(), Some("new"));
    }

    #[test]
    fn finishing_another_states_cleanup_cannot_clear_the_owner() {
        let mut owner = ClientState::new();
        owner
            .admit_with_resources("active", || Ok::<(), &str>(()), || vec![1_u8, 2])
            .expect("active client");
        drop(owner.session_transition().expect("owner client revoked"));

        let mut unrelated = ClientState::<&str, Vec<u8>>::new();
        assert_eq!(unrelated.finish_revocation(), None);
        assert!(owner.has_pending_revocation_cleanup());
        unrelated
            .admit_with_resources("other", || Ok::<(), &str>(()), || vec![9_u8])
            .expect("unrelated client");
        let mut unrelated_cleanup = unrelated
            .session_transition()
            .expect("unrelated client revoked");
        unrelated_cleanup.resources_mut().clear();
        unrelated_cleanup.confirm_cleanup();
        assert_eq!(unrelated.finish_revocation(), Some("other"));

        assert!(owner.has_pending_revocation_cleanup());
        assert_eq!(owner.finish_revocation(), None);
        assert_eq!(
            owner.admit_with_resources("replacement", || Ok::<(), &str>(()), Vec::new),
            Err(ClientAdmissionError::RevocationCleanupPending)
        );

        let mut owner_cleanup = owner.pending_revocation().expect("owner cleanup retained");
        assert_eq!(owner_cleanup.resources(), &[1, 2]);
        owner_cleanup.resources_mut().clear();
        owner_cleanup.confirm_cleanup();
        assert_eq!(owner.finish_revocation(), Some("active"));
        assert!(!owner.has_pending_revocation_cleanup());
    }

    #[test]
    fn cleanup_unwind_retains_the_exact_bundle_and_blocks_admission() {
        let mut state = ClientState::new();
        state
            .admit_with_resources("old", || Ok::<(), &str>(()), || vec![1_u8])
            .expect("old client");

        let panic = catch_unwind(AssertUnwindSafe(|| {
            let mut revoked = state.session_transition().expect("old client revoked");
            revoked.resources_mut().push(2);
            panic!("synthetic cleanup interruption");
        }));

        assert!(panic.is_err());
        assert!(!state.has_active_client());
        assert!(state.has_pending_revocation_cleanup());
        assert_eq!(
            state.admit_with_resources("unauthorized", || Err("denied"), Vec::new),
            Err(ClientAdmissionError::Unauthorized("denied"))
        );
        assert_eq!(
            state.admit_with_resources("new", || Ok::<(), &str>(()), Vec::new),
            Err(ClientAdmissionError::RevocationCleanupPending)
        );
        let mut retry = state.pending_revocation().expect("cleanup retry");
        assert_eq!(retry.connection_id(), &"old");
        assert_eq!(retry.resources(), &[1, 2]);
        retry.resources_mut().clear();
        retry.confirm_cleanup();
        assert_eq!(state.finish_revocation(), Some("old"));
    }

    #[test]
    fn unwind_after_confirmation_keeps_admission_closed_until_finish() {
        let mut state = ClientState::new();
        state
            .admit_with_resources("old", || Ok::<(), &str>(()), || vec![1_u8])
            .expect("old client");

        let panic = catch_unwind(AssertUnwindSafe(|| {
            let mut revoked = state.session_transition().expect("old client revoked");
            revoked.resources_mut().clear();
            revoked.confirm_cleanup();
            panic!("synthetic interruption before finish");
        }));

        assert!(panic.is_err());
        assert!(state.has_pending_revocation_cleanup());
        assert!(state.pending_revocation().is_none());
        assert_eq!(
            state.admit_with_resources("new", || Ok::<(), &str>(()), Vec::new),
            Err(ClientAdmissionError::RevocationCleanupPending)
        );
        assert_eq!(state.finish_revocation(), Some("old"));
        state
            .admit_with_resources("new", || Ok::<(), &str>(()), Vec::new)
            .expect("replacement client");
    }

    #[test]
    fn rejected_admission_never_constructs_connection_resources() {
        let mut state = ClientState::<&str, Vec<&str>>::new();
        let constructions = Cell::new(0);
        let make_resources = || {
            constructions.set(constructions.get() + 1);
            vec!["connection-owned state"]
        };

        assert_eq!(
            state.admit_with_resources("unauthorized", || Err("denied"), make_resources),
            Err(ClientAdmissionError::Unauthorized("denied"))
        );
        assert_eq!(constructions.get(), 0);

        state
            .admit_with_resources("active", || Ok::<(), &str>(()), make_resources)
            .expect("active client");
        assert_eq!(constructions.get(), 1);
        assert_eq!(
            state.admit_with_resources("extra", || Ok::<(), &str>(()), make_resources),
            Err(ClientAdmissionError::ActiveClientExists)
        );
        assert_eq!(constructions.get(), 1);
    }

    #[test]
    fn resources_are_accessible_only_through_their_exact_connection() {
        let mut state = ClientState::new();
        state
            .admit_with_resources("active", || Ok::<(), &str>(()), || vec![1_u8])
            .expect("active client");

        assert_eq!(state.resources(&"stale"), None);
        assert_eq!(state.resources_mut(&"stale"), None);
        state
            .resources_mut(&"active")
            .expect("active resources")
            .push(2);
        assert_eq!(state.resources(&"active"), Some(&vec![1, 2]));
    }

    #[test]
    fn revocation_transfers_complete_frame_ownership_before_replacement() {
        let layout = FrameLayout::new(100, 20).expect("valid layout");
        let metadata = VerifiedBufferMetadata {
            stride: layout.stride(),
            byte_length: layout.byte_length(),
        };
        let mut state = ClientState::new();
        state
            .admit_with_resources(
                "old",
                || Ok::<(), &str>(()),
                || FrameState::<&str, u64>::new(layout),
            )
            .expect("old client");
        let frames = state.resources_mut(&"old").expect("old frame state");
        frames
            .register_buffer("old-buffer", metadata)
            .expect("old buffer");
        frames
            .submit_frame(&"old-buffer", 7, &[])
            .expect("old in-flight frame");

        let revoked = state.session_transition().expect("old client revoked");
        assert_eq!(revoked.connection_id(), &"old");
        assert_eq!(revoked.resources().registered_buffer_count(), 1);
        assert_eq!(revoked.resources().in_flight_count(), 1);
        drop(revoked);
        assert!(!state.has_active_client());
        assert!(state.has_pending_revocation_cleanup());
        assert!(state.resources(&"old").is_none());
        assert!(state.disconnect(&"old").is_none());

        let mut revoked = state.pending_revocation().expect("frame cleanup retry");
        revoked.resources_mut().disconnect();
        assert_eq!(revoked.resources().registered_buffer_count(), 0);
        assert_eq!(revoked.resources().in_flight_count(), 0);
        revoked.confirm_cleanup();
        assert_eq!(state.finish_revocation(), Some("old"));

        state
            .admit_with_resources(
                "new",
                || Ok::<(), &str>(()),
                || FrameState::<&str, u64>::new(layout),
            )
            .expect("replacement client");
        assert_eq!(
            state
                .resources(&"new")
                .expect("new frames")
                .registered_buffer_count(),
            0
        );
        assert!(state.has_active_client());
    }

    #[test]
    fn resource_debug_output_is_redacted() {
        let mut state = ClientState::new();
        state
            .admit_with_resources(
                "private connection",
                || Ok::<(), &str>(()),
                || vec!["private resource"],
            )
            .expect("active client");
        assert_eq!(
            format!("{state:?}"),
            "ClientState { has_active_client: true, revocation_cleanup_pending: false, revocation_cleanup_confirmed: false }"
        );

        let revoked = state.session_transition().expect("client revoked");
        assert_eq!(format!("{revoked:?}"), "RevokedClient([redacted])");
        revoked.confirm_cleanup();
        assert_eq!(state.finish_revocation(), Some("private connection"));
    }

    #[test]
    fn admission_diagnostic_does_not_echo_authorization_details() {
        let mut state = ClientState::new();
        let error = state
            .admit("synthetic", || Err("private peer detail"))
            .expect_err("connection is unauthorized");

        assert_eq!(error.to_string(), "rendering client is not authorized");
        assert!(!error.to_string().contains("private"));
        assert_eq!(format!("{error:?}"), "Unauthorized([redacted])");
        assert!(!format!("{error:?}").contains("private"));
    }
}

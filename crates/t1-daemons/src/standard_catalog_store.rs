//! Read-only standard identity view over committed private broker state.
//!
//! This adapter performs no hardware work. It loads one active catacomb
//! generation and its separately recorded owner, then revalidates every
//! canonical account through NSS before exposing standard identities.

use std::fmt;

use crate::catacomb_store::{CatacombPairStore, CatacombStoreError};
use crate::enrollment_owner::{EnrollmentOwner, EnrollmentOwnerError, EnrollmentOwnerStore};
use crate::identity_metadata::{IdentityMetadata, MetadataError, decode as decode_metadata};
use crate::nss_account::{NssAccountError, resolve_standard_account};
use crate::standard_fingerprint_protocol::{Identity, ServerMessage, Username};
use crate::standard_identity_catalog::{CatalogError, StandardIdentityCatalog};
use crate::standard_operation_authority::ResolvedStandardAccount;

/// Standard-visible listing built from one committed generation.
#[derive(Clone, Eq, PartialEq)]
pub struct CommittedStandardIdentityList {
    owner: Option<Username>,
    identities: Vec<Identity>,
}

impl CommittedStandardIdentityList {
    /// Returns the canonical owner only when at least one labeled identity is
    /// visible.
    #[must_use]
    pub const fn owner(&self) -> Option<&Username> {
        self.owner.as_ref()
    }

    /// Returns only labeled standard identities.
    #[must_use]
    pub fn identities(&self) -> &[Identity] {
        &self.identities
    }

    /// Converts this validated view to the broker's existing response shape.
    #[must_use]
    pub fn into_server_message(self) -> ServerMessage {
        ServerMessage::IdentityList {
            owner: self.owner,
            identities: self.identities,
        }
    }
}

impl fmt::Debug for CommittedStandardIdentityList {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CommittedStandardIdentityList(<redacted>)")
    }
}

/// Loads the standard-visible list without opening the biometric device.
///
/// Legacy generations without identity metadata return an empty, ownerless
/// standard list even when durable owner state exists. Present metadata is
/// bound to the recorded owner through a fresh canonical NSS lookup.
///
/// # Errors
///
/// Fails closed for unavailable or unsafe stores, malformed metadata, account
/// lookup failure, owner disagreement, or catalog reconciliation failure.
pub fn load_committed_standard_list(
    pair_store: &CatacombPairStore,
    owner_store: &EnrollmentOwnerStore,
) -> Result<CommittedStandardIdentityList, StandardCatalogStoreError> {
    load_committed_standard_list_with(pair_store, owner_store, resolve_standard_account)
}

/// Loads a committed catalog for one previously resolved standard account.
///
/// The supplied canonical name is re-resolved at execution time. Its exact
/// name and UID must remain unchanged, equal the metadata owner, and equal the
/// separately recorded enrollment-owner UID. Canonical peer admission before
/// this call does not replace this execution-time check.
///
/// # Errors
///
/// In addition to storage, metadata, NSS, and catalog failures, refuses legacy
/// metadata-free state and every account or recorded-owner mismatch.
pub fn load_committed_catalog_for_account(
    pair_store: &CatacombPairStore,
    owner_store: &EnrollmentOwnerStore,
    account: &ResolvedStandardAccount,
) -> Result<StandardIdentityCatalog, StandardCatalogStoreError> {
    load_committed_catalog_for_account_with(
        pair_store,
        owner_store,
        account,
        resolve_standard_account,
    )
}

fn load_committed_standard_list_with(
    pair_store: &CatacombPairStore,
    owner_store: &EnrollmentOwnerStore,
    resolve: impl FnOnce(&Username) -> Result<ResolvedStandardAccount, NssAccountError>,
) -> Result<CommittedStandardIdentityList, StandardCatalogStoreError> {
    let pair = match pair_store.load() {
        Ok(pair) => pair,
        Err(CatacombStoreError::MissingPair) => {
            return match owner_store.load() {
                Err(EnrollmentOwnerError::MissingOwner) => Ok(CommittedStandardIdentityList {
                    owner: None,
                    identities: Vec::new(),
                }),
                Ok(_) => Err(StandardCatalogStoreError::PairStore(
                    CatacombStoreError::MissingPair,
                )),
                Err(error) => Err(StandardCatalogStoreError::OwnerStore(error)),
            };
        }
        Err(error) => return Err(StandardCatalogStoreError::PairStore(error)),
    };
    let recorded_owner = owner_store
        .load()
        .map_err(StandardCatalogStoreError::OwnerStore)?;
    let manifest = pair
        .metadata()
        .map(decode_metadata)
        .transpose()
        .map_err(StandardCatalogStoreError::Metadata)?;
    let Some(manifest) = manifest else {
        return Ok(CommittedStandardIdentityList {
            owner: None,
            identities: Vec::new(),
        });
    };

    let account = resolve(&manifest.owner).map_err(StandardCatalogStoreError::AccountLookup)?;
    require_manifest_account(&manifest, recorded_owner, &account)?;
    let catalog = reconcile_manifest(manifest)?;
    let identities = catalog.labeled_identities();
    let owner = if identities.is_empty() {
        None
    } else {
        Some(account.canonical_username().clone())
    };
    Ok(CommittedStandardIdentityList { owner, identities })
}

fn load_committed_catalog_for_account_with(
    pair_store: &CatacombPairStore,
    owner_store: &EnrollmentOwnerStore,
    account: &ResolvedStandardAccount,
    resolve: impl FnOnce(&Username) -> Result<ResolvedStandardAccount, NssAccountError>,
) -> Result<StandardIdentityCatalog, StandardCatalogStoreError> {
    let (recorded_owner, manifest) = load_committed_state(pair_store, owner_store)?;
    let manifest = manifest.ok_or(StandardCatalogStoreError::MissingMetadata)?;
    let current =
        resolve(account.canonical_username()).map_err(StandardCatalogStoreError::AccountLookup)?;
    if current != *account {
        return Err(StandardCatalogStoreError::AccountChanged);
    }
    require_manifest_account(&manifest, recorded_owner, &current)?;
    reconcile_manifest(manifest)
}

fn load_committed_state(
    pair_store: &CatacombPairStore,
    owner_store: &EnrollmentOwnerStore,
) -> Result<(EnrollmentOwner, Option<IdentityMetadata>), StandardCatalogStoreError> {
    let pair = pair_store
        .load()
        .map_err(StandardCatalogStoreError::PairStore)?;
    let recorded_owner = owner_store
        .load()
        .map_err(StandardCatalogStoreError::OwnerStore)?;
    let manifest = pair
        .metadata()
        .map(decode_metadata)
        .transpose()
        .map_err(StandardCatalogStoreError::Metadata)?;
    Ok((recorded_owner, manifest))
}

fn require_manifest_account(
    manifest: &IdentityMetadata,
    recorded_owner: EnrollmentOwner,
    account: &ResolvedStandardAccount,
) -> Result<(), StandardCatalogStoreError> {
    if manifest.owner != *account.canonical_username() {
        return Err(StandardCatalogStoreError::AccountMismatch);
    }
    if recorded_owner.as_raw() != account.user_id() {
        return Err(StandardCatalogStoreError::OwnerMismatch);
    }
    Ok(())
}

fn reconcile_manifest(
    manifest: IdentityMetadata,
) -> Result<StandardIdentityCatalog, StandardCatalogStoreError> {
    let owner = manifest.owner.clone();
    let live_identities: Vec<_> = manifest
        .identities
        .iter()
        .map(|identity| identity.id)
        .collect();
    StandardIdentityCatalog::reconcile(Some(manifest), owner, &live_identities)
        .map_err(StandardCatalogStoreError::Catalog)
}

/// Payload-free committed-catalog loading failure.
pub enum StandardCatalogStoreError {
    PairStore(CatacombStoreError),
    OwnerStore(EnrollmentOwnerError),
    Metadata(MetadataError),
    AccountLookup(NssAccountError),
    MissingMetadata,
    AccountChanged,
    AccountMismatch,
    OwnerMismatch,
    Catalog(CatalogError),
}

impl fmt::Debug for StandardCatalogStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PairStore(_) => "PairStore(<redacted>)",
            Self::OwnerStore(_) => "OwnerStore(<redacted>)",
            Self::Metadata(_) => "Metadata(<redacted>)",
            Self::AccountLookup(_) => "AccountLookup(<redacted>)",
            Self::MissingMetadata => "MissingMetadata",
            Self::AccountChanged => "AccountChanged",
            Self::AccountMismatch => "AccountMismatch",
            Self::OwnerMismatch => "OwnerMismatch",
            Self::Catalog(_) => "Catalog(<redacted>)",
        })
    }
}

impl fmt::Display for StandardCatalogStoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::PairStore(_) => "committed fingerprint generation is unavailable",
            Self::OwnerStore(_) => "committed fingerprint owner is unavailable",
            Self::Metadata(_) => "committed fingerprint metadata is invalid",
            Self::AccountLookup(_) => "committed fingerprint account lookup failed",
            Self::MissingMetadata => "committed fingerprint metadata is absent",
            Self::AccountChanged => "standard fingerprint account changed",
            Self::AccountMismatch => "committed fingerprint account does not match",
            Self::OwnerMismatch => "committed fingerprint owner does not match",
            Self::Catalog(_) => "committed fingerprint catalog is invalid",
        })
    }
}

impl std::error::Error for StandardCatalogStoreError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use crate::enrollment_owner::OwnerClaim;
    use crate::identity_metadata::{IdentityMetadataEntry, encode as encode_metadata};
    use crate::standard_fingerprint_protocol::{FingerLabel, IdentityId};

    static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(0);
    const OWNER_UID: u32 = 42_000;

    struct TestState {
        directory: PathBuf,
        pair_store: CatacombPairStore,
        owner_store: EnrollmentOwnerStore,
    }

    impl TestState {
        fn new() -> Self {
            let state = Self::unowned();
            assert_eq!(
                state
                    .owner_store
                    .claim(EnrollmentOwner::new(OWNER_UID).unwrap()),
                Ok(OwnerClaim::Recorded)
            );
            state
        }

        fn unowned() -> Self {
            let sequence = DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let directory = std::env::temp_dir().join(format!(
                "t1bridge-standard-catalog-store-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&directory).unwrap();
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
            let metadata = fs::metadata(&directory).unwrap();
            let pair_store = CatacombPairStore::new(directory.join("pairs"));
            let owner_store = EnrollmentOwnerStore::for_test(
                directory.join("owner"),
                metadata.uid(),
                metadata.gid(),
            );
            Self {
                directory,
                pair_store,
                owner_store,
            }
        }

        fn commit_legacy(&self) {
            self.pair_store
                .commit(b"synthetic user catacomb", b"synthetic master catacomb")
                .unwrap();
        }

        fn commit_manifest(&self, manifest: &IdentityMetadata) {
            let encoded = encode_metadata(manifest).unwrap();
            let mut transaction = self.pair_store.begin_transaction().unwrap();
            transaction.reserve_recovery().unwrap();
            transaction.write_metadata(&encoded).unwrap();
            transaction.write_user(b"synthetic user catacomb").unwrap();
            transaction
                .write_master(b"synthetic master catacomb")
                .unwrap();
            transaction.promote_after_native_finish().unwrap();
        }
    }

    impl Drop for TestState {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    fn username(value: &str) -> Username {
        Username::new(value).unwrap()
    }

    fn account(name: &str, user_id: u32) -> ResolvedStandardAccount {
        let name = username(name);
        ResolvedStandardAccount::new(&name, &name, user_id).unwrap()
    }

    fn id(value: u8) -> crate::standard_fingerprint_protocol::IdentityId {
        IdentityId::new([value; 16]).unwrap()
    }

    fn manifest(entries: Vec<IdentityMetadataEntry>) -> IdentityMetadata {
        IdentityMetadata::new(username("synthetic-owner"), entries).unwrap()
    }

    #[test]
    fn metadata_free_generation_is_an_empty_ownerless_standard_list() {
        let state = TestState::new();
        state.commit_legacy();
        let list = load_committed_standard_list_with(&state.pair_store, &state.owner_store, |_| {
            panic!("legacy state must not invent or resolve an owner name")
        })
        .unwrap();

        assert_eq!(list.owner(), None);
        assert!(list.identities().is_empty());
        assert_eq!(
            list.into_server_message(),
            ServerMessage::IdentityList {
                owner: None,
                identities: Vec::new(),
            }
        );
    }

    #[test]
    fn completely_fresh_state_is_an_empty_ownerless_standard_list() {
        let state = TestState::unowned();
        let list = load_committed_standard_list_with(&state.pair_store, &state.owner_store, |_| {
            panic!("fresh state must not invent or resolve an owner name")
        })
        .unwrap();

        assert_eq!(list.owner(), None);
        assert!(list.identities().is_empty());
    }

    #[test]
    fn list_revalidates_owner_and_exposes_only_labeled_identities() {
        let state = TestState::new();
        state.commit_manifest(&manifest(vec![
            IdentityMetadataEntry {
                id: id(1),
                finger: None,
            },
            IdentityMetadataEntry {
                id: id(2),
                finger: Some(FingerLabel::RightIndex),
            },
        ]));

        let list =
            load_committed_standard_list_with(&state.pair_store, &state.owner_store, |name| {
                Ok(account(name.as_str(), OWNER_UID))
            })
            .unwrap();
        assert_eq!(list.owner(), Some(&username("synthetic-owner")));
        assert_eq!(
            list.identities(),
            [Identity {
                id: id(2),
                finger: FingerLabel::RightIndex,
            }]
        );
    }

    #[test]
    fn all_unlabeled_metadata_still_returns_no_standard_owner() {
        let state = TestState::new();
        state.commit_manifest(&manifest(vec![IdentityMetadataEntry {
            id: id(1),
            finger: None,
        }]));

        let list =
            load_committed_standard_list_with(&state.pair_store, &state.owner_store, |name| {
                Ok(account(name.as_str(), OWNER_UID))
            })
            .unwrap();
        assert_eq!(list.owner(), None);
        assert!(list.identities().is_empty());
    }

    #[test]
    fn list_fails_closed_when_nss_uid_disagrees_with_recorded_owner() {
        let state = TestState::new();
        state.commit_manifest(&manifest(vec![IdentityMetadataEntry {
            id: id(2),
            finger: Some(FingerLabel::LeftThumb),
        }]));

        let result =
            load_committed_standard_list_with(&state.pair_store, &state.owner_store, |name| {
                Ok(account(name.as_str(), OWNER_UID + 1))
            });
        assert!(matches!(
            result,
            Err(StandardCatalogStoreError::OwnerMismatch)
        ));
    }

    #[test]
    fn supplied_account_is_re_resolved_and_exactly_bound_at_execution() {
        let state = TestState::new();
        state.commit_manifest(&manifest(vec![
            IdentityMetadataEntry {
                id: id(1),
                finger: None,
            },
            IdentityMetadataEntry {
                id: id(2),
                finger: Some(FingerLabel::LeftIndex),
            },
        ]));
        let admitted = account("synthetic-owner", OWNER_UID);

        let catalog = load_committed_catalog_for_account_with(
            &state.pair_store,
            &state.owner_store,
            &admitted,
            |name| Ok(account(name.as_str(), OWNER_UID)),
        )
        .unwrap();
        assert!(!catalog.contains_labeled(id(1)));
        assert!(catalog.contains_labeled(id(2)));

        let changed = load_committed_catalog_for_account_with(
            &state.pair_store,
            &state.owner_store,
            &admitted,
            |name| Ok(account(name.as_str(), OWNER_UID + 1)),
        );
        assert!(matches!(
            changed,
            Err(StandardCatalogStoreError::AccountChanged)
        ));
    }

    #[test]
    fn supplied_account_must_match_manifest_name_and_recorded_owner() {
        let state = TestState::new();
        state.commit_manifest(&manifest(vec![IdentityMetadataEntry {
            id: id(2),
            finger: Some(FingerLabel::RightThumb),
        }]));

        let wrong_name = account("synthetic-other", OWNER_UID);
        let result = load_committed_catalog_for_account_with(
            &state.pair_store,
            &state.owner_store,
            &wrong_name,
            |name| Ok(account(name.as_str(), OWNER_UID)),
        );
        assert!(matches!(
            result,
            Err(StandardCatalogStoreError::AccountMismatch)
        ));
    }

    #[test]
    fn account_bound_load_refuses_metadata_free_legacy_state() {
        let state = TestState::new();
        state.commit_legacy();
        let admitted = account("synthetic-owner", OWNER_UID);
        let result = load_committed_catalog_for_account_with(
            &state.pair_store,
            &state.owner_store,
            &admitted,
            |_| panic!("missing metadata must fail before NSS lookup"),
        );
        assert!(matches!(
            result,
            Err(StandardCatalogStoreError::MissingMetadata)
        ));
    }

    #[test]
    fn missing_committed_state_and_diagnostics_are_redacted() {
        let state = TestState::new();
        let error =
            load_committed_standard_list_with(&state.pair_store, &state.owner_store, |name| {
                Ok(account(name.as_str(), OWNER_UID))
            })
            .unwrap_err();
        assert!(matches!(
            error,
            StandardCatalogStoreError::PairStore(CatacombStoreError::MissingPair)
        ));

        let list = CommittedStandardIdentityList {
            owner: Some(username("synthetic-owner")),
            identities: vec![Identity {
                id: id(8),
                finger: FingerLabel::RightLittle,
            }],
        };
        let diagnostic = format!("{list:?} {error:?} {error}");
        assert!(!diagnostic.contains("synthetic-owner"));
        assert!(!diagnostic.contains("RightLittle"));
        assert!(!diagnostic.contains("8, 8, 8"));
        assert!(!diagnostic.contains(OWNER_UID.to_string().as_str()));
    }
}

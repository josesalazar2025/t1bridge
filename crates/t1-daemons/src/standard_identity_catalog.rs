//! Standard-facing identity labels reconciled with Mesa's live identity set.
//!
//! The catalog keeps pre-standard identities as unlabeled recovery anchors.
//! Only identities carrying an explicit standard finger label are visible to
//! standard clients.

pub mod deletion;

use std::collections::HashSet;
use std::fmt;

use crate::identity_metadata::{
    IdentityMetadata, IdentityMetadataEntry, encode as encode_metadata,
};
use crate::standard_fingerprint_protocol::{
    FingerLabel, Identity, IdentityId, MAX_IDENTITIES, MAX_OWNER_IDENTITIES, Username,
};

/// A bounded, owner-bound catalog reconciled with Mesa's complete live set.
#[derive(Clone, Eq, PartialEq)]
pub struct StandardIdentityCatalog {
    owner: Username,
    identities: Vec<IdentityMetadataEntry>,
}

impl StandardIdentityCatalog {
    /// Reconciles optional committed metadata with Mesa's complete live set.
    ///
    /// Missing metadata imports every live identity as an unlabeled legacy
    /// entry. Present metadata must name the exact owner and contain exactly
    /// the same physical identity IDs as Mesa, independent of ordering.
    ///
    /// # Errors
    ///
    /// Fails closed for an oversized or duplicate live set, a mismatched
    /// owner, or any difference between committed and live identity IDs.
    pub fn reconcile(
        manifest: Option<IdentityMetadata>,
        owner: Username,
        live_identities: &[IdentityId],
    ) -> Result<Self, CatalogError> {
        validate_live_identities(live_identities)?;

        let identities = if let Some(manifest) = manifest {
            if manifest.owner != owner {
                return Err(CatalogError::OwnerMismatch);
            }
            validate_entries(&manifest.identities)?;
            if !same_identity_set(&manifest.identities, live_identities) {
                return Err(CatalogError::IdentitySetMismatch);
            }
            manifest.identities
        } else {
            live_identities
                .iter()
                .copied()
                .map(|id| IdentityMetadataEntry { id, finger: None })
                .collect()
        };

        Ok(Self { owner, identities })
    }

    /// Returns only explicitly labeled standard identities.
    #[must_use]
    pub fn labeled_identities(&self) -> Vec<Identity> {
        self.identities
            .iter()
            .filter_map(|entry| {
                entry.finger.map(|finger| Identity {
                    id: entry.id,
                    finger,
                })
            })
            .collect()
    }

    /// Tests whether an exact physical identity has an explicit standard label.
    #[must_use]
    pub fn contains_labeled(&self, id: IdentityId) -> bool {
        self.identities
            .iter()
            .any(|entry| entry.id == id && entry.finger.is_some())
    }

    /// Adds one newly enrolled, explicitly labeled identity.
    ///
    /// Multiple templates may use the same standard finger label. Physical
    /// identity IDs remain unique.
    ///
    /// # Errors
    ///
    /// Rejects duplicate IDs and Mesa's bounded identity-set overflow.
    pub fn add_labeled(&mut self, id: IdentityId, finger: FingerLabel) -> Result<(), CatalogError> {
        if self.identities.len() >= usize::from(MAX_OWNER_IDENTITIES) {
            return Err(CatalogError::TooManyIdentities);
        }
        if self.identities.iter().any(|entry| entry.id == id) {
            return Err(CatalogError::DuplicateIdentity);
        }
        self.identities.push(IdentityMetadataEntry {
            id,
            finger: Some(finger),
        });
        Ok(())
    }

    /// Removes exactly one labeled identity while preserving every other
    /// labeled or legacy entry.
    ///
    /// # Errors
    ///
    /// Refuses absent IDs and unlabeled legacy identities alike.
    pub fn remove_labeled(&mut self, id: IdentityId) -> Result<(), CatalogError> {
        let position = self
            .identities
            .iter()
            .position(|entry| entry.id == id && entry.finger.is_some())
            .ok_or(CatalogError::IdentityNotLabeled)?;
        self.identities.remove(position);
        Ok(())
    }

    /// Encodes the complete next-generation manifest, including hidden legacy
    /// entries.
    ///
    /// # Errors
    ///
    /// Returns [`CatalogError::InvalidState`] if internal metadata validation
    /// unexpectedly fails.
    pub fn encode_next_manifest(&self) -> Result<Vec<u8>, CatalogError> {
        let manifest = IdentityMetadata::new(self.owner.clone(), self.identities.clone())
            .map_err(|_| CatalogError::InvalidState)?;
        encode_metadata(&manifest).map_err(|_| CatalogError::InvalidState)
    }
}

impl fmt::Debug for StandardIdentityCatalog {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StandardIdentityCatalog(<redacted>)")
    }
}

/// Payload-free catalog reconciliation or mutation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CatalogError {
    TooManyIdentities,
    DuplicateIdentity,
    OwnerMismatch,
    IdentitySetMismatch,
    IdentityNotLabeled,
    InvalidState,
}

impl fmt::Display for CatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TooManyIdentities => "standard identity catalog exceeds its identity bound",
            Self::DuplicateIdentity => "standard identity catalog contains a duplicate identity",
            Self::OwnerMismatch => "standard identity catalog owner does not match",
            Self::IdentitySetMismatch => "standard identity catalog does not match live identities",
            Self::IdentityNotLabeled => "standard identity is not labeled",
            Self::InvalidState => "standard identity catalog state is invalid",
        })
    }
}

impl std::error::Error for CatalogError {}

fn validate_live_identities(live_identities: &[IdentityId]) -> Result<(), CatalogError> {
    if live_identities.len() > usize::from(MAX_IDENTITIES) {
        return Err(CatalogError::TooManyIdentities);
    }
    let unique: HashSet<_> = live_identities.iter().copied().collect();
    if unique.len() != live_identities.len() {
        return Err(CatalogError::DuplicateIdentity);
    }
    Ok(())
}

fn validate_entries(entries: &[IdentityMetadataEntry]) -> Result<(), CatalogError> {
    if entries.len() > usize::from(MAX_IDENTITIES) {
        return Err(CatalogError::TooManyIdentities);
    }
    let unique: HashSet<_> = entries.iter().map(|entry| entry.id).collect();
    if unique.len() != entries.len() {
        return Err(CatalogError::DuplicateIdentity);
    }
    Ok(())
}

fn same_identity_set(entries: &[IdentityMetadataEntry], live_identities: &[IdentityId]) -> bool {
    entries.len() == live_identities.len()
        && entries
            .iter()
            .all(|entry| live_identities.contains(&entry.id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_metadata::decode as decode_metadata;

    fn owner() -> Username {
        Username::new("synthetic-owner").unwrap()
    }

    fn other_owner() -> Username {
        Username::new("synthetic-other").unwrap()
    }

    fn id(value: u8) -> IdentityId {
        IdentityId::new([value; 16]).unwrap()
    }

    fn entry(value: u8, finger: Option<FingerLabel>) -> IdentityMetadataEntry {
        IdentityMetadataEntry {
            id: id(value),
            finger,
        }
    }

    fn manifest(entries: Vec<IdentityMetadataEntry>) -> IdentityMetadata {
        IdentityMetadata::new(owner(), entries).unwrap()
    }

    #[test]
    fn missing_manifest_imports_every_live_identity_as_hidden_legacy() {
        let catalog = StandardIdentityCatalog::reconcile(None, owner(), &[id(1), id(2)]).unwrap();

        assert!(catalog.labeled_identities().is_empty());
        assert!(!catalog.contains_labeled(id(1)));
        let encoded = decode_metadata(&catalog.encode_next_manifest().unwrap()).unwrap();
        assert_eq!(encoded.owner, owner());
        assert_eq!(encoded.identities, vec![entry(1, None), entry(2, None)]);
    }

    #[test]
    fn present_manifest_requires_exact_owner_and_physical_identity_set() {
        let matching = manifest(vec![
            entry(1, None),
            entry(2, Some(FingerLabel::RightIndex)),
        ]);
        assert!(
            StandardIdentityCatalog::reconcile(Some(matching.clone()), owner(), &[id(2), id(1)])
                .is_ok()
        );
        assert_eq!(
            StandardIdentityCatalog::reconcile(
                Some(IdentityMetadata {
                    owner: other_owner(),
                    identities: matching.identities.clone(),
                }),
                owner(),
                &[id(1), id(2)],
            ),
            Err(CatalogError::OwnerMismatch)
        );
        assert_eq!(
            StandardIdentityCatalog::reconcile(Some(matching), owner(), &[id(1), id(3)]),
            Err(CatalogError::IdentitySetMismatch)
        );
    }

    #[test]
    fn listing_and_membership_expose_only_exact_labeled_entries() {
        let catalog = StandardIdentityCatalog::reconcile(
            Some(manifest(vec![
                entry(1, None),
                entry(2, Some(FingerLabel::RightIndex)),
            ])),
            owner(),
            &[id(1), id(2)],
        )
        .unwrap();
        let labeled = Identity {
            id: id(2),
            finger: FingerLabel::RightIndex,
        };

        assert_eq!(catalog.labeled_identities(), vec![labeled]);
        assert!(catalog.contains_labeled(id(2)));
        assert!(!catalog.contains_labeled(id(1)));
        assert!(!catalog.contains_labeled(id(3)));
    }

    #[test]
    fn add_and_delete_preserve_unrelated_and_unlabeled_entries() {
        let mut catalog = StandardIdentityCatalog::reconcile(
            Some(manifest(vec![
                entry(1, None),
                entry(2, Some(FingerLabel::RightIndex)),
            ])),
            owner(),
            &[id(1), id(2)],
        )
        .unwrap();

        catalog.add_labeled(id(3), FingerLabel::RightIndex).unwrap();
        catalog.remove_labeled(id(2)).unwrap();

        let encoded = decode_metadata(&catalog.encode_next_manifest().unwrap()).unwrap();
        assert_eq!(
            encoded.identities,
            vec![entry(1, None), entry(3, Some(FingerLabel::RightIndex))]
        );
    }

    #[test]
    fn unlabeled_and_absent_identities_cannot_be_removed() {
        let mut catalog = StandardIdentityCatalog::reconcile(None, owner(), &[id(1)]).unwrap();

        assert_eq!(
            catalog.remove_labeled(id(1)),
            Err(CatalogError::IdentityNotLabeled)
        );
        assert_eq!(
            catalog.remove_labeled(id(2)),
            Err(CatalogError::IdentityNotLabeled)
        );
    }

    #[test]
    fn duplicate_and_oversized_identity_sets_fail_closed() {
        assert_eq!(
            StandardIdentityCatalog::reconcile(None, owner(), &[id(1), id(1)]),
            Err(CatalogError::DuplicateIdentity)
        );
        let oversized: Vec<_> = (1..=MAX_IDENTITIES + 1).map(id).collect();
        assert_eq!(
            StandardIdentityCatalog::reconcile(None, owner(), &oversized),
            Err(CatalogError::TooManyIdentities)
        );

        let duplicate_entry = entry(1, None);
        assert_eq!(
            StandardIdentityCatalog::reconcile(
                Some(IdentityMetadata {
                    owner: owner(),
                    identities: vec![duplicate_entry, duplicate_entry],
                }),
                owner(),
                &[id(1)],
            ),
            Err(CatalogError::DuplicateIdentity)
        );
    }

    #[test]
    fn reconcile_accepts_the_full_mesa_set_above_the_owner_enrollment_limit() {
        let live: Vec<_> = (1..=MAX_IDENTITIES).map(id).collect();
        let catalog = StandardIdentityCatalog::reconcile(None, owner(), &live).unwrap();

        assert!(catalog.labeled_identities().is_empty());
        assert_eq!(
            decode_metadata(&catalog.encode_next_manifest().unwrap())
                .unwrap()
                .identities
                .len(),
            usize::from(MAX_IDENTITIES)
        );
    }

    #[test]
    fn add_rejects_duplicate_ids_and_capacity_but_allows_same_finger_templates() {
        let mut catalog = StandardIdentityCatalog::reconcile(None, owner(), &[id(1)]).unwrap();
        catalog.add_labeled(id(2), FingerLabel::LeftThumb).unwrap();
        assert_eq!(
            catalog.add_labeled(id(2), FingerLabel::RightThumb),
            Err(CatalogError::DuplicateIdentity)
        );
        catalog.add_labeled(id(3), FingerLabel::LeftThumb).unwrap();
        assert_eq!(
            catalog.add_labeled(id(4), FingerLabel::RightMiddle),
            Err(CatalogError::TooManyIdentities)
        );
    }

    #[test]
    fn diagnostics_redact_owner_and_identity_bytes() {
        let catalog = StandardIdentityCatalog::reconcile(
            Some(manifest(vec![entry(7, Some(FingerLabel::RightLittle))])),
            owner(),
            &[id(7)],
        )
        .unwrap();
        let diagnostic = format!("{catalog:?}");
        assert_eq!(diagnostic, "StandardIdentityCatalog(<redacted>)");
        assert!(!diagnostic.contains("synthetic-owner"));
        assert!(!diagnostic.contains("7, 7, 7"));

        for error in [
            CatalogError::OwnerMismatch,
            CatalogError::IdentitySetMismatch,
            CatalogError::IdentityNotLabeled,
        ] {
            let diagnostic = format!("{error:?}: {error}");
            assert!(!diagnostic.contains("synthetic-owner"));
            assert!(!diagnostic.contains("070707"));
        }
    }
}

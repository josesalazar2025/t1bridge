//! Authentication, xART storage, and Touch ID state daemons.

pub mod auth_client;
#[cfg(feature = "auth-broker-service")]
pub mod auth_daemon;
pub mod auth_feedback;
pub mod auth_lifecycle;
pub mod auth_operation;
pub mod auth_protocol;
pub mod auth_scheduler;
pub mod auth_session;
pub mod auth_socket;
pub mod catacomb_restore;
pub mod catacomb_session;
pub mod catacomb_store;
pub mod enrollment_lifecycle;
pub mod enrollment_owner;
mod enrollment_transaction;
pub mod identity_lifecycle;
pub mod identity_metadata;
pub mod keybag_relay;
#[cfg(feature = "keybag-relay-service")]
pub mod keybag_relay_daemon;
#[cfg(feature = "auth-broker-service")]
pub mod live_authentication;
pub mod live_enrollment;
#[cfg(feature = "legacy-recovery")]
pub mod live_legacy_recovery;
#[cfg(feature = "auth-broker-service")]
pub mod live_standard_fingerprint;
#[cfg(feature = "auth-broker-service")]
pub mod live_worker;
pub mod machine_data;
pub mod nss_account;
#[allow(unsafe_code)]
mod nss_account_ffi;
pub mod overlay;
pub mod pam_client;
pub mod request_ids;
pub mod sep_lifecycle;
pub mod service_lifecycle;
#[allow(unsafe_code)]
mod service_lifecycle_ffi;
pub mod standard_catalog_store;
pub mod standard_connection;
pub mod standard_fingerprint_protocol;
pub mod standard_identity_catalog;
pub mod standard_operation_authority;
pub mod standard_query_policy;
pub mod standard_smoke;
#[cfg(feature = "auth-broker-service")]
pub mod standard_socket;
pub mod xart_daemon;
pub mod xart_live;
#[allow(unsafe_code)]
mod xart_live_ffi;
pub mod xart_protocol;
pub mod xart_service;
pub mod xart_session;
pub mod xart_store;

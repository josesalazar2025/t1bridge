#ifndef T1BRIDGE_SEP_KEYBAG_H
#define T1BRIDGE_SEP_KEYBAG_H

#include "sep_operation.h"

#include <stddef.h>
#include <stdint.h>

#define SEP_KEYBAG_STATE_DIRECTORY "/var/lib/t1bridge/touch-id"
#define SEP_KEYBAG_STATE_FILENAME "keybag.state"
#define SEP_KEYBAG_MAX_SERIALIZED_SIZE 0x8000U
#define SEP_KEYBAG_BIOMETRIC_HANDLE (-501)
#define SEP_KEYBAG_RELAY_MAX_POLL_MS 1000U

enum sep_keybag_mode {
	/* Existing state is required and already promoted by relay handoff. */
	SEP_KEYBAG_EXISTING_ONLY = 0,
	/* Startup may create absent state but must never replay existing state. */
	SEP_KEYBAG_CREATE_IF_ABSENT = 1,
};

enum sep_keybag_disposition {
	SEP_KEYBAG_REUSED = 0,
	SEP_KEYBAG_CREATED = 1,
};

enum sep_keybag_authorization {
	SEP_KEYBAG_AUTHENTICATION = 0,
	SEP_KEYBAG_ENROLLMENT = 1,
};

enum sep_keybag_store_result {
	SEP_KEYBAG_STORE_EXISTING = 0,
	SEP_KEYBAG_STORE_ABSENT = 1,
	SEP_KEYBAG_STORE_ERROR = -1,
};

struct sep_keybag_material {
	uint8_t secret[SEP_KEYSTORE_SECRET_SIZE];
	uint8_t blob[SEP_KEYBAG_MAX_SERIALIZED_SIZE];
	size_t blob_length;
};

struct sep_keybag_store_ops {
	void *context;
	int (*load)(void *context, struct sep_keybag_material *material);
	int (*persist_absent)(void *context,
			      const struct sep_keybag_material *material);
};

typedef int (*sep_keybag_credential_callback)(
	void *context, enum sep_keybag_disposition disposition,
	const uint8_t credential[SEP_ACM_EXTERNAL_FORM_SIZE],
	size_t credential_length);
typedef int (*sep_keybag_ready_callback)(void *context);
typedef int (*sep_keybag_prepare_callback)(void *context);
typedef void (*sep_keybag_prepared_cleanup)(void *context);

enum sep_operation_result sep_keybag_run(
	enum sep_keybag_mode mode, enum sep_keybag_authorization authorization,
	unsigned int timeout_ms,
	sep_operation_cancelled cancelled, void *cancellation_context,
	sep_keybag_credential_callback callback, void *callback_context);

enum sep_operation_result sep_keybag_run_with_ops(
	const struct sep_operation_ops *operation_ops,
	const struct sep_keybag_store_ops *store_ops,
	enum sep_keybag_mode mode, enum sep_keybag_authorization authorization,
	unsigned int timeout_ms,
	sep_operation_cancelled cancelled, void *cancellation_context,
	sep_keybag_credential_callback callback, void *callback_context);

enum sep_operation_result sep_keybag_run_prepared(
	enum sep_keybag_mode mode, enum sep_keybag_authorization authorization,
	unsigned int timeout_ms,
	sep_operation_cancelled cancelled, void *cancellation_context,
	sep_keybag_prepare_callback prepare, void *prepare_context,
	sep_keybag_credential_callback callback, void *callback_context,
	sep_keybag_prepared_cleanup cleanup, void *cleanup_context);

enum sep_operation_result sep_keybag_run_prepared_with_ops(
	const struct sep_operation_ops *operation_ops,
	const struct sep_keybag_store_ops *store_ops,
	enum sep_keybag_mode mode, enum sep_keybag_authorization authorization,
	unsigned int timeout_ms,
	sep_operation_cancelled cancelled, void *cancellation_context,
	sep_keybag_prepare_callback prepare, void *prepare_context,
	sep_keybag_credential_callback callback, void *callback_context,
	sep_keybag_prepared_cleanup cleanup, void *cleanup_context);

/* Existing-only shared owner for idle BridgeOS keybag notifications. */
enum sep_operation_result sep_keybag_run_notification_relay(
	unsigned int acquisition_timeout_ms, unsigned int poll_timeout_ms,
	sep_operation_cancelled cancelled, void *cancellation_context,
	sep_keybag_ready_callback ready, void *ready_context);

enum sep_operation_result sep_keybag_run_notification_relay_with_ops(
	const struct sep_operation_ops *operation_ops,
	const struct sep_keybag_store_ops *store_ops,
	unsigned int acquisition_timeout_ms, unsigned int poll_timeout_ms,
	sep_operation_cancelled cancelled, void *cancellation_context,
	sep_keybag_ready_callback ready, void *ready_context);

/* Testable storage core; production always supplies root as expected_owner. */
int sep_keybag_state_load_at(int directory_descriptor,
			     uint32_t expected_owner,
			     struct sep_keybag_material *material);
int sep_keybag_state_persist_absent_at(
	int directory_descriptor, uint32_t expected_owner,
	const struct sep_keybag_material *material);

#endif

#ifndef SEP_KEYSTORE_H
#define SEP_KEYSTORE_H

#include "sep_relay.h"

#include <stddef.h>
#include <stdint.h>

#define SEP_KEYSTORE_IPC_HEADER_SIZE 0x50U
#define SEP_KEYSTORE_IPC_WIRE_HEADER_SIZE 0x54U
#define SEP_KEYSTORE_SECRET_SIZE 32U
#define SEP_KEYSTORE_EXTERNAL_FORM_SIZE 16U
#define SEP_KEYSTORE_UUID_SIZE 16U
#define SEP_KEYSTORE_ENVIRONMENT_SIZE 0x40cU

#define SEP_KEYSTORE_SELECTOR_CREATE UINT8_C(0x01)
#define SEP_KEYSTORE_SELECTOR_SERIALIZE UINT8_C(0x02)
#define SEP_KEYSTORE_SELECTOR_LOAD UINT8_C(0x03)
#define SEP_KEYSTORE_SELECTOR_LOCK_STATE UINT8_C(0x04)
#define SEP_KEYSTORE_SELECTOR_COPY_UUID UINT8_C(0x06)
#define SEP_KEYSTORE_SELECTOR_MAKE_SYSTEM UINT8_C(0x0d)
#define SEP_KEYSTORE_SELECTOR_UNLOCK UINT8_C(0x18)
#define SEP_KEYSTORE_SELECTOR_DEVICE_STATE UINT8_C(0x19)
#define SEP_KEYSTORE_SELECTOR_VERIFY_SECRET UINT8_C(0x21)
#define SEP_KEYSTORE_SELECTOR_GET_CONFIGURATION UINT8_C(0x23)
#define SEP_KEYSTORE_SELECTOR_SET_CONFIGURATION UINT8_C(0x24)
#define SEP_KEYSTORE_SELECTOR_SET_ENVIRONMENT UINT8_C(0x2a)
#define SEP_KEYSTORE_SELECTOR_CAPABILITIES UINT8_C(0x4d)

enum sep_keystore_result {
	SEP_KEYSTORE_OK = 0,
	SEP_KEYSTORE_REMOTE_ERROR = 1,
	SEP_KEYSTORE_ERROR_ARGUMENT = -1,
	SEP_KEYSTORE_ERROR_CAPACITY = -2,
	SEP_KEYSTORE_ERROR_LENGTH = -3,
	SEP_KEYSTORE_ERROR_HEADER = -4,
	SEP_KEYSTORE_ERROR_HASH = -5,
	SEP_KEYSTORE_ERROR_SELECTOR = -6,
	SEP_KEYSTORE_ERROR_TRANSACTION = -7,
	SEP_KEYSTORE_ERROR_STATE = -8,
	SEP_KEYSTORE_ERROR_EXHAUSTED = -9,
	SEP_KEYSTORE_ERROR_RELAY = -10,
};

enum sep_keystore_operation_kind {
	SEP_KEYSTORE_OPERATION_CAPABILITIES,
	SEP_KEYSTORE_OPERATION_CREATE,
	SEP_KEYSTORE_OPERATION_SERIALIZE,
	SEP_KEYSTORE_OPERATION_LOAD,
	SEP_KEYSTORE_OPERATION_LOCK_STATE,
	SEP_KEYSTORE_OPERATION_COPY_UUID,
	SEP_KEYSTORE_OPERATION_MAKE_SYSTEM,
	SEP_KEYSTORE_OPERATION_UNLOCK,
	SEP_KEYSTORE_OPERATION_DEVICE_STATE,
	SEP_KEYSTORE_OPERATION_VERIFY_SECRET,
	SEP_KEYSTORE_OPERATION_GET_CONFIGURATION,
	SEP_KEYSTORE_OPERATION_SET_CONFIGURATION,
	SEP_KEYSTORE_OPERATION_SET_ENVIRONMENT,
};

enum sep_keystore_reply_kind {
	SEP_KEYSTORE_REPLY_NONE,
	SEP_KEYSTORE_REPLY_VALUE,
	SEP_KEYSTORE_REPLY_VALUE_AND_FLAGS,
	SEP_KEYSTORE_REPLY_STATE_PAIR,
	SEP_KEYSTORE_REPLY_OPAQUE,
};

struct sep_keystore_state {
	uint64_t client_context;
	uint64_t last_timestamp_us;
	uint8_t next_transaction;
	uint8_t has_timestamp;
	uint8_t transaction_exhausted;
};

struct sep_keystore_operation {
	enum sep_keystore_operation_kind kind;
	size_t request_length;
	uint8_t selector;
	uint8_t transaction;
};

struct sep_keystore_reply {
	enum sep_keystore_reply_kind kind;
	const uint8_t *opaque;
	size_t opaque_length;
	uint64_t first_wide_value;
	uint64_t second_wide_value;
	uint32_t value;
	int32_t inner_result;
	int8_t outer_result;
};

/* client_context is an opaque session value, never a userspace pointer. */
int sep_keystore_state_init(struct sep_keystore_state *state,
			    uint64_t client_context,
			    uint8_t first_transaction);

int sep_keystore_seal(void *request, size_t request_length,
		      uint64_t timestamp_us);
int sep_keystore_verify_seal(const void *request, size_t request_length);

int sep_keystore_build_capabilities(
	struct sep_keystore_state *state, uint64_t timestamp_us, void *output,
	size_t output_capacity, struct sep_keystore_operation *operation);
int sep_keystore_build_create(
	struct sep_keystore_state *state, uint64_t timestamp_us,
	const uint8_t secret[SEP_KEYSTORE_SECRET_SIZE], void *output,
	size_t output_capacity, struct sep_keystore_operation *operation);
int sep_keystore_build_serialize(
	struct sep_keystore_state *state, uint64_t timestamp_us,
	int32_t keybag_handle, void *output, size_t output_capacity,
	struct sep_keystore_operation *operation);
int sep_keystore_build_load(
	struct sep_keystore_state *state, uint64_t timestamp_us,
	const void *serialized_keybag, size_t serialized_keybag_length,
	void *output, size_t output_capacity,
	struct sep_keystore_operation *operation);
/* Selector 4 with state UINT32_MAX is a read-only lock-state query. */
int sep_keystore_build_lock_state(
	struct sep_keystore_state *state, uint64_t timestamp_us,
	int32_t keybag_handle, void *output, size_t output_capacity,
	struct sep_keystore_operation *operation);
int sep_keystore_build_copy_uuid(
	struct sep_keystore_state *state, uint64_t timestamp_us,
	int32_t keybag_handle, void *output, size_t output_capacity,
	struct sep_keystore_operation *operation);
int sep_keystore_build_make_system(
	struct sep_keystore_state *state, uint64_t timestamp_us,
	uint32_t source_handle, int32_t target_handle,
	const uint8_t *secret, size_t secret_length, void *output,
	size_t output_capacity, struct sep_keystore_operation *operation);
int sep_keystore_build_unlock(
	struct sep_keystore_state *state, uint64_t timestamp_us,
	int32_t keybag_handle,
	const uint8_t secret[SEP_KEYSTORE_SECRET_SIZE], void *output,
	size_t output_capacity, struct sep_keystore_operation *operation);
int sep_keystore_build_device_state(
	struct sep_keystore_state *state, uint64_t timestamp_us,
	int32_t keybag_handle, void *output, size_t output_capacity,
	struct sep_keystore_operation *operation);
int sep_keystore_build_verify_secret(
	struct sep_keystore_state *state, uint64_t timestamp_us,
	int32_t keybag_handle,
	const uint8_t secret[SEP_KEYSTORE_SECRET_SIZE],
	const uint8_t *external_form, size_t external_form_length, void *output,
	size_t output_capacity, struct sep_keystore_operation *operation);
int sep_keystore_build_get_configuration(
	struct sep_keystore_state *state, uint64_t timestamp_us,
	int32_t keybag_handle, void *output, size_t output_capacity,
	struct sep_keystore_operation *operation);
int sep_keystore_build_set_configuration(
	struct sep_keystore_state *state, uint64_t timestamp_us,
	int32_t keybag_handle, uint32_t flags, const void *configuration,
	size_t configuration_length, void *output, size_t output_capacity,
	struct sep_keystore_operation *operation);
int sep_keystore_build_set_environment(
	struct sep_keystore_state *state, uint64_t timestamp_us, void *output,
	size_t output_capacity, struct sep_keystore_operation *operation);

int sep_keystore_wrap_request(
	struct sep_relay_state *relay_state,
	const struct sep_keystore_operation *operation, const void *request,
	size_t request_length,
	uint8_t output[SEP_RELAY_BUFFER_SIZE],
	struct sep_relay_pending *pending);

int sep_keystore_parse_reply(
	const struct sep_relay_message *message,
	const struct sep_relay_pending *pending,
	const struct sep_keystore_operation *operation,
	struct sep_keystore_reply *reply);

/* Clear successful request, relay, secret, and opaque reply buffers after use. */
void sep_keystore_clear(void *data, size_t length);

#endif

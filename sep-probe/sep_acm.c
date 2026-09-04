#include "sep_acm.h"

#include "sep_crypto.h"

#include <limits.h>
#include <string.h>

#define ACM_MAGIC UINT32_C(0x53435244)
#define ACM_PROTOCOL_VERSION UINT8_C(1)
#define ACM_DEFAULT_LOG_LEVEL UINT8_C(0x28)
#define ACM_RELAY_HEADER_SIZE 10U
#define ACM_CONTEXT_CREATE UINT8_C(0x01)
#define ACM_CONTEXT_DELETE UINT8_C(0x02)
#define ACM_CONTEXT_VERIFY_POLICY UINT8_C(0x03)
#define ACM_CONTEXT_CONTAINS_CREDENTIAL UINT8_C(0x04)
#define ACM_INITIALIZE UINT8_C(0x0a)
#define ACM_CONTEXT_REPLACE_PASSPHRASE UINT8_C(0x0f)
#define ACM_CONTEXT_GET_EXTERNAL_FORM UINT8_C(0x13)
#define ACM_CREDENTIAL_HEADER_SIZE 0x20U
#define ACM_PASSPHRASE_DATA_SIZE 0x88U
#define ACM_PASSPHRASE_CREDENTIAL_SIZE 0xa8U
#define ACM_REPLACE_PAYLOAD_SIZE 0xbcU
#define ACM_VERIFY_UNBOUND_PAYLOAD_SIZE 0x2bU
#define ACM_VERIFY_BOUND_PAYLOAD_SIZE 0x43U
#define ACM_KEYBAG_UUID_SIZE 16U
#define ACM_CONTEXT_SCOPE UINT32_C(1)

static const uint8_t enrollment_policy[] = "TouchIdEnrollment";

_Static_assert(ACM_CREDENTIAL_HEADER_SIZE + ACM_PASSPHRASE_DATA_SIZE ==
		       ACM_PASSPHRASE_CREDENTIAL_SIZE,
	       "ACM passphrase credential size changed");
_Static_assert(SEP_ACM_EXTERNAL_FORM_SIZE +
		       ACM_PASSPHRASE_CREDENTIAL_SIZE + sizeof(uint32_t) ==
		       ACM_REPLACE_PAYLOAD_SIZE,
	       "ACM replace-passphrase payload size changed");
_Static_assert(sizeof(enrollment_policy) == 18,
	       "ACM enrollment policy wire size changed");
_Static_assert(SEP_ACM_EXTERNAL_FORM_SIZE + sizeof(enrollment_policy) + 1 +
		       2 * sizeof(uint32_t) ==
		       ACM_VERIFY_UNBOUND_PAYLOAD_SIZE,
	       "ACM unbound policy payload size changed");
_Static_assert(ACM_VERIFY_UNBOUND_PAYLOAD_SIZE + 2 * sizeof(uint32_t) +
		       ACM_KEYBAG_UUID_SIZE == ACM_VERIFY_BOUND_PAYLOAD_SIZE,
	       "ACM bound policy payload size changed");

static uint32_t load_u32_le(const uint8_t *input)
{
	return (uint32_t)input[0] | (uint32_t)input[1] << 8 |
	       (uint32_t)input[2] << 16 | (uint32_t)input[3] << 24;
}

static int32_t load_i32_le(const uint8_t *input)
{
	uint32_t value = load_u32_le(input);

	if (value <= INT32_MAX)
		return (int32_t)value;
	return -1 - (int32_t)(UINT32_MAX - value);
}

static void store_u32_le(uint8_t *output, uint32_t value)
{
	output[0] = (uint8_t)value;
	output[1] = (uint8_t)(value >> 8);
	output[2] = (uint8_t)(value >> 16);
	output[3] = (uint8_t)(value >> 24);
}

static void build_command(uint8_t *command, uint8_t selector,
			  uint8_t parameter, const void *payload,
			  size_t payload_length)
{
	store_u32_le(command, ACM_MAGIC);
	command[4] = selector;
	command[5] = parameter;
	command[6] = 0;
	command[7] = selector == ACM_INITIALIZE ? 0 : ACM_PROTOCOL_VERSION;
	if (payload_length != 0)
		memcpy(command + SEP_ACM_COMMAND_HEADER_SIZE, payload,
		       payload_length);
}

static int begin_command(struct sep_acm_state *state,
			 struct sep_relay_state *relay,
			 enum sep_acm_operation operation, uint8_t *command,
			 size_t command_length,
			 uint8_t output[SEP_RELAY_BUFFER_SIZE])
{
	struct sep_relay_pending pending;
	int result;

	if (!state || !relay || !command || !output)
		return SEP_ACM_ERROR_ARGUMENT;
	if (state->pending_valid || state->phase == SEP_ACM_PHASE_FAILED)
		return SEP_ACM_ERROR_STATE;
	result = sep_relay_build_acm_request(relay, command, command_length,
					   SEP_ACM_RELAY_REQUEST, output,
					   &pending);
	sep_crypto_wipe(command, command_length);
	if (result != SEP_RELAY_OK)
		return SEP_ACM_ERROR_RELAY;
	state->pending = pending;
	state->pending_operation = operation;
	state->pending_valid = 1;
	return SEP_ACM_OK;
}

static int require_active(const struct sep_acm_state *state,
			  int require_externalized)
{
	if (!state || state->phase != SEP_ACM_PHASE_ACTIVE ||
	    state->pending_valid)
		return SEP_ACM_ERROR_STATE;
	if (require_externalized && !state->context_externalized)
		return SEP_ACM_ERROR_STATE;
	return SEP_ACM_OK;
}

int sep_acm_state_init(struct sep_acm_state *state)
{
	if (!state)
		return SEP_ACM_ERROR_ARGUMENT;
	sep_crypto_wipe(state, sizeof(*state));
	state->phase = SEP_ACM_PHASE_NEW;
	return SEP_ACM_OK;
}

void sep_acm_state_wipe(struct sep_acm_state *state)
{
	if (state) {
		sep_crypto_wipe(state, sizeof(*state));
		state->phase = SEP_ACM_PHASE_FAILED;
	}
}

static void fail_state(struct sep_acm_state *state)
{
	sep_crypto_wipe(&state->pending, sizeof(state->pending));
	sep_acm_external_form_wipe(&state->context);
	state->pending_operation = SEP_ACM_OPERATION_NONE;
	state->log_level = 0;
	state->context_externalized = 0;
	state->pending_valid = 0;
	state->phase = SEP_ACM_PHASE_FAILED;
}

int sep_acm_mark_ambiguous(struct sep_acm_state *state)
{
	if (!state || !state->pending_valid)
		return SEP_ACM_ERROR_STATE;
	fail_state(state);
	return SEP_ACM_ERROR_AMBIGUOUS;
}

int sep_acm_external_form_import(struct sep_acm_external_form *form,
				 const void *input, size_t input_length)
{
	if (!form || !input || input_length != sizeof(form->bytes))
		return SEP_ACM_ERROR_ARGUMENT;
	memmove(form->bytes, input, sizeof(form->bytes));
	return SEP_ACM_OK;
}

int sep_acm_external_form_export(const struct sep_acm_external_form *form,
				 void *output, size_t output_length)
{
	if (!form || !output || output_length != sizeof(form->bytes))
		return SEP_ACM_ERROR_ARGUMENT;
	memmove(output, form->bytes, sizeof(form->bytes));
	return SEP_ACM_OK;
}

void sep_acm_external_form_wipe(struct sep_acm_external_form *form)
{
	if (form)
		sep_crypto_wipe(form, sizeof(*form));
}

int sep_acm_export_active_context(const struct sep_acm_state *state,
				  struct sep_acm_external_form *form)
{
	if (!state || !form || state->phase != SEP_ACM_PHASE_ACTIVE ||
	    state->pending_valid || !state->context_externalized)
		return SEP_ACM_ERROR_STATE;
	*form = state->context;
	return SEP_ACM_OK;
}

int sep_acm_build_initialize(struct sep_acm_state *state,
			     struct sep_relay_state *relay,
			     uint8_t output[SEP_RELAY_BUFFER_SIZE])
{
	uint8_t command[SEP_ACM_COMMAND_HEADER_SIZE] = { 0 };

	if (!state || state->phase != SEP_ACM_PHASE_NEW || state->pending_valid)
		return SEP_ACM_ERROR_STATE;
	build_command(command, ACM_INITIALIZE, ACM_DEFAULT_LOG_LEVEL, NULL, 0);
	return begin_command(state, relay, SEP_ACM_OPERATION_INITIALIZE, command,
			     sizeof(command), output);
}

int sep_acm_build_context_create(struct sep_acm_state *state,
				 struct sep_relay_state *relay,
				 uint32_t audit_uid,
				 uint8_t output[SEP_RELAY_BUFFER_SIZE])
{
	uint8_t command[SEP_ACM_COMMAND_HEADER_SIZE + sizeof(audit_uid)] = { 0 };

	if (!state || state->phase != SEP_ACM_PHASE_READY ||
	    state->pending_valid)
		return SEP_ACM_ERROR_STATE;
	build_command(command, ACM_CONTEXT_CREATE, 0, NULL, 0);
	store_u32_le(command + SEP_ACM_COMMAND_HEADER_SIZE, audit_uid);
	return begin_command(state, relay, SEP_ACM_OPERATION_CONTEXT_CREATE,
			     command, sizeof(command), output);
}

int sep_acm_build_context_delete(struct sep_acm_state *state,
				 struct sep_relay_state *relay,
				 uint8_t output[SEP_RELAY_BUFFER_SIZE])
{
	uint8_t command[SEP_ACM_COMMAND_HEADER_SIZE +
			SEP_ACM_EXTERNAL_FORM_SIZE] = { 0 };

	if (require_active(state, 0) != SEP_ACM_OK)
		return SEP_ACM_ERROR_STATE;
	build_command(command, ACM_CONTEXT_DELETE, 0, state->context.bytes,
		      sizeof(state->context.bytes));
	return begin_command(state, relay, SEP_ACM_OPERATION_CONTEXT_DELETE,
			     command, sizeof(command), output);
}

int sep_acm_build_context_externalize(
	struct sep_acm_state *state, struct sep_relay_state *relay,
	uint8_t output[SEP_RELAY_BUFFER_SIZE])
{
	uint8_t command[SEP_ACM_COMMAND_HEADER_SIZE +
			SEP_ACM_EXTERNAL_FORM_SIZE] = { 0 };

	if (require_active(state, 0) != SEP_ACM_OK ||
	    state->context_externalized)
		return SEP_ACM_ERROR_STATE;
	build_command(command, ACM_CONTEXT_GET_EXTERNAL_FORM, 0,
		      state->context.bytes, sizeof(state->context.bytes));
	return begin_command(state, relay, SEP_ACM_OPERATION_CONTEXT_EXTERNALIZE,
			     command, sizeof(command), output);
}

int sep_acm_build_contains_credential(
	struct sep_acm_state *state, struct sep_relay_state *relay,
	uint32_t credential_type, uint32_t credential_scope,
	uint8_t output[SEP_RELAY_BUFFER_SIZE])
{
	uint8_t payload[SEP_ACM_EXTERNAL_FORM_SIZE + 2 * sizeof(uint32_t)] = { 0 };
	uint8_t command[SEP_ACM_COMMAND_HEADER_SIZE + sizeof(payload)] = { 0 };
	int result;

	result = require_active(state, 1);
	if (result != SEP_ACM_OK)
		return result;
	if ((credential_type != 1 && credential_type != 2) ||
	    credential_scope != 0)
		return SEP_ACM_ERROR_ARGUMENT;
	memcpy(payload, state->context.bytes, sizeof(state->context.bytes));
	store_u32_le(payload + SEP_ACM_EXTERNAL_FORM_SIZE, credential_type);
	store_u32_le(payload + SEP_ACM_EXTERNAL_FORM_SIZE + sizeof(uint32_t),
		     credential_scope);
	build_command(command, ACM_CONTEXT_CONTAINS_CREDENTIAL, 0, payload,
		      sizeof(payload));
	result = begin_command(state, relay,
			       SEP_ACM_OPERATION_CONTAINS_CREDENTIAL, command,
			       sizeof(command), output);
	sep_crypto_wipe(payload, sizeof(payload));
	return result;
}

int sep_acm_build_replace_passphrase(
	struct sep_acm_state *state, struct sep_relay_state *relay,
	const void *secret, size_t secret_length, uint32_t credential_scope,
	uint8_t output[SEP_RELAY_BUFFER_SIZE])
{
	uint8_t payload[ACM_REPLACE_PAYLOAD_SIZE] = { 0 };
	uint8_t command[SEP_ACM_COMMAND_HEADER_SIZE + sizeof(payload)] = { 0 };
	uint8_t *credential = payload + SEP_ACM_EXTERNAL_FORM_SIZE;
	int result;

	result = require_active(state, 1);
	if (result != SEP_ACM_OK)
		return result;
	if (!secret || secret_length == 0 ||
	    secret_length > SEP_ACM_PASSPHRASE_MAX_SIZE ||
	    credential_scope != ACM_CONTEXT_SCOPE)
		return SEP_ACM_ERROR_ARGUMENT;
	memcpy(payload, state->context.bytes, sizeof(state->context.bytes));
	store_u32_le(credential, 2);
	store_u32_le(credential + 4, 1);
	store_u32_le(credential + 0x0c, UINT32_MAX);
	store_u32_le(credential + 0x1c, ACM_PASSPHRASE_DATA_SIZE);
	store_u32_le(credential + ACM_CREDENTIAL_HEADER_SIZE, 0);
	store_u32_le(credential + ACM_CREDENTIAL_HEADER_SIZE + sizeof(uint32_t),
		     (uint32_t)secret_length);
	memcpy(credential + ACM_CREDENTIAL_HEADER_SIZE + 2 * sizeof(uint32_t),
	       secret, secret_length);
	store_u32_le(payload + SEP_ACM_EXTERNAL_FORM_SIZE +
			     ACM_PASSPHRASE_CREDENTIAL_SIZE,
		     credential_scope);
	build_command(command, ACM_CONTEXT_REPLACE_PASSPHRASE, 0, payload,
		      sizeof(payload));
	result = begin_command(state, relay, SEP_ACM_OPERATION_REPLACE_PASSPHRASE,
			       command, sizeof(command), output);
	sep_crypto_wipe(payload, sizeof(payload));
	return result;
}

int sep_acm_build_verify_enrollment(
	struct sep_acm_state *state, struct sep_relay_state *relay, int preflight,
	const void *keybag_uuid, size_t keybag_uuid_length,
	uint8_t output[SEP_RELAY_BUFFER_SIZE])
{
	uint8_t payload[ACM_VERIFY_BOUND_PAYLOAD_SIZE] = { 0 };
	uint8_t command[SEP_ACM_COMMAND_HEADER_SIZE + sizeof(payload)] = { 0 };
	size_t preflight_offset = SEP_ACM_EXTERNAL_FORM_SIZE +
				   sizeof(enrollment_policy);
	size_t count_offset = preflight_offset + 1 + sizeof(uint32_t);
	size_t payload_length = ACM_VERIFY_UNBOUND_PAYLOAD_SIZE;
	int result;

	result = require_active(state, 1);
	if (result != SEP_ACM_OK)
		return result;
	if (preflight != 0 && preflight != 1)
		return SEP_ACM_ERROR_ARGUMENT;
	if ((keybag_uuid &&
	     (keybag_uuid_length != ACM_KEYBAG_UUID_SIZE || preflight != 0)) ||
	    (!keybag_uuid && (keybag_uuid_length != 0 || preflight != 1)))
		return SEP_ACM_ERROR_ARGUMENT;
	memcpy(payload, state->context.bytes, sizeof(state->context.bytes));
	memcpy(payload + SEP_ACM_EXTERNAL_FORM_SIZE, enrollment_policy,
	       sizeof(enrollment_policy));
	payload[preflight_offset] = (uint8_t)preflight;
	if (keybag_uuid) {
		size_t parameter_offset = ACM_VERIFY_UNBOUND_PAYLOAD_SIZE;

		store_u32_le(payload + count_offset, 1);
		store_u32_le(payload + parameter_offset, 2);
		store_u32_le(payload + parameter_offset + sizeof(uint32_t),
			     ACM_KEYBAG_UUID_SIZE);
		memcpy(payload + parameter_offset + 2 * sizeof(uint32_t),
		       keybag_uuid, ACM_KEYBAG_UUID_SIZE);
		payload_length = sizeof(payload);
	}
	build_command(command, ACM_CONTEXT_VERIFY_POLICY, 0, payload,
		      payload_length);
	result = begin_command(state, relay, SEP_ACM_OPERATION_VERIFY_ENROLLMENT,
			       command, SEP_ACM_COMMAND_HEADER_SIZE + payload_length,
			       output);
	sep_crypto_wipe(payload, sizeof(payload));
	sep_crypto_wipe(command, sizeof(command));
	return result;
}

static int expected_payload(const struct sep_acm_state *state,
			    const uint8_t *payload, size_t payload_length,
			    struct sep_acm_outcome *outcome)
{
	uint32_t value;

	switch (state->pending_operation) {
	case SEP_ACM_OPERATION_INITIALIZE:
	case SEP_ACM_OPERATION_CONTEXT_DELETE:
	case SEP_ACM_OPERATION_CONTEXT_EXTERNALIZE:
	case SEP_ACM_OPERATION_REPLACE_PASSPHRASE:
		return payload_length == 0 ? SEP_ACM_OK : SEP_ACM_ERROR_REPLY;
	case SEP_ACM_OPERATION_CONTEXT_CREATE:
		if (payload_length != SEP_ACM_CONTEXT_CREATE_REPLY_SIZE)
			return SEP_ACM_ERROR_REPLY;
		return SEP_ACM_OK;
	case SEP_ACM_OPERATION_CONTAINS_CREDENTIAL:
		if (payload_length != sizeof(uint32_t))
			return SEP_ACM_ERROR_REPLY;
		value = load_u32_le(payload);
		if (value > 1)
			return SEP_ACM_ERROR_REPLY;
		outcome->boolean_valid = 1;
		outcome->boolean_value = (uint8_t)value;
		return SEP_ACM_OK;
	case SEP_ACM_OPERATION_VERIFY_ENROLLMENT:
		if (payload_length < sizeof(uint32_t) ||
		    payload_length > SEP_ACM_VERIFY_REPLY_CAPACITY)
			return SEP_ACM_ERROR_REPLY;
		value = load_u32_le(payload);
		if (value > 1)
			return SEP_ACM_ERROR_REPLY;
		outcome->boolean_valid = 1;
		outcome->boolean_value = (uint8_t)value;
		return SEP_ACM_OK;
	case SEP_ACM_OPERATION_NONE:
	default:
		return SEP_ACM_ERROR_STATE;
	}
}

static void clear_pending(struct sep_acm_state *state)
{
	memset(&state->pending, 0, sizeof(state->pending));
	state->pending_valid = 0;
	state->pending_operation = SEP_ACM_OPERATION_NONE;
}

static void accept_success(struct sep_acm_state *state,
			   enum sep_acm_operation operation,
			   const uint8_t *payload,
			   struct sep_acm_outcome *outcome)
{
	switch (operation) {
	case SEP_ACM_OPERATION_INITIALIZE:
		state->phase = SEP_ACM_PHASE_READY;
		break;
	case SEP_ACM_OPERATION_CONTEXT_CREATE:
		memcpy(state->context.bytes, payload, sizeof(state->context.bytes));
		state->log_level = payload[SEP_ACM_EXTERNAL_FORM_SIZE];
		state->context_externalized = 0;
		state->phase = SEP_ACM_PHASE_ACTIVE;
		outcome->log_level_valid = 1;
		outcome->log_level = state->log_level;
		break;
	case SEP_ACM_OPERATION_CONTEXT_DELETE:
		sep_acm_external_form_wipe(&state->context);
		state->context_externalized = 0;
		state->log_level = 0;
		state->phase = SEP_ACM_PHASE_READY;
		break;
	case SEP_ACM_OPERATION_CONTEXT_EXTERNALIZE:
		state->context_externalized = 1;
		break;
	case SEP_ACM_OPERATION_CONTAINS_CREDENTIAL:
	case SEP_ACM_OPERATION_REPLACE_PASSPHRASE:
	case SEP_ACM_OPERATION_VERIFY_ENROLLMENT:
	case SEP_ACM_OPERATION_NONE:
		break;
	}
}

int sep_acm_accept_reply(struct sep_acm_state *state,
			 const struct sep_relay_message *message,
			 struct sep_acm_outcome *outcome)
{
	const uint8_t *payload;
	uint32_t declared_length;
	int32_t remote_result;
	enum sep_acm_operation operation;
	int result;

	if (!state || !message || !outcome || !state->pending_valid ||
	    !message->message || !message->data)
		return SEP_ACM_ERROR_ARGUMENT;
	memset(outcome, 0, sizeof(*outcome));
	operation = state->pending_operation;
	outcome->operation = operation;
	result = sep_relay_matches(message, &state->pending);
	if (result != SEP_RELAY_MATCHED)
		return SEP_ACM_ERROR_RELAY;
	/* Relay response byte 8 has no proven invariant, so do not guess one. */
	if (message->message_length != ACM_RELAY_HEADER_SIZE) {
		fail_state(state);
		return SEP_ACM_ERROR_REPLY;
	}
	declared_length = load_u32_le(message->message + 10);
	remote_result = load_i32_le(message->message + 14);
	outcome->remote_result = remote_result;
	if (declared_length > message->data_length ||
	    message->data_length > SEP_RELAY_DATA_CAPACITY) {
		fail_state(state);
		return SEP_ACM_ERROR_REPLY;
	}
	payload = message->data;
	if (remote_result != 0) {
		clear_pending(state);
		return SEP_ACM_ERROR_REMOTE;
	}
	result = expected_payload(state, payload, declared_length, outcome);
	if (result != SEP_ACM_OK) {
		fail_state(state);
		return result;
	}
	accept_success(state, operation, payload, outcome);
	clear_pending(state);
	return SEP_ACM_OK;
}

void sep_acm_wipe_transfer(uint8_t transfer[SEP_RELAY_BUFFER_SIZE])
{
	if (transfer)
		sep_crypto_wipe(transfer, SEP_RELAY_BUFFER_SIZE);
}

const char *sep_acm_result_name(int result)
{
	switch (result) {
	case SEP_ACM_OK:
		return "success";
	case SEP_ACM_ERROR_ARGUMENT:
		return "invalid ACM input";
	case SEP_ACM_ERROR_STATE:
		return "invalid ACM state";
	case SEP_ACM_ERROR_RELAY:
		return "ACM relay failure";
	case SEP_ACM_ERROR_REPLY:
		return "invalid ACM reply";
	case SEP_ACM_ERROR_REMOTE:
		return "ACM command rejected";
	case SEP_ACM_ERROR_AMBIGUOUS:
		return "ACM command outcome is ambiguous";
	default:
		return "unknown ACM failure";
	}
}

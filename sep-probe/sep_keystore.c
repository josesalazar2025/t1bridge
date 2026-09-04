#include "sep_keystore.h"

#include "sep_crypto.h"

#include <limits.h>
#include <string.h>

#define IPC_DIGEST_SIZE 16U
#define IPC_HASHED_HEADER_OFFSET 0x14U
#define IPC_HASHED_HEADER_SIZE 0x38U
#define IPC_VERSION_OFFSET 0x14U
#define IPC_TIMESTAMP_OFFSET 0x18U
#define IPC_ARGUMENTS_OFFSET SEP_KEYSTORE_IPC_WIRE_HEADER_SIZE
#define IPC_RESULT_OFFSET 0x54U
#define IPC_CONTEXT_OFFSET 0x58U
#define IPC_FIRST_ARGUMENT_OFFSET 0x60U
#define IPC_SECOND_ARGUMENT_OFFSET 0x64U
#define IPC_LENGTH_OFFSET 0x68U
#define IPC_BYTES_OFFSET 0x6cU

#define CAPABILITIES_REQUEST_SIZE 0x64U
#define HANDLE_REQUEST_SIZE 0x64U
#define DEVICE_STATE_REQUEST_SIZE 0x68U
#define LOCK_STATE_REQUEST_SIZE 0x6cU
#define CREATE_REQUEST_SIZE (IPC_BYTES_OFFSET + SEP_KEYSTORE_SECRET_SIZE)
#define UNLOCK_REQUEST_SIZE (0x74U + SEP_KEYSTORE_SECRET_SIZE)
#define VERIFY_SECRET_BASE_SIZE 0x68U
#define SET_ENVIRONMENT_REQUEST_SIZE \
	(SEP_KEYSTORE_IPC_WIRE_HEADER_SIZE + 4U + 8U + 4U + \
	 SEP_KEYSTORE_ENVIRONMENT_SIZE)

static uint16_t load_u16_le(const uint8_t *input)
{
	return (uint16_t)input[0] | (uint16_t)((uint16_t)input[1] << 8);
}

static uint32_t load_u32_le(const uint8_t *input)
{
	return (uint32_t)input[0] | (uint32_t)input[1] << 8 |
	       (uint32_t)input[2] << 16 | (uint32_t)input[3] << 24;
}

static uint64_t load_u64_le(const uint8_t *input)
{
	return (uint64_t)load_u32_le(input) |
	       (uint64_t)load_u32_le(input + sizeof(uint32_t)) << 32;
}

static void store_u32_le(uint8_t *output, uint32_t value)
{
	output[0] = (uint8_t)value;
	output[1] = (uint8_t)(value >> 8);
	output[2] = (uint8_t)(value >> 16);
	output[3] = (uint8_t)(value >> 24);
}

static void store_u64_le(uint8_t *output, uint64_t value)
{
	store_u32_le(output, (uint32_t)value);
	store_u32_le(output + sizeof(uint32_t), (uint32_t)(value >> 32));
}

static int padded_length(size_t length, size_t *padded)
{
	if (!padded || length > SIZE_MAX - 3U)
		return SEP_KEYSTORE_ERROR_LENGTH;
	*padded = (length + 3U) & ~(size_t)3U;
	return SEP_KEYSTORE_OK;
}

static int calculate_digest(const uint8_t *request, size_t request_length,
			    uint8_t digest[SEP_SHA256_DIGEST_SIZE])
{
	struct sep_sha256_context context;

	if (sep_sha256_init(&context) != 0 ||
	    sep_sha256_update(&context, request + IPC_HASHED_HEADER_OFFSET,
			      IPC_HASHED_HEADER_SIZE) != 0 ||
	    sep_sha256_update(&context, request + IPC_ARGUMENTS_OFFSET,
			      request_length - IPC_ARGUMENTS_OFFSET) != 0 ||
	    sep_sha256_final(&context, digest) != 0) {
		sep_crypto_wipe(&context, sizeof(context));
		return SEP_KEYSTORE_ERROR_HASH;
	}
	return SEP_KEYSTORE_OK;
}

static int validate_ipc_bounds(const uint8_t *request, size_t request_length)
{
	if (!request)
		return SEP_KEYSTORE_ERROR_ARGUMENT;
	if (request_length < SEP_KEYSTORE_IPC_WIRE_HEADER_SIZE ||
	    request_length > SEP_RELAY_DATA_CAPACITY ||
	    request_length > UINT16_MAX)
		return SEP_KEYSTORE_ERROR_LENGTH;
	return SEP_KEYSTORE_OK;
}

static int prepare_common(struct sep_keystore_state *state, void *output,
			  size_t output_capacity, size_t request_length)
{
	uint8_t *request = output;

	if (!state || !output)
		return SEP_KEYSTORE_ERROR_ARGUMENT;
	if (request_length > output_capacity ||
	    request_length > SEP_RELAY_DATA_CAPACITY)
		return SEP_KEYSTORE_ERROR_CAPACITY;
	memset(request, 0, request_length);
	store_u32_le(request + IPC_RESULT_OFFSET, 0);
	store_u64_le(request + IPC_CONTEXT_OFFSET, state->client_context);
	return SEP_KEYSTORE_OK;
}

static int finish_request(struct sep_keystore_state *state,
			  uint64_t timestamp_us,
			  enum sep_keystore_operation_kind kind,
			  uint8_t selector, void *request,
			  size_t request_length,
			  struct sep_keystore_operation *operation)
{
	int result;

	if (!state || !request || !operation)
		return SEP_KEYSTORE_ERROR_ARGUMENT;
	if (state->transaction_exhausted) {
		sep_crypto_wipe(request, request_length);
		return SEP_KEYSTORE_ERROR_EXHAUSTED;
	}
	if (state->has_timestamp && timestamp_us <= state->last_timestamp_us) {
		sep_crypto_wipe(request, request_length);
		return SEP_KEYSTORE_ERROR_STATE;
	}
	result = sep_keystore_seal(request, request_length, timestamp_us);
	if (result != SEP_KEYSTORE_OK) {
		sep_crypto_wipe(request, request_length);
		return result;
	}

	operation->kind = kind;
	operation->request_length = request_length;
	operation->selector = selector;
	operation->transaction = state->next_transaction;
	if (state->next_transaction == UINT8_MAX)
		state->transaction_exhausted = 1;
	else
		state->next_transaction++;
	state->last_timestamp_us = timestamp_us;
	state->has_timestamp = 1;
	return SEP_KEYSTORE_OK;
}

static int build_handle_request(
	struct sep_keystore_state *state, uint64_t timestamp_us,
	int32_t keybag_handle, enum sep_keystore_operation_kind kind,
	uint8_t selector, void *output, size_t output_capacity,
	struct sep_keystore_operation *operation)
{
	uint8_t *request = output;
	int result = prepare_common(state, output, output_capacity,
				    HANDLE_REQUEST_SIZE);

	if (result != SEP_KEYSTORE_OK)
		return result;
	store_u32_le(request + IPC_FIRST_ARGUMENT_OFFSET,
		     (uint32_t)keybag_handle);
	return finish_request(state, timestamp_us, kind, selector, request,
			      HANDLE_REQUEST_SIZE, operation);
}

int sep_keystore_state_init(struct sep_keystore_state *state,
			    uint64_t client_context,
			    uint8_t first_transaction)
{
	if (!state || client_context == 0)
		return SEP_KEYSTORE_ERROR_ARGUMENT;
	memset(state, 0, sizeof(*state));
	state->client_context = client_context;
	state->next_transaction = first_transaction;
	return SEP_KEYSTORE_OK;
}

int sep_keystore_seal(void *request_data, size_t request_length,
		      uint64_t timestamp_us)
{
	uint8_t *request = request_data;
	uint8_t digest[SEP_SHA256_DIGEST_SIZE];
	int result = validate_ipc_bounds(request, request_length);

	if (result != SEP_KEYSTORE_OK)
		return result;
	store_u32_le(request, SEP_KEYSTORE_IPC_HEADER_SIZE);
	memset(request + sizeof(uint32_t), 0, IPC_DIGEST_SIZE);
	store_u32_le(request + IPC_VERSION_OFFSET, 1);
	store_u64_le(request + IPC_TIMESTAMP_OFFSET, timestamp_us);
	result = calculate_digest(request, request_length, digest);
	if (result == SEP_KEYSTORE_OK)
		memcpy(request + sizeof(uint32_t), digest, IPC_DIGEST_SIZE);
	sep_crypto_wipe(digest, sizeof(digest));
	return result;
}

int sep_keystore_verify_seal(const void *request_data, size_t request_length)
{
	const uint8_t *request = request_data;
	uint8_t digest[SEP_SHA256_DIGEST_SIZE];
	int result = validate_ipc_bounds(request, request_length);

	if (result != SEP_KEYSTORE_OK)
		return result;
	if (load_u32_le(request) != SEP_KEYSTORE_IPC_HEADER_SIZE ||
	    load_u32_le(request + IPC_VERSION_OFFSET) != 1)
		return SEP_KEYSTORE_ERROR_HEADER;
	result = calculate_digest(request, request_length, digest);
	if (result == SEP_KEYSTORE_OK &&
	    !sep_crypto_equal(request + sizeof(uint32_t), digest,
			      IPC_DIGEST_SIZE))
		result = SEP_KEYSTORE_ERROR_HASH;
	sep_crypto_wipe(digest, sizeof(digest));
	return result;
}

int sep_keystore_build_capabilities(
	struct sep_keystore_state *state, uint64_t timestamp_us, void *output,
	size_t output_capacity, struct sep_keystore_operation *operation)
{
	uint8_t *request = output;

	if (!state || !output)
		return SEP_KEYSTORE_ERROR_ARGUMENT;
	if (CAPABILITIES_REQUEST_SIZE > output_capacity)
		return SEP_KEYSTORE_ERROR_CAPACITY;
	memset(request, 0, CAPABILITIES_REQUEST_SIZE);
	store_u32_le(request + IPC_RESULT_OFFSET, 0);
	store_u64_le(request + IPC_CONTEXT_OFFSET, 1);
	store_u32_le(request + IPC_FIRST_ARGUMENT_OFFSET, 0);
	return finish_request(state, timestamp_us,
			      SEP_KEYSTORE_OPERATION_CAPABILITIES,
			      SEP_KEYSTORE_SELECTOR_CAPABILITIES, request,
			      CAPABILITIES_REQUEST_SIZE, operation);
}

int sep_keystore_build_create(
	struct sep_keystore_state *state, uint64_t timestamp_us,
	const uint8_t secret[SEP_KEYSTORE_SECRET_SIZE], void *output,
	size_t output_capacity, struct sep_keystore_operation *operation)
{
	uint8_t *request = output;
	int result;

	if (!secret)
		return SEP_KEYSTORE_ERROR_ARGUMENT;
	result = prepare_common(state, output, output_capacity,
				CREATE_REQUEST_SIZE);
	if (result != SEP_KEYSTORE_OK)
		return result;
	store_u32_le(request + IPC_FIRST_ARGUMENT_OFFSET, 0);
	store_u32_le(request + IPC_SECOND_ARGUMENT_OFFSET, UINT32_MAX);
	store_u32_le(request + IPC_LENGTH_OFFSET, SEP_KEYSTORE_SECRET_SIZE);
	memcpy(request + IPC_BYTES_OFFSET, secret, SEP_KEYSTORE_SECRET_SIZE);
	return finish_request(state, timestamp_us, SEP_KEYSTORE_OPERATION_CREATE,
			      SEP_KEYSTORE_SELECTOR_CREATE, request,
			      CREATE_REQUEST_SIZE, operation);
}

int sep_keystore_build_serialize(
	struct sep_keystore_state *state, uint64_t timestamp_us,
	int32_t keybag_handle, void *output, size_t output_capacity,
	struct sep_keystore_operation *operation)
{
	return build_handle_request(
		state, timestamp_us, keybag_handle,
		SEP_KEYSTORE_OPERATION_SERIALIZE,
		SEP_KEYSTORE_SELECTOR_SERIALIZE, output, output_capacity,
		operation);
}

int sep_keystore_build_load(
	struct sep_keystore_state *state, uint64_t timestamp_us,
	const void *serialized_keybag, size_t serialized_keybag_length,
	void *output, size_t output_capacity,
	struct sep_keystore_operation *operation)
{
	uint8_t *request = output;
	size_t padded;
	size_t request_length;
	int result;

	if (!serialized_keybag || serialized_keybag_length == 0 ||
	    serialized_keybag_length > UINT32_MAX)
		return SEP_KEYSTORE_ERROR_ARGUMENT;
	result = padded_length(serialized_keybag_length, &padded);
	if (result != SEP_KEYSTORE_OK ||
	    padded > SEP_RELAY_DATA_CAPACITY - HANDLE_REQUEST_SIZE)
		return SEP_KEYSTORE_ERROR_LENGTH;
	request_length = HANDLE_REQUEST_SIZE + padded;
	result = prepare_common(state, output, output_capacity, request_length);
	if (result != SEP_KEYSTORE_OK)
		return result;
	store_u32_le(request + IPC_FIRST_ARGUMENT_OFFSET,
		     (uint32_t)serialized_keybag_length);
	memcpy(request + HANDLE_REQUEST_SIZE, serialized_keybag,
	       serialized_keybag_length);
	return finish_request(state, timestamp_us, SEP_KEYSTORE_OPERATION_LOAD,
			      SEP_KEYSTORE_SELECTOR_LOAD, request,
			      request_length, operation);
}

int sep_keystore_build_lock_state(
	struct sep_keystore_state *state, uint64_t timestamp_us,
	int32_t keybag_handle, void *output, size_t output_capacity,
	struct sep_keystore_operation *operation)
{
	uint8_t *request = output;
	int result = prepare_common(state, output, output_capacity,
				    LOCK_STATE_REQUEST_SIZE);

	if (result != SEP_KEYSTORE_OK)
		return result;
	store_u32_le(request + IPC_FIRST_ARGUMENT_OFFSET,
		     (uint32_t)keybag_handle);
	store_u32_le(request + IPC_SECOND_ARGUMENT_OFFSET, UINT32_MAX);
	store_u32_le(request + IPC_LENGTH_OFFSET, 0);
	return finish_request(state, timestamp_us,
			      SEP_KEYSTORE_OPERATION_LOCK_STATE,
			      SEP_KEYSTORE_SELECTOR_LOCK_STATE, request,
			      LOCK_STATE_REQUEST_SIZE, operation);
}

int sep_keystore_build_copy_uuid(
	struct sep_keystore_state *state, uint64_t timestamp_us,
	int32_t keybag_handle, void *output, size_t output_capacity,
	struct sep_keystore_operation *operation)
{
	return build_handle_request(
		state, timestamp_us, keybag_handle,
		SEP_KEYSTORE_OPERATION_COPY_UUID,
		SEP_KEYSTORE_SELECTOR_COPY_UUID, output, output_capacity,
		operation);
}

int sep_keystore_build_make_system(
	struct sep_keystore_state *state, uint64_t timestamp_us,
	uint32_t source_handle, int32_t target_handle,
	const uint8_t *secret, size_t secret_length, void *output,
	size_t output_capacity, struct sep_keystore_operation *operation)
{
	uint8_t *request = output;
	size_t request_length = IPC_BYTES_OFFSET;
	int result;

	if ((!secret && secret_length != 0) ||
	    (secret && secret_length != SEP_KEYSTORE_SECRET_SIZE))
		return SEP_KEYSTORE_ERROR_ARGUMENT;
	if (secret)
		request_length += SEP_KEYSTORE_SECRET_SIZE;
	result = prepare_common(state, output, output_capacity, request_length);
	if (result != SEP_KEYSTORE_OK)
		return result;
	store_u32_le(request + IPC_FIRST_ARGUMENT_OFFSET, source_handle);
	store_u32_le(request + IPC_SECOND_ARGUMENT_OFFSET,
		     (uint32_t)target_handle);
	store_u32_le(request + IPC_LENGTH_OFFSET, (uint32_t)secret_length);
	if (secret)
		memcpy(request + IPC_BYTES_OFFSET, secret,
		       SEP_KEYSTORE_SECRET_SIZE);
	return finish_request(state, timestamp_us,
			      SEP_KEYSTORE_OPERATION_MAKE_SYSTEM,
			      SEP_KEYSTORE_SELECTOR_MAKE_SYSTEM, request,
			      request_length, operation);
}

int sep_keystore_build_unlock(
	struct sep_keystore_state *state, uint64_t timestamp_us,
	int32_t keybag_handle,
	const uint8_t secret[SEP_KEYSTORE_SECRET_SIZE], void *output,
	size_t output_capacity, struct sep_keystore_operation *operation)
{
	uint8_t *request = output;
	int result;

	if (!secret)
		return SEP_KEYSTORE_ERROR_ARGUMENT;
	result = prepare_common(state, output, output_capacity,
				UNLOCK_REQUEST_SIZE);
	if (result != SEP_KEYSTORE_OK)
		return result;
	store_u32_le(request + IPC_FIRST_ARGUMENT_OFFSET,
		     (uint32_t)keybag_handle);
	store_u32_le(request + IPC_SECOND_ARGUMENT_OFFSET, 0);
	store_u64_le(request + IPC_LENGTH_OFFSET, 0);
	store_u32_le(request + 0x70U, SEP_KEYSTORE_SECRET_SIZE);
	memcpy(request + 0x74U, secret, SEP_KEYSTORE_SECRET_SIZE);
	return finish_request(state, timestamp_us, SEP_KEYSTORE_OPERATION_UNLOCK,
			      SEP_KEYSTORE_SELECTOR_UNLOCK, request,
			      UNLOCK_REQUEST_SIZE, operation);
}

int sep_keystore_build_device_state(
	struct sep_keystore_state *state, uint64_t timestamp_us,
	int32_t keybag_handle, void *output, size_t output_capacity,
	struct sep_keystore_operation *operation)
{
	uint8_t *request = output;
	int result = prepare_common(state, output, output_capacity,
				    DEVICE_STATE_REQUEST_SIZE);

	if (result != SEP_KEYSTORE_OK)
		return result;
	store_u32_le(request + IPC_FIRST_ARGUMENT_OFFSET,
		     (uint32_t)keybag_handle);
	store_u32_le(request + IPC_SECOND_ARGUMENT_OFFSET, 0);
	return finish_request(state, timestamp_us,
			      SEP_KEYSTORE_OPERATION_DEVICE_STATE,
			      SEP_KEYSTORE_SELECTOR_DEVICE_STATE, request,
			      DEVICE_STATE_REQUEST_SIZE, operation);
}

int sep_keystore_build_verify_secret(
	struct sep_keystore_state *state, uint64_t timestamp_us,
	int32_t keybag_handle,
	const uint8_t secret[SEP_KEYSTORE_SECRET_SIZE],
	const uint8_t *external_form, size_t external_form_length, void *output,
	size_t output_capacity, struct sep_keystore_operation *operation)
{
	uint8_t *request = output;
	size_t request_length = VERIFY_SECRET_BASE_SIZE +
				SEP_KEYSTORE_SECRET_SIZE + sizeof(uint32_t);
	int result;

	if (!secret || (!external_form && external_form_length != 0) ||
	    (external_form &&
	     external_form_length != SEP_KEYSTORE_EXTERNAL_FORM_SIZE))
		return SEP_KEYSTORE_ERROR_ARGUMENT;
	if (external_form)
		request_length += SEP_KEYSTORE_EXTERNAL_FORM_SIZE;
	result = prepare_common(state, output, output_capacity, request_length);
	if (result != SEP_KEYSTORE_OK)
		return result;
	store_u32_le(request + IPC_FIRST_ARGUMENT_OFFSET,
		     (uint32_t)keybag_handle);
	store_u32_le(request + IPC_SECOND_ARGUMENT_OFFSET,
		     SEP_KEYSTORE_SECRET_SIZE);
	memcpy(request + VERIFY_SECRET_BASE_SIZE, secret,
	       SEP_KEYSTORE_SECRET_SIZE);
	store_u32_le(request + VERIFY_SECRET_BASE_SIZE +
			     SEP_KEYSTORE_SECRET_SIZE,
		     (uint32_t)external_form_length);
	if (external_form)
		memcpy(request + VERIFY_SECRET_BASE_SIZE +
			       SEP_KEYSTORE_SECRET_SIZE + sizeof(uint32_t),
		       external_form, SEP_KEYSTORE_EXTERNAL_FORM_SIZE);
	return finish_request(state, timestamp_us,
			      SEP_KEYSTORE_OPERATION_VERIFY_SECRET,
			      SEP_KEYSTORE_SELECTOR_VERIFY_SECRET, request,
			      request_length, operation);
}

int sep_keystore_build_get_configuration(
	struct sep_keystore_state *state, uint64_t timestamp_us,
	int32_t keybag_handle, void *output, size_t output_capacity,
	struct sep_keystore_operation *operation)
{
	return build_handle_request(
		state, timestamp_us, keybag_handle,
		SEP_KEYSTORE_OPERATION_GET_CONFIGURATION,
		SEP_KEYSTORE_SELECTOR_GET_CONFIGURATION, output,
		output_capacity, operation);
}

int sep_keystore_build_set_configuration(
	struct sep_keystore_state *state, uint64_t timestamp_us,
	int32_t keybag_handle, uint32_t flags, const void *configuration,
	size_t configuration_length, void *output, size_t output_capacity,
	struct sep_keystore_operation *operation)
{
	uint8_t *request = output;
	size_t padded;
	size_t request_length;
	int result;

	if (!configuration || configuration_length == 0 ||
	    configuration_length > UINT32_MAX)
		return SEP_KEYSTORE_ERROR_ARGUMENT;
	result = padded_length(configuration_length, &padded);
	if (result != SEP_KEYSTORE_OK ||
	    padded > SEP_RELAY_DATA_CAPACITY - IPC_BYTES_OFFSET)
		return SEP_KEYSTORE_ERROR_LENGTH;
	request_length = IPC_BYTES_OFFSET + padded;
	result = prepare_common(state, output, output_capacity, request_length);
	if (result != SEP_KEYSTORE_OK)
		return result;
	store_u32_le(request + IPC_FIRST_ARGUMENT_OFFSET,
		     (uint32_t)keybag_handle);
	store_u32_le(request + IPC_SECOND_ARGUMENT_OFFSET, flags);
	store_u32_le(request + IPC_LENGTH_OFFSET,
		     (uint32_t)configuration_length);
	memcpy(request + IPC_BYTES_OFFSET, configuration, configuration_length);
	return finish_request(state, timestamp_us,
			      SEP_KEYSTORE_OPERATION_SET_CONFIGURATION,
			      SEP_KEYSTORE_SELECTOR_SET_CONFIGURATION, request,
			      request_length, operation);
}

int sep_keystore_build_set_environment(
	struct sep_keystore_state *state, uint64_t timestamp_us, void *output,
	size_t output_capacity, struct sep_keystore_operation *operation)
{
	uint8_t *request = output;
	uint8_t *environment;
	int result = prepare_common(state, output, output_capacity,
				    SET_ENVIRONMENT_REQUEST_SIZE);

	if (result != SEP_KEYSTORE_OK)
		return result;
	store_u64_le(request + IPC_CONTEXT_OFFSET, 1);
	store_u32_le(request + IPC_FIRST_ARGUMENT_OFFSET,
		     SEP_KEYSTORE_ENVIRONMENT_SIZE);
	environment = request + HANDLE_REQUEST_SIZE;
	store_u32_le(environment, 1);
	store_u32_le(environment + 4, 0);
	store_u32_le(environment + 8, 0);
	store_u64_le(environment + 0xc, 0);
	return finish_request(state, timestamp_us,
			      SEP_KEYSTORE_OPERATION_SET_ENVIRONMENT,
			      SEP_KEYSTORE_SELECTOR_SET_ENVIRONMENT, request,
			      SET_ENVIRONMENT_REQUEST_SIZE, operation);
}

static int operation_selector(enum sep_keystore_operation_kind kind,
			      uint8_t *selector)
{
	if (!selector)
		return SEP_KEYSTORE_ERROR_ARGUMENT;
	switch (kind) {
	case SEP_KEYSTORE_OPERATION_CAPABILITIES:
		*selector = SEP_KEYSTORE_SELECTOR_CAPABILITIES;
		break;
	case SEP_KEYSTORE_OPERATION_CREATE:
		*selector = SEP_KEYSTORE_SELECTOR_CREATE;
		break;
	case SEP_KEYSTORE_OPERATION_SERIALIZE:
		*selector = SEP_KEYSTORE_SELECTOR_SERIALIZE;
		break;
	case SEP_KEYSTORE_OPERATION_LOAD:
		*selector = SEP_KEYSTORE_SELECTOR_LOAD;
		break;
	case SEP_KEYSTORE_OPERATION_LOCK_STATE:
		*selector = SEP_KEYSTORE_SELECTOR_LOCK_STATE;
		break;
	case SEP_KEYSTORE_OPERATION_COPY_UUID:
		*selector = SEP_KEYSTORE_SELECTOR_COPY_UUID;
		break;
	case SEP_KEYSTORE_OPERATION_MAKE_SYSTEM:
		*selector = SEP_KEYSTORE_SELECTOR_MAKE_SYSTEM;
		break;
	case SEP_KEYSTORE_OPERATION_UNLOCK:
		*selector = SEP_KEYSTORE_SELECTOR_UNLOCK;
		break;
	case SEP_KEYSTORE_OPERATION_DEVICE_STATE:
		*selector = SEP_KEYSTORE_SELECTOR_DEVICE_STATE;
		break;
	case SEP_KEYSTORE_OPERATION_VERIFY_SECRET:
		*selector = SEP_KEYSTORE_SELECTOR_VERIFY_SECRET;
		break;
	case SEP_KEYSTORE_OPERATION_GET_CONFIGURATION:
		*selector = SEP_KEYSTORE_SELECTOR_GET_CONFIGURATION;
		break;
	case SEP_KEYSTORE_OPERATION_SET_CONFIGURATION:
		*selector = SEP_KEYSTORE_SELECTOR_SET_CONFIGURATION;
		break;
	case SEP_KEYSTORE_OPERATION_SET_ENVIRONMENT:
		*selector = SEP_KEYSTORE_SELECTOR_SET_ENVIRONMENT;
		break;
	default:
		return SEP_KEYSTORE_ERROR_SELECTOR;
	}
	return SEP_KEYSTORE_OK;
}

int sep_keystore_wrap_request(
	struct sep_relay_state *relay_state,
	const struct sep_keystore_operation *operation, const void *request,
	size_t request_length,
	uint8_t output[SEP_RELAY_BUFFER_SIZE],
	struct sep_relay_pending *pending)
{
	uint8_t expected_selector;
	int result;

	if (!relay_state || !operation || !request || !output || !pending)
		return SEP_KEYSTORE_ERROR_ARGUMENT;
	if (request_length != operation->request_length)
		return SEP_KEYSTORE_ERROR_LENGTH;
	result = operation_selector(operation->kind, &expected_selector);
	if (result != SEP_KEYSTORE_OK ||
	    operation->selector != expected_selector)
		return SEP_KEYSTORE_ERROR_SELECTOR;
	result = sep_keystore_verify_seal(request, operation->request_length);
	if (result != SEP_KEYSTORE_OK)
		return result;
	result = sep_relay_build_keystore_request(
		relay_state, request, operation->request_length,
		operation->selector, operation->transaction, output, pending);
	return result == SEP_RELAY_OK ? SEP_KEYSTORE_OK :
				       SEP_KEYSTORE_ERROR_RELAY;
}

static int parse_length_prefixed_opaque(const uint8_t *output,
					size_t output_length,
					struct sep_keystore_reply *reply,
					size_t exact_length)
{
	size_t opaque_length;

	if (output_length < sizeof(uint32_t))
		return SEP_KEYSTORE_ERROR_LENGTH;
	opaque_length = load_u32_le(output);
	if (opaque_length > output_length - sizeof(uint32_t) ||
	    (exact_length != 0 && opaque_length != exact_length))
		return SEP_KEYSTORE_ERROR_LENGTH;
	reply->kind = SEP_KEYSTORE_REPLY_OPAQUE;
	reply->opaque = output + sizeof(uint32_t);
	reply->opaque_length = opaque_length;
	return SEP_KEYSTORE_OK;
}

static int parse_typed_output(const struct sep_keystore_operation *operation,
			      const uint8_t *output, size_t output_length,
			      struct sep_keystore_reply *reply)
{
	switch (operation->kind) {
	case SEP_KEYSTORE_OPERATION_CREATE:
	case SEP_KEYSTORE_OPERATION_LOAD:
		if (output_length != sizeof(uint32_t))
			return SEP_KEYSTORE_ERROR_LENGTH;
		reply->kind = SEP_KEYSTORE_REPLY_VALUE;
		reply->value = load_u32_le(output);
		return SEP_KEYSTORE_OK;
	case SEP_KEYSTORE_OPERATION_SERIALIZE:
	case SEP_KEYSTORE_OPERATION_DEVICE_STATE:
	case SEP_KEYSTORE_OPERATION_GET_CONFIGURATION:
		return parse_length_prefixed_opaque(output, output_length, reply, 0);
	case SEP_KEYSTORE_OPERATION_COPY_UUID:
		return parse_length_prefixed_opaque(
			output, output_length, reply, SEP_KEYSTORE_UUID_SIZE);
	case SEP_KEYSTORE_OPERATION_LOCK_STATE:
		if (output_length != sizeof(uint32_t) + sizeof(uint64_t))
			return SEP_KEYSTORE_ERROR_LENGTH;
		reply->kind = SEP_KEYSTORE_REPLY_VALUE_AND_FLAGS;
		reply->value = load_u32_le(output);
		reply->first_wide_value = load_u64_le(output + sizeof(uint32_t));
		return SEP_KEYSTORE_OK;
	case SEP_KEYSTORE_OPERATION_UNLOCK:
	case SEP_KEYSTORE_OPERATION_SET_CONFIGURATION:
		if (output_length != 2U * sizeof(uint64_t))
			return SEP_KEYSTORE_ERROR_LENGTH;
		reply->kind = SEP_KEYSTORE_REPLY_STATE_PAIR;
		reply->first_wide_value = load_u64_le(output);
		reply->second_wide_value = load_u64_le(output + sizeof(uint64_t));
		return SEP_KEYSTORE_OK;
	case SEP_KEYSTORE_OPERATION_CAPABILITIES:
		reply->kind = SEP_KEYSTORE_REPLY_OPAQUE;
		reply->opaque = output;
		reply->opaque_length = output_length;
		return SEP_KEYSTORE_OK;
	case SEP_KEYSTORE_OPERATION_MAKE_SYSTEM:
	case SEP_KEYSTORE_OPERATION_VERIFY_SECRET:
	case SEP_KEYSTORE_OPERATION_SET_ENVIRONMENT:
		reply->kind = SEP_KEYSTORE_REPLY_NONE;
		return SEP_KEYSTORE_OK;
	default:
		return SEP_KEYSTORE_ERROR_SELECTOR;
	}
}

int sep_keystore_parse_reply(
	const struct sep_relay_message *message,
	const struct sep_relay_pending *pending,
	const struct sep_keystore_operation *operation,
	struct sep_keystore_reply *reply)
{
	const uint8_t *ipc;
	const uint8_t *output;
	size_t declared_length;
	size_t result_offset;
	size_t output_offset;
	uint32_t header_length;
	uint8_t expected_selector;
	int result;

	if (!message || !pending || !operation || !reply)
		return SEP_KEYSTORE_ERROR_ARGUMENT;
	memset(reply, 0, sizeof(*reply));
	result = operation_selector(operation->kind, &expected_selector);
	if (result != SEP_KEYSTORE_OK ||
	    operation->selector != expected_selector)
		return SEP_KEYSTORE_ERROR_SELECTOR;
	if (pending->kind != SEP_RELAY_REQUEST_KEYSTORE ||
	    pending->selector != operation->selector)
		return SEP_KEYSTORE_ERROR_SELECTOR;
	if (pending->transaction != operation->transaction)
		return SEP_KEYSTORE_ERROR_TRANSACTION;
	result = sep_relay_matches(message, pending);
	if (result != SEP_RELAY_MATCHED)
		return SEP_KEYSTORE_ERROR_RELAY;
	if (message->message_length < 8)
		return SEP_KEYSTORE_ERROR_LENGTH;

	reply->outer_result = (int8_t)message->message[11];
	declared_length = load_u16_le(message->message + 14);
	if (declared_length > message->data_length)
		return SEP_KEYSTORE_ERROR_LENGTH;
	if (reply->outer_result != 0)
		return SEP_KEYSTORE_REMOTE_ERROR;
	if (declared_length < 2U * sizeof(uint32_t))
		return SEP_KEYSTORE_ERROR_LENGTH;
	ipc = message->data;
	header_length = load_u32_le(ipc);
	if (header_length > declared_length - 2U * sizeof(uint32_t))
		return SEP_KEYSTORE_ERROR_HEADER;
	result_offset = sizeof(uint32_t) + (size_t)header_length;
	if (result_offset > declared_length - sizeof(uint32_t))
		return SEP_KEYSTORE_ERROR_LENGTH;
	reply->inner_result = (int32_t)load_u32_le(ipc + result_offset);
	if (reply->inner_result != 0)
		return SEP_KEYSTORE_REMOTE_ERROR;
	output_offset = result_offset + sizeof(uint32_t);
	output = ipc + output_offset;
	return parse_typed_output(operation, output,
				  declared_length - output_offset, reply);
}

void sep_keystore_clear(void *data, size_t length)
{
	sep_crypto_wipe(data, length);
}

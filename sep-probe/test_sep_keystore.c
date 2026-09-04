#include "sep_keystore.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

#define RESULT_OFFSET 0x54U
#define CONTEXT_OFFSET 0x58U
#define FIRST_ARGUMENT_OFFSET 0x60U
#define SECOND_ARGUMENT_OFFSET 0x64U
#define LENGTH_OFFSET 0x68U
#define BYTES_OFFSET 0x6cU
#define MESSAGE_INDEX_OFFSET 0x88U
#define REPLY_TOKEN_OFFSET 0x8cU
#define REQUEST_TOKEN_OFFSET 0x98U
#define MESSAGE_LENGTH_OFFSET 0xa4U
#define DATA_LENGTH_OFFSET 0xa8U

static int failures;

static void check(int condition, const char *description)
{
	if (condition)
		return;
	fprintf(stderr, "FAIL: %s\n", description);
	failures++;
}

static int all_zero(const uint8_t *data, size_t length)
{
	if (!data)
		return 0;
	for (size_t index = 0; index < length; index++) {
		if (data[index] != 0)
			return 0;
	}
	return 1;
}

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

static void store_u16_le(uint8_t *output, uint16_t value)
{
	output[0] = (uint8_t)value;
	output[1] = (uint8_t)(value >> 8);
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

static int new_state(struct sep_keystore_state *state)
{
	return sep_keystore_state_init(state, UINT64_C(0x8877665544332211), 7);
}

static void build_reply(
	uint8_t transfer[SEP_RELAY_BUFFER_SIZE],
	const struct sep_relay_pending *pending, int8_t outer_result,
	int32_t inner_result, const void *typed_output, size_t typed_output_length)
{
	uint8_t *message = transfer + SEP_RELAY_MESSAGE_OFFSET;
	size_t ipc_length = 0;

	memset(transfer, 0, SEP_RELAY_BUFFER_SIZE);
	if (outer_result == 0) {
		ipc_length = SEP_KEYSTORE_IPC_WIRE_HEADER_SIZE + sizeof(uint32_t) +
			     typed_output_length;
		store_u32_le(transfer + RESULT_OFFSET, (uint32_t)inner_result);
		if (typed_output_length != 0)
			memcpy(transfer + RESULT_OFFSET + sizeof(uint32_t),
			       typed_output, typed_output_length);
		check(sep_keystore_seal(transfer, ipc_length, 9001) ==
			      SEP_KEYSTORE_OK,
		      "seal synthetic reply");
	}
	message[0] = SEP_RELAY_WIRE_VERSION;
	store_u32_le(message + 4, SEP_RELAY_KEYSTORE_ENDPOINT);
	message[9] = (uint8_t)(pending->selector | UINT8_C(0x80));
	message[10] = pending->transaction;
	message[11] = (uint8_t)outer_result;
	store_u16_le(message + 14, (uint16_t)ipc_length);
	store_u64_le(message + REPLY_TOKEN_OFFSET, pending->token);
	store_u32_le(message + MESSAGE_LENGTH_OFFSET, 8);
	store_u32_le(message + DATA_LENGTH_OFFSET, (uint32_t)ipc_length);
}

static int prepare_wrapped_request(
	struct sep_keystore_state *keystore_state,
	struct sep_relay_state *relay_state, uint8_t request[SEP_RELAY_DATA_CAPACITY],
	uint8_t transfer[SEP_RELAY_BUFFER_SIZE],
	struct sep_keystore_operation *operation,
	struct sep_relay_pending *pending)
{
	int result = new_state(keystore_state);

	if (result != SEP_KEYSTORE_OK)
		return result;
	result = sep_keystore_build_capabilities(
		keystore_state, 100, request, SEP_RELAY_DATA_CAPACITY, operation);
	if (result != SEP_KEYSTORE_OK)
		return result;
	result = sep_relay_state_init(relay_state, UINT64_C(0x1020304050607080),
				      12);
	if (result != SEP_RELAY_OK)
		return SEP_KEYSTORE_ERROR_RELAY;
	relay_state->version_confirmed = 1;
	relay_state->endpoint_status_confirmed = 1;
	return sep_keystore_wrap_request(relay_state, operation, request,
					 operation->request_length, transfer, pending);
}

static void test_seal_contract(void)
{
	static const uint8_t expected_digest[16] = {
		0x3d, 0x36, 0xad, 0xdc, 0x2a, 0xc4, 0xb3, 0xac,
		0xe3, 0x07, 0x47, 0x72, 0x53, 0xcb, 0xf7, 0x53,
	};
	uint8_t request[0x64] = { 0 };
	uint8_t original_digest[16];

	store_u32_le(request + RESULT_OFFSET, 0x12345678);
	store_u64_le(request + CONTEXT_OFFSET, UINT64_C(0x0102030405060708));
	store_u32_le(request + FIRST_ARGUMENT_OFFSET, 0xaabbccdd);
	check(sep_keystore_seal(request, sizeof(request),
			       UINT64_C(0x1112131415161718)) == SEP_KEYSTORE_OK,
	      "seal bounded IPC request");
	check(load_u32_le(request) == SEP_KEYSTORE_IPC_HEADER_SIZE,
	      "encode IPC header length");
	check(load_u32_le(request + 0x14) == 1, "encode IPC version");
	check(load_u64_le(request + 0x18) == UINT64_C(0x1112131415161718),
	      "encode IPC timestamp");
	check(memcmp(request + 4, expected_digest, sizeof(expected_digest)) == 0,
	      "match exact IPC digest vector");
	check(sep_keystore_verify_seal(request, sizeof(request)) ==
		      SEP_KEYSTORE_OK,
	      "verify exact IPC seal");
	memcpy(original_digest, request + 4, sizeof(original_digest));
	request[RESULT_OFFSET] ^= 1;
	check(sep_keystore_verify_seal(request, sizeof(request)) ==
		      SEP_KEYSTORE_ERROR_HASH,
	      "reject modified IPC arguments");
	request[RESULT_OFFSET] ^= 1;
	request[4] ^= 1;
	check(sep_keystore_verify_seal(request, sizeof(request)) ==
		      SEP_KEYSTORE_ERROR_HASH,
	      "reject modified IPC digest");
	memcpy(request + 4, original_digest, sizeof(original_digest));
	store_u32_le(request, SEP_KEYSTORE_IPC_HEADER_SIZE - 1U);
	check(sep_keystore_verify_seal(request, sizeof(request)) ==
		      SEP_KEYSTORE_ERROR_HEADER,
	      "reject wrong IPC header length");
	store_u32_le(request, SEP_KEYSTORE_IPC_HEADER_SIZE);
	store_u32_le(request + 0x14, 2);
	check(sep_keystore_verify_seal(request, sizeof(request)) ==
		      SEP_KEYSTORE_ERROR_HEADER,
	      "reject wrong IPC version");
	check(sep_keystore_seal(request,
			       SEP_KEYSTORE_IPC_WIRE_HEADER_SIZE - 1U, 1) ==
		      SEP_KEYSTORE_ERROR_LENGTH,
	      "reject truncated IPC seal input");
	check(sep_keystore_seal(request, SEP_RELAY_DATA_CAPACITY + 1U, 1) ==
		      SEP_KEYSTORE_ERROR_LENGTH,
	      "reject oversized IPC seal input before access");
	check(sep_keystore_verify_seal(NULL, 0) ==
		      SEP_KEYSTORE_ERROR_ARGUMENT,
	      "reject null IPC verification input");
}

static void test_capabilities_and_create(void)
{
	uint8_t request[SEP_RELAY_DATA_CAPACITY];
	uint8_t secret[SEP_KEYSTORE_SECRET_SIZE];
	struct sep_keystore_state state = { 0 };
	struct sep_keystore_operation operation = { 0 };

	memset(secret, 0xa5, sizeof(secret));
	check(new_state(&state) == SEP_KEYSTORE_OK, "initialize request state");
	check(sep_keystore_build_capabilities(
		      &state, 10, request, sizeof(request), &operation) ==
		      SEP_KEYSTORE_OK,
	      "build capabilities request");
	check(operation.kind == SEP_KEYSTORE_OPERATION_CAPABILITIES &&
		      operation.selector == SEP_KEYSTORE_SELECTOR_CAPABILITIES &&
		      operation.transaction == 7 &&
		      operation.request_length == 0x64,
	      "record capabilities operation identity");
	check(load_u32_le(request + RESULT_OFFSET) == 0 &&
		      load_u64_le(request + CONTEXT_OFFSET) == 1 &&
		      load_u32_le(request + FIRST_ARGUMENT_OFFSET) == 0,
	      "encode capabilities arguments");
	check(sep_keystore_verify_seal(request, operation.request_length) ==
		      SEP_KEYSTORE_OK,
	      "verify capabilities seal");

	check(sep_keystore_build_create(&state, 11, secret, request,
					 sizeof(request), &operation) ==
		      SEP_KEYSTORE_OK,
	      "build create request");
	check(operation.selector == SEP_KEYSTORE_SELECTOR_CREATE &&
		      operation.transaction == 8 &&
		      operation.request_length == 0x8c,
	      "record create operation identity");
	check(load_u64_le(request + CONTEXT_OFFSET) == state.client_context &&
		      load_u32_le(request + FIRST_ARGUMENT_OFFSET) == 0 &&
		      load_u32_le(request + SECOND_ARGUMENT_OFFSET) == UINT32_MAX &&
		      load_u32_le(request + LENGTH_OFFSET) == sizeof(secret),
	      "encode create arguments");
	check(memcmp(request + BYTES_OFFSET, secret, sizeof(secret)) == 0,
	      "encode opaque create secret");
	check(sep_keystore_build_create(&state, 11, secret, request,
					 sizeof(request), &operation) ==
		      SEP_KEYSTORE_ERROR_STATE,
	      "reject non-monotonic IPC timestamp");
	check(all_zero(request, 0x8c),
	      "wipe failed secret-bearing request");
	check(state.next_transaction == 9 && state.last_timestamp_us == 11,
	      "leave request state unchanged after failure");
	check(sep_keystore_build_create(&state, 12, NULL, request,
					 sizeof(request), &operation) ==
		      SEP_KEYSTORE_ERROR_ARGUMENT,
	      "reject missing create secret");
	sep_keystore_clear(secret, sizeof(secret));
	for (size_t index = 0; index < sizeof(secret); index++)
		check(secret[index] == 0, "clear sensitive builder input");
}

static void test_keybag_builders(void)
{
	uint8_t request[SEP_RELAY_DATA_CAPACITY];
	uint8_t secret[SEP_KEYSTORE_SECRET_SIZE];
	uint8_t blob[] = { 1, 3, 5, 7, 9 };
	struct sep_keystore_state state = { 0 };
	struct sep_keystore_operation operation = { 0 };
	uint64_t timestamp = 100;

	memset(secret, 0x3c, sizeof(secret));
	check(new_state(&state) == SEP_KEYSTORE_OK, "initialize keybag builders");
	check(sep_keystore_build_serialize(&state, timestamp++, -501, request,
					   sizeof(request), &operation) ==
		      SEP_KEYSTORE_OK,
	      "build serialize request");
	check(operation.selector == SEP_KEYSTORE_SELECTOR_SERIALIZE &&
		      operation.request_length == 0x64 &&
		      load_u32_le(request + FIRST_ARGUMENT_OFFSET) ==
			      (uint32_t)-501,
	      "encode serialize request");
	check(sep_keystore_build_load(&state, timestamp++, blob, sizeof(blob),
				      request, sizeof(request), &operation) ==
		      SEP_KEYSTORE_OK,
	      "build load request");
	check(operation.selector == SEP_KEYSTORE_SELECTOR_LOAD &&
		      operation.request_length == 0x6c &&
		      load_u32_le(request + FIRST_ARGUMENT_OFFSET) == sizeof(blob),
	      "encode padded load request");
	check(memcmp(request + 0x64, blob, sizeof(blob)) == 0 &&
		      request[0x69] == 0 && request[0x6a] == 0 &&
		      request[0x6b] == 0,
	      "zero load padding");
	check(sep_keystore_build_lock_state(&state, timestamp++, -3, request,
					    sizeof(request), &operation) ==
		      SEP_KEYSTORE_OK,
	      "build lock-state query");
	check(operation.selector == SEP_KEYSTORE_SELECTOR_LOCK_STATE &&
		      load_u32_le(request + FIRST_ARGUMENT_OFFSET) == (uint32_t)-3 &&
		      load_u32_le(request + SECOND_ARGUMENT_OFFSET) == UINT32_MAX &&
		      load_u32_le(request + LENGTH_OFFSET) == 0,
	      "encode read-only lock-state query");
	check(sep_keystore_build_copy_uuid(&state, timestamp++, -501, request,
					   sizeof(request), &operation) ==
		      SEP_KEYSTORE_OK,
	      "build copy-UUID request");
	check(operation.selector == SEP_KEYSTORE_SELECTOR_COPY_UUID,
	      "encode copy-UUID selector");
	check(sep_keystore_build_make_system(
		      &state, timestamp++, 23, -501, NULL, 0, request,
		      sizeof(request), &operation) == SEP_KEYSTORE_OK,
	      "build passcode-free promotion");
	check(operation.selector == SEP_KEYSTORE_SELECTOR_MAKE_SYSTEM &&
		      operation.request_length == 0x6c &&
		      load_u32_le(request + FIRST_ARGUMENT_OFFSET) == 23 &&
		      load_u32_le(request + SECOND_ARGUMENT_OFFSET) ==
			      (uint32_t)-501 &&
		      load_u32_le(request + LENGTH_OFFSET) == 0,
	      "encode passcode-free promotion");
	check(sep_keystore_build_make_system(
		      &state, timestamp++, 24, -501, secret, sizeof(secret), request,
		      sizeof(request), &operation) == SEP_KEYSTORE_OK,
	      "build passcode-bearing promotion");
	check(operation.request_length == 0x8c &&
		      load_u32_le(request + LENGTH_OFFSET) == sizeof(secret) &&
		      memcmp(request + BYTES_OFFSET, secret, sizeof(secret)) == 0,
	      "encode passcode-bearing promotion");
	check(sep_keystore_build_unlock(&state, timestamp++, -501, secret,
					request, sizeof(request), &operation) ==
		      SEP_KEYSTORE_OK,
	      "build unlock request");
	check(operation.selector == SEP_KEYSTORE_SELECTOR_UNLOCK &&
		      operation.request_length == 0x94 &&
		      load_u32_le(request + FIRST_ARGUMENT_OFFSET) ==
			      (uint32_t)-501 &&
		      load_u64_le(request + LENGTH_OFFSET) == 0 &&
		      load_u32_le(request + 0x70) == sizeof(secret) &&
		      memcmp(request + 0x74, secret, sizeof(secret)) == 0,
	      "encode unlock arguments");
	check(sep_keystore_build_device_state(&state, timestamp++, 0, request,
					      sizeof(request), &operation) ==
		      SEP_KEYSTORE_OK,
	      "build device-state request");
	check(operation.selector == SEP_KEYSTORE_SELECTOR_DEVICE_STATE &&
		      operation.request_length == 0x68,
	      "encode device-state request");
	check(sep_keystore_build_load(
		      &state, timestamp++, blob, SEP_RELAY_DATA_CAPACITY, request,
		      sizeof(request), &operation) == SEP_KEYSTORE_ERROR_LENGTH,
	      "reject overflowing serialized keybag");
	check(sep_keystore_build_load(&state, timestamp++, blob, SIZE_MAX,
				      request, sizeof(request), &operation) ==
		      SEP_KEYSTORE_ERROR_ARGUMENT,
	      "reject size_t serialized-keybag overflow");
}

static void test_configuration_builders(void)
{
	uint8_t request[SEP_RELAY_DATA_CAPACITY];
	uint8_t secret[SEP_KEYSTORE_SECRET_SIZE];
	uint8_t external[SEP_KEYSTORE_EXTERNAL_FORM_SIZE];
	uint8_t configuration[] = { 0x31, 3, 1, 2, 3 };
	struct sep_keystore_state state = { 0 };
	struct sep_keystore_operation operation = { 0 };
	uint64_t timestamp = 200;

	memset(secret, 0x5a, sizeof(secret));
	memset(external, 0xc3, sizeof(external));
	check(new_state(&state) == SEP_KEYSTORE_OK,
	      "initialize configuration builders");
	check(sep_keystore_build_verify_secret(
		      &state, timestamp++, -501, secret, NULL, 0, request,
		      sizeof(request), &operation) == SEP_KEYSTORE_OK,
	      "build verify-secret preflight");
	check(operation.selector == SEP_KEYSTORE_SELECTOR_VERIFY_SECRET &&
		      operation.request_length == 0x8c &&
		      load_u32_le(request + SECOND_ARGUMENT_OFFSET) == sizeof(secret) &&
		      load_u32_le(request + 0x88) == 0,
	      "encode verify-secret preflight");
	check(sep_keystore_build_verify_secret(
		      &state, timestamp++, -501, secret, external, sizeof(external),
		      request, sizeof(request), &operation) == SEP_KEYSTORE_OK,
	      "build authorized verify-secret request");
	check(operation.request_length == 0x9c &&
		      load_u32_le(request + 0x88) == sizeof(external) &&
		      memcmp(request + 0x8c, external, sizeof(external)) == 0,
	      "encode authorized external form");
	check(sep_keystore_build_get_configuration(
		      &state, timestamp++, -501, request, sizeof(request),
		      &operation) == SEP_KEYSTORE_OK,
	      "build get-configuration request");
	check(operation.selector == SEP_KEYSTORE_SELECTOR_GET_CONFIGURATION,
	      "encode get-configuration selector");
	check(sep_keystore_build_set_configuration(
		      &state, timestamp++, -501, 2, configuration,
		      sizeof(configuration), request, sizeof(request),
		      &operation) == SEP_KEYSTORE_OK,
	      "build set-configuration request");
	check(operation.selector == SEP_KEYSTORE_SELECTOR_SET_CONFIGURATION &&
		      operation.request_length == 0x74 &&
		      load_u32_le(request + SECOND_ARGUMENT_OFFSET) == 2 &&
		      load_u32_le(request + LENGTH_OFFSET) ==
			      sizeof(configuration) &&
		      memcmp(request + BYTES_OFFSET, configuration,
			     sizeof(configuration)) == 0 &&
		      request[0x71] == 0 && request[0x72] == 0 &&
		      request[0x73] == 0,
	      "encode opaque configuration and padding");
	check(sep_keystore_build_set_environment(
		      &state, timestamp++, request, sizeof(request), &operation) ==
		      SEP_KEYSTORE_OK,
	      "build environment request");
	check(operation.selector == SEP_KEYSTORE_SELECTOR_SET_ENVIRONMENT &&
		      operation.request_length == 0x470 &&
		      load_u64_le(request + CONTEXT_OFFSET) == 1 &&
		      load_u32_le(request + FIRST_ARGUMENT_OFFSET) ==
			      SEP_KEYSTORE_ENVIRONMENT_SIZE &&
		      load_u32_le(request + 0x64) == 1 &&
		      load_u32_le(request + 0x68) == 0 &&
		      load_u32_le(request + 0x6c) == 0 &&
		      load_u64_le(request + 0x70) == 0,
	      "encode zero-dependency environment payload");
	check(sep_keystore_build_verify_secret(
		      &state, timestamp++, -501, secret, external,
		      sizeof(external) - 1U, request, sizeof(request),
		      &operation) == SEP_KEYSTORE_ERROR_ARGUMENT,
	      "reject wrong external-form length");
	check(sep_keystore_build_set_configuration(
		      &state, timestamp++, -501, 2, configuration, SIZE_MAX,
		      request, sizeof(request), &operation) ==
		      SEP_KEYSTORE_ERROR_ARGUMENT,
	      "reject size_t configuration overflow");
}

static void test_relay_composition(void)
{
	uint8_t request[SEP_RELAY_DATA_CAPACITY] = { 0 };
	uint8_t transfer[SEP_RELAY_BUFFER_SIZE] = { 0 };
	const uint8_t *message = transfer + SEP_RELAY_MESSAGE_OFFSET;
	struct sep_keystore_state keystore_state = { 0 };
	struct sep_relay_state relay_state = { 0 };
	struct sep_keystore_operation operation = { 0 };
	struct sep_relay_pending pending = { 0 };

	check(prepare_wrapped_request(&keystore_state, &relay_state, request,
				      transfer, &operation, &pending) ==
		      SEP_KEYSTORE_OK,
	      "compose sealed request with relay");
	check(pending.kind == SEP_RELAY_REQUEST_KEYSTORE &&
		      pending.selector == operation.selector &&
		      pending.transaction == operation.transaction,
	      "preserve selector and transaction in relay identity");
	check(load_u32_le(message + 4) == SEP_RELAY_KEYSTORE_ENDPOINT &&
		      message[9] == operation.selector &&
		      message[10] == operation.transaction &&
		      load_u16_le(message + 14) == operation.request_length,
	      "encode typed keystore relay header");
	check(load_u64_le(message + REQUEST_TOKEN_OFFSET) == pending.token &&
		      load_u64_le(message + REPLY_TOKEN_OFFSET) == 0,
	      "use opaque relay token instead of pointer");
	check(load_u32_le(message + MESSAGE_INDEX_OFFSET) ==
		      pending.message_index &&
		      load_u32_le(message + DATA_LENGTH_OFFSET) ==
			      operation.request_length,
	      "encode relay request identity and length");
	check(memcmp(transfer, request, operation.request_length) == 0,
	      "copy only sealed IPC bytes into relay data");
	request[RESULT_OFFSET] ^= 1;
	check(sep_keystore_wrap_request(&relay_state, &operation, request,
					operation.request_length, transfer, &pending) ==
		      SEP_KEYSTORE_ERROR_HASH,
	      "reject corrupted request before relay wrapping");
	check(sep_keystore_wrap_request(&relay_state, &operation, request,
					operation.request_length - 1, transfer,
					&pending) == SEP_KEYSTORE_ERROR_LENGTH,
	      "reject a request buffer shorter than its operation");
}

static int parse_reply_fixture(
	const struct sep_keystore_operation *operation,
	const struct sep_relay_pending *pending,
	uint8_t transfer[SEP_RELAY_BUFFER_SIZE], struct sep_keystore_reply *reply)
{
	struct sep_relay_message message = { 0 };
	int result = sep_relay_parse(transfer, SEP_RELAY_BUFFER_SIZE, &message);

	if (result != SEP_RELAY_OK)
		return SEP_KEYSTORE_ERROR_RELAY;
	return sep_keystore_parse_reply(&message, pending, operation, reply);
}

static void test_typed_replies(void)
{
	uint8_t request[SEP_RELAY_DATA_CAPACITY] = { 0 };
	uint8_t transfer[SEP_RELAY_BUFFER_SIZE] = { 0 };
	uint8_t typed[128];
	struct sep_keystore_state keystore_state = { 0 };
	struct sep_relay_state relay_state = { 0 };
	struct sep_keystore_operation operation = { 0 };
	struct sep_relay_pending pending = { 0 };
	struct sep_keystore_reply reply = { 0 };

	check(prepare_wrapped_request(&keystore_state, &relay_state, request,
				      transfer, &operation, &pending) ==
		      SEP_KEYSTORE_OK,
	      "prepare reply identity");
	operation.kind = SEP_KEYSTORE_OPERATION_CREATE;
	operation.selector = SEP_KEYSTORE_SELECTOR_CREATE;
	pending.selector = operation.selector;
	store_u32_le(typed, 37);
	build_reply(transfer, &pending, 0, 0, typed, sizeof(uint32_t));
	check(parse_reply_fixture(&operation, &pending, transfer, &reply) ==
		      SEP_KEYSTORE_OK,
	      "parse created handle reply");
	check(reply.kind == SEP_KEYSTORE_REPLY_VALUE && reply.value == 37,
	      "return created handle");

	operation.kind = SEP_KEYSTORE_OPERATION_SERIALIZE;
	operation.selector = SEP_KEYSTORE_SELECTOR_SERIALIZE;
	pending.selector = operation.selector;
	store_u32_le(typed, 5);
	memcpy(typed + 4, (const uint8_t[]){ 2, 4, 6, 8, 10 }, 5);
	build_reply(transfer, &pending, 0, 0, typed, 9);
	check(parse_reply_fixture(&operation, &pending, transfer, &reply) ==
		      SEP_KEYSTORE_OK,
	      "parse opaque serialized keybag");
	check(reply.kind == SEP_KEYSTORE_REPLY_OPAQUE &&
		      reply.opaque_length == 5 && reply.opaque[4] == 10,
	      "return bounded opaque keybag without interpretation");

	operation.kind = SEP_KEYSTORE_OPERATION_DEVICE_STATE;
	operation.selector = SEP_KEYSTORE_SELECTOR_DEVICE_STATE;
	pending.selector = operation.selector;
	store_u32_le(typed, 91);
	memset(typed + sizeof(uint32_t), 0x5a, 91);
	typed[95] = 0;
	build_reply(transfer, &pending, 0, 0, typed, 96);
	check(parse_reply_fixture(&operation, &pending, transfer, &reply) ==
		      SEP_KEYSTORE_OK && reply.kind == SEP_KEYSTORE_REPLY_OPAQUE &&
		      reply.opaque_length == 91,
	      "parse padded live device-state value");

	operation.kind = SEP_KEYSTORE_OPERATION_COPY_UUID;
	operation.selector = SEP_KEYSTORE_SELECTOR_COPY_UUID;
	pending.selector = operation.selector;
	store_u32_le(typed, SEP_KEYSTORE_UUID_SIZE);
	memset(typed + 4, 0x77, SEP_KEYSTORE_UUID_SIZE);
	build_reply(transfer, &pending, 0, 0, typed,
		       4 + SEP_KEYSTORE_UUID_SIZE);
	check(parse_reply_fixture(&operation, &pending, transfer, &reply) ==
		      SEP_KEYSTORE_OK &&
		      reply.opaque_length == SEP_KEYSTORE_UUID_SIZE,
	      "parse exact keybag UUID length");

	operation.kind = SEP_KEYSTORE_OPERATION_LOCK_STATE;
	operation.selector = SEP_KEYSTORE_SELECTOR_LOCK_STATE;
	pending.selector = operation.selector;
	store_u32_le(typed, 4);
	store_u64_le(typed + 4, UINT64_C(0x1020304050607080));
	build_reply(transfer, &pending, 0, 0, typed, 12);
	check(parse_reply_fixture(&operation, &pending, transfer, &reply) ==
		      SEP_KEYSTORE_OK,
	      "parse lock-state reply");
	check(reply.kind == SEP_KEYSTORE_REPLY_VALUE_AND_FLAGS &&
		      reply.value == 4 &&
		      reply.first_wide_value == UINT64_C(0x1020304050607080),
	      "return lock state and flags");

	operation.kind = SEP_KEYSTORE_OPERATION_UNLOCK;
	operation.selector = SEP_KEYSTORE_SELECTOR_UNLOCK;
	pending.selector = operation.selector;
	store_u64_le(typed, 11);
	store_u64_le(typed + 8, 12);
	build_reply(transfer, &pending, 0, 0, typed, 16);
	check(parse_reply_fixture(&operation, &pending, transfer, &reply) ==
		      SEP_KEYSTORE_OK,
	      "parse unlock state pair");
	check(reply.kind == SEP_KEYSTORE_REPLY_STATE_PAIR &&
		      reply.first_wide_value == 11 && reply.second_wide_value == 12,
	      "return unlock state values");

	operation.kind = SEP_KEYSTORE_OPERATION_VERIFY_SECRET;
	operation.selector = SEP_KEYSTORE_SELECTOR_VERIFY_SECRET;
	pending.selector = operation.selector;
	memset(typed, 0, sizeof(uint32_t));
	build_reply(transfer, &pending, 0, 0, typed, sizeof(uint32_t));
	check(parse_reply_fixture(&operation, &pending, transfer, &reply) ==
		      SEP_KEYSTORE_OK && reply.kind == SEP_KEYSTORE_REPLY_NONE,
	      "parse status-only verification reply with alignment padding");

	operation.kind = SEP_KEYSTORE_OPERATION_SET_ENVIRONMENT;
	operation.selector = SEP_KEYSTORE_SELECTOR_SET_ENVIRONMENT;
	pending.selector = operation.selector;
	build_reply(transfer, &pending, 0, 0, NULL, 0);
	store_u32_le(transfer, 0x48);
	store_u32_le(transfer + 0x4c, 0);
	store_u16_le(transfer + SEP_RELAY_MESSAGE_OFFSET + 14, 0x50);
	store_u32_le(transfer + SEP_RELAY_MESSAGE_OFFSET + DATA_LENGTH_OFFSET,
		     0x50);
	check(parse_reply_fixture(&operation, &pending, transfer, &reply) ==
		      SEP_KEYSTORE_OK && reply.kind == SEP_KEYSTORE_REPLY_NONE,
	      "parse live short-header environment reply");
}

static void test_reply_rejections(void)
{
	uint8_t request[SEP_RELAY_DATA_CAPACITY] = { 0 };
	uint8_t transfer[SEP_RELAY_BUFFER_SIZE] = { 0 };
	uint8_t typed[8];
	struct sep_keystore_state keystore_state = { 0 };
	struct sep_relay_state relay_state = { 0 };
	struct sep_keystore_operation operation = { 0 };
	struct sep_relay_pending pending = { 0 };
	struct sep_keystore_reply reply = { 0 };
	struct sep_relay_message message = { 0 };

	check(prepare_wrapped_request(&keystore_state, &relay_state, request,
				      transfer, &operation, &pending) ==
		      SEP_KEYSTORE_OK,
	      "prepare rejection identity");
	operation.kind = SEP_KEYSTORE_OPERATION_CREATE;
	operation.selector = SEP_KEYSTORE_SELECTOR_CREATE;
	pending.selector = operation.selector;
	store_u32_le(typed, 9);
	build_reply(transfer, &pending, 0, 0, typed, 4);
	transfer[sizeof(uint32_t)] ^= 1;
	check(parse_reply_fixture(&operation, &pending, transfer, &reply) ==
		      SEP_KEYSTORE_OK && reply.kind == SEP_KEYSTORE_REPLY_VALUE &&
		      reply.value == 9,
	      "accept live reply with non-authoritative integrity field");
	build_reply(transfer, &pending, 0, 0, typed, 3);
	check(parse_reply_fixture(&operation, &pending, transfer, &reply) ==
		      SEP_KEYSTORE_ERROR_LENGTH,
	      "reject truncated typed output");
	build_reply(transfer, &pending, -3, 0, NULL, 0);
	check(parse_reply_fixture(&operation, &pending, transfer, &reply) ==
		      SEP_KEYSTORE_REMOTE_ERROR && reply.outer_result == -3,
	      "return redacted outer result only");
	build_reply(transfer, &pending, 0, -3, NULL, 0);
	check(parse_reply_fixture(&operation, &pending, transfer, &reply) ==
		      SEP_KEYSTORE_REMOTE_ERROR && reply.inner_result == -3,
	      "return redacted inner result only");
	build_reply(transfer, &pending, 0, 0, typed, 4);
	transfer[SEP_RELAY_MESSAGE_OFFSET + 10]++;
	check(sep_relay_parse(transfer, sizeof(transfer), &message) == SEP_RELAY_OK,
	      "parse wrong transaction fixture");
	memset(&reply, 0xa5, sizeof(reply));
	check(sep_keystore_parse_reply(&message, &pending, &operation, &reply) ==
		      SEP_KEYSTORE_ERROR_RELAY,
	      "reject wrong reply transaction");
	check(reply.opaque == NULL && reply.opaque_length == 0 &&
		      reply.outer_result == 0 && reply.inner_result == 0,
	      "clear stale reply data on rejected transaction");
	build_reply(transfer, &pending, 0, 0, typed, 4);
	store_u64_le(transfer + SEP_RELAY_MESSAGE_OFFSET + REPLY_TOKEN_OFFSET,
			     0);
	check(sep_relay_parse(transfer, sizeof(transfer), &message) == SEP_RELAY_OK,
	      "parse non-echoing token fixture");
	check(sep_keystore_parse_reply(&message, &pending, &operation, &reply) ==
		      SEP_KEYSTORE_OK,
	      "accept live non-authoritative reply token");
	build_reply(transfer, &pending, 0, 0, typed, 4);
	store_u32_le(transfer + SEP_RELAY_MESSAGE_OFFSET + DATA_LENGTH_OFFSET,
		     load_u32_le(transfer + SEP_RELAY_MESSAGE_OFFSET +
				 DATA_LENGTH_OFFSET) + 4);
	check(sep_relay_parse(transfer, sizeof(transfer), &message) == SEP_RELAY_OK,
	      "parse padded reply data fixture");
	check(sep_keystore_parse_reply(&message, &pending, &operation, &reply) ==
		      SEP_KEYSTORE_OK,
	      "accept proven relay data padding");
	build_reply(transfer, &pending, 0, 0, typed, 4);
	store_u32_le(transfer + SEP_RELAY_MESSAGE_OFFSET + DATA_LENGTH_OFFSET, 4);
	check(sep_relay_parse(transfer, sizeof(transfer), &message) == SEP_RELAY_OK,
	      "parse truncated reply data fixture");
	check(sep_keystore_parse_reply(&message, &pending, &operation, &reply) ==
		      SEP_KEYSTORE_ERROR_LENGTH,
	      "reject declared payload beyond relay data");
	build_reply(transfer, &pending, 0, 0, typed, 4);
	store_u32_le(transfer + SEP_RELAY_MESSAGE_OFFSET + MESSAGE_LENGTH_OFFSET,
		     9);
	check(sep_relay_parse(transfer, sizeof(transfer), &message) == SEP_RELAY_OK,
	      "parse extended keystore header fixture");
	check(sep_keystore_parse_reply(&message, &pending, &operation, &reply) ==
		      SEP_KEYSTORE_OK,
	      "accept proven extended keystore header framing");
	build_reply(transfer, &pending, 0, 0, typed, 4);
	check(sep_relay_parse(transfer, sizeof(transfer), &message) == SEP_RELAY_OK,
	      "parse operation transaction mismatch fixture");
	operation.transaction++;
	check(sep_keystore_parse_reply(&message, &pending, &operation, &reply) ==
		      SEP_KEYSTORE_ERROR_TRANSACTION,
	      "reject operation transaction mismatch");
	operation.transaction--;
	operation.selector++;
	check(sep_keystore_parse_reply(&message, &pending, &operation, &reply) ==
		      SEP_KEYSTORE_ERROR_SELECTOR,
	      "reject operation selector mismatch");
}

static void test_transaction_exhaustion(void)
{
	uint8_t request[SEP_RELAY_DATA_CAPACITY];
	struct sep_keystore_state state = { 0 };
	struct sep_keystore_operation first = { 0 };
	struct sep_keystore_operation unused = { 0 };

	check(sep_keystore_state_init(&state, 1, UINT8_MAX) == SEP_KEYSTORE_OK,
	      "initialize final transaction");
	check(sep_keystore_build_capabilities(&state, 1, request,
					      sizeof(request), &first) ==
		      SEP_KEYSTORE_OK,
	      "issue final transaction");
	check(first.transaction == UINT8_MAX && state.transaction_exhausted,
	      "record final transaction without wrap");
	check(sep_keystore_build_capabilities(&state, 2, request,
					      sizeof(request), &unused) ==
		      SEP_KEYSTORE_ERROR_EXHAUSTED,
	      "reject transaction reuse after exhaustion");
	check(all_zero(request, 0x64),
	      "wipe request rejected after transaction exhaustion");
	check(state.next_transaction == UINT8_MAX,
	      "never wrap transaction counter");
	check(sep_keystore_state_init(NULL, 1, 1) ==
		      SEP_KEYSTORE_ERROR_ARGUMENT,
	      "reject null keystore state");
	check(sep_keystore_state_init(&state, 0, 1) ==
		      SEP_KEYSTORE_ERROR_ARGUMENT,
	      "reject zero client context");
}

int main(void)
{
	test_seal_contract();
	test_capabilities_and_create();
	test_keybag_builders();
	test_configuration_builders();
	test_relay_composition();
	test_typed_replies();
	test_reply_rejections();
	test_transaction_exhaustion();
	if (failures != 0) {
		fprintf(stderr, "%d test failure(s)\n", failures);
		return 1;
	}
	puts("sep_keystore: all tests passed");
	return 0;
}

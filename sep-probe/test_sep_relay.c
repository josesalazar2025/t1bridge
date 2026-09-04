#include "sep_relay.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

#define MESSAGE_INDEX_OFFSET 0x88U
#define REPLY_TOKEN_OFFSET 0x8cU
#define REQUEST_TOKEN_OFFSET 0x98U
#define HAS_BUFFER_OFFSET 0xa0U
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

static void build_response(uint8_t output[SEP_RELAY_BUFFER_SIZE],
			   uint32_t endpoint, const uint8_t *message_payload,
			   size_t message_length, const uint8_t *data,
			   size_t data_length, uint64_t reply_token)
{
	uint8_t *message = output + SEP_RELAY_MESSAGE_OFFSET;

	memset(output, 0, SEP_RELAY_BUFFER_SIZE);
	if (data_length != 0)
		memcpy(output, data, data_length);
	message[0] = SEP_RELAY_WIRE_VERSION;
	store_u32_le(message + 4, endpoint);
	if (message_length != 0)
		memcpy(message + 8, message_payload, message_length);
	store_u64_le(message + REPLY_TOKEN_OFFSET, reply_token);
	store_u32_le(message + MESSAGE_LENGTH_OFFSET, (uint32_t)message_length);
	store_u32_le(message + DATA_LENGTH_OFFSET, (uint32_t)data_length);
}

static int negotiate(struct sep_relay_state *state)
{
	uint8_t transfer[SEP_RELAY_BUFFER_SIZE];
	uint8_t payload[2 + SEP_RELAY_ENDPOINT_COUNT] = { 6,
							     SEP_RELAY_ENDPOINT_COUNT };
	struct sep_relay_pending pending;
	struct sep_relay_message message;
	int result;

	result = sep_relay_state_init(state, UINT64_C(0x1020304050607080), 7);
	if (result != SEP_RELAY_OK)
		return result;
	result = sep_relay_build_get_version(state, transfer, &pending);
	if (result != SEP_RELAY_OK)
		return result;
	build_response(transfer, SEP_RELAY_CONTROL_ENDPOINT,
		       (const uint8_t[]){ 1 }, 1, NULL, 0, pending.token);
	result = sep_relay_parse(transfer, sizeof(transfer), &message);
	if (result != SEP_RELAY_OK)
		return result;
	result = sep_relay_accept_version(state, &message, &pending);
	if (result != SEP_RELAY_OK)
		return result;

	for (size_t index = 0; index < SEP_RELAY_ENDPOINT_COUNT; index++)
		payload[index + 2] = (uint8_t)(index % 3);
	result = sep_relay_build_endpoint_status(state, transfer, &pending);
	if (result != SEP_RELAY_OK)
		return result;
	build_response(transfer, SEP_RELAY_CONTROL_ENDPOINT, payload,
		       sizeof(payload), NULL, 0, pending.token);
	result = sep_relay_parse(transfer, sizeof(transfer), &message);
	if (result != SEP_RELAY_OK)
		return result;
	return sep_relay_accept_endpoint_status(state, &message, &pending);
}

static void test_get_version_wire(void)
{
	uint8_t transfer[SEP_RELAY_BUFFER_SIZE];
	const uint8_t *message = transfer + SEP_RELAY_MESSAGE_OFFSET;
	struct sep_relay_state state;
	struct sep_relay_pending pending;
	const uint64_t token = UINT64_C(0x1122334455667788);

	check(sep_relay_state_init(NULL, token, 9) == SEP_RELAY_ERROR_ARGUMENT,
	      "reject null relay state");
	check(sep_relay_state_init(&state, 0, 9) == SEP_RELAY_ERROR_ARGUMENT,
	      "reject zero initial token");
	check(sep_relay_state_init(&state, token, 9) == SEP_RELAY_OK,
	      "initialize relay state");
	check(sep_relay_build_get_version(&state, transfer, &pending) ==
		      SEP_RELAY_OK,
	      "build get-version request");
	check(message[0] == SEP_RELAY_WIRE_VERSION, "encode relay version");
	check(load_u32_le(message + 4) == SEP_RELAY_CONTROL_ENDPOINT,
	      "encode control endpoint");
	check(message[8] == 1, "encode get-version selector");
	check(load_u32_le(message + MESSAGE_INDEX_OFFSET) == 9,
	      "encode message index");
	check(load_u64_le(message + REQUEST_TOKEN_OFFSET) == token,
	      "encode opaque request token");
	check(load_u64_le(message + REPLY_TOKEN_OFFSET) == 0,
	      "leave request reply token empty");
	check(load_u32_le(message + HAS_BUFFER_OFFSET) == 1,
	      "encode backing-buffer flag");
	check(load_u32_le(message + MESSAGE_LENGTH_OFFSET) == 1,
	      "encode get-version length");
	check(load_u32_le(message + DATA_LENGTH_OFFSET) == 0,
	      "encode empty get-version data");
	check(pending.token == token && pending.message_index == 9,
	      "return get-version identity");
	check(state.next_token == token + 1 && state.next_message_index == 10,
	      "advance monotonic identities");
}

static void test_version_matching(void)
{
	uint8_t transfer[SEP_RELAY_BUFFER_SIZE];
	struct sep_relay_state state;
	struct sep_relay_pending pending;
	struct sep_relay_message message;
	uint8_t version_payload[] = { 1 };

	check(sep_relay_state_init(&state, 41, 0) == SEP_RELAY_OK,
	      "initialize version test");
	check(sep_relay_build_get_version(&state, transfer, &pending) ==
		      SEP_RELAY_OK,
	      "build version identity");
	build_response(transfer, SEP_RELAY_CONTROL_ENDPOINT, version_payload,
		       sizeof(version_payload), NULL, 0, pending.token);
	check(sep_relay_parse(transfer, sizeof(transfer), &message) == SEP_RELAY_OK,
	      "parse version response");
	check(sep_relay_accept_version(&state, &message, &pending) == SEP_RELAY_OK,
	      "accept exact version response");
	check(state.version_confirmed == 1, "record version negotiation");

	check(sep_relay_state_init(&state, 51, 0) == SEP_RELAY_OK,
	      "reset version test");
	check(sep_relay_build_get_version(&state, transfer, &pending) ==
		      SEP_RELAY_OK,
	      "build reset version identity");
	build_response(transfer, SEP_RELAY_KEYSTORE_ENDPOINT, version_payload,
		       sizeof(version_payload), NULL, 0, pending.token);
	check(sep_relay_parse(transfer, sizeof(transfer), &message) == SEP_RELAY_OK,
	      "parse wrong-endpoint version response");
	check(sep_relay_accept_version(&state, &message, &pending) ==
		      SEP_RELAY_ERROR_ENDPOINT,
	      "reject wrong version endpoint");
	build_response(transfer, SEP_RELAY_CONTROL_ENDPOINT,
		       (const uint8_t[]){ 6 }, 1, NULL, 0, pending.token);
	check(sep_relay_parse(transfer, sizeof(transfer), &message) == SEP_RELAY_OK,
	      "parse wrong-selector version response");
	check(sep_relay_accept_version(&state, &message, &pending) ==
		      SEP_RELAY_ERROR_SELECTOR,
	      "reject wrong version selector");
	build_response(transfer, SEP_RELAY_CONTROL_ENDPOINT, version_payload,
		       sizeof(version_payload), NULL, 0, pending.token + 1);
	check(sep_relay_parse(transfer, sizeof(transfer), &message) == SEP_RELAY_OK,
	      "parse token-independent version response");
	check(sep_relay_accept_version(&state, &message, &pending) ==
		      SEP_RELAY_OK,
	      "accept serialized control reply without token authority");
	transfer[SEP_RELAY_MESSAGE_OFFSET] = 1;
	check(sep_relay_parse(transfer, sizeof(transfer), &message) ==
		      SEP_RELAY_ERROR_VERSION,
	      "reject wrong wire version");
}

static void test_endpoint_negotiation(void)
{
	uint8_t transfer[SEP_RELAY_BUFFER_SIZE];
	const uint8_t *header = transfer + SEP_RELAY_MESSAGE_OFFSET;
	struct sep_relay_state state;
	struct sep_relay_pending pending;
	struct sep_relay_message message;
	uint8_t states[2 + SEP_RELAY_ENDPOINT_COUNT] = { 6,
							    SEP_RELAY_ENDPOINT_COUNT };

	check(sep_relay_state_init(&state, 71, 3) == SEP_RELAY_OK,
	      "initialize endpoint negotiation");
	state.version_confirmed = 1;
	state.local_endpoint_states[2] = 1;
	check(sep_relay_build_endpoint_status(&state, transfer, &pending) ==
		      SEP_RELAY_OK,
	      "build endpoint-status request");
	check(load_u32_le(header + MESSAGE_LENGTH_OFFSET) == sizeof(states),
	      "encode endpoint-status length");
	check(header[8] == 6 && header[9] == SEP_RELAY_ENDPOINT_COUNT,
	      "encode endpoint-status selector and count");
	check(header[12] == 1, "encode local endpoint state");

	for (size_t index = 0; index < SEP_RELAY_ENDPOINT_COUNT; index++)
		states[index + 2] = (uint8_t)(2 - index % 3);
	build_response(transfer, SEP_RELAY_CONTROL_ENDPOINT, states,
		       sizeof(states), NULL, 0, pending.token + 1);
	check(sep_relay_parse(transfer, sizeof(transfer), &message) == SEP_RELAY_OK,
	      "parse endpoint-status response");
	check(sep_relay_accept_endpoint_status(&state, &message, &pending) ==
		      SEP_RELAY_OK,
	      "accept endpoint-status response");
	check(state.endpoint_status_confirmed == 1 &&
		      state.peer_endpoint_count == SEP_RELAY_ENDPOINT_COUNT,
	      "record endpoint negotiation");
	check(memcmp(state.peer_endpoint_states, states + 2,
		     SEP_RELAY_ENDPOINT_COUNT) == 0,
	      "record peer endpoint states");

	check(sep_relay_state_init(&state, 81, 4) == SEP_RELAY_OK,
	      "reset endpoint negotiation");
	state.version_confirmed = 1;
	check(sep_relay_build_endpoint_status(&state, transfer, &pending) ==
		      SEP_RELAY_OK,
	      "build malformed-status identity");
	states[1] = SEP_RELAY_ENDPOINT_COUNT + 1;
	build_response(transfer, SEP_RELAY_CONTROL_ENDPOINT, states,
		       sizeof(states), NULL, 0, pending.token);
	check(sep_relay_parse(transfer, sizeof(transfer), &message) == SEP_RELAY_OK,
	      "parse malformed endpoint count");
	check(sep_relay_accept_endpoint_status(&state, &message, &pending) ==
		      SEP_RELAY_ERROR_LENGTH,
	      "reject oversized endpoint count");
}

static void test_endpoint_commands(void)
{
	uint8_t transfer[SEP_RELAY_BUFFER_SIZE];
	const uint8_t *header = transfer + SEP_RELAY_MESSAGE_OFFSET;
	struct sep_relay_state state;
	struct sep_relay_pending identity;
	uint32_t next_message_index;
	uint64_t next_token;
	struct sep_relay_pending completed = {
		.kind = SEP_RELAY_REQUEST_ACM,
		.token = UINT64_C(0x1234),
		.message_index = UINT32_C(0x1234567),
		.endpoint = SEP_RELAY_ACM_ENDPOINT,
		.selector = UINT8_C(1),
	};

	check(negotiate(&state) == SEP_RELAY_OK, "prepare endpoint commands");
	check(sep_relay_build_endpoint_enable(&state, 3, 1, transfer,
					      &identity) == SEP_RELAY_OK,
	      "build endpoint-enable command");
	check(header[8] == 2 && load_u32_le(header + 9) == 3 &&
		      load_u32_le(header + 13) == 1,
	      "encode endpoint-enable wire payload");
	check(state.local_endpoint_states[3] == 1,
	      "record enabled local endpoint");
	check(sep_relay_build_endpoint_enable(&state, 3, 0, transfer,
					      &identity) == SEP_RELAY_OK,
	      "build endpoint-disable command");
	check(state.local_endpoint_states[3] == 0,
	      "record disabled local endpoint");
	next_message_index = state.next_message_index;
	next_token = state.next_token;
	check(sep_relay_build_endpoint_ready(&state, 1, &completed, transfer,
					     &identity) == SEP_RELAY_OK,
	      "build endpoint-ready command");
	check(header[8] == 4 && load_u32_le(header + 9) == 1 &&
		      load_u32_le(header + 13) == 1,
	      "encode endpoint-ready wire payload");
	check(load_u32_le(header + MESSAGE_INDEX_OFFSET) ==
		      (completed.message_index | UINT32_C(0x80000000)),
	      "bind endpoint-ready to completed message index");
	check(identity.token == next_token && state.next_token == next_token + 1 &&
		      state.next_message_index == next_message_index,
	      "reserve a fresh token without consuming a normal message index");
	completed.message_index = UINT32_C(0x80000001);
	check(sep_relay_build_endpoint_ready(&state, 1, &completed, transfer,
					     &identity) ==
		      SEP_RELAY_ERROR_EXHAUSTED,
	      "reject endpoint-ready message-index aliasing");
	completed.message_index = 1;
	completed.token = 0;
	check(sep_relay_build_endpoint_ready(&state, 1, &completed, transfer,
					     &identity) ==
		      SEP_RELAY_ERROR_ARGUMENT,
	      "reject endpoint-ready without a completed token");
	check(sep_relay_build_endpoint_enable(&state, SEP_RELAY_ENDPOINT_COUNT,
					      1, transfer, &identity) ==
		      SEP_RELAY_ERROR_ENDPOINT,
	      "reject out-of-range endpoint");
	check(sep_relay_build_endpoint_enable(&state, 1, 2, transfer,
					      &identity) ==
		      SEP_RELAY_ERROR_ENDPOINT,
	      "reject invalid endpoint state");
}

static void test_keystore_wire_and_matching(void)
{
	uint8_t transfer[SEP_RELAY_BUFFER_SIZE];
	uint8_t request[] = { 0x10, 0x20, 0x30, 0x40, 0x50 };
	uint8_t reply_header[] = { 0, 0x92, 0x35, 0, 0, 0, 0, 0 };
	const uint8_t *header = transfer + SEP_RELAY_MESSAGE_OFFSET;
	struct sep_relay_state state;
	struct sep_relay_pending pending;
	struct sep_relay_message message;

	check(negotiate(&state) == SEP_RELAY_OK, "prepare keystore request");
	check(sep_relay_build_keystore_request(
		      &state, request, sizeof(request), 0x12, 0x35, transfer,
		      &pending) == SEP_RELAY_OK,
	      "build keystore request");
	check(memcmp(transfer, request, sizeof(request)) == 0,
	      "encode keystore request data");
	check(load_u32_le(header + 4) == SEP_RELAY_KEYSTORE_ENDPOINT,
	      "encode keystore endpoint");
	check(header[8] == 0 && header[9] == 0x12 && header[10] == 0x35,
	      "encode keystore selector and transaction");
	check(load_u16_le(header + 14) == sizeof(request),
	      "encode declared keystore length");
	check(load_u32_le(header + MESSAGE_LENGTH_OFFSET) == 8 &&
		      load_u32_le(header + DATA_LENGTH_OFFSET) == sizeof(request),
	      "encode keystore wire lengths");

	build_response(transfer, SEP_RELAY_KEYSTORE_ENDPOINT, reply_header,
		       sizeof(reply_header), request, sizeof(request), 0);
	check(sep_relay_parse(transfer, sizeof(transfer), &message) == SEP_RELAY_OK,
	      "parse keystore response");
	check(sep_relay_matches(&message, &pending) == SEP_RELAY_MATCHED,
	      "match exact keystore response");
	reply_header[1] = 0x93;
	build_response(transfer, SEP_RELAY_KEYSTORE_ENDPOINT, reply_header,
		       sizeof(reply_header), request, sizeof(request), 0);
	check(sep_relay_parse(transfer, sizeof(transfer), &message) == SEP_RELAY_OK,
	      "parse wrong-selector response");
	check(sep_relay_matches(&message, &pending) == SEP_RELAY_ERROR_SELECTOR,
	      "reject wrong keystore selector");
	reply_header[1] = 0x92;
	reply_header[2] = 0x36;
	build_response(transfer, SEP_RELAY_KEYSTORE_ENDPOINT, reply_header,
		       sizeof(reply_header), request, sizeof(request), 0);
	check(sep_relay_parse(transfer, sizeof(transfer), &message) == SEP_RELAY_OK,
	      "parse wrong-transaction response");
	check(sep_relay_matches(&message, &pending) == SEP_RELAY_ERROR_SELECTOR,
	      "reject wrong keystore transaction");
	reply_header[2] = 0x35;
	build_response(transfer, SEP_RELAY_KEYSTORE_ENDPOINT, reply_header,
		       sizeof(reply_header), request, sizeof(request),
		       pending.token + 1);
	check(sep_relay_parse(transfer, sizeof(transfer), &message) == SEP_RELAY_OK,
	      "parse non-echoing-token response");
	check(sep_relay_matches(&message, &pending) == SEP_RELAY_MATCHED,
	      "ignore non-authoritative keystore reply token");
	build_response(transfer, SEP_RELAY_ACM_ENDPOINT, reply_header,
		       sizeof(reply_header), request, sizeof(request), pending.token);
	check(sep_relay_parse(transfer, sizeof(transfer), &message) == SEP_RELAY_OK,
	      "parse wrong-endpoint keystore response");
	check(sep_relay_matches(&message, &pending) == SEP_RELAY_ERROR_ENDPOINT,
	      "reject wrong keystore endpoint");

	check(sep_relay_build_keystore_request(
		      &state, request, SEP_RELAY_DATA_CAPACITY + 1U, 1, 1,
		      transfer, &pending) == SEP_RELAY_ERROR_ARGUMENT,
	      "reject oversized keystore request");
	check(sep_relay_build_keystore_request(&state, request, sizeof(request),
					       0x80, 1, transfer,
					       &pending) ==
		      SEP_RELAY_ERROR_ARGUMENT,
	      "reject reply-bit keystore selector");
}

static void test_acm_wire_and_matching(void)
{
	uint8_t transfer[SEP_RELAY_BUFFER_SIZE];
	uint8_t command[8] = { 'D', 'R', 'C', 'S', 1, 0, 0, 1 };
	uint8_t reply_header[10] = { 0, 7, 8, 0, 0, 0, 0, 0, 0, 0 };
	const uint8_t *header = transfer + SEP_RELAY_MESSAGE_OFFSET;
	struct sep_relay_state state;
	struct sep_relay_pending pending;
	struct sep_relay_message message;

	check(negotiate(&state) == SEP_RELAY_OK, "prepare ACM request");
	check(sep_relay_build_acm_request(&state, command, sizeof(command), 7,
					  transfer, &pending) == SEP_RELAY_OK,
	      "build ACM request");
	check(memcmp(transfer, command, sizeof(command)) == 0,
	      "encode ACM command data");
	check(load_u32_le(header + 4) == SEP_RELAY_ACM_ENDPOINT &&
		      header[8] == 1 && header[9] == 7,
	      "encode ACM relay header");
	check(load_u32_le(header + 10) == sizeof(command) &&
		      load_u32_le(header + 14) == 0,
	      "encode ACM lengths and result");
	build_response(transfer, SEP_RELAY_ACM_ENDPOINT, reply_header,
		       sizeof(reply_header), command, sizeof(command), 0);
	check(sep_relay_parse(transfer, sizeof(transfer), &message) == SEP_RELAY_OK,
	      "parse ACM response");
	check(sep_relay_matches(&message, &pending) == SEP_RELAY_MATCHED,
	      "match exact ACM response");
	reply_header[1] = 8;
	build_response(transfer, SEP_RELAY_ACM_ENDPOINT, reply_header,
		       sizeof(reply_header), command, sizeof(command), 0);
	check(sep_relay_parse(transfer, sizeof(transfer), &message) == SEP_RELAY_OK,
	      "parse wrong ACM selector");
	check(sep_relay_matches(&message, &pending) == SEP_RELAY_ERROR_SELECTOR,
	      "reject wrong ACM selector");
	check(sep_relay_build_acm_request(&state, command, 7, 1, transfer,
					  &pending) == SEP_RELAY_ERROR_ARGUMENT,
	      "reject truncated ACM command");
}

static void test_parse_bounds(void)
{
	uint8_t transfer[SEP_RELAY_BUFFER_SIZE + 1];
	struct sep_relay_message message;

	memset(transfer, 0, sizeof(transfer));
	transfer[SEP_RELAY_MESSAGE_OFFSET] = SEP_RELAY_WIRE_VERSION;
	check(sep_relay_parse(transfer,
			      SEP_RELAY_MESSAGE_OFFSET +
				      SEP_RELAY_V2_HEADER_SIZE - 1,
			      &message) == SEP_RELAY_ERROR_TRUNCATED,
	      "reject truncated relay header");
	check(sep_relay_parse(transfer, sizeof(transfer), &message) ==
		      SEP_RELAY_ERROR_LENGTH,
	      "reject oversized transfer");
	store_u32_le(transfer + SEP_RELAY_MESSAGE_OFFSET +
			     MESSAGE_LENGTH_OFFSET,
		     SEP_RELAY_MESSAGE_CAPACITY + 1U);
	check(sep_relay_parse(transfer, SEP_RELAY_BUFFER_SIZE, &message) ==
		      SEP_RELAY_ERROR_LENGTH,
	      "reject overflowing message length");
	store_u32_le(transfer + SEP_RELAY_MESSAGE_OFFSET +
			     MESSAGE_LENGTH_OFFSET,
		     0);
	store_u32_le(transfer + SEP_RELAY_MESSAGE_OFFSET + DATA_LENGTH_OFFSET,
		     SEP_RELAY_DATA_CAPACITY + 1U);
	check(sep_relay_parse(transfer, SEP_RELAY_BUFFER_SIZE, &message) ==
		      SEP_RELAY_ERROR_LENGTH,
	      "reject overflowing data length");
	check(sep_relay_parse(NULL, 0, &message) == SEP_RELAY_ERROR_ARGUMENT,
	      "reject null transfer");
}

static void test_async_skip_bound(void)
{
	uint8_t transfer[SEP_RELAY_BUFFER_SIZE];
	uint8_t request[8] = { 0 };
	uint8_t reply_header[8] = { 0, 0x81, 9, 0, 0, 0, 0, 0 };
	uint8_t notification[8] = { 3, 0, 0, 0, 4, 0, 0, 0 };
	struct sep_relay_state state;
	struct sep_relay_pending pending;
	struct sep_relay_waiter waiter;
	struct sep_relay_message message;
	enum sep_relay_message_class classification;

	check(negotiate(&state) == SEP_RELAY_OK, "prepare async wait");
	check(sep_relay_build_keystore_request(&state, request, sizeof(request),
					       1, 9, transfer,
					       &pending) == SEP_RELAY_OK,
	      "build async wait request");
	check(sep_relay_waiter_init(&waiter, &pending,
				    SEP_RELAY_DEFAULT_SKIP_LIMIT) == SEP_RELAY_OK,
	      "initialize bounded waiter");
	build_response(transfer, SEP_RELAY_KEYSTORE_ENDPOINT, notification,
		       sizeof(notification), NULL, 0, 0);
	for (size_t index = 1; index < SEP_RELAY_DEFAULT_SKIP_LIMIT; index++) {
		check(sep_relay_waiter_consume(&waiter, transfer,
					       SEP_RELAY_BUFFER_SIZE,
					       &classification, &message) ==
			      SEP_RELAY_SKIPPED,
		      "skip bounded asynchronous message");
		check(classification ==
			      SEP_RELAY_MESSAGE_KEYSTORE_NOTIFICATION,
		      "classify keystore notification");
	}
	check(sep_relay_waiter_consume(&waiter, transfer,
				       SEP_RELAY_BUFFER_SIZE, &classification,
				       &message) == SEP_RELAY_ERROR_SKIP_LIMIT,
	      "stop at asynchronous skip limit");

	check(sep_relay_waiter_init(&waiter, &pending,
				    SEP_RELAY_DEFAULT_SKIP_LIMIT) == SEP_RELAY_OK,
	      "reset bounded waiter");
	reply_header[2] = 10;
	build_response(transfer, SEP_RELAY_KEYSTORE_ENDPOINT, reply_header,
		       sizeof(reply_header), request, sizeof(request), 0);
	check(sep_relay_waiter_consume(&waiter, transfer, sizeof(transfer),
				       &classification, &message) ==
		      SEP_RELAY_SKIPPED,
	      "skip response carrying another transaction");
	check(classification == SEP_RELAY_MESSAGE_KEYSTORE_REPLY,
	      "classify unrelated keystore reply");
	reply_header[2] = 9;
	build_response(transfer, SEP_RELAY_KEYSTORE_ENDPOINT, reply_header,
		       sizeof(reply_header), request, sizeof(request), 0);
	check(sep_relay_waiter_consume(&waiter, transfer, sizeof(transfer),
				       &classification, &message) ==
		      SEP_RELAY_MATCHED,
	      "accept exact reply after unrelated response");
	check(classification == SEP_RELAY_MESSAGE_EXPECTED_REPLY,
	      "classify exact expected reply");
}

static void test_token_exhaustion(void)
{
	uint8_t transfer[SEP_RELAY_BUFFER_SIZE];
	struct sep_relay_state state;
	struct sep_relay_pending first;
	struct sep_relay_pending second;
	struct sep_relay_pending unused;

	check(sep_relay_state_init(&state, UINT64_MAX - 1U, 0) == SEP_RELAY_OK,
	      "initialize token exhaustion");
	check(sep_relay_build_get_version(&state, transfer, &first) ==
		      SEP_RELAY_OK,
	      "issue penultimate token");
	check(sep_relay_build_get_version(&state, transfer, &second) ==
		      SEP_RELAY_OK,
	      "issue final token");
	check(first.token == UINT64_MAX - 1U && second.token == UINT64_MAX &&
		      first.token != second.token,
	      "tokens remain monotonic and unique");
	check(sep_relay_build_get_version(&state, transfer, &unused) ==
		      SEP_RELAY_ERROR_EXHAUSTED,
	      "reject token reuse after exhaustion");
	check(state.next_token == UINT64_MAX,
	      "never wrap exhausted token counter");

	check(sep_relay_state_init(&state, 1, UINT32_MAX) == SEP_RELAY_OK,
	      "initialize message-index exhaustion");
	check(sep_relay_build_get_version(&state, transfer, &first) ==
		      SEP_RELAY_OK,
	      "issue final message index");
	check(first.message_index == UINT32_MAX,
	      "preserve final message index");
	check(sep_relay_build_get_version(&state, transfer, &unused) ==
		      SEP_RELAY_ERROR_EXHAUSTED,
	      "reject message-index reuse after exhaustion");
}

int main(void)
{
	test_get_version_wire();
	test_version_matching();
	test_endpoint_negotiation();
	test_endpoint_commands();
	test_keystore_wire_and_matching();
	test_acm_wire_and_matching();
	test_parse_bounds();
	test_async_skip_bound();
	test_token_exhaustion();
	if (failures != 0) {
		fprintf(stderr, "%d test failure(s)\n", failures);
		return 1;
	}
	puts("sep_relay: all tests passed");
	return 0;
}

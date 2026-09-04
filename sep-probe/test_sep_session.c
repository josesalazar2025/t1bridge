#include "sep_session.h"

#include <stdio.h>
#include <string.h>

#define HEADER_OFFSET SEP_RELAY_MESSAGE_OFFSET
#define REPLY_TOKEN_OFFSET 0x8cU
#define REQUEST_TOKEN_OFFSET 0x98U
#define MESSAGE_LENGTH_OFFSET 0xa4U
#define DATA_LENGTH_OFFSET 0xa8U
#define IPC_RESULT_OFFSET 0x54U

enum fake_mode {
	FAKE_NORMAL,
	FAKE_KEYSTORE_SKIP_ONCE,
	FAKE_KEYSTORE_NON_AUTHORITATIVE_HASH,
	FAKE_UNRELATED_STREAM,
	FAKE_ACM_OK,
	FAKE_ACM_REMOTE,
};

struct fake_transport {
	enum fake_mode mode;
	char calls[32];
	size_t call_count;
	unsigned int receive_count;
	unsigned int destroy_failures;
	unsigned int destroy_calls;
	uint64_t now;
	uint64_t clock_step;
	int bad_negotiation_token;
	uint64_t pending_token;
	uint8_t pending_selector;
	uint8_t pending_transaction;
	uint32_t pending_message_index;
	uint8_t last_send_selector;
	uint32_t last_ready_endpoint;
	uint32_t last_send_message_index;
};

static unsigned int failures;

#define EXPECT(condition) test_expect((condition), #condition, __LINE__)

static void test_expect(int condition, const char *expression, int line)
{
	if (!condition) {
		fprintf(stderr, "line %d: failed: %s\n", line, expression);
		failures++;
	}
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

static void build_response(uint8_t output[SEP_RELAY_BUFFER_SIZE],
			   uint32_t endpoint, const void *message_payload,
			   size_t message_length, const void *data,
			   size_t data_length, uint64_t reply_token)
{
	uint8_t *header = output + HEADER_OFFSET;

	memset(output, 0, SEP_RELAY_BUFFER_SIZE);
	if (data_length)
		memcpy(output, data, data_length);
	header[0] = SEP_RELAY_WIRE_VERSION;
	store_u32_le(header + 4, endpoint);
	if (message_length)
		memcpy(header + 8, message_payload, message_length);
	store_u64_le(header + REPLY_TOKEN_OFFSET, reply_token);
	store_u32_le(header + MESSAGE_LENGTH_OFFSET, (uint32_t)message_length);
	store_u32_le(header + DATA_LENGTH_OFFSET, (uint32_t)data_length);
}

static void build_control_reply(struct fake_transport *fake,
				const uint8_t *request,
				uint8_t response[SEP_RELAY_BUFFER_SIZE])
{
	const uint8_t *header = request + HEADER_OFFSET;
	uint64_t token = load_u64_le(header + REQUEST_TOKEN_OFFSET);
	uint8_t selector = header[8];

	if (fake->bad_negotiation_token)
		token++;
	if (selector == 1) {
		const uint8_t payload[] = { 1 };

		build_response(response, SEP_RELAY_CONTROL_ENDPOINT, payload,
			       sizeof(payload), NULL, 0, token);
	} else {
		uint8_t payload[2 + SEP_RELAY_ENDPOINT_COUNT] = {
			6, SEP_RELAY_ENDPOINT_COUNT,
		};

		payload[2 + SEP_RELAY_ACM_ENDPOINT] = 1;
		payload[2 + SEP_RELAY_KEYSTORE_ENDPOINT] = 1;
		build_response(response, SEP_RELAY_CONTROL_ENDPOINT, payload,
			       sizeof(payload), NULL, 0, token);
	}
}

static void build_unrelated(struct fake_transport *fake,
			    uint8_t response[SEP_RELAY_BUFFER_SIZE])
{
	const uint8_t payload[] = { 9 };

	build_response(response, SEP_RELAY_CONTROL_ENDPOINT, payload,
		       sizeof(payload), NULL, 0, fake->pending_token + 1);
}

static void build_keystore_reply(struct fake_transport *fake,
				 uint8_t response[SEP_RELAY_BUFFER_SIZE])
{
	uint8_t ipc[SEP_KEYSTORE_IPC_WIRE_HEADER_SIZE + sizeof(uint32_t)] = { 0 };
	uint8_t message[8] = { 0 };
	size_t ipc_length = sizeof(ipc);

	store_u32_le(ipc + IPC_RESULT_OFFSET, 0);
	EXPECT(sep_keystore_seal(ipc, ipc_length, UINT64_C(9001)) ==
	       SEP_KEYSTORE_OK);
	if (fake->mode == FAKE_KEYSTORE_NON_AUTHORITATIVE_HASH)
		ipc[4] ^= UINT8_C(0x80);
	message[1] = (uint8_t)(fake->pending_selector | UINT8_C(0x80));
	message[2] = fake->pending_transaction;
	store_u16_le(message + 6, (uint16_t)ipc_length);
	build_response(response, SEP_RELAY_KEYSTORE_ENDPOINT, message,
		       sizeof(message), ipc, ipc_length, 0);
}

static void build_acm_reply(struct fake_transport *fake,
			    uint8_t response[SEP_RELAY_BUFFER_SIZE])
{
	uint8_t message[10] = { 0 };

	message[1] = SEP_ACM_RELAY_REQUEST;
	if (fake->mode == FAKE_ACM_REMOTE)
		store_u32_le(message + 6, UINT32_C(0xfffffffb));
	build_response(response, SEP_RELAY_ACM_ENDPOINT, message,
		       sizeof(message), NULL, 0, 0);
}

static void record_call(struct fake_transport *fake, char call)
{
	if (fake->call_count < sizeof(fake->calls))
		fake->calls[fake->call_count++] = call;
}

static enum sep_urb_status fake_exchange(void *context,
					 const uint8_t *output,
					 size_t output_length, uint8_t *input,
					 size_t input_capacity,
					 unsigned int timeout_ms)
{
	struct fake_transport *fake = context;
	const uint8_t *header;
	uint32_t endpoint;

	EXPECT(output && input && output_length == SEP_RELAY_BUFFER_SIZE &&
	       input_capacity == SEP_RELAY_BUFFER_SIZE && timeout_ms > 0);
	record_call(fake, 'E');
	header = output + HEADER_OFFSET;
	endpoint = load_u32_le(header + 4);
	if (endpoint == SEP_RELAY_CONTROL_ENDPOINT) {
		build_control_reply(fake, output, input);
		return SEP_URB_OK;
	}
	fake->pending_token = load_u64_le(header + REQUEST_TOKEN_OFFSET);
	fake->pending_message_index = load_u32_le(header + 0x88U);
	fake->pending_selector = header[9];
	fake->pending_transaction = header[10];
	if (fake->mode == FAKE_KEYSTORE_SKIP_ONCE ||
	    fake->mode == FAKE_UNRELATED_STREAM)
		build_unrelated(fake, input);
	else if (endpoint == SEP_RELAY_KEYSTORE_ENDPOINT)
		build_keystore_reply(fake, input);
	else
		build_acm_reply(fake, input);
	return SEP_URB_OK;
}

static enum sep_urb_status fake_send_only(void *context,
					  const uint8_t *output,
					  size_t output_length,
					  unsigned int timeout_ms)
{
	struct fake_transport *fake = context;
	const uint8_t *header = output + HEADER_OFFSET;

	EXPECT(output_length == SEP_RELAY_BUFFER_SIZE && timeout_ms > 0);
	record_call(fake, 'S');
	fake->last_send_selector = header[8];
	fake->last_send_message_index = load_u32_le(header + 0x88U);
	if (header[8] == 4)
		fake->last_ready_endpoint = load_u32_le(header + 9);
	return SEP_URB_OK;
}

static enum sep_urb_status fake_receive_only(void *context, uint8_t *input,
					     size_t input_capacity,
					     unsigned int timeout_ms)
{
	struct fake_transport *fake = context;

	EXPECT(input && input_capacity == SEP_RELAY_BUFFER_SIZE && timeout_ms > 0);
	record_call(fake, 'R');
	fake->receive_count++;
	if (fake->mode == FAKE_UNRELATED_STREAM)
		build_unrelated(fake, input);
	else
		build_keystore_reply(fake, input);
	return SEP_URB_OK;
}

static enum sep_urb_status fake_destroy(void *context)
{
	struct fake_transport *fake = context;

	fake->destroy_calls++;
	if (fake->destroy_failures) {
		fake->destroy_failures--;
		return SEP_URB_RELEASE_FAILED;
	}
	return SEP_URB_OK;
}

static int fake_monotonic_ms(void *context, uint64_t *value)
{
	struct fake_transport *fake = context;

	*value = fake->now;
	fake->now += fake->clock_step;
	return 0;
}

static int initialize_session(struct sep_session *session,
			      struct fake_transport *fake)
{
	const struct sep_session_transport_ops ops = {
		.context = fake,
		.exchange = fake_exchange,
		.send_only = fake_send_only,
		.receive_only = fake_receive_only,
		.destroy = fake_destroy,
		.monotonic_ms = fake_monotonic_ms,
	};

	return sep_session_init_with_ops(session, &ops,
					 UINT64_C(0x1020304050607080),
					 UINT32_C(0x1020));
}

static int negotiate_session(struct sep_session *session,
			     struct fake_transport *fake)
{
	int result = initialize_session(session, fake);

	if (result != SEP_SESSION_OK)
		return result;
	return sep_session_negotiate(session, 1000);
}

static int all_zero(const uint8_t *bytes, size_t length)
{
	while (length) {
		if (*bytes++)
			return 0;
		length--;
	}
	return 1;
}

static void build_capabilities(uint8_t *request,
			       struct sep_keystore_operation *operation)
{
	struct sep_keystore_state state;

	EXPECT(sep_keystore_state_init(&state,
				       UINT64_C(0x8877665544332211), 7) ==
	       SEP_KEYSTORE_OK);
	EXPECT(sep_keystore_build_capabilities(
		       &state, 100, request, SEP_RELAY_DATA_CAPACITY, operation) ==
	       SEP_KEYSTORE_OK);
}

static int build_acm_initialize(void *context, struct sep_acm_state *state,
				struct sep_relay_state *relay,
				uint8_t output[SEP_RELAY_BUFFER_SIZE])
{
	(void)context;
	return sep_acm_build_initialize(state, relay, output);
}

static int fail_acm_builder(void *context, struct sep_acm_state *state,
			    struct sep_relay_state *relay,
			    uint8_t output[SEP_RELAY_BUFFER_SIZE])
{
	(void)context;
	(void)state;
	(void)relay;
	memset(output, 0xa5, SEP_RELAY_BUFFER_SIZE);
	return SEP_ACM_ERROR_ARGUMENT;
}

static void test_negotiation_uses_exact_directions(void)
{
	struct fake_transport fake = { 0 };
	struct sep_session session;
	const uint8_t expected_states[] = { 1, 1, 1 };

	EXPECT(negotiate_session(&session, &fake) == SEP_SESSION_OK);
	EXPECT(session.phase == SEP_SESSION_PHASE_READY);
	EXPECT(fake.call_count == 5 && memcmp(fake.calls, "EESSS", 5) == 0);
	EXPECT(session.relay.local_endpoint_states[1] == expected_states[0] &&
	       session.relay.local_endpoint_states[2] == expected_states[1] &&
	       session.relay.local_endpoint_states[3] == expected_states[2]);
	EXPECT(sep_session_negotiate(&session, 1000) ==
	       SEP_SESSION_ERROR_STATE);
	EXPECT(sep_session_destroy(&session) == SEP_SESSION_OK);
	EXPECT(fake.destroy_calls == 1);
}

static void test_keystore_skips_with_in_only(void)
{
	struct fake_transport fake = { 0 };
	struct sep_session session;
	struct sep_keystore_operation operation;
	struct sep_keystore_reply reply;
	uint8_t request[SEP_RELAY_DATA_CAPACITY] = { 0 };
	size_t call_start;

	EXPECT(negotiate_session(&session, &fake) == SEP_SESSION_OK);
	build_capabilities(request, &operation);
	fake.mode = FAKE_KEYSTORE_SKIP_ONCE;
	call_start = fake.call_count;
	EXPECT(sep_session_keystore_exchange(&session, &operation, request,
					     operation.request_length - 1, &reply,
					     1000) ==
	       SEP_SESSION_ERROR_ARGUMENT);
	EXPECT(fake.call_count == call_start);
	EXPECT(session.phase == SEP_SESSION_PHASE_READY);
	EXPECT(sep_session_keystore_exchange(&session, &operation, request,
					     operation.request_length, &reply,
					     1000) ==
	       SEP_SESSION_OK);
	EXPECT(fake.call_count == call_start + 2 &&
	       fake.calls[call_start] == 'E' && fake.calls[call_start + 1] == 'R');
	EXPECT(reply.kind == SEP_KEYSTORE_REPLY_OPAQUE &&
	       reply.opaque_length == 0);
	sep_session_clear_transfers(&session);
	EXPECT(all_zero(session.input, sizeof(session.input)));
	EXPECT(sep_session_destroy(&session) == SEP_SESSION_OK);
}

static void test_acm_reply_is_acknowledged_out_only(void)
{
	struct fake_transport fake = { 0 };
	struct sep_session session;
	struct sep_acm_state acm;
	struct sep_acm_outcome outcome;
	size_t call_start;

	EXPECT(negotiate_session(&session, &fake) == SEP_SESSION_OK);
	EXPECT(sep_acm_state_init(&acm) == SEP_ACM_OK);
	fake.mode = FAKE_ACM_OK;
	call_start = fake.call_count;
	EXPECT(sep_session_acm_exchange(&session, &acm, build_acm_initialize,
					NULL, &outcome, 1000) == SEP_SESSION_OK);
	EXPECT(fake.call_count == call_start + 2 &&
	       fake.calls[call_start] == 'E' && fake.calls[call_start + 1] == 'S');
	EXPECT(fake.last_send_selector == 4 &&
	       fake.last_ready_endpoint == SEP_RELAY_ACM_ENDPOINT);
	EXPECT(fake.last_send_message_index ==
	       (fake.pending_message_index | UINT32_C(0x80000000)));
	EXPECT(acm.phase == SEP_ACM_PHASE_READY &&
	       outcome.operation == SEP_ACM_OPERATION_INITIALIZE);
	sep_acm_state_wipe(&acm);
	EXPECT(sep_session_destroy(&session) == SEP_SESSION_OK);
}

static void test_known_acm_rejection_is_acknowledged_without_poison(void)
{
	struct fake_transport fake = { 0 };
	struct sep_session session;
	struct sep_acm_state acm;
	struct sep_acm_outcome outcome;
	size_t call_start;

	EXPECT(negotiate_session(&session, &fake) == SEP_SESSION_OK);
	EXPECT(sep_acm_state_init(&acm) == SEP_ACM_OK);
	fake.mode = FAKE_ACM_REMOTE;
	call_start = fake.call_count;
	EXPECT(sep_session_acm_exchange(&session, &acm, build_acm_initialize,
					NULL, &outcome, 1000) ==
	       SEP_SESSION_REMOTE_ERROR);
	EXPECT(fake.call_count == call_start + 2 &&
	       fake.calls[call_start] == 'E' && fake.calls[call_start + 1] == 'S');
	EXPECT(fake.last_send_selector == 4 &&
	       fake.last_ready_endpoint == SEP_RELAY_ACM_ENDPOINT);
	EXPECT(outcome.remote_result == -5 && acm.phase == SEP_ACM_PHASE_NEW &&
	       !acm.pending_valid);
	EXPECT(session.phase == SEP_SESSION_PHASE_READY);
	sep_acm_state_wipe(&acm);
	EXPECT(sep_session_destroy(&session) == SEP_SESSION_OK);
}

static void test_acm_builder_failure_clears_partial_transfer(void)
{
	struct fake_transport fake = { 0 };
	struct sep_session session;
	struct sep_acm_state acm;
	struct sep_acm_outcome outcome;
	size_t call_start;

	EXPECT(negotiate_session(&session, &fake) == SEP_SESSION_OK);
	EXPECT(sep_acm_state_init(&acm) == SEP_ACM_OK);
	call_start = fake.call_count;
	EXPECT(sep_session_acm_exchange(&session, &acm, fail_acm_builder,
					NULL, &outcome, 1000) ==
	       SEP_SESSION_ERROR_ARGUMENT);
	EXPECT(fake.call_count == call_start);
	EXPECT(all_zero(session.output, sizeof(session.output)) &&
	       all_zero(session.input, sizeof(session.input)));
	EXPECT(session.phase == SEP_SESSION_PHASE_READY);
	sep_acm_state_wipe(&acm);
	EXPECT(sep_session_destroy(&session) == SEP_SESSION_OK);
}

static void test_non_authoritative_hash_and_skip_limit(void)
{
	struct fake_transport fake = { 0 };
	struct sep_session session;
	struct sep_keystore_operation operation;
	struct sep_keystore_reply reply;
	uint8_t request[SEP_RELAY_DATA_CAPACITY] = { 0 };

	EXPECT(negotiate_session(&session, &fake) == SEP_SESSION_OK);
	build_capabilities(request, &operation);
	fake.mode = FAKE_KEYSTORE_NON_AUTHORITATIVE_HASH;
	EXPECT(sep_session_keystore_exchange(&session, &operation, request,
					     operation.request_length, &reply,
					     1000) ==
	       SEP_SESSION_OK);
	EXPECT(session.phase == SEP_SESSION_PHASE_READY);
	EXPECT(sep_session_destroy(&session) == SEP_SESSION_OK);

	memset(&fake, 0, sizeof(fake));
	EXPECT(negotiate_session(&session, &fake) == SEP_SESSION_OK);
	build_capabilities(request, &operation);
	fake.mode = FAKE_UNRELATED_STREAM;
	EXPECT(sep_session_keystore_exchange(&session, &operation, request,
					     operation.request_length, &reply,
					     1000) ==
	       SEP_SESSION_ERROR_SKIP_LIMIT);
	EXPECT(fake.receive_count == SEP_RELAY_DEFAULT_SKIP_LIMIT - 1);
	EXPECT(session.phase == SEP_SESSION_PHASE_POISONED);
	EXPECT(sep_session_destroy(&session) == SEP_SESSION_OK);
}

static void test_deadline_and_teardown_are_bounded(void)
{
	struct fake_transport fake = { 0 };
	struct sep_session session;
	struct sep_keystore_operation operation;
	struct sep_keystore_reply reply;
	uint8_t request[SEP_RELAY_DATA_CAPACITY] = { 0 };

	EXPECT(negotiate_session(&session, &fake) == SEP_SESSION_OK);
	build_capabilities(request, &operation);
	fake.mode = FAKE_KEYSTORE_SKIP_ONCE;
	fake.clock_step = 6;
	EXPECT(sep_session_keystore_exchange(&session, &operation, request,
					     operation.request_length, &reply, 10) ==
	       SEP_SESSION_ERROR_TIMEOUT);
	EXPECT(session.phase == SEP_SESSION_PHASE_POISONED);
	fake.destroy_failures = 1;
	EXPECT(sep_session_destroy(&session) == SEP_SESSION_ERROR_TEARDOWN);
	EXPECT(session.phase == SEP_SESSION_PHASE_CLOSED &&
	       fake.destroy_calls == 1);
	EXPECT(sep_session_destroy(&session) == SEP_SESSION_OK);
	EXPECT(session.phase == SEP_SESSION_PHASE_CLOSED &&
	       fake.destroy_calls == 1);
	EXPECT(all_zero((const uint8_t *)&session.transport,
		       sizeof(session.transport)) &&
	       all_zero((const uint8_t *)&session.relay, sizeof(session.relay)) &&
	       session.operation_deadline_ms == 0 &&
		       session.operation_deadline_set == 0);
}

static void test_live_deadline_can_be_released_and_replaced(void)
{
	struct fake_transport fake = { .now = 40 };
	struct sep_session session;
	struct sep_keystore_operation operation;
	struct sep_keystore_reply reply;
	uint8_t request[SEP_RELAY_DATA_CAPACITY] = { 0 };

	EXPECT(negotiate_session(&session, &fake) == SEP_SESSION_OK);
	EXPECT(sep_session_set_operation_deadline(&session, fake.now + 20) ==
	       SEP_SESSION_OK);
	EXPECT(sep_session_release_operation_deadline(&session) ==
	       SEP_SESSION_OK);
	EXPECT(session.operation_deadline_ms == 0 &&
	       session.operation_deadline_set == 0);

	/* A consumer-governed hold is not charged to the acquisition budget. */
	fake.now += 5000;
	EXPECT(sep_session_set_operation_deadline(&session, fake.now + 30) ==
	       SEP_SESSION_OK);
	build_capabilities(request, &operation);
	EXPECT(sep_session_keystore_exchange(
		       &session, &operation, request, operation.request_length,
		       &reply, 1000) == SEP_SESSION_OK);
	EXPECT(sep_session_destroy(&session) == SEP_SESSION_OK);
}

static void test_expired_deadline_cannot_be_released(void)
{
	struct fake_transport fake = { .now = 70 };
	struct sep_session session;

	EXPECT(negotiate_session(&session, &fake) == SEP_SESSION_OK);
	EXPECT(sep_session_set_operation_deadline(&session, fake.now + 1) ==
	       SEP_SESSION_OK);
	fake.now++;
	EXPECT(sep_session_release_operation_deadline(&session) ==
	       SEP_SESSION_ERROR_TIMEOUT);
	EXPECT(session.phase == SEP_SESSION_PHASE_POISONED &&
	       session.operation_deadline_set == 1);
	EXPECT(sep_session_destroy(&session) == SEP_SESSION_OK);
}

static void test_control_reply_tokens_are_not_transaction_authority(void)
{
	struct fake_transport fake = { .bad_negotiation_token = 1 };
	struct sep_session session;

	EXPECT(initialize_session(&session, &fake) == SEP_SESSION_OK);
	EXPECT(sep_session_negotiate(&session, 1000) == SEP_SESSION_OK);
	EXPECT(session.phase == SEP_SESSION_PHASE_READY);
	EXPECT(fake.call_count == 5 && memcmp(fake.calls, "EESSS", 5) == 0);
	EXPECT(sep_session_destroy(&session) == SEP_SESSION_OK);
}

int main(void)
{
	test_negotiation_uses_exact_directions();
	test_keystore_skips_with_in_only();
	test_acm_reply_is_acknowledged_out_only();
	test_known_acm_rejection_is_acknowledged_without_poison();
	test_acm_builder_failure_clears_partial_transfer();
	test_non_authoritative_hash_and_skip_limit();
	test_deadline_and_teardown_are_bounded();
	test_live_deadline_can_be_released_and_replaced();
	test_expired_deadline_cannot_be_released();
	test_control_reply_tokens_are_not_transaction_authority();
	if (failures) {
		fprintf(stderr, "sep_session: %u tests failed\n", failures);
		return 1;
	}
	puts("sep_session: all tests passed");
	return 0;
}

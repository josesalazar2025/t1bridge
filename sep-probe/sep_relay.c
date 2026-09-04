#include "sep_relay.h"

#include <limits.h>
#include <string.h>

#define RELAY_MESSAGE_INDEX_OFFSET 0x88U
#define RELAY_REPLY_TOKEN_OFFSET 0x8cU
#define RELAY_REQUEST_TOKEN_OFFSET 0x98U
#define RELAY_HAS_BUFFER_OFFSET 0xa0U
#define RELAY_MESSAGE_LENGTH_OFFSET 0xa4U
#define RELAY_DATA_LENGTH_OFFSET 0xa8U
#define RELAY_ACM_HEADER_SIZE 10U
#define RELAY_KEYSTORE_HEADER_SIZE 8U

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

static int reserve_identity(struct sep_relay_state *state,
			    enum sep_relay_request_kind kind,
			    uint32_t endpoint, uint8_t selector,
			    uint8_t transaction,
			    struct sep_relay_pending *pending)
{
	if (!state || !pending)
		return SEP_RELAY_ERROR_ARGUMENT;
	if (state->token_exhausted || state->message_index_exhausted)
		return SEP_RELAY_ERROR_EXHAUSTED;

	pending->kind = kind;
	pending->token = state->next_token;
	pending->message_index = state->next_message_index;
	pending->endpoint = endpoint;
	pending->selector = selector;
	pending->transaction = transaction;

	if (state->next_token == UINT64_MAX)
		state->token_exhausted = 1;
	else
		state->next_token++;
	if (state->next_message_index == UINT32_MAX)
		state->message_index_exhausted = 1;
	else
		state->next_message_index++;
	return SEP_RELAY_OK;
}

static void build_header(uint8_t output[SEP_RELAY_BUFFER_SIZE],
			 const struct sep_relay_pending *identity,
			 uint32_t message_length, uint32_t data_length)
{
	uint8_t *message = output + SEP_RELAY_MESSAGE_OFFSET;

	memset(output, 0, SEP_RELAY_BUFFER_SIZE);
	message[0] = SEP_RELAY_WIRE_VERSION;
	store_u32_le(message + 4, identity->endpoint);
	store_u32_le(message + RELAY_MESSAGE_INDEX_OFFSET,
		     identity->message_index);
	store_u64_le(message + RELAY_REQUEST_TOKEN_OFFSET, identity->token);
	store_u32_le(message + RELAY_HAS_BUFFER_OFFSET, 1);
	store_u32_le(message + RELAY_MESSAGE_LENGTH_OFFSET, message_length);
	store_u32_le(message + RELAY_DATA_LENGTH_OFFSET, data_length);
}

static int build_control(struct sep_relay_state *state, const uint8_t *payload,
			 size_t payload_length,
			 uint8_t output[SEP_RELAY_BUFFER_SIZE],
			 struct sep_relay_pending *pending)
{
	int result;

	if (!state || !payload || !output || !pending || payload_length == 0 ||
	    payload_length > SEP_RELAY_MESSAGE_CAPACITY)
		return SEP_RELAY_ERROR_ARGUMENT;
	result = reserve_identity(state, SEP_RELAY_REQUEST_CONTROL,
				  SEP_RELAY_CONTROL_ENDPOINT, payload[0], 0,
				  pending);
	if (result != SEP_RELAY_OK)
		return result;
	build_header(output, pending, (uint32_t)payload_length, 0);
	memcpy(output + SEP_RELAY_MESSAGE_OFFSET + 8, payload, payload_length);
	return SEP_RELAY_OK;
}

static int pending_matches_header(const struct sep_relay_message *message,
				  const struct sep_relay_pending *pending)
{
	if (!message || !pending)
		return SEP_RELAY_ERROR_ARGUMENT;
	if (message->version != SEP_RELAY_WIRE_VERSION)
		return SEP_RELAY_ERROR_VERSION;
	if (message->endpoint != pending->endpoint)
		return SEP_RELAY_ERROR_ENDPOINT;
	/*
	 * BridgeOS leaves reply_token zero on live control, AppleKeyStore, and ACM
	 * replies. Outbound tokens remain fresh request identities, but are not
	 * reply-correlation authority. Each synchronous endpoint exchange is
	 * correlated by its endpoint and protocol-specific selector/transaction.
	 */
	return SEP_RELAY_OK;
}

static int pending_matches_control_header(
	const struct sep_relay_message *message,
	const struct sep_relay_pending *pending)
{
	if (!message || !pending)
		return SEP_RELAY_ERROR_ARGUMENT;
	if (message->version != SEP_RELAY_WIRE_VERSION)
		return SEP_RELAY_ERROR_VERSION;
	if (message->endpoint != pending->endpoint)
		return SEP_RELAY_ERROR_ENDPOINT;
	return SEP_RELAY_OK;
}

int sep_relay_state_init(struct sep_relay_state *state, uint64_t first_token,
			 uint32_t first_message_index)
{
	if (!state || first_token == 0)
		return SEP_RELAY_ERROR_ARGUMENT;
	memset(state, 0, sizeof(*state));
	state->next_token = first_token;
	state->next_message_index = first_message_index;
	return SEP_RELAY_OK;
}

int sep_relay_build_get_version(struct sep_relay_state *state,
				uint8_t output[SEP_RELAY_BUFFER_SIZE],
				struct sep_relay_pending *pending)
{
	const uint8_t payload[] = { 1 };

	if (!state || state->version_confirmed)
		return SEP_RELAY_ERROR_STATE;
	return build_control(state, payload, sizeof(payload), output, pending);
}

int sep_relay_accept_version(struct sep_relay_state *state,
			     const struct sep_relay_message *message,
			     const struct sep_relay_pending *pending)
{
	int result;

	if (!state || !message || !pending || state->version_confirmed ||
	    pending->kind != SEP_RELAY_REQUEST_CONTROL || pending->selector != 1)
		return SEP_RELAY_ERROR_STATE;
	result = pending_matches_control_header(message, pending);
	if (result != SEP_RELAY_OK)
		return result;
	if (message->message_length < 1 || message->message[8] != 1)
		return SEP_RELAY_ERROR_SELECTOR;
	state->version_confirmed = 1;
	return SEP_RELAY_OK;
}

int sep_relay_build_endpoint_status(
	struct sep_relay_state *state,
	uint8_t output[SEP_RELAY_BUFFER_SIZE],
	struct sep_relay_pending *pending)
{
	uint8_t payload[2 + SEP_RELAY_ENDPOINT_COUNT];

	if (!state || !state->version_confirmed ||
	    state->endpoint_status_confirmed)
		return SEP_RELAY_ERROR_STATE;
	payload[0] = 6;
	payload[1] = SEP_RELAY_ENDPOINT_COUNT;
	memcpy(payload + 2, state->local_endpoint_states,
	       SEP_RELAY_ENDPOINT_COUNT);
	return build_control(state, payload, sizeof(payload), output, pending);
}

int sep_relay_accept_endpoint_status(
	struct sep_relay_state *state,
	const struct sep_relay_message *message,
	const struct sep_relay_pending *pending)
{
	size_t count;
	int result;

	if (!state || !message || !pending || !state->version_confirmed ||
	    state->endpoint_status_confirmed ||
	    pending->kind != SEP_RELAY_REQUEST_CONTROL || pending->selector != 6)
		return SEP_RELAY_ERROR_STATE;
	result = pending_matches_control_header(message, pending);
	if (result != SEP_RELAY_OK)
		return result;
	if (message->message_length < 2 || message->message[8] != 6)
		return SEP_RELAY_ERROR_SELECTOR;
	count = message->message[9];
	if (count > SEP_RELAY_ENDPOINT_COUNT ||
	    message->message_length != count + 2)
		return SEP_RELAY_ERROR_LENGTH;
	memset(state->peer_endpoint_states, 0,
	       sizeof(state->peer_endpoint_states));
	memcpy(state->peer_endpoint_states, message->message + 10, count);
	state->peer_endpoint_count = (uint8_t)count;
	state->endpoint_status_confirmed = 1;
	return SEP_RELAY_OK;
}

int sep_relay_build_endpoint_enable(
	struct sep_relay_state *state, uint32_t endpoint, int enabled,
	uint8_t output[SEP_RELAY_BUFFER_SIZE],
	struct sep_relay_pending *identity)
{
	uint8_t payload[9] = { 2 };
	int result;

	if (!state || !output || !identity)
		return SEP_RELAY_ERROR_ARGUMENT;
	if (!state->endpoint_status_confirmed)
		return SEP_RELAY_ERROR_STATE;
	if (endpoint >= SEP_RELAY_ENDPOINT_COUNT ||
	    (enabled != 0 && enabled != 1))
		return SEP_RELAY_ERROR_ENDPOINT;
	store_u32_le(payload + 1, endpoint);
	store_u32_le(payload + 5, (uint32_t)enabled);
	result = build_control(state, payload, sizeof(payload), output, identity);
	if (result == SEP_RELAY_OK)
		state->local_endpoint_states[endpoint] = (uint8_t)enabled;
	return result;
}

int sep_relay_build_endpoint_ready(
	struct sep_relay_state *state, uint32_t endpoint,
	const struct sep_relay_pending *completed,
	uint8_t output[SEP_RELAY_BUFFER_SIZE],
	struct sep_relay_pending *identity)
{
	uint8_t payload[9] = { 4 };

	if (!state || !completed || completed->token == 0 || !output || !identity)
		return SEP_RELAY_ERROR_ARGUMENT;
	if (!state->endpoint_status_confirmed)
		return SEP_RELAY_ERROR_STATE;
	if (endpoint >= SEP_RELAY_ENDPOINT_COUNT ||
	    completed->endpoint != endpoint)
		return SEP_RELAY_ERROR_ENDPOINT;
	if ((completed->message_index & UINT32_C(0x80000000)) != 0 ||
	    state->token_exhausted)
		return SEP_RELAY_ERROR_EXHAUSTED;
	identity->kind = SEP_RELAY_REQUEST_CONTROL;
	identity->token = state->next_token;
	identity->message_index =
		completed->message_index | UINT32_C(0x80000000);
	identity->endpoint = SEP_RELAY_CONTROL_ENDPOINT;
	identity->selector = 4;
	identity->transaction = 0;
	if (state->next_token == UINT64_MAX)
		state->token_exhausted = 1;
	else
		state->next_token++;
	store_u32_le(payload + 1, endpoint);
	store_u32_le(payload + 5, 1);
	build_header(output, identity, sizeof(payload), 0);
	memcpy(output + SEP_RELAY_MESSAGE_OFFSET + 8, payload, sizeof(payload));
	state->local_endpoint_states[endpoint] = 1;
	return SEP_RELAY_OK;
}

int sep_relay_build_keystore_request(
	struct sep_relay_state *state, const void *request, size_t request_length,
	uint8_t selector, uint8_t transaction,
	uint8_t output[SEP_RELAY_BUFFER_SIZE],
	struct sep_relay_pending *pending)
{
	uint8_t *message;
	int result;

	if (!state || !state->endpoint_status_confirmed || !request ||
	    request_length == 0 || request_length > SEP_RELAY_DATA_CAPACITY ||
	    request_length > UINT16_MAX || selector >= UINT8_C(0x80) ||
	    !output || !pending)
		return SEP_RELAY_ERROR_ARGUMENT;
	result = reserve_identity(state, SEP_RELAY_REQUEST_KEYSTORE,
				  SEP_RELAY_KEYSTORE_ENDPOINT, selector,
				  transaction, pending);
	if (result != SEP_RELAY_OK)
		return result;
	build_header(output, pending, RELAY_KEYSTORE_HEADER_SIZE,
		     (uint32_t)request_length);
	memcpy(output, request, request_length);
	message = output + SEP_RELAY_MESSAGE_OFFSET;
	message[8] = 0;
	message[9] = selector;
	message[10] = transaction;
	store_u16_le(message + 14, (uint16_t)request_length);
	return SEP_RELAY_OK;
}

int sep_relay_build_acm_request(
	struct sep_relay_state *state, const void *command, size_t command_length,
	uint8_t request_selector, uint8_t output[SEP_RELAY_BUFFER_SIZE],
	struct sep_relay_pending *pending)
{
	uint8_t *message;
	int result;

	if (!state || !state->endpoint_status_confirmed || !command ||
	    command_length < 8 || command_length > SEP_RELAY_DATA_CAPACITY ||
	    command_length > UINT32_MAX || !output || !pending)
		return SEP_RELAY_ERROR_ARGUMENT;
	result = reserve_identity(state, SEP_RELAY_REQUEST_ACM,
				  SEP_RELAY_ACM_ENDPOINT, request_selector, 0,
				  pending);
	if (result != SEP_RELAY_OK)
		return result;
	build_header(output, pending, RELAY_ACM_HEADER_SIZE,
		     (uint32_t)command_length);
	memcpy(output, command, command_length);
	message = output + SEP_RELAY_MESSAGE_OFFSET;
	message[8] = 1;
	message[9] = request_selector;
	store_u32_le(message + 10, (uint32_t)command_length);
	store_u32_le(message + 14, 0);
	return SEP_RELAY_OK;
}

int sep_relay_parse(const void *transfer, size_t transfer_length,
		    struct sep_relay_message *message)
{
	const uint8_t *bytes = transfer;
	const uint8_t *header;

	if (!transfer || !message)
		return SEP_RELAY_ERROR_ARGUMENT;
	if (transfer_length < SEP_RELAY_MESSAGE_OFFSET +
				      SEP_RELAY_V2_HEADER_SIZE)
		return SEP_RELAY_ERROR_TRUNCATED;
	if (transfer_length > SEP_RELAY_BUFFER_SIZE)
		return SEP_RELAY_ERROR_LENGTH;
	header = bytes + SEP_RELAY_MESSAGE_OFFSET;
	if (header[0] != SEP_RELAY_WIRE_VERSION)
		return SEP_RELAY_ERROR_VERSION;

	memset(message, 0, sizeof(*message));
	message->data = bytes;
	message->message = header;
	message->transfer_length = transfer_length;
	message->version = header[0];
	message->endpoint = load_u32_le(header + 4);
	message->message_index =
		load_u32_le(header + RELAY_MESSAGE_INDEX_OFFSET);
	message->reply_token = load_u64_le(header + RELAY_REPLY_TOKEN_OFFSET);
	message->request_token =
		load_u64_le(header + RELAY_REQUEST_TOKEN_OFFSET);
	message->message_length =
		load_u32_le(header + RELAY_MESSAGE_LENGTH_OFFSET);
	message->data_length =
		load_u32_le(header + RELAY_DATA_LENGTH_OFFSET);
	if (message->message_length > SEP_RELAY_MESSAGE_CAPACITY ||
	    message->data_length > SEP_RELAY_DATA_CAPACITY)
		return SEP_RELAY_ERROR_LENGTH;
	return SEP_RELAY_OK;
}

enum sep_relay_message_class
sep_relay_classify(const struct sep_relay_message *message)
{
	if (!message || !message->message)
		return SEP_RELAY_MESSAGE_OTHER;
	if (message->endpoint == SEP_RELAY_CONTROL_ENDPOINT)
		return SEP_RELAY_MESSAGE_CONTROL;
	if (message->endpoint == SEP_RELAY_KEYSTORE_ENDPOINT &&
	    message->message_length >= RELAY_KEYSTORE_HEADER_SIZE) {
		if ((message->message[9] & UINT8_C(0x80)) != 0)
			return SEP_RELAY_MESSAGE_KEYSTORE_REPLY;
		if (message->message_length == RELAY_KEYSTORE_HEADER_SIZE &&
		    message->data_length == 0)
			return SEP_RELAY_MESSAGE_KEYSTORE_NOTIFICATION;
		return SEP_RELAY_MESSAGE_KEYSTORE_REQUEST;
	}
	if (message->endpoint == SEP_RELAY_ACM_ENDPOINT &&
	    message->message_length >= RELAY_ACM_HEADER_SIZE)
		return SEP_RELAY_MESSAGE_ACM;
	return SEP_RELAY_MESSAGE_OTHER;
}

int sep_relay_matches(const struct sep_relay_message *message,
		      const struct sep_relay_pending *pending)
{
	int result = pending_matches_header(message, pending);

	if (result != SEP_RELAY_OK)
		return result;
	switch (pending->kind) {
	case SEP_RELAY_REQUEST_CONTROL:
		if (message->message_length < 1 ||
		    message->message[8] != pending->selector)
			return SEP_RELAY_ERROR_SELECTOR;
		break;
	case SEP_RELAY_REQUEST_KEYSTORE:
		if (message->message_length < RELAY_KEYSTORE_HEADER_SIZE ||
		    message->message[9] !=
			    (uint8_t)(pending->selector | UINT8_C(0x80)) ||
		    message->message[10] != pending->transaction)
			return SEP_RELAY_ERROR_SELECTOR;
		break;
	case SEP_RELAY_REQUEST_ACM:
		if (message->message_length < RELAY_ACM_HEADER_SIZE ||
		    message->message[9] != pending->selector)
			return SEP_RELAY_ERROR_SELECTOR;
		break;
	default:
		return SEP_RELAY_ERROR_ARGUMENT;
	}
	return SEP_RELAY_MATCHED;
}

int sep_relay_waiter_init(struct sep_relay_waiter *waiter,
			  const struct sep_relay_pending *pending,
			  size_t skip_limit)
{
	if (!waiter || !pending || pending->token == 0 || skip_limit == 0)
		return SEP_RELAY_ERROR_ARGUMENT;
	waiter->pending = *pending;
	waiter->skipped = 0;
	waiter->skip_limit = skip_limit;
	return SEP_RELAY_OK;
}

int sep_relay_waiter_consume(
	struct sep_relay_waiter *waiter, const void *transfer,
	size_t transfer_length, enum sep_relay_message_class *classification,
	struct sep_relay_message *message)
{
	int result;

	if (!waiter || !classification || !message)
		return SEP_RELAY_ERROR_ARGUMENT;
	result = sep_relay_parse(transfer, transfer_length, message);
	if (result != SEP_RELAY_OK)
		return result;
	result = sep_relay_matches(message, &waiter->pending);
	if (result == SEP_RELAY_MATCHED) {
		*classification = SEP_RELAY_MESSAGE_EXPECTED_REPLY;
		return SEP_RELAY_MATCHED;
	}
	*classification = sep_relay_classify(message);
	if (++waiter->skipped >= waiter->skip_limit)
		return SEP_RELAY_ERROR_SKIP_LIMIT;
	return SEP_RELAY_SKIPPED;
}

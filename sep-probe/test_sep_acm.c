#include "sep_acm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static void store_u32_le(uint8_t *output, uint32_t value)
{
	output[0] = (uint8_t)value;
	output[1] = (uint8_t)(value >> 8);
	output[2] = (uint8_t)(value >> 16);
	output[3] = (uint8_t)(value >> 24);
}

static void prepare_relay(struct sep_relay_state *relay)
{
	EXPECT(sep_relay_state_init(relay, UINT64_C(0x1020304050607080),
				    UINT32_C(0x1020)) == SEP_RELAY_OK);
	relay->version_confirmed = 1;
	relay->endpoint_status_confirmed = 1;
	relay->local_endpoint_states[SEP_RELAY_ACM_ENDPOINT] = 1;
}

static int parse_reply(const void *payload, size_t payload_length,
		       int32_t remote_result, uint8_t request_selector,
		       uint32_t declared_length, uint32_t data_length,
		       uint32_t message_length,
		       uint8_t transfer[SEP_RELAY_BUFFER_SIZE],
		       struct sep_relay_message *message)
{
	uint8_t *header;

	memset(transfer, 0, SEP_RELAY_BUFFER_SIZE);
	header = transfer + SEP_RELAY_MESSAGE_OFFSET;
	if (payload && payload_length)
		memcpy(transfer, payload, payload_length);
	header[0] = SEP_RELAY_WIRE_VERSION;
	store_u32_le(header + 4, SEP_RELAY_ACM_ENDPOINT);
	header[9] = request_selector;
	store_u32_le(header + 10, declared_length);
	store_u32_le(header + 14, (uint32_t)remote_result);
	store_u32_le(header + 0xa4, message_length);
	store_u32_le(header + 0xa8, data_length);
	return sep_relay_parse(transfer, SEP_RELAY_BUFFER_SIZE, message);
}

static int accept_reply(struct sep_acm_state *state, const void *payload,
			size_t payload_length, int32_t remote_result,
			struct sep_acm_outcome *outcome)
{
	struct sep_relay_message message;
	uint8_t transfer[SEP_RELAY_BUFFER_SIZE];

	EXPECT(parse_reply(payload, payload_length, remote_result,
			   SEP_ACM_RELAY_REQUEST, (uint32_t)payload_length,
			   (uint32_t)payload_length, 10, transfer, &message) ==
	       SEP_RELAY_OK);
	return sep_acm_accept_reply(state, &message, outcome);
}

static void initialize(struct sep_acm_state *state,
		       struct sep_relay_state *relay)
{
	uint8_t transfer[SEP_RELAY_BUFFER_SIZE];
	struct sep_acm_outcome outcome;

	EXPECT(sep_acm_state_init(state) == SEP_ACM_OK);
	EXPECT(sep_acm_build_initialize(state, relay, transfer) == SEP_ACM_OK);
	EXPECT(accept_reply(state, NULL, 0, 0, &outcome) == SEP_ACM_OK);
	EXPECT(state->phase == SEP_ACM_PHASE_READY);
	sep_acm_wipe_transfer(transfer);
}

static void create_context(struct sep_acm_state *state,
			   struct sep_relay_state *relay,
			   const uint8_t external[SEP_ACM_EXTERNAL_FORM_SIZE])
{
	uint8_t transfer[SEP_RELAY_BUFFER_SIZE];
	uint8_t reply[SEP_ACM_CONTEXT_CREATE_REPLY_SIZE];
	struct sep_acm_outcome outcome;

	memcpy(reply, external, SEP_ACM_EXTERNAL_FORM_SIZE);
	reply[SEP_ACM_EXTERNAL_FORM_SIZE] = 0x28;
	EXPECT(sep_acm_build_context_create(state, relay, UINT32_C(0x10203040),
					    transfer) == SEP_ACM_OK);
	EXPECT(accept_reply(state, reply, sizeof(reply), 0, &outcome) ==
	       SEP_ACM_OK);
	EXPECT(state->phase == SEP_ACM_PHASE_ACTIVE);
	EXPECT(outcome.log_level_valid && outcome.log_level == 0x28);
	sep_acm_wipe_transfer(transfer);
}

static void externalize_context(struct sep_acm_state *state,
				struct sep_relay_state *relay)
{
	uint8_t transfer[SEP_RELAY_BUFFER_SIZE];
	struct sep_acm_outcome outcome;

	EXPECT(sep_acm_build_context_externalize(state, relay, transfer) ==
	       SEP_ACM_OK);
	EXPECT(accept_reply(state, NULL, 0, 0, &outcome) == SEP_ACM_OK);
	EXPECT(state->context_externalized == 1);
	sep_acm_wipe_transfer(transfer);
}

static void active_context(struct sep_acm_state *state,
			   struct sep_relay_state *relay,
			   const uint8_t external[SEP_ACM_EXTERNAL_FORM_SIZE])
{
	initialize(state, relay);
	create_context(state, relay, external);
	externalize_context(state, relay);
}

static void test_initialize_wire_and_state(void)
{
	struct sep_relay_state relay;
	struct sep_acm_state state;
	struct sep_acm_outcome outcome;
	uint8_t transfer[SEP_RELAY_BUFFER_SIZE] = { 0 };
	uint8_t expected[] = { 'D', 'R', 'C', 'S', 0x0a, 0x28, 0, 0 };

	prepare_relay(&relay);
	EXPECT(sep_acm_state_init(&state) == SEP_ACM_OK);
	EXPECT(sep_acm_build_initialize(&state, &relay, transfer) == SEP_ACM_OK);
	EXPECT(memcmp(transfer, expected, sizeof(expected)) == 0);
	EXPECT(state.pending_operation == SEP_ACM_OPERATION_INITIALIZE);
	EXPECT(sep_acm_build_initialize(&state, &relay, transfer) ==
	       SEP_ACM_ERROR_STATE);
	EXPECT(accept_reply(&state, NULL, 0, 0, &outcome) == SEP_ACM_OK);
	EXPECT(state.phase == SEP_ACM_PHASE_READY && !state.pending_valid);
	sep_acm_state_wipe(&state);
	EXPECT(state.phase == SEP_ACM_PHASE_FAILED &&
	       state.context.bytes[0] == 0);
}

static void test_create_externalize_export_and_delete(void)
{
	const uint8_t external[SEP_ACM_EXTERNAL_FORM_SIZE] = {
		0x31, 0x72, 0x43, 0x94, 0x55, 0xa6, 0x77, 0xc8,
		0x19, 0x2a, 0x3b, 0x4c, 0x5d, 0x6e, 0x7f, 0x80,
	};
	struct sep_acm_external_form exported;
	struct sep_relay_state relay;
	struct sep_acm_state state;
	struct sep_acm_outcome outcome;
	uint8_t transfer[SEP_RELAY_BUFFER_SIZE] = { 0 };

	prepare_relay(&relay);
	initialize(&state, &relay);
	EXPECT(sep_acm_build_context_create(&state, &relay,
					    UINT32_C(0x10203040), transfer) ==
	       SEP_ACM_OK);
	EXPECT(memcmp(transfer, "DRCS", 4) == 0 && transfer[4] == 1 &&
	       transfer[7] == 1);
	EXPECT(load_u32_le(transfer + SEP_ACM_COMMAND_HEADER_SIZE) ==
	       UINT32_C(0x10203040));
	{
		uint8_t reply[SEP_ACM_CONTEXT_CREATE_REPLY_SIZE];

		memcpy(reply, external, sizeof(external));
		reply[SEP_ACM_EXTERNAL_FORM_SIZE] = 0x34;
		EXPECT(accept_reply(&state, reply, sizeof(reply), 0, &outcome) ==
		       SEP_ACM_OK);
		EXPECT(outcome.log_level_valid && outcome.log_level == 0x34);
	}
	EXPECT(sep_acm_export_active_context(&state, &exported) ==
	       SEP_ACM_ERROR_STATE);
	EXPECT(sep_acm_build_context_externalize(&state, &relay, transfer) ==
	       SEP_ACM_OK);
	EXPECT(transfer[4] == 0x13 && transfer[7] == 1 &&
	       memcmp(transfer + SEP_ACM_COMMAND_HEADER_SIZE, external,
		      sizeof(external)) == 0);
	EXPECT(accept_reply(&state, NULL, 0, 0, &outcome) == SEP_ACM_OK);
	EXPECT(sep_acm_export_active_context(&state, &exported) == SEP_ACM_OK);
	EXPECT(memcmp(exported.bytes, external, sizeof(external)) == 0);
	EXPECT(sep_acm_build_context_delete(&state, &relay, transfer) ==
	       SEP_ACM_OK);
	EXPECT(transfer[4] == 2 &&
	       memcmp(transfer + SEP_ACM_COMMAND_HEADER_SIZE, external,
		      sizeof(external)) == 0);
	EXPECT(accept_reply(&state, NULL, 0, 0, &outcome) == SEP_ACM_OK);
	EXPECT(state.phase == SEP_ACM_PHASE_READY &&
	       !state.context_externalized);
	EXPECT(memcmp(state.context.bytes,
		      (uint8_t[SEP_ACM_EXTERNAL_FORM_SIZE]){ 0 },
		      SEP_ACM_EXTERNAL_FORM_SIZE) == 0);
	sep_acm_external_form_wipe(&exported);
	sep_acm_wipe_transfer(transfer);
}

static void test_external_form_exact_lengths_and_wipe(void)
{
	uint8_t input[SEP_ACM_EXTERNAL_FORM_SIZE];
	uint8_t output[SEP_ACM_EXTERNAL_FORM_SIZE] = { 0 };
	struct sep_acm_external_form form;
	size_t index;

	for (index = 0; index < sizeof(input); ++index)
		input[index] = (uint8_t)(0xa0 + index);
	EXPECT(sep_acm_external_form_import(&form, input, sizeof(input)) ==
	       SEP_ACM_OK);
	EXPECT(sep_acm_external_form_export(&form, output, sizeof(output)) ==
	       SEP_ACM_OK);
	EXPECT(memcmp(input, output, sizeof(input)) == 0);
	EXPECT(sep_acm_external_form_import(&form, input, sizeof(input) - 1) ==
	       SEP_ACM_ERROR_ARGUMENT);
	EXPECT(sep_acm_external_form_export(&form, output, sizeof(output) - 1) ==
	       SEP_ACM_ERROR_ARGUMENT);
	sep_acm_external_form_wipe(&form);
	EXPECT(memcmp(form.bytes,
		      (uint8_t[SEP_ACM_EXTERNAL_FORM_SIZE]){ 0 },
		      SEP_ACM_EXTERNAL_FORM_SIZE) == 0);
}

static void test_credential_presence_wire_and_strict_reply(void)
{
	const uint8_t external[SEP_ACM_EXTERNAL_FORM_SIZE] = {
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	};
	struct sep_relay_state relay;
	struct sep_acm_state state;
	struct sep_acm_outcome outcome;
	uint8_t transfer[SEP_RELAY_BUFFER_SIZE] = { 0 };
	uint8_t reply[4] = { 1, 0, 0, 0 };

	prepare_relay(&relay);
	active_context(&state, &relay, external);
	EXPECT(sep_acm_build_contains_credential(&state, &relay, 2, 0,
						 transfer) == SEP_ACM_OK);
	EXPECT(transfer[4] == 4 && transfer[7] == 1);
	EXPECT(memcmp(transfer + 8, external, sizeof(external)) == 0);
	EXPECT(load_u32_le(transfer + 24) == 2 &&
	       load_u32_le(transfer + 28) == 0);
	EXPECT(accept_reply(&state, reply, sizeof(reply), 0, &outcome) ==
	       SEP_ACM_OK);
	EXPECT(outcome.boolean_valid && outcome.boolean_value == 1);
	EXPECT(sep_acm_build_contains_credential(&state, &relay, 3, 0,
						 transfer) ==
	       SEP_ACM_ERROR_ARGUMENT);
	EXPECT(sep_acm_build_contains_credential(&state, &relay, 1, 1,
						 transfer) ==
	       SEP_ACM_ERROR_ARGUMENT);

	EXPECT(sep_acm_build_contains_credential(&state, &relay, 1, 0,
						 transfer) == SEP_ACM_OK);
	reply[0] = 2;
	EXPECT(accept_reply(&state, reply, sizeof(reply), 0, &outcome) ==
	       SEP_ACM_ERROR_REPLY);
	EXPECT(state.phase == SEP_ACM_PHASE_FAILED);
	EXPECT(memcmp(state.context.bytes,
		      (uint8_t[SEP_ACM_EXTERNAL_FORM_SIZE]){ 0 },
		      SEP_ACM_EXTERNAL_FORM_SIZE) == 0);
	sep_acm_wipe_transfer(transfer);
}

static void test_replace_passphrase_exact_wire_and_limits(void)
{
	const uint8_t external[SEP_ACM_EXTERNAL_FORM_SIZE] = {
		0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87,
		0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f,
	};
	uint8_t secret[32];
	uint8_t maximum_secret[SEP_ACM_PASSPHRASE_MAX_SIZE];
	struct sep_relay_state relay;
	struct sep_acm_state state;
	struct sep_acm_outcome outcome;
	uint8_t transfer[SEP_RELAY_BUFFER_SIZE] = { 0 };
	uint8_t *credential = transfer + 8 + SEP_ACM_EXTERNAL_FORM_SIZE;
	size_t index;

	for (index = 0; index < sizeof(secret); ++index)
		secret[index] = (uint8_t)(0x80 + index);
	for (index = 0; index < sizeof(maximum_secret); ++index)
		maximum_secret[index] = (uint8_t)(0x40 + index);
	prepare_relay(&relay);
	active_context(&state, &relay, external);
	EXPECT(sep_acm_build_replace_passphrase(&state, &relay, secret,
						sizeof(secret), 1, transfer) ==
	       SEP_ACM_OK);
	EXPECT(transfer[4] == 0x0f && transfer[7] == 1);
	EXPECT(memcmp(transfer + 8, external, sizeof(external)) == 0);
	EXPECT(load_u32_le(credential) == 2 &&
	       load_u32_le(credential + 4) == 1 &&
	       load_u32_le(credential + 0x0c) == UINT32_MAX &&
	       load_u32_le(credential + 0x1c) == 0x88 &&
	       load_u32_le(credential + 0x20) == 0 &&
	       load_u32_le(credential + 0x24) == sizeof(secret));
	EXPECT(memcmp(credential + 0x28, secret, sizeof(secret)) == 0);
	EXPECT(load_u32_le(transfer + 8 + 0xb8) == 1);
	EXPECT(accept_reply(&state, NULL, 0, 0, &outcome) == SEP_ACM_OK);
	EXPECT(sep_acm_build_replace_passphrase(
		       &state, &relay, maximum_secret, sizeof(maximum_secret), 1,
		       transfer) == SEP_ACM_OK);
	credential = transfer + 8 + SEP_ACM_EXTERNAL_FORM_SIZE;
	EXPECT(load_u32_le(credential + 0x24) == sizeof(maximum_secret));
	EXPECT(memcmp(credential + 0x28, maximum_secret,
		      sizeof(maximum_secret)) == 0);
	EXPECT(accept_reply(&state, NULL, 0, 0, &outcome) == SEP_ACM_OK);
	EXPECT(sep_acm_build_replace_passphrase(&state, &relay, secret, 0, 1,
						 transfer) ==
	       SEP_ACM_ERROR_ARGUMENT);
	EXPECT(sep_acm_build_replace_passphrase(
		       &state, &relay, secret, SEP_ACM_PASSPHRASE_MAX_SIZE + 1,
		       1, transfer) == SEP_ACM_ERROR_ARGUMENT);
	EXPECT(sep_acm_build_replace_passphrase(&state, &relay, secret,
						sizeof(secret), 0, transfer) ==
	       SEP_ACM_ERROR_ARGUMENT);
	sep_acm_wipe_transfer(transfer);
	EXPECT(memcmp(transfer,
		      (uint8_t[SEP_RELAY_BUFFER_SIZE]){ 0 },
		      sizeof(transfer)) == 0);
}

static void test_verify_policy_unbound_and_bound_wire(void)
{
	const uint8_t external[SEP_ACM_EXTERNAL_FORM_SIZE] = {
		0x91, 0x82, 0x73, 0x64, 0x55, 0x46, 0x37, 0x28,
		0x19, 0x0a, 0xfb, 0xec, 0xdd, 0xce, 0xbf, 0xa0,
	};
	uint8_t uuid[16];
	uint8_t reply[4] = { 1, 0, 0, 0 };
	uint8_t maximum_reply[SEP_ACM_VERIFY_REPLY_CAPACITY] = { 1 };
	uint8_t oversized_reply[SEP_ACM_VERIFY_REPLY_CAPACITY + 1] = { 1 };
	struct sep_relay_state relay;
	struct sep_acm_state state;
	struct sep_acm_outcome outcome;
	uint8_t transfer[SEP_RELAY_BUFFER_SIZE] = { 0 };
	size_t index;

	for (index = 0; index < sizeof(uuid); ++index)
		uuid[index] = (uint8_t)(0x40 + index);
	prepare_relay(&relay);
	active_context(&state, &relay, external);
	EXPECT(sep_acm_build_verify_enrollment(&state, &relay, 1, NULL, 0,
					       transfer) == SEP_ACM_OK);
	EXPECT(transfer[4] == 3 && transfer[7] == 1);
	EXPECT(memcmp(transfer + 8, external, sizeof(external)) == 0);
	EXPECT(memcmp(transfer + 24, "TouchIdEnrollment", 18) == 0);
	EXPECT(transfer[42] == 1 && load_u32_le(transfer + 43) == 0 &&
	       load_u32_le(transfer + 47) == 0);
	EXPECT(load_u32_le(transfer + SEP_RELAY_MESSAGE_OFFSET + 10) == 0x33);
	EXPECT(accept_reply(&state, reply, sizeof(reply), 0, &outcome) ==
	       SEP_ACM_OK);
	EXPECT(outcome.boolean_valid && outcome.boolean_value);

	EXPECT(sep_acm_build_verify_enrollment(&state, &relay, 0, uuid,
					       sizeof(uuid), transfer) == SEP_ACM_OK);
	EXPECT(load_u32_le(transfer + 47) == 1);
	EXPECT(load_u32_le(transfer + 51) == 2 &&
	       load_u32_le(transfer + 55) == sizeof(uuid));
	EXPECT(memcmp(transfer + 59, uuid, sizeof(uuid)) == 0);
	EXPECT(load_u32_le(transfer + SEP_RELAY_MESSAGE_OFFSET + 10) == 0x4b);
	EXPECT(accept_reply(&state, reply, sizeof(reply), 0, &outcome) ==
	       SEP_ACM_OK);
	EXPECT(sep_acm_build_verify_enrollment(&state, &relay, 0, NULL, 0,
					       transfer) ==
	       SEP_ACM_ERROR_ARGUMENT);
	EXPECT(sep_acm_build_verify_enrollment(&state, &relay, 1, uuid,
					       sizeof(uuid), transfer) ==
	       SEP_ACM_ERROR_ARGUMENT);
	EXPECT(sep_acm_build_verify_enrollment(&state, &relay, 1, NULL, 0,
					       transfer) == SEP_ACM_OK);
	EXPECT(accept_reply(&state, maximum_reply, sizeof(maximum_reply), 0,
			    &outcome) == SEP_ACM_OK);
	EXPECT(outcome.boolean_valid && outcome.boolean_value);
	EXPECT(sep_acm_build_verify_enrollment(&state, &relay, 1, NULL, 0,
					       transfer) == SEP_ACM_OK);
	EXPECT(accept_reply(&state, oversized_reply, sizeof(oversized_reply), 0,
			    &outcome) == SEP_ACM_ERROR_REPLY);
	EXPECT(state.phase == SEP_ACM_PHASE_FAILED);
	sep_acm_wipe_transfer(transfer);
}

static void test_remote_failure_and_ambiguity_fail_closed(void)
{
	const uint8_t external[SEP_ACM_EXTERNAL_FORM_SIZE] = {
		0x91, 0x82, 0x73, 0x64, 0x55, 0x46, 0x37, 0x28,
		0x19, 0x0a, 0xfb, 0xec, 0xdd, 0xce, 0xbf, 0xa0,
	};
	struct sep_relay_state relay;
	struct sep_acm_state state;
	struct sep_acm_outcome outcome;
	uint8_t transfer[SEP_RELAY_BUFFER_SIZE] = { 0 };

	prepare_relay(&relay);
	initialize(&state, &relay);
	EXPECT(sep_acm_build_context_create(&state, &relay, 42, transfer) ==
	       SEP_ACM_OK);
	EXPECT(accept_reply(&state, NULL, 0, -7, &outcome) ==
	       SEP_ACM_ERROR_REMOTE);
	EXPECT(outcome.remote_result == -7 &&
	       state.phase == SEP_ACM_PHASE_READY && !state.pending_valid);
	EXPECT(sep_acm_build_context_create(&state, &relay, 42, transfer) ==
	       SEP_ACM_OK);
	EXPECT(sep_acm_mark_ambiguous(&state) == SEP_ACM_ERROR_AMBIGUOUS);
	EXPECT(state.phase == SEP_ACM_PHASE_FAILED && !state.pending_valid);
	EXPECT(sep_acm_build_context_create(&state, &relay, 42, transfer) ==
	       SEP_ACM_ERROR_STATE);

	prepare_relay(&relay);
	active_context(&state, &relay, external);
	EXPECT(sep_acm_build_contains_credential(&state, &relay, 1, 0,
						 transfer) == SEP_ACM_OK);
	EXPECT(sep_acm_mark_ambiguous(&state) == SEP_ACM_ERROR_AMBIGUOUS);
	EXPECT(memcmp(state.context.bytes,
		      (uint8_t[SEP_ACM_EXTERNAL_FORM_SIZE]){ 0 },
		      SEP_ACM_EXTERNAL_FORM_SIZE) == 0);
	sep_acm_wipe_transfer(transfer);
}

static void test_declared_payload_allows_proven_relay_padding(void)
{
	const uint8_t external[SEP_ACM_EXTERNAL_FORM_SIZE] = {
		1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
	};
	uint8_t payload[4] = { 1, 0, 0, 0 };
	struct sep_relay_state relay;
	struct sep_acm_state state;
	struct sep_acm_outcome outcome;
	struct sep_relay_message message;
	uint8_t transfer[SEP_RELAY_BUFFER_SIZE];

	prepare_relay(&relay);
	active_context(&state, &relay, external);
	EXPECT(sep_acm_build_contains_credential(&state, &relay, 1, 0,
						 transfer) == SEP_ACM_OK);
	EXPECT(parse_reply(payload, sizeof(payload), 0,
			   SEP_ACM_RELAY_REQUEST, sizeof(payload), 8, 10,
			   transfer, &message) == SEP_RELAY_OK);
	EXPECT(sep_acm_accept_reply(&state, &message, &outcome) == SEP_ACM_OK);
	EXPECT(outcome.boolean_valid && outcome.boolean_value == 1);
	sep_acm_wipe_transfer(transfer);
}

static void test_malformed_replies_fail_closed(void)
{
	const uint8_t external[SEP_ACM_EXTERNAL_FORM_SIZE] = { 1 };
	struct sep_relay_state relay;
	struct sep_acm_state state;
	struct sep_acm_outcome outcome;
	struct sep_relay_message message;
	uint8_t transfer[SEP_RELAY_BUFFER_SIZE] = { 0 };

	prepare_relay(&relay);
	initialize(&state, &relay);
	EXPECT(sep_acm_build_context_create(&state, &relay, 1, transfer) ==
	       SEP_ACM_OK);
	EXPECT(parse_reply(external, sizeof(external), 0,
			   SEP_ACM_RELAY_REQUEST, sizeof(external),
			   sizeof(external), 10, transfer, &message) ==
	       SEP_RELAY_OK);
	EXPECT(sep_acm_accept_reply(&state, &message, &outcome) ==
	       SEP_ACM_ERROR_REPLY);
	EXPECT(state.phase == SEP_ACM_PHASE_FAILED);

	prepare_relay(&relay);
	initialize(&state, &relay);
	EXPECT(sep_acm_build_context_create(&state, &relay, 1, transfer) ==
	       SEP_ACM_OK);
	EXPECT(parse_reply(NULL, 0, 0, 2, 0, 0, 10, transfer,
			   &message) == SEP_RELAY_OK);
	EXPECT(sep_acm_accept_reply(&state, &message, &outcome) ==
	       SEP_ACM_ERROR_RELAY);
	EXPECT(state.pending_valid);
	EXPECT(sep_acm_mark_ambiguous(&state) == SEP_ACM_ERROR_AMBIGUOUS);

	prepare_relay(&relay);
	initialize(&state, &relay);
	EXPECT(sep_acm_build_context_create(&state, &relay, 1, transfer) ==
	       SEP_ACM_OK);
	EXPECT(parse_reply(NULL, 0, 0, SEP_ACM_RELAY_REQUEST, 1,
			   0, 10, transfer, &message) == SEP_RELAY_OK);
	EXPECT(sep_acm_accept_reply(&state, &message, &outcome) ==
	       SEP_ACM_ERROR_REPLY);
	EXPECT(state.phase == SEP_ACM_PHASE_FAILED);

	prepare_relay(&relay);
	initialize(&state, &relay);
	EXPECT(sep_acm_build_context_create(&state, &relay, 1, transfer) ==
	       SEP_ACM_OK);
	memset(&message, 0, sizeof(message));
	EXPECT(sep_acm_accept_reply(&state, &message, &outcome) ==
	       SEP_ACM_ERROR_ARGUMENT);
	EXPECT(state.pending_valid);
	EXPECT(sep_acm_mark_ambiguous(&state) == SEP_ACM_ERROR_AMBIGUOUS);
	sep_acm_wipe_transfer(transfer);
}

static void test_diagnostics_are_fixed_and_redacted(void)
{
	const char *name;
	int result;

	for (result = SEP_ACM_ERROR_ARGUMENT;
	     result >= SEP_ACM_ERROR_AMBIGUOUS; --result) {
		name = sep_acm_result_name(result);
		EXPECT(name != NULL);
		if (name) {
			EXPECT(strlen(name) < 64);
			EXPECT(strstr(name, "SYNTHETIC_SECRET_MARKER") == NULL);
		}
	}
	EXPECT(strcmp(sep_acm_result_name(99), "unknown ACM failure") == 0);
}

int main(void)
{
	test_initialize_wire_and_state();
	test_create_externalize_export_and_delete();
	test_external_form_exact_lengths_and_wipe();
	test_credential_presence_wire_and_strict_reply();
	test_replace_passphrase_exact_wire_and_limits();
	test_verify_policy_unbound_and_bound_wire();
	test_remote_failure_and_ambiguity_fail_closed();
	test_declared_payload_allows_proven_relay_padding();
	test_malformed_replies_fail_closed();
	test_diagnostics_are_fixed_and_redacted();

	if (failures != 0) {
		fprintf(stderr, "%u ACM tests failed\n", failures);
		return EXIT_FAILURE;
	}
	puts("all ACM tests passed");
	return EXIT_SUCCESS;
}

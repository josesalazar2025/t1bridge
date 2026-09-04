#ifndef SEP_RELAY_H
#define SEP_RELAY_H

#include <stddef.h>
#include <stdint.h>

#define SEP_RELAY_BUFFER_SIZE 0x4400U
#define SEP_RELAY_DATA_CAPACITY 0x4000U
#define SEP_RELAY_MESSAGE_OFFSET 0x4000U
#define SEP_RELAY_V2_HEADER_SIZE 0xb4U
#define SEP_RELAY_MESSAGE_CAPACITY 0x80U
#define SEP_RELAY_ENDPOINT_COUNT 10U
#define SEP_RELAY_CONTROL_ENDPOINT UINT32_MAX
#define SEP_RELAY_ACM_ENDPOINT UINT32_C(1)
#define SEP_RELAY_KEYSTORE_ENDPOINT UINT32_C(3)
#define SEP_RELAY_WIRE_VERSION UINT8_C(2)
#define SEP_RELAY_DEFAULT_SKIP_LIMIT 4U

enum sep_relay_result {
	SEP_RELAY_OK = 0,
	SEP_RELAY_SKIPPED = 1,
	SEP_RELAY_MATCHED = 2,
	SEP_RELAY_ERROR_ARGUMENT = -1,
	SEP_RELAY_ERROR_TRUNCATED = -2,
	SEP_RELAY_ERROR_LENGTH = -3,
	SEP_RELAY_ERROR_VERSION = -4,
	SEP_RELAY_ERROR_ENDPOINT = -5,
	SEP_RELAY_ERROR_SELECTOR = -6,
	SEP_RELAY_ERROR_STATE = -8,
	SEP_RELAY_ERROR_EXHAUSTED = -9,
	SEP_RELAY_ERROR_SKIP_LIMIT = -10,
};

enum sep_relay_request_kind {
	SEP_RELAY_REQUEST_CONTROL,
	SEP_RELAY_REQUEST_KEYSTORE,
	SEP_RELAY_REQUEST_ACM,
};

enum sep_relay_message_class {
	SEP_RELAY_MESSAGE_EXPECTED_REPLY,
	SEP_RELAY_MESSAGE_CONTROL,
	SEP_RELAY_MESSAGE_KEYSTORE_REPLY,
	SEP_RELAY_MESSAGE_KEYSTORE_NOTIFICATION,
	SEP_RELAY_MESSAGE_KEYSTORE_REQUEST,
	SEP_RELAY_MESSAGE_ACM,
	SEP_RELAY_MESSAGE_OTHER,
};

struct sep_relay_state {
	uint64_t next_token;
	uint32_t next_message_index;
	uint8_t local_endpoint_states[SEP_RELAY_ENDPOINT_COUNT];
	uint8_t peer_endpoint_states[SEP_RELAY_ENDPOINT_COUNT];
	uint8_t peer_endpoint_count;
	uint8_t version_confirmed;
	uint8_t endpoint_status_confirmed;
	uint8_t token_exhausted;
	uint8_t message_index_exhausted;
};

struct sep_relay_pending {
	enum sep_relay_request_kind kind;
	uint64_t token;
	uint32_t message_index;
	uint32_t endpoint;
	uint8_t selector;
	uint8_t transaction;
};

struct sep_relay_message {
	const uint8_t *data;
	const uint8_t *message;
	size_t transfer_length;
	uint64_t reply_token;
	uint64_t request_token;
	uint32_t endpoint;
	uint32_t message_index;
	uint32_t message_length;
	uint32_t data_length;
	uint8_t version;
};

struct sep_relay_waiter {
	struct sep_relay_pending pending;
	size_t skipped;
	size_t skip_limit;
};

/* A session token is never a pointer. first_token must be nonzero. */
int sep_relay_state_init(struct sep_relay_state *state, uint64_t first_token,
			 uint32_t first_message_index);

int sep_relay_build_get_version(struct sep_relay_state *state,
				uint8_t output[SEP_RELAY_BUFFER_SIZE],
				struct sep_relay_pending *pending);
int sep_relay_accept_version(struct sep_relay_state *state,
			     const struct sep_relay_message *message,
			     const struct sep_relay_pending *pending);

int sep_relay_build_endpoint_status(
	struct sep_relay_state *state,
	uint8_t output[SEP_RELAY_BUFFER_SIZE],
	struct sep_relay_pending *pending);
int sep_relay_accept_endpoint_status(
	struct sep_relay_state *state,
	const struct sep_relay_message *message,
	const struct sep_relay_pending *pending);

int sep_relay_build_endpoint_enable(
	struct sep_relay_state *state, uint32_t endpoint, int enabled,
	uint8_t output[SEP_RELAY_BUFFER_SIZE],
	struct sep_relay_pending *identity);
int sep_relay_build_endpoint_ready(
	struct sep_relay_state *state, uint32_t endpoint,
	/* The acknowledgement index is completed->message_index | 0x80000000. */
	const struct sep_relay_pending *completed,
	uint8_t output[SEP_RELAY_BUFFER_SIZE],
	struct sep_relay_pending *identity);

int sep_relay_build_keystore_request(
	struct sep_relay_state *state, const void *request, size_t request_length,
	uint8_t selector, uint8_t transaction,
	uint8_t output[SEP_RELAY_BUFFER_SIZE],
	struct sep_relay_pending *pending);
int sep_relay_build_acm_request(
	struct sep_relay_state *state, const void *command, size_t command_length,
	uint8_t request_selector, uint8_t output[SEP_RELAY_BUFFER_SIZE],
	struct sep_relay_pending *pending);

int sep_relay_parse(const void *transfer, size_t transfer_length,
		    struct sep_relay_message *message);
enum sep_relay_message_class
sep_relay_classify(const struct sep_relay_message *message);
int sep_relay_matches(const struct sep_relay_message *message,
		      const struct sep_relay_pending *pending);

int sep_relay_waiter_init(struct sep_relay_waiter *waiter,
			  const struct sep_relay_pending *pending,
			  size_t skip_limit);
int sep_relay_waiter_consume(
	struct sep_relay_waiter *waiter, const void *transfer,
	size_t transfer_length, enum sep_relay_message_class *classification,
	struct sep_relay_message *message);

#endif

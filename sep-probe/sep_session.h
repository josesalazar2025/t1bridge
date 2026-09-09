#ifndef SEP_SESSION_H
#define SEP_SESSION_H

#include "sep_acm.h"
#include "sep_keystore.h"
#include "sep_urb.h"

#include <stddef.h>
#include <stdint.h>

enum sep_session_result {
	SEP_SESSION_OK = 0,
	SEP_SESSION_REMOTE_ERROR = 1,
	SEP_SESSION_IDLE = 2,
	SEP_SESSION_ERROR_ARGUMENT = -1,
	SEP_SESSION_ERROR_STATE = -2,
	SEP_SESSION_ERROR_CLOCK = -3,
	SEP_SESSION_ERROR_TRANSPORT = -4,
	SEP_SESSION_ERROR_TIMEOUT = -5,
	SEP_SESSION_ERROR_PROTOCOL = -6,
	SEP_SESSION_ERROR_SKIP_LIMIT = -7,
	SEP_SESSION_ERROR_POISONED = -8,
	SEP_SESSION_ERROR_TEARDOWN = -9,
};

enum sep_session_phase {
	SEP_SESSION_PHASE_NEW,
	SEP_SESSION_PHASE_READY,
	SEP_SESSION_PHASE_POISONED,
	SEP_SESSION_PHASE_CLOSED,
};

/* Focused seam for synthetic tests. Production sessions use sep_urb directly. */
struct sep_session_transport_ops {
	void *context;
	enum sep_urb_status (*exchange)(void *context, const uint8_t *output,
					size_t output_length, uint8_t *input,
					size_t input_capacity,
					unsigned int timeout_ms);
	enum sep_urb_status (*send_only)(void *context, const uint8_t *output,
					 size_t output_length,
					 unsigned int timeout_ms);
	enum sep_urb_status (*receive_only)(void *context, uint8_t *input,
					    size_t input_capacity,
					    unsigned int timeout_ms);
	enum sep_urb_status (*destroy)(void *context);
	int (*monotonic_ms)(void *context, uint64_t *value);
};

struct sep_session {
	struct sep_session_transport_ops transport;
	struct sep_relay_state relay;
	uint8_t output[SEP_RELAY_BUFFER_SIZE];
	uint8_t input[SEP_RELAY_BUFFER_SIZE];
	uint64_t operation_deadline_ms;
	enum sep_session_phase phase;
	uint8_t operation_deadline_set;
};

/* The initialized URB transport becomes owned by the session until destroy. */
int sep_session_init(struct sep_session *session,
		     struct sep_urb_transport *transport, uint64_t first_token,
		     uint32_t first_message_index);

int sep_session_init_with_ops(struct sep_session *session,
			      const struct sep_session_transport_ops *ops,
			      uint64_t first_token,
			      uint32_t first_message_index);

/*
 * Pins later negotiation, keystore, and ACM transfers to one absolute deadline
 * from the transport's monotonic clock. Only one deadline is active at a time;
 * a caller may release a live acquisition deadline before a transfer-free lease
 * hold, then install a fresh cleanup deadline. Every individual transport wait
 * remains capped at SEP_URB_MAX_TIMEOUT_MS.
 */
int sep_session_set_operation_deadline(struct sep_session *session,
				       uint64_t deadline_ms);

/* Releases a still-live deadline. Expired sessions remain failed closed. */
int sep_session_release_operation_deadline(struct sep_session *session);

/* Negotiate control state, then announce endpoints 1, 2, and 3 OUT-only. */
int sep_session_negotiate(struct sep_session *session,
			  unsigned int timeout_ms);

int sep_session_keystore_exchange(
	struct sep_session *session,
	const struct sep_keystore_operation *operation, const void *request,
	size_t request_length, struct sep_keystore_reply *reply,
	unsigned int timeout_ms);

/*
 * Optional synchronous observer of validated keystore reply status only.
 * No buffers, handles, transaction identities, or opaque values are exposed.
 * The observer is thread-local; callers restore the returned previous value.
 * Remote fields are meaningful only for SEP_KEYSTORE_REMOTE_ERROR; inner status
 * is present only when outer status is zero. Observers must not alter the lease.
 */
typedef void (*sep_keystore_observer)(uint8_t selector, int result,
				      int8_t outer_status, int32_t inner_status);
sep_keystore_observer sep_session_set_keystore_observer(
	sep_keystore_observer observer);

/* Receive-only traffic. Timeout/interruption is healthy idle, not poison. */
int sep_session_drain_notification(struct sep_session *session,
				   unsigned int timeout_ms);
/* A successful opaque reply borrows session input until clear/next/destroy. */

typedef int (*sep_session_acm_builder)(
	void *context, struct sep_acm_state *state,
	struct sep_relay_state *relay,
	uint8_t output[SEP_RELAY_BUFFER_SIZE]);

/* Build, exchange, validate, then acknowledge the ACM reply OUT-only. */
int sep_session_acm_exchange(struct sep_session *session,
			     struct sep_acm_state *state,
			     sep_session_acm_builder builder,
			     void *builder_context,
			     struct sep_acm_outcome *outcome,
			     unsigned int timeout_ms);

/* Wipes retained request/reply bytes without changing protocol state. */
void sep_session_clear_transfers(struct sep_session *session);

/*
 * Wipes buffers and destroys the owned transport. Teardown is attempted once;
 * success and failure both close the session permanently.
 */
int sep_session_destroy(struct sep_session *session);

enum sep_session_phase sep_session_phase(const struct sep_session *session);
const char *sep_session_result_name(int result);

#endif

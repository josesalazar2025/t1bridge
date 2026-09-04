#include "sep_session.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>

static const char *relay_validation_name(int result)
{
	switch (result) {
	case SEP_RELAY_ERROR_ARGUMENT:
		return "invalid validator input";
	case SEP_RELAY_ERROR_TRUNCATED:
		return "truncated reply";
	case SEP_RELAY_ERROR_LENGTH:
		return "invalid reply length";
	case SEP_RELAY_ERROR_VERSION:
		return "wire version mismatch";
	case SEP_RELAY_ERROR_ENDPOINT:
		return "endpoint mismatch";
	case SEP_RELAY_ERROR_SELECTOR:
		return "selector mismatch";
	case SEP_RELAY_ERROR_STATE:
		return "invalid validator state";
	case SEP_RELAY_ERROR_EXHAUSTED:
		return "request identity exhausted";
	default:
		return "unknown reply validation failure";
	}
}

static const char *keystore_validation_name(int result)
{
	switch (result) {
	case SEP_KEYSTORE_ERROR_LENGTH:
		return "invalid keystore reply length";
	case SEP_KEYSTORE_ERROR_HEADER:
		return "invalid keystore reply header";
	case SEP_KEYSTORE_ERROR_SELECTOR:
		return "keystore selector mismatch";
	case SEP_KEYSTORE_ERROR_TRANSACTION:
		return "keystore transaction mismatch";
	case SEP_KEYSTORE_ERROR_RELAY:
		return "keystore relay identity mismatch";
	default:
		return "unknown keystore reply validation failure";
	}
}

static enum sep_urb_status urb_exchange(void *context,
					const uint8_t *output,
					size_t output_length, uint8_t *input,
					size_t input_capacity,
					unsigned int timeout_ms)
{
	return sep_urb_exchange(context, output, output_length, input,
				input_capacity, timeout_ms);
}

static enum sep_urb_status urb_send_only(void *context,
					 const uint8_t *output,
					 size_t output_length,
					 unsigned int timeout_ms)
{
	return sep_urb_send_only(context, output, output_length, timeout_ms);
}

static enum sep_urb_status urb_receive_only(void *context, uint8_t *input,
					    size_t input_capacity,
					    unsigned int timeout_ms)
{
	return sep_urb_receive_only(context, input, input_capacity, timeout_ms);
}

static enum sep_urb_status urb_destroy(void *context)
{
	return sep_urb_transport_destroy(context);
}

static int urb_monotonic_ms(void *context, uint64_t *value)
{
	struct sep_urb_transport *transport = context;

	if (!transport || !value || !transport->ops.monotonic_ms)
		return -1;
	return transport->ops.monotonic_ms(transport->ops.context, value) ==
			       SEP_URB_OP_OK ?
		       0 :
		       -1;
}

static int valid_transport_ops(const struct sep_session_transport_ops *ops)
{
	return ops && ops->exchange && ops->send_only && ops->receive_only &&
	       ops->destroy && ops->monotonic_ms;
}

void sep_session_clear_transfers(struct sep_session *session)
{
	if (!session)
		return;
	sep_keystore_clear(session->output, sizeof(session->output));
	sep_keystore_clear(session->input, sizeof(session->input));
}

static int poison(struct sep_session *session, int result)
{
	sep_session_clear_transfers(session);
	session->phase = SEP_SESSION_PHASE_POISONED;
	return result;
}

int sep_session_init_with_ops(struct sep_session *session,
			      const struct sep_session_transport_ops *ops,
			      uint64_t first_token,
			      uint32_t first_message_index)
{
	if (!session || !valid_transport_ops(ops) || first_token == 0)
		return SEP_SESSION_ERROR_ARGUMENT;
	memset(session, 0, sizeof(*session));
	session->transport = *ops;
	if (sep_relay_state_init(&session->relay, first_token,
				 first_message_index) != SEP_RELAY_OK) {
		memset(session, 0, sizeof(*session));
		return SEP_SESSION_ERROR_ARGUMENT;
	}
	session->phase = SEP_SESSION_PHASE_NEW;
	return SEP_SESSION_OK;
}

int sep_session_init(struct sep_session *session,
		     struct sep_urb_transport *transport, uint64_t first_token,
		     uint32_t first_message_index)
{
	const struct sep_session_transport_ops ops = {
		.context = transport,
		.exchange = urb_exchange,
		.send_only = urb_send_only,
		.receive_only = urb_receive_only,
		.destroy = urb_destroy,
		.monotonic_ms = urb_monotonic_ms,
	};

	if (!transport || sep_urb_transport_state(transport) !=
				  SEP_URB_STATE_READY)
		return SEP_SESSION_ERROR_ARGUMENT;
	return sep_session_init_with_ops(session, &ops, first_token,
					 first_message_index);
}

static int begin_deadline(struct sep_session *session, unsigned int timeout_ms,
			  uint64_t *deadline)
{
	uint64_t now;
	uint64_t requested_deadline;

	if (!session || !deadline || timeout_ms == 0 ||
	    timeout_ms > SEP_URB_MAX_TIMEOUT_MS)
		return SEP_SESSION_ERROR_ARGUMENT;
	if (session->phase == SEP_SESSION_PHASE_POISONED)
		return SEP_SESSION_ERROR_POISONED;
	if (session->phase == SEP_SESSION_PHASE_CLOSED)
		return SEP_SESSION_ERROR_STATE;
	if (session->transport.monotonic_ms(session->transport.context, &now) != 0)
		return poison(session, SEP_SESSION_ERROR_CLOCK);
	if (UINT64_MAX - now < timeout_ms)
		return poison(session, SEP_SESSION_ERROR_CLOCK);
	requested_deadline = now + timeout_ms;
	if (session->operation_deadline_set) {
		if (now >= session->operation_deadline_ms)
			return poison(session, SEP_SESSION_ERROR_TIMEOUT);
		if (session->operation_deadline_ms < requested_deadline)
			requested_deadline = session->operation_deadline_ms;
	}
	*deadline = requested_deadline;
	return SEP_SESSION_OK;
}

int sep_session_set_operation_deadline(struct sep_session *session,
				       uint64_t deadline_ms)
{
	uint64_t now;

	if (!session || deadline_ms == 0 || session->operation_deadline_set)
		return SEP_SESSION_ERROR_ARGUMENT;
	if (session->phase == SEP_SESSION_PHASE_POISONED)
		return SEP_SESSION_ERROR_POISONED;
	if (session->phase == SEP_SESSION_PHASE_CLOSED)
		return SEP_SESSION_ERROR_STATE;
	if (session->transport.monotonic_ms(session->transport.context, &now) != 0)
		return poison(session, SEP_SESSION_ERROR_CLOCK);
	if (now >= deadline_ms)
		return poison(session, SEP_SESSION_ERROR_TIMEOUT);
	/* The operation may span several transfers. Individual waits remain
	 * capped by SEP_URB_MAX_TIMEOUT_MS in remaining_timeout(). */
	if (deadline_ms - now > UINT_MAX)
		return SEP_SESSION_ERROR_ARGUMENT;
	session->operation_deadline_ms = deadline_ms;
	session->operation_deadline_set = 1;
	return SEP_SESSION_OK;
}

int sep_session_release_operation_deadline(struct sep_session *session)
{
	uint64_t now;

	if (!session || !session->operation_deadline_set)
		return SEP_SESSION_ERROR_ARGUMENT;
	if (session->phase == SEP_SESSION_PHASE_POISONED)
		return SEP_SESSION_ERROR_POISONED;
	if (session->phase == SEP_SESSION_PHASE_CLOSED)
		return SEP_SESSION_ERROR_STATE;
	if (session->transport.monotonic_ms(session->transport.context, &now) != 0)
		return poison(session, SEP_SESSION_ERROR_CLOCK);
	if (now >= session->operation_deadline_ms)
		return poison(session, SEP_SESSION_ERROR_TIMEOUT);
	session->operation_deadline_ms = 0;
	session->operation_deadline_set = 0;
	return SEP_SESSION_OK;
}

static int remaining_timeout(struct sep_session *session, uint64_t deadline,
			     unsigned int *remaining)
{
	uint64_t now;
	uint64_t difference;

	if (session->transport.monotonic_ms(session->transport.context, &now) != 0)
		return poison(session, SEP_SESSION_ERROR_CLOCK);
	if (now >= deadline)
		return poison(session, SEP_SESSION_ERROR_TIMEOUT);
	difference = deadline - now;
	if (difference > SEP_URB_MAX_TIMEOUT_MS)
		difference = SEP_URB_MAX_TIMEOUT_MS;
	*remaining = (unsigned int)difference;
	return SEP_SESSION_OK;
}

static int transport_failure(struct sep_session *session,
			     enum sep_urb_status status)
{
	if (status == SEP_URB_TIMED_OUT)
		return poison(session, SEP_SESSION_ERROR_TIMEOUT);
	return poison(session, SEP_SESSION_ERROR_TRANSPORT);
}

static int exchange_transfer(struct sep_session *session, uint64_t deadline)
{
	unsigned int remaining;
	int result;
	enum sep_urb_status status;

	result = remaining_timeout(session, deadline, &remaining);
	if (result != SEP_SESSION_OK)
		return result;
	status = session->transport.exchange(
		session->transport.context, session->output,
		sizeof(session->output), session->input, sizeof(session->input),
		remaining);
	sep_keystore_clear(session->output, sizeof(session->output));
	return status == SEP_URB_OK ? SEP_SESSION_OK :
				      transport_failure(session, status);
}

static int send_transfer(struct sep_session *session, uint64_t deadline)
{
	unsigned int remaining;
	int result;
	enum sep_urb_status status;

	result = remaining_timeout(session, deadline, &remaining);
	if (result != SEP_SESSION_OK)
		return result;
	status = session->transport.send_only(
		session->transport.context, session->output,
		sizeof(session->output), remaining);
	sep_keystore_clear(session->output, sizeof(session->output));
	return status == SEP_URB_OK ? SEP_SESSION_OK :
				      transport_failure(session, status);
}

static int receive_transfer(struct sep_session *session, uint64_t deadline)
{
	unsigned int remaining;
	int result;
	enum sep_urb_status status;

	result = remaining_timeout(session, deadline, &remaining);
	if (result != SEP_SESSION_OK)
		return result;
	status = session->transport.receive_only(
		session->transport.context, session->input,
		sizeof(session->input), remaining);
	return status == SEP_URB_OK ? SEP_SESSION_OK :
				      transport_failure(session, status);
}

static int parse_control_reply(struct sep_session *session,
			       const struct sep_relay_pending *pending,
			       int endpoint_status)
{
	struct sep_relay_message message;
	int result;

	result = sep_relay_parse(session->input, sizeof(session->input), &message);
	if (result != SEP_RELAY_OK) {
		fprintf(stderr, "t1bridge SEP reply: %s\n",
			relay_validation_name(result));
		return poison(session, SEP_SESSION_ERROR_PROTOCOL);
	}
	result = endpoint_status ?
			 sep_relay_accept_endpoint_status(&session->relay, &message,
						  pending) :
			 sep_relay_accept_version(&session->relay, &message, pending);
	if (result != SEP_RELAY_OK) {
		fprintf(stderr, "t1bridge SEP reply: %s\n",
			relay_validation_name(result));
		return poison(session, SEP_SESSION_ERROR_PROTOCOL);
	}
	return SEP_SESSION_OK;
}

int sep_session_negotiate(struct sep_session *session,
			  unsigned int timeout_ms)
{
	static const uint32_t security_endpoints[] = {
		SEP_RELAY_ACM_ENDPOINT,
		UINT32_C(2),
		SEP_RELAY_KEYSTORE_ENDPOINT,
	};
	struct sep_relay_pending pending;
	uint64_t deadline;
	size_t index;
	int result;

	if (!session)
		return SEP_SESSION_ERROR_ARGUMENT;
	if (session->phase != SEP_SESSION_PHASE_NEW)
		return session->phase == SEP_SESSION_PHASE_POISONED ?
			       SEP_SESSION_ERROR_POISONED :
			       SEP_SESSION_ERROR_STATE;
	result = begin_deadline(session, timeout_ms, &deadline);
	if (result != SEP_SESSION_OK)
		return result;
	result = sep_relay_build_get_version(&session->relay, session->output,
					     &pending);
	if (result != SEP_RELAY_OK)
		return poison(session, SEP_SESSION_ERROR_PROTOCOL);
	result = exchange_transfer(session, deadline);
	if (result != SEP_SESSION_OK)
		return result;
	result = parse_control_reply(session, &pending, 0);
	if (result != SEP_SESSION_OK)
		return result;

	result = sep_relay_build_endpoint_status(
		&session->relay, session->output, &pending);
	if (result != SEP_RELAY_OK)
		return poison(session, SEP_SESSION_ERROR_PROTOCOL);
	result = exchange_transfer(session, deadline);
	if (result != SEP_SESSION_OK)
		return result;
	result = parse_control_reply(session, &pending, 1);
	if (result != SEP_SESSION_OK)
		return result;

	for (index = 0; index < sizeof(security_endpoints) /
					 sizeof(security_endpoints[0]); ++index) {
		result = sep_relay_build_endpoint_enable(
			&session->relay, security_endpoints[index], 1,
			session->output, &pending);
		if (result != SEP_RELAY_OK)
			return poison(session, SEP_SESSION_ERROR_PROTOCOL);
		result = send_transfer(session, deadline);
		if (result != SEP_SESSION_OK)
			return result;
	}
	sep_keystore_clear(session->input, sizeof(session->input));
	session->phase = SEP_SESSION_PHASE_READY;
	return SEP_SESSION_OK;
}

static int wait_for_reply(struct sep_session *session,
			  const struct sep_relay_pending *pending,
			  uint64_t deadline, struct sep_relay_message *message)
{
	struct sep_relay_waiter waiter;
	enum sep_relay_message_class classification;
	int result;
	int first = 1;

	if (sep_relay_waiter_init(&waiter, pending,
				  SEP_RELAY_DEFAULT_SKIP_LIMIT) != SEP_RELAY_OK)
		return poison(session, SEP_SESSION_ERROR_PROTOCOL);
	for (;;) {
		result = first ? exchange_transfer(session, deadline) :
				 receive_transfer(session, deadline);
		first = 0;
		if (result != SEP_SESSION_OK)
			return result;
		result = sep_relay_waiter_consume(
			&waiter, session->input, sizeof(session->input),
			&classification, message);
		if (result == SEP_RELAY_MATCHED)
			return SEP_SESSION_OK;
		if (result == SEP_RELAY_SKIPPED)
			continue;
		if (result == SEP_RELAY_ERROR_SKIP_LIMIT) {
			fprintf(stderr,
				"t1bridge SEP reply: unrelated message limit reached\n");
			return poison(session, SEP_SESSION_ERROR_SKIP_LIMIT);
		}
		fprintf(stderr, "t1bridge SEP reply: %s\n",
			relay_validation_name(result));
		return poison(session, SEP_SESSION_ERROR_PROTOCOL);
	}
}

int sep_session_keystore_exchange(
	struct sep_session *session,
	const struct sep_keystore_operation *operation, const void *request,
	size_t request_length, struct sep_keystore_reply *reply,
	unsigned int timeout_ms)
{
	struct sep_relay_pending pending;
	struct sep_relay_message message;
	uint64_t deadline;
	int result;

	if (!session || !operation || !request || !reply ||
	    request_length != operation->request_length)
		return SEP_SESSION_ERROR_ARGUMENT;
	if (session->phase != SEP_SESSION_PHASE_READY)
		return session->phase == SEP_SESSION_PHASE_POISONED ?
			       SEP_SESSION_ERROR_POISONED :
			       SEP_SESSION_ERROR_STATE;
	result = begin_deadline(session, timeout_ms, &deadline);
	if (result != SEP_SESSION_OK)
		return result;
	sep_session_clear_transfers(session);
	result = sep_keystore_wrap_request(&session->relay, operation, request,
					   request_length, session->output,
					   &pending);
	if (result == SEP_KEYSTORE_ERROR_RELAY)
		return poison(session, SEP_SESSION_ERROR_PROTOCOL);
	if (result != SEP_KEYSTORE_OK)
		return SEP_SESSION_ERROR_ARGUMENT;
	result = wait_for_reply(session, &pending, deadline, &message);
	if (result != SEP_SESSION_OK)
		return result;
	result = sep_keystore_parse_reply(&message, &pending, operation, reply);
	if (result == SEP_KEYSTORE_REMOTE_ERROR) {
		sep_session_clear_transfers(session);
		return SEP_SESSION_REMOTE_ERROR;
	}
	if (result != SEP_KEYSTORE_OK) {
		fprintf(stderr, "t1bridge SEP reply: %s\n",
			keystore_validation_name(result));
		return poison(session, SEP_SESSION_ERROR_PROTOCOL);
	}
	return SEP_SESSION_OK;
}

int sep_session_drain_notification(struct sep_session *session,
				   unsigned int timeout_ms)
{
	struct sep_relay_message message;
	enum sep_urb_status status;

	if (!session || timeout_ms == 0 ||
	    timeout_ms > SEP_URB_MAX_TIMEOUT_MS)
		return SEP_SESSION_ERROR_ARGUMENT;
	if (session->phase != SEP_SESSION_PHASE_READY)
		return session->phase == SEP_SESSION_PHASE_POISONED ?
			       SEP_SESSION_ERROR_POISONED :
			       SEP_SESSION_ERROR_STATE;
	sep_session_clear_transfers(session);
	status = session->transport.receive_only(
		session->transport.context, session->input,
		sizeof(session->input), timeout_ms);
	if (status == SEP_URB_TIMED_OUT || status == SEP_URB_INTERRUPTED) {
		sep_session_clear_transfers(session);
		return SEP_SESSION_IDLE;
	}
	if (status != SEP_URB_OK)
		return transport_failure(session, status);
	if (sep_relay_parse(session->input, sizeof(session->input), &message) !=
		    SEP_RELAY_OK ||
	    sep_relay_classify(&message) !=
		    SEP_RELAY_MESSAGE_KEYSTORE_NOTIFICATION)
		return poison(session, SEP_SESSION_ERROR_PROTOCOL);
	sep_session_clear_transfers(session);
	return SEP_SESSION_OK;
}

int sep_session_acm_exchange(struct sep_session *session,
			     struct sep_acm_state *state,
			     sep_session_acm_builder builder,
			     void *builder_context,
			     struct sep_acm_outcome *outcome,
			     unsigned int timeout_ms)
{
	struct sep_relay_message message;
	struct sep_relay_pending completed;
	struct sep_relay_pending ready;
	uint64_t deadline;
	int accept_result;
	int result;

	if (!session || !state || !builder || !outcome)
		return SEP_SESSION_ERROR_ARGUMENT;
	if (session->phase != SEP_SESSION_PHASE_READY)
		return session->phase == SEP_SESSION_PHASE_POISONED ?
			       SEP_SESSION_ERROR_POISONED :
			       SEP_SESSION_ERROR_STATE;
	result = begin_deadline(session, timeout_ms, &deadline);
	if (result != SEP_SESSION_OK)
		return result;
	sep_session_clear_transfers(session);
	result = builder(builder_context, state, &session->relay,
			 session->output);
	if (result == SEP_ACM_ERROR_RELAY)
		return poison(session, SEP_SESSION_ERROR_PROTOCOL);
	if (result == SEP_ACM_ERROR_ARGUMENT) {
		sep_session_clear_transfers(session);
		return SEP_SESSION_ERROR_ARGUMENT;
	}
	if (result != SEP_ACM_OK) {
		sep_session_clear_transfers(session);
		return SEP_SESSION_ERROR_STATE;
	}
	completed = state->pending;
	result = wait_for_reply(session, &completed, deadline, &message);
	if (result != SEP_SESSION_OK) {
		(void)sep_acm_mark_ambiguous(state);
		return result;
	}
	accept_result = sep_acm_accept_reply(state, &message, outcome);
	if (accept_result != SEP_ACM_OK &&
	    accept_result != SEP_ACM_ERROR_REMOTE)
		return poison(session, SEP_SESSION_ERROR_PROTOCOL);

	result = sep_relay_build_endpoint_ready(
		&session->relay, SEP_RELAY_ACM_ENDPOINT, &completed,
		session->output, &ready);
	if (result != SEP_RELAY_OK)
		return poison(session, SEP_SESSION_ERROR_PROTOCOL);
	result = send_transfer(session, deadline);
	if (result != SEP_SESSION_OK)
		return result;
	sep_keystore_clear(session->input, sizeof(session->input));
	return accept_result == SEP_ACM_ERROR_REMOTE ?
		       SEP_SESSION_REMOTE_ERROR :
		       SEP_SESSION_OK;
}

int sep_session_destroy(struct sep_session *session)
{
	enum sep_urb_status status;

	if (!session)
		return SEP_SESSION_ERROR_ARGUMENT;
	if (session->phase == SEP_SESSION_PHASE_CLOSED)
		return SEP_SESSION_OK;
	sep_session_clear_transfers(session);
	status = session->transport.destroy ?
			 session->transport.destroy(session->transport.context) :
			 SEP_URB_INVALID_STATE;
	sep_keystore_clear(&session->relay, sizeof(session->relay));
	memset(&session->transport, 0, sizeof(session->transport));
	session->operation_deadline_ms = 0;
	session->operation_deadline_set = 0;
	session->phase = SEP_SESSION_PHASE_CLOSED;
	return status == SEP_URB_OK ? SEP_SESSION_OK :
				      SEP_SESSION_ERROR_TEARDOWN;
}

enum sep_session_phase sep_session_phase(const struct sep_session *session)
{
	return session ? session->phase : SEP_SESSION_PHASE_CLOSED;
}

const char *sep_session_result_name(int result)
{
	switch (result) {
	case SEP_SESSION_OK:
		return "success";
	case SEP_SESSION_REMOTE_ERROR:
		return "remote operation rejected";
	case SEP_SESSION_IDLE:
		return "notification relay idle";
	case SEP_SESSION_ERROR_ARGUMENT:
		return "invalid session input";
	case SEP_SESSION_ERROR_STATE:
		return "invalid session state";
	case SEP_SESSION_ERROR_CLOCK:
		return "session clock failed";
	case SEP_SESSION_ERROR_TRANSPORT:
		return "session transport failed";
	case SEP_SESSION_ERROR_TIMEOUT:
		return "session timed out";
	case SEP_SESSION_ERROR_PROTOCOL:
		return "session protocol validation failed";
	case SEP_SESSION_ERROR_SKIP_LIMIT:
		return "unrelated message limit reached";
	case SEP_SESSION_ERROR_POISONED:
		return "session is poisoned";
	case SEP_SESSION_ERROR_TEARDOWN:
		return "session teardown failed";
	default:
		return "unknown session failure";
	}
}

#include "t1_xart_listener.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ARRAY_SIZE(values) (sizeof(values) / sizeof((values)[0]))
#define FAKE_DESCRIPTOR 73
#define FAKE_CONNECTION 91
#define SYNTHETIC_INDEX 41u

static unsigned int failures;

#define CHECK(condition, message)                                             \
	do {                                                                    \
		if (!(condition)) {                                                \
			fprintf(stderr, "FAIL: %s\n", message);                     \
			failures++;                                                 \
		}                                                               \
	} while (0)

struct fake_state {
	struct t1_xart_interface_candidate candidates[4];
	size_t candidate_count;
	int enumerate_result;
	int socket_result;
	int bind_interface_result;
	int bind_address_result;
	int listen_result;
	int inspect_result;
	uint32_t bound_index;
	int accept_result;
	struct t1_xart_peer_observation peer;
	unsigned int enumerate_calls;
	uint32_t replacement_index;
	unsigned int close_calls;
	int closed_descriptor;
	uint32_t bound_argument;
	uint16_t port_argument;
	int backlog_argument;
};

static struct t1_xart_interface_candidate valid_candidate(uint32_t index)
{
	const struct t1_xart_interface_candidate candidate = {
		.interface_index = index,
		.usb_vendor_id = T1_XART_APPLE_VENDOR_ID,
		.usb_product_id = T1_XART_APPLE_PRODUCT_ID,
		.usb_interface_number = T1_XART_NCM_INTERFACE,
		.driver_matches = 1,
	};

	return candidate;
}

static struct fake_state default_state(void)
{
	struct fake_state state;

	memset(&state, 0, sizeof(state));
	state.candidates[0] = valid_candidate(SYNTHETIC_INDEX);
	state.candidate_count = 1;
	state.socket_result = FAKE_DESCRIPTOR;
	state.bound_index = SYNTHETIC_INDEX;
	state.accept_result = FAKE_CONNECTION;
	state.peer.peer_scope_id = SYNTHETIC_INDEX;
	state.peer.peer_port = 49152;
	state.peer.peer_address[0] = 0xfe;
	state.peer.peer_address[1] = 0x80;
	state.closed_descriptor = -1;
	return state;
}

static int fake_enumerate(void *context,
	struct t1_xart_interface_candidate *candidates, size_t capacity,
	size_t *count)
{
	struct fake_state *state = context;
	struct t1_xart_interface_candidate source[4];

	state->enumerate_calls++;
	if (state->enumerate_result != 0)
		return state->enumerate_result;
	if (state->candidate_count > capacity) {
		*count = state->candidate_count;
		return 0;
	}
	memcpy(source, state->candidates,
	       state->candidate_count * sizeof(*source));
	if (state->enumerate_calls > 1 && state->replacement_index != 0)
		source[0].interface_index = state->replacement_index;
	memcpy(candidates, source,
	       state->candidate_count * sizeof(*candidates));
	*count = state->candidate_count;
	return 0;
}

static int fake_open_socket(void *context)
{
	return ((struct fake_state *)context)->socket_result;
}

static int fake_bind_interface(void *context, int descriptor,
	uint32_t interface_index)
{
	struct fake_state *state = context;

	CHECK(descriptor == FAKE_DESCRIPTOR, "bind receives opened descriptor");
	state->bound_argument = interface_index;
	return state->bind_interface_result;
}

static int fake_bind_address(void *context, int descriptor, uint16_t port)
{
	struct fake_state *state = context;

	CHECK(descriptor == FAKE_DESCRIPTOR, "address bind receives descriptor");
	state->port_argument = port;
	return state->bind_address_result;
}

static int fake_listen(void *context, int descriptor, int backlog)
{
	struct fake_state *state = context;

	CHECK(descriptor == FAKE_DESCRIPTOR, "listen receives descriptor");
	state->backlog_argument = backlog;
	return state->listen_result;
}

static int fake_bound_interface(void *context, int descriptor,
	uint32_t *interface_index)
{
	struct fake_state *state = context;

	CHECK(descriptor == FAKE_DESCRIPTOR, "inspection receives listener");
	if (state->inspect_result != 0)
		return state->inspect_result;
	*interface_index = state->bound_index;
	return 0;
}

static int fake_accept(void *context, int descriptor,
	struct t1_xart_peer_observation *observation)
{
	struct fake_state *state = context;

	CHECK(descriptor == FAKE_DESCRIPTOR, "accept receives listener");
	if (state->accept_result >= 0)
		*observation = state->peer;
	return state->accept_result;
}

static int fake_close(void *context, int descriptor)
{
	struct fake_state *state = context;

	state->close_calls++;
	state->closed_descriptor = descriptor;
	return 0;
}

static struct t1_xart_listener_ops fake_ops(struct fake_state *state)
{
	const struct t1_xart_listener_ops ops = {
		.context = state,
		.enumerate = fake_enumerate,
		.open_socket = fake_open_socket,
		.bind_interface = fake_bind_interface,
		.bind_address = fake_bind_address,
		.listen_socket = fake_listen,
		.bound_interface = fake_bound_interface,
		.accept_socket = fake_accept,
		.close_fd = fake_close,
	};

	return ops;
}

static enum t1_xart_listener_status open_fake(struct fake_state *state,
	int *descriptor, uint32_t *index)
{
	const struct t1_xart_listener_ops ops = fake_ops(state);

	return t1_xart_listener_open_with_ops(&ops, descriptor, index);
}

static enum t1_xart_listener_status discover_fake(
	struct fake_state *state, uint32_t *index)
{
	const struct t1_xart_listener_ops ops = fake_ops(state);

	return t1_xart_interface_discover_with_ops(&ops, index);
}

static enum t1_xart_listener_status accept_fake(struct fake_state *state,
	int *descriptor, struct t1_xart_peer_observation *observation)
{
	const struct t1_xart_listener_ops ops = fake_ops(state);

	return t1_xart_listener_accept_with_ops(&ops, FAKE_DESCRIPTOR,
		descriptor, observation);
}

static void test_open_selects_and_binds_unique_interface(void)
{
	struct fake_state state = default_state();
	uint32_t index = 0;
	int descriptor = -1;

	CHECK(open_fake(&state, &descriptor, &index) ==
		T1_XART_LISTENER_OK, "open unique interface");
	CHECK(descriptor == FAKE_DESCRIPTOR, "transfer listener descriptor");
	CHECK(index == SYNTHETIC_INDEX, "transfer interface index");
	CHECK(state.bound_argument == SYNTHETIC_INDEX,
	      "bind selected interface only");
	CHECK(state.port_argument == T1_XART_PORT,
	      "bind verified xART protocol port");
	CHECK(state.backlog_argument == 4, "use bounded backlog");
	CHECK(state.close_calls == 0, "retain successful listener");
	CHECK(state.enumerate_calls == 2,
	      "revalidate metadata after kernel binding");
}

static void test_read_only_discovery_has_exact_bounded_outcomes(void)
{
	struct fake_state state = default_state();
	uint32_t index = 0;

	CHECK(discover_fake(&state, &index) == T1_XART_LISTENER_OK,
	      "discover exact validated interface");
	CHECK(index == SYNTHETIC_INDEX, "return only validated kernel index");
	CHECK(state.enumerate_calls == 1 && state.bound_argument == 0 &&
	      state.port_argument == 0 && state.backlog_argument == 0,
	      "read-only discovery performs no socket operation");

	state = default_state();
	state.candidate_count = 0;
	index = 99;
	CHECK(discover_fake(&state, &index) ==
		T1_XART_LISTENER_DEVICE_NOT_FOUND,
	      "read-only discovery reports absence");
	CHECK(index == 0, "absence clears discovery output");

	state = default_state();
	state.candidates[1] = valid_candidate(SYNTHETIC_INDEX + 1);
	state.candidate_count = 2;
	CHECK(discover_fake(&state, &index) ==
		T1_XART_LISTENER_DEVICE_AMBIGUOUS,
	      "read-only discovery reports ambiguity");
	CHECK(index == 0, "ambiguity transfers no index");

	state = default_state();
	state.candidates[0].interface_index = 0;
	CHECK(discover_fake(&state, &index) ==
		T1_XART_LISTENER_DEVICE_NOT_FOUND,
	      "read-only discovery rejects malformed index");
	state.candidates[0] = valid_candidate(SYNTHETIC_INDEX);
	state.candidates[0].driver_matches = 2;
	CHECK(discover_fake(&state, &index) ==
		T1_XART_LISTENER_DEVICE_NOT_FOUND,
	      "read-only discovery rejects malformed driver evidence");
}

static void test_discovery_rejects_absent_invalid_and_ambiguous(void)
{
	struct fake_state state = default_state();
	uint32_t index = 99;
	int descriptor = 99;

	state.candidate_count = 0;
	CHECK(open_fake(&state, &descriptor, &index) ==
		T1_XART_LISTENER_DEVICE_NOT_FOUND, "reject absent interface");
	CHECK(descriptor == -1 && index == 0, "clear absent outputs");

	state = default_state();
	state.candidates[0].driver_matches = 0;
	CHECK(open_fake(&state, &descriptor, &index) ==
		T1_XART_LISTENER_DEVICE_NOT_FOUND, "reject wrong driver");
	state.candidates[0] = valid_candidate(SYNTHETIC_INDEX);
	state.candidates[0].usb_vendor_id ^= 1;
	CHECK(open_fake(&state, &descriptor, &index) ==
		T1_XART_LISTENER_DEVICE_NOT_FOUND, "reject wrong USB device");
	state.candidates[0] = valid_candidate(SYNTHETIC_INDEX);
	state.candidates[0].usb_interface_number ^= 1;
	CHECK(open_fake(&state, &descriptor, &index) ==
		T1_XART_LISTENER_DEVICE_NOT_FOUND, "reject wrong USB interface");

	state = default_state();
	state.candidates[1] = valid_candidate(SYNTHETIC_INDEX + 1);
	state.candidate_count = 2;
	CHECK(open_fake(&state, &descriptor, &index) ==
		T1_XART_LISTENER_DEVICE_AMBIGUOUS,
	      "reject multiple validated interfaces");
	CHECK(state.socket_result == FAKE_DESCRIPTOR && state.close_calls == 0,
	      "ambiguity stops before socket creation");
}

static void test_enumeration_failures_are_distinct_and_bounded(void)
{
	struct fake_state state = default_state();
	uint32_t index;
	int descriptor;

	state.enumerate_result = -1;
	CHECK(open_fake(&state, &descriptor, &index) ==
		T1_XART_LISTENER_ENUMERATION_FAILED,
	      "report enumeration failure");
	state.enumerate_result = 1;
	CHECK(open_fake(&state, &descriptor, &index) ==
		T1_XART_LISTENER_CANDIDATE_LIMIT,
	      "report enumeration limit");
}

static void test_socket_failures_close_owned_descriptor(void)
{
	struct fake_state state = default_state();
	uint32_t index;
	int descriptor;

	state.socket_result = -1;
	CHECK(open_fake(&state, &descriptor, &index) ==
		T1_XART_LISTENER_SOCKET_FAILED, "report socket failure");
	CHECK(state.close_calls == 0, "do not close absent socket");

	state = default_state();
	state.bind_interface_result = -1;
	CHECK(open_fake(&state, &descriptor, &index) ==
		T1_XART_LISTENER_BIND_FAILED, "report interface bind failure");
	CHECK(state.close_calls == 1 &&
	      state.closed_descriptor == FAKE_DESCRIPTOR,
	      "close after bind failure");

	state = default_state();
	state.inspect_result = -1;
	CHECK(open_fake(&state, &descriptor, &index) ==
		T1_XART_LISTENER_INSPECTION_FAILED,
	      "report post-bind inspection failure");
	CHECK(state.close_calls == 1, "close after inspection failure");

	state = default_state();
	state.bound_index++;
	CHECK(open_fake(&state, &descriptor, &index) ==
		T1_XART_LISTENER_WRONG_INTERFACE,
	      "reject changed kernel binding");
	CHECK(state.close_calls == 1, "close wrong-interface listener");

	state = default_state();
	state.listen_result = -1;
	CHECK(open_fake(&state, &descriptor, &index) ==
		T1_XART_LISTENER_LISTEN_FAILED, "report listen failure");
	CHECK(state.close_calls == 1, "close after listen failure");
}

static void test_post_bind_device_replacement_is_rejected(void)
{
	struct fake_state state = default_state();
	uint32_t index;
	int descriptor;

	state.replacement_index = SYNTHETIC_INDEX + 1;
	CHECK(open_fake(&state, &descriptor, &index) ==
		T1_XART_LISTENER_WRONG_INTERFACE,
	      "reject interface identity replaced during bind");
	CHECK(descriptor == -1 && index == 0,
	      "replacement transfers no outputs");
	CHECK(state.close_calls == 1, "close listener after replacement");
}

static void test_accept_captures_kernel_evidence(void)
{
	struct fake_state state = default_state();
	struct t1_xart_peer_observation observation;
	int descriptor = -1;

	memset(&observation, 0, sizeof(observation));
	CHECK(accept_fake(&state, &descriptor, &observation) ==
		T1_XART_LISTENER_OK, "accept connection");
	CHECK(descriptor == FAKE_CONNECTION, "transfer accepted descriptor");
	CHECK(observation.listener_interface_index == SYNTHETIC_INDEX,
	      "capture current listener binding");
	CHECK(observation.peer_scope_id == SYNTHETIC_INDEX &&
	      observation.peer_port == 49152 &&
	      observation.peer_address[0] == 0xfe &&
	      observation.peer_address[1] == 0x80,
	      "capture peer evidence before return");
}

static void test_accept_rejects_uncertain_socket_state(void)
{
	struct fake_state state = default_state();
	struct t1_xart_peer_observation observation;
	int descriptor = 17;

	state.inspect_result = -1;
	CHECK(accept_fake(&state, &descriptor, &observation) ==
		T1_XART_LISTENER_INSPECTION_FAILED,
	      "reject uninspectable listener");
	CHECK(descriptor == -1, "clear failed accept descriptor");

	const struct {
		int result;
		enum t1_xart_listener_status expected;
	} cases[] = {
		{ -EAGAIN, T1_XART_LISTENER_WOULD_BLOCK },
		{ -EINTR, T1_XART_LISTENER_INTERRUPTED },
		{ -EAFNOSUPPORT, T1_XART_LISTENER_WRONG_PEER_FAMILY },
		{ -EIO, T1_XART_LISTENER_ACCEPT_FAILED },
	};
	for (size_t index = 0; index < ARRAY_SIZE(cases); index++) {
		state = default_state();
		state.accept_result = cases[index].result;
		CHECK(accept_fake(&state, &descriptor, &observation) ==
			cases[index].expected, "map accept failure");
		CHECK(descriptor == -1, "failed accept transfers no descriptor");
	}
}

static void test_invalid_arguments_clear_outputs(void)
{
	struct fake_state state = default_state();
	struct t1_xart_listener_ops ops = fake_ops(&state);
	struct t1_xart_peer_observation observation;
	uint32_t index = 55;
	int descriptor = 55;

	CHECK(t1_xart_listener_open_with_ops(NULL, &descriptor, &index) ==
		T1_XART_LISTENER_INVALID_ARGUMENT, "reject absent ops");
	CHECK(descriptor == -1 && index == 0, "clear invalid open outputs");
	ops.close_fd = NULL;
	CHECK(t1_xart_listener_open_with_ops(&ops, &descriptor, &index) ==
		T1_XART_LISTENER_INVALID_ARGUMENT, "reject incomplete ops");
	CHECK(t1_xart_listener_accept_with_ops(&ops, FAKE_DESCRIPTOR,
		&descriptor, &observation) == T1_XART_LISTENER_INVALID_ARGUMENT,
	      "reject incomplete accept ops");
}

int main(void)
{
	test_open_selects_and_binds_unique_interface();
	test_read_only_discovery_has_exact_bounded_outcomes();
	test_discovery_rejects_absent_invalid_and_ambiguous();
	test_enumeration_failures_are_distinct_and_bounded();
	test_socket_failures_close_owned_descriptor();
	test_post_bind_device_replacement_is_rejected();
	test_accept_captures_kernel_evidence();
	test_accept_rejects_uncertain_socket_state();
	test_invalid_arguments_clear_outputs();

	if (failures != 0) {
		fprintf(stderr, "xart_listener: %u tests failed\n", failures);
		return 1;
	}
	puts("xart_listener: all tests passed");
	return 0;
}

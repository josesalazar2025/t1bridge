#include "t1_touchid_cancel.h"

#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define ARRAY_SIZE(values) (sizeof(values) / sizeof((values)[0]))
#define FAKE_DESCRIPTOR 73

static unsigned int failures;

#define CHECK(condition, message)                                             \
	do {                                                                    \
		if (!(condition)) {                                                \
			fprintf(stderr, "FAIL: %s\n", message);                     \
			failures++;                                                 \
		}                                                               \
	} while (0)

struct fake_cancel {
	uint64_t now;
	uint64_t clock_step;
	int clock_result;
	int inspect_result;
	int open_result;
	int connect_results[4];
	size_t connect_count;
	size_t connect_index;
	int credentials_result;
	uint32_t peer_user_id;
	int send_results[4];
	size_t send_count;
	size_t send_index;
	int receive_results[4];
	size_t receive_count;
	size_t receive_index;
	uint8_t reply[8];
	size_t reply_length;
	int wait_results[4];
	size_t wait_count;
	size_t wait_index;
	int close_result;
	unsigned int inspect_calls;
	unsigned int open_calls;
	unsigned int credential_calls;
	unsigned int send_calls;
	unsigned int receive_calls;
	unsigned int wait_calls;
	unsigned int close_calls;
	unsigned int last_wait_timeout;
	enum t1_touchid_cancel_wait last_wait_interest;
};

static struct fake_cancel default_fake(void)
{
	struct fake_cancel fake;

	memset(&fake, 0, sizeof(fake));
	fake.now = 100;
	fake.open_result = FAKE_DESCRIPTOR;
	fake.peer_user_id = 0;
	memcpy(fake.reply, "OKAY", 4);
	fake.reply_length = 4;
	return fake;
}

static int next_result(const int *results, size_t count, size_t *index)
{
	if (*index >= count)
		return 0;
	return results[(*index)++];
}

static int fake_monotonic(void *context, uint64_t *value)
{
	struct fake_cancel *fake = context;

	if (fake->clock_result != 0)
		return fake->clock_result;
	*value = fake->now;
	fake->now += fake->clock_step;
	return 0;
}

static int fake_inspect(void *context, const char *path)
{
	struct fake_cancel *fake = context;

	fake->inspect_calls++;
	CHECK(strcmp(path, "/run/t1-touchid/auth.sock") == 0,
	      "inspect only fixed broker path");
	return fake->inspect_result;
}

static int fake_open(void *context)
{
	struct fake_cancel *fake = context;

	fake->open_calls++;
	return fake->open_result;
}

static int fake_connect(void *context, int descriptor, const char *path)
{
	struct fake_cancel *fake = context;

	CHECK(descriptor == FAKE_DESCRIPTOR, "connect uses owned descriptor");
	CHECK(strcmp(path, "/run/t1-touchid/auth.sock") == 0,
	      "connect only fixed broker path");
	return next_result(fake->connect_results, fake->connect_count,
		&fake->connect_index);
}

static int fake_peer_user(void *context, int descriptor, uint32_t *user_id)
{
	struct fake_cancel *fake = context;

	CHECK(descriptor == FAKE_DESCRIPTOR, "credentials use connected descriptor");
	fake->credential_calls++;
	if (fake->credentials_result != 0)
		return fake->credentials_result;
	*user_id = fake->peer_user_id;
	return 0;
}

static int fake_send(void *context, int descriptor, const void *packet,
	size_t packet_length)
{
	static const uint8_t expected[] = {
		'T', '1', 'C', 'N', 'C', 'L', 0x01, '\n'
	};
	struct fake_cancel *fake = context;

	CHECK(descriptor == FAKE_DESCRIPTOR, "send uses connected descriptor");
	CHECK(packet_length == sizeof(expected) &&
	      memcmp(packet, expected, sizeof(expected)) == 0,
	      "send only exact cancellation request");
	fake->send_calls++;
	return next_result(fake->send_results, fake->send_count,
		&fake->send_index);
}

static int fake_receive(void *context, int descriptor, void *packet,
	size_t capacity, size_t *packet_length)
{
	struct fake_cancel *fake = context;
	int result;

	CHECK(descriptor == FAKE_DESCRIPTOR, "receive uses connected descriptor");
	fake->receive_calls++;
	result = next_result(fake->receive_results, fake->receive_count,
		&fake->receive_index);
	if (result != 0)
		return result;
	if (fake->reply_length <= capacity)
		memcpy(packet, fake->reply, fake->reply_length);
	*packet_length = fake->reply_length;
	return 0;
}

static int fake_wait(void *context, int descriptor,
	enum t1_touchid_cancel_wait interest, unsigned int timeout_ms)
{
	struct fake_cancel *fake = context;

	CHECK(descriptor == FAKE_DESCRIPTOR, "wait uses connected descriptor");
	fake->wait_calls++;
	fake->last_wait_interest = interest;
	fake->last_wait_timeout = timeout_ms;
	return next_result(fake->wait_results, fake->wait_count,
		&fake->wait_index);
}

static int fake_close(void *context, int descriptor)
{
	struct fake_cancel *fake = context;

	CHECK(descriptor == FAKE_DESCRIPTOR, "close consumes owned descriptor");
	fake->close_calls++;
	return fake->close_result;
}

static struct t1_touchid_cancel_ops fake_ops(struct fake_cancel *fake)
{
	const struct t1_touchid_cancel_ops ops = {
		.context = fake,
		.monotonic_ms = fake_monotonic,
		.inspect_path = fake_inspect,
		.open_socket = fake_open,
		.connect_socket = fake_connect,
		.peer_user_id = fake_peer_user,
		.send_packet = fake_send,
		.receive_packet = fake_receive,
		.wait_socket = fake_wait,
		.close_fd = fake_close,
	};

	return ops;
}

static enum t1_touchid_cancel_result run_fake(struct fake_cancel *fake)
{
	const struct t1_touchid_cancel_ops ops = fake_ops(fake);

	return t1_touchid_cancel_with_ops(&ops);
}

static void test_exact_accepted_and_denied_transactions(void)
{
	struct fake_cancel fake = default_fake();

	CHECK(run_fake(&fake) == T1_TOUCHID_CANCEL_OK,
	      "accept exact OKAY reply");
	CHECK(fake.inspect_calls == 1 && fake.open_calls == 1 &&
	      fake.credential_calls == 1 && fake.send_calls == 1 &&
	      fake.receive_calls == 1 && fake.close_calls == 1,
	      "run every exact transaction stage once");

	fake = default_fake();
	memcpy(fake.reply, "DENY", 4);
	CHECK(run_fake(&fake) == T1_TOUCHID_CANCEL_DENIED,
	      "preserve exact broker denial");
	CHECK(fake.close_calls == 1, "close denied transaction");
}

static void test_path_and_root_credentials_are_mandatory(void)
{
	struct fake_cancel fake = default_fake();

	fake.inspect_result = -1;
	CHECK(run_fake(&fake) == T1_TOUCHID_CANCEL_ERROR_PATH,
	      "reject unsafe or absent socket metadata");
	CHECK(fake.open_calls == 0, "path rejection stops before socket open");

	fake = default_fake();
	fake.peer_user_id = 1001;
	CHECK(run_fake(&fake) == T1_TOUCHID_CANCEL_ERROR_CREDENTIALS,
	      "reject non-root connected peer");
	CHECK(fake.send_calls == 0 && fake.close_calls == 1,
	      "credential rejection sends nothing and closes");

	fake = default_fake();
	fake.credentials_result = -1;
	CHECK(run_fake(&fake) == T1_TOUCHID_CANCEL_ERROR_CREDENTIALS,
	      "fail closed when credentials are unavailable");
}

static void test_only_exact_replies_are_terminal_outcomes(void)
{
	struct fake_cancel fake = default_fake();

	memcpy(fake.reply, "FAIL", 4);
	CHECK(run_fake(&fake) == T1_TOUCHID_CANCEL_ERROR_PROTOCOL,
	      "reject unknown four-byte reply");
	fake = default_fake();
	fake.reply_length = 3;
	CHECK(run_fake(&fake) == T1_TOUCHID_CANCEL_ERROR_PROTOCOL,
	      "reject short reply");
	fake = default_fake();
	fake.reply_length = 5;
	CHECK(run_fake(&fake) == T1_TOUCHID_CANCEL_ERROR_PROTOCOL,
	      "reject oversized reply result");
}

static void test_one_deadline_bounds_connect_send_and_receive(void)
{
	struct fake_cancel fake = default_fake();

	fake.connect_results[0] = 1;
	fake.connect_count = 1;
	fake.clock_step = 25;
	CHECK(run_fake(&fake) == T1_TOUCHID_CANCEL_OK,
	      "retry pending connect within total deadline");
	CHECK(fake.wait_calls == 1 &&
	      fake.last_wait_interest == T1_TOUCHID_CANCEL_WAIT_WRITE &&
	      fake.last_wait_timeout < 500,
	      "connect wait receives only remaining budget");

	fake = default_fake();
	fake.send_results[0] = 1;
	fake.send_count = 1;
	fake.receive_results[0] = 1;
	fake.receive_count = 1;
	fake.clock_step = 40;
	CHECK(run_fake(&fake) == T1_TOUCHID_CANCEL_OK,
	      "retry send and receive within shared deadline");
	CHECK(fake.wait_calls == 2 &&
	      fake.last_wait_interest == T1_TOUCHID_CANCEL_WAIT_READ &&
	      fake.last_wait_timeout < 500,
	      "receive wait uses reduced shared budget");

	fake = default_fake();
	fake.clock_step = 500;
	CHECK(run_fake(&fake) == T1_TOUCHID_CANCEL_ERROR_TIMEOUT,
	      "expire before opening after metadata consumes total budget");
	CHECK(fake.open_calls == 0, "deadline stops before socket mutation");

	fake = default_fake();
	fake.receive_results[0] = 1;
	fake.receive_count = 1;
	fake.wait_results[0] = 1;
	fake.wait_count = 1;
	CHECK(run_fake(&fake) == T1_TOUCHID_CANCEL_ERROR_TIMEOUT,
	      "poll timeout is terminal");
}

static void test_io_and_cleanup_failures_are_typed(void)
{
	struct fake_cancel fake = default_fake();

	fake.open_result = -1;
	CHECK(run_fake(&fake) == T1_TOUCHID_CANCEL_ERROR_CONNECT,
	      "map socket open failure");
	fake = default_fake();
	fake.connect_results[0] = -1;
	fake.connect_count = 1;
	CHECK(run_fake(&fake) == T1_TOUCHID_CANCEL_ERROR_CONNECT,
	      "map connect failure");
	fake = default_fake();
	fake.send_results[0] = -1;
	fake.send_count = 1;
	CHECK(run_fake(&fake) == T1_TOUCHID_CANCEL_ERROR_SEND,
	      "map send failure");
	fake = default_fake();
	fake.receive_results[0] = -1;
	fake.receive_count = 1;
	CHECK(run_fake(&fake) == T1_TOUCHID_CANCEL_ERROR_RECEIVE,
	      "map receive failure");
	fake = default_fake();
	fake.close_result = -1;
	CHECK(run_fake(&fake) == T1_TOUCHID_CANCEL_ERROR_CLOSE,
	      "successful delivery requires descriptor cleanup");
}

static void test_invalid_ops_never_start(void)
{
	struct fake_cancel fake = default_fake();
	struct t1_touchid_cancel_ops ops = fake_ops(&fake);

	CHECK(t1_touchid_cancel_with_ops(NULL) ==
		T1_TOUCHID_CANCEL_ERROR_ARGUMENT, "reject absent ops");
	ops.receive_packet = NULL;
	CHECK(t1_touchid_cancel_with_ops(&ops) ==
		T1_TOUCHID_CANCEL_ERROR_ARGUMENT, "reject incomplete ops");
	CHECK(fake.inspect_calls == 0, "invalid ops perform no operation");
}

static void test_poll_event_policy_preserves_queued_reply(void)
{
	CHECK(t1_touchid_cancel_test_poll_events(POLLIN | POLLHUP,
		T1_TOUCHID_CANCEL_WAIT_READ) == 0,
	      "read readiness wins when peer also closes");
	CHECK(t1_touchid_cancel_test_poll_events(POLLHUP,
		T1_TOUCHID_CANCEL_WAIT_READ) == 0,
	      "read-side hangup proceeds to receive for packet or EOF");
	CHECK(t1_touchid_cancel_test_poll_events(POLLOUT | POLLHUP,
		T1_TOUCHID_CANCEL_WAIT_WRITE) == 0,
	      "write readiness wins when accompanied by hangup");
	CHECK(t1_touchid_cancel_test_poll_events(POLLHUP,
		T1_TOUCHID_CANCEL_WAIT_WRITE) == -1,
	      "bare write-side hangup fails");
	CHECK(t1_touchid_cancel_test_poll_events(POLLIN | POLLERR,
		T1_TOUCHID_CANCEL_WAIT_READ) == -1,
	      "poll error remains fatal despite requested readiness");
	CHECK(t1_touchid_cancel_test_poll_events(POLLIN | POLLNVAL,
		T1_TOUCHID_CANCEL_WAIT_READ) == -1,
	      "invalid descriptor remains fatal despite readiness");
	CHECK(t1_touchid_cancel_test_poll_events(0,
		T1_TOUCHID_CANCEL_WAIT_READ) == -1,
	      "unrelated event set is not ready");
}

int main(void)
{
	test_exact_accepted_and_denied_transactions();
	test_path_and_root_credentials_are_mandatory();
	test_only_exact_replies_are_terminal_outcomes();
	test_one_deadline_bounds_connect_send_and_receive();
	test_io_and_cleanup_failures_are_typed();
	test_invalid_ops_never_start();
	test_poll_event_policy_preserves_queued_reply();

	if (failures != 0) {
		fprintf(stderr, "touchid_cancel: %u tests failed\n", failures);
		return 1;
	}
	puts("touchid_cancel: all tests passed");
	return 0;
}

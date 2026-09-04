#define _GNU_SOURCE

#include "t1_touchid_cancel.h"
#include "../../t1-daemons/c/t1_seqpacket.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define T1_TOUCHID_CANCEL_TIMEOUT_MS 500u
#define T1_TOUCHID_ROOT_USER_ID 0u

static const char broker_path[] = "/run/t1-touchid/auth.sock";
static const uint8_t cancel_request[] = {
	'T', '1', 'C', 'N', 'C', 'L', 0x01, '\n'
};
static const uint8_t accepted_reply[] = { 'O', 'K', 'A', 'Y' };
static const uint8_t denied_reply[] = { 'D', 'E', 'N', 'Y' };

static int linux_monotonic_ms(void *context, uint64_t *value)
{
	struct timespec now;

	(void)context;
	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || now.tv_sec < 0)
		return -1;
	if ((uint64_t)now.tv_sec > UINT64_MAX / 1000u)
		return -1;
	*value = (uint64_t)now.tv_sec * 1000u +
		(uint64_t)now.tv_nsec / 1000000u;
	return 0;
}

static int linux_inspect_path(void *context, const char *path)
{
	struct stat metadata;

	(void)context;
	memset(&metadata, 0, sizeof(metadata));
	if (lstat(path, &metadata) != 0)
		return -1;
	return S_ISSOCK(metadata.st_mode) && metadata.st_uid == 0 ? 0 : -1;
}

static int linux_open_socket(void *context)
{
	(void)context;
	return socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK,
		      0);
}

static int linux_connect_socket(void *context, int descriptor,
	const char *path)
{
	struct sockaddr_un address;
	socklen_t address_length;
	size_t path_length = strlen(path);

	(void)context;
	if (path_length >= sizeof(address.sun_path))
		return -1;
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	memcpy(address.sun_path, path, path_length + 1);
	address_length = offsetof(struct sockaddr_un, sun_path) +
		(socklen_t)path_length + 1;
	if (connect(descriptor, (const struct sockaddr *)&address,
		    address_length) == 0 || errno == EISCONN)
		return 0;
	if (errno == EINTR)
		return 2;
	if (errno == EAGAIN || errno == EINPROGRESS || errno == EALREADY)
		return 1;
	return -1;
}

static int linux_peer_user_id(void *context, int descriptor,
	uint32_t *user_id)
{
	struct t1_seqpacket_credentials credentials;

	(void)context;
	if (t1_seqpacket_peer_credentials(descriptor, &credentials) !=
	    T1_SEQPACKET_OK)
		return -1;
	*user_id = credentials.user_id;
	return 0;
}

static int map_transient_seqpacket(enum t1_seqpacket_status status)
{
	if (status == T1_SEQPACKET_OK)
		return 0;
	if (status == T1_SEQPACKET_WOULD_BLOCK)
		return 1;
	if (status == T1_SEQPACKET_INTERRUPTED)
		return 2;
	return -1;
}

static int linux_send_packet(void *context, int descriptor,
	const void *packet, size_t packet_length)
{
	(void)context;
	return map_transient_seqpacket(t1_seqpacket_send(
		descriptor, packet, packet_length));
}

static int linux_receive_packet(void *context, int descriptor,
	void *packet, size_t capacity, size_t *packet_length)
{
	(void)context;
	return map_transient_seqpacket(t1_seqpacket_receive(
		descriptor, packet, capacity, packet_length));
}

static int poll_events_result(short revents,
	enum t1_touchid_cancel_wait interest)
{
	short requested = interest == T1_TOUCHID_CANCEL_WAIT_READ ?
		POLLIN : POLLOUT;

	if ((revents & (POLLERR | POLLNVAL)) != 0)
		return -1;
	if ((revents & requested) != 0)
		return 0;
	if (interest == T1_TOUCHID_CANCEL_WAIT_READ &&
	    (revents & POLLHUP) != 0)
		return 0;
	return -1;
}

#ifdef T1_TOUCHID_CANCEL_TESTING
int t1_touchid_cancel_test_poll_events(int revents,
	enum t1_touchid_cancel_wait interest)
{
	return poll_events_result((short)revents, interest);
}
#endif

static int linux_wait_socket(void *context, int descriptor,
	enum t1_touchid_cancel_wait interest, unsigned int timeout_ms)
{
	struct pollfd watched;
	int result;

	(void)context;
	memset(&watched, 0, sizeof(watched));
	watched.fd = descriptor;
	watched.events = interest == T1_TOUCHID_CANCEL_WAIT_READ ? POLLIN : POLLOUT;
	result = poll(&watched, 1, (int)timeout_ms);
	if (result < 0)
		return errno == EINTR ? 2 : -1;
	if (result == 0)
		return 1;
	return poll_events_result(watched.revents, interest);
}

static int linux_close_fd(void *context, int descriptor)
{
	(void)context;
	return close(descriptor);
}

static const struct t1_touchid_cancel_ops linux_ops = {
	.context = NULL,
	.monotonic_ms = linux_monotonic_ms,
	.inspect_path = linux_inspect_path,
	.open_socket = linux_open_socket,
	.connect_socket = linux_connect_socket,
	.peer_user_id = linux_peer_user_id,
	.send_packet = linux_send_packet,
	.receive_packet = linux_receive_packet,
	.wait_socket = linux_wait_socket,
	.close_fd = linux_close_fd,
};

static int valid_ops(const struct t1_touchid_cancel_ops *ops)
{
	return ops != NULL && ops->monotonic_ms != NULL &&
		ops->inspect_path != NULL && ops->open_socket != NULL &&
		ops->connect_socket != NULL && ops->peer_user_id != NULL &&
		ops->send_packet != NULL && ops->receive_packet != NULL &&
		ops->wait_socket != NULL && ops->close_fd != NULL;
}

static enum t1_touchid_cancel_result remaining_ms(
	const struct t1_touchid_cancel_ops *ops, uint64_t deadline,
	unsigned int *remaining)
{
	uint64_t now;

	if (ops->monotonic_ms(ops->context, &now) != 0)
		return T1_TOUCHID_CANCEL_ERROR_CLOCK;
	if (now >= deadline)
		return T1_TOUCHID_CANCEL_ERROR_TIMEOUT;
	*remaining = (unsigned int)(deadline - now);
	return T1_TOUCHID_CANCEL_OK;
}

static enum t1_touchid_cancel_result wait_until_ready(
	const struct t1_touchid_cancel_ops *ops, int descriptor,
	enum t1_touchid_cancel_wait interest, uint64_t deadline)
{
	for (;;) {
		unsigned int remaining;
		enum t1_touchid_cancel_result result =
			remaining_ms(ops, deadline, &remaining);
		int wait_result;

		if (result != T1_TOUCHID_CANCEL_OK)
			return result;
		wait_result = ops->wait_socket(ops->context, descriptor,
			interest, remaining);
		if (wait_result == 0)
			return T1_TOUCHID_CANCEL_OK;
		if (wait_result == 1)
			return T1_TOUCHID_CANCEL_ERROR_TIMEOUT;
		if (wait_result != 2)
			return interest == T1_TOUCHID_CANCEL_WAIT_WRITE ?
				T1_TOUCHID_CANCEL_ERROR_SEND :
				T1_TOUCHID_CANCEL_ERROR_RECEIVE;
	}
}

static enum t1_touchid_cancel_result run_transaction(
	const struct t1_touchid_cancel_ops *ops, int descriptor,
	uint64_t deadline)
{
	uint8_t reply[sizeof(accepted_reply)];
	uint32_t user_id = UINT32_MAX;
	size_t reply_length = 0;
	unsigned int remaining;
	enum t1_touchid_cancel_result result;
	int operation;

	for (;;) {
		result = remaining_ms(ops, deadline, &remaining);
		if (result != T1_TOUCHID_CANCEL_OK)
			return result;
		operation = ops->connect_socket(ops->context, descriptor,
			broker_path);
		if (operation == 0)
			break;
		if (operation < 0 || operation > 2)
			return T1_TOUCHID_CANCEL_ERROR_CONNECT;
		if (operation == 1) {
			result = wait_until_ready(ops, descriptor,
				T1_TOUCHID_CANCEL_WAIT_WRITE, deadline);
			if (result != T1_TOUCHID_CANCEL_OK)
				return result == T1_TOUCHID_CANCEL_ERROR_SEND ?
					T1_TOUCHID_CANCEL_ERROR_CONNECT : result;
		}
	}
	result = remaining_ms(ops, deadline, &remaining);
	if (result != T1_TOUCHID_CANCEL_OK)
		return result;
	if (ops->peer_user_id(ops->context, descriptor, &user_id) != 0 ||
	    user_id != T1_TOUCHID_ROOT_USER_ID)
		return T1_TOUCHID_CANCEL_ERROR_CREDENTIALS;

	for (;;) {
		result = remaining_ms(ops, deadline, &remaining);
		if (result != T1_TOUCHID_CANCEL_OK)
			return result;
		operation = ops->send_packet(ops->context, descriptor,
			cancel_request, sizeof(cancel_request));
		if (operation == 0)
			break;
		if (operation < 0 || operation > 2)
			return T1_TOUCHID_CANCEL_ERROR_SEND;
		if (operation == 1) {
			result = wait_until_ready(ops, descriptor,
				T1_TOUCHID_CANCEL_WAIT_WRITE, deadline);
			if (result != T1_TOUCHID_CANCEL_OK)
				return result;
		}
	}

	for (;;) {
		result = remaining_ms(ops, deadline, &remaining);
		if (result != T1_TOUCHID_CANCEL_OK)
			return result;
		operation = ops->receive_packet(ops->context, descriptor,
			reply, sizeof(reply), &reply_length);
		if (operation == 0)
			break;
		if (operation < 0 || operation > 2)
			return T1_TOUCHID_CANCEL_ERROR_RECEIVE;
		if (operation == 1) {
			result = wait_until_ready(ops, descriptor,
				T1_TOUCHID_CANCEL_WAIT_READ, deadline);
			if (result != T1_TOUCHID_CANCEL_OK)
				return result;
		}
	}
	result = remaining_ms(ops, deadline, &remaining);
	if (result != T1_TOUCHID_CANCEL_OK)
		return result;
	if (reply_length != sizeof(reply))
		return T1_TOUCHID_CANCEL_ERROR_PROTOCOL;
	if (memcmp(reply, accepted_reply, sizeof(reply)) == 0)
		return T1_TOUCHID_CANCEL_OK;
	if (memcmp(reply, denied_reply, sizeof(reply)) == 0)
		return T1_TOUCHID_CANCEL_DENIED;
	return T1_TOUCHID_CANCEL_ERROR_PROTOCOL;
}

enum t1_touchid_cancel_result t1_touchid_cancel_with_ops(
	const struct t1_touchid_cancel_ops *ops)
{
	uint64_t started;
	uint64_t deadline;
	enum t1_touchid_cancel_result result;
	int descriptor;

	if (!valid_ops(ops))
		return T1_TOUCHID_CANCEL_ERROR_ARGUMENT;
	if (ops->monotonic_ms(ops->context, &started) != 0 ||
	    started > UINT64_MAX - T1_TOUCHID_CANCEL_TIMEOUT_MS)
		return T1_TOUCHID_CANCEL_ERROR_CLOCK;
	deadline = started + T1_TOUCHID_CANCEL_TIMEOUT_MS;
	if (ops->inspect_path(ops->context, broker_path) != 0)
		return T1_TOUCHID_CANCEL_ERROR_PATH;
	result = remaining_ms(ops, deadline, &(unsigned int){ 0 });
	if (result != T1_TOUCHID_CANCEL_OK)
		return result;
	descriptor = ops->open_socket(ops->context);
	if (descriptor < 0)
		return T1_TOUCHID_CANCEL_ERROR_CONNECT;
	result = run_transaction(ops, descriptor, deadline);
	if (ops->close_fd(ops->context, descriptor) != 0 &&
	    (result == T1_TOUCHID_CANCEL_OK ||
	     result == T1_TOUCHID_CANCEL_DENIED))
		return T1_TOUCHID_CANCEL_ERROR_CLOSE;
	return result;
}

enum t1_touchid_cancel_result t1_touchid_cancel(void)
{
	return t1_touchid_cancel_with_ops(&linux_ops);
}

const char *t1_touchid_cancel_result_string(
	enum t1_touchid_cancel_result result)
{
	switch (result) {
	case T1_TOUCHID_CANCEL_OK:
		return "cancellation delivered";
	case T1_TOUCHID_CANCEL_DENIED:
		return "cancellation denied";
	case T1_TOUCHID_CANCEL_ERROR_ARGUMENT:
		return "invalid cancellation boundary";
	case T1_TOUCHID_CANCEL_ERROR_CLOCK:
		return "cancellation clock failed";
	case T1_TOUCHID_CANCEL_ERROR_TIMEOUT:
		return "cancellation timed out";
	case T1_TOUCHID_CANCEL_ERROR_PATH:
		return "cancellation socket metadata is invalid";
	case T1_TOUCHID_CANCEL_ERROR_CONNECT:
		return "cancellation connection failed";
	case T1_TOUCHID_CANCEL_ERROR_CREDENTIALS:
		return "cancellation peer is not root";
	case T1_TOUCHID_CANCEL_ERROR_SEND:
		return "cancellation send failed";
	case T1_TOUCHID_CANCEL_ERROR_RECEIVE:
		return "cancellation receive failed";
	case T1_TOUCHID_CANCEL_ERROR_PROTOCOL:
		return "cancellation response is invalid";
	case T1_TOUCHID_CANCEL_ERROR_CLOSE:
		return "cancellation socket close failed";
	default:
		return "unknown cancellation failure";
	}
}

#define _GNU_SOURCE

#include "t1_touchbar_io.h"

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <string.h>
#include <time.h>

_Static_assert(T1_TOUCHBAR_IO_OK == 0, "Touch Bar status ABI changed");
_Static_assert(T1_TOUCHBAR_IO_IDLE == 1, "Touch Bar status ABI changed");
_Static_assert(T1_TOUCHBAR_IO_RESYNC == 2, "Touch Bar status ABI changed");
_Static_assert(T1_TOUCHBAR_IO_ERROR_ARGUMENT == -1,
	       "Touch Bar status ABI changed");
_Static_assert(T1_TOUCHBAR_IO_ERROR_CAPACITY == -10,
	       "Touch Bar status ABI changed");

static int monotonic_ms(uint64_t *value)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
		return -1;
	*value = (uint64_t)now.tv_sec * UINT64_C(1000) +
		 (uint64_t)now.tv_nsec / UINT64_C(1000000);
	return 0;
}

static enum t1_touchbar_io_status poll_descriptors(
	struct pollfd *watched, nfds_t count, unsigned int timeout_ms)
{
	uint64_t start;
	uint64_t deadline;
	int remaining;

	if (watched == NULL || count == 0 || timeout_ms > (unsigned int)INT_MAX)
		return T1_TOUCHBAR_IO_ERROR_ARGUMENT;
	if (monotonic_ms(&start) != 0 ||
	    UINT64_MAX - start < (uint64_t)timeout_ms)
		return T1_TOUCHBAR_IO_ERROR_IO;
	deadline = start + (uint64_t)timeout_ms;
	remaining = (int)timeout_ms;

	for (;;) {
		int result = poll(watched, count, remaining);

		if (result > 0)
			break;
		if (result == 0)
			return T1_TOUCHBAR_IO_IDLE;
		if (errno != EINTR)
			return T1_TOUCHBAR_IO_ERROR_IO;
		{
			uint64_t now;
			uint64_t left;

			if (monotonic_ms(&now) != 0)
				return T1_TOUCHBAR_IO_ERROR_IO;
			if (now >= deadline)
				return T1_TOUCHBAR_IO_IDLE;
			left = deadline - now;
			remaining = left > (uint64_t)INT_MAX ? INT_MAX :
				(int)left;
		}
	}

	return T1_TOUCHBAR_IO_OK;
}

static enum t1_touchbar_io_status validate_input(const struct pollfd *watched)
{
	if ((watched->revents & (POLLERR | POLLNVAL)) != 0)
		return T1_TOUCHBAR_IO_ERROR_IO;
	if ((watched->revents & POLLHUP) != 0 &&
	    (watched->revents & POLLIN) == 0)
		return T1_TOUCHBAR_IO_ERROR_CLOSED;
	return T1_TOUCHBAR_IO_OK;
}

enum t1_touchbar_io_status t1_touchbar_wait_readable(
	int descriptor, unsigned int timeout_ms, int *ready)
{
	struct pollfd watched = {
		.fd = descriptor,
		.events = POLLIN,
	};
	enum t1_touchbar_io_status status;

	if (descriptor < 0 || ready == NULL)
		return T1_TOUCHBAR_IO_ERROR_ARGUMENT;
	*ready = 0;
	status = poll_descriptors(&watched, 1, timeout_ms);
	if (status != T1_TOUCHBAR_IO_OK)
		return status;
	status = validate_input(&watched);
	if (status != T1_TOUCHBAR_IO_OK)
		return status;
	if ((watched.revents & POLLIN) == 0)
		return T1_TOUCHBAR_IO_ERROR_IO;
	*ready = 1;
	return T1_TOUCHBAR_IO_OK;
}

enum t1_touchbar_io_status t1_touchbar_wait_inputs(
	int digitizer_descriptor, int fn_descriptor, unsigned int timeout_ms,
	uint32_t *ready_inputs)
{
	struct pollfd watched[2] = {
		{ .fd = digitizer_descriptor, .events = POLLIN },
		{ .fd = fn_descriptor, .events = POLLIN },
	};
	enum t1_touchbar_io_status status;

	if (digitizer_descriptor < 0 || fn_descriptor < 0 ||
	    ready_inputs == NULL)
		return T1_TOUCHBAR_IO_ERROR_ARGUMENT;
	*ready_inputs = 0;
	status = poll_descriptors(watched, 2, timeout_ms);
	if (status != T1_TOUCHBAR_IO_OK)
		return status;
	status = validate_input(&watched[0]);
	if (status != T1_TOUCHBAR_IO_OK)
		return status;
	status = validate_input(&watched[1]);
	if (status != T1_TOUCHBAR_IO_OK)
		return status;
	if ((watched[0].revents & POLLIN) != 0)
		*ready_inputs |= T1_TOUCHBAR_INPUT_DIGITIZER_READY;
	if ((watched[1].revents & POLLIN) != 0)
		*ready_inputs |= T1_TOUCHBAR_INPUT_FN_READY;
	return *ready_inputs == 0 ? T1_TOUCHBAR_IO_ERROR_IO :
		T1_TOUCHBAR_IO_OK;
}

enum t1_touchbar_io_status t1_touchbar_wait_events(
	int digitizer_descriptor, int fn_descriptor, int client_descriptor,
	uint32_t client_interest, unsigned int timeout_ms,
	uint32_t *ready_events)
{
	const uint32_t client_mask = T1_TOUCHBAR_CLIENT_READABLE |
		T1_TOUCHBAR_CLIENT_WRITABLE;
	struct pollfd watched[3] = {
		{ .fd = digitizer_descriptor, .events = POLLIN },
		{ .fd = fn_descriptor, .events = POLLIN },
		{ .fd = client_descriptor },
	};
	enum t1_touchbar_io_status status;
	short client_poll_events = 0;

	if (digitizer_descriptor < 0 || fn_descriptor < 0 ||
	    client_descriptor < -1 || ready_events == NULL ||
	    (client_interest & ~client_mask) != 0 ||
	    ((client_descriptor == -1) != (client_interest == 0)))
		return T1_TOUCHBAR_IO_ERROR_ARGUMENT;
	if ((client_interest & T1_TOUCHBAR_CLIENT_READABLE) != 0)
		client_poll_events |= POLLIN;
	if ((client_interest & T1_TOUCHBAR_CLIENT_WRITABLE) != 0)
		client_poll_events |= POLLOUT;
	watched[2].events = client_poll_events;
	*ready_events = 0;
	status = poll_descriptors(watched, client_descriptor == -1 ? 2 : 3,
				  timeout_ms);
	if (status != T1_TOUCHBAR_IO_OK)
		return status;
	status = validate_input(&watched[0]);
	if (status != T1_TOUCHBAR_IO_OK)
		return status;
	status = validate_input(&watched[1]);
	if (status != T1_TOUCHBAR_IO_OK)
		return status;
	if ((watched[0].revents & POLLIN) != 0)
		*ready_events |= T1_TOUCHBAR_INPUT_DIGITIZER_READY;
	if ((watched[1].revents & POLLIN) != 0)
		*ready_events |= T1_TOUCHBAR_INPUT_FN_READY;
	if (client_descriptor != -1) {
		if ((watched[2].revents & POLLNVAL) != 0)
			return T1_TOUCHBAR_IO_ERROR_IO;
		if ((watched[2].revents & POLLIN) != 0)
			*ready_events |= T1_TOUCHBAR_CLIENT_READABLE;
		if ((watched[2].revents & POLLOUT) != 0)
			*ready_events |= T1_TOUCHBAR_CLIENT_WRITABLE;
		if ((watched[2].revents & (POLLERR | POLLHUP)) != 0)
			*ready_events |= client_interest;
	}
	return *ready_events == 0 ? T1_TOUCHBAR_IO_ERROR_IO :
		T1_TOUCHBAR_IO_OK;
}

int t1_touchbar_indexed_name(const char *name, const char *prefix)
{
	size_t prefix_length;
	const unsigned char *cursor;

	if (name == NULL || prefix == NULL)
		return 0;
	prefix_length = strlen(prefix);
	if (prefix_length == 0 || strncmp(name, prefix, prefix_length) != 0)
		return 0;
	cursor = (const unsigned char *)name + prefix_length;
	if (*cursor == '\0')
		return 0;
	if (*cursor == '0' && cursor[1] != '\0')
		return 0;
	for (; *cursor != '\0'; ++cursor) {
		if (*cursor < '0' || *cursor > '9')
			return 0;
	}
	return 1;
}

const char *t1_touchbar_io_status_name(enum t1_touchbar_io_status status)
{
	switch (status) {
	case T1_TOUCHBAR_IO_OK:
		return "Touch Bar I/O completed";
	case T1_TOUCHBAR_IO_IDLE:
		return "Touch Bar input is idle";
	case T1_TOUCHBAR_IO_RESYNC:
		return "Touch Bar input requires resynchronization";
	case T1_TOUCHBAR_IO_ERROR_ARGUMENT:
		return "Touch Bar I/O argument is invalid";
	case T1_TOUCHBAR_IO_ERROR_DISCOVERY:
		return "Touch Bar device discovery failed";
	case T1_TOUCHBAR_IO_ERROR_AMBIGUOUS:
		return "Touch Bar device discovery is ambiguous";
	case T1_TOUCHBAR_IO_ERROR_OPEN:
		return "Touch Bar device could not be opened";
	case T1_TOUCHBAR_IO_ERROR_TYPE:
		return "Touch Bar device has the wrong file type";
	case T1_TOUCHBAR_IO_ERROR_IDENTITY:
		return "Touch Bar device identity is invalid";
	case T1_TOUCHBAR_IO_ERROR_IO:
		return "Touch Bar device I/O failed";
	case T1_TOUCHBAR_IO_ERROR_CLOSED:
		return "Touch Bar device closed";
	case T1_TOUCHBAR_IO_ERROR_PROTOCOL:
		return "Touch Bar input record is malformed";
	case T1_TOUCHBAR_IO_ERROR_CAPACITY:
		return "Touch Bar input output capacity is insufficient";
	default:
		return "Touch Bar I/O status is unknown";
	}
}

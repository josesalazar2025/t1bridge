#define _GNU_SOURCE

#include "t1_touchbar_digitizer.h"
#include "t1_touchbar_fn.h"
#include "t1_touchbar_io.h"
#include "t1_touchbar_uinput.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define EXPECT_TRUE(condition)                                                   \
	do {                                                                       \
		if (!(condition)) {                                                   \
			fprintf(stderr, "%s:%d: expectation failed: %s\n", __FILE__, \
				__LINE__, #condition);                                  \
			exit(EXIT_FAILURE);                                            \
		}                                                                  \
	} while (0)

static void write_complete(int descriptor, const void *data, size_t size)
{
	const uint8_t *bytes = data;
	size_t offset = 0;

	while (offset < size) {
		ssize_t count = write(descriptor, bytes + offset, size - offset);

		EXPECT_TRUE(count > 0);
		offset += (size_t)count;
	}
}

static void read_complete(int descriptor, void *data, size_t size)
{
	uint8_t *bytes = data;
	size_t offset = 0;

	while (offset < size) {
		ssize_t count = read(descriptor, bytes + offset, size - offset);

		EXPECT_TRUE(count > 0);
		offset += (size_t)count;
	}
}

static void test_indexed_names(void)
{
	EXPECT_TRUE(t1_touchbar_indexed_name("hidraw0", "hidraw"));
	EXPECT_TRUE(t1_touchbar_indexed_name("hidraw42", "hidraw"));
	EXPECT_TRUE(t1_touchbar_indexed_name("event7", "event"));
	EXPECT_TRUE(!t1_touchbar_indexed_name("hidraw", "hidraw"));
	EXPECT_TRUE(!t1_touchbar_indexed_name("hidraw01", "hidraw"));
	EXPECT_TRUE(!t1_touchbar_indexed_name("hidraw-1", "hidraw"));
	EXPECT_TRUE(!t1_touchbar_indexed_name("hidraw1x", "hidraw"));
	EXPECT_TRUE(!t1_touchbar_indexed_name("event1", "hidraw"));
	EXPECT_TRUE(!t1_touchbar_indexed_name(NULL, "hidraw"));
}

static void test_opened_device_identities(void)
{
	EXPECT_TRUE(t1_touchbar_digitizer_test_identity(
			    BUS_USB, 0x05ac, 0x8600, 782));
	EXPECT_TRUE(!t1_touchbar_digitizer_test_identity(
			    BUS_USB, 0x05ac, 0x8600, 781));
	EXPECT_TRUE(!t1_touchbar_digitizer_test_identity(
			    BUS_USB, 0x05ac, 0x1234, 782));
	EXPECT_TRUE(!t1_touchbar_digitizer_test_identity(
			    BUS_VIRTUAL, 0x05ac, 0x8600, 782));

	EXPECT_TRUE(t1_touchbar_fn_test_identity(
			    "Apple SPI Keyboard", BUS_SPI, 1, 1));
	EXPECT_TRUE(!t1_touchbar_fn_test_identity(
			    "Apple SPI Keyboard", BUS_USB, 1, 1));
	EXPECT_TRUE(!t1_touchbar_fn_test_identity(
			    "Apple SPI Keyboard", BUS_SPI, 1, 0));
	EXPECT_TRUE(!t1_touchbar_fn_test_identity(
			    "Synthetic Keyboard", BUS_SPI, 1, 1));
}

static void test_poll_and_digitizer_reports(void)
{
	int descriptors[2];
	uint8_t raw[T1_TOUCHBAR_DIGITIZER_REPORT_SIZE + 1U];
	uint8_t report[T1_TOUCHBAR_DIGITIZER_REPORT_SIZE];
	int ready = -1;
	size_t index;

	EXPECT_TRUE(pipe2(descriptors, O_CLOEXEC | O_NONBLOCK) == 0);
	EXPECT_TRUE(t1_touchbar_wait_readable(descriptors[0], 0, &ready) ==
		    T1_TOUCHBAR_IO_IDLE);
	EXPECT_TRUE(ready == 0);
	for (index = 0; index < sizeof(raw); ++index)
		raw[index] = (uint8_t)index;
	write_complete(descriptors[1], raw, sizeof(raw));
	EXPECT_TRUE(t1_touchbar_digitizer_read(descriptors[0], 0, report) ==
		    T1_TOUCHBAR_IO_OK);
	EXPECT_TRUE(memcmp(report, raw + 1, sizeof(report)) == 0);

	write_complete(descriptors[1], raw, sizeof(report));
	EXPECT_TRUE(t1_touchbar_digitizer_read(descriptors[0], 0, report) ==
		    T1_TOUCHBAR_IO_OK);
	EXPECT_TRUE(memcmp(report, raw, sizeof(report)) == 0);

	write_complete(descriptors[1], raw, 7);
	EXPECT_TRUE(t1_touchbar_digitizer_read(descriptors[0], 0, report) ==
		    T1_TOUCHBAR_IO_ERROR_PROTOCOL);
	EXPECT_TRUE(close(descriptors[1]) == 0);
	EXPECT_TRUE(t1_touchbar_digitizer_read(descriptors[0], 0, report) ==
		    T1_TOUCHBAR_IO_ERROR_CLOSED);
	EXPECT_TRUE(close(descriptors[0]) == 0);
}

static void test_combined_input_poll(void)
{
	int digitizer[2];
	int fn[2];
	uint32_t ready = UINT32_MAX;
	uint8_t byte = 0x5a;

	EXPECT_TRUE(pipe2(digitizer, O_CLOEXEC | O_NONBLOCK) == 0);
	EXPECT_TRUE(pipe2(fn, O_CLOEXEC | O_NONBLOCK) == 0);
	EXPECT_TRUE(t1_touchbar_wait_inputs(digitizer[0], fn[0], 0, &ready) ==
		    T1_TOUCHBAR_IO_IDLE);
	EXPECT_TRUE(ready == 0);
	write_complete(fn[1], &byte, sizeof(byte));
	EXPECT_TRUE(t1_touchbar_wait_inputs(digitizer[0], fn[0], 0, &ready) ==
		    T1_TOUCHBAR_IO_OK);
	EXPECT_TRUE(ready == T1_TOUCHBAR_INPUT_FN_READY);
	EXPECT_TRUE(read(fn[0], &byte, sizeof(byte)) == 1);
	write_complete(digitizer[1], &byte, sizeof(byte));
	write_complete(fn[1], &byte, sizeof(byte));
	EXPECT_TRUE(t1_touchbar_wait_inputs(digitizer[0], fn[0], 0, &ready) ==
		    T1_TOUCHBAR_IO_OK);
	EXPECT_TRUE(ready == (T1_TOUCHBAR_INPUT_DIGITIZER_READY |
			      T1_TOUCHBAR_INPUT_FN_READY));
	EXPECT_TRUE(close(digitizer[0]) == 0);
	EXPECT_TRUE(close(digitizer[1]) == 0);
	EXPECT_TRUE(close(fn[0]) == 0);
	EXPECT_TRUE(close(fn[1]) == 0);
}

static void test_combined_event_poll(void)
{
	int digitizer[2];
	int fn[2];
	int client[2];
	uint32_t ready = UINT32_MAX;
	uint8_t byte = 0x5a;
	uint8_t payload[4096] = { 0 };
	unsigned int drained;

	EXPECT_TRUE(pipe2(digitizer, O_CLOEXEC | O_NONBLOCK) == 0);
	EXPECT_TRUE(pipe2(fn, O_CLOEXEC | O_NONBLOCK) == 0);
	EXPECT_TRUE(socketpair(AF_UNIX,
			       SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK,
			       0, client) == 0);
	EXPECT_TRUE(t1_touchbar_wait_events(
			    digitizer[0], fn[0], -1, 0, 0, &ready) ==
		    T1_TOUCHBAR_IO_IDLE);
	EXPECT_TRUE(ready == 0);

	write_complete(client[1], &byte, sizeof(byte));
	EXPECT_TRUE(t1_touchbar_wait_events(
			    digitizer[0], fn[0], client[0],
			    T1_TOUCHBAR_CLIENT_READABLE, 0, &ready) ==
		    T1_TOUCHBAR_IO_OK);
	EXPECT_TRUE(ready == T1_TOUCHBAR_CLIENT_READABLE);
	EXPECT_TRUE(read(client[0], &byte, sizeof(byte)) == 1);

	write_complete(digitizer[1], &byte, sizeof(byte));
	write_complete(fn[1], &byte, sizeof(byte));
	write_complete(client[1], &byte, sizeof(byte));
	EXPECT_TRUE(t1_touchbar_wait_events(
			    digitizer[0], fn[0], client[0],
			    T1_TOUCHBAR_CLIENT_READABLE, 0, &ready) ==
		    T1_TOUCHBAR_IO_OK);
	EXPECT_TRUE(ready == (T1_TOUCHBAR_INPUT_DIGITIZER_READY |
			      T1_TOUCHBAR_INPUT_FN_READY |
			      T1_TOUCHBAR_CLIENT_READABLE));
	EXPECT_TRUE(read(digitizer[0], &byte, sizeof(byte)) == 1);
	EXPECT_TRUE(read(fn[0], &byte, sizeof(byte)) == 1);
	EXPECT_TRUE(read(client[0], &byte, sizeof(byte)) == 1);

	EXPECT_TRUE(t1_touchbar_wait_events(
			    digitizer[0], fn[0], client[0],
			    T1_TOUCHBAR_CLIENT_WRITABLE, 0, &ready) ==
		    T1_TOUCHBAR_IO_OK);
	EXPECT_TRUE(ready == T1_TOUCHBAR_CLIENT_WRITABLE);
	for (;;) {
		ssize_t count = send(client[0], payload, sizeof(payload),
				     MSG_NOSIGNAL);

		if (count == (ssize_t)sizeof(payload))
			continue;
		EXPECT_TRUE(count == -1 &&
			    (errno == EAGAIN || errno == EWOULDBLOCK));
		break;
	}
	EXPECT_TRUE(t1_touchbar_wait_events(
			    digitizer[0], fn[0], client[0],
			    T1_TOUCHBAR_CLIENT_WRITABLE, 0, &ready) ==
		    T1_TOUCHBAR_IO_IDLE);
	EXPECT_TRUE(ready == 0);
	for (drained = 0; drained < 1024; ++drained) {
		EXPECT_TRUE(recv(client[1], payload, sizeof(payload), 0) ==
			    (ssize_t)sizeof(payload));
		if (t1_touchbar_wait_events(
			    digitizer[0], fn[0], client[0],
			    T1_TOUCHBAR_CLIENT_WRITABLE, 0, &ready) ==
		    T1_TOUCHBAR_IO_OK)
			break;
	}
	EXPECT_TRUE(drained < 1024);
	EXPECT_TRUE(ready == T1_TOUCHBAR_CLIENT_WRITABLE);
	while (recv(client[1], payload, sizeof(payload), 0) > 0)
		;

	EXPECT_TRUE(close(client[1]) == 0);
	EXPECT_TRUE(t1_touchbar_wait_events(
			    digitizer[0], fn[0], client[0],
			    T1_TOUCHBAR_CLIENT_READABLE, 0, &ready) ==
		    T1_TOUCHBAR_IO_OK);
	EXPECT_TRUE(ready == T1_TOUCHBAR_CLIENT_READABLE);
	EXPECT_TRUE(close(client[0]) == 0);
	EXPECT_TRUE(close(fn[1]) == 0);
	EXPECT_TRUE(t1_touchbar_wait_events(
			    digitizer[0], fn[0], -1, 0, 0, &ready) ==
		    T1_TOUCHBAR_IO_ERROR_CLOSED);
	EXPECT_TRUE(close(digitizer[0]) == 0);
	EXPECT_TRUE(close(digitizer[1]) == 0);
	EXPECT_TRUE(close(fn[0]) == 0);
}

static struct input_event input_event(uint16_t type, uint16_t code, int value)
{
	struct input_event event;

	memset(&event, 0, sizeof(event));
	event.type = type;
	event.code = code;
	event.value = value;
	return event;
}

static void test_fn_edges(void)
{
	int descriptors[2];
	struct input_event events[6];
	struct t1_touchbar_fn_edge edges[2];
	size_t count = 99;

	EXPECT_TRUE(pipe2(descriptors, O_CLOEXEC | O_NONBLOCK) == 0);
	events[0] = input_event(EV_KEY, KEY_A, 1);
	events[1] = input_event(EV_KEY, KEY_FN, 1);
	events[2] = input_event(EV_SYN, SYN_REPORT, 0);
	events[3] = input_event(EV_KEY, KEY_FN, 2);
	events[4] = input_event(EV_KEY, KEY_FN, 0);
	events[5] = input_event(EV_SYN, SYN_REPORT, 0);
	write_complete(descriptors[1], events, sizeof(events));
	EXPECT_TRUE(t1_touchbar_fn_read(descriptors[0], edges, 2, &count) ==
		    T1_TOUCHBAR_IO_OK);
	EXPECT_TRUE(count == 2);
	EXPECT_TRUE(edges[0].pressed == 1);
	EXPECT_TRUE(edges[1].pressed == 0);

	write_complete(descriptors[1], events, sizeof(events));
	EXPECT_TRUE(t1_touchbar_fn_read(descriptors[0], edges, 1, &count) ==
		    T1_TOUCHBAR_IO_ERROR_CAPACITY);
	EXPECT_TRUE(count == 0);

	events[0] = input_event(EV_SYN, SYN_DROPPED, 0);
	write_complete(descriptors[1], events, sizeof(events[0]));
	EXPECT_TRUE(t1_touchbar_fn_read(descriptors[0], edges, 2, &count) ==
		    T1_TOUCHBAR_IO_RESYNC);
	EXPECT_TRUE(count == 0);
	EXPECT_TRUE(t1_touchbar_fn_read(descriptors[0], edges, 2, &count) ==
		    T1_TOUCHBAR_IO_IDLE);
	{
		uint8_t malformed = 0;

		write_complete(descriptors[1], &malformed, sizeof(malformed));
		EXPECT_TRUE(t1_touchbar_fn_read(descriptors[0], edges, 2,
					       &count) ==
			    T1_TOUCHBAR_IO_ERROR_PROTOCOL);
	}
	EXPECT_TRUE(close(descriptors[0]) == 0);
	EXPECT_TRUE(close(descriptors[1]) == 0);
}

static void expect_key_sequence(int descriptor, uint16_t code)
{
	struct input_event events[4];

	read_complete(descriptor, events, sizeof(events));
	EXPECT_TRUE(events[0].type == EV_KEY && events[0].code == code &&
		    events[0].value == 1);
	EXPECT_TRUE(events[1].type == EV_SYN && events[1].code == SYN_REPORT);
	EXPECT_TRUE(events[2].type == EV_KEY && events[2].code == code &&
		    events[2].value == 0);
	EXPECT_TRUE(events[3].type == EV_SYN && events[3].code == SYN_REPORT);
}

static void test_uinput_key_allowlist(void)
{
	int descriptors[2];
	struct t1_touchbar_uinput *device;
	unsigned int index;
	const uint16_t expected[] = {
		KEY_ESC, KEY_F1, KEY_F2, KEY_F3, KEY_F4, KEY_F5, KEY_F6,
		KEY_F7, KEY_F8, KEY_F9, KEY_F10, KEY_F11, KEY_F12,
	};

	EXPECT_TRUE(pipe2(descriptors, O_CLOEXEC) == 0);
	device = t1_touchbar_uinput_test_device(descriptors[1]);
	EXPECT_TRUE(device != NULL);
	for (index = 0; index < sizeof(expected) / sizeof(expected[0]); ++index) {
		EXPECT_TRUE(t1_touchbar_uinput_tap(
				    device, (enum t1_touchbar_key)index) ==
			    T1_TOUCHBAR_IO_OK);
		expect_key_sequence(descriptors[0], expected[index]);
	}
	EXPECT_TRUE(t1_touchbar_uinput_tap(
			    device, (enum t1_touchbar_key)-1) ==
		    T1_TOUCHBAR_IO_ERROR_ARGUMENT);
	EXPECT_TRUE(t1_touchbar_uinput_tap(
			    device, (enum t1_touchbar_key)13) ==
		    T1_TOUCHBAR_IO_ERROR_ARGUMENT);
	EXPECT_TRUE(t1_touchbar_uinput_release_all(device) == T1_TOUCHBAR_IO_OK);
	EXPECT_TRUE(t1_touchbar_uinput_close(device) == T1_TOUCHBAR_IO_OK);
	EXPECT_TRUE(close(descriptors[0]) == 0);
}

static void test_tracked_keys_are_released_during_cleanup(void)
{
	int descriptors[2];
	struct t1_touchbar_uinput *device;

	EXPECT_TRUE(pipe2(descriptors, O_CLOEXEC) == 0);
	device = t1_touchbar_uinput_test_device(descriptors[1]);
	EXPECT_TRUE(device != NULL);
	t1_touchbar_uinput_test_mark_held(device, T1_TOUCHBAR_KEY_ESCAPE);
	t1_touchbar_uinput_test_mark_held(device, T1_TOUCHBAR_KEY_F12);
	EXPECT_TRUE(t1_touchbar_uinput_test_held(device) ==
		    ((1U << T1_TOUCHBAR_KEY_ESCAPE) |
		     (1U << T1_TOUCHBAR_KEY_F12)));
	EXPECT_TRUE(t1_touchbar_uinput_release_all(device) == T1_TOUCHBAR_IO_OK);
	EXPECT_TRUE(t1_touchbar_uinput_test_held(device) == 0U);
	{
		struct input_event events[4];

		read_complete(descriptors[0], events, sizeof(events));
		EXPECT_TRUE(events[0].type == EV_KEY &&
			    events[0].code == KEY_ESC && events[0].value == 0);
		EXPECT_TRUE(events[2].type == EV_KEY &&
			    events[2].code == KEY_F12 && events[2].value == 0);
	}
	EXPECT_TRUE(t1_touchbar_uinput_close(device) == T1_TOUCHBAR_IO_OK);
	EXPECT_TRUE(close(descriptors[0]) == 0);
}

static void test_argument_contracts(void)
{
	uint8_t report[T1_TOUCHBAR_DIGITIZER_REPORT_SIZE];
	struct t1_touchbar_fn_edge edge;
	size_t count;
	int ready;

	EXPECT_TRUE(t1_touchbar_wait_readable(-1, 0, &ready) ==
		    T1_TOUCHBAR_IO_ERROR_ARGUMENT);
	EXPECT_TRUE(t1_touchbar_digitizer_read(-1, 0, report) ==
		    T1_TOUCHBAR_IO_ERROR_ARGUMENT);
	EXPECT_TRUE(t1_touchbar_fn_read(-1, &edge, 1, &count) ==
		    T1_TOUCHBAR_IO_ERROR_ARGUMENT);
}

int main(void)
{
	test_indexed_names();
	test_opened_device_identities();
	test_poll_and_digitizer_reports();
	test_combined_input_poll();
	test_combined_event_poll();
	test_fn_edges();
	test_uinput_key_allowlist();
	test_tracked_keys_are_released_during_cleanup();
	test_argument_contracts();
	puts("Touch Bar native I/O tests passed");
	return EXIT_SUCCESS;
}

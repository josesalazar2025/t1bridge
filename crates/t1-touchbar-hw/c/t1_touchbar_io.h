#ifndef T1BRIDGE_TOUCHBAR_IO_H
#define T1BRIDGE_TOUCHBAR_IO_H

#include <stddef.h>
#include <stdint.h>

enum t1_touchbar_io_status {
	T1_TOUCHBAR_IO_OK = 0,
	T1_TOUCHBAR_IO_IDLE = 1,
	T1_TOUCHBAR_IO_RESYNC = 2,
	T1_TOUCHBAR_IO_ERROR_ARGUMENT = -1,
	T1_TOUCHBAR_IO_ERROR_DISCOVERY = -2,
	T1_TOUCHBAR_IO_ERROR_AMBIGUOUS = -3,
	T1_TOUCHBAR_IO_ERROR_OPEN = -4,
	T1_TOUCHBAR_IO_ERROR_TYPE = -5,
	T1_TOUCHBAR_IO_ERROR_IDENTITY = -6,
	T1_TOUCHBAR_IO_ERROR_IO = -7,
	T1_TOUCHBAR_IO_ERROR_CLOSED = -8,
	T1_TOUCHBAR_IO_ERROR_PROTOCOL = -9,
	T1_TOUCHBAR_IO_ERROR_CAPACITY = -10,
};

/* Waits without consuming data. Timeout zero is a nonblocking probe. */
enum t1_touchbar_io_status t1_touchbar_wait_readable(
	int descriptor, unsigned int timeout_ms, int *ready);

#define T1_TOUCHBAR_INPUT_DIGITIZER_READY UINT32_C(1)
#define T1_TOUCHBAR_INPUT_FN_READY UINT32_C(2)
#define T1_TOUCHBAR_CLIENT_READABLE UINT32_C(4)
#define T1_TOUCHBAR_CLIENT_WRITABLE UINT32_C(8)

/* Polls both input sources together without reading either one. */
enum t1_touchbar_io_status t1_touchbar_wait_inputs(
	int digitizer_descriptor, int fn_descriptor, unsigned int timeout_ms,
	uint32_t *ready_inputs);

/* Polls hardware input and an optional renderer connection together. */
enum t1_touchbar_io_status t1_touchbar_wait_events(
	int digitizer_descriptor, int fn_descriptor, int client_descriptor,
	uint32_t client_interest, unsigned int timeout_ms,
	uint32_t *ready_events);

/* Returns one of the fixed, payload-free status descriptions. */
const char *t1_touchbar_io_status_name(enum t1_touchbar_io_status status);

/* Shared strict decimal-suffix validator for dynamic device enumeration. */
int t1_touchbar_indexed_name(const char *name, const char *prefix);

#endif

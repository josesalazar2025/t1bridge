#ifndef T1BRIDGE_TOUCHBAR_FN_H
#define T1BRIDGE_TOUCHBAR_FN_H

#include "t1_touchbar_io.h"

#include <stddef.h>

struct t1_touchbar_fn_edge {
	int pressed;
};

/* Opens the unique Apple SPI keyboard that advertises KEY_FN, nonblocking. */
enum t1_touchbar_io_status t1_touchbar_fn_open(int *descriptor);

/* Reads the kernel's current Fn state for startup or SYN_DROPPED recovery. */
enum t1_touchbar_io_status t1_touchbar_fn_state(
	int descriptor, int *pressed);

/*
 * Drains one batch and returns only Fn press/release edges. Repeats and other
 * keys are ignored. SYN_DROPPED returns RESYNC and no edges.
 */
enum t1_touchbar_io_status t1_touchbar_fn_read(
	int descriptor, struct t1_touchbar_fn_edge *edges, size_t capacity,
	size_t *edge_count);

#ifdef T1_TOUCHBAR_TESTING
int t1_touchbar_fn_test_identity(const char *name, unsigned int bus,
				 int has_key_events, int has_fn_key);
#endif

#endif

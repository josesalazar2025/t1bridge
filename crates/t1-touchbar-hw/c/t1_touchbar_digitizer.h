#ifndef T1BRIDGE_TOUCHBAR_DIGITIZER_H
#define T1BRIDGE_TOUCHBAR_DIGITIZER_H

#include "t1_touchbar_io.h"

#include <stddef.h>
#include <stdint.h>

#define T1_TOUCHBAR_DIGITIZER_REPORT_SIZE 52U

/* Opens the unique descriptor-validated T1 hidraw digitizer, nonblocking. */
enum t1_touchbar_io_status t1_touchbar_digitizer_open(int *descriptor);

/*
 * Reads one complete report and normalizes an optional hidraw report-ID byte.
 * An idle timeout consumes nothing and returns T1_TOUCHBAR_IO_IDLE.
 */
enum t1_touchbar_io_status t1_touchbar_digitizer_read(
	int descriptor, unsigned int timeout_ms,
	uint8_t report[T1_TOUCHBAR_DIGITIZER_REPORT_SIZE]);

#ifdef T1_TOUCHBAR_TESTING
int t1_touchbar_digitizer_test_identity(
	unsigned int bus, unsigned int vendor, unsigned int product,
	int descriptor_size);
#endif

#endif

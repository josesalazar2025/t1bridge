#ifndef T1BRIDGE_SEP_USBFS_H
#define T1BRIDGE_SEP_USBFS_H

#include <stddef.h>
#include <stdint.h>

#include <linux/usbdevice_fs.h>

#define SEP_USBFS_VENDOR_ID 0x05acu
#define SEP_USBFS_PRODUCT_ID 0x8600u
#define SEP_USBFS_CONFIGURATION 2u
#define SEP_USBFS_INTERFACE 7u
#define SEP_USBFS_BULK_OUT 0x05u
#define SEP_USBFS_BULK_IN 0x88u

#define SEP_USBFS_PATH_CAPACITY 64u
#define SEP_USBFS_MAX_CANDIDATES 64u
#define SEP_USBFS_MAX_CONFIGURATION_BYTES 65535u

enum sep_usbfs_status {
	SEP_USBFS_OK = 0,
	SEP_USBFS_INVALID_ARGUMENT,
	SEP_USBFS_ENUMERATION_FAILED,
	SEP_USBFS_CANDIDATE_LIMIT,
	SEP_USBFS_DEVICE_NOT_FOUND,
	SEP_USBFS_DEVICE_AMBIGUOUS,
	SEP_USBFS_DEVICE_ACCESS_FAILED,
	SEP_USBFS_CONTROL_FAILED,
	SEP_USBFS_NOT_TARGET,
	SEP_USBFS_DESCRIPTOR_INVALID,
	SEP_USBFS_CONFIGURATION_MISMATCH,
	SEP_USBFS_INTERFACE_MISMATCH,
	SEP_USBFS_TIMED_OUT,
	SEP_USBFS_CLOCK_FAILED,
};

struct sep_usbfs_candidate {
	char path[SEP_USBFS_PATH_CAPACITY];
};

/*
 * These seams let tests exercise enumeration, open races, and control
 * transfers without touching a real USB device.  Production callers normally
 * use sep_usbfs_open_unique(), which supplies the Linux implementations.
 */
struct sep_usbfs_ops {
	void *context;
	int (*list_candidates)(void *context,
			       struct sep_usbfs_candidate *candidates,
			       size_t capacity, size_t *count);
	int (*open_path)(void *context, const char *path, int flags);
	int (*control)(void *context, int file_descriptor,
		       struct usbdevfs_ctrltransfer *transfer);
	int (*close_fd)(void *context, int file_descriptor);
	int (*monotonic_ms)(void *context, uint64_t *value);
};

/* Validate an already-fetched device descriptor and configuration-2 tree. */
enum sep_usbfs_status sep_usbfs_validate_descriptors(
	const uint8_t *device_descriptor, size_t device_length,
	const uint8_t *configuration_descriptor, size_t configuration_length);

/*
 * Open exactly one dynamically discovered, fully revalidated SEP device.
 * The returned descriptor is open read/write and has not claimed or detached
 * any interface.  The caller owns it and closes it with close(2).
 */
enum sep_usbfs_status sep_usbfs_open_unique(int *file_descriptor);

/* Every control transfer shares one monotonic timeout budget. */
enum sep_usbfs_status sep_usbfs_open_unique_bounded(
	unsigned int timeout_ms, int *file_descriptor);

enum sep_usbfs_status sep_usbfs_open_unique_with_ops(
	const struct sep_usbfs_ops *ops, int *file_descriptor);

enum sep_usbfs_status sep_usbfs_open_unique_bounded_with_ops(
	const struct sep_usbfs_ops *ops, unsigned int timeout_ms,
	int *file_descriptor);

const char *sep_usbfs_status_string(enum sep_usbfs_status status);

#endif

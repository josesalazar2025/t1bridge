#ifndef T1BRIDGE_T1_NCM_READY_H
#define T1BRIDGE_T1_NCM_READY_H

#include <stdint.h>

#define T1_NCM_READY_TIMEOUT_MS 5000u
#define T1_NCM_READY_RETRY_MS 25u

enum t1_ncm_ready_status {
	T1_NCM_READY_OK = 0,
	T1_NCM_READY_INVALID_ARGUMENT,
	T1_NCM_READY_DISCOVERY_FAILED,
	T1_NCM_READY_LINK_UP_FAILED,
	T1_NCM_READY_INSPECTION_FAILED,
	T1_NCM_READY_TIMEOUT,
	T1_NCM_READY_DEVICE_CHANGED,
	T1_NCM_READY_CLOCK_FAILED,
	T1_NCM_READY_WAIT_FAILED,
};

/* Focused lifecycle seam for hardware-free native tests. */
struct t1_ncm_ready_ops {
	void *context;
	int (*discover)(void *context, uint32_t *interface_index);
	int (*set_up)(void *context, uint32_t interface_index);
	int (*is_ready)(void *context, uint32_t interface_index);
	int (*monotonic_ms)(void *context, uint64_t *milliseconds);
	int (*wait_ms)(void *context, uint32_t milliseconds);
};

/*
 * Validate exactly one T1 NCM interface, prove it is the interface named by
 * the device-triggered service instance, bring only that kernel index up,
 * wait boundedly for usable IPv6 link-local addressing, and revalidate it.
 */
enum t1_ncm_ready_status t1_ncm_ready_prepare_for_interface(
	const char *expected_interface);

enum t1_ncm_ready_status t1_ncm_ready_prepare_for_index_with_ops(
	uint32_t expected_interface_index, const struct t1_ncm_ready_ops *ops);

#endif

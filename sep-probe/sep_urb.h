#ifndef T1BRIDGE_SEP_URB_H
#define T1BRIDGE_SEP_URB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sep_usbfs.h"

#define SEP_URB_TRANSFER_SIZE 0x4400u
#define SEP_URB_BUFFER_ALIGNMENT 4096u
#define SEP_URB_MAX_TIMEOUT_MS 60000u

enum sep_urb_status {
	SEP_URB_OK = 0,
	SEP_URB_INVALID_ARGUMENT,
	SEP_URB_ALLOCATION_FAILED,
	SEP_URB_CLAIM_FAILED,
	SEP_URB_RELEASE_FAILED,
	SEP_URB_SUBMIT_FAILED,
	SEP_URB_TIMED_OUT,
	SEP_URB_INTERRUPTED,
	SEP_URB_TRANSFER_FAILED,
	SEP_URB_SHORT_TRANSFER,
	SEP_URB_REAP_FAILED,
	SEP_URB_CLEANUP_FAILED,
	SEP_URB_INVALID_STATE,
};

enum sep_urb_state {
	SEP_URB_STATE_UNINITIALIZED = 0,
	SEP_URB_STATE_READY,
	SEP_URB_STATE_BUSY,
	SEP_URB_STATE_TIMED_OUT,
	SEP_URB_STATE_INTERRUPTED,
	SEP_URB_STATE_TRANSFER_ERROR,
	SEP_URB_STATE_POISONED,
};

enum sep_urb_op_result {
	SEP_URB_OP_OK = 0,
	SEP_URB_OP_AGAIN,
	SEP_URB_OP_INTERRUPTED,
	SEP_URB_OP_NOT_FOUND,
	SEP_URB_OP_FAILED,
};

struct sep_urb_ops {
	void *context;
	enum sep_urb_op_result (*claim_interface)(void *context,
						  int file_descriptor,
						  unsigned int interface);
	enum sep_urb_op_result (*release_interface)(void *context,
						    int file_descriptor,
						    unsigned int interface);
	enum sep_urb_op_result (*submit)(void *context, int file_descriptor,
					 struct usbdevfs_urb *urb);
	enum sep_urb_op_result (*discard)(void *context, int file_descriptor,
					  struct usbdevfs_urb *urb);
	enum sep_urb_op_result (*reap)(void *context, int file_descriptor,
				       struct usbdevfs_urb **urb);
	enum sep_urb_op_result (*wait_ready)(void *context, int file_descriptor,
					     unsigned int timeout_ms);
	enum sep_urb_op_result (*monotonic_ms)(void *context, uint64_t *value);
};

enum sep_urb_slot_state {
	SEP_URB_SLOT_IDLE = 0,
	SEP_URB_SLOT_SUBMITTED,
	SEP_URB_SLOT_REAPED,
};

struct sep_urb_slot {
	struct usbdevfs_urb *urb;
	uint8_t *buffer;
	enum sep_urb_slot_state state;
};

/*
 * One owner manages both URBs because usbfs completion reaping operates on the
 * whole file descriptor, not on a requested endpoint. Fields are public so
 * callers can allocate the transport without a hidden allocator; mutate them
 * only through these functions. The descriptor must not be shared with
 * another asynchronous URB owner.
 */
struct sep_urb_transport {
	int file_descriptor;
	struct sep_urb_ops ops;
	struct sep_urb_slot input;
	struct sep_urb_slot output;
	enum sep_urb_state state;
	bool interface_claimed;
};

enum sep_urb_status sep_urb_transport_initialize(
	struct sep_urb_transport *transport, int file_descriptor);

enum sep_urb_status sep_urb_transport_initialize_with_ops(
	struct sep_urb_transport *transport, int file_descriptor,
	const struct sep_urb_ops *ops);

/*
 * Submit the complete IN URB before the complete OUT URB, then reap both.
 * Both application buffers must have exactly SEP_URB_TRANSFER_SIZE bytes.
 */
enum sep_urb_status sep_urb_exchange(struct sep_urb_transport *transport,
	const uint8_t *output, size_t output_length, uint8_t *input,
	size_t input_capacity, unsigned int timeout_ms);

/*
 * Submit one complete relay buffer to the fixed SEP bulk OUT endpoint and wait
 * for its exact completion. No receive URB is armed.
 */
enum sep_urb_status sep_urb_send_only(struct sep_urb_transport *transport,
	const uint8_t *output, size_t output_length, unsigned int timeout_ms);

/*
 * Receive one complete relay buffer from the fixed SEP bulk IN endpoint and
 * wait for its exact completion. No send URB is submitted.
 */
enum sep_urb_status sep_urb_receive_only(struct sep_urb_transport *transport,
	uint8_t *input, size_t input_capacity, unsigned int timeout_ms);

/* Release interface 7 and wipe/free buffers. */
enum sep_urb_status sep_urb_transport_destroy(
	struct sep_urb_transport *transport);

/*
 * Wipe/free retained allocations after the owning descriptor has been closed.
 * This is the terminal path after destroy cannot prove that all kernel work
 * was reaped. It performs no transport operation and makes the object unusable.
 */
void sep_urb_transport_abandon_after_close(
	struct sep_urb_transport *transport);

enum sep_urb_state sep_urb_transport_state(
	const struct sep_urb_transport *transport);

const char *sep_urb_status_string(enum sep_urb_status status);

#endif

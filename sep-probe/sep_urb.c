#define _POSIX_C_SOURCE 200809L

#include "sep_urb.h"

#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>

#define SEP_URB_NORMAL_REAP_LIMIT 8u
#define SEP_URB_WAIT_LIMIT 16u
#define SEP_URB_CLEANUP_REAP_LIMIT 16u
#define SEP_URB_DISCARD_RETRY_LIMIT 4u
#define SEP_URB_CLEANUP_WAIT_MS 50u

static void clear_bytes(void *memory, size_t length)
{
	volatile uint8_t *bytes = memory;

	while (length > 0) {
		*bytes = 0;
		++bytes;
		--length;
	}
}

static bool slot_is_active(const struct sep_urb_slot *slot)
{
	return slot->state == SEP_URB_SLOT_SUBMITTED;
}

static bool any_slot_is_active(const struct sep_urb_transport *transport)
{
	return slot_is_active(&transport->input) ||
	       slot_is_active(&transport->output);
}

static void reset_slot(struct sep_urb_slot *slot, uint8_t endpoint)
{
	memset(slot->urb, 0, sizeof(*slot->urb));
	clear_bytes(slot->buffer, SEP_URB_TRANSFER_SIZE);
	slot->urb->type = USBDEVFS_URB_TYPE_BULK;
	slot->urb->endpoint = endpoint;
	slot->urb->flags = endpoint == SEP_USBFS_BULK_IN
				   ? USBDEVFS_URB_SHORT_NOT_OK
				   : 0;
	slot->urb->buffer = slot->buffer;
	slot->urb->buffer_length = (int)SEP_URB_TRANSFER_SIZE;
	/* usercontext intentionally stays NULL; it is not a wire identity. */
	slot->state = SEP_URB_SLOT_IDLE;
}

static enum sep_urb_op_result linux_claim_interface(void *context,
						     int file_descriptor,
						     unsigned int interface)
{
	(void)context;
	if (ioctl(file_descriptor, USBDEVFS_CLAIMINTERFACE, &interface) == 0)
		return SEP_URB_OP_OK;
	return errno == EINTR ? SEP_URB_OP_INTERRUPTED : SEP_URB_OP_FAILED;
}

static enum sep_urb_op_result linux_release_interface(void *context,
						       int file_descriptor,
						       unsigned int interface)
{
	(void)context;
	if (ioctl(file_descriptor, USBDEVFS_RELEASEINTERFACE, &interface) == 0)
		return SEP_URB_OP_OK;
	return errno == EINTR ? SEP_URB_OP_INTERRUPTED : SEP_URB_OP_FAILED;
}

static enum sep_urb_op_result linux_submit(void *context, int file_descriptor,
					   struct usbdevfs_urb *urb)
{
	(void)context;
	if (ioctl(file_descriptor, USBDEVFS_SUBMITURB, urb) == 0)
		return SEP_URB_OP_OK;
	return errno == EINTR ? SEP_URB_OP_INTERRUPTED : SEP_URB_OP_FAILED;
}

static enum sep_urb_op_result linux_discard(void *context, int file_descriptor,
					    struct usbdevfs_urb *urb)
{
	(void)context;
	if (ioctl(file_descriptor, USBDEVFS_DISCARDURB, urb) == 0)
		return SEP_URB_OP_OK;
	if (errno == EINTR)
		return SEP_URB_OP_INTERRUPTED;
	if (errno == EINVAL || errno == ENOENT)
		return SEP_URB_OP_NOT_FOUND;
	return SEP_URB_OP_FAILED;
}

static enum sep_urb_op_result linux_reap(void *context, int file_descriptor,
					 struct usbdevfs_urb **urb)
{
	(void)context;
	if (ioctl(file_descriptor, USBDEVFS_REAPURBNDELAY, urb) == 0)
		return SEP_URB_OP_OK;
	if (errno == EINTR)
		return SEP_URB_OP_INTERRUPTED;
	if (errno == EAGAIN)
		return SEP_URB_OP_AGAIN;
	return SEP_URB_OP_FAILED;
}

static enum sep_urb_op_result linux_wait_ready(void *context,
					       int file_descriptor,
					       unsigned int timeout_ms)
{
	struct pollfd descriptor = {
		.fd = file_descriptor,
		.events = POLLOUT,
	};
	int result;

	(void)context;
	result = poll(&descriptor, 1, (int)timeout_ms);
	if (result > 0 &&
	    (descriptor.revents & (POLLOUT | POLLERR | POLLHUP)) != 0)
		return SEP_URB_OP_OK;
	if (result == 0)
		return SEP_URB_OP_AGAIN;
	if (result < 0 && errno == EINTR)
		return SEP_URB_OP_INTERRUPTED;
	return SEP_URB_OP_FAILED;
}

static enum sep_urb_op_result linux_monotonic_ms(void *context,
						 uint64_t *value)
{
	struct timespec time;

	(void)context;
	if (clock_gettime(CLOCK_MONOTONIC, &time) != 0)
		return SEP_URB_OP_FAILED;
	*value = (uint64_t)time.tv_sec * 1000u +
		 (uint64_t)time.tv_nsec / 1000000u;
	return SEP_URB_OP_OK;
}

static const struct sep_urb_ops linux_ops = {
	.context = NULL,
	.claim_interface = linux_claim_interface,
	.release_interface = linux_release_interface,
	.submit = linux_submit,
	.discard = linux_discard,
	.reap = linux_reap,
	.wait_ready = linux_wait_ready,
	.monotonic_ms = linux_monotonic_ms,
};

static bool valid_ops(const struct sep_urb_ops *ops)
{
	return ops != NULL && ops->claim_interface != NULL &&
	       ops->release_interface != NULL && ops->submit != NULL &&
	       ops->discard != NULL && ops->reap != NULL &&
	       ops->wait_ready != NULL && ops->monotonic_ms != NULL;
}

static enum sep_urb_status allocate_slot(struct sep_urb_slot *slot)
{
	void *buffer = NULL;

	slot->urb = calloc(1, sizeof(*slot->urb));
	if (slot->urb == NULL)
		return SEP_URB_ALLOCATION_FAILED;
	if (posix_memalign(&buffer, SEP_URB_BUFFER_ALIGNMENT,
			   SEP_URB_TRANSFER_SIZE) != 0) {
		free(slot->urb);
		slot->urb = NULL;
		return SEP_URB_ALLOCATION_FAILED;
	}
	slot->buffer = buffer;
	return SEP_URB_OK;
}

enum sep_urb_status sep_urb_transport_initialize_with_ops(
	struct sep_urb_transport *transport, int file_descriptor,
	const struct sep_urb_ops *ops)
{
	enum sep_urb_status status;

	if (transport == NULL || file_descriptor < 0 || !valid_ops(ops))
		return SEP_URB_INVALID_ARGUMENT;
	memset(transport, 0, sizeof(*transport));
	transport->file_descriptor = file_descriptor;
	transport->ops = *ops;
	status = allocate_slot(&transport->input);
	if (status != SEP_URB_OK)
		return status;
	status = allocate_slot(&transport->output);
	if (status != SEP_URB_OK) {
		clear_bytes(transport->input.buffer, SEP_URB_TRANSFER_SIZE);
		free(transport->input.buffer);
		free(transport->input.urb);
		transport->input.buffer = NULL;
		transport->input.urb = NULL;
		return status;
	}
	reset_slot(&transport->input, SEP_USBFS_BULK_IN);
	reset_slot(&transport->output, SEP_USBFS_BULK_OUT);
	if (transport->ops.claim_interface(transport->ops.context,
					   file_descriptor,
					   SEP_USBFS_INTERFACE) != SEP_URB_OP_OK) {
		clear_bytes(transport->input.buffer, SEP_URB_TRANSFER_SIZE);
		clear_bytes(transport->output.buffer, SEP_URB_TRANSFER_SIZE);
		free(transport->input.buffer);
		free(transport->output.buffer);
		free(transport->input.urb);
		free(transport->output.urb);
		transport->input.buffer = NULL;
		transport->output.buffer = NULL;
		transport->input.urb = NULL;
		transport->output.urb = NULL;
		return SEP_URB_CLAIM_FAILED;
	}
	transport->interface_claimed = true;
	transport->state = SEP_URB_STATE_READY;
	return SEP_URB_OK;
}

enum sep_urb_status sep_urb_transport_initialize(
	struct sep_urb_transport *transport, int file_descriptor)
{
	return sep_urb_transport_initialize_with_ops(transport, file_descriptor,
						     &linux_ops);
}

static struct sep_urb_slot *find_slot(struct sep_urb_transport *transport,
				      struct usbdevfs_urb *urb)
{
	if (urb == transport->input.urb)
		return &transport->input;
	if (urb == transport->output.urb)
		return &transport->output;
	return NULL;
}

static enum sep_urb_status record_reap(struct sep_urb_transport *transport,
				       struct usbdevfs_urb *urb)
{
	struct sep_urb_slot *slot = find_slot(transport, urb);

	if (slot == NULL || slot->state != SEP_URB_SLOT_SUBMITTED)
		return SEP_URB_REAP_FAILED;
	slot->state = SEP_URB_SLOT_REAPED;
	return SEP_URB_OK;
}

static enum sep_urb_status discard_slot(struct sep_urb_transport *transport,
					struct sep_urb_slot *slot)
{
	unsigned int attempt;

	if (!slot_is_active(slot))
		return SEP_URB_OK;
	for (attempt = 0; attempt < SEP_URB_DISCARD_RETRY_LIMIT; ++attempt) {
		enum sep_urb_op_result result = transport->ops.discard(
			transport->ops.context, transport->file_descriptor,
			slot->urb);

		if (result == SEP_URB_OP_OK || result == SEP_URB_OP_NOT_FOUND)
			return SEP_URB_OK;
		if (result != SEP_URB_OP_INTERRUPTED)
			return SEP_URB_TRANSFER_FAILED;
	}
	return SEP_URB_INTERRUPTED;
}

static enum sep_urb_status cleanup_active_urbs(
	struct sep_urb_transport *transport)
{
	unsigned int wait_attempts = 0;
	unsigned int reaped = 0;

	(void)discard_slot(transport, &transport->input);
	(void)discard_slot(transport, &transport->output);

	while (wait_attempts < SEP_URB_CLEANUP_REAP_LIMIT &&
	       reaped < 2 && any_slot_is_active(transport)) {
		struct usbdevfs_urb *urb = NULL;
		enum sep_urb_op_result result = transport->ops.reap(
			transport->ops.context, transport->file_descriptor, &urb);

		if (result == SEP_URB_OP_OK) {
			if (record_reap(transport, urb) != SEP_URB_OK)
				break;
			++reaped;
			continue;
		}
		/*
		 * DISCARDURB completion is asynchronous. Poll briefly, then retry
		 * the nonblocking reap regardless of poll's result. The attempt
		 * limit bounds cancellation even on a broken or disconnected fd.
		 */
		(void)transport->ops.wait_ready(
			transport->ops.context, transport->file_descriptor,
			SEP_URB_CLEANUP_WAIT_MS);
		++wait_attempts;
	}
	if (any_slot_is_active(transport)) {
		transport->state = SEP_URB_STATE_POISONED;
		return SEP_URB_CLEANUP_FAILED;
	}
	/* A failed discard is harmless only after the exact URB is reaped. */
	return SEP_URB_OK;
}

static void make_slots_reusable(struct sep_urb_transport *transport)
{
	reset_slot(&transport->input, SEP_USBFS_BULK_IN);
	reset_slot(&transport->output, SEP_USBFS_BULK_OUT);
}

static enum sep_urb_status finish_failure(struct sep_urb_transport *transport,
					  enum sep_urb_status status,
					  enum sep_urb_state state)
{
	if (cleanup_active_urbs(transport) != SEP_URB_OK)
		return SEP_URB_CLEANUP_FAILED;
	make_slots_reusable(transport);
	transport->state = state;
	return status;
}

static enum sep_urb_status submit_slot(struct sep_urb_transport *transport,
				       struct sep_urb_slot *slot)
{
	if (slot->state != SEP_URB_SLOT_IDLE)
		return SEP_URB_INVALID_STATE;
	if (transport->ops.submit(transport->ops.context,
				  transport->file_descriptor,
				  slot->urb) != SEP_URB_OP_OK)
		return SEP_URB_SUBMIT_FAILED;
	slot->state = SEP_URB_SLOT_SUBMITTED;
	return SEP_URB_OK;
}

static enum sep_urb_status validate_reaped_slots(
	const struct sep_urb_transport *transport)
{
	if (transport->input.urb->status != 0 ||
	    transport->output.urb->status != 0)
		return SEP_URB_TRANSFER_FAILED;
	if (transport->input.urb->actual_length != (int)SEP_URB_TRANSFER_SIZE ||
	    transport->output.urb->actual_length != (int)SEP_URB_TRANSFER_SIZE)
		return SEP_URB_SHORT_TRANSFER;
	return SEP_URB_OK;
}

static enum sep_urb_status reap_available(struct sep_urb_transport *transport)
{
	unsigned int attempt;

	for (attempt = 0; attempt < SEP_URB_NORMAL_REAP_LIMIT; ++attempt) {
		struct usbdevfs_urb *urb = NULL;
		enum sep_urb_op_result result = transport->ops.reap(
			transport->ops.context, transport->file_descriptor, &urb);

		if (result == SEP_URB_OP_AGAIN)
			return SEP_URB_OK;
		if (result == SEP_URB_OP_INTERRUPTED)
			return SEP_URB_INTERRUPTED;
		if (result != SEP_URB_OP_OK)
			return SEP_URB_REAP_FAILED;
		if (record_reap(transport, urb) != SEP_URB_OK)
			return SEP_URB_REAP_FAILED;
		if (urb->status != 0)
			return SEP_URB_TRANSFER_FAILED;
		if (urb->actual_length != (int)SEP_URB_TRANSFER_SIZE)
			return SEP_URB_SHORT_TRANSFER;
	}
	return any_slot_is_active(transport) ? SEP_URB_OK :
					      SEP_URB_REAP_FAILED;
}

static unsigned int remaining_timeout(uint64_t deadline, uint64_t now)
{
	uint64_t remaining;

	if (now >= deadline)
		return 0;
	remaining = deadline - now;
	if (remaining > SEP_URB_MAX_TIMEOUT_MS)
		remaining = SEP_URB_MAX_TIMEOUT_MS;
	return (unsigned int)remaining;
}

static enum sep_urb_status validate_transfer_ready(
	struct sep_urb_transport *transport, unsigned int timeout_ms,
	uint64_t *deadline)
{
	uint64_t start;

	if (transport == NULL || deadline == NULL || timeout_ms == 0 ||
	    timeout_ms > SEP_URB_MAX_TIMEOUT_MS)
		return SEP_URB_INVALID_ARGUMENT;
	if (!transport->interface_claimed || transport->input.buffer == NULL ||
	    transport->output.buffer == NULL || any_slot_is_active(transport) ||
	    transport->state == SEP_URB_STATE_UNINITIALIZED ||
	    transport->state == SEP_URB_STATE_BUSY ||
	    transport->state == SEP_URB_STATE_POISONED)
		return SEP_URB_INVALID_STATE;
	if (transport->ops.monotonic_ms(transport->ops.context, &start) !=
	    SEP_URB_OP_OK || UINT64_MAX - start < timeout_ms) {
		transport->state = SEP_URB_STATE_TRANSFER_ERROR;
		return SEP_URB_TRANSFER_FAILED;
	}
	*deadline = start + timeout_ms;
	return SEP_URB_OK;
}

static enum sep_urb_status wait_for_active_urbs(
	struct sep_urb_transport *transport, uint64_t deadline)
{
	unsigned int wait_attempt;

	for (wait_attempt = 0;
	     wait_attempt < SEP_URB_WAIT_LIMIT && any_slot_is_active(transport);
	     ++wait_attempt) {
		uint64_t now;
		unsigned int remaining;
		enum sep_urb_op_result wait_result;
		enum sep_urb_status status;

		if (transport->ops.monotonic_ms(transport->ops.context, &now) !=
		    SEP_URB_OP_OK)
			return finish_failure(transport, SEP_URB_TRANSFER_FAILED,
					      SEP_URB_STATE_TRANSFER_ERROR);
		remaining = remaining_timeout(deadline, now);
		if (remaining == 0)
			return finish_failure(transport, SEP_URB_TIMED_OUT,
					      SEP_URB_STATE_TIMED_OUT);
		wait_result = transport->ops.wait_ready(
			transport->ops.context, transport->file_descriptor, remaining);
		if (wait_result == SEP_URB_OP_AGAIN)
			return finish_failure(transport, SEP_URB_TIMED_OUT,
					      SEP_URB_STATE_TIMED_OUT);
		if (wait_result == SEP_URB_OP_INTERRUPTED)
			return finish_failure(transport, SEP_URB_INTERRUPTED,
					      SEP_URB_STATE_INTERRUPTED);
		if (wait_result != SEP_URB_OP_OK)
			return finish_failure(transport, SEP_URB_TRANSFER_FAILED,
					      SEP_URB_STATE_TRANSFER_ERROR);
		status = reap_available(transport);
		if (status == SEP_URB_INTERRUPTED)
			return finish_failure(transport, status,
					      SEP_URB_STATE_INTERRUPTED);
		if (status != SEP_URB_OK)
			return finish_failure(transport, status,
					      SEP_URB_STATE_TRANSFER_ERROR);
	}
	if (any_slot_is_active(transport))
		return finish_failure(transport, SEP_URB_REAP_FAILED,
				      SEP_URB_STATE_TRANSFER_ERROR);
	return SEP_URB_OK;
}

enum sep_urb_status sep_urb_exchange(struct sep_urb_transport *transport,
	const uint8_t *output, size_t output_length, uint8_t *input,
	size_t input_capacity, unsigned int timeout_ms)
{
	uint64_t deadline;
	enum sep_urb_status status;

	if (transport == NULL || output == NULL || input == NULL ||
	    output_length != SEP_URB_TRANSFER_SIZE ||
	    input_capacity != SEP_URB_TRANSFER_SIZE || timeout_ms == 0 ||
	    timeout_ms > SEP_URB_MAX_TIMEOUT_MS)
		return SEP_URB_INVALID_ARGUMENT;
	status = validate_transfer_ready(transport, timeout_ms, &deadline);
	if (status != SEP_URB_OK)
		return status;
	make_slots_reusable(transport);
	memcpy(transport->output.buffer, output, SEP_URB_TRANSFER_SIZE);
	transport->state = SEP_URB_STATE_BUSY;

	/* Arm the receive before making the request visible to the device. */
	status = submit_slot(transport, &transport->input);
	if (status != SEP_URB_OK)
		return finish_failure(transport, status,
				      SEP_URB_STATE_TRANSFER_ERROR);
	status = submit_slot(transport, &transport->output);
	if (status != SEP_URB_OK)
		return finish_failure(transport, status,
				      SEP_URB_STATE_TRANSFER_ERROR);

	status = wait_for_active_urbs(transport, deadline);
	if (status != SEP_URB_OK)
		return status;

	status = validate_reaped_slots(transport);
	if (status != SEP_URB_OK)
		return finish_failure(transport, status,
				      SEP_URB_STATE_TRANSFER_ERROR);
	memcpy(input, transport->input.buffer, SEP_URB_TRANSFER_SIZE);
	make_slots_reusable(transport);
	transport->state = SEP_URB_STATE_READY;
	return SEP_URB_OK;
}

static enum sep_urb_status directional_transfer(
	struct sep_urb_transport *transport, struct sep_urb_slot *slot,
	uint64_t deadline)
{
	enum sep_urb_status status;

	transport->state = SEP_URB_STATE_BUSY;
	status = submit_slot(transport, slot);
	if (status != SEP_URB_OK)
		return finish_failure(transport, status,
				      SEP_URB_STATE_TRANSFER_ERROR);
	status = wait_for_active_urbs(transport, deadline);
	if (status != SEP_URB_OK)
		return status;
	if (slot->urb->status != 0)
		return finish_failure(transport, SEP_URB_TRANSFER_FAILED,
				      SEP_URB_STATE_TRANSFER_ERROR);
	if (slot->urb->actual_length != (int)SEP_URB_TRANSFER_SIZE)
		return finish_failure(transport, SEP_URB_SHORT_TRANSFER,
				      SEP_URB_STATE_TRANSFER_ERROR);
	return SEP_URB_OK;
}

enum sep_urb_status sep_urb_send_only(struct sep_urb_transport *transport,
	const uint8_t *output, size_t output_length, unsigned int timeout_ms)
{
	uint64_t deadline;
	enum sep_urb_status status;

	if (transport == NULL || output == NULL ||
	    output_length != SEP_URB_TRANSFER_SIZE)
		return SEP_URB_INVALID_ARGUMENT;
	status = validate_transfer_ready(transport, timeout_ms, &deadline);
	if (status != SEP_URB_OK)
		return status;
	make_slots_reusable(transport);
	memcpy(transport->output.buffer, output, SEP_URB_TRANSFER_SIZE);
	status = directional_transfer(transport, &transport->output, deadline);
	if (status != SEP_URB_OK)
		return status;
	make_slots_reusable(transport);
	transport->state = SEP_URB_STATE_READY;
	return SEP_URB_OK;
}

enum sep_urb_status sep_urb_receive_only(struct sep_urb_transport *transport,
	uint8_t *input, size_t input_capacity, unsigned int timeout_ms)
{
	uint64_t deadline;
	enum sep_urb_status status;

	if (transport == NULL || input == NULL ||
	    input_capacity != SEP_URB_TRANSFER_SIZE)
		return SEP_URB_INVALID_ARGUMENT;
	status = validate_transfer_ready(transport, timeout_ms, &deadline);
	if (status != SEP_URB_OK)
		return status;
	make_slots_reusable(transport);
	status = directional_transfer(transport, &transport->input, deadline);
	if (status != SEP_URB_OK)
		return status;
	memcpy(input, transport->input.buffer, SEP_URB_TRANSFER_SIZE);
	make_slots_reusable(transport);
	transport->state = SEP_URB_STATE_READY;
	return SEP_URB_OK;
}

static void release_allocations(struct sep_urb_transport *transport)
{
	if (transport->input.buffer != NULL)
		clear_bytes(transport->input.buffer, SEP_URB_TRANSFER_SIZE);
	if (transport->output.buffer != NULL)
		clear_bytes(transport->output.buffer, SEP_URB_TRANSFER_SIZE);
	free(transport->input.buffer);
	free(transport->output.buffer);
	free(transport->input.urb);
	free(transport->output.urb);
	memset(transport, 0, sizeof(*transport));
}

enum sep_urb_status sep_urb_transport_destroy(
	struct sep_urb_transport *transport)
{
	if (transport == NULL)
		return SEP_URB_INVALID_ARGUMENT;
	if (transport->state == SEP_URB_STATE_UNINITIALIZED &&
	    !transport->interface_claimed && transport->input.buffer == NULL &&
	    transport->output.buffer == NULL)
		return SEP_URB_OK;
	if (any_slot_is_active(transport) &&
	    cleanup_active_urbs(transport) != SEP_URB_OK)
		return SEP_URB_CLEANUP_FAILED;
	if (transport->interface_claimed &&
	    transport->ops.release_interface(
		    transport->ops.context, transport->file_descriptor,
		    SEP_USBFS_INTERFACE) != SEP_URB_OP_OK) {
		release_allocations(transport);
		return SEP_URB_RELEASE_FAILED;
	}
	transport->interface_claimed = false;
	release_allocations(transport);
	return SEP_URB_OK;
}

void sep_urb_transport_abandon_after_close(
	struct sep_urb_transport *transport)
{
	if (transport != NULL)
		release_allocations(transport);
}

enum sep_urb_state sep_urb_transport_state(
	const struct sep_urb_transport *transport)
{
	return transport == NULL ? SEP_URB_STATE_UNINITIALIZED : transport->state;
}

const char *sep_urb_status_string(enum sep_urb_status status)
{
	switch (status) {
	case SEP_URB_OK:
		return "success";
	case SEP_URB_INVALID_ARGUMENT:
		return "invalid argument";
	case SEP_URB_ALLOCATION_FAILED:
		return "USB transfer buffer allocation failed";
	case SEP_URB_CLAIM_FAILED:
		return "SEP interface claim failed";
	case SEP_URB_RELEASE_FAILED:
		return "SEP interface release failed";
	case SEP_URB_SUBMIT_FAILED:
		return "SEP transfer submission failed";
	case SEP_URB_TIMED_OUT:
		return "SEP transfer timed out";
	case SEP_URB_INTERRUPTED:
		return "SEP transfer interrupted";
	case SEP_URB_TRANSFER_FAILED:
		return "SEP transfer failed";
	case SEP_URB_SHORT_TRANSFER:
		return "SEP transfer was short";
	case SEP_URB_REAP_FAILED:
		return "SEP transfer reap failed";
	case SEP_URB_CLEANUP_FAILED:
		return "SEP transfer cleanup failed";
	case SEP_URB_INVALID_STATE:
		return "SEP transport state is invalid";
	}
	return "unknown SEP transfer error";
}

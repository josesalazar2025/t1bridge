#define _POSIX_C_SOURCE 200809L

#include "sep_urb.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FAKE_SLOT_COUNT 2u
#define FAKE_EVENT_LIMIT 128u

static unsigned int failures;

#define EXPECT_TRUE(expression)                                                \
	do {                                                                    \
		if (!(expression)) {                                              \
			fprintf(stderr, "%s:%d: expectation failed: %s\n",       \
				__FILE__, __LINE__, #expression);                    \
			++failures;                                                 \
		}                                                               \
	} while (0)

#define EXPECT_STATUS(expected, expression)                                   \
	do {                                                                    \
		enum sep_urb_status actual_status = (expression);                 \
		if (actual_status != (expected)) {                                \
			fprintf(stderr,                                             \
				"%s:%d: expected status %d, received %d\n",       \
				__FILE__, __LINE__, (int)(expected),                \
				(int)actual_status);                                    \
			++failures;                                                 \
		}                                                               \
	} while (0)

enum fake_wait_mode {
	FAKE_WAIT_NORMAL = 0,
	FAKE_WAIT_TIMEOUT,
	FAKE_WAIT_INTERRUPTED,
	FAKE_WAIT_FAILED,
};

enum fake_event_type {
	FAKE_EVENT_CLAIM = 1,
	FAKE_EVENT_SUBMIT_IN,
	FAKE_EVENT_SUBMIT_OUT,
	FAKE_EVENT_DISCARD_IN,
	FAKE_EVENT_DISCARD_OUT,
	FAKE_EVENT_REAP_IN,
	FAKE_EVENT_REAP_OUT,
	FAKE_EVENT_RELEASE,
};

struct fake_slot {
	struct usbdevfs_urb *urb;
	bool submitted;
	bool discarded;
	bool reaped;
	int completion_status;
	int completion_length;
	unsigned int discard_event;
	unsigned int reap_event;
};

struct fake_context {
	struct fake_slot slots[FAKE_SLOT_COUNT];
	enum fake_wait_mode wait_mode;
	enum sep_urb_op_result discard_result;
	unsigned int completion_order[FAKE_SLOT_COUNT];
	unsigned int completion_available;
	unsigned int completion_index;
	unsigned int submit_calls;
	unsigned int fail_submit_call;
	unsigned int wait_calls;
	unsigned int discard_calls;
	unsigned int reap_calls;
	unsigned int cancelled_reap_delay;
	unsigned int claim_calls;
	unsigned int release_calls;
	unsigned int claimed_interface;
	unsigned int released_interface;
	unsigned int events[FAKE_EVENT_LIMIT];
	unsigned int event_count;
	uint64_t now_ms;
	bool claim_fails;
	bool release_fails;
	bool clock_fails;
	bool reap_without_discard;
	bool submit_shape_valid;
	const uint8_t *expected_output;
};

static void record_event(struct fake_context *context,
			 unsigned int event_type)
{
	if (context->event_count < FAKE_EVENT_LIMIT)
		context->events[context->event_count] = event_type;
	++context->event_count;
}

static struct fake_context make_fake_context(void)
{
	struct fake_context context = { 0 };

	context.wait_mode = FAKE_WAIT_NORMAL;
	context.discard_result = SEP_URB_OP_OK;
	context.completion_order[0] = 1;
	context.completion_order[1] = 0;
	context.slots[0].completion_status = 0;
	context.slots[0].completion_length = (int)SEP_URB_TRANSFER_SIZE;
	context.slots[1].completion_status = 0;
	context.slots[1].completion_length = (int)SEP_URB_TRANSFER_SIZE;
	context.submit_shape_valid = true;
	return context;
}

static unsigned int slot_index_for_endpoint(uint8_t endpoint)
{
	return endpoint == SEP_USBFS_BULK_IN ? 0u : 1u;
}

static unsigned int submit_event_for_slot(unsigned int slot)
{
	return slot == 0 ? FAKE_EVENT_SUBMIT_IN : FAKE_EVENT_SUBMIT_OUT;
}

static unsigned int discard_event_for_slot(unsigned int slot)
{
	return slot == 0 ? FAKE_EVENT_DISCARD_IN : FAKE_EVENT_DISCARD_OUT;
}

static unsigned int reap_event_for_slot(unsigned int slot)
{
	return slot == 0 ? FAKE_EVENT_REAP_IN : FAKE_EVENT_REAP_OUT;
}

static enum sep_urb_op_result fake_claim(void *opaque, int file_descriptor,
						 unsigned int interface)
{
	struct fake_context *context = opaque;

	(void)file_descriptor;
	++context->claim_calls;
	context->claimed_interface = interface;
	record_event(context, FAKE_EVENT_CLAIM);
	return context->claim_fails ? SEP_URB_OP_FAILED : SEP_URB_OP_OK;
}

static enum sep_urb_op_result fake_release(void *opaque, int file_descriptor,
						   unsigned int interface)
{
	struct fake_context *context = opaque;

	(void)file_descriptor;
	++context->release_calls;
	context->released_interface = interface;
	record_event(context, FAKE_EVENT_RELEASE);
	return context->release_fails ? SEP_URB_OP_FAILED : SEP_URB_OP_OK;
}

static enum sep_urb_op_result fake_submit(void *opaque, int file_descriptor,
					  struct usbdevfs_urb *urb)
{
	struct fake_context *context = opaque;
	unsigned int slot;

	(void)file_descriptor;
	++context->submit_calls;
	if (context->fail_submit_call == context->submit_calls)
		return SEP_URB_OP_FAILED;
	if (urb->endpoint != SEP_USBFS_BULK_IN &&
	    urb->endpoint != SEP_USBFS_BULK_OUT)
		return SEP_URB_OP_FAILED;
	slot = slot_index_for_endpoint(urb->endpoint);
	context->slots[slot].urb = urb;
	context->slots[slot].submitted = true;
	context->slots[slot].discarded = false;
	context->slots[slot].reaped = false;
	if (urb->type != USBDEVFS_URB_TYPE_BULK ||
	    urb->buffer_length != (int)SEP_URB_TRANSFER_SIZE ||
	    urb->flags != (urb->endpoint == SEP_USBFS_BULK_IN
				      ? USBDEVFS_URB_SHORT_NOT_OK
				      : 0) ||
	    urb->usercontext != NULL ||
	    (uintptr_t)urb->buffer % SEP_URB_BUFFER_ALIGNMENT != 0)
		context->submit_shape_valid = false;
	if (slot == 1 && context->expected_output != NULL &&
	    memcmp(urb->buffer, context->expected_output,
		   SEP_URB_TRANSFER_SIZE) != 0)
		context->submit_shape_valid = false;
	record_event(context, submit_event_for_slot(slot));
	return SEP_URB_OP_OK;
}

static enum sep_urb_op_result fake_discard(void *opaque, int file_descriptor,
					   struct usbdevfs_urb *urb)
{
	struct fake_context *context = opaque;
	unsigned int slot = slot_index_for_endpoint(urb->endpoint);

	(void)file_descriptor;
	++context->discard_calls;
	context->slots[slot].discarded = true;
	context->slots[slot].discard_event = context->event_count;
	record_event(context, discard_event_for_slot(slot));
	return context->discard_result;
}

static struct fake_slot *next_active_slot(struct fake_context *context)
{
	unsigned int slot;

	for (slot = 0; slot < FAKE_SLOT_COUNT; ++slot) {
		if (context->slots[slot].submitted &&
		    !context->slots[slot].reaped)
			return &context->slots[slot];
	}
	return NULL;
}

static void complete_slot(struct fake_context *context, unsigned int slot,
			  bool cancelled, struct usbdevfs_urb **urb)
{
	struct fake_slot *fake_slot = &context->slots[slot];

	if (cancelled && !fake_slot->discarded)
		context->reap_without_discard = true;
	if (cancelled) {
		fake_slot->urb->status = -ENOENT;
		fake_slot->urb->actual_length = 0;
	} else {
		fake_slot->urb->status = fake_slot->completion_status;
		fake_slot->urb->actual_length = fake_slot->completion_length;
		if (slot == 0 && fake_slot->completion_status == 0)
			memset(fake_slot->urb->buffer, 0xa5,
			       (size_t)fake_slot->completion_length);
	}
	fake_slot->reaped = true;
	fake_slot->reap_event = context->event_count;
	record_event(context, reap_event_for_slot(slot));
	*urb = fake_slot->urb;
}

static enum sep_urb_op_result fake_reap(void *opaque, int file_descriptor,
					struct usbdevfs_urb **urb)
{
	struct fake_context *context = opaque;
	struct fake_slot *slot;
	unsigned int index;

	(void)file_descriptor;
	++context->reap_calls;
	if (context->completion_index < context->completion_available) {
		if (context->completion_index >= FAKE_SLOT_COUNT)
			return SEP_URB_OP_FAILED;
		complete_slot(
			context,
			context->completion_order[context->completion_index], false,
			urb);
		++context->completion_index;
		return SEP_URB_OP_OK;
	}
	slot = next_active_slot(context);
	if (slot == NULL || !slot->discarded)
		return SEP_URB_OP_AGAIN;
	if (context->cancelled_reap_delay > 0) {
		--context->cancelled_reap_delay;
		return SEP_URB_OP_AGAIN;
	}
	index = (unsigned int)(slot - context->slots);
	complete_slot(context, index, true, urb);
	return SEP_URB_OP_OK;
}

static enum sep_urb_op_result fake_wait_ready(void *opaque,
					      int file_descriptor,
					      unsigned int timeout_ms)
{
	struct fake_context *context = opaque;

	(void)file_descriptor;
	++context->wait_calls;
	context->now_ms += timeout_ms > 1 ? 1 : timeout_ms;
	if (context->wait_mode == FAKE_WAIT_TIMEOUT)
		return SEP_URB_OP_AGAIN;
	if (context->wait_mode == FAKE_WAIT_INTERRUPTED)
		return SEP_URB_OP_INTERRUPTED;
	if (context->wait_mode == FAKE_WAIT_FAILED)
		return SEP_URB_OP_FAILED;
	if (context->completion_available < FAKE_SLOT_COUNT)
		++context->completion_available;
	return SEP_URB_OP_OK;
}

static enum sep_urb_op_result fake_monotonic_ms(void *opaque, uint64_t *value)
{
	struct fake_context *context = opaque;

	if (context->clock_fails)
		return SEP_URB_OP_FAILED;
	*value = context->now_ms;
	return SEP_URB_OP_OK;
}

static struct sep_urb_ops fake_ops(struct fake_context *context)
{
	const struct sep_urb_ops ops = {
		.context = context,
		.claim_interface = fake_claim,
		.release_interface = fake_release,
		.submit = fake_submit,
		.discard = fake_discard,
		.reap = fake_reap,
		.wait_ready = fake_wait_ready,
		.monotonic_ms = fake_monotonic_ms,
	};

	return ops;
}

static void fill_output(uint8_t output[SEP_URB_TRANSFER_SIZE])
{
	size_t index;

	for (index = 0; index < SEP_URB_TRANSFER_SIZE; ++index)
		output[index] = (uint8_t)(index & 0xffu);
}

static bool all_bytes_equal(const uint8_t *buffer, size_t length, uint8_t value)
{
	size_t index;

	for (index = 0; index < length; ++index) {
		if (buffer[index] != value)
			return false;
	}
	return true;
}

static void initialize_transport(struct sep_urb_transport *transport,
				 struct fake_context *context)
{
	struct sep_urb_ops ops = fake_ops(context);

	EXPECT_STATUS(SEP_URB_OK,
		      sep_urb_transport_initialize_with_ops(transport, 42, &ops));
	EXPECT_TRUE(context->claim_calls == 1);
	EXPECT_TRUE(context->claimed_interface == SEP_USBFS_INTERFACE);
	EXPECT_TRUE(sep_urb_transport_state(transport) == SEP_URB_STATE_READY);
}

static void destroy_transport(struct sep_urb_transport *transport,
			      struct fake_context *context)
{
	EXPECT_STATUS(SEP_URB_OK, sep_urb_transport_destroy(transport));
	EXPECT_TRUE(context->release_calls == 1);
	EXPECT_TRUE(context->released_interface == SEP_USBFS_INTERFACE);
}

static void reset_fake_exchange(struct fake_context *context)
{
	unsigned int slot;

	context->completion_available = 0;
	context->completion_index = 0;
	context->submit_calls = 0;
	context->wait_calls = 0;
	context->discard_calls = 0;
	context->reap_calls = 0;
	context->fail_submit_call = 0;
	context->wait_mode = FAKE_WAIT_NORMAL;
	context->discard_result = SEP_URB_OP_OK;
	context->reap_without_discard = false;
	for (slot = 0; slot < FAKE_SLOT_COUNT; ++slot) {
		context->slots[slot].urb = NULL;
		context->slots[slot].submitted = false;
		context->slots[slot].discarded = false;
		context->slots[slot].reaped = false;
		context->slots[slot].completion_status = 0;
		context->slots[slot].completion_length =
			(int)SEP_URB_TRANSFER_SIZE;
	}
}

static void test_success_arms_input_before_full_output(void)
{
	struct fake_context context = make_fake_context();
	struct sep_urb_transport transport;
	uint8_t output[SEP_URB_TRANSFER_SIZE];
	uint8_t input[SEP_URB_TRANSFER_SIZE] = { 0 };

	fill_output(output);
	context.expected_output = output;
	initialize_transport(&transport, &context);
	EXPECT_STATUS(SEP_URB_OK,
		      sep_urb_exchange(&transport, output, sizeof(output), input,
				       sizeof(input), 100));
	EXPECT_TRUE(context.submit_calls == 2);
	EXPECT_TRUE(context.submit_shape_valid);
	EXPECT_TRUE(context.events[1] == FAKE_EVENT_SUBMIT_IN);
	EXPECT_TRUE(context.events[2] == FAKE_EVENT_SUBMIT_OUT);
	EXPECT_TRUE(all_bytes_equal(input, sizeof(input), 0xa5));
	EXPECT_TRUE(all_bytes_equal(transport.input.buffer,
				    SEP_URB_TRANSFER_SIZE, 0));
	EXPECT_TRUE(all_bytes_equal(transport.output.buffer,
				    SEP_URB_TRANSFER_SIZE, 0));
	destroy_transport(&transport, &context);
}

static void test_directional_success_uses_only_fixed_sep_endpoint(void)
{
	struct fake_context context = make_fake_context();
	struct sep_urb_transport transport;
	uint8_t output[SEP_URB_TRANSFER_SIZE];
	uint8_t input[SEP_URB_TRANSFER_SIZE] = { 0 };

	fill_output(output);
	context.expected_output = output;
	initialize_transport(&transport, &context);
	EXPECT_STATUS(SEP_URB_OK,
		      sep_urb_send_only(&transport, output, sizeof(output), 100));
	EXPECT_TRUE(context.submit_calls == 1);
	EXPECT_TRUE(context.events[1] == FAKE_EVENT_SUBMIT_OUT);
	EXPECT_TRUE(!context.slots[0].submitted);
	EXPECT_TRUE(context.submit_shape_valid);
	EXPECT_TRUE(all_bytes_equal(transport.output.buffer,
				    SEP_URB_TRANSFER_SIZE, 0));

	reset_fake_exchange(&context);
	context.completion_order[0] = 0;
	EXPECT_STATUS(SEP_URB_OK,
		      sep_urb_receive_only(&transport, input, sizeof(input), 100));
	EXPECT_TRUE(context.submit_calls == 1);
	EXPECT_TRUE(context.events[context.event_count - 2] ==
		    FAKE_EVENT_SUBMIT_IN);
	EXPECT_TRUE(!context.slots[1].submitted);
	EXPECT_TRUE(context.submit_shape_valid);
	EXPECT_TRUE(all_bytes_equal(input, sizeof(input), 0xa5));
	EXPECT_TRUE(all_bytes_equal(transport.input.buffer,
				    SEP_URB_TRANSFER_SIZE, 0));
	destroy_transport(&transport, &context);
}

static void assert_discarded_then_reaped(const struct fake_context *context,
					 unsigned int slot)
{
	EXPECT_TRUE(context->slots[slot].discarded);
	EXPECT_TRUE(context->slots[slot].reaped);
	EXPECT_TRUE(context->slots[slot].discard_event <
		    context->slots[slot].reap_event);
}

static void test_timeout_cancels_reaps_and_allows_reuse(void)
{
	struct fake_context context = make_fake_context();
	struct sep_urb_transport transport;
	uint8_t output[SEP_URB_TRANSFER_SIZE] = { 0 };
	uint8_t input[SEP_URB_TRANSFER_SIZE] = { 0 };

	initialize_transport(&transport, &context);
	context.wait_mode = FAKE_WAIT_TIMEOUT;
	EXPECT_STATUS(SEP_URB_TIMED_OUT,
		      sep_urb_exchange(&transport, output, sizeof(output), input,
				       sizeof(input), 20));
	EXPECT_TRUE(sep_urb_transport_state(&transport) ==
		    SEP_URB_STATE_TIMED_OUT);
	EXPECT_TRUE(context.discard_calls == 2);
	assert_discarded_then_reaped(&context, 0);
	assert_discarded_then_reaped(&context, 1);
	EXPECT_TRUE(!context.reap_without_discard);
	EXPECT_TRUE(all_bytes_equal(transport.output.buffer,
				    SEP_URB_TRANSFER_SIZE, 0));

	reset_fake_exchange(&context);
	EXPECT_STATUS(SEP_URB_OK,
		      sep_urb_exchange(&transport, output, sizeof(output), input,
				       sizeof(input), 20));
	destroy_transport(&transport, &context);
}

static void test_directional_timeout_interruption_and_error_cancel_safely(void)
{
	struct fake_context context = make_fake_context();
	struct sep_urb_transport transport;
	uint8_t buffer[SEP_URB_TRANSFER_SIZE] = { 0 };

	initialize_transport(&transport, &context);
	context.completion_order[0] = 0;
	context.wait_mode = FAKE_WAIT_TIMEOUT;
	EXPECT_STATUS(SEP_URB_TIMED_OUT,
		      sep_urb_receive_only(&transport, buffer, sizeof(buffer), 20));
	EXPECT_TRUE(sep_urb_transport_state(&transport) ==
		    SEP_URB_STATE_TIMED_OUT);
	EXPECT_TRUE(context.discard_calls == 1);
	assert_discarded_then_reaped(&context, 0);
	EXPECT_TRUE(!context.slots[1].submitted);

	reset_fake_exchange(&context);
	context.completion_order[0] = 1;
	context.wait_mode = FAKE_WAIT_INTERRUPTED;
	EXPECT_STATUS(SEP_URB_INTERRUPTED,
		      sep_urb_send_only(&transport, buffer, sizeof(buffer), 20));
	EXPECT_TRUE(sep_urb_transport_state(&transport) ==
		    SEP_URB_STATE_INTERRUPTED);
	EXPECT_TRUE(context.discard_calls == 1);
	assert_discarded_then_reaped(&context, 1);
	EXPECT_TRUE(!context.slots[0].submitted);

	reset_fake_exchange(&context);
	context.completion_order[0] = 0;
	context.wait_mode = FAKE_WAIT_FAILED;
	EXPECT_STATUS(SEP_URB_TRANSFER_FAILED,
		      sep_urb_receive_only(&transport, buffer, sizeof(buffer), 20));
	EXPECT_TRUE(sep_urb_transport_state(&transport) ==
		    SEP_URB_STATE_TRANSFER_ERROR);
	EXPECT_TRUE(context.discard_calls == 1);
	assert_discarded_then_reaped(&context, 0);
	EXPECT_TRUE(!context.reap_without_discard);
	destroy_transport(&transport, &context);
}

static void test_directional_submit_completion_and_cleanup_failures(void)
{
	struct fake_context context = make_fake_context();
	struct sep_urb_transport transport;
	uint8_t buffer[SEP_URB_TRANSFER_SIZE] = { 0 };

	initialize_transport(&transport, &context);
	context.fail_submit_call = 1;
	EXPECT_STATUS(SEP_URB_SUBMIT_FAILED,
		      sep_urb_send_only(&transport, buffer, sizeof(buffer), 20));
	EXPECT_TRUE(context.discard_calls == 0);
	EXPECT_TRUE(sep_urb_transport_state(&transport) ==
		    SEP_URB_STATE_TRANSFER_ERROR);

	reset_fake_exchange(&context);
	context.completion_order[0] = 0;
	context.slots[0].completion_length = (int)SEP_URB_TRANSFER_SIZE - 1;
	EXPECT_STATUS(SEP_URB_SHORT_TRANSFER,
		      sep_urb_receive_only(&transport, buffer, sizeof(buffer), 20));
	EXPECT_TRUE(sep_urb_transport_state(&transport) ==
		    SEP_URB_STATE_TRANSFER_ERROR);

	reset_fake_exchange(&context);
	context.completion_order[0] = 1;
	context.slots[1].completion_status = -EIO;
	EXPECT_STATUS(SEP_URB_TRANSFER_FAILED,
		      sep_urb_send_only(&transport, buffer, sizeof(buffer), 20));
	EXPECT_TRUE(sep_urb_transport_state(&transport) ==
		    SEP_URB_STATE_TRANSFER_ERROR);

	reset_fake_exchange(&context);
	context.completion_order[0] = 0;
	context.wait_mode = FAKE_WAIT_TIMEOUT;
	context.cancelled_reap_delay = 32;
	EXPECT_STATUS(SEP_URB_CLEANUP_FAILED,
		      sep_urb_receive_only(&transport, buffer, sizeof(buffer), 20));
	EXPECT_TRUE(sep_urb_transport_state(&transport) ==
		    SEP_URB_STATE_POISONED);
	EXPECT_STATUS(SEP_URB_INVALID_STATE,
		      sep_urb_send_only(&transport, buffer, sizeof(buffer), 20));
	context.cancelled_reap_delay = 0;
	EXPECT_STATUS(SEP_URB_OK, sep_urb_transport_destroy(&transport));
	EXPECT_TRUE(context.release_calls == 1);
}

static void test_interruption_and_wait_error_cancel_safely(void)
{
	struct fake_context context = make_fake_context();
	struct sep_urb_transport transport;
	uint8_t buffer[SEP_URB_TRANSFER_SIZE] = { 0 };

	initialize_transport(&transport, &context);
	context.wait_mode = FAKE_WAIT_INTERRUPTED;
	EXPECT_STATUS(SEP_URB_INTERRUPTED,
		      sep_urb_exchange(&transport, buffer, sizeof(buffer), buffer,
				       sizeof(buffer), 20));
	EXPECT_TRUE(sep_urb_transport_state(&transport) ==
		    SEP_URB_STATE_INTERRUPTED);
	assert_discarded_then_reaped(&context, 0);
	assert_discarded_then_reaped(&context, 1);

	reset_fake_exchange(&context);
	context.wait_mode = FAKE_WAIT_FAILED;
	EXPECT_STATUS(SEP_URB_TRANSFER_FAILED,
		      sep_urb_exchange(&transport, buffer, sizeof(buffer), buffer,
				       sizeof(buffer), 20));
	EXPECT_TRUE(sep_urb_transport_state(&transport) ==
		    SEP_URB_STATE_TRANSFER_ERROR);
	assert_discarded_then_reaped(&context, 0);
	assert_discarded_then_reaped(&context, 1);
	destroy_transport(&transport, &context);
}

static void test_submit_failure_cleans_only_submitted_urb(void)
{
	struct fake_context context = make_fake_context();
	struct sep_urb_transport transport;
	uint8_t buffer[SEP_URB_TRANSFER_SIZE] = { 0 };

	initialize_transport(&transport, &context);
	context.fail_submit_call = 2;
	EXPECT_STATUS(SEP_URB_SUBMIT_FAILED,
		      sep_urb_exchange(&transport, buffer, sizeof(buffer), buffer,
				       sizeof(buffer), 20));
	EXPECT_TRUE(context.discard_calls == 1);
	assert_discarded_then_reaped(&context, 0);
	EXPECT_TRUE(!context.slots[1].submitted);

	reset_fake_exchange(&context);
	context.fail_submit_call = 1;
	EXPECT_STATUS(SEP_URB_SUBMIT_FAILED,
		      sep_urb_exchange(&transport, buffer, sizeof(buffer), buffer,
				       sizeof(buffer), 20));
	EXPECT_TRUE(context.discard_calls == 0);
	EXPECT_TRUE(context.reap_calls == 0);
	destroy_transport(&transport, &context);
}

static void test_short_and_failed_completion_cancel_peer(void)
{
	struct fake_context context = make_fake_context();
	struct sep_urb_transport transport;
	uint8_t buffer[SEP_URB_TRANSFER_SIZE] = { 0 };

	context.completion_order[0] = 0;
	context.completion_order[1] = 1;
	context.slots[0].completion_length =
		(int)SEP_URB_TRANSFER_SIZE - 1;
	initialize_transport(&transport, &context);
	EXPECT_STATUS(SEP_URB_SHORT_TRANSFER,
		      sep_urb_exchange(&transport, buffer, sizeof(buffer), buffer,
				       sizeof(buffer), 20));
	EXPECT_TRUE(!context.slots[0].discarded);
	assert_discarded_then_reaped(&context, 1);

	reset_fake_exchange(&context);
	context.completion_order[0] = 0;
	context.completion_order[1] = 1;
	context.slots[0].completion_status = -EIO;
	EXPECT_STATUS(SEP_URB_TRANSFER_FAILED,
		      sep_urb_exchange(&transport, buffer, sizeof(buffer), buffer,
				       sizeof(buffer), 20));
	EXPECT_TRUE(!context.slots[0].discarded);
	assert_discarded_then_reaped(&context, 1);
	destroy_transport(&transport, &context);
}

static void test_discard_race_still_requires_exact_reap(void)
{
	struct fake_context context = make_fake_context();
	struct sep_urb_transport transport;
	uint8_t buffer[SEP_URB_TRANSFER_SIZE] = { 0 };

	initialize_transport(&transport, &context);
	context.wait_mode = FAKE_WAIT_TIMEOUT;
	context.discard_result = SEP_URB_OP_NOT_FOUND;
	context.cancelled_reap_delay = 3;
	EXPECT_STATUS(SEP_URB_TIMED_OUT,
		      sep_urb_exchange(&transport, buffer, sizeof(buffer), buffer,
				       sizeof(buffer), 20));
	assert_discarded_then_reaped(&context, 0);
	assert_discarded_then_reaped(&context, 1);
	EXPECT_TRUE(!context.reap_without_discard);
	EXPECT_TRUE(context.wait_calls >= 4);
	destroy_transport(&transport, &context);
}

static void test_unreaped_transport_is_poisoned_and_recoverable(void)
{
	struct fake_context context = make_fake_context();
	struct sep_urb_transport transport;
	uint8_t buffer[SEP_URB_TRANSFER_SIZE] = { 0 };

	initialize_transport(&transport, &context);
	context.wait_mode = FAKE_WAIT_TIMEOUT;
	context.cancelled_reap_delay = 32;
	EXPECT_STATUS(SEP_URB_CLEANUP_FAILED,
		      sep_urb_exchange(&transport, buffer, sizeof(buffer), buffer,
				       sizeof(buffer), 20));
	EXPECT_TRUE(sep_urb_transport_state(&transport) ==
		    SEP_URB_STATE_POISONED);
	EXPECT_TRUE(context.wait_calls == 17);
	EXPECT_STATUS(SEP_URB_INVALID_STATE,
		      sep_urb_exchange(&transport, buffer, sizeof(buffer), buffer,
				       sizeof(buffer), 20));
	EXPECT_TRUE(context.release_calls == 0);

	context.cancelled_reap_delay = 0;
	EXPECT_STATUS(SEP_URB_OK, sep_urb_transport_destroy(&transport));
	EXPECT_TRUE(context.release_calls == 1);
}

static void test_closed_descriptor_allows_terminal_memory_cleanup(void)
{
	struct fake_context context = make_fake_context();
	struct sep_urb_transport transport;
	uint8_t buffer[SEP_URB_TRANSFER_SIZE] = { 0 };

	initialize_transport(&transport, &context);
	context.wait_mode = FAKE_WAIT_TIMEOUT;
	context.cancelled_reap_delay = 32;
	EXPECT_STATUS(SEP_URB_CLEANUP_FAILED,
		      sep_urb_receive_only(&transport, buffer, sizeof(buffer), 20));
	EXPECT_TRUE(transport.input.buffer != NULL &&
		    transport.output.buffer != NULL);
	/* The operation owner has consumed the descriptor before this call. */
	sep_urb_transport_abandon_after_close(&transport);
	EXPECT_TRUE(transport.input.buffer == NULL &&
		    transport.output.buffer == NULL &&
		    sep_urb_transport_state(&transport) ==
			    SEP_URB_STATE_UNINITIALIZED);
}

static void test_claim_release_and_arguments(void)
{
	struct fake_context context = make_fake_context();
	struct sep_urb_transport transport;
	struct sep_urb_ops ops = fake_ops(&context);
	uint8_t buffer[SEP_URB_TRANSFER_SIZE] = { 0 };

	context.claim_fails = true;
	EXPECT_STATUS(SEP_URB_CLAIM_FAILED,
		      sep_urb_transport_initialize_with_ops(&transport, 42, &ops));
	EXPECT_TRUE(context.release_calls == 0);

	context = make_fake_context();
	initialize_transport(&transport, &context);
	EXPECT_STATUS(SEP_URB_INVALID_ARGUMENT,
		      sep_urb_exchange(&transport, buffer, sizeof(buffer) - 1,
				       buffer, sizeof(buffer), 20));
	EXPECT_STATUS(SEP_URB_INVALID_ARGUMENT,
		      sep_urb_exchange(&transport, buffer, sizeof(buffer), buffer,
				       sizeof(buffer), 0));
	EXPECT_STATUS(SEP_URB_INVALID_ARGUMENT,
		      sep_urb_send_only(&transport, buffer, sizeof(buffer) - 1, 20));
	EXPECT_STATUS(SEP_URB_INVALID_ARGUMENT,
		      sep_urb_receive_only(&transport, buffer, sizeof(buffer) - 1,
				       20));
	EXPECT_STATUS(SEP_URB_INVALID_ARGUMENT,
		      sep_urb_send_only(&transport, buffer, sizeof(buffer),
				SEP_URB_MAX_TIMEOUT_MS + 1));
	EXPECT_STATUS(SEP_URB_INVALID_ARGUMENT,
		      sep_urb_receive_only(&transport, buffer, sizeof(buffer), 0));
	EXPECT_TRUE(context.submit_calls == 0);
	context.release_fails = true;
	EXPECT_STATUS(SEP_URB_RELEASE_FAILED,
		      sep_urb_transport_destroy(&transport));
	EXPECT_TRUE(transport.input.buffer == NULL &&
		    transport.output.buffer == NULL &&
		    sep_urb_transport_state(&transport) ==
			    SEP_URB_STATE_UNINITIALIZED);
	EXPECT_STATUS(SEP_URB_OK, sep_urb_transport_destroy(&transport));
	EXPECT_TRUE(context.release_calls == 1);
}

static void test_redacted_status_messages(void)
{
	static const char marker[] = "synthetic-private-marker";
	int status;

	for (status = SEP_URB_OK; status <= SEP_URB_INVALID_STATE; ++status) {
		const char *message =
			sep_urb_status_string((enum sep_urb_status)status);

		EXPECT_TRUE(strstr(message, marker) == NULL);
		EXPECT_TRUE(strchr(message, '/') == NULL);
		EXPECT_TRUE(strstr(message, "0x") == NULL);
	}
}

int main(void)
{
	test_success_arms_input_before_full_output();
	test_directional_success_uses_only_fixed_sep_endpoint();
	test_timeout_cancels_reaps_and_allows_reuse();
	test_directional_timeout_interruption_and_error_cancel_safely();
	test_directional_submit_completion_and_cleanup_failures();
	test_interruption_and_wait_error_cancel_safely();
	test_submit_failure_cleans_only_submitted_urb();
	test_short_and_failed_completion_cancel_peer();
	test_discard_race_still_requires_exact_reap();
	test_unreaped_transport_is_poisoned_and_recoverable();
	test_closed_descriptor_allows_terminal_memory_cleanup();
	test_claim_release_and_arguments();
	test_redacted_status_messages();

	if (failures != 0) {
		fprintf(stderr, "%u sep_urb test(s) failed\n", failures);
		return EXIT_FAILURE;
	}
	puts("sep_urb tests passed");
	return EXIT_SUCCESS;
}

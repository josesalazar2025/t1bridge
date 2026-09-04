#define _POSIX_C_SOURCE 200809L

#include "sep_usbfs.h"

#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/usb/ch9.h>

#define ARRAY_LENGTH(array) (sizeof(array) / sizeof((array)[0]))
#define FAKE_DEVICE_LIMIT 4u
#define FAKE_CONFIG_LIMIT 4u

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
		enum sep_usbfs_status actual_status = (expression);               \
		if (actual_status != (expected)) {                                \
			fprintf(stderr,                                             \
				"%s:%d: expected status %d, received %d\n",       \
				__FILE__, __LINE__, (int)(expected),                \
				(int)actual_status);                                    \
			++failures;                                                 \
		}                                                               \
	} while (0)

static const uint8_t valid_device_descriptor[USB_DT_DEVICE_SIZE] = {
	USB_DT_DEVICE_SIZE, USB_DT_DEVICE, 0x00, 0x02, 0xef, 0x02, 0x01, 0x40,
	0xac, 0x05, 0x00, 0x86, 0x00, 0x01, 0x01, 0x02, 0x00, 0x01,
};

static const uint8_t valid_configuration[] = {
	USB_DT_CONFIG_SIZE, USB_DT_CONFIG, 32, 0, 1, SEP_USBFS_CONFIGURATION,
	0, 0x80, 50,
	USB_DT_INTERFACE_SIZE, USB_DT_INTERFACE, SEP_USBFS_INTERFACE, 0, 2,
	0xff, 0, 0, 0,
	USB_DT_ENDPOINT_SIZE, USB_DT_ENDPOINT, SEP_USBFS_BULK_OUT,
	USB_ENDPOINT_XFER_BULK, 0x00, 0x02, 0,
	USB_DT_ENDPOINT_SIZE, USB_DT_ENDPOINT, SEP_USBFS_BULK_IN,
	USB_ENDPOINT_XFER_BULK, 0x00, 0x02, 0,
};

struct fake_device {
	const char *path;
	uint8_t device[USB_DT_DEVICE_SIZE];
	const uint8_t *configurations[FAKE_CONFIG_LIMIT];
	size_t configuration_lengths[FAKE_CONFIG_LIMIT];
	size_t configuration_count;
	uint8_t active_configuration;
	bool open_fails;
	bool control_fails;
	bool closed;
};

struct fake_context {
	struct fake_device devices[FAKE_DEVICE_LIMIT];
	size_t device_count;
	bool enumeration_fails;
	bool report_overflow;
	bool observed_safe_open_flags;
	unsigned int close_count;
	uint64_t now_ms;
	unsigned int control_advance_ms;
	unsigned int control_count;
	unsigned int control_timeouts[16];
	bool clock_fails;
};

static void set_u16_le(uint8_t *bytes, uint16_t value)
{
	bytes[0] = (uint8_t)value;
	bytes[1] = (uint8_t)(value >> 8);
}

static struct fake_device make_valid_device(const char *path)
{
	struct fake_device device = { 0 };

	device.path = path;
	memcpy(device.device, valid_device_descriptor, sizeof(device.device));
	device.configurations[0] = valid_configuration;
	device.configuration_lengths[0] = sizeof(valid_configuration);
	device.configuration_count = 1;
	device.active_configuration = SEP_USBFS_CONFIGURATION;
	return device;
}

static int fake_list_candidates(void *opaque,
				struct sep_usbfs_candidate *candidates,
				size_t capacity, size_t *count)
{
	struct fake_context *context = opaque;
	size_t index;

	if (context->enumeration_fails)
		return -1;
	if (context->report_overflow) {
		*count = capacity + 1;
		return 0;
	}
	if (context->device_count > capacity)
		return -1;
	for (index = 0; index < context->device_count; ++index) {
		int written = snprintf(candidates[index].path,
				       sizeof(candidates[index].path), "%s",
				       context->devices[index].path);

		if (written < 0 ||
		    (size_t)written >= sizeof(candidates[index].path))
			return -1;
	}
	*count = context->device_count;
	return 0;
}

static int fake_open_path(void *opaque, const char *path, int flags)
{
	struct fake_context *context = opaque;
	size_t index;

	if ((flags & (O_RDWR | O_CLOEXEC | O_NOFOLLOW)) ==
	    (O_RDWR | O_CLOEXEC | O_NOFOLLOW))
		context->observed_safe_open_flags = true;
	for (index = 0; index < context->device_count; ++index) {
		if (strcmp(path, context->devices[index].path) == 0)
			return context->devices[index].open_fails ? -1 :
			       100 + (int)index;
	}
	return -1;
}

static int fake_control(void *opaque, int file_descriptor,
			struct usbdevfs_ctrltransfer *transfer)
{
	struct fake_context *context = opaque;
	int raw_index = file_descriptor - 100;
	struct fake_device *device;
	size_t requested;
	size_t available;
	const uint8_t *source;
	unsigned int descriptor_type;
	unsigned int descriptor_index;

	if (context->control_count < ARRAY_LENGTH(context->control_timeouts))
		context->control_timeouts[context->control_count] = transfer->timeout;
	++context->control_count;
	context->now_ms += context->control_advance_ms;

	if (raw_index < 0 || (size_t)raw_index >= context->device_count)
		return -1;
	device = &context->devices[(size_t)raw_index];
	if (device->control_fails)
		return -1;
	if (transfer->bRequest == USB_REQ_GET_CONFIGURATION) {
		if (transfer->wLength != 1)
			return -1;
		*(uint8_t *)transfer->data = device->active_configuration;
		return 1;
	}
	if (transfer->bRequest != USB_REQ_GET_DESCRIPTOR)
		return -1;
	descriptor_type = transfer->wValue >> 8;
	descriptor_index = transfer->wValue & 0xffu;
	if (descriptor_type == USB_DT_DEVICE) {
		source = device->device;
		available = sizeof(device->device);
	} else if (descriptor_type == USB_DT_CONFIG &&
		   descriptor_index < device->configuration_count) {
		source = device->configurations[descriptor_index];
		available = device->configuration_lengths[descriptor_index];
	} else {
		return -1;
	}
	requested = transfer->wLength;
	if (requested > available)
		requested = available;
	memcpy(transfer->data, source, requested);
	return (int)requested;
}

static int fake_close_fd(void *opaque, int file_descriptor)
{
	struct fake_context *context = opaque;
	int raw_index = file_descriptor - 100;

	if (raw_index < 0 || (size_t)raw_index >= context->device_count)
		return -1;
	context->devices[(size_t)raw_index].closed = true;
	++context->close_count;
	return 0;
}

static int fake_monotonic_ms(void *opaque, uint64_t *value)
{
	struct fake_context *context = opaque;

	if (context->clock_fails)
		return -1;
	*value = context->now_ms;
	return 0;
}

static struct sep_usbfs_ops fake_ops(struct fake_context *context)
{
	const struct sep_usbfs_ops ops = {
		.context = context,
		.list_candidates = fake_list_candidates,
		.open_path = fake_open_path,
		.control = fake_control,
		.close_fd = fake_close_fd,
		.monotonic_ms = fake_monotonic_ms,
	};

	return ops;
}

static void test_valid_descriptor_tree(void)
{
	EXPECT_STATUS(SEP_USBFS_OK,
		      sep_usbfs_validate_descriptors(
			      valid_device_descriptor,
			      sizeof(valid_device_descriptor), valid_configuration,
			      sizeof(valid_configuration)));
}

static void test_device_identity_and_type(void)
{
	uint8_t device[sizeof(valid_device_descriptor)];

	memcpy(device, valid_device_descriptor, sizeof(device));
	device[8] ^= 1;
	EXPECT_STATUS(SEP_USBFS_NOT_TARGET,
		      sep_usbfs_validate_descriptors(
			      device, sizeof(device), valid_configuration,
			      sizeof(valid_configuration)));
	memcpy(device, valid_device_descriptor, sizeof(device));
	device[1] = USB_DT_CONFIG;
	EXPECT_STATUS(SEP_USBFS_DESCRIPTOR_INVALID,
		      sep_usbfs_validate_descriptors(
			      device, sizeof(device), valid_configuration,
			      sizeof(valid_configuration)));
	EXPECT_STATUS(SEP_USBFS_DESCRIPTOR_INVALID,
		      sep_usbfs_validate_descriptors(
			      valid_device_descriptor,
			      sizeof(valid_device_descriptor) - 1,
			      valid_configuration,
			      sizeof(valid_configuration)));
}

static void test_malformed_descriptor_lengths_and_types(void)
{
	uint8_t configuration[sizeof(valid_configuration)];

	memcpy(configuration, valid_configuration, sizeof(configuration));
	configuration[0] = 0;
	EXPECT_STATUS(SEP_USBFS_DESCRIPTOR_INVALID,
		      sep_usbfs_validate_descriptors(
			      valid_device_descriptor,
			      sizeof(valid_device_descriptor), configuration,
			      sizeof(configuration)));

	memcpy(configuration, valid_configuration, sizeof(configuration));
	configuration[1] = USB_DT_INTERFACE;
	EXPECT_STATUS(SEP_USBFS_DESCRIPTOR_INVALID,
		      sep_usbfs_validate_descriptors(
			      valid_device_descriptor,
			      sizeof(valid_device_descriptor), configuration,
			      sizeof(configuration)));

	memcpy(configuration, valid_configuration, sizeof(configuration));
	set_u16_le(configuration + 2, (uint16_t)(sizeof(configuration) - 1));
	EXPECT_STATUS(SEP_USBFS_DESCRIPTOR_INVALID,
		      sep_usbfs_validate_descriptors(
			      valid_device_descriptor,
			      sizeof(valid_device_descriptor), configuration,
			      sizeof(configuration)));

	memcpy(configuration, valid_configuration, sizeof(configuration));
	configuration[USB_DT_CONFIG_SIZE] = 8;
	EXPECT_STATUS(SEP_USBFS_DESCRIPTOR_INVALID,
		      sep_usbfs_validate_descriptors(
			      valid_device_descriptor,
			      sizeof(valid_device_descriptor), configuration,
			      sizeof(configuration)));

	memcpy(configuration, valid_configuration, sizeof(configuration));
	configuration[USB_DT_CONFIG_SIZE + USB_DT_INTERFACE_SIZE] = 6;
	EXPECT_STATUS(SEP_USBFS_DESCRIPTOR_INVALID,
		      sep_usbfs_validate_descriptors(
			      valid_device_descriptor,
			      sizeof(valid_device_descriptor), configuration,
			      sizeof(configuration)));

	memcpy(configuration, valid_configuration, sizeof(configuration));
	configuration[USB_DT_CONFIG_SIZE + USB_DT_INTERFACE_SIZE] = 100;
	EXPECT_STATUS(SEP_USBFS_DESCRIPTOR_INVALID,
		      sep_usbfs_validate_descriptors(
			      valid_device_descriptor,
			      sizeof(valid_device_descriptor), configuration,
			      sizeof(configuration)));
}

static void test_configuration_interface_and_endpoints(void)
{
	uint8_t configuration[sizeof(valid_configuration)];
	const size_t interface_offset = USB_DT_CONFIG_SIZE;
	const size_t out_offset = interface_offset + USB_DT_INTERFACE_SIZE;
	const size_t in_offset = out_offset + USB_DT_ENDPOINT_SIZE;

	memcpy(configuration, valid_configuration, sizeof(configuration));
	configuration[5] = 1;
	EXPECT_STATUS(SEP_USBFS_CONFIGURATION_MISMATCH,
		      sep_usbfs_validate_descriptors(
			      valid_device_descriptor,
			      sizeof(valid_device_descriptor), configuration,
			      sizeof(configuration)));

	memcpy(configuration, valid_configuration, sizeof(configuration));
	configuration[interface_offset + 2] = SEP_USBFS_INTERFACE - 1;
	EXPECT_STATUS(SEP_USBFS_INTERFACE_MISMATCH,
		      sep_usbfs_validate_descriptors(
			      valid_device_descriptor,
			      sizeof(valid_device_descriptor), configuration,
			      sizeof(configuration)));

	memcpy(configuration, valid_configuration, sizeof(configuration));
	configuration[interface_offset + 3] = 1;
	EXPECT_STATUS(SEP_USBFS_INTERFACE_MISMATCH,
		      sep_usbfs_validate_descriptors(
			      valid_device_descriptor,
			      sizeof(valid_device_descriptor), configuration,
			      sizeof(configuration)));

	memcpy(configuration, valid_configuration, sizeof(configuration));
	configuration[interface_offset + 4] = 3;
	EXPECT_STATUS(SEP_USBFS_INTERFACE_MISMATCH,
		      sep_usbfs_validate_descriptors(
			      valid_device_descriptor,
			      sizeof(valid_device_descriptor), configuration,
			      sizeof(configuration)));

	memcpy(configuration, valid_configuration, sizeof(configuration));
	configuration[out_offset + 2] ^= 1;
	EXPECT_STATUS(SEP_USBFS_INTERFACE_MISMATCH,
		      sep_usbfs_validate_descriptors(
			      valid_device_descriptor,
			      sizeof(valid_device_descriptor), configuration,
			      sizeof(configuration)));

	memcpy(configuration, valid_configuration, sizeof(configuration));
	configuration[in_offset + 3] = USB_ENDPOINT_XFER_INT;
	EXPECT_STATUS(SEP_USBFS_INTERFACE_MISMATCH,
		      sep_usbfs_validate_descriptors(
			      valid_device_descriptor,
			      sizeof(valid_device_descriptor), configuration,
			      sizeof(configuration)));

	memcpy(configuration, valid_configuration, sizeof(configuration));
	configuration[in_offset + 2] = SEP_USBFS_BULK_OUT;
	EXPECT_STATUS(SEP_USBFS_INTERFACE_MISMATCH,
		      sep_usbfs_validate_descriptors(
			      valid_device_descriptor,
			      sizeof(valid_device_descriptor), configuration,
			      sizeof(configuration)));
}

static void test_unique_open_revalidates_and_selects_configuration_value(void)
{
	static const uint8_t other_configuration[] = {
		USB_DT_CONFIG_SIZE, USB_DT_CONFIG, USB_DT_CONFIG_SIZE, 0, 0, 1,
		0, 0x80, 50,
	};
	struct fake_context context = { 0 };
	struct sep_usbfs_ops ops;
	int file_descriptor = -1;

	context.devices[0] = make_valid_device("synthetic-candidate-alpha");
	context.devices[0].device[17] = 2;
	context.devices[0].configurations[0] = other_configuration;
	context.devices[0].configuration_lengths[0] =
		sizeof(other_configuration);
	context.devices[0].configurations[1] = valid_configuration;
	context.devices[0].configuration_lengths[1] =
		sizeof(valid_configuration);
	context.devices[0].configuration_count = 2;
	context.device_count = 1;
	ops = fake_ops(&context);

	EXPECT_STATUS(SEP_USBFS_OK,
		      sep_usbfs_open_unique_with_ops(&ops, &file_descriptor));
	EXPECT_TRUE(file_descriptor == 100);
	EXPECT_TRUE(context.observed_safe_open_flags);
	EXPECT_TRUE(context.close_count == 0);
	EXPECT_TRUE(fake_close_fd(&context, file_descriptor) == 0);
}

static void test_zero_and_multiple_matches_are_rejected(void)
{
	struct fake_context empty = { 0 };
	struct fake_context ambiguous = { 0 };
	struct sep_usbfs_ops ops;
	int file_descriptor = 9;

	ops = fake_ops(&empty);
	EXPECT_STATUS(SEP_USBFS_DEVICE_NOT_FOUND,
		      sep_usbfs_open_unique_with_ops(&ops, &file_descriptor));
	EXPECT_TRUE(file_descriptor == -1);

	ambiguous.devices[0] = make_valid_device("synthetic-candidate-alpha");
	ambiguous.devices[1] = make_valid_device("synthetic-candidate-beta");
	ambiguous.device_count = 2;
	ops = fake_ops(&ambiguous);
	EXPECT_STATUS(SEP_USBFS_DEVICE_AMBIGUOUS,
		      sep_usbfs_open_unique_with_ops(&ops, &file_descriptor));
	EXPECT_TRUE(file_descriptor == -1);
	EXPECT_TRUE(ambiguous.close_count == 2);
	EXPECT_TRUE(ambiguous.devices[0].closed);
	EXPECT_TRUE(ambiguous.devices[1].closed);
}

static void test_opened_identity_and_active_configuration_are_revalidated(void)
{
	struct fake_context context = { 0 };
	struct sep_usbfs_ops ops;
	int file_descriptor = -1;

	context.devices[0] = make_valid_device("synthetic-candidate-alpha");
	context.devices[0].device[10] ^= 1;
	context.device_count = 1;
	ops = fake_ops(&context);
	EXPECT_STATUS(SEP_USBFS_DEVICE_NOT_FOUND,
		      sep_usbfs_open_unique_with_ops(&ops, &file_descriptor));
	EXPECT_TRUE(context.close_count == 1);

	context = (struct fake_context){ 0 };
	context.devices[0] = make_valid_device("synthetic-candidate-alpha");
	context.devices[0].active_configuration = 1;
	context.device_count = 1;
	ops = fake_ops(&context);
	EXPECT_STATUS(SEP_USBFS_CONFIGURATION_MISMATCH,
		      sep_usbfs_open_unique_with_ops(&ops, &file_descriptor));
	EXPECT_TRUE(context.close_count == 1);
}

static void test_discovery_and_control_failures_close_safely(void)
{
	struct fake_context context = { 0 };
	struct sep_usbfs_ops ops;
	int file_descriptor = -1;

	context.enumeration_fails = true;
	ops = fake_ops(&context);
	EXPECT_STATUS(SEP_USBFS_ENUMERATION_FAILED,
		      sep_usbfs_open_unique_with_ops(&ops, &file_descriptor));

	context = (struct fake_context){ 0 };
	context.report_overflow = true;
	ops = fake_ops(&context);
	EXPECT_STATUS(SEP_USBFS_CANDIDATE_LIMIT,
		      sep_usbfs_open_unique_with_ops(&ops, &file_descriptor));

	context = (struct fake_context){ 0 };
	context.devices[0] = make_valid_device("synthetic-candidate-alpha");
	context.devices[0].open_fails = true;
	context.device_count = 1;
	ops = fake_ops(&context);
	EXPECT_STATUS(SEP_USBFS_DEVICE_ACCESS_FAILED,
		      sep_usbfs_open_unique_with_ops(&ops, &file_descriptor));

	context = (struct fake_context){ 0 };
	context.devices[0] = make_valid_device("synthetic-candidate-alpha");
	context.devices[0].control_fails = true;
	context.device_count = 1;
	ops = fake_ops(&context);
	EXPECT_STATUS(SEP_USBFS_CONTROL_FAILED,
		      sep_usbfs_open_unique_with_ops(&ops, &file_descriptor));
	EXPECT_TRUE(context.close_count == 1);
}

static void test_malformed_target_is_rejected_during_open(void)
{
	uint8_t malformed[sizeof(valid_configuration)];
	struct fake_context context = { 0 };
	struct sep_usbfs_ops ops;
	int file_descriptor = -1;

	memcpy(malformed, valid_configuration, sizeof(malformed));
	malformed[USB_DT_CONFIG_SIZE] = 0;
	context.devices[0] = make_valid_device("synthetic-candidate-alpha");
	context.devices[0].configurations[0] = malformed;
	context.devices[0].configuration_lengths[0] = sizeof(malformed);
	context.device_count = 1;
	ops = fake_ops(&context);
	EXPECT_STATUS(SEP_USBFS_DESCRIPTOR_INVALID,
		      sep_usbfs_open_unique_with_ops(&ops, &file_descriptor));
	EXPECT_TRUE(context.close_count == 1);
}

static void test_bounded_discovery_shares_one_deadline(void)
{
	struct fake_context context = { 0 };
	struct sep_usbfs_ops ops;
	int file_descriptor = -1;

	context.devices[0] = make_valid_device("synthetic-candidate-alpha");
	context.device_count = 1;
	context.now_ms = 100;
	context.control_advance_ms = 6;
	ops = fake_ops(&context);
	EXPECT_STATUS(SEP_USBFS_TIMED_OUT,
		      sep_usbfs_open_unique_bounded_with_ops(
			      &ops, 10, &file_descriptor));
	EXPECT_TRUE(file_descriptor == -1 && context.close_count == 1 &&
		    context.control_count == 2);
	EXPECT_TRUE(context.control_timeouts[0] == 10 &&
		    context.control_timeouts[1] == 4);

	context = (struct fake_context){ 0 };
	context.devices[0] = make_valid_device("synthetic-candidate-alpha");
	context.device_count = 1;
	ops = fake_ops(&context);
	EXPECT_STATUS(SEP_USBFS_OK,
		      sep_usbfs_open_unique_bounded_with_ops(
			      &ops, 5000, &file_descriptor));
	EXPECT_TRUE(context.control_count == 4 &&
		    context.control_timeouts[0] == 1000 &&
		    context.control_timeouts[3] == 1000);
	EXPECT_TRUE(fake_close_fd(&context, file_descriptor) == 0);

	context = (struct fake_context){ .clock_fails = true };
	ops = fake_ops(&context);
	EXPECT_STATUS(SEP_USBFS_CLOCK_FAILED,
		      sep_usbfs_open_unique_bounded_with_ops(
			      &ops, 10, &file_descriptor));
}

static void test_errors_are_redacted(void)
{
	static const char private_marker[] = "synthetic-candidate-alpha";
	int status;

	for (status = SEP_USBFS_OK; status <= SEP_USBFS_CLOCK_FAILED;
	     ++status) {
		const char *message =
			sep_usbfs_status_string((enum sep_usbfs_status)status);

		EXPECT_TRUE(strstr(message, private_marker) == NULL);
		EXPECT_TRUE(strchr(message, '/') == NULL);
	}
	EXPECT_TRUE(strstr(sep_usbfs_status_string((enum sep_usbfs_status)999),
			   private_marker) == NULL);
}

int main(void)
{
	test_valid_descriptor_tree();
	test_device_identity_and_type();
	test_malformed_descriptor_lengths_and_types();
	test_configuration_interface_and_endpoints();
	test_unique_open_revalidates_and_selects_configuration_value();
	test_zero_and_multiple_matches_are_rejected();
	test_opened_identity_and_active_configuration_are_revalidated();
	test_discovery_and_control_failures_close_safely();
	test_malformed_target_is_rejected_during_open();
	test_bounded_discovery_shares_one_deadline();
	test_errors_are_redacted();

	if (failures != 0) {
		fprintf(stderr, "%u sep_usbfs test(s) failed\n", failures);
		return EXIT_FAILURE;
	}
	puts("sep_usbfs tests passed");
	return EXIT_SUCCESS;
}

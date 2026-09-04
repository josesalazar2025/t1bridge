#define _POSIX_C_SOURCE 200809L

#include "sep_usbfs.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>

#include <linux/usb/ch9.h>

#define SEP_USBFS_CONTROL_TIMEOUT_MS 1000u
#define SEP_USBFS_SYSFS_ROOT "/sys/bus/usb/devices"
#define SEP_USBFS_MAX_CONFIGURATIONS 16u

static uint16_t get_u16_le(const uint8_t *bytes)
{
	return (uint16_t)bytes[0] | (uint16_t)((uint16_t)bytes[1] << 8);
}

static bool is_expected_device(const uint8_t *descriptor, size_t length)
{
	return length >= USB_DT_DEVICE_SIZE &&
	       descriptor[0] == USB_DT_DEVICE_SIZE &&
	       descriptor[1] == USB_DT_DEVICE &&
	       get_u16_le(descriptor + 8) == SEP_USBFS_VENDOR_ID &&
	       get_u16_le(descriptor + 10) == SEP_USBFS_PRODUCT_ID;
}

enum sep_usbfs_status sep_usbfs_validate_descriptors(
	const uint8_t *device_descriptor, size_t device_length,
	const uint8_t *configuration_descriptor, size_t configuration_length)
{
	size_t offset;
	unsigned int interface_count = 0;
	bool in_sep_interface = false;
	bool found_bulk_out = false;
	bool found_bulk_in = false;

	if (device_descriptor == NULL || configuration_descriptor == NULL)
		return SEP_USBFS_INVALID_ARGUMENT;
	if (!is_expected_device(device_descriptor, device_length)) {
		if (device_length < USB_DT_DEVICE_SIZE || device_descriptor[0] !=
							 USB_DT_DEVICE_SIZE ||
		    device_descriptor[1] != USB_DT_DEVICE)
			return SEP_USBFS_DESCRIPTOR_INVALID;
		return SEP_USBFS_NOT_TARGET;
	}
	if (configuration_length < USB_DT_CONFIG_SIZE ||
	    configuration_length > SEP_USBFS_MAX_CONFIGURATION_BYTES ||
	    configuration_descriptor[0] != USB_DT_CONFIG_SIZE ||
	    configuration_descriptor[1] != USB_DT_CONFIG ||
	    get_u16_le(configuration_descriptor + 2) != configuration_length)
		return SEP_USBFS_DESCRIPTOR_INVALID;
	if (configuration_descriptor[5] != SEP_USBFS_CONFIGURATION)
		return SEP_USBFS_CONFIGURATION_MISMATCH;

	offset = 0;
	while (offset < configuration_length) {
		const uint8_t *descriptor;
		size_t descriptor_length;
		uint8_t descriptor_type;

		if (configuration_length - offset < 2)
			return SEP_USBFS_DESCRIPTOR_INVALID;
		descriptor = configuration_descriptor + offset;
		descriptor_length = descriptor[0];
		descriptor_type = descriptor[1];
		if (descriptor_length < 2 ||
		    descriptor_length > configuration_length - offset)
			return SEP_USBFS_DESCRIPTOR_INVALID;

		switch (descriptor_type) {
		case USB_DT_CONFIG:
			if (offset != 0 || descriptor_length < USB_DT_CONFIG_SIZE)
				return SEP_USBFS_DESCRIPTOR_INVALID;
			break;
		case USB_DT_INTERFACE:
			if (descriptor_length < USB_DT_INTERFACE_SIZE)
				return SEP_USBFS_DESCRIPTOR_INVALID;
			in_sep_interface = descriptor[2] == SEP_USBFS_INTERFACE;
			if (in_sep_interface) {
				/* Alternate or extra endpoints make selection ambiguous. */
				if (descriptor[3] != 0 || descriptor[4] != 2 ||
				    ++interface_count != 1)
					return SEP_USBFS_INTERFACE_MISMATCH;
			}
			break;
		case USB_DT_ENDPOINT:
			if (descriptor_length < USB_DT_ENDPOINT_SIZE)
				return SEP_USBFS_DESCRIPTOR_INVALID;
			if (!in_sep_interface)
				break;
			if (descriptor[2] == SEP_USBFS_BULK_OUT) {
				if ((descriptor[3] & USB_ENDPOINT_XFERTYPE_MASK) !=
					    USB_ENDPOINT_XFER_BULK ||
				    found_bulk_out)
					return SEP_USBFS_INTERFACE_MISMATCH;
				found_bulk_out = true;
			} else if (descriptor[2] == SEP_USBFS_BULK_IN) {
				if ((descriptor[3] & USB_ENDPOINT_XFERTYPE_MASK) !=
					    USB_ENDPOINT_XFER_BULK ||
				    found_bulk_in)
					return SEP_USBFS_INTERFACE_MISMATCH;
				found_bulk_in = true;
			}
			break;
		default:
			break;
		}
		offset += descriptor_length;
	}

	if (interface_count != 1 || !found_bulk_out || !found_bulk_in)
		return SEP_USBFS_INTERFACE_MISMATCH;
	return SEP_USBFS_OK;
}

static void initialize_control(struct usbdevfs_ctrltransfer *transfer,
			       uint8_t request, uint16_t value, void *data,
			       uint16_t length)
{
	memset(transfer, 0, sizeof(*transfer));
	transfer->bRequestType = USB_DIR_IN | USB_TYPE_STANDARD | USB_RECIP_DEVICE;
	transfer->bRequest = request;
	transfer->wValue = value;
	transfer->wLength = length;
	transfer->data = data;
}

struct sep_usbfs_deadline {
	const struct sep_usbfs_ops *ops;
	uint64_t value_ms;
	bool bounded;
};

static enum sep_usbfs_status control_timeout(
	const struct sep_usbfs_deadline *deadline, unsigned int *timeout_ms)
{
	uint64_t now;
	uint64_t remaining;

	if (!deadline->bounded) {
		*timeout_ms = SEP_USBFS_CONTROL_TIMEOUT_MS;
		return SEP_USBFS_OK;
	}
	if (deadline->ops->monotonic_ms(deadline->ops->context, &now) != 0)
		return SEP_USBFS_CLOCK_FAILED;
	if (now >= deadline->value_ms)
		return SEP_USBFS_TIMED_OUT;
	remaining = deadline->value_ms - now;
	if (remaining > SEP_USBFS_CONTROL_TIMEOUT_MS)
		remaining = SEP_USBFS_CONTROL_TIMEOUT_MS;
	*timeout_ms = (unsigned int)remaining;
	return SEP_USBFS_OK;
}

static enum sep_usbfs_status run_control(
	const struct sep_usbfs_deadline *deadline, int file_descriptor,
	struct usbdevfs_ctrltransfer *transfer, int expected_length)
{
	unsigned int timeout_ms;
	int result;
	enum sep_usbfs_status status = control_timeout(deadline, &timeout_ms);

	if (status != SEP_USBFS_OK)
		return status;
	transfer->timeout = timeout_ms;
	result = deadline->ops->control(deadline->ops->context, file_descriptor,
					transfer);
	if (result == expected_length)
		return SEP_USBFS_OK;
	status = control_timeout(deadline, &timeout_ms);
	return status == SEP_USBFS_OK ? SEP_USBFS_CONTROL_FAILED : status;
}

static enum sep_usbfs_status inspect_open_device(
	const struct sep_usbfs_deadline *deadline, int file_descriptor,
	bool *target)
{
	uint8_t device[USB_DT_DEVICE_SIZE];
	uint8_t active_configuration = 0;
	struct usbdevfs_ctrltransfer transfer;
	uint8_t configuration_count;
	unsigned int matching_configurations = 0;
	unsigned int index;
	enum sep_usbfs_status control_status;

	*target = false;
	initialize_control(&transfer, USB_REQ_GET_DESCRIPTOR,
			   (uint16_t)(USB_DT_DEVICE << 8), device,
			   (uint16_t)sizeof(device));
	control_status = run_control(deadline, file_descriptor, &transfer,
				     (int)sizeof(device));
	if (control_status != SEP_USBFS_OK)
		return control_status;
	if (!is_expected_device(device, sizeof(device))) {
		if (device[0] != USB_DT_DEVICE_SIZE || device[1] != USB_DT_DEVICE)
			return SEP_USBFS_DESCRIPTOR_INVALID;
		return SEP_USBFS_NOT_TARGET;
	}
	*target = true;
	configuration_count = device[17];
	if (configuration_count == 0 ||
	    configuration_count > SEP_USBFS_MAX_CONFIGURATIONS)
		return SEP_USBFS_DESCRIPTOR_INVALID;

	initialize_control(&transfer, USB_REQ_GET_CONFIGURATION, 0,
			   &active_configuration, 1);
	control_status = run_control(deadline, file_descriptor, &transfer, 1);
	if (control_status != SEP_USBFS_OK)
		return control_status;
	if (active_configuration != SEP_USBFS_CONFIGURATION)
		return SEP_USBFS_CONFIGURATION_MISMATCH;

	for (index = 0; index < configuration_count; ++index) {
		uint8_t header[USB_DT_CONFIG_SIZE];
		uint8_t *configuration;
		uint16_t total_length;
		enum sep_usbfs_status status;

		initialize_control(&transfer, USB_REQ_GET_DESCRIPTOR,
				   (uint16_t)((USB_DT_CONFIG << 8) | index),
				   header, (uint16_t)sizeof(header));
		control_status = run_control(deadline, file_descriptor, &transfer,
					     (int)sizeof(header));
		if (control_status != SEP_USBFS_OK)
			return control_status;
		if (header[0] != USB_DT_CONFIG_SIZE ||
		    header[1] != USB_DT_CONFIG)
			return SEP_USBFS_DESCRIPTOR_INVALID;
		total_length = get_u16_le(header + 2);
		if (total_length < USB_DT_CONFIG_SIZE)
			return SEP_USBFS_DESCRIPTOR_INVALID;
		configuration = malloc(total_length);
		if (configuration == NULL)
			return SEP_USBFS_DEVICE_ACCESS_FAILED;
		initialize_control(&transfer, USB_REQ_GET_DESCRIPTOR,
				   (uint16_t)((USB_DT_CONFIG << 8) | index),
				   configuration, total_length);
		control_status = run_control(deadline, file_descriptor, &transfer,
					     total_length);
		if (control_status != SEP_USBFS_OK) {
			free(configuration);
			return control_status;
		}
		if (configuration[5] != SEP_USBFS_CONFIGURATION) {
			free(configuration);
			continue;
		}
		++matching_configurations;
		status = sep_usbfs_validate_descriptors(
			device, sizeof(device), configuration, total_length);
		free(configuration);
		if (status != SEP_USBFS_OK)
			return status;
	}
	if (matching_configurations != 1)
		return SEP_USBFS_CONFIGURATION_MISMATCH;
	return SEP_USBFS_OK;
}

static enum sep_usbfs_status open_unique(
	const struct sep_usbfs_ops *ops, struct sep_usbfs_deadline *deadline,
	int *file_descriptor)
{
	struct sep_usbfs_candidate candidates[SEP_USBFS_MAX_CANDIDATES];
	size_t count = 0;
	size_t index;
	int matched_descriptor = -1;

	if (ops == NULL || file_descriptor == NULL ||
	    ops->list_candidates == NULL || ops->open_path == NULL ||
	    ops->control == NULL || ops->close_fd == NULL)
		return SEP_USBFS_INVALID_ARGUMENT;
	*file_descriptor = -1;
	if (ops->list_candidates(ops->context, candidates,
				 SEP_USBFS_MAX_CANDIDATES, &count) != 0)
		return SEP_USBFS_ENUMERATION_FAILED;
	if (count > SEP_USBFS_MAX_CANDIDATES)
		return SEP_USBFS_CANDIDATE_LIMIT;

	for (index = 0; index < count; ++index) {
		bool target = false;
		enum sep_usbfs_status status;
		int current_descriptor;

		if (memchr(candidates[index].path, '\0',
			   SEP_USBFS_PATH_CAPACITY) == NULL) {
			if (matched_descriptor >= 0)
				(void)ops->close_fd(ops->context, matched_descriptor);
			return SEP_USBFS_ENUMERATION_FAILED;
		}
		current_descriptor = ops->open_path(
			ops->context, candidates[index].path,
			O_RDWR | O_CLOEXEC | O_NOFOLLOW);
		if (current_descriptor < 0) {
			if (matched_descriptor >= 0)
				(void)ops->close_fd(ops->context, matched_descriptor);
			return SEP_USBFS_DEVICE_ACCESS_FAILED;
		}
		status = inspect_open_device(deadline, current_descriptor, &target);
		if (status == SEP_USBFS_NOT_TARGET) {
			(void)ops->close_fd(ops->context, current_descriptor);
			continue;
		}
		if (status != SEP_USBFS_OK) {
			(void)ops->close_fd(ops->context, current_descriptor);
			if (matched_descriptor >= 0)
				(void)ops->close_fd(ops->context, matched_descriptor);
			return status;
		}
		if (!target) {
			(void)ops->close_fd(ops->context, current_descriptor);
			if (matched_descriptor >= 0)
				(void)ops->close_fd(ops->context, matched_descriptor);
			return SEP_USBFS_DESCRIPTOR_INVALID;
		}
		if (matched_descriptor >= 0) {
			(void)ops->close_fd(ops->context, current_descriptor);
			(void)ops->close_fd(ops->context, matched_descriptor);
			return SEP_USBFS_DEVICE_AMBIGUOUS;
		}
		matched_descriptor = current_descriptor;
	}
	if (matched_descriptor < 0)
		return SEP_USBFS_DEVICE_NOT_FOUND;
	*file_descriptor = matched_descriptor;
	return SEP_USBFS_OK;
}

enum sep_usbfs_status sep_usbfs_open_unique_with_ops(
	const struct sep_usbfs_ops *ops, int *file_descriptor)
{
	struct sep_usbfs_deadline deadline = {
		.ops = ops,
		.bounded = false,
	};

	return open_unique(ops, &deadline, file_descriptor);
}

enum sep_usbfs_status sep_usbfs_open_unique_bounded_with_ops(
	const struct sep_usbfs_ops *ops, unsigned int timeout_ms,
	int *file_descriptor)
{
	struct sep_usbfs_deadline deadline = {
		.ops = ops,
		.bounded = true,
	};
	uint64_t now;

	if (file_descriptor)
		*file_descriptor = -1;
	if (!file_descriptor || !ops || !ops->monotonic_ms || timeout_ms == 0)
		return SEP_USBFS_INVALID_ARGUMENT;
	if (ops->monotonic_ms(ops->context, &now) != 0 ||
	    UINT64_MAX - now < timeout_ms)
		return SEP_USBFS_CLOCK_FAILED;
	deadline.value_ms = now + timeout_ms;
	return open_unique(ops, &deadline, file_descriptor);
}

static int read_hex_attribute(int directory, const char *name,
			      unsigned int *value)
{
	char buffer[16];
	char *end;
	ssize_t length;
	unsigned long parsed;
	int file_descriptor;

	file_descriptor = openat(directory, name, O_RDONLY | O_CLOEXEC);
	if (file_descriptor < 0)
		return -1;
	length = read(file_descriptor, buffer, sizeof(buffer) - 1);
	(void)close(file_descriptor);
	if (length <= 0 || (size_t)length >= sizeof(buffer))
		return -1;
	buffer[length] = '\0';
	errno = 0;
	parsed = strtoul(buffer, &end, 16);
	if (errno != 0 || end == buffer || parsed > UINT_MAX)
		return -1;
	while (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')
		++end;
	if (*end != '\0')
		return -1;
	*value = (unsigned int)parsed;
	return 0;
}

static int read_decimal_attribute(int directory, const char *name,
				  unsigned int *value)
{
	char buffer[16];
	char *end;
	ssize_t length;
	unsigned long parsed;
	int file_descriptor;

	file_descriptor = openat(directory, name, O_RDONLY | O_CLOEXEC);
	if (file_descriptor < 0)
		return -1;
	length = read(file_descriptor, buffer, sizeof(buffer) - 1);
	(void)close(file_descriptor);
	if (length <= 0 || (size_t)length >= sizeof(buffer))
		return -1;
	buffer[length] = '\0';
	errno = 0;
	parsed = strtoul(buffer, &end, 10);
	if (errno != 0 || end == buffer || parsed > UINT_MAX)
		return -1;
	while (*end == ' ' || *end == '\t' || *end == '\n' || *end == '\r')
		++end;
	if (*end != '\0')
		return -1;
	*value = (unsigned int)parsed;
	return 0;
}

static int linux_list_candidates(void *context,
				 struct sep_usbfs_candidate *candidates,
				 size_t capacity, size_t *count)
{
	DIR *directory;
	struct dirent *entry;
	size_t found = 0;
	int root_descriptor;
	int result = 0;

	(void)context;
	directory = opendir(SEP_USBFS_SYSFS_ROOT);
	if (directory == NULL)
		return -1;
	root_descriptor = dirfd(directory);
	if (root_descriptor < 0) {
		(void)closedir(directory);
		return -1;
	}
	for (;;) {
		unsigned int vendor;
		unsigned int product;
		unsigned int bus;
		unsigned int device;
		int device_directory;
		int written;

		errno = 0;
		entry = readdir(directory);
		if (entry == NULL) {
			if (errno != 0)
				result = -1;
			break;
		}

		if (entry->d_name[0] == '.')
			continue;
		device_directory = openat(root_descriptor, entry->d_name,
					  O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (device_directory < 0)
			continue;
		if (read_hex_attribute(device_directory, "idVendor", &vendor) != 0 ||
		    read_hex_attribute(device_directory, "idProduct", &product) != 0 ||
		    vendor != SEP_USBFS_VENDOR_ID ||
		    product != SEP_USBFS_PRODUCT_ID) {
			(void)close(device_directory);
			continue;
		}
		if (read_decimal_attribute(device_directory, "busnum", &bus) != 0 ||
		    read_decimal_attribute(device_directory, "devnum", &device) != 0 ||
		    bus > 999 || device == 0 || device > 127) {
			(void)close(device_directory);
			result = -1;
			break;
		}
		(void)close(device_directory);
		if (found >= capacity) {
			*count = found + 1;
			found = capacity + 1;
			result = 0;
			break;
		}
		written = snprintf(candidates[found].path,
				   sizeof(candidates[found].path),
				   "/dev/bus/usb/%03u/%03u", bus, device);
		if (written < 0 ||
		    (size_t)written >= sizeof(candidates[found].path)) {
			result = -1;
			break;
		}
		++found;
	}
	if (result == 0 && found <= capacity)
		*count = found;
	(void)closedir(directory);
	return result;
}

static int linux_open_path(void *context, const char *path, int flags)
{
	(void)context;
	return open(path, flags);
}

static int linux_control(void *context, int file_descriptor,
			 struct usbdevfs_ctrltransfer *transfer)
{
	(void)context;
	return ioctl(file_descriptor, USBDEVFS_CONTROL, transfer);
}

static int linux_close_fd(void *context, int file_descriptor)
{
	(void)context;
	return close(file_descriptor);
}

static int linux_monotonic_ms(void *context, uint64_t *value)
{
	struct timespec now;

	(void)context;
	if (!value || clock_gettime(CLOCK_MONOTONIC, &now) != 0)
		return -1;
	*value = (uint64_t)now.tv_sec * 1000U +
		 (uint64_t)now.tv_nsec / 1000000U;
	return 0;
}

static struct sep_usbfs_ops linux_ops(void)
{
	const struct sep_usbfs_ops ops = {
		.context = NULL,
		.list_candidates = linux_list_candidates,
		.open_path = linux_open_path,
		.control = linux_control,
		.close_fd = linux_close_fd,
		.monotonic_ms = linux_monotonic_ms,
	};

	return ops;
}

enum sep_usbfs_status sep_usbfs_open_unique(int *file_descriptor)
{
	struct sep_usbfs_ops ops = linux_ops();

	return sep_usbfs_open_unique_with_ops(&ops, file_descriptor);
}

enum sep_usbfs_status sep_usbfs_open_unique_bounded(
	unsigned int timeout_ms, int *file_descriptor)
{
	struct sep_usbfs_ops ops = linux_ops();

	return sep_usbfs_open_unique_bounded_with_ops(
		&ops, timeout_ms, file_descriptor);
}

const char *sep_usbfs_status_string(enum sep_usbfs_status status)
{
	switch (status) {
	case SEP_USBFS_OK:
		return "success";
	case SEP_USBFS_INVALID_ARGUMENT:
		return "invalid argument";
	case SEP_USBFS_ENUMERATION_FAILED:
		return "USB enumeration failed";
	case SEP_USBFS_CANDIDATE_LIMIT:
		return "too many USB candidates";
	case SEP_USBFS_DEVICE_NOT_FOUND:
		return "matching SEP device not found";
	case SEP_USBFS_DEVICE_AMBIGUOUS:
		return "multiple matching SEP devices";
	case SEP_USBFS_DEVICE_ACCESS_FAILED:
		return "SEP device access failed";
	case SEP_USBFS_CONTROL_FAILED:
		return "SEP device control transfer failed";
	case SEP_USBFS_NOT_TARGET:
		return "USB device is not the expected SEP target";
	case SEP_USBFS_DESCRIPTOR_INVALID:
		return "USB descriptor validation failed";
	case SEP_USBFS_CONFIGURATION_MISMATCH:
		return "SEP device configuration mismatch";
	case SEP_USBFS_INTERFACE_MISMATCH:
		return "SEP interface descriptor mismatch";
	case SEP_USBFS_TIMED_OUT:
		return "SEP device discovery timed out";
	case SEP_USBFS_CLOCK_FAILED:
		return "SEP device discovery clock failed";
	}
	return "unknown SEP USB error";
}

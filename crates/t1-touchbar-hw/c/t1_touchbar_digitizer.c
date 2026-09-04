#define _GNU_SOURCE

#include "t1_touchbar_digitizer.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/hidraw.h>
#include <linux/input.h>
#include <stdbool.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#define T1_USB_VENDOR UINT16_C(0x05ac)
#define T1_USB_PRODUCT UINT16_C(0x8600)
#define T1_DIGITIZER_DESCRIPTOR_SIZE 782

static int digitizer_identity_matches(unsigned int bus, unsigned int vendor,
				      unsigned int product,
				      int descriptor_size)
{
	return bus == BUS_USB && vendor == T1_USB_VENDOR &&
	       product == T1_USB_PRODUCT &&
	       descriptor_size == T1_DIGITIZER_DESCRIPTOR_SIZE;
}

static enum t1_touchbar_io_status validate_digitizer(int descriptor)
{
	struct stat metadata;
	struct hidraw_devinfo identity;
	int descriptor_size = 0;

	memset(&identity, 0, sizeof(identity));
	if (fstat(descriptor, &metadata) != 0)
		return T1_TOUCHBAR_IO_ERROR_IO;
	if (!S_ISCHR(metadata.st_mode))
		return T1_TOUCHBAR_IO_ERROR_TYPE;
	if (ioctl(descriptor, HIDIOCGRAWINFO, &identity) != 0 ||
	    ioctl(descriptor, HIDIOCGRDESCSIZE, &descriptor_size) != 0)
		return T1_TOUCHBAR_IO_ERROR_IDENTITY;
	if (!digitizer_identity_matches(identity.bustype,
					(uint16_t)identity.vendor,
					(uint16_t)identity.product,
					descriptor_size))
		return T1_TOUCHBAR_IO_ERROR_IDENTITY;
	return T1_TOUCHBAR_IO_OK;
}

enum t1_touchbar_io_status t1_touchbar_digitizer_open(int *descriptor)
{
	DIR *directory;
	struct dirent *entry;
	int directory_descriptor;
	int selected = -1;
	enum t1_touchbar_io_status failure = T1_TOUCHBAR_IO_ERROR_DISCOVERY;

	if (descriptor == NULL)
		return T1_TOUCHBAR_IO_ERROR_ARGUMENT;
	*descriptor = -1;
	directory = opendir("/dev");
	if (directory == NULL)
		return T1_TOUCHBAR_IO_ERROR_DISCOVERY;
	directory_descriptor = dirfd(directory);
	for (;;) {
		int candidate;
		enum t1_touchbar_io_status status;

		errno = 0;
		entry = readdir(directory);
		if (entry == NULL)
			break;
		if (!t1_touchbar_indexed_name(entry->d_name, "hidraw"))
			continue;
		candidate = openat(directory_descriptor, entry->d_name,
				   O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
		if (candidate < 0) {
			failure = T1_TOUCHBAR_IO_ERROR_OPEN;
			continue;
		}
		status = validate_digitizer(candidate);
		if (status != T1_TOUCHBAR_IO_OK) {
			(void)close(candidate);
			continue;
		}
		if (selected >= 0) {
			(void)close(candidate);
			(void)close(selected);
			(void)closedir(directory);
			return T1_TOUCHBAR_IO_ERROR_AMBIGUOUS;
		}
		selected = candidate;
	}
	if (errno != 0) {
		if (selected >= 0)
			(void)close(selected);
		failure = T1_TOUCHBAR_IO_ERROR_DISCOVERY;
	}
	if (closedir(directory) != 0) {
		if (selected >= 0)
			(void)close(selected);
		return T1_TOUCHBAR_IO_ERROR_IO;
	}
	if (selected < 0)
		return failure;
	*descriptor = selected;
	return T1_TOUCHBAR_IO_OK;
}

enum t1_touchbar_io_status t1_touchbar_digitizer_read(
	int descriptor, unsigned int timeout_ms,
	uint8_t report[T1_TOUCHBAR_DIGITIZER_REPORT_SIZE])
{
	uint8_t raw[T1_TOUCHBAR_DIGITIZER_REPORT_SIZE + 1U];
	ssize_t count;
	int ready;
	enum t1_touchbar_io_status status;

	if (descriptor < 0 || report == NULL)
		return T1_TOUCHBAR_IO_ERROR_ARGUMENT;
	status = t1_touchbar_wait_readable(descriptor, timeout_ms, &ready);
	if (status != T1_TOUCHBAR_IO_OK)
		return status;
	if (!ready)
		return T1_TOUCHBAR_IO_ERROR_IO;
	do {
		count = read(descriptor, raw, sizeof(raw));
	} while (count < 0 && errno == EINTR);
	if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
		return T1_TOUCHBAR_IO_IDLE;
	if (count < 0)
		return T1_TOUCHBAR_IO_ERROR_IO;
	if (count == 0)
		return T1_TOUCHBAR_IO_ERROR_CLOSED;
	if ((size_t)count == T1_TOUCHBAR_DIGITIZER_REPORT_SIZE) {
		memcpy(report, raw, T1_TOUCHBAR_DIGITIZER_REPORT_SIZE);
		return T1_TOUCHBAR_IO_OK;
	}
	if ((size_t)count == T1_TOUCHBAR_DIGITIZER_REPORT_SIZE + 1U) {
		memcpy(report, raw + 1, T1_TOUCHBAR_DIGITIZER_REPORT_SIZE);
		return T1_TOUCHBAR_IO_OK;
	}
	return T1_TOUCHBAR_IO_ERROR_PROTOCOL;
}

#ifdef T1_TOUCHBAR_TESTING
int t1_touchbar_digitizer_test_identity(
	unsigned int bus, unsigned int vendor, unsigned int product,
	int descriptor_size)
{
	return digitizer_identity_matches(bus, vendor, product,
					   descriptor_size);
}
#endif

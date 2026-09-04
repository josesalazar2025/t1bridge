#define _GNU_SOURCE

#include "t1_touchbar_uinput.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <linux/uinput.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#define KEY_COUNT 13U

struct t1_touchbar_uinput {
	int descriptor;
	uint16_t held;
	int created;
};

static const unsigned int key_codes[KEY_COUNT] = {
	KEY_ESC,
	KEY_F1,
	KEY_F2,
	KEY_F3,
	KEY_F4,
	KEY_F5,
	KEY_F6,
	KEY_F7,
	KEY_F8,
	KEY_F9,
	KEY_F10,
	KEY_F11,
	KEY_F12,
};

_Static_assert(T1_TOUCHBAR_KEY_ESCAPE == 0,
	       "Touch Bar key ABI changed");
_Static_assert(T1_TOUCHBAR_KEY_F12 == 12,
	       "Touch Bar key ABI changed");

static int write_all(int descriptor, const void *data, size_t size)
{
	const uint8_t *bytes = data;
	size_t offset = 0;

	while (offset < size) {
		ssize_t count = write(descriptor, bytes + offset, size - offset);

		if (count < 0 && errno == EINTR)
			continue;
		if (count <= 0)
			return -1;
		offset += (size_t)count;
	}
	return 0;
}

static int valid_key(enum t1_touchbar_key key)
{
	return key >= T1_TOUCHBAR_KEY_ESCAPE &&
	       (unsigned int)key < KEY_COUNT;
}

static int emit(struct t1_touchbar_uinput *device,
		enum t1_touchbar_key key, int pressed)
{
	struct input_event events[2];

	memset(events, 0, sizeof(events));
	events[0].type = EV_KEY;
	events[0].code = (uint16_t)key_codes[(unsigned int)key];
	events[0].value = pressed;
	events[1].type = EV_SYN;
	events[1].code = SYN_REPORT;
	return write_all(device->descriptor, events, sizeof(events));
}

enum t1_touchbar_io_status t1_touchbar_uinput_create(
	struct t1_touchbar_uinput **device)
{
	struct t1_touchbar_uinput *created;
	struct uinput_setup setup;
	struct stat metadata;
	unsigned int index;

	if (device == NULL)
		return T1_TOUCHBAR_IO_ERROR_ARGUMENT;
	*device = NULL;
	created = calloc(1, sizeof(*created));
	if (created == NULL)
		return T1_TOUCHBAR_IO_ERROR_IO;
	created->descriptor = open("/dev/uinput",
				   O_WRONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
	if (created->descriptor < 0) {
		free(created);
		return T1_TOUCHBAR_IO_ERROR_OPEN;
	}
	if (fstat(created->descriptor, &metadata) != 0 ||
	    !S_ISCHR(metadata.st_mode)) {
		(void)close(created->descriptor);
		free(created);
		return T1_TOUCHBAR_IO_ERROR_TYPE;
	}
	if (ioctl(created->descriptor, UI_SET_EVBIT, EV_KEY) != 0)
		goto configure_failure;
	for (index = 0; index < KEY_COUNT; ++index) {
		if (ioctl(created->descriptor, UI_SET_KEYBIT, key_codes[index]) != 0)
			goto configure_failure;
	}
	memset(&setup, 0, sizeof(setup));
	setup.id.bustype = BUS_VIRTUAL;
	(void)strncpy(setup.name, "T1Bridge Touch Bar", UINPUT_MAX_NAME_SIZE - 1U);
	if (ioctl(created->descriptor, UI_DEV_SETUP, &setup) != 0 ||
	    ioctl(created->descriptor, UI_DEV_CREATE) != 0)
		goto configure_failure;
	created->created = 1;
	*device = created;
	return T1_TOUCHBAR_IO_OK;

configure_failure:
	(void)close(created->descriptor);
	free(created);
	return T1_TOUCHBAR_IO_ERROR_IO;
}

enum t1_touchbar_io_status t1_touchbar_uinput_tap(
	struct t1_touchbar_uinput *device, enum t1_touchbar_key key)
{
	uint16_t mask;

	if (device == NULL || device->descriptor < 0 || !valid_key(key))
		return T1_TOUCHBAR_IO_ERROR_ARGUMENT;
	mask = (uint16_t)(UINT16_C(1) << (unsigned int)key);
	if ((device->held & mask) != 0)
		return T1_TOUCHBAR_IO_ERROR_PROTOCOL;
	device->held |= mask;
	if (emit(device, key, 1) != 0) {
		if (emit(device, key, 0) == 0)
			device->held &= (uint16_t)~mask;
		return T1_TOUCHBAR_IO_ERROR_IO;
	}
	if (emit(device, key, 0) != 0)
		return T1_TOUCHBAR_IO_ERROR_IO;
	device->held &= (uint16_t)~mask;
	return T1_TOUCHBAR_IO_OK;
}

enum t1_touchbar_io_status t1_touchbar_uinput_release_all(
	struct t1_touchbar_uinput *device)
{
	unsigned int index;
	enum t1_touchbar_io_status result = T1_TOUCHBAR_IO_OK;

	if (device == NULL || device->descriptor < 0)
		return T1_TOUCHBAR_IO_ERROR_ARGUMENT;
	for (index = 0; index < KEY_COUNT; ++index) {
		uint16_t mask = (uint16_t)(UINT16_C(1) << index);

		if ((device->held & mask) == 0)
			continue;
		if (emit(device, (enum t1_touchbar_key)index, 0) != 0) {
			result = T1_TOUCHBAR_IO_ERROR_IO;
			continue;
		}
		device->held &= (uint16_t)~mask;
	}
	return result;
}

enum t1_touchbar_io_status t1_touchbar_uinput_close(
	struct t1_touchbar_uinput *device)
{
	enum t1_touchbar_io_status result;

	if (device == NULL || device->descriptor < 0)
		return T1_TOUCHBAR_IO_ERROR_ARGUMENT;
	result = t1_touchbar_uinput_release_all(device);
	if (device->created && ioctl(device->descriptor, UI_DEV_DESTROY) != 0)
		result = T1_TOUCHBAR_IO_ERROR_IO;
	if (close(device->descriptor) != 0)
		result = T1_TOUCHBAR_IO_ERROR_IO;
	device->descriptor = -1;
	free(device);
	return result;
}

#ifdef T1_TOUCHBAR_TESTING
struct t1_touchbar_uinput *t1_touchbar_uinput_test_device(int descriptor)
{
	struct t1_touchbar_uinput *device;

	if (descriptor < 0)
		return NULL;
	device = calloc(1, sizeof(*device));
	if (device == NULL)
		return NULL;
	device->descriptor = descriptor;
	return device;
}

unsigned int t1_touchbar_uinput_test_held(
	const struct t1_touchbar_uinput *device)
{
	return device == NULL ? UINT32_MAX : device->held;
}

void t1_touchbar_uinput_test_mark_held(
	struct t1_touchbar_uinput *device, enum t1_touchbar_key key)
{
	if (device != NULL && valid_key(key))
		device->held |= (uint16_t)(UINT16_C(1) << (unsigned int)key);
}
#endif

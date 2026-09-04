#define _GNU_SOURCE

#include "t1_touchbar_fn.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/input.h>
#include <stdbool.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#define BITS_PER_WORD (sizeof(unsigned long) * 8U)
#define BIT_WORD(bit) ((unsigned int)(bit) / BITS_PER_WORD)
#define BIT_MASK(bit) (1UL << ((unsigned int)(bit) % BITS_PER_WORD))
#define KEY_WORDS (BIT_WORD(KEY_MAX) + 1U)
#define EVENT_WORDS (BIT_WORD(EV_MAX) + 1U)
#define INPUT_BATCH 32U

static int bit_is_set(const unsigned long *bits, unsigned int bit)
{
	return (bits[BIT_WORD(bit)] & BIT_MASK(bit)) != 0;
}

static int keyboard_identity_matches(const char *name, unsigned int bus,
				     int has_key_events, int has_fn_key)
{
	return name != NULL && strcmp(name, "Apple SPI Keyboard") == 0 &&
	       bus == BUS_SPI && has_key_events && has_fn_key;
}

static enum t1_touchbar_io_status validate_keyboard(int descriptor)
{
	struct stat metadata;
	struct input_id identity;
	char name[128];
	unsigned long event_bits[EVENT_WORDS];
	unsigned long key_bits[KEY_WORDS];
	int name_length;

	memset(&identity, 0, sizeof(identity));
	memset(name, 0, sizeof(name));
	memset(event_bits, 0, sizeof(event_bits));
	memset(key_bits, 0, sizeof(key_bits));
	if (fstat(descriptor, &metadata) != 0)
		return T1_TOUCHBAR_IO_ERROR_IO;
	if (!S_ISCHR(metadata.st_mode))
		return T1_TOUCHBAR_IO_ERROR_TYPE;
	name_length = ioctl(descriptor, EVIOCGNAME(sizeof(name)), name);
	if (name_length <= 0 || (size_t)name_length >= sizeof(name) ||
	    ioctl(descriptor, EVIOCGID, &identity) != 0 ||
	    ioctl(descriptor, EVIOCGBIT(0, sizeof(event_bits)), event_bits) < 0 ||
	    ioctl(descriptor, EVIOCGBIT(EV_KEY, sizeof(key_bits)), key_bits) < 0)
		return T1_TOUCHBAR_IO_ERROR_IDENTITY;
	name[sizeof(name) - 1U] = '\0';
	if (!keyboard_identity_matches(name, identity.bustype,
				       bit_is_set(event_bits, EV_KEY),
				       bit_is_set(key_bits, KEY_FN)))
		return T1_TOUCHBAR_IO_ERROR_IDENTITY;
	return T1_TOUCHBAR_IO_OK;
}

enum t1_touchbar_io_status t1_touchbar_fn_open(int *descriptor)
{
	DIR *directory;
	struct dirent *entry;
	int directory_descriptor;
	int selected = -1;
	enum t1_touchbar_io_status failure = T1_TOUCHBAR_IO_ERROR_DISCOVERY;

	if (descriptor == NULL)
		return T1_TOUCHBAR_IO_ERROR_ARGUMENT;
	*descriptor = -1;
	directory = opendir("/dev/input");
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
		if (!t1_touchbar_indexed_name(entry->d_name, "event"))
			continue;
		candidate = openat(directory_descriptor, entry->d_name,
				   O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
		if (candidate < 0) {
			failure = T1_TOUCHBAR_IO_ERROR_OPEN;
			continue;
		}
		status = validate_keyboard(candidate);
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

enum t1_touchbar_io_status t1_touchbar_fn_state(
	int descriptor, int *pressed)
{
	unsigned long key_bits[KEY_WORDS];

	if (descriptor < 0 || pressed == NULL)
		return T1_TOUCHBAR_IO_ERROR_ARGUMENT;
	memset(key_bits, 0, sizeof(key_bits));
	if (ioctl(descriptor, EVIOCGKEY(sizeof(key_bits)), key_bits) < 0)
		return T1_TOUCHBAR_IO_ERROR_IO;
	*pressed = bit_is_set(key_bits, KEY_FN);
	return T1_TOUCHBAR_IO_OK;
}

enum t1_touchbar_io_status t1_touchbar_fn_read(
	int descriptor, struct t1_touchbar_fn_edge *edges, size_t capacity,
	size_t *edge_count)
{
	struct input_event events[INPUT_BATCH];
	ssize_t byte_count;
	size_t event_count;
	size_t count = 0;
	size_t index;

	if (descriptor < 0 || edge_count == NULL ||
	    (capacity != 0 && edges == NULL))
		return T1_TOUCHBAR_IO_ERROR_ARGUMENT;
	*edge_count = 0;
	do {
		byte_count = read(descriptor, events, sizeof(events));
	} while (byte_count < 0 && errno == EINTR);
	if (byte_count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
		return T1_TOUCHBAR_IO_IDLE;
	if (byte_count < 0)
		return T1_TOUCHBAR_IO_ERROR_IO;
	if (byte_count == 0)
		return T1_TOUCHBAR_IO_ERROR_CLOSED;
	if ((size_t)byte_count % sizeof(events[0]) != 0)
		return T1_TOUCHBAR_IO_ERROR_PROTOCOL;
	event_count = (size_t)byte_count / sizeof(events[0]);
	for (index = 0; index < event_count; ++index) {
		if (events[index].type == EV_SYN &&
		    events[index].code == SYN_DROPPED)
			return T1_TOUCHBAR_IO_RESYNC;
		if (events[index].type == EV_KEY &&
		    events[index].code == KEY_FN &&
		    (events[index].value == 0 || events[index].value == 1))
			++count;
	}
	if (count > capacity)
		return T1_TOUCHBAR_IO_ERROR_CAPACITY;
	count = 0;
	for (index = 0; index < event_count; ++index) {
		if (events[index].type == EV_KEY &&
		    events[index].code == KEY_FN &&
		    (events[index].value == 0 || events[index].value == 1)) {
			edges[count].pressed = events[index].value;
			++count;
		}
	}
	*edge_count = count;
	return T1_TOUCHBAR_IO_OK;
}

#ifdef T1_TOUCHBAR_TESTING
int t1_touchbar_fn_test_identity(const char *name, unsigned int bus,
				 int has_key_events, int has_fn_key)
{
	return keyboard_identity_matches(name, bus, has_key_events, has_fn_key);
}
#endif

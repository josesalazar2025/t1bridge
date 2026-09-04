#define _GNU_SOURCE

#include "t1_frame_memfd.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define T1_FRAME_REQUIRED_SEALS \
	(F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL)

struct t1_frame_memfd_renderer {
	int descriptor;
	uint8_t *mapping;
	size_t length;
};

struct t1_frame_memfd_reader {
	int descriptor;
	uint8_t *mapping;
	size_t length;
};

static int byte_length_valid(uint64_t byte_length)
{
	return byte_length != 0 && byte_length <= T1_FRAME_MEMFD_MAX_BYTES &&
	    byte_length <= SIZE_MAX;
}

static int fcntl_no_argument_retry(int descriptor, int command)
{
	int result;

	do {
		result = fcntl(descriptor, command);
	} while (result < 0 && errno == EINTR);
	return result;
}

static int fcntl_argument_retry(int descriptor, int command, int argument)
{
	int result;

	do {
		result = fcntl(descriptor, command, argument);
	} while (result < 0 && errno == EINTR);
	return result;
}

static int fstat_retry(int descriptor, struct stat *status)
{
	int result;

	do {
		result = fstat(descriptor, status);
	} while (result < 0 && errno == EINTR);
	return result;
}

enum t1_frame_memfd_status t1_frame_memfd_renderer_create(
	struct t1_frame_memfd_renderer **output, uint64_t byte_length)
{
	struct t1_frame_memfd_renderer *frame;
	void *mapping;
	int seals;

	if (output == NULL)
		return T1_FRAME_MEMFD_INVALID_ARGUMENT;
	*output = NULL;
	if (!byte_length_valid(byte_length))
		return T1_FRAME_MEMFD_SIZE_OUT_OF_RANGE;
	frame = calloc(1, sizeof(*frame));
	if (frame == NULL)
		return T1_FRAME_MEMFD_ALLOCATION_FAILED;
	frame->descriptor = -1;
	frame->descriptor = memfd_create("t1-frame",
	    MFD_CLOEXEC | MFD_ALLOW_SEALING);
	if (frame->descriptor < 0) {
		free(frame);
		return T1_FRAME_MEMFD_CREATE_FAILED;
	}
	frame->length = (size_t)byte_length;
	if (ftruncate(frame->descriptor, (off_t)frame->length) != 0) {
		t1_frame_memfd_renderer_destroy(frame);
		return T1_FRAME_MEMFD_RESIZE_FAILED;
	}
	mapping = mmap(NULL, frame->length, PROT_READ | PROT_WRITE, MAP_SHARED,
	    frame->descriptor, 0);
	if (mapping == MAP_FAILED) {
		t1_frame_memfd_renderer_destroy(frame);
		return T1_FRAME_MEMFD_MAPPING_FAILED;
	}
	if (mapping == NULL) {
		(void)munmap(mapping, frame->length);
		t1_frame_memfd_renderer_destroy(frame);
		return T1_FRAME_MEMFD_MAPPING_FAILED;
	}
	frame->mapping = mapping;
	if (fcntl_argument_retry(frame->descriptor, F_ADD_SEALS,
	    T1_FRAME_REQUIRED_SEALS) < 0) {
		t1_frame_memfd_renderer_destroy(frame);
		return T1_FRAME_MEMFD_SEAL_FAILED;
	}
	seals = fcntl_no_argument_retry(frame->descriptor, F_GET_SEALS);
	if (seals < 0 || (seals & T1_FRAME_REQUIRED_SEALS) !=
	    T1_FRAME_REQUIRED_SEALS || (seals & F_SEAL_WRITE) != 0) {
		t1_frame_memfd_renderer_destroy(frame);
		return T1_FRAME_MEMFD_SEAL_FAILED;
	}
	*output = frame;
	return T1_FRAME_MEMFD_OK;
}

int t1_frame_memfd_renderer_descriptor(
	const struct t1_frame_memfd_renderer *frame)
{
	return frame == NULL ? -1 : frame->descriptor;
}

uint8_t *t1_frame_memfd_renderer_mapping(
	struct t1_frame_memfd_renderer *frame)
{
	return frame == NULL ? NULL : frame->mapping;
}

size_t t1_frame_memfd_renderer_length(
	const struct t1_frame_memfd_renderer *frame)
{
	return frame == NULL ? 0 : frame->length;
}

void t1_frame_memfd_renderer_destroy(struct t1_frame_memfd_renderer *frame)
{
	if (frame == NULL)
		return;
	if (frame->mapping != NULL)
		(void)munmap(frame->mapping, frame->length);
	if (frame->descriptor >= 0)
		(void)close(frame->descriptor);
	free(frame);
}

enum t1_frame_memfd_status t1_frame_memfd_reader_accept(
	struct t1_frame_memfd_reader **output, int received_descriptor,
	uint64_t expected_byte_length)
{
	struct t1_frame_memfd_reader *frame;
	struct stat status;
	void *mapping;
	int seals;

	if (output == NULL)
		return T1_FRAME_MEMFD_INVALID_ARGUMENT;
	*output = NULL;
	if (received_descriptor < 0)
		return T1_FRAME_MEMFD_INVALID_ARGUMENT;
	if (!byte_length_valid(expected_byte_length))
		return T1_FRAME_MEMFD_SIZE_OUT_OF_RANGE;
	frame = calloc(1, sizeof(*frame));
	if (frame == NULL)
		return T1_FRAME_MEMFD_ALLOCATION_FAILED;
	frame->descriptor = -1;
	frame->descriptor = fcntl_argument_retry(received_descriptor,
	    F_DUPFD_CLOEXEC, 0);
	if (frame->descriptor < 0) {
		free(frame);
		return T1_FRAME_MEMFD_DUPLICATE_FAILED;
	}
	frame->length = (size_t)expected_byte_length;
	seals = fcntl_no_argument_retry(frame->descriptor, F_GET_SEALS);
	if (fstat_retry(frame->descriptor, &status) != 0 ||
	    !S_ISREG(status.st_mode) || status.st_nlink != 0 ||
	    status.st_size < 0 || (uint64_t)status.st_size !=
	    expected_byte_length || seals < 0 ||
	    (seals & T1_FRAME_REQUIRED_SEALS) != T1_FRAME_REQUIRED_SEALS) {
		t1_frame_memfd_reader_destroy(frame);
		return T1_FRAME_MEMFD_INVALID_FILE;
	}
	mapping = mmap(NULL, frame->length, PROT_READ, MAP_SHARED,
	    frame->descriptor, 0);
	if (mapping == MAP_FAILED) {
		t1_frame_memfd_reader_destroy(frame);
		return T1_FRAME_MEMFD_MAPPING_FAILED;
	}
	if (mapping == NULL) {
		(void)munmap(mapping, frame->length);
		t1_frame_memfd_reader_destroy(frame);
		return T1_FRAME_MEMFD_MAPPING_FAILED;
	}
	frame->mapping = mapping;
	*output = frame;
	return T1_FRAME_MEMFD_OK;
}

size_t t1_frame_memfd_reader_length(
	const struct t1_frame_memfd_reader *frame)
{
	return frame == NULL ? 0 : frame->length;
}

enum t1_frame_memfd_status t1_frame_memfd_reader_copy(
	const struct t1_frame_memfd_reader *frame, uint8_t *destination,
	size_t destination_length)
{
	const volatile uint8_t *source;
	size_t index;

	if (frame == NULL || destination == NULL ||
	    destination_length != frame->length)
		return T1_FRAME_MEMFD_INVALID_ARGUMENT;
	source = frame->mapping;
	for (index = 0; index < frame->length; ++index)
		destination[index] = source[index];
	return T1_FRAME_MEMFD_OK;
}

void t1_frame_memfd_reader_destroy(struct t1_frame_memfd_reader *frame)
{
	if (frame == NULL)
		return;
	if (frame->mapping != NULL)
		(void)munmap(frame->mapping, frame->length);
	if (frame->descriptor >= 0)
		(void)close(frame->descriptor);
	free(frame);
}

const char *t1_frame_memfd_status_string(enum t1_frame_memfd_status status)
{
	switch (status) {
	case T1_FRAME_MEMFD_OK:
		return "frame memory operation succeeded";
	case T1_FRAME_MEMFD_INVALID_ARGUMENT:
		return "invalid frame memory argument";
	case T1_FRAME_MEMFD_SIZE_OUT_OF_RANGE:
		return "frame memory size is out of range";
	case T1_FRAME_MEMFD_ALLOCATION_FAILED:
		return "frame memory allocation failed";
	case T1_FRAME_MEMFD_CREATE_FAILED:
		return "frame memory creation failed";
	case T1_FRAME_MEMFD_RESIZE_FAILED:
		return "frame memory sizing failed";
	case T1_FRAME_MEMFD_SEAL_FAILED:
		return "frame memory sealing failed";
	case T1_FRAME_MEMFD_DUPLICATE_FAILED:
		return "frame memory ownership failed";
	case T1_FRAME_MEMFD_INVALID_FILE:
		return "invalid frame memory file";
	case T1_FRAME_MEMFD_MAPPING_FAILED:
		return "frame memory mapping failed";
	default:
		return "unknown frame memory failure";
	}
}

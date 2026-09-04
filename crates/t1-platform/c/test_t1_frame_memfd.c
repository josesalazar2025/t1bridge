#define _GNU_SOURCE

#include "t1_frame_memfd.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define TEST_FRAME_BYTES UINT64_C(520800)
#define REQUIRED_SEALS (F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL)

static unsigned int failures;

static void check(int condition, const char *description)
{
	if (condition)
		return;
	fprintf(stderr, "FAIL: %s\n", description);
	++failures;
}

static int raw_memfd(size_t length, int seals)
{
	int descriptor;

	descriptor = memfd_create("synthetic-frame",
	    MFD_CLOEXEC | MFD_ALLOW_SEALING);
	if (descriptor < 0)
		return -1;
	if (ftruncate(descriptor, (off_t)length) != 0 ||
	    (seals != 0 && fcntl(descriptor, F_ADD_SEALS, seals) != 0)) {
		(void)close(descriptor);
		return -1;
	}
	return descriptor;
}

static int lowest_unused_descriptor(void)
{
	int descriptor;

	for (descriptor = 0; descriptor < 4096; ++descriptor) {
		errno = 0;
		if (fcntl(descriptor, F_GETFD) < 0 && errno == EBADF)
			return descriptor;
	}
	return -1;
}

static void test_renderer_frame(void)
{
	struct t1_frame_memfd_renderer *frame = NULL;
	struct stat status;
	uint8_t *mapping;
	int descriptor;
	int seals;

	check(t1_frame_memfd_renderer_create(&frame, TEST_FRAME_BYTES) ==
	    T1_FRAME_MEMFD_OK, "create a renderer frame");
	if (frame == NULL)
		return;
	descriptor = t1_frame_memfd_renderer_descriptor(frame);
	mapping = t1_frame_memfd_renderer_mapping(frame);
	check(descriptor >= 0, "expose the renderer transfer descriptor");
	if (descriptor < 0) {
		t1_frame_memfd_renderer_destroy(frame);
		return;
	}
	seals = fcntl(descriptor, F_GET_SEALS);
	check(fcntl(descriptor, F_GETFD) == FD_CLOEXEC,
	    "create the descriptor close-on-exec");
	check(fstat(descriptor, &status) == 0 && S_ISREG(status.st_mode) &&
	    status.st_nlink == 0, "create an anonymous regular file");
	check(status.st_size == (off_t)TEST_FRAME_BYTES,
	    "size the renderer file exactly");
	check((seals & REQUIRED_SEALS) == REQUIRED_SEALS,
	    "seal size and further seal changes");
	check((seals & F_SEAL_WRITE) == 0, "keep renderer writes permitted");
	check(t1_frame_memfd_renderer_length(frame) == TEST_FRAME_BYTES,
	    "report exact renderer length");
	check(mapping != NULL, "expose a writable renderer mapping");
	if (mapping != NULL) {
		mapping[0] = UINT8_C(0x31);
		mapping[TEST_FRAME_BYTES - 1] = UINT8_C(0x79);
		check(mapping[0] == UINT8_C(0x31) &&
		    mapping[TEST_FRAME_BYTES - 1] == UINT8_C(0x79),
		    "write both ends of the renderer mapping");
	}
	check(ftruncate(descriptor, (off_t)TEST_FRAME_BYTES - 1) != 0,
	    "reject shrinking a renderer frame");
	check(ftruncate(descriptor, (off_t)TEST_FRAME_BYTES + 1) != 0,
	    "reject growing a renderer frame");
	check(fcntl(descriptor, F_ADD_SEALS, F_SEAL_WRITE) != 0,
	    "reject changes to the completed seal set");
	t1_frame_memfd_renderer_destroy(frame);
}

static void test_reader_frame(void)
{
	struct t1_frame_memfd_renderer *renderer = NULL;
	struct t1_frame_memfd_reader *reader = NULL;
	uint8_t snapshot[TEST_FRAME_BYTES];
	uint8_t *writable;
	int owned;
	int received;

	check(t1_frame_memfd_renderer_create(&renderer, TEST_FRAME_BYTES) ==
	    T1_FRAME_MEMFD_OK, "create source frame for reader");
	if (renderer == NULL)
		return;
	writable = t1_frame_memfd_renderer_mapping(renderer);
	writable[41] = UINT8_C(0xa6);
	received = dup(t1_frame_memfd_renderer_descriptor(renderer));
	check(received >= 0, "simulate an SCM_RIGHTS descriptor");
	if (received < 0) {
		t1_frame_memfd_renderer_destroy(renderer);
		return;
	}
	owned = lowest_unused_descriptor();
	check(owned >= 0, "identify the next owned descriptor");
	check(t1_frame_memfd_reader_accept(&reader, received,
	    TEST_FRAME_BYTES) == T1_FRAME_MEMFD_OK,
	    "accept a valid sealed renderer frame");
	if (owned >= 0)
		check(fcntl(owned, F_GETFD) == FD_CLOEXEC,
		    "duplicate the received descriptor close-on-exec");
	check(fcntl(received, F_GETFD) >= 0,
	    "leave the borrowed received descriptor open");
	(void)close(received);
	if (reader != NULL) {
		memset(snapshot, 0, sizeof(snapshot));
		check(t1_frame_memfd_reader_copy(reader, snapshot,
		    sizeof(snapshot)) == T1_FRAME_MEMFD_OK &&
		    snapshot[41] == UINT8_C(0xa6),
		    "copy pixels from the hardware mapping");
		writable[41] = UINT8_C(0x5c);
		check(t1_frame_memfd_reader_copy(reader, snapshot,
		    sizeof(snapshot)) == T1_FRAME_MEMFD_OK &&
		    snapshot[41] == UINT8_C(0x5c),
		    "retain an owned duplicate after the received fd closes");
		check(t1_frame_memfd_reader_length(reader) == TEST_FRAME_BYTES,
		    "report exact reader length");
	}
	t1_frame_memfd_renderer_destroy(renderer);
	if (reader != NULL) {
		check(t1_frame_memfd_reader_copy(reader, snapshot,
		    sizeof(snapshot)) == T1_FRAME_MEMFD_OK &&
		    snapshot[41] == UINT8_C(0x5c),
		    "retain the file and mapping after renderer cleanup");
		memset(snapshot, 0xa5, sizeof(snapshot));
		check(t1_frame_memfd_reader_copy(reader, snapshot,
		    sizeof(snapshot) - 1) == T1_FRAME_MEMFD_INVALID_ARGUMENT,
		    "reject a short snapshot destination");
		check(snapshot[0] == UINT8_C(0xa5),
		    "reject snapshot length before mutation");
		check(t1_frame_memfd_reader_copy(reader, snapshot,
		    sizeof(snapshot) + 1) == T1_FRAME_MEMFD_INVALID_ARGUMENT,
		    "reject a long snapshot destination");
		check(snapshot[0] == UINT8_C(0xa5),
		    "reject long snapshot length before mutation");
		check(t1_frame_memfd_reader_copy(reader, snapshot,
		    sizeof(snapshot)) == T1_FRAME_MEMFD_OK,
		    "accept the exact snapshot destination length");
	}
	t1_frame_memfd_reader_destroy(reader);
	if (owned >= 0) {
		errno = 0;
		check(fcntl(owned, F_GETFD) < 0 && errno == EBADF,
		    "close the owned reader descriptor during cleanup");
	}
}

static void expect_invalid_file(int descriptor, uint64_t expected_length,
	const char *description)
{
	struct t1_frame_memfd_reader *reader = NULL;

	check(descriptor >= 0, "create malformed synthetic descriptor");
	if (descriptor < 0)
		return;
	check(t1_frame_memfd_reader_accept(&reader, descriptor,
	    expected_length) == T1_FRAME_MEMFD_INVALID_FILE, description);
	check(reader == NULL, "clear reader output after file rejection");
	check(fcntl(descriptor, F_GETFD) >= 0,
	    "leave rejected borrowed descriptor open");
	t1_frame_memfd_reader_destroy(reader);
	(void)close(descriptor);
}

static void test_reader_rejections(void)
{
	char temporary[] = "/tmp/t1bridge-frame-test-XXXXXX";
	int pipe_descriptors[2] = {-1, -1};
	int pipe_result;
	int descriptor;

	expect_invalid_file(raw_memfd(TEST_FRAME_BYTES, 0), TEST_FRAME_BYTES,
	    "reject a frame with no seals");
	expect_invalid_file(raw_memfd(TEST_FRAME_BYTES,
	    F_SEAL_SHRINK | F_SEAL_GROW), TEST_FRAME_BYTES,
	    "reject a frame whose seals can still change");
	expect_invalid_file(raw_memfd(TEST_FRAME_BYTES + 1, REQUIRED_SEALS),
	    TEST_FRAME_BYTES, "reject a frame with the wrong exact size");
	pipe_result = pipe(pipe_descriptors);
	check(pipe_result == 0, "create a synthetic non-regular fd");
	if (pipe_result == 0) {
		expect_invalid_file(pipe_descriptors[0], TEST_FRAME_BYTES,
		    "reject a non-regular file");
		(void)close(pipe_descriptors[1]);
	}
	descriptor = mkstemp(temporary);
	check(descriptor >= 0, "create an ordinary synthetic file");
	if (descriptor >= 0) {
		(void)unlink(temporary);
		check(ftruncate(descriptor, (off_t)TEST_FRAME_BYTES) == 0,
		    "size the ordinary synthetic file");
		expect_invalid_file(descriptor, TEST_FRAME_BYTES,
		    "reject a non-memfd anonymous regular file");
	}
	expect_invalid_file(raw_memfd(TEST_FRAME_BYTES, REQUIRED_SEALS),
	    TEST_FRAME_BYTES - 1, "reject a mismatched declared size");
	expect_invalid_file(raw_memfd(TEST_FRAME_BYTES, REQUIRED_SEALS),
	    TEST_FRAME_BYTES + 1, "reject an oversized declared size");
}

static void test_arguments_and_diagnostics(void)
{
	struct t1_frame_memfd_renderer *renderer = (void *)(uintptr_t)1;
	struct t1_frame_memfd_reader *reader = (void *)(uintptr_t)1;

	check(t1_frame_memfd_renderer_create(NULL, 1) ==
	    T1_FRAME_MEMFD_INVALID_ARGUMENT, "reject null renderer output");
	check(t1_frame_memfd_renderer_create(&renderer, 0) ==
	    T1_FRAME_MEMFD_SIZE_OUT_OF_RANGE && renderer == NULL,
	    "reject an empty renderer frame and clear output");
	renderer = (void *)(uintptr_t)1;
	check(t1_frame_memfd_renderer_create(&renderer,
	    T1_FRAME_MEMFD_MAX_BYTES + 1) ==
	    T1_FRAME_MEMFD_SIZE_OUT_OF_RANGE && renderer == NULL,
	    "reject an oversized renderer frame and clear output");
	check(t1_frame_memfd_reader_accept(NULL, 0, 1) ==
	    T1_FRAME_MEMFD_INVALID_ARGUMENT, "reject null reader output");
	check(t1_frame_memfd_reader_accept(&reader, -1, 1) ==
	    T1_FRAME_MEMFD_INVALID_ARGUMENT,
	    "reject an invalid received descriptor");
	reader = (void *)(uintptr_t)1;
	check(t1_frame_memfd_reader_accept(&reader, 0, 0) ==
	    T1_FRAME_MEMFD_SIZE_OUT_OF_RANGE && reader == NULL,
	    "reject an empty reader frame and clear output");
	check(t1_frame_memfd_renderer_descriptor(NULL) == -1,
	    "handle null renderer descriptor query");
	check(t1_frame_memfd_renderer_mapping(NULL) == NULL &&
	    t1_frame_memfd_renderer_length(NULL) == 0,
	    "handle null renderer mapping queries");
	check(t1_frame_memfd_reader_length(NULL) == 0,
	    "handle null reader length query");
	check(t1_frame_memfd_reader_copy(NULL, (uint8_t *)&reader, 1) ==
	    T1_FRAME_MEMFD_INVALID_ARGUMENT,
	    "reject a null reader snapshot");
	t1_frame_memfd_renderer_destroy(NULL);
	t1_frame_memfd_reader_destroy(NULL);
	check(strcmp(t1_frame_memfd_status_string(T1_FRAME_MEMFD_INVALID_FILE),
	    "invalid frame memory file") == 0,
	    "describe rejection without a name or path");
	check(strcmp(t1_frame_memfd_status_string(
	    (enum t1_frame_memfd_status)999),
	    "unknown frame memory failure") == 0,
	    "describe unknown status without external detail");
}

int main(void)
{
	test_renderer_frame();
	test_reader_frame();
	test_reader_rejections();
	test_arguments_and_diagnostics();

	if (failures != 0) {
		fprintf(stderr, "Frame memory: %u tests failed\n", failures);
		return 1;
	}
	puts("Frame memory: all tests passed");
	return 0;
}

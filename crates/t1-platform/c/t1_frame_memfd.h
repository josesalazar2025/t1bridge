#ifndef T1BRIDGE_T1_FRAME_MEMFD_H
#define T1BRIDGE_T1_FRAME_MEMFD_H

#include <stddef.h>
#include <stdint.h>

#define T1_FRAME_MEMFD_MAX_BYTES (UINT64_C(16) * UINT64_C(1024) * \
	UINT64_C(1024))

enum t1_frame_memfd_status {
	T1_FRAME_MEMFD_OK = 0,
	T1_FRAME_MEMFD_INVALID_ARGUMENT,
	T1_FRAME_MEMFD_SIZE_OUT_OF_RANGE,
	T1_FRAME_MEMFD_ALLOCATION_FAILED,
	T1_FRAME_MEMFD_CREATE_FAILED,
	T1_FRAME_MEMFD_RESIZE_FAILED,
	T1_FRAME_MEMFD_SEAL_FAILED,
	T1_FRAME_MEMFD_DUPLICATE_FAILED,
	T1_FRAME_MEMFD_INVALID_FILE,
	T1_FRAME_MEMFD_MAPPING_FAILED,
};

struct t1_frame_memfd_renderer;
struct t1_frame_memfd_reader;

/*
 * Create one anonymous, fixed-size renderer frame. The returned descriptor is
 * borrowed from the handle and is intended only for SCM_RIGHTS transfer. The
 * mapping remains writable until the handle is destroyed.
 */
enum t1_frame_memfd_status t1_frame_memfd_renderer_create(
	struct t1_frame_memfd_renderer **output, uint64_t byte_length);
int t1_frame_memfd_renderer_descriptor(
	const struct t1_frame_memfd_renderer *frame);
uint8_t *t1_frame_memfd_renderer_mapping(
	struct t1_frame_memfd_renderer *frame);
size_t t1_frame_memfd_renderer_length(
	const struct t1_frame_memfd_renderer *frame);
void t1_frame_memfd_renderer_destroy(struct t1_frame_memfd_renderer *frame);

/*
 * Validate and duplicate a borrowed SCM_RIGHTS descriptor. Acceptance requires
 * an anonymous regular file with the exact expected size and immutable size
 * and seal set. The hardware process can copy snapshots from an internal
 * read-only mapping without borrowing externally mutable memory.
 */
enum t1_frame_memfd_status t1_frame_memfd_reader_accept(
	struct t1_frame_memfd_reader **output, int received_descriptor,
	uint64_t expected_byte_length);
size_t t1_frame_memfd_reader_length(
	const struct t1_frame_memfd_reader *frame);
enum t1_frame_memfd_status t1_frame_memfd_reader_copy(
	const struct t1_frame_memfd_reader *frame, uint8_t *destination,
	size_t destination_length);
void t1_frame_memfd_reader_destroy(struct t1_frame_memfd_reader *frame);

const char *t1_frame_memfd_status_string(enum t1_frame_memfd_status status);

#endif

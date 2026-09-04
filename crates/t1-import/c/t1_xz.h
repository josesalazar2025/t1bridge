#ifndef T1BRIDGE_IMPORT_XZ_H
#define T1BRIDGE_IMPORT_XZ_H

#include <stddef.h>
#include <stdint.h>

#define T1_XZ_MAX_CHUNK_SIZE (UINT64_C(1) << 30)
#define T1_XZ_MAX_MEMORY_LIMIT (UINT64_C(1) << 30)

enum t1_xz_status {
	T1_XZ_OK = 0,
	T1_XZ_INVALID_ARGUMENT,
	T1_XZ_INPUT_LIMIT,
	T1_XZ_OUTPUT_LIMIT,
	T1_XZ_MEMORY_LIMIT,
	T1_XZ_ALLOCATION_FAILED,
	T1_XZ_MALFORMED,
	T1_XZ_TRUNCATED,
	T1_XZ_TRAILING_DATA,
	T1_XZ_UNSUPPORTED,
	T1_XZ_LIBRARY_ERROR,
};

/*
 * Decode exactly one complete XZ stream from one PBZX chunk. The caller owns
 * both buffers. output may be NULL only when output_capacity is zero.
 * memory_limit is passed to liblzma and cannot exceed
 * T1_XZ_MAX_MEMORY_LIMIT. On failure, bytes written to output are cleared and
 * *output_size remains zero.
 */
enum t1_xz_status t1_xz_decode(const uint8_t *input, size_t input_size,
	uint8_t *output, size_t output_capacity, uint64_t memory_limit,
	size_t *output_size);

const char *t1_xz_status_string(enum t1_xz_status status);

#endif

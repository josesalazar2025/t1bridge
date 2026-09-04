#include "t1_xz.h"

#include <lzma.h>
#include <stdbool.h>
#include <string.h>

static enum t1_xz_status map_decoder_error(lzma_ret result,
	const lzma_stream *stream)
{
	switch (result) {
	case LZMA_MEM_ERROR:
		return T1_XZ_ALLOCATION_FAILED;
	case LZMA_MEMLIMIT_ERROR:
		return T1_XZ_MEMORY_LIMIT;
	case LZMA_FORMAT_ERROR:
	case LZMA_DATA_ERROR:
		return T1_XZ_MALFORMED;
	case LZMA_BUF_ERROR:
		return stream->avail_out == 0 ? T1_XZ_OUTPUT_LIMIT :
			T1_XZ_TRUNCATED;
	case LZMA_OPTIONS_ERROR:
	case LZMA_UNSUPPORTED_CHECK:
		return T1_XZ_UNSUPPORTED;
	case LZMA_PROG_ERROR:
	default:
		return T1_XZ_LIBRARY_ERROR;
	}
}

static void clear_output(uint8_t *output, size_t capacity, uint64_t produced)
{
	size_t written = capacity;

	if (produced < (uint64_t)written)
		written = (size_t)produced;
	if (written != 0)
		memset(output, 0, written);
}

enum t1_xz_status t1_xz_decode(const uint8_t *input, size_t input_size,
	uint8_t *output, size_t output_capacity, uint64_t memory_limit,
	size_t *output_size)
{
	lzma_stream stream = LZMA_STREAM_INIT;
	lzma_ret result;
	enum t1_xz_status status = T1_XZ_LIBRARY_ERROR;
	uint8_t overflow_byte = 0;
	bool overflow_probe = false;
	uint64_t previous_input = 0;
	uint64_t previous_output = 0;
	bool stalled = false;

	if (output_size == NULL)
		return T1_XZ_INVALID_ARGUMENT;
	*output_size = 0;
	if (input == NULL || input_size == 0 ||
	    (output == NULL && output_capacity != 0))
		return T1_XZ_INVALID_ARGUMENT;
	if ((uint64_t)input_size > T1_XZ_MAX_CHUNK_SIZE)
		return T1_XZ_INPUT_LIMIT;
	if ((uint64_t)output_capacity > T1_XZ_MAX_CHUNK_SIZE)
		return T1_XZ_OUTPUT_LIMIT;
	if (memory_limit == 0 || memory_limit > T1_XZ_MAX_MEMORY_LIMIT)
		return T1_XZ_MEMORY_LIMIT;

	result = lzma_stream_decoder(&stream, memory_limit, 0);
	if (result != LZMA_OK)
		return map_decoder_error(result, &stream);

	stream.next_in = input;
	stream.avail_in = input_size;
	if (output_capacity == 0) {
		stream.next_out = &overflow_byte;
		stream.avail_out = 1;
		overflow_probe = true;
	} else {
		stream.next_out = output;
		stream.avail_out = output_capacity;
	}

	for (;;) {
		previous_input = stream.total_in;
		previous_output = stream.total_out;
		result = lzma_code(&stream, LZMA_FINISH);

		if (overflow_probe && stream.avail_out == 0) {
			status = T1_XZ_OUTPUT_LIMIT;
			break;
		}
		if (result == LZMA_STREAM_END) {
			if (stream.avail_in != 0) {
				status = T1_XZ_TRAILING_DATA;
				break;
			}
			*output_size = (size_t)stream.total_out;
			status = T1_XZ_OK;
			break;
		}
		if (result != LZMA_OK) {
			status = map_decoder_error(result, &stream);
			break;
		}
		if (stream.avail_out == 0) {
			stream.next_out = &overflow_byte;
			stream.avail_out = 1;
			overflow_probe = true;
			stalled = false;
			continue;
		}

		if (stream.total_in == previous_input &&
		    stream.total_out == previous_output) {
			if (stalled) {
				status = T1_XZ_LIBRARY_ERROR;
				break;
			}
			stalled = true;
		} else {
			stalled = false;
		}
	}

	if (status != T1_XZ_OK) {
		clear_output(output, output_capacity, stream.total_out);
		*output_size = 0;
	}
	lzma_end(&stream);
	return status;
}

const char *t1_xz_status_string(enum t1_xz_status status)
{
	switch (status) {
	case T1_XZ_OK:
		return "ok";
	case T1_XZ_INVALID_ARGUMENT:
		return "invalid argument";
	case T1_XZ_INPUT_LIMIT:
		return "XZ input limit exceeded";
	case T1_XZ_OUTPUT_LIMIT:
		return "XZ output limit exceeded";
	case T1_XZ_MEMORY_LIMIT:
		return "XZ memory limit exceeded";
	case T1_XZ_ALLOCATION_FAILED:
		return "XZ decoder allocation failed";
	case T1_XZ_MALFORMED:
		return "malformed XZ stream";
	case T1_XZ_TRUNCATED:
		return "truncated XZ stream";
	case T1_XZ_TRAILING_DATA:
		return "trailing data after XZ stream";
	case T1_XZ_UNSUPPORTED:
		return "unsupported XZ stream";
	case T1_XZ_LIBRARY_ERROR:
	default:
		return "XZ decoder failed";
	}
}

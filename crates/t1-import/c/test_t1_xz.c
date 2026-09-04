#include "t1_xz.h"

#include <lzma.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define FIXTURE_CAPACITY 65536u
#define PAYLOAD_SIZE 4096u

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
		enum t1_xz_status actual_status = (expression);                    \
		if (actual_status != (expected)) {                                \
			fprintf(stderr,                                             \
				"%s:%d: expected status %d, received %d\n",       \
				__FILE__, __LINE__, (int)(expected),                \
				(int)actual_status);                                    \
			++failures;                                                 \
		}                                                               \
	} while (0)

static size_t encode_fixture(const uint8_t *input, size_t input_size,
	uint8_t *encoded, size_t encoded_capacity)
{
	size_t encoded_size = 0;
	lzma_ret result = lzma_easy_buffer_encode(6, LZMA_CHECK_CRC64, NULL,
		input, input_size, encoded, &encoded_size, encoded_capacity);

	EXPECT_TRUE(result == LZMA_OK);
	return result == LZMA_OK ? encoded_size : 0;
}

static void fill_payload(uint8_t *payload)
{
	size_t index;

	for (index = 0; index < PAYLOAD_SIZE; ++index)
		payload[index] = (uint8_t)((index * 31u + 7u) & 0xffu);
}

static void test_round_trip_and_exact_capacity(void)
{
	uint8_t payload[PAYLOAD_SIZE];
	uint8_t encoded[FIXTURE_CAPACITY];
	uint8_t output[PAYLOAD_SIZE];
	size_t encoded_size;
	size_t output_size = 0;

	fill_payload(payload);
	encoded_size = encode_fixture(payload, sizeof(payload), encoded,
		sizeof(encoded));
	EXPECT_STATUS(T1_XZ_OK,
		t1_xz_decode(encoded, encoded_size, output, sizeof(output),
			T1_XZ_MAX_MEMORY_LIMIT, &output_size));
	EXPECT_TRUE(output_size == sizeof(payload));
	EXPECT_TRUE(memcmp(output, payload, sizeof(payload)) == 0);
}

static void test_empty_stream_with_zero_capacity(void)
{
	uint8_t encoded[FIXTURE_CAPACITY];
	size_t encoded_size = encode_fixture(NULL, 0, encoded, sizeof(encoded));
	size_t output_size = 123u;

	EXPECT_STATUS(T1_XZ_OK,
		t1_xz_decode(encoded, encoded_size, NULL, 0, 1u << 20,
			&output_size));
	EXPECT_TRUE(output_size == 0);
}

static void test_output_and_memory_limits(void)
{
	uint8_t payload[PAYLOAD_SIZE];
	uint8_t encoded[FIXTURE_CAPACITY];
	uint8_t output[31];
	size_t encoded_size;
	size_t output_size = 123u;
	size_t index;

	fill_payload(payload);
	encoded_size = encode_fixture(payload, sizeof(payload), encoded,
		sizeof(encoded));
	memset(output, 0xa5, sizeof(output));
	EXPECT_STATUS(T1_XZ_OUTPUT_LIMIT,
		t1_xz_decode(encoded, encoded_size, output, sizeof(output),
			T1_XZ_MAX_MEMORY_LIMIT, &output_size));
	EXPECT_TRUE(output_size == 0);
	for (index = 0; index < sizeof(output); ++index)
		EXPECT_TRUE(output[index] == 0);

	EXPECT_STATUS(T1_XZ_MEMORY_LIMIT,
		t1_xz_decode(encoded, encoded_size, payload, sizeof(payload), 1,
			&output_size));
	EXPECT_TRUE(output_size == 0);
	EXPECT_STATUS(T1_XZ_MEMORY_LIMIT,
		t1_xz_decode(encoded, encoded_size, payload, sizeof(payload),
			T1_XZ_MAX_MEMORY_LIMIT + 1, &output_size));
}

static void test_trailing_and_concatenated_streams(void)
{
	static const uint8_t first[] = "synthetic first stream";
	static const uint8_t second[] = "synthetic second stream";
	uint8_t encoded[FIXTURE_CAPACITY];
	uint8_t second_encoded[FIXTURE_CAPACITY];
	uint8_t output[128];
	size_t first_size;
	size_t second_size;
	size_t output_size = 123u;

	first_size = encode_fixture(first, sizeof(first), encoded,
		sizeof(encoded));
	encoded[first_size] = 0xa5;
	memset(output, 0xa5, sizeof(output));
	EXPECT_STATUS(T1_XZ_TRAILING_DATA,
		t1_xz_decode(encoded, first_size + 1, output, sizeof(output),
			1u << 26, &output_size));
	EXPECT_TRUE(output_size == 0);
	EXPECT_TRUE(output[0] == 0);

	second_size = encode_fixture(second, sizeof(second), second_encoded,
		sizeof(second_encoded));
	EXPECT_TRUE(first_size + second_size <= sizeof(encoded));
	memcpy(encoded + first_size, second_encoded, second_size);
	EXPECT_STATUS(T1_XZ_TRAILING_DATA,
		t1_xz_decode(encoded, first_size + second_size, output,
			sizeof(output), 1u << 26, &output_size));
}

static void test_truncated_and_malformed_streams(void)
{
	static const uint8_t payload[] = "synthetic integrity fixture";
	uint8_t encoded[FIXTURE_CAPACITY];
	uint8_t corrupt[FIXTURE_CAPACITY];
	uint8_t output[128];
	size_t encoded_size = encode_fixture(payload, sizeof(payload), encoded,
		sizeof(encoded));
	size_t output_size = 123u;

	EXPECT_STATUS(T1_XZ_TRUNCATED,
		t1_xz_decode(encoded, encoded_size - 4, output, sizeof(output),
			1u << 26, &output_size));
	memcpy(corrupt, encoded, encoded_size);
	corrupt[encoded_size / 2] ^= 0x80u;
	EXPECT_STATUS(T1_XZ_MALFORMED,
		t1_xz_decode(corrupt, encoded_size, output, sizeof(output),
			1u << 26, &output_size));
	EXPECT_STATUS(T1_XZ_MALFORMED,
		t1_xz_decode((const uint8_t *)"not an XZ stream", 16, output,
			sizeof(output), 1u << 26, &output_size));
}

static void test_argument_and_size_validation(void)
{
	uint8_t byte = 0;
	size_t output_size = 123u;

	EXPECT_STATUS(T1_XZ_INVALID_ARGUMENT,
		t1_xz_decode(NULL, 1, &byte, 1, 1u << 20, &output_size));
	EXPECT_STATUS(T1_XZ_INVALID_ARGUMENT,
		t1_xz_decode(&byte, 0, &byte, 1, 1u << 20, &output_size));
	EXPECT_STATUS(T1_XZ_INVALID_ARGUMENT,
		t1_xz_decode(&byte, 1, NULL, 1, 1u << 20, &output_size));
	EXPECT_STATUS(T1_XZ_INVALID_ARGUMENT,
		t1_xz_decode(&byte, 1, &byte, 1, 1u << 20, NULL));
	EXPECT_STATUS(T1_XZ_INPUT_LIMIT,
		t1_xz_decode(&byte, (size_t)T1_XZ_MAX_CHUNK_SIZE + 1u, &byte,
			1, 1u << 20, &output_size));
	EXPECT_STATUS(T1_XZ_OUTPUT_LIMIT,
		t1_xz_decode(&byte, 1, &byte,
			(size_t)T1_XZ_MAX_CHUNK_SIZE + 1u, 1u << 20,
			&output_size));
	EXPECT_STATUS(T1_XZ_MEMORY_LIMIT,
		t1_xz_decode(&byte, 1, &byte, 1, 0, &output_size));
	EXPECT_TRUE(output_size == 0);
}

static void test_status_strings_are_static_and_complete(void)
{
	enum t1_xz_status status;

	for (status = T1_XZ_OK; status <= T1_XZ_LIBRARY_ERROR;
	     status = (enum t1_xz_status)(status + 1))
		EXPECT_TRUE(t1_xz_status_string(status) != NULL);
	EXPECT_TRUE(strcmp(t1_xz_status_string((enum t1_xz_status)999),
		"XZ decoder failed") == 0);
}

int main(void)
{
	test_round_trip_and_exact_capacity();
	test_empty_stream_with_zero_capacity();
	test_output_and_memory_limits();
	test_trailing_and_concatenated_streams();
	test_truncated_and_malformed_streams();
	test_argument_and_size_validation();
	test_status_strings_are_static_and_complete();

	if (failures != 0) {
		fprintf(stderr, "%u XZ test(s) failed\n", failures);
		return 1;
	}
	puts("XZ tests passed");
	return 0;
}

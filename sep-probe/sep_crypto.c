#include "sep_crypto.h"

#include <limits.h>
#include <string.h>

#define SEP_SHA256_MARKER UINT32_C(0x53484132)

static const uint32_t round_constants[64] = {
	UINT32_C(0x428a2f98), UINT32_C(0x71374491), UINT32_C(0xb5c0fbcf),
	UINT32_C(0xe9b5dba5), UINT32_C(0x3956c25b), UINT32_C(0x59f111f1),
	UINT32_C(0x923f82a4), UINT32_C(0xab1c5ed5), UINT32_C(0xd807aa98),
	UINT32_C(0x12835b01), UINT32_C(0x243185be), UINT32_C(0x550c7dc3),
	UINT32_C(0x72be5d74), UINT32_C(0x80deb1fe), UINT32_C(0x9bdc06a7),
	UINT32_C(0xc19bf174), UINT32_C(0xe49b69c1), UINT32_C(0xefbe4786),
	UINT32_C(0x0fc19dc6), UINT32_C(0x240ca1cc), UINT32_C(0x2de92c6f),
	UINT32_C(0x4a7484aa), UINT32_C(0x5cb0a9dc), UINT32_C(0x76f988da),
	UINT32_C(0x983e5152), UINT32_C(0xa831c66d), UINT32_C(0xb00327c8),
	UINT32_C(0xbf597fc7), UINT32_C(0xc6e00bf3), UINT32_C(0xd5a79147),
	UINT32_C(0x06ca6351), UINT32_C(0x14292967), UINT32_C(0x27b70a85),
	UINT32_C(0x2e1b2138), UINT32_C(0x4d2c6dfc), UINT32_C(0x53380d13),
	UINT32_C(0x650a7354), UINT32_C(0x766a0abb), UINT32_C(0x81c2c92e),
	UINT32_C(0x92722c85), UINT32_C(0xa2bfe8a1), UINT32_C(0xa81a664b),
	UINT32_C(0xc24b8b70), UINT32_C(0xc76c51a3), UINT32_C(0xd192e819),
	UINT32_C(0xd6990624), UINT32_C(0xf40e3585), UINT32_C(0x106aa070),
	UINT32_C(0x19a4c116), UINT32_C(0x1e376c08), UINT32_C(0x2748774c),
	UINT32_C(0x34b0bcb5), UINT32_C(0x391c0cb3), UINT32_C(0x4ed8aa4a),
	UINT32_C(0x5b9cca4f), UINT32_C(0x682e6ff3), UINT32_C(0x748f82ee),
	UINT32_C(0x78a5636f), UINT32_C(0x84c87814), UINT32_C(0x8cc70208),
	UINT32_C(0x90befffa), UINT32_C(0xa4506ceb), UINT32_C(0xbef9a3f7),
	UINT32_C(0xc67178f2),
};

static uint32_t rotate_right(uint32_t value, unsigned int bits)
{
	return (value >> bits) | (value << (32U - bits));
}

static uint32_t load_u32_be(const uint8_t *input)
{
	return (uint32_t)input[0] << 24 | (uint32_t)input[1] << 16 |
	       (uint32_t)input[2] << 8 | (uint32_t)input[3];
}

static void store_u32_be(uint8_t *output, uint32_t value)
{
	output[0] = (uint8_t)(value >> 24);
	output[1] = (uint8_t)(value >> 16);
	output[2] = (uint8_t)(value >> 8);
	output[3] = (uint8_t)value;
}

static void store_u64_be(uint8_t *output, uint64_t value)
{
	for (size_t index = 0; index < sizeof(value); index++) {
		output[sizeof(value) - 1U - index] = (uint8_t)value;
		value >>= CHAR_BIT;
	}
}

static void sha256_compress(struct sep_sha256_context *context,
			    const uint8_t block[SEP_SHA256_BLOCK_SIZE])
{
	uint32_t words[64];
	uint32_t a = context->state[0];
	uint32_t b = context->state[1];
	uint32_t c = context->state[2];
	uint32_t d = context->state[3];
	uint32_t e = context->state[4];
	uint32_t f = context->state[5];
	uint32_t g = context->state[6];
	uint32_t h = context->state[7];

	for (size_t index = 0; index < 16; index++)
		words[index] = load_u32_be(block + index * sizeof(uint32_t));
	for (size_t index = 16; index < 64; index++) {
		uint32_t first = rotate_right(words[index - 15], 7) ^
				 rotate_right(words[index - 15], 18) ^
				 (words[index - 15] >> 3);
		uint32_t second = rotate_right(words[index - 2], 17) ^
				  rotate_right(words[index - 2], 19) ^
				  (words[index - 2] >> 10);

		words[index] = words[index - 16] + first + words[index - 7] +
			       second;
	}

	for (size_t index = 0; index < 64; index++) {
		uint32_t sum_one = rotate_right(e, 6) ^ rotate_right(e, 11) ^
				   rotate_right(e, 25);
		uint32_t choice = (e & f) ^ (~e & g);
		uint32_t temporary_one = h + sum_one + choice +
					 round_constants[index] + words[index];
		uint32_t sum_zero = rotate_right(a, 2) ^ rotate_right(a, 13) ^
				    rotate_right(a, 22);
		uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
		uint32_t temporary_two = sum_zero + majority;

		h = g;
		g = f;
		f = e;
		e = d + temporary_one;
		d = c;
		c = b;
		b = a;
		a = temporary_one + temporary_two;
	}

	context->state[0] += a;
	context->state[1] += b;
	context->state[2] += c;
	context->state[3] += d;
	context->state[4] += e;
	context->state[5] += f;
	context->state[6] += g;
	context->state[7] += h;
	sep_crypto_wipe(words, sizeof(words));
}

static int sha256_context_valid(const struct sep_sha256_context *context)
{
	const uint64_t maximum_bytes = UINT64_MAX / CHAR_BIT;

	return context && context->marker == SEP_SHA256_MARKER &&
	       context->buffer_length < SEP_SHA256_BLOCK_SIZE &&
	       context->total_length <= maximum_bytes &&
	       context->buffer_length ==
		       context->total_length % SEP_SHA256_BLOCK_SIZE;
}

int sep_sha256_init(struct sep_sha256_context *context)
{
	if (!context)
		return -1;

	memset(context, 0, sizeof(*context));
	context->state[0] = UINT32_C(0x6a09e667);
	context->state[1] = UINT32_C(0xbb67ae85);
	context->state[2] = UINT32_C(0x3c6ef372);
	context->state[3] = UINT32_C(0xa54ff53a);
	context->state[4] = UINT32_C(0x510e527f);
	context->state[5] = UINT32_C(0x9b05688c);
	context->state[6] = UINT32_C(0x1f83d9ab);
	context->state[7] = UINT32_C(0x5be0cd19);
	context->marker = SEP_SHA256_MARKER;
	return 0;
}

int sep_sha256_update(struct sep_sha256_context *context, const void *data,
		      size_t length)
{
	const uint8_t *input = data;
	const uint64_t maximum_bytes = UINT64_MAX / CHAR_BIT;

	if (!sha256_context_valid(context) || (!data && length != 0))
		return -1;
	if (length == 0)
		return 0;
	if (length > maximum_bytes ||
	    (uint64_t)length > maximum_bytes - context->total_length)
		return -1;

	context->total_length += (uint64_t)length;
	if (context->buffer_length != 0) {
		size_t available = SEP_SHA256_BLOCK_SIZE - context->buffer_length;
		size_t copied = length < available ? length : available;

		memcpy(context->buffer + context->buffer_length, input, copied);
		context->buffer_length += copied;
		input += copied;
		length -= copied;
		if (context->buffer_length == SEP_SHA256_BLOCK_SIZE) {
			sha256_compress(context, context->buffer);
			context->buffer_length = 0;
		}
	}

	while (length >= SEP_SHA256_BLOCK_SIZE) {
		sha256_compress(context, input);
		input += SEP_SHA256_BLOCK_SIZE;
		length -= SEP_SHA256_BLOCK_SIZE;
	}
	if (length != 0) {
		memcpy(context->buffer, input, length);
		context->buffer_length = length;
	}
	return 0;
}

int sep_sha256_final(struct sep_sha256_context *context,
		     uint8_t digest[SEP_SHA256_DIGEST_SIZE])
{
	uint64_t bit_length;

	if (!digest || !sha256_context_valid(context))
		return -1;

	bit_length = context->total_length * CHAR_BIT;
	context->buffer[context->buffer_length++] = UINT8_C(0x80);
	if (context->buffer_length > SEP_SHA256_BLOCK_SIZE - sizeof(bit_length)) {
		memset(context->buffer + context->buffer_length, 0,
		       SEP_SHA256_BLOCK_SIZE - context->buffer_length);
		sha256_compress(context, context->buffer);
		context->buffer_length = 0;
	}
	memset(context->buffer + context->buffer_length, 0,
	       SEP_SHA256_BLOCK_SIZE - sizeof(bit_length) -
		       context->buffer_length);
	store_u64_be(context->buffer + SEP_SHA256_BLOCK_SIZE - sizeof(bit_length),
		     bit_length);
	sha256_compress(context, context->buffer);

	for (size_t index = 0; index < 8; index++)
		store_u32_be(digest + index * sizeof(uint32_t),
			     context->state[index]);
	sep_crypto_wipe(context, sizeof(*context));
	return 0;
}

int sep_crypto_equal(const void *left, const void *right, size_t length)
{
	const uint8_t *left_bytes = left;
	const uint8_t *right_bytes = right;
	volatile uint8_t difference = 0;

	if (length == 0)
		return 1;
	if (!left || !right)
		return 0;
	for (size_t index = 0; index < length; index++)
		difference |= left_bytes[index] ^ right_bytes[index];
	return difference == 0;
}

void sep_crypto_wipe(void *data, size_t length)
{
	volatile uint8_t *bytes = data;

	if (!data)
		return;
	while (length-- != 0)
		*bytes++ = 0;
}

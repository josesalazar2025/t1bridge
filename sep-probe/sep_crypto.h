#ifndef SEP_CRYPTO_H
#define SEP_CRYPTO_H

#include <stddef.h>
#include <stdint.h>

#define SEP_SHA256_BLOCK_SIZE 64U
#define SEP_SHA256_DIGEST_SIZE 32U

struct sep_sha256_context {
	uint32_t state[8];
	uint64_t total_length;
	size_t buffer_length;
	uint32_t marker;
	uint8_t buffer[SEP_SHA256_BLOCK_SIZE];
};

int sep_sha256_init(struct sep_sha256_context *context);
int sep_sha256_update(struct sep_sha256_context *context, const void *data,
		      size_t length);
int sep_sha256_final(struct sep_sha256_context *context,
		     uint8_t digest[SEP_SHA256_DIGEST_SIZE]);

/* Zero-length inputs may be null. Other null inputs are rejected. */
int sep_crypto_equal(const void *left, const void *right, size_t length);
void sep_crypto_wipe(void *data, size_t length);

#endif

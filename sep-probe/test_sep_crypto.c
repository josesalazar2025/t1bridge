#include "sep_crypto.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void check(int condition, const char *description)
{
	if (condition)
		return;
	fprintf(stderr, "FAIL: %s\n", description);
	failures++;
}

static int decode_hex(uint8_t *output, size_t output_length, const char *hex)
{
	for (size_t index = 0; index < output_length; index++) {
		unsigned int high;
		unsigned int low;
		char first = hex[index * 2];
		char second = hex[index * 2 + 1];

		if (first >= '0' && first <= '9')
			high = (unsigned int)(first - '0');
		else if (first >= 'a' && first <= 'f')
			high = (unsigned int)(first - 'a') + 10U;
		else
			return -1;
		if (second >= '0' && second <= '9')
			low = (unsigned int)(second - '0');
		else if (second >= 'a' && second <= 'f')
			low = (unsigned int)(second - 'a') + 10U;
		else
			return -1;
		output[index] = (uint8_t)(high << 4 | low);
	}
	return hex[output_length * 2] == '\0' ? 0 : -1;
}

static void check_hash(const void *input, size_t input_length,
		       const char *expected_hex, const char *description)
{
	struct sep_sha256_context context;
	uint8_t digest[SEP_SHA256_DIGEST_SIZE];
	uint8_t expected[SEP_SHA256_DIGEST_SIZE];

	check(decode_hex(expected, sizeof(expected), expected_hex) == 0,
	      "decode expected digest");
	check(sep_sha256_init(&context) == 0, "initialize hash");
	check(sep_sha256_update(&context, input, input_length) == 0,
	      "update hash");
	check(sep_sha256_final(&context, digest) == 0, "finalize hash");
	check(sep_crypto_equal(digest, expected, sizeof(digest)), description);
	sep_crypto_wipe(digest, sizeof(digest));
	sep_crypto_wipe(expected, sizeof(expected));
}

static void test_hash_vectors(void)
{
	static const char multi_block[] =
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	static const char long_multi_block[] =
		"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
		"hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

	check_hash(NULL, 0,
		   "e3b0c44298fc1c149afbf4c8996fb924"
		   "27ae41e4649b934ca495991b7852b855",
		   "SHA-256 empty vector");
	check_hash("abc", 3,
		   "ba7816bf8f01cfea414140de5dae2223"
		   "b00361a396177a9cb410ff61f20015ad",
		   "SHA-256 abc vector");
	check_hash(multi_block, sizeof(multi_block) - 1,
		   "248d6a61d20638b8e5c026930c3e6039"
		   "a33ce45964ff2167f6ecedd419db06c1",
		   "SHA-256 NIST multi-block vector");
	check_hash(long_multi_block, sizeof(long_multi_block) - 1,
		   "cf5b16a778af8380036ce59e7b049237"
		   "0b249b11e8f07a51afac45037afee9d1",
		   "SHA-256 NIST long multi-block vector");
}

static void test_split_updates(void)
{
	static const uint8_t input[] =
		"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
		"hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
	struct sep_sha256_context context;
	uint8_t digest[SEP_SHA256_DIGEST_SIZE];
	uint8_t expected[SEP_SHA256_DIGEST_SIZE];
	static const size_t splits[] = { 1, 63, 1, 47 };
	size_t offset = 0;

	check(decode_hex(expected, sizeof(expected),
			 "cf5b16a778af8380036ce59e7b049237"
			 "0b249b11e8f07a51afac45037afee9d1") == 0,
	      "decode split digest");
	check(sep_sha256_init(&context) == 0, "initialize split hash");
	check(sep_sha256_update(&context, NULL, 0) == 0,
	      "accept empty update");
	for (size_t index = 0; index < sizeof(splits) / sizeof(splits[0]);
	     index++) {
		check(sep_sha256_update(&context, input + offset, splits[index]) ==
			      0,
		      "accept split update");
		offset += splits[index];
		check(sep_sha256_update(&context, NULL, 0) == 0,
		      "accept empty update with buffered data");
	}
	check(offset == sizeof(input) - 1, "split lengths cover input");
	check(sep_sha256_final(&context, digest) == 0, "finalize split hash");
	check(sep_crypto_equal(digest, expected, sizeof(digest)),
	      "split and one-shot hashes match");
	check(sep_sha256_final(&context, digest) < 0,
	      "reject finalization after context wipe");
}

static void test_constant_time_equality(void)
{
	uint8_t left[9] = { 0, 1, 2, 3, 4, 5, 6, 7, 8 };
	uint8_t right[sizeof(left)];

	memcpy(right, left, sizeof(left));
	check(sep_crypto_equal(left, right, sizeof(left)), "equal buffers");
	right[0] ^= 1U;
	check(!sep_crypto_equal(left, right, sizeof(left)), "first-byte mismatch");
	memcpy(right, left, sizeof(left));
	right[sizeof(right) / 2] ^= 1U;
	check(!sep_crypto_equal(left, right, sizeof(left)), "middle-byte mismatch");
	memcpy(right, left, sizeof(left));
	right[sizeof(right) - 1] ^= 1U;
	check(!sep_crypto_equal(left, right, sizeof(left)), "last-byte mismatch");
	check(sep_crypto_equal(NULL, NULL, 0), "empty buffers compare equal");
	check(!sep_crypto_equal(NULL, right, sizeof(right)),
	      "reject null nonempty input");
}

static void test_wipe(void)
{
	uint8_t secret[37];

	memset(secret, 0xa5, sizeof(secret));
	sep_crypto_wipe(secret, sizeof(secret));
	for (size_t index = 0; index < sizeof(secret); index++)
		check(secret[index] == 0, "wipe every byte");
	sep_crypto_wipe(NULL, 0);
}

static void test_invalid_hash_inputs(void)
{
	struct sep_sha256_context context;
	uint8_t digest[SEP_SHA256_DIGEST_SIZE];

	check(sep_sha256_init(NULL) < 0, "reject null context initialization");
	check(sep_sha256_init(&context) == 0, "initialize defensive hash");
	check(sep_sha256_update(&context, NULL, 1) < 0,
	      "reject null nonempty update");
	context.total_length = UINT64_MAX / 8;
	check(sep_sha256_update(&context, "x", 1) < 0,
	      "reject SHA-256 length overflow");
	check(sep_sha256_final(&context, NULL) < 0, "reject null digest");
	check(sep_sha256_init(&context) == 0, "reinitialize defensive hash");
	context.buffer_length = SEP_SHA256_BLOCK_SIZE;
	check(sep_sha256_final(&context, digest) < 0,
	      "reject invalid buffered length");
	check(sep_sha256_init(&context) == 0, "restore defensive hash");
	check(sep_sha256_final(&context, digest) == 0,
	      "context remains usable after rejected inputs");
}

int main(void)
{
	test_hash_vectors();
	test_split_updates();
	test_constant_time_equality();
	test_wipe();
	test_invalid_hash_inputs();
	if (failures != 0) {
		fprintf(stderr, "%d test failure(s)\n", failures);
		return 1;
	}
	puts("sep_crypto: all tests passed");
	return 0;
}

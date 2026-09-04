#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "sep_keybag.h"
#include "sep_crypto.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static unsigned int failures;

#define TEST_STATE_PREFIX_SIZE 24U
#define TEST_STATE_HEADER_SIZE \
	(TEST_STATE_PREFIX_SIZE + SEP_SHA256_DIGEST_SIZE)

static const uint8_t legacy_state_magic[8] = {
	'T', '1', 'K', 'B', 'A', 'G', '0', '1'
};

#define EXPECT(condition) test_expect((condition), #condition, __LINE__)

static void test_expect(int condition, const char *expression, int line)
{
	if (!condition) {
		fprintf(stderr, "line %d: failed: %s\n", line, expression);
		++failures;
	}
}

static int all_zero(const void *data, size_t length)
{
	const uint8_t *bytes = data;

	for (size_t index = 0; index < length; ++index) {
		if (bytes[index] != 0)
			return 0;
	}
	return 1;
}

static int read_all(int descriptor, uint8_t *output, size_t length)
{
	size_t offset = 0;

	while (offset < length) {
		ssize_t received = read(descriptor, output + offset,
					length - offset);

		if (received <= 0)
			return -1;
		offset += (size_t)received;
	}
	return 0;
}

static int write_all(int descriptor, const uint8_t *input, size_t length)
{
	size_t offset = 0;

	while (offset < length) {
		ssize_t written = write(descriptor, input + offset,
					length - offset);

		if (written <= 0)
			return -1;
		offset += (size_t)written;
	}
	return 0;
}

static int rewrite_with_legacy_magic(int directory_descriptor)
{
	struct sep_sha256_context digest_context;
	uint8_t digest[SEP_SHA256_DIGEST_SIZE] = { 0 };
	uint8_t *state = NULL;
	struct stat status;
	size_t length = 0;
	int descriptor = -1;
	int result = -1;

	descriptor = openat(directory_descriptor, SEP_KEYBAG_STATE_FILENAME,
			    O_RDWR | O_NOFOLLOW | O_CLOEXEC);
	if (descriptor < 0 || fstat(descriptor, &status) != 0 ||
	    status.st_size <= (off_t)TEST_STATE_HEADER_SIZE)
		goto out;
	length = (size_t)status.st_size;
	state = malloc(length);
	if (!state || read_all(descriptor, state, length) != 0)
		goto out;
	memcpy(state, legacy_state_magic, sizeof(legacy_state_magic));
	if (sep_sha256_init(&digest_context) != 0 ||
	    sep_sha256_update(&digest_context, state, TEST_STATE_PREFIX_SIZE) !=
		    0 ||
	    sep_sha256_update(&digest_context, state + TEST_STATE_HEADER_SIZE,
			      length - TEST_STATE_HEADER_SIZE) != 0 ||
	    sep_sha256_final(&digest_context, digest) != 0)
		goto out;
	memcpy(state + TEST_STATE_PREFIX_SIZE, digest, sizeof(digest));
	if (lseek(descriptor, 0, SEEK_SET) < 0 ||
	    write_all(descriptor, state, length) != 0 || fsync(descriptor) != 0)
		goto out;
	result = 0;

out:
	if (descriptor >= 0)
		(void)close(descriptor);
	if (state) {
		sep_crypto_wipe(state, length);
		free(state);
	}
	sep_crypto_wipe(digest, sizeof(digest));
	return result;
}

static int open_test_directory(char path[64])
{
	memcpy(path, "/tmp/t1bridge-keybag-XXXXXX",
	       sizeof("/tmp/t1bridge-keybag-XXXXXX"));
	if (!mkdtemp(path) || chmod(path, 0700) != 0)
		return -1;
	return open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}

static void remove_test_directory(const char *path, int descriptor)
{
	if (descriptor >= 0) {
		(void)unlinkat(descriptor, SEP_KEYBAG_STATE_FILENAME, 0);
		(void)unlinkat(descriptor, ".keybag.state.new", 0);
		(void)close(descriptor);
	}
	if (path[0] != '\0')
		(void)rmdir(path);
}

static void test_round_trip_is_private_durable_and_absent_only(void)
{
	char path[64] = { 0 };
	struct sep_keybag_material original = { 0 };
	struct sep_keybag_material loaded;
	struct sep_keybag_material replacement = { 0 };
	struct stat status;
	int descriptor = open_test_directory(path);
	int state_descriptor;

	EXPECT(descriptor >= 0);
	if (descriptor < 0)
		return;
	memset(&loaded, 0xa5, sizeof(loaded));
	EXPECT(sep_keybag_state_load_at(
		       descriptor, (uint32_t)geteuid(), &loaded) ==
	       SEP_KEYBAG_STORE_ABSENT);
	EXPECT(all_zero(&loaded, sizeof(loaded)));
	memset(original.secret, 0x5a, sizeof(original.secret));
	memcpy(original.blob, (const uint8_t[]){ 1, 3, 5, 7, 9 }, 5);
	original.blob_length = 5;
	EXPECT(symlinkat("unsafe-stale-object", descriptor,
			 ".keybag.state.new") == 0);
	EXPECT(sep_keybag_state_persist_absent_at(
		       descriptor, (uint32_t)geteuid(), &original) == 0);
	EXPECT(fstatat(descriptor, ".keybag.state.new", &status,
		       AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(status.st_mode));
	state_descriptor = openat(
		descriptor, SEP_KEYBAG_STATE_FILENAME,
		O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	EXPECT(state_descriptor >= 0 && fstat(state_descriptor, &status) == 0 &&
	       S_ISREG(status.st_mode) && status.st_nlink == 1 &&
	       (status.st_mode & 07777U) == 0600U);
	if (state_descriptor >= 0)
		(void)close(state_descriptor);
	EXPECT(sep_keybag_state_load_at(
		       descriptor, (uint32_t)geteuid(), &loaded) ==
	       SEP_KEYBAG_STORE_EXISTING);
	EXPECT(loaded.blob_length == original.blob_length &&
	       memcmp(loaded.secret, original.secret, sizeof(original.secret)) ==
		       0 &&
	       memcmp(loaded.blob, original.blob, original.blob_length) == 0);
	memset(replacement.secret, 0xc3, sizeof(replacement.secret));
	memset(replacement.blob, 0xc3, 4);
	replacement.blob_length = 4;
	EXPECT(sep_keybag_state_persist_absent_at(
		       descriptor, (uint32_t)geteuid(), &replacement) != 0);
	memset(&loaded, 0, sizeof(loaded));
	EXPECT(sep_keybag_state_load_at(
		       descriptor, (uint32_t)geteuid(), &loaded) ==
	       SEP_KEYBAG_STORE_EXISTING);
	EXPECT(loaded.blob_length == original.blob_length &&
	       memcmp(loaded.secret, original.secret, sizeof(original.secret)) ==
		       0);
	sep_crypto_wipe(&original, sizeof(original));
	sep_crypto_wipe(&loaded, sizeof(loaded));
	sep_crypto_wipe(&replacement, sizeof(replacement));
	remove_test_directory(path, descriptor);
}

static void test_unsafe_metadata_and_corruption_fail_closed(void)
{
	char path[64] = { 0 };
	struct sep_keybag_material material = { 0 };
	struct sep_keybag_material loaded;
	uint8_t byte = 0;
	int descriptor = open_test_directory(path);
	int state_descriptor;

	EXPECT(descriptor >= 0);
	if (descriptor < 0)
		return;
	memset(material.secret, 0x11, sizeof(material.secret));
	material.blob[0] = 0x22;
	material.blob_length = 1;
	EXPECT(sep_keybag_state_persist_absent_at(
		       descriptor, (uint32_t)geteuid(), &material) == 0);
	EXPECT(fchmodat(
		       descriptor, SEP_KEYBAG_STATE_FILENAME, 0640, 0) == 0);
	memset(&loaded, 0xa5, sizeof(loaded));
	EXPECT(sep_keybag_state_load_at(
		       descriptor, (uint32_t)geteuid(), &loaded) ==
	       SEP_KEYBAG_STORE_ERROR);
	EXPECT(all_zero(&loaded, sizeof(loaded)));
	EXPECT(fchmodat(
		       descriptor, SEP_KEYBAG_STATE_FILENAME, 0600, 0) == 0);
	state_descriptor = openat(
		descriptor, SEP_KEYBAG_STATE_FILENAME,
		O_RDWR | O_NOFOLLOW | O_CLOEXEC);
	EXPECT(state_descriptor >= 0 && pread(state_descriptor, &byte, 1, 0) == 1);
	byte ^= UINT8_C(0x80);
	EXPECT(state_descriptor >= 0 && pwrite(state_descriptor, &byte, 1, 0) == 1);
	if (state_descriptor >= 0)
		(void)close(state_descriptor);
	memset(&loaded, 0xa5, sizeof(loaded));
	EXPECT(sep_keybag_state_load_at(
		       descriptor, (uint32_t)geteuid(), &loaded) ==
	       SEP_KEYBAG_STORE_ERROR);
	EXPECT(all_zero(&loaded, sizeof(loaded)));
	sep_crypto_wipe(&material, sizeof(material));
	sep_crypto_wipe(&loaded, sizeof(loaded));
	remove_test_directory(path, descriptor);
}

static void test_legacy_magic_remains_read_compatible(void)
{
	char path[64] = { 0 };
	struct sep_keybag_material material = { 0 };
	struct sep_keybag_material loaded;
	int descriptor = open_test_directory(path);

	EXPECT(descriptor >= 0);
	if (descriptor < 0)
		return;
	memset(material.secret, 0x37, sizeof(material.secret));
	memcpy(material.blob, (const uint8_t[]){ 2, 4, 6, 8 }, 4);
	material.blob_length = 4;
	EXPECT(sep_keybag_state_persist_absent_at(
		       descriptor, (uint32_t)geteuid(), &material) == 0);
	EXPECT(rewrite_with_legacy_magic(descriptor) == 0);
	memset(&loaded, 0, sizeof(loaded));
	EXPECT(sep_keybag_state_load_at(
		       descriptor, (uint32_t)geteuid(), &loaded) ==
	       SEP_KEYBAG_STORE_EXISTING);
	EXPECT(loaded.blob_length == material.blob_length &&
	       memcmp(loaded.secret, material.secret, sizeof(material.secret)) ==
		       0 &&
	       memcmp(loaded.blob, material.blob, material.blob_length) == 0);
	sep_crypto_wipe(&material, sizeof(material));
	sep_crypto_wipe(&loaded, sizeof(loaded));
	remove_test_directory(path, descriptor);
}

static void test_unsafe_directory_is_rejected(void)
{
	char path[64] = { 0 };
	struct sep_keybag_material material = { 0 };
	int descriptor = open_test_directory(path);

	EXPECT(descriptor >= 0);
	if (descriptor < 0)
		return;
	EXPECT(fchmod(descriptor, 0750) == 0);
	EXPECT(sep_keybag_state_load_at(
		       descriptor, (uint32_t)geteuid(), &material) ==
	       SEP_KEYBAG_STORE_ERROR);
	EXPECT(sep_keybag_state_persist_absent_at(
		       descriptor, (uint32_t)geteuid(), &material) != 0);
	EXPECT(fchmod(descriptor, 0700) == 0);
	remove_test_directory(path, descriptor);
}

int main(void)
{
	test_round_trip_is_private_durable_and_absent_only();
	test_legacy_magic_remains_read_compatible();
	test_unsafe_metadata_and_corruption_fail_closed();
	test_unsafe_directory_is_rejected();
	if (failures != 0) {
		fprintf(stderr, "sep_keybag_store: %u tests failed\n", failures);
		return 1;
	}
	puts("sep_keybag_store: all tests passed");
	return 0;
}

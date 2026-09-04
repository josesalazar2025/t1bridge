#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "sep_keybag.h"

#include "sep_crypto.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#define STATE_VERSION 1U
#define STATE_PREFIX_SIZE 24U
#define STATE_HEADER_SIZE (STATE_PREFIX_SIZE + SEP_SHA256_DIGEST_SIZE)
#define STATE_TEMPORARY_PREFIX ".keybag.state.new."
#define STATE_TEMPORARY_RANDOM_SIZE 16U
#define STATE_TEMPORARY_NAME_SIZE \
	(sizeof(STATE_TEMPORARY_PREFIX) + 2U * STATE_TEMPORARY_RANDOM_SIZE)
#define STATE_TEMPORARY_ATTEMPTS 4U

static const uint8_t state_magic[8] = {
	'T', '1', 'K', 'B', 'A', 'G', '0', '2'
};

static const uint8_t legacy_state_magic[8] = {
	'T', '1', 'K', 'B', 'A', 'G', '0', '1'
};

static uint32_t load_u32_le(const uint8_t *input)
{
	return (uint32_t)input[0] | (uint32_t)input[1] << 8 |
	       (uint32_t)input[2] << 16 | (uint32_t)input[3] << 24;
}

static void store_u32_le(uint8_t *output, uint32_t value)
{
	output[0] = (uint8_t)value;
	output[1] = (uint8_t)(value >> 8);
	output[2] = (uint8_t)(value >> 16);
	output[3] = (uint8_t)(value >> 24);
}

static int state_digest(const uint8_t *state, size_t length,
			uint8_t digest[SEP_SHA256_DIGEST_SIZE])
{
	struct sep_sha256_context context;
	int result = -1;

	if (!state || length < STATE_HEADER_SIZE || !digest ||
	    sep_sha256_init(&context) != 0)
		return -1;
	if (sep_sha256_update(&context, state, STATE_PREFIX_SIZE) == 0 &&
	    sep_sha256_update(&context, state + STATE_HEADER_SIZE,
			      length - STATE_HEADER_SIZE) == 0 &&
	    sep_sha256_final(&context, digest) == 0)
		result = 0;
	else
		sep_crypto_wipe(&context, sizeof(context));
	return result;
}

static int valid_directory(int descriptor, uint32_t expected_owner)
{
	struct stat status;

	return descriptor >= 0 && fstat(descriptor, &status) == 0 &&
	       S_ISDIR(status.st_mode) && status.st_uid == expected_owner &&
	       (status.st_mode & 07777U) == 0700U;
}

static int valid_state_file(int descriptor, uint32_t expected_owner,
			    struct stat *status)
{
	return descriptor >= 0 && status && fstat(descriptor, status) == 0 &&
	       S_ISREG(status->st_mode) && status->st_uid == expected_owner &&
	       status->st_nlink == 1 && (status->st_mode & 07777U) == 0600U;
}

static int read_all(int descriptor, uint8_t *output, size_t length)
{
	size_t offset = 0;

	while (offset < length) {
		ssize_t result = read(descriptor, output + offset, length - offset);

		if (result > 0) {
			offset += (size_t)result;
			continue;
		}
		if (result < 0 && errno == EINTR)
			continue;
		return -1;
	}
	return 0;
}

static int write_all(int descriptor, const uint8_t *input, size_t length)
{
	size_t offset = 0;

	while (offset < length) {
		ssize_t result = write(descriptor, input + offset, length - offset);

		if (result > 0) {
			offset += (size_t)result;
			continue;
		}
		if (result < 0 && errno == EINTR)
			continue;
		return -1;
	}
	return 0;
}

static int random_temporary_name(char output[STATE_TEMPORARY_NAME_SIZE])
{
	static const char hexadecimal[] = "0123456789abcdef";
	uint8_t random[STATE_TEMPORARY_RANDOM_SIZE];
	size_t offset = 0;
	size_t prefix_length = sizeof(STATE_TEMPORARY_PREFIX) - 1U;
	int result = -1;

	while (offset < sizeof(random)) {
		ssize_t received = getrandom(
			random + offset, sizeof(random) - offset, 0);

		if (received > 0) {
			offset += (size_t)received;
			continue;
		}
		if (received < 0 && errno == EINTR)
			continue;
		goto cleanup;
	}
	memcpy(output, STATE_TEMPORARY_PREFIX, prefix_length);
	for (size_t index = 0; index < sizeof(random); ++index) {
		output[prefix_length + 2U * index] =
			hexadecimal[random[index] >> 4];
		output[prefix_length + 2U * index + 1U] =
			hexadecimal[random[index] & 0x0fU];
	}
	output[prefix_length + 2U * sizeof(random)] = '\0';
	result = 0;

cleanup:
	sep_crypto_wipe(random, sizeof(random));
	return result;
}

int sep_keybag_state_load_at(int directory_descriptor,
			     uint32_t expected_owner,
			     struct sep_keybag_material *material)
{
	uint8_t digest[SEP_SHA256_DIGEST_SIZE] = { 0 };
	uint8_t extra;
	uint8_t *state = NULL;
	struct stat status;
	size_t length = 0;
	size_t expected_length;
	uint32_t blob_length;
	int descriptor = -1;
	int result = SEP_KEYBAG_STORE_ERROR;

	if (!material || !valid_directory(directory_descriptor, expected_owner))
		return SEP_KEYBAG_STORE_ERROR;
	sep_crypto_wipe(material, sizeof(*material));
	descriptor = openat(directory_descriptor, SEP_KEYBAG_STATE_FILENAME,
			    O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (descriptor < 0) {
		if (errno == ENOENT)
			result = SEP_KEYBAG_STORE_ABSENT;
		goto out;
	}
	if (!valid_state_file(descriptor, expected_owner, &status) ||
	    status.st_size < (off_t)(STATE_HEADER_SIZE +
				       SEP_KEYSTORE_SECRET_SIZE + 1U) ||
	    status.st_size > (off_t)(STATE_HEADER_SIZE +
				       SEP_KEYSTORE_SECRET_SIZE +
				       SEP_KEYBAG_MAX_SERIALIZED_SIZE))
		goto out;
	length = (size_t)status.st_size;
	state = malloc(length);
	if (!state || read_all(descriptor, state, length) != 0 ||
	    read(descriptor, &extra, 1) != 0)
		goto out;
	blob_length = load_u32_le(state + 16U);
	expected_length = STATE_HEADER_SIZE + SEP_KEYSTORE_SECRET_SIZE +
			  (size_t)blob_length;
	if ((memcmp(state, state_magic, sizeof(state_magic)) != 0 &&
	     memcmp(state, legacy_state_magic,
		    sizeof(legacy_state_magic)) != 0) ||
	    load_u32_le(state + 8U) != STATE_VERSION ||
	    load_u32_le(state + 12U) != SEP_KEYSTORE_SECRET_SIZE ||
	    blob_length == 0 || blob_length > SEP_KEYBAG_MAX_SERIALIZED_SIZE ||
	    load_u32_le(state + 20U) != 0 || expected_length != length ||
	    state_digest(state, length, digest) != 0 ||
	    !sep_crypto_equal(digest, state + STATE_PREFIX_SIZE,
			      sizeof(digest)))
		goto out;
	memcpy(material->secret, state + STATE_HEADER_SIZE,
	       sizeof(material->secret));
	memcpy(material->blob,
	       state + STATE_HEADER_SIZE + sizeof(material->secret),
	       blob_length);
	material->blob_length = blob_length;
	result = SEP_KEYBAG_STORE_EXISTING;

out:
	if (result != SEP_KEYBAG_STORE_EXISTING)
		sep_crypto_wipe(material, sizeof(*material));
	if (descriptor >= 0)
		(void)close(descriptor);
	if (state) {
		sep_crypto_wipe(state, length);
		free(state);
	}
	sep_crypto_wipe(digest, sizeof(digest));
	return result;
}

int sep_keybag_state_persist_absent_at(
	int directory_descriptor, uint32_t expected_owner,
	const struct sep_keybag_material *material)
{
	uint8_t digest[SEP_SHA256_DIGEST_SIZE] = { 0 };
	uint8_t *state = NULL;
	char temporary_name[STATE_TEMPORARY_NAME_SIZE] = { 0 };
	struct stat status;
	size_t length = 0;
	int descriptor = -1;
	int temporary_created = 0;
	int renamed = 0;
	int result = -1;

	if (!material || material->blob_length == 0 ||
	    material->blob_length > SEP_KEYBAG_MAX_SERIALIZED_SIZE ||
	    !valid_directory(directory_descriptor, expected_owner))
		return -1;
	if (fstatat(directory_descriptor, SEP_KEYBAG_STATE_FILENAME, &status,
		    AT_SYMLINK_NOFOLLOW) == 0 || errno != ENOENT)
		return -1;
	length = STATE_HEADER_SIZE + sizeof(material->secret) +
		 material->blob_length;
	state = calloc(1, length);
	if (!state)
		goto out;
	memcpy(state, state_magic, sizeof(state_magic));
	store_u32_le(state + 8U, STATE_VERSION);
	store_u32_le(state + 12U, SEP_KEYSTORE_SECRET_SIZE);
	store_u32_le(state + 16U, (uint32_t)material->blob_length);
	memcpy(state + STATE_HEADER_SIZE, material->secret,
	       sizeof(material->secret));
	memcpy(state + STATE_HEADER_SIZE + sizeof(material->secret),
	       material->blob, material->blob_length);
	if (state_digest(state, length, digest) != 0)
		goto out;
	memcpy(state + STATE_PREFIX_SIZE, digest, sizeof(digest));
	for (unsigned int attempt = 0; attempt < STATE_TEMPORARY_ATTEMPTS;
	     ++attempt) {
		if (random_temporary_name(temporary_name) != 0)
			goto out;
		descriptor = openat(
			directory_descriptor, temporary_name,
			O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
			0600);
		if (descriptor >= 0) {
			temporary_created = 1;
			break;
		}
		if (errno != EEXIST)
			goto out;
	}
	if (!valid_state_file(descriptor, expected_owner, &status) ||
	    write_all(descriptor, state, length) != 0 || fsync(descriptor) != 0)
		goto out;
	{
		int close_result = close(descriptor);

		descriptor = -1;
		if (close_result != 0)
			goto out;
	}
	if (renameat2(directory_descriptor, temporary_name,
		      directory_descriptor, SEP_KEYBAG_STATE_FILENAME,
		      RENAME_NOREPLACE) != 0)
		goto out;
	renamed = 1;
	if (fsync(directory_descriptor) != 0)
		goto out;
	result = 0;

out:
	if (descriptor >= 0)
		(void)close(descriptor);
	if (temporary_created && !renamed)
		(void)unlinkat(directory_descriptor, temporary_name, 0);
	if (state) {
		sep_crypto_wipe(state, length);
		free(state);
	}
	sep_crypto_wipe(digest, sizeof(digest));
	sep_crypto_wipe(temporary_name, sizeof(temporary_name));
	return result;
}

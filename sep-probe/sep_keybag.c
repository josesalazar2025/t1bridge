#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include "sep_keybag.h"

#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define KEYBAG_STATE_BEEN_UNLOCKED UINT32_C(0x04)
#define USER_CONFIGURATION_SIZE 68U
#define DEVICE_KEYBAG_HANDLE 0
#define DEFAULT_SYSTEM_KEYBAG_HANDLE (-3)
#define BIOMETRIC_UID UINT32_C(501)

static const uint8_t compatibility_user_uuid[SEP_KEYSTORE_UUID_SIZE] = {
	0xff, 0xff, 0xee, 0xee, 0xdd, 0xdd, 0xcc, 0xcc,
	0xbb, 0xbb, 0xaa, 0xaa, 0x00, 0x00, 0x01, 0xf5,
};

struct keybag_operation_context {
	const struct sep_keybag_store_ops *store;
	enum sep_keybag_mode mode;
	enum sep_keybag_authorization authorization;
	sep_keybag_credential_callback callback;
	void *callback_context;
	sep_keybag_prepare_callback prepare;
	void *prepare_context;
	sep_keybag_prepared_cleanup cleanup;
	void *cleanup_context;
	enum sep_keybag_disposition disposition;
	struct sep_keybag_material *material;
	int stored;
	bool prepared;
	const char *failure_stage;
	bool report_failures;
};

struct credential_adapter_context {
	struct keybag_operation_context *keybag;
};

struct acm_contains_context {
	uint32_t credential_type;
};

struct acm_replace_context {
	const uint8_t *secret;
	size_t secret_length;
};

struct acm_verify_context {
	int preflight;
	const uint8_t *keybag_uuid;
	size_t keybag_uuid_length;
};

struct keybag_relay_context {
	const struct sep_keybag_store_ops *store;
	unsigned int poll_timeout_ms;
	sep_keybag_ready_callback ready;
	void *ready_context;
	bool ready_called;
	const char *failure_stage;
	bool report_failures;
};

static void report_stage_failure(const char *operation, const char *stage,
				 enum sep_operation_result result)
{
	if (result != SEP_OPERATION_OK &&
	    result != SEP_OPERATION_ERROR_CANCELLED)
		fprintf(stderr, "t1bridge %s: %s failed\n", operation, stage);
}

static int credential_adapter(void *context, const uint8_t *credential,
			      size_t credential_length);

static int open_fixed_directory(void)
{
	if (geteuid() != 0)
		return -1;
	return open(SEP_KEYBAG_STATE_DIRECTORY,
		    O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}

static int fixed_load(void *context, struct sep_keybag_material *material)
{
	int descriptor;
	int result;

	(void)context;
	descriptor = open_fixed_directory();
	if (descriptor < 0)
		return SEP_KEYBAG_STORE_ERROR;
	result = sep_keybag_state_load_at(descriptor, 0, material);
	(void)close(descriptor);
	return result;
}

static int fixed_persist(void *context,
			 const struct sep_keybag_material *material)
{
	int descriptor;
	int result;

	(void)context;
	descriptor = open_fixed_directory();
	if (descriptor < 0)
		return -1;
	result = sep_keybag_state_persist_absent_at(descriptor, 0, material);
	(void)close(descriptor);
	return result;
}

static const struct sep_keybag_store_ops fixed_store_ops = {
	.context = NULL,
	.load = fixed_load,
	.persist_absent = fixed_persist,
};

static uint64_t load_u64_le(const uint8_t input[sizeof(uint64_t)])
{
	uint64_t value = 0;

	for (size_t index = 0; index < sizeof(value); ++index)
		value |= (uint64_t)input[index] << (index * 8U);
	return value;
}

static int build_protected_user_configuration(
	const uint8_t secret[SEP_KEYSTORE_SECRET_SIZE],
	uint8_t output[USER_CONFIGURATION_SIZE])
{
	if (!secret || !output)
		return -1;
	memset(output, 0, USER_CONFIGURATION_SIZE);
	output[0] = 0x31;
	output[1] = 0x42;
	output[2] = 0x30;
	output[3] = 0x25;
	output[4] = 0x0c;
	output[5] = 0x01;
	output[6] = 'p';
	output[7] = 0x04;
	output[8] = SEP_KEYSTORE_SECRET_SIZE;
	memcpy(output + 9U, secret, SEP_KEYSTORE_SECRET_SIZE);
	output[41] = 0x30;
	output[42] = 0x19;
	output[43] = 0x0c;
	output[44] = 0x05;
	memcpy(output + 45U, "uuuid", 5);
	output[50] = 0x04;
	output[51] = SEP_KEYSTORE_UUID_SIZE;
	memcpy(output + 52U, compatibility_user_uuid,
	       sizeof(compatibility_user_uuid));
	return 0;
}

static enum sep_operation_result exchange(
	struct sep_operation *operation,
	const struct sep_keystore_operation *request_operation,
	uint8_t request[SEP_RELAY_DATA_CAPACITY],
	struct sep_keystore_reply *reply)
{
	enum sep_operation_result result = sep_operation_keystore_exchange(
		operation, request_operation, request,
		request_operation->request_length, reply);

	sep_keystore_clear(request, SEP_RELAY_DATA_CAPACITY);
	return result;
}

static int der_number_for_key(const uint8_t *blob, size_t blob_length,
			      const char *key, uint64_t *value)
{
	size_t key_length;

	if (!blob || !key || !value)
		return 0;
	key_length = strlen(key);
	if (key_length == 0 || key_length > UINT8_MAX)
		return 0;
	for (size_t offset = 0; offset + 2U + key_length < blob_length;
	     ++offset) {
		size_t cursor;
		size_t number_length;
		uint64_t number = 0;

		if (blob[offset] != UINT8_C(0x0c) ||
		    blob[offset + 1U] != key_length ||
		    memcmp(blob + offset + 2U, key, key_length) != 0)
			continue;
		cursor = offset + 2U + key_length;
		while (cursor < blob_length && blob[cursor] != UINT8_C(0x02) &&
		       cursor < offset + 2U + key_length + 8U)
			++cursor;
		if (cursor + 2U > blob_length ||
		    blob[cursor] != UINT8_C(0x02) ||
		    (blob[cursor + 1U] & UINT8_C(0x80)) != 0)
			return 0;
		number_length = blob[cursor + 1U];
		cursor += 2U;
		if (number_length == 0 || number_length > sizeof(number) ||
		    number_length > blob_length - cursor)
			return 0;
		for (size_t index = 0; index < number_length; ++index)
			number = (number << 8U) | blob[cursor + index];
		*value = number;
		return 1;
	}
	return 0;
}

static int unlocked_device_state(const struct sep_keystore_reply *reply)
{
	uint64_t state;
	uint64_t lock_state;

	return reply->kind == SEP_KEYSTORE_REPLY_OPAQUE &&
	       der_number_for_key(reply->opaque, reply->opaque_length, "ss",
				  &state) &&
	       der_number_for_key(reply->opaque, reply->opaque_length, "sls",
				  &lock_state) &&
	       (state & KEYBAG_STATE_BEEN_UNLOCKED) != 0 && lock_state == 0;
}

static int reply_is_not_found(const struct sep_keystore_reply *reply)
{
	return (reply->outer_result == -3 && reply->inner_result == 0) ||
	       (reply->outer_result == 0 && reply->inner_result == -3);
}

static enum sep_operation_result set_environment(
	struct sep_operation *operation, struct sep_keystore_state *keystore,
	uint64_t *timestamp)
{
	uint8_t request[SEP_RELAY_DATA_CAPACITY] = { 0 };
	struct sep_keystore_operation request_operation = { 0 };
	struct sep_keystore_reply reply = { 0 };
	enum sep_operation_result result = sep_operation_timestamp_us(
		operation, *timestamp, timestamp);

	if (result == SEP_OPERATION_OK &&
	    sep_keystore_build_set_environment(
		    keystore, *timestamp, request, sizeof(request),
		    &request_operation) != SEP_KEYSTORE_OK)
		result = SEP_OPERATION_ERROR_KEYBAG;
	if (result == SEP_OPERATION_OK)
		result = exchange(
			operation, &request_operation, request, &reply);
	if (result == SEP_OPERATION_OK &&
	    reply.kind != SEP_KEYSTORE_REPLY_NONE)
		result = SEP_OPERATION_ERROR_KEYBAG;
	sep_keystore_clear(request, sizeof(request));
	sep_keystore_clear(&reply, sizeof(reply));
	return result;
}

static enum sep_operation_result query_device_state(
	struct sep_operation *operation, struct sep_keystore_state *keystore,
	uint64_t *timestamp, int32_t handle, bool allow_not_found, bool *absent)
{
	uint8_t request[SEP_RELAY_DATA_CAPACITY] = { 0 };
	struct sep_keystore_operation request_operation = { 0 };
	struct sep_keystore_reply reply = { 0 };
	enum sep_operation_result result;

	if (!absent)
		return SEP_OPERATION_ERROR_ARGUMENT;
	*absent = false;
	result = sep_operation_timestamp_us(operation, *timestamp, timestamp);
	if (result == SEP_OPERATION_OK &&
	    sep_keystore_build_device_state(
		    keystore, *timestamp, handle, request, sizeof(request),
		    &request_operation) != SEP_KEYSTORE_OK)
		result = SEP_OPERATION_ERROR_KEYBAG;
	if (result == SEP_OPERATION_OK)
		result = exchange(
			operation, &request_operation, request, &reply);
	if (result == SEP_OPERATION_REMOTE_ERROR && allow_not_found &&
	    reply_is_not_found(&reply)) {
		*absent = true;
		result = SEP_OPERATION_OK;
	} else if (result == SEP_OPERATION_OK &&
		   !unlocked_device_state(&reply)) {
		result = SEP_OPERATION_ERROR_KEYBAG;
	}
	sep_keystore_clear(request, sizeof(request));
	sep_keystore_clear(&reply, sizeof(reply));
	return result;
}

static enum sep_operation_result create_session_keybag(
	struct sep_operation *operation, struct sep_keystore_state *keystore,
	uint64_t *timestamp,
	const uint8_t secret[SEP_KEYSTORE_SECRET_SIZE], uint32_t *source_handle)
{
	uint8_t request[SEP_RELAY_DATA_CAPACITY] = { 0 };
	struct sep_keystore_operation request_operation = { 0 };
	struct sep_keystore_reply reply = { 0 };
	enum sep_operation_result result = sep_operation_timestamp_us(
		operation, *timestamp, timestamp);

	if (result == SEP_OPERATION_OK &&
	    sep_keystore_build_create(
		    keystore, *timestamp, secret, request, sizeof(request),
		    &request_operation) != SEP_KEYSTORE_OK)
		result = SEP_OPERATION_ERROR_KEYBAG;
	if (result == SEP_OPERATION_OK)
		result = exchange(
			operation, &request_operation, request, &reply);
	if (result == SEP_OPERATION_OK &&
	    (reply.kind != SEP_KEYSTORE_REPLY_VALUE || reply.value == 0 ||
	     reply.value > INT32_MAX))
		result = SEP_OPERATION_ERROR_KEYBAG;
	if (result == SEP_OPERATION_OK)
		*source_handle = reply.value;
	sep_keystore_clear(request, sizeof(request));
	sep_keystore_clear(&reply, sizeof(reply));
	return result;
}

static enum sep_operation_result make_system(
	struct sep_operation *operation, struct sep_keystore_state *keystore,
	uint64_t *timestamp, uint32_t source_handle, int32_t target_handle,
	const uint8_t *secret, size_t secret_length)
{
	uint8_t request[SEP_RELAY_DATA_CAPACITY] = { 0 };
	struct sep_keystore_operation request_operation = { 0 };
	struct sep_keystore_reply reply = { 0 };
	enum sep_operation_result result = sep_operation_timestamp_us(
		operation, *timestamp, timestamp);

	if (result == SEP_OPERATION_OK &&
	    sep_keystore_build_make_system(
		    keystore, *timestamp, source_handle, target_handle, secret,
		    secret_length, request, sizeof(request),
		    &request_operation) != SEP_KEYSTORE_OK)
		result = SEP_OPERATION_ERROR_KEYBAG;
	if (result == SEP_OPERATION_OK)
		result = exchange(
			operation, &request_operation, request, &reply);
	if (result == SEP_OPERATION_OK &&
	    reply.kind != SEP_KEYSTORE_REPLY_NONE)
		result = SEP_OPERATION_ERROR_KEYBAG;
	sep_keystore_clear(request, sizeof(request));
	sep_keystore_clear(&reply, sizeof(reply));
	return result;
}

static enum sep_operation_result inspect_lock_state(
	struct sep_operation *operation, struct sep_keystore_state *keystore,
	uint64_t *timestamp, int32_t handle, bool require_unlocked)
{
	uint8_t request[SEP_RELAY_DATA_CAPACITY] = { 0 };
	struct sep_keystore_operation request_operation = { 0 };
	struct sep_keystore_reply reply = { 0 };
	enum sep_operation_result result = sep_operation_timestamp_us(
		operation, *timestamp, timestamp);

	if (result == SEP_OPERATION_OK &&
	    sep_keystore_build_lock_state(
		    keystore, *timestamp, handle, request, sizeof(request),
		    &request_operation) != SEP_KEYSTORE_OK)
		result = SEP_OPERATION_ERROR_KEYBAG;
	if (result == SEP_OPERATION_OK)
		result = exchange(
			operation, &request_operation, request, &reply);
	if (result == SEP_OPERATION_OK &&
	    (reply.kind != SEP_KEYSTORE_REPLY_VALUE_AND_FLAGS ||
	     (require_unlocked &&
	      ((reply.value & KEYBAG_STATE_BEEN_UNLOCKED) == 0 ||
	       reply.first_wide_value != 0))))
		result = SEP_OPERATION_ERROR_KEYBAG;
	sep_keystore_clear(request, sizeof(request));
	sep_keystore_clear(&reply, sizeof(reply));
	return result;
}

static enum sep_operation_result unlock_keybag(
	struct sep_operation *operation, struct sep_keystore_state *keystore,
	uint64_t *timestamp, int32_t handle,
	const uint8_t secret[SEP_KEYSTORE_SECRET_SIZE])
{
	uint8_t request[SEP_RELAY_DATA_CAPACITY] = { 0 };
	struct sep_keystore_operation request_operation = { 0 };
	struct sep_keystore_reply reply = { 0 };
	enum sep_operation_result result = sep_operation_timestamp_us(
		operation, *timestamp, timestamp);

	if (result == SEP_OPERATION_OK &&
	    sep_keystore_build_unlock(
		    keystore, *timestamp, handle, secret, request,
		    sizeof(request), &request_operation) != SEP_KEYSTORE_OK)
		result = SEP_OPERATION_ERROR_KEYBAG;
	if (result == SEP_OPERATION_OK)
		result = exchange(
			operation, &request_operation, request, &reply);
	if (result == SEP_OPERATION_OK &&
	    reply.kind != SEP_KEYSTORE_REPLY_STATE_PAIR)
		result = SEP_OPERATION_ERROR_KEYBAG;
	sep_keystore_clear(request, sizeof(request));
	sep_keystore_clear(&reply, sizeof(reply));
	return result;
}

static enum sep_operation_result ensure_boot_keybag(
	struct sep_operation *operation, struct sep_keystore_state *keystore,
	uint64_t *timestamp, int32_t target_handle, bool promote_with_secret)
{
	uint8_t secret[SEP_KEYSTORE_SECRET_SIZE] = { 0 };
	uint32_t source_handle = 0;
	bool absent;
	enum sep_operation_result result = query_device_state(
		operation, keystore, timestamp, target_handle, true, &absent);

	if (result != SEP_OPERATION_OK || !absent)
		goto out;
	result = sep_operation_entropy(operation, secret, sizeof(secret));
	if (result != SEP_OPERATION_OK)
		goto out;
	result = create_session_keybag(
		operation, keystore, timestamp, secret, &source_handle);
	if (result != SEP_OPERATION_OK)
		goto out;
	result = make_system(
		operation, keystore, timestamp, source_handle, target_handle,
		promote_with_secret ? secret : NULL,
		promote_with_secret ? sizeof(secret) : 0);
	if (result != SEP_OPERATION_OK)
		goto out;
	result = inspect_lock_state(
		operation, keystore, timestamp, target_handle,
		promote_with_secret);
	if (result != SEP_OPERATION_OK)
		goto out;
	if (!promote_with_secret) {
		result = unlock_keybag(
			operation, keystore, timestamp, target_handle, secret);
		if (result != SEP_OPERATION_OK)
			goto out;
		result = inspect_lock_state(
			operation, keystore, timestamp, target_handle, true);
		if (result != SEP_OPERATION_OK)
			goto out;
	}
	result = query_device_state(
		operation, keystore, timestamp, target_handle, false, &absent);

out:
	sep_keystore_clear(secret, sizeof(secret));
	return result;
}

static enum sep_operation_result prepare_keystore_prerequisites(
	struct sep_operation *operation, struct sep_keystore_state *keystore,
	uint64_t *timestamp, bool include_default_system)
{
	enum sep_operation_result result = set_environment(
		operation, keystore, timestamp);

	if (result == SEP_OPERATION_OK)
		result = ensure_boot_keybag(
			operation, keystore, timestamp, DEVICE_KEYBAG_HANDLE, true);
	if (result == SEP_OPERATION_OK && include_default_system)
		result = ensure_boot_keybag(
			operation, keystore, timestamp,
			DEFAULT_SYSTEM_KEYBAG_HANDLE, false);
	return result;
}

static enum sep_operation_result load_material_state(
	struct keybag_operation_context *context,
	struct sep_keybag_material *material, int *stored)
{
	*stored = context->store->load(context->store->context, material);
	if (*stored == SEP_KEYBAG_STORE_ERROR ||
	    (*stored == SEP_KEYBAG_STORE_ABSENT &&
	     context->mode == SEP_KEYBAG_EXISTING_ONLY) ||
	    (*stored == SEP_KEYBAG_STORE_EXISTING &&
	     context->mode == SEP_KEYBAG_CREATE_IF_ABSENT))
		return SEP_OPERATION_ERROR_STATE;
	return SEP_OPERATION_OK;
}

static enum sep_operation_result keybag_state_preflight(void *callback_context)
{
	struct keybag_operation_context *context = callback_context;
	enum sep_operation_result result;

	context->failure_stage = "load persisted state";
	result = load_material_state(
		context, context->material, &context->stored);
	if (result == SEP_OPERATION_OK && context->prepare) {
		context->failure_stage = "prepare caller resources";
		if (context->prepare(context->prepare_context) != 0)
			result = SEP_OPERATION_ERROR_CALLBACK;
		else
			context->prepared = true;
	}
	if (context->report_failures)
		report_stage_failure("keybag", context->failure_stage, result);
	return result;
}

static void keybag_prepared_finalizer(void *callback_context)
{
	struct keybag_operation_context *context = callback_context;

	if (!context->prepared)
		return;
	context->cleanup(context->cleanup_context);
	context->prepared = false;
}

static enum sep_operation_result create_or_load(
	struct sep_operation *operation, struct keybag_operation_context *context,
	struct sep_keybag_material *material,
	struct sep_keystore_state *keystore, uint64_t *timestamp,
	uint32_t *source_handle, int stored)
{
	uint8_t request[SEP_RELAY_DATA_CAPACITY] = { 0 };
	struct sep_keystore_operation request_operation = { 0 };
	struct sep_keystore_reply reply = { 0 };
	enum sep_operation_result result;
	result = sep_operation_timestamp_us(operation, *timestamp, timestamp);
	if (result != SEP_OPERATION_OK)
		goto out;
	if (stored == SEP_KEYBAG_STORE_EXISTING) {
		context->disposition = SEP_KEYBAG_REUSED;
		if (sep_keystore_build_load(
			    keystore, *timestamp, material->blob,
			    material->blob_length, request, sizeof(request),
			    &request_operation) != SEP_KEYSTORE_OK)
			result = SEP_OPERATION_ERROR_KEYBAG;
	} else {
		context->disposition = SEP_KEYBAG_CREATED;
		result = sep_operation_entropy(
			operation, material->secret, sizeof(material->secret));
		if (result == SEP_OPERATION_OK &&
		    sep_keystore_build_create(
			    keystore, *timestamp, material->secret, request,
			    sizeof(request), &request_operation) != SEP_KEYSTORE_OK)
			result = SEP_OPERATION_ERROR_KEYBAG;
	}
	if (result != SEP_OPERATION_OK)
		goto out;
	result = exchange(operation, &request_operation, request, &reply);
	if (result == SEP_OPERATION_OK &&
	    (reply.kind != SEP_KEYSTORE_REPLY_VALUE || reply.value == 0 ||
	     reply.value > INT32_MAX))
		result = SEP_OPERATION_ERROR_KEYBAG;
	if (result == SEP_OPERATION_OK)
		*source_handle = reply.value;

out:
	sep_keystore_clear(request, sizeof(request));
	sep_keystore_clear(&reply, sizeof(reply));
	return result;
}

static enum sep_operation_result activate_and_validate(
	struct sep_operation *operation, struct sep_keystore_state *keystore,
	uint64_t *timestamp, uint32_t source_handle,
	const uint8_t secret[SEP_KEYSTORE_SECRET_SIZE], bool created)
{
	uint8_t request[SEP_RELAY_DATA_CAPACITY] = { 0 };
	uint8_t configuration[USER_CONFIGURATION_SIZE] = { 0 };
	struct sep_keystore_operation request_operation = { 0 };
	struct sep_keystore_reply reply = { 0 };
	enum sep_operation_result result;

	result = sep_operation_timestamp_us(operation, *timestamp, timestamp);
	if (result == SEP_OPERATION_OK &&
	    sep_keystore_build_make_system(
		    keystore, *timestamp, source_handle,
		    SEP_KEYBAG_BIOMETRIC_HANDLE,
		    created ? secret : NULL,
		    created ? SEP_KEYSTORE_SECRET_SIZE : 0, request,
		    sizeof(request), &request_operation) != SEP_KEYSTORE_OK)
		result = SEP_OPERATION_ERROR_KEYBAG;
	if (result == SEP_OPERATION_OK)
		result = exchange(
			operation, &request_operation, request, &reply);
	sep_keystore_clear(&reply, sizeof(reply));
	if (result != SEP_OPERATION_OK)
		goto out;

	if (!created) {
		/*
		 * Match keybagd's persisted-user restore order.  Observe the promoted
		 * bag before resolving its protected configuration, then unlock it.
		 * The state read is required even though this pre-unlock result is not
		 * expected to report an unlocked bag.  Resolving the configuration then
		 * binds the loaded bag to its serialized user record before selector
		 * 0x18 publishes first-unlock state to Mesa.  The returned DER is opaque;
		 * successful bounded parsing is the only validation required here.
		 */
		result = inspect_lock_state(
			operation, keystore, timestamp,
			SEP_KEYBAG_BIOMETRIC_HANDLE, false);
		if (result != SEP_OPERATION_OK)
			goto out;

		result = sep_operation_timestamp_us(
			operation, *timestamp, timestamp);
		if (result == SEP_OPERATION_OK &&
		    sep_keystore_build_get_configuration(
			    keystore, *timestamp, SEP_KEYBAG_BIOMETRIC_HANDLE,
			    request, sizeof(request), &request_operation) !=
			    SEP_KEYSTORE_OK)
			result = SEP_OPERATION_ERROR_KEYBAG;
		if (result == SEP_OPERATION_OK)
			result = exchange(
				operation, &request_operation, request, &reply);
		if (result == SEP_OPERATION_OK &&
		    reply.kind != SEP_KEYSTORE_REPLY_OPAQUE)
			result = SEP_OPERATION_ERROR_KEYBAG;
		sep_keystore_clear(&reply, sizeof(reply));
		if (result != SEP_OPERATION_OK)
			goto out;

		result = sep_operation_timestamp_us(
			operation, *timestamp, timestamp);
		if (result == SEP_OPERATION_OK &&
		    sep_keystore_build_unlock(
			    keystore, *timestamp, SEP_KEYBAG_BIOMETRIC_HANDLE,
			    secret, request, sizeof(request),
			    &request_operation) != SEP_KEYSTORE_OK)
			result = SEP_OPERATION_ERROR_KEYBAG;
		if (result == SEP_OPERATION_OK)
			result = exchange(
				operation, &request_operation, request, &reply);
		if (result == SEP_OPERATION_OK &&
		    reply.kind != SEP_KEYSTORE_REPLY_STATE_PAIR)
			result = SEP_OPERATION_ERROR_KEYBAG;
		sep_keystore_clear(&reply, sizeof(reply));
		if (result != SEP_OPERATION_OK)
			goto out;
	}

	result = sep_operation_timestamp_us(operation, *timestamp, timestamp);
	if (result == SEP_OPERATION_OK &&
	    sep_keystore_build_lock_state(
		    keystore, *timestamp, SEP_KEYBAG_BIOMETRIC_HANDLE, request,
		    sizeof(request), &request_operation) != SEP_KEYSTORE_OK)
		result = SEP_OPERATION_ERROR_KEYBAG;
	if (result == SEP_OPERATION_OK)
		result = exchange(
			operation, &request_operation, request, &reply);
	if (result == SEP_OPERATION_OK &&
	    (reply.kind != SEP_KEYSTORE_REPLY_VALUE_AND_FLAGS ||
	     (reply.value & KEYBAG_STATE_BEEN_UNLOCKED) == 0 ||
	     reply.first_wide_value != 0))
		result = SEP_OPERATION_ERROR_KEYBAG;
	sep_keystore_clear(&reply, sizeof(reply));
	if (result != SEP_OPERATION_OK || !created)
		goto out;

	result = sep_operation_timestamp_us(operation, *timestamp, timestamp);
	if (result == SEP_OPERATION_OK &&
	    (build_protected_user_configuration(secret, configuration) != 0 ||
	     sep_keystore_build_set_configuration(
		     keystore, *timestamp, SEP_KEYBAG_BIOMETRIC_HANDLE, 2,
		     configuration, sizeof(configuration), request,
		     sizeof(request), &request_operation) != SEP_KEYSTORE_OK))
		result = SEP_OPERATION_ERROR_KEYBAG;
	if (result == SEP_OPERATION_OK)
		result = exchange(
			operation, &request_operation, request, &reply);
	if (result == SEP_OPERATION_OK &&
	    reply.kind != SEP_KEYSTORE_REPLY_STATE_PAIR)
		result = SEP_OPERATION_ERROR_KEYBAG;
	sep_keystore_clear(&reply, sizeof(reply));

out:
	sep_keystore_clear(request, sizeof(request));
	sep_keystore_clear(configuration, sizeof(configuration));
	return result;
}

static enum sep_operation_result serialize_and_persist(
	struct sep_operation *operation, struct keybag_operation_context *context,
	struct sep_keybag_material *material,
	struct sep_keystore_state *keystore, uint64_t *timestamp)
{
	uint8_t request[SEP_RELAY_DATA_CAPACITY] = { 0 };
	struct sep_keystore_operation request_operation = { 0 };
	struct sep_keystore_reply reply = { 0 };
	enum sep_operation_result result = sep_operation_timestamp_us(
		operation, *timestamp, timestamp);

	if (result == SEP_OPERATION_OK &&
	    sep_keystore_build_serialize(
		    keystore, *timestamp, SEP_KEYBAG_BIOMETRIC_HANDLE, request,
		    sizeof(request), &request_operation) != SEP_KEYSTORE_OK)
		result = SEP_OPERATION_ERROR_KEYBAG;
	if (result == SEP_OPERATION_OK)
		result = exchange(
			operation, &request_operation, request, &reply);
	if (result == SEP_OPERATION_OK &&
	    (reply.kind != SEP_KEYSTORE_REPLY_OPAQUE ||
	     reply.opaque_length == 0 ||
	     reply.opaque_length > sizeof(material->blob)))
		result = SEP_OPERATION_ERROR_KEYBAG;
	if (result == SEP_OPERATION_OK) {
		memcpy(material->blob, reply.opaque, reply.opaque_length);
		material->blob_length = reply.opaque_length;
		if (context->store->persist_absent(
			    context->store->context, material) != 0)
			result = SEP_OPERATION_ERROR_PERSISTENCE;
	}
	sep_keystore_clear(request, sizeof(request));
	sep_keystore_clear(&reply, sizeof(reply));
	return result;
}

static int build_acm_initialize(void *context, struct sep_acm_state *state,
				struct sep_relay_state *relay,
				uint8_t output[SEP_RELAY_BUFFER_SIZE])
{
	(void)context;
	return sep_acm_build_initialize(state, relay, output);
}

static int build_acm_biometric_context(
	void *context, struct sep_acm_state *state,
	struct sep_relay_state *relay,
	uint8_t output[SEP_RELAY_BUFFER_SIZE])
{
	(void)context;
	return sep_acm_build_context_create(
		state, relay, BIOMETRIC_UID, output);
}

static int build_acm_externalize(void *context, struct sep_acm_state *state,
				  struct sep_relay_state *relay,
				  uint8_t output[SEP_RELAY_BUFFER_SIZE])
{
	(void)context;
	return sep_acm_build_context_externalize(state, relay, output);
}

static int build_acm_contains(void *context, struct sep_acm_state *state,
			      struct sep_relay_state *relay,
			      uint8_t output[SEP_RELAY_BUFFER_SIZE])
{
	const struct acm_contains_context *contains = context;

	return sep_acm_build_contains_credential(
		state, relay, contains->credential_type, 0, output);
}

static int build_acm_replace(void *context, struct sep_acm_state *state,
			     struct sep_relay_state *relay,
			     uint8_t output[SEP_RELAY_BUFFER_SIZE])
{
	const struct acm_replace_context *replace = context;

	return sep_acm_build_replace_passphrase(
		state, relay, replace->secret, replace->secret_length, 1,
		output);
}

static int build_acm_verify(void *context, struct sep_acm_state *state,
			    struct sep_relay_state *relay,
			    uint8_t output[SEP_RELAY_BUFFER_SIZE])
{
	const struct acm_verify_context *verify = context;

	return sep_acm_build_verify_enrollment(
		state, relay, verify->preflight, verify->keybag_uuid,
		verify->keybag_uuid_length, output);
}

static enum sep_operation_result verify_keybag_secret(
	struct sep_operation *operation, struct sep_keystore_state *keystore,
	uint64_t *timestamp, const uint8_t secret[SEP_KEYSTORE_SECRET_SIZE],
	const struct sep_acm_external_form *credential)
{
	uint8_t request[SEP_RELAY_DATA_CAPACITY] = { 0 };
	struct sep_keystore_operation request_operation = { 0 };
	struct sep_keystore_reply reply = { 0 };
	enum sep_operation_result result = sep_operation_timestamp_us(
		operation, *timestamp, timestamp);

	if (result == SEP_OPERATION_OK &&
	    sep_keystore_build_verify_secret(
		    keystore, *timestamp, SEP_KEYBAG_BIOMETRIC_HANDLE, secret,
		    credential->bytes, sizeof(credential->bytes), request,
		    sizeof(request), &request_operation) != SEP_KEYSTORE_OK)
		result = SEP_OPERATION_ERROR_KEYBAG;
	if (result == SEP_OPERATION_OK)
		result = exchange(
			operation, &request_operation, request, &reply);
	if (result == SEP_OPERATION_OK &&
	    reply.kind != SEP_KEYSTORE_REPLY_NONE)
		result = SEP_OPERATION_ERROR_KEYBAG;
	sep_keystore_clear(request, sizeof(request));
	sep_keystore_clear(&reply, sizeof(reply));
	return result;
}

static enum sep_operation_result copy_keybag_uuid(
	struct sep_operation *operation, struct sep_keystore_state *keystore,
	uint64_t *timestamp, uint8_t uuid[SEP_KEYSTORE_UUID_SIZE])
{
	uint8_t request[SEP_RELAY_DATA_CAPACITY] = { 0 };
	struct sep_keystore_operation request_operation = { 0 };
	struct sep_keystore_reply reply = { 0 };
	enum sep_operation_result result = sep_operation_timestamp_us(
		operation, *timestamp, timestamp);

	if (result == SEP_OPERATION_OK &&
	    sep_keystore_build_copy_uuid(
		    keystore, *timestamp, SEP_KEYBAG_BIOMETRIC_HANDLE, request,
		    sizeof(request), &request_operation) != SEP_KEYSTORE_OK)
		result = SEP_OPERATION_ERROR_KEYBAG;
	if (result == SEP_OPERATION_OK)
		result = exchange(
			operation, &request_operation, request, &reply);
	if (result == SEP_OPERATION_OK &&
	    (reply.kind != SEP_KEYSTORE_REPLY_OPAQUE ||
	     reply.opaque_length != SEP_KEYSTORE_UUID_SIZE))
		result = SEP_OPERATION_ERROR_KEYBAG;
	if (result == SEP_OPERATION_OK)
		memcpy(uuid, reply.opaque, SEP_KEYSTORE_UUID_SIZE);
	sep_keystore_clear(request, sizeof(request));
	sep_keystore_clear(&reply, sizeof(reply));
	return result;
}

static enum sep_operation_result acm_exchange(
	struct sep_operation *operation, sep_session_acm_builder builder,
	void *builder_context, struct sep_acm_outcome *outcome)
{
	enum sep_operation_result result = sep_operation_acm_exchange(
		operation, builder, builder_context, outcome);

	return result == SEP_OPERATION_OK && outcome->remote_result == 0 ?
		       SEP_OPERATION_OK :
		       result == SEP_OPERATION_OK ? SEP_OPERATION_ERROR_ACM :
					    result;
}

static enum sep_operation_result acm_contains(
	struct sep_operation *operation, uint32_t credential_type,
	bool require_present)
{
	struct acm_contains_context contains = {
		.credential_type = credential_type,
	};
	struct sep_acm_outcome outcome = { 0 };
	enum sep_operation_result result = acm_exchange(
		operation, build_acm_contains, &contains, &outcome);

	if (result == SEP_OPERATION_OK &&
	    (outcome.operation != SEP_ACM_OPERATION_CONTAINS_CREDENTIAL ||
	     !outcome.boolean_valid ||
	     (require_present && !outcome.boolean_value)))
		result = SEP_OPERATION_ERROR_ACM;
	sep_keystore_clear(&outcome, sizeof(outcome));
	return result;
}

static enum sep_operation_result acm_verify_policy(
	struct sep_operation *operation, int preflight, const uint8_t *uuid,
	size_t uuid_length)
{
	struct acm_verify_context verify = {
		.preflight = preflight,
		.keybag_uuid = uuid,
		.keybag_uuid_length = uuid_length,
	};
	struct sep_acm_outcome outcome = { 0 };
	enum sep_operation_result result = acm_exchange(
		operation, build_acm_verify, &verify, &outcome);

	if (result == SEP_OPERATION_OK &&
	    (outcome.operation != SEP_ACM_OPERATION_VERIFY_ENROLLMENT ||
	     !outcome.boolean_valid || !outcome.boolean_value))
		result = SEP_OPERATION_ERROR_ACM;
	sep_keystore_clear(&outcome, sizeof(outcome));
	return result;
}

static enum sep_operation_result authorize_and_lend_credential(
	struct sep_operation *operation, struct keybag_operation_context *context,
	struct sep_keystore_state *keystore, uint64_t *timestamp,
	const uint8_t secret[SEP_KEYSTORE_SECRET_SIZE])
{
	struct credential_adapter_context adapter = { .keybag = context };
	struct acm_replace_context replace = {
		.secret = secret,
		.secret_length = SEP_KEYSTORE_SECRET_SIZE,
	};
	struct sep_acm_external_form credential = { 0 };
	struct sep_acm_outcome outcome = { 0 };
	uint8_t uuid[SEP_KEYSTORE_UUID_SIZE] = { 0 };
	bool biometric_keybag_absent = false;
	enum sep_operation_result result;

	result = acm_exchange(operation, build_acm_initialize, NULL, &outcome);
	if (result != SEP_OPERATION_OK)
		goto out;
	result = acm_exchange(
		operation, build_acm_biometric_context, NULL, &outcome);
	if (result != SEP_OPERATION_OK)
		goto out;
	result = acm_exchange(
		operation, build_acm_externalize, NULL, &outcome);
	if (result != SEP_OPERATION_OK ||
	    sep_operation_export_acm_context(operation, &credential) !=
		    SEP_ACM_OK) {
		result = SEP_OPERATION_ERROR_ACM;
		goto out;
	}
	result = verify_keybag_secret(
		operation, keystore, timestamp, secret, &credential);
	if (result != SEP_OPERATION_OK)
		goto out;
	result = copy_keybag_uuid(operation, keystore, timestamp, uuid);
	if (result != SEP_OPERATION_OK)
		goto out;
	if (context->authorization == SEP_KEYBAG_AUTHENTICATION) {
		/*
		 * Match the proven existing-keybag authentication path: publish one
		 * final readback for the concrete biometric handle after the ACM
		 * context has verified the secret and resolved its keybag UUID, but
		 * before lending that credential to Mesa.
		 */
		context->failure_stage =
			"publish authorized biometric keybag state";
		result = query_device_state(
			operation, keystore, timestamp,
			SEP_KEYBAG_BIOMETRIC_HANDLE, false,
			&biometric_keybag_absent);
		if (result != SEP_OPERATION_OK)
			goto out;
	}
	if (context->authorization == SEP_KEYBAG_ENROLLMENT) {
		result = acm_contains(operation, 1, false);
		if (result != SEP_OPERATION_OK)
			goto out;
		result = acm_contains(operation, 2, false);
		if (result != SEP_OPERATION_OK)
			goto out;
		result = acm_exchange(
			operation, build_acm_replace, &replace, &outcome);
		if (result != SEP_OPERATION_OK)
			goto out;
		result = acm_contains(operation, 1, false);
		if (result != SEP_OPERATION_OK)
			goto out;
		result = acm_contains(operation, 2, true);
		if (result != SEP_OPERATION_OK)
			goto out;
		result = acm_verify_policy(operation, 1, NULL, 0);
		if (result != SEP_OPERATION_OK)
			goto out;
		result = acm_verify_policy(
			operation, 0, uuid, sizeof(uuid));
		if (result != SEP_OPERATION_OK)
			goto out;
	}
	context->failure_stage = "lend authorized biometric credential";
	result = sep_operation_release_acquisition_deadline(operation);
	if (result != SEP_OPERATION_OK)
		goto out;
	result = credential_adapter(
		&adapter, credential.bytes, sizeof(credential.bytes)) == 0 ?
		       SEP_OPERATION_OK :
		       SEP_OPERATION_ERROR_CALLBACK;

out:
	sep_acm_external_form_wipe(&credential);
	sep_keystore_clear(uuid, sizeof(uuid));
	sep_keystore_clear(&outcome, sizeof(outcome));
	return result;
}

static int credential_adapter(void *context, const uint8_t *credential,
			      size_t credential_length)
{
	struct credential_adapter_context *adapter = context;
	struct keybag_operation_context *keybag = adapter->keybag;

	return keybag->callback(
		keybag->callback_context, keybag->disposition, credential,
		credential_length);
}

static enum sep_operation_result keybag_operation_callback(
	void *callback_context, struct sep_operation *operation)
{
	struct keybag_operation_context *context = callback_context;
	struct sep_keybag_material *material = context->material;
	struct sep_keystore_state keystore;
	uint8_t context_entropy[sizeof(uint64_t)] = { 0 };
	uint64_t client_context;
	uint64_t timestamp = 0;
	uint32_t source_handle = 0;
	enum sep_operation_result result;

	memset(&keystore, 0, sizeof(keystore));
	context->failure_stage = "initialize protocol state";
	result = sep_operation_entropy(
		operation, context_entropy, sizeof(context_entropy));
	client_context = load_u64_le(context_entropy);
	if (result != SEP_OPERATION_OK || client_context == 0 ||
	    sep_keystore_state_init(&keystore, client_context, 1) !=
			SEP_KEYSTORE_OK) {
		if (result == SEP_OPERATION_OK)
			result = SEP_OPERATION_ERROR_KEYBAG;
		goto out;
	}
	if (context->mode == SEP_KEYBAG_EXISTING_ONLY) {
		context->disposition = SEP_KEYBAG_REUSED;
		context->failure_stage = "set keystore environment";
		result = set_environment(operation, &keystore, &timestamp);
		if (result != SEP_OPERATION_OK)
			goto out;
	} else {
		context->failure_stage = "prepare device keybag";
		result = prepare_keystore_prerequisites(
			operation, &keystore, &timestamp, false);
		if (result != SEP_OPERATION_OK)
			goto out;
		context->failure_stage = "create or load biometric keybag";
		result = create_or_load(
			operation, context, material, &keystore, &timestamp,
			&source_handle, context->stored);
		if (result != SEP_OPERATION_OK)
			goto out;
		context->failure_stage = "activate biometric keybag";
		result = activate_and_validate(
			operation, &keystore, &timestamp, source_handle,
			material->secret,
			context->disposition == SEP_KEYBAG_CREATED);
		if (result != SEP_OPERATION_OK)
			goto out;
		if (context->disposition == SEP_KEYBAG_CREATED) {
			context->failure_stage = "persist biometric keybag";
			result = serialize_and_persist(
				operation, context, material, &keystore, &timestamp);
			if (result != SEP_OPERATION_OK)
				goto out;
		}
	}
	context->failure_stage = context->authorization == SEP_KEYBAG_ENROLLMENT ?
				 "authorize enrollment credential" :
				 "authorize authentication credential";
	result = authorize_and_lend_credential(
		operation, context, &keystore, &timestamp, material->secret);

out:
	if (context->report_failures)
		report_stage_failure("keybag", context->failure_stage, result);
	sep_keystore_clear(&keystore, sizeof(keystore));
	sep_keystore_clear(context_entropy, sizeof(context_entropy));
	return result;
}

static enum sep_operation_result keybag_relay_callback(
	void *callback_context, struct sep_operation *operation)
{
	struct keybag_relay_context *relay = callback_context;
	struct keybag_operation_context keybag = {
		.store = relay->store,
		.mode = SEP_KEYBAG_EXISTING_ONLY,
		.disposition = SEP_KEYBAG_REUSED,
	};
	struct sep_keybag_material material;
	struct sep_keystore_state keystore;
	uint8_t context_entropy[sizeof(uint64_t)] = { 0 };
	uint64_t client_context;
	uint64_t timestamp = 0;
	uint32_t source_handle = 0;
	struct sep_acm_outcome acm_outcome = { 0 };
	bool biometric_keybag_absent = false;
	int stored;
	enum sep_operation_result result;

	memset(&material, 0, sizeof(material));
	memset(&keystore, 0, sizeof(keystore));
	relay->failure_stage = "initialize protocol state";
	result = sep_operation_entropy(
		operation, context_entropy, sizeof(context_entropy));
	client_context = load_u64_le(context_entropy);
	if (result != SEP_OPERATION_OK || client_context == 0 ||
	    sep_keystore_state_init(&keystore, client_context, 1) !=
		    SEP_KEYSTORE_OK) {
		if (result == SEP_OPERATION_OK)
			result = SEP_OPERATION_ERROR_KEYBAG;
		goto out;
	}
	relay->failure_stage = "load persisted state";
	result = load_material_state(&keybag, &material, &stored);
	if (result != SEP_OPERATION_OK)
		goto out;
	relay->failure_stage = "prepare shared keybags";
	result = prepare_keystore_prerequisites(
		operation, &keystore, &timestamp, true);
	if (result != SEP_OPERATION_OK)
		goto out;
	relay->failure_stage = "load biometric keybag";
	result = create_or_load(
		operation, &keybag, &material, &keystore, &timestamp,
		&source_handle, stored);
	if (result != SEP_OPERATION_OK)
		goto out;
	relay->failure_stage = "activate biometric keybag";
	result = activate_and_validate(
		operation, &keystore, &timestamp, source_handle, material.secret,
		false);
	if (result == SEP_OPERATION_OK) {
		relay->failure_stage = "initialize ACM";
		result = acm_exchange(
			operation, build_acm_initialize, NULL, &acm_outcome);
	}
	if (result == SEP_OPERATION_OK) {
		relay->failure_stage = "publish biometric keybag state";
		result = query_device_state(
			operation, &keystore, &timestamp,
			SEP_KEYBAG_BIOMETRIC_HANDLE, false,
			&biometric_keybag_absent);
	}
	if (result == SEP_OPERATION_OK) {
		relay->failure_stage = "begin notification lease";
		result = sep_operation_release_acquisition_deadline(operation);
	}
	/* The persisted secret and serialized blob are no longer needed. */
	sep_keystore_clear(&material, sizeof(material));
	sep_keystore_clear(context_entropy, sizeof(context_entropy));
	if (result != SEP_OPERATION_OK)
		goto out;
	relay->failure_stage = "publish relay readiness";
	if (relay->ready(relay->ready_context) != 0) {
		result = SEP_OPERATION_ERROR_CALLBACK;
		goto out;
	}
	relay->ready_called = true;
	relay->failure_stage = "receive keybag notifications";
	for (;;) {
		if (sep_operation_is_cancelled(operation)) {
			result = SEP_OPERATION_OK;
			break;
		}
		result = sep_operation_drain_notification(
			operation, relay->poll_timeout_ms);
		if (result == SEP_OPERATION_IDLE)
			continue;
		if (result != SEP_OPERATION_OK)
			break;
	}

out:
	if (relay->report_failures)
		report_stage_failure(
			"keybag relay", relay->failure_stage, result);
	sep_keystore_clear(&keystore, sizeof(keystore));
	sep_keystore_clear(&acm_outcome, sizeof(acm_outcome));
	sep_keystore_clear(&material, sizeof(material));
	sep_keystore_clear(context_entropy, sizeof(context_entropy));
	return result;
}

static int valid_run_inputs(const struct sep_keybag_store_ops *store,
			    enum sep_keybag_mode mode,
			    enum sep_keybag_authorization authorization,
			    sep_keybag_credential_callback callback)
{
	return store && store->load && store->persist_absent && callback &&
	       (mode == SEP_KEYBAG_EXISTING_ONLY ||
		mode == SEP_KEYBAG_CREATE_IF_ABSENT) &&
	       (authorization == SEP_KEYBAG_AUTHENTICATION ||
		authorization == SEP_KEYBAG_ENROLLMENT);
}

static enum sep_operation_result run_keybag_operation(
	const struct sep_operation_ops *operation_ops,
	const struct sep_keybag_store_ops *store_ops,
	enum sep_keybag_mode mode, enum sep_keybag_authorization authorization,
	unsigned int timeout_ms,
	sep_operation_cancelled cancelled, void *cancellation_context,
	sep_keybag_prepare_callback prepare, void *prepare_context,
	sep_keybag_credential_callback callback, void *callback_context,
	sep_keybag_prepared_cleanup cleanup, void *cleanup_context,
	int production)
{
	struct sep_keybag_material material;
	struct keybag_operation_context context = {
		.store = store_ops,
		.mode = mode,
		.authorization = authorization,
		.callback = callback,
		.callback_context = callback_context,
		.prepare = prepare,
		.prepare_context = prepare_context,
		.cleanup = cleanup,
		.cleanup_context = cleanup_context,
		.report_failures = production != 0,
	};
	enum sep_operation_result result;

	if (!valid_run_inputs(store_ops, mode, authorization, callback))
		return SEP_OPERATION_ERROR_ARGUMENT;
	if ((prepare == NULL) != (cleanup == NULL))
		return SEP_OPERATION_ERROR_ARGUMENT;
	memset(&material, 0, sizeof(material));
	context.material = &material;
	if (production && prepare)
		result = sep_operation_run_preflight_finalized(
			timeout_ms, cancelled, cancellation_context,
			keybag_state_preflight, &context,
			keybag_operation_callback, &context,
			keybag_prepared_finalizer, &context);
	else if (production)
		result = sep_operation_run_preflight(
			timeout_ms, cancelled, cancellation_context,
			keybag_state_preflight, &context,
			keybag_operation_callback, &context);
	else if (prepare)
		result = sep_operation_run_preflight_finalized_with_ops(
			operation_ops, timeout_ms, cancelled, cancellation_context,
			keybag_state_preflight, &context,
			keybag_operation_callback, &context,
			keybag_prepared_finalizer, &context);
	else
		result = sep_operation_run_preflight_with_ops(
			operation_ops, timeout_ms, cancelled, cancellation_context,
			keybag_state_preflight, &context,
			keybag_operation_callback, &context);

	sep_keystore_clear(&material, sizeof(material));
	return result;
}

enum sep_operation_result sep_keybag_run_with_ops(
	const struct sep_operation_ops *operation_ops,
	const struct sep_keybag_store_ops *store_ops,
	enum sep_keybag_mode mode, enum sep_keybag_authorization authorization,
	unsigned int timeout_ms,
	sep_operation_cancelled cancelled, void *cancellation_context,
	sep_keybag_credential_callback callback, void *callback_context)
{
	return run_keybag_operation(
		operation_ops, store_ops, mode, authorization, timeout_ms, cancelled,
		cancellation_context, NULL, NULL, callback, callback_context,
		NULL, NULL, 0);
}

enum sep_operation_result sep_keybag_run_prepared_with_ops(
	const struct sep_operation_ops *operation_ops,
	const struct sep_keybag_store_ops *store_ops,
	enum sep_keybag_mode mode, enum sep_keybag_authorization authorization,
	unsigned int timeout_ms,
	sep_operation_cancelled cancelled, void *cancellation_context,
	sep_keybag_prepare_callback prepare, void *prepare_context,
	sep_keybag_credential_callback callback, void *callback_context,
	sep_keybag_prepared_cleanup cleanup, void *cleanup_context)
{
	return run_keybag_operation(
		operation_ops, store_ops, mode, authorization, timeout_ms, cancelled,
		cancellation_context, prepare, prepare_context, callback,
		callback_context, cleanup, cleanup_context, 0);
}

enum sep_operation_result sep_keybag_run(
	enum sep_keybag_mode mode, enum sep_keybag_authorization authorization,
	unsigned int timeout_ms,
	sep_operation_cancelled cancelled, void *cancellation_context,
	sep_keybag_credential_callback callback, void *callback_context)
{
	return run_keybag_operation(
		NULL, &fixed_store_ops, mode, authorization, timeout_ms, cancelled,
		cancellation_context, NULL, NULL, callback, callback_context,
		NULL, NULL, 1);
}

enum sep_operation_result sep_keybag_run_prepared(
	enum sep_keybag_mode mode, enum sep_keybag_authorization authorization,
	unsigned int timeout_ms,
	sep_operation_cancelled cancelled, void *cancellation_context,
	sep_keybag_prepare_callback prepare, void *prepare_context,
	sep_keybag_credential_callback callback, void *callback_context,
	sep_keybag_prepared_cleanup cleanup, void *cleanup_context)
{
	return run_keybag_operation(
		NULL, &fixed_store_ops, mode, authorization, timeout_ms, cancelled,
		cancellation_context, prepare, prepare_context, callback,
		callback_context, cleanup, cleanup_context, 1);
}

static enum sep_operation_result run_keybag_notification_relay(
	const struct sep_operation_ops *operation_ops,
	const struct sep_keybag_store_ops *store_ops,
	unsigned int acquisition_timeout_ms, unsigned int poll_timeout_ms,
	sep_operation_cancelled cancelled, void *cancellation_context,
	sep_keybag_ready_callback ready, void *ready_context, int production)
{
	struct keybag_relay_context context = {
		.store = store_ops,
		.poll_timeout_ms = poll_timeout_ms,
		.ready = ready,
		.ready_context = ready_context,
		.report_failures = production != 0,
	};
	enum sep_operation_result result;

	if (!store_ops || !store_ops->load || !ready ||
	    acquisition_timeout_ms == 0 || poll_timeout_ms == 0 ||
	    poll_timeout_ms > SEP_KEYBAG_RELAY_MAX_POLL_MS)
		return SEP_OPERATION_ERROR_ARGUMENT;

	if (production)
		result = sep_operation_run_shared(
			acquisition_timeout_ms, cancelled, cancellation_context,
			keybag_relay_callback, &context);
	else
		result = sep_operation_run_shared_with_ops(
			operation_ops, acquisition_timeout_ms, cancelled,
			cancellation_context, keybag_relay_callback, &context);
	return result == SEP_OPERATION_ERROR_CANCELLED && context.ready_called ?
		       SEP_OPERATION_OK :
		       result;
}

enum sep_operation_result sep_keybag_run_notification_relay_with_ops(
	const struct sep_operation_ops *operation_ops,
	const struct sep_keybag_store_ops *store_ops,
	unsigned int acquisition_timeout_ms, unsigned int poll_timeout_ms,
	sep_operation_cancelled cancelled, void *cancellation_context,
	sep_keybag_ready_callback ready, void *ready_context)
{
	return run_keybag_notification_relay(
		operation_ops, store_ops, acquisition_timeout_ms,
		poll_timeout_ms, cancelled, cancellation_context, ready,
		ready_context, 0);
}

enum sep_operation_result sep_keybag_run_notification_relay(
	unsigned int acquisition_timeout_ms, unsigned int poll_timeout_ms,
	sep_operation_cancelled cancelled, void *cancellation_context,
	sep_keybag_ready_callback ready, void *ready_context)
{
	return run_keybag_notification_relay(
		NULL, &fixed_store_ops, acquisition_timeout_ms, poll_timeout_ms,
		cancelled, cancellation_context, ready, ready_context, 1);
}

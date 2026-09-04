#define _POSIX_C_SOURCE 200809L

#include "t1_nss_account.h"

#include <inttypes.h>
#include <pwd.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define T1_NSS_ACCOUNT_NAME_MAX 255U
#define T1_NSS_ACCOUNT_BUFFER_SIZE 16384U

static int uid_is_representable(uintmax_t user_id)
{
	return user_id <= UINT32_MAX;
}

int t1_nss_account_resolve(const char *username, uint32_t *user_id)
{
	char buffer[T1_NSS_ACCOUNT_BUFFER_SIZE];
	struct passwd entry;
	struct passwd *result = NULL;
	uintptr_t buffer_end;
	uintptr_t buffer_start;
	uintptr_t canonical_name;
	uintmax_t resolved_user_id;
	size_t canonical_capacity;
	size_t username_length;
	int status;

	if (user_id == NULL)
		return T1_NSS_ACCOUNT_INVALID_INPUT;
	*user_id = 0;
	if (username == NULL)
		return T1_NSS_ACCOUNT_INVALID_INPUT;
	username_length = strnlen(username, T1_NSS_ACCOUNT_NAME_MAX + 1U);
	if (username_length == 0 || username_length > T1_NSS_ACCOUNT_NAME_MAX)
		return T1_NSS_ACCOUNT_INVALID_INPUT;

	memset(&entry, 0, sizeof(entry));
	status = getpwnam_r(username, &entry, buffer, sizeof(buffer), &result);
	if (status != 0)
		return T1_NSS_ACCOUNT_LOOKUP_FAILED;
	if (result == NULL)
		return T1_NSS_ACCOUNT_NOT_FOUND;
	if (result != &entry || result->pw_name == NULL)
		return T1_NSS_ACCOUNT_INVALID_RESULT;
	buffer_start = (uintptr_t)buffer;
	buffer_end = buffer_start + sizeof(buffer);
	canonical_name = (uintptr_t)result->pw_name;
	if (canonical_name < buffer_start || canonical_name >= buffer_end)
		return T1_NSS_ACCOUNT_INVALID_RESULT;
	canonical_capacity = (size_t)(buffer_end - canonical_name);
	if (memchr(result->pw_name, '\0', canonical_capacity) == NULL)
		return T1_NSS_ACCOUNT_INVALID_RESULT;
	if (strcmp(username, result->pw_name) != 0)
		return T1_NSS_ACCOUNT_NON_CANONICAL;

	resolved_user_id = (uintmax_t)result->pw_uid;
	if (resolved_user_id == 0)
		return T1_NSS_ACCOUNT_ROOT;
	if (!uid_is_representable(resolved_user_id))
		return T1_NSS_ACCOUNT_UNREPRESENTABLE;
	*user_id = (uint32_t)resolved_user_id;
	return T1_NSS_ACCOUNT_OK;
}

#ifdef T1_NSS_ACCOUNT_TEST
int t1_nss_account_uid_is_representable_for_test(uintmax_t user_id)
{
	return uid_is_representable(user_id);
}
#endif

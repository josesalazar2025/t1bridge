#define _POSIX_C_SOURCE 200809L
#define T1_NSS_ACCOUNT_TEST 1

#include "t1_nss_account.h"

#include <errno.h>
#include <inttypes.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

static unsigned int failures;
static unsigned int lookup_calls;

#define EXPECT(condition) expect((condition), #condition, __LINE__)

static void expect(int condition, const char *expression, int line)
{
	if (!condition) {
		fprintf(stderr, "line %d: failed: %s\n", line, expression);
		++failures;
	}
}

static int return_account(struct passwd *entry, char *buffer,
			  size_t buffer_length, struct passwd **result,
			  const char *canonical_name, uid_t user_id)
{
	size_t name_length = strlen(canonical_name) + 1U;

	if (name_length > buffer_length)
		return ERANGE;
	memset(entry, 0, sizeof(*entry));
	memcpy(buffer, canonical_name, name_length);
	entry->pw_name = buffer;
	entry->pw_uid = user_id;
	*result = entry;
	return 0;
}

int __wrap_getpwnam_r(const char *name, struct passwd *entry, char *buffer,
		      size_t buffer_length, struct passwd **result)
{
	static struct passwd foreign_entry;

	++lookup_calls;
	if (strcmp(name, "synthetic-ok") == 0)
		return return_account(entry, buffer, buffer_length, result,
				      "synthetic-ok", (uid_t)42000U);
	if (strcmp(name, "synthetic-alias") == 0)
		return return_account(entry, buffer, buffer_length, result,
				      "synthetic-canonical", (uid_t)42000U);
	if (strcmp(name, "synthetic-root") == 0)
		return return_account(entry, buffer, buffer_length, result,
				      "synthetic-root", (uid_t)0);
	if (strcmp(name, "synthetic-absent") == 0) {
		*result = NULL;
		return 0;
	}
	if (strcmp(name, "synthetic-foreign") == 0) {
		memset(&foreign_entry, 0, sizeof(foreign_entry));
		foreign_entry.pw_name = (char *)"synthetic-foreign";
		foreign_entry.pw_uid = (uid_t)42000U;
		*result = &foreign_entry;
		return 0;
	}
	if (strcmp(name, "synthetic-static") == 0) {
		memset(entry, 0, sizeof(*entry));
		entry->pw_name = (char *)"synthetic-static";
		entry->pw_uid = (uid_t)42000U;
		*result = entry;
		return 0;
	}
	if (strcmp(name, "synthetic-erange") == 0)
		return ERANGE;
	return EIO;
}

static void test_exact_canonical_non_root_account(void)
{
	uint32_t user_id = UINT32_MAX;

	lookup_calls = 0;
	EXPECT(t1_nss_account_resolve("synthetic-ok", &user_id) ==
	       T1_NSS_ACCOUNT_OK);
	EXPECT(user_id == 42000U);
	EXPECT(lookup_calls == 1U);
}

static void test_rejections_are_bounded_and_clear_output(void)
{
	struct rejection {
		const char *name;
		int status;
	};
	static const struct rejection rejections[] = {
		{ "synthetic-alias", T1_NSS_ACCOUNT_NON_CANONICAL },
		{ "synthetic-root", T1_NSS_ACCOUNT_ROOT },
		{ "synthetic-absent", T1_NSS_ACCOUNT_NOT_FOUND },
		{ "synthetic-error", T1_NSS_ACCOUNT_LOOKUP_FAILED },
		{ "synthetic-erange", T1_NSS_ACCOUNT_LOOKUP_FAILED },
		{ "synthetic-foreign", T1_NSS_ACCOUNT_INVALID_RESULT },
		{ "synthetic-static", T1_NSS_ACCOUNT_INVALID_RESULT },
	};
	size_t index;

	for (index = 0; index < sizeof(rejections) / sizeof(rejections[0]);
	     ++index) {
		uint32_t user_id = UINT32_MAX;

		lookup_calls = 0;
		EXPECT(t1_nss_account_resolve(rejections[index].name,
					      &user_id) ==
		       rejections[index].status);
		EXPECT(user_id == 0);
		EXPECT(lookup_calls == 1U);
	}
}

static void test_invalid_inputs_never_reach_nss(void)
{
	char oversized[257];
	uint32_t user_id = UINT32_MAX;

	memset(oversized, 'x', sizeof(oversized));
	oversized[sizeof(oversized) - 1U] = '\0';
	lookup_calls = 0;
	EXPECT(t1_nss_account_resolve(NULL, &user_id) ==
	       T1_NSS_ACCOUNT_INVALID_INPUT);
	EXPECT(user_id == 0);
	user_id = UINT32_MAX;
	EXPECT(t1_nss_account_resolve("", &user_id) ==
	       T1_NSS_ACCOUNT_INVALID_INPUT);
	EXPECT(user_id == 0);
	user_id = UINT32_MAX;
	EXPECT(t1_nss_account_resolve(oversized, &user_id) ==
	       T1_NSS_ACCOUNT_INVALID_INPUT);
	EXPECT(user_id == 0);
	EXPECT(t1_nss_account_resolve("synthetic-ok", NULL) ==
	       T1_NSS_ACCOUNT_INVALID_INPUT);
	EXPECT(lookup_calls == 0U);
}

static void test_uid_width_guard(void)
{
	EXPECT(t1_nss_account_uid_is_representable_for_test(UINT32_MAX) == 1);
#if UINTMAX_MAX > UINT32_MAX
	EXPECT(t1_nss_account_uid_is_representable_for_test(
		       (uintmax_t)UINT32_MAX + 1U) == 0);
#endif
}

int main(void)
{
	test_exact_canonical_non_root_account();
	test_rejections_are_bounded_and_clear_output();
	test_invalid_inputs_never_reach_nss();
	test_uid_width_guard();
	if (failures != 0) {
		fprintf(stderr, "NSS account resolver: %u tests failed\n", failures);
		return 1;
	}
	puts("NSS account resolver: all tests passed");
	return 0;
}

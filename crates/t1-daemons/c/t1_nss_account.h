#ifndef T1BRIDGE_NSS_ACCOUNT_H
#define T1BRIDGE_NSS_ACCOUNT_H

#include <stdint.h>

enum t1_nss_account_status {
	T1_NSS_ACCOUNT_OK = 0,
	T1_NSS_ACCOUNT_INVALID_INPUT = 1,
	T1_NSS_ACCOUNT_LOOKUP_FAILED = 2,
	T1_NSS_ACCOUNT_NOT_FOUND = 3,
	T1_NSS_ACCOUNT_NON_CANONICAL = 4,
	T1_NSS_ACCOUNT_ROOT = 5,
	T1_NSS_ACCOUNT_UNREPRESENTABLE = 6,
	T1_NSS_ACCOUNT_INVALID_RESULT = 7,
};

/* Resolves one already-bounded account name with exactly one NSS lookup. */
int t1_nss_account_resolve(const char *username, uint32_t *user_id);

#ifdef T1_NSS_ACCOUNT_TEST
int t1_nss_account_uid_is_representable_for_test(uintmax_t user_id);
#endif

#endif

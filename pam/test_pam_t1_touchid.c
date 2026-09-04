#include <assert.h>

#include "pam_t1_touchid.c"

int main(void)
{
	uid_t user_id = 0;
	pid_t child;

	assert(strcmp(purpose_for_service("sudo"), "approve") == 0);
	assert(strcmp(purpose_for_service("polkit-1"), "approve") == 0);
	assert(strcmp(purpose_for_service("hyprlock"), "authenticate") == 0);
	assert(strcmp(purpose_for_service(NULL), "authenticate") == 0);

	assert(resolve_user_id("root", &user_id) < 0);
	assert(resolve_user_id("t1bridge-synthetic-missing-user", &user_id) < 0);
	assert(resolve_user_id(NULL, &user_id) < 0);
	assert(run_helper_at("/usr/bin/true", 42000, "authenticate") == 0);
	assert(run_helper_at("/usr/bin/false", 42000, "approve") < 0);
	assert(run_helper_at("/definitely/missing", 42000, "authenticate") < 0);

	child = fork();
	assert(child >= 0);
	if (child == 0)
		for (;;)
			pause();
	assert(wait_for_child(child, 50) < 0);
	errno = 0;
	assert(kill(child, 0) < 0 && errno == ESRCH);
	return 0;
}

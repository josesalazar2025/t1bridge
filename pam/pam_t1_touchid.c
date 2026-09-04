#include <errno.h>
#include <fcntl.h>
#include <linux/close_range.h>
#include <pwd.h>
#include <security/pam_ext.h>
#include <security/pam_modules.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PAM_HELPER "/usr/lib/t1bridge/t1-pam-auth"
#define HELPER_TIMEOUT_MILLISECONDS 70000
#define USER_BUFFER_SIZE 16384

static const char *purpose_for_service(const char *service)
{
	if (service && (strcmp(service, "sudo") == 0 ||
			strcmp(service, "polkit-1") == 0))
		return "approve";
	return "authenticate";
}

static int helper_is_trusted(const char *path)
{
	struct stat status;

	return lstat(path, &status) == 0 && S_ISREG(status.st_mode) &&
		status.st_uid == 0 && (status.st_mode & (S_IWGRP | S_IWOTH)) == 0 &&
		access(path, X_OK) == 0;
}

static int resolve_user_id(const char *name, uid_t *user_id)
{
	char buffer[USER_BUFFER_SIZE];
	struct passwd record;
	struct passwd *result = NULL;

	if (!name || !*name || !user_id ||
		getpwnam_r(name, &record, buffer, sizeof(buffer), &result) != 0 ||
		!result || result->pw_uid == 0)
		return -1;
	*user_id = result->pw_uid;
	return 0;
}

static int prepare_child(pid_t expected_parent)
{
	const struct sigaction default_action = { .sa_handler = SIG_DFL };
	sigset_t termination_signal;

	if (sigaction(SIGTERM, &default_action, NULL) < 0 ||
		sigemptyset(&termination_signal) < 0 ||
		sigaddset(&termination_signal, SIGTERM) < 0 ||
		sigprocmask(SIG_UNBLOCK, &termination_signal, NULL) < 0 ||
		prctl(PR_SET_PDEATHSIG, SIGTERM) < 0 || getppid() != expected_parent)
		return -1;
	return 0;
}

static long long monotonic_milliseconds(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return -1;
	return (long long)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static void terminate_child(pid_t child)
{
	const struct timespec interval = { .tv_sec = 0, .tv_nsec = 50000000 };
	int status;

	(void)kill(child, SIGTERM);
	for (int attempt = 0; attempt < 10; attempt++) {
		pid_t waited = waitpid(child, &status, WNOHANG);

		if (waited == child || (waited < 0 && errno == ECHILD))
			return;
		if (waited < 0 && errno != EINTR)
			break;
		(void)nanosleep(&interval, NULL);
	}
	(void)kill(child, SIGKILL);
	while (waitpid(child, &status, 0) < 0 && errno == EINTR)
		;
}

static int wait_for_child(pid_t child, long long timeout_milliseconds)
{
	const struct timespec interval = { .tv_sec = 0, .tv_nsec = 50000000 };
	long long start = monotonic_milliseconds();
	int status;

	if (start < 0)
		goto failed;
	for (;;) {
		pid_t waited = waitpid(child, &status, WNOHANG);
		long long now;

		if (waited == child)
			return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
		if (waited < 0 && errno != EINTR)
			goto failed;
		now = monotonic_milliseconds();
		if (now < 0 || now - start >= timeout_milliseconds)
			goto failed;
		(void)nanosleep(&interval, NULL);
	}

failed:
	terminate_child(child);
	return -1;
}

static int run_helper_at(const char *path, uid_t user_id, const char *purpose)
{
	char encoded_user[16];
	pid_t parent = getpid();
	pid_t child;
	int length;

	length = snprintf(encoded_user, sizeof(encoded_user), "%u",
			  (unsigned int)user_id);
	if (!helper_is_trusted(path) || length <= 0 ||
		(size_t)length >= sizeof(encoded_user))
		return -1;
	child = fork();
	if (child < 0)
		return -1;
	if (child == 0) {
		int null_fd = open("/dev/null", O_RDWR | O_CLOEXEC);
		char *const arguments[] = {
			(char *)path,
			encoded_user,
			(char *)purpose,
			NULL,
		};
		char *const environment[] = { "PATH=/usr/sbin:/usr/bin", NULL };

		if (prepare_child(parent) < 0 || null_fd < 0)
			_exit(127);
		if (dup2(null_fd, STDIN_FILENO) < 0 ||
			dup2(null_fd, STDOUT_FILENO) < 0 ||
			dup2(null_fd, STDERR_FILENO) < 0)
			_exit(127);
		if (close_range(STDERR_FILENO + 1, ~0U,
				CLOSE_RANGE_UNSHARE) < 0)
			_exit(127);
		execve(path, arguments, environment);
		_exit(127);
	}
	return wait_for_child(child, HELPER_TIMEOUT_MILLISECONDS);
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
				   const char **argv)
{
	const void *service_item = NULL;
	const char *user = NULL;
	uid_t user_id;

	(void)flags;
	(void)argv;
	if (argc != 0 || pam_get_user(pamh, &user, NULL) != PAM_SUCCESS ||
		resolve_user_id(user, &user_id) < 0 ||
		pam_get_item(pamh, PAM_SERVICE, &service_item) != PAM_SUCCESS ||
		!service_item)
		return PAM_IGNORE;

	return run_helper_at(PAM_HELPER, user_id,
			     purpose_for_service((const char *)service_item)) == 0
		       ? PAM_SUCCESS
		       : PAM_IGNORE;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
			      const char **argv)
{
	(void)pamh;
	(void)flags;
	(void)argc;
	(void)argv;
	return PAM_SUCCESS;
}

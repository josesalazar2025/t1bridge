#define _GNU_SOURCE

#include "t1_usb_cycle_guard.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define T1_USB_CYCLE_LOCK_PATH "/run/lock/t1bridge-usb-cycle.lock"
#define T1_SEP_LOCK_PATH "/run/lock/t1-touchid-sep.lock"

static int cycle_fd = -1;
static int sep_fd = -1;
static volatile sig_atomic_t interrupted;
static bool handlers_installed;
static struct sigaction old_hup;
static struct sigaction old_int;
static struct sigaction old_term;

static void handle_signal(int signal_number)
{
	(void)signal_number;
	interrupted = 1;
}

static int open_lock(const char *path, int *descriptor)
{
	struct stat metadata;
	int fd;

	fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0600);
	if (fd < 0)
		return T1_USB_CYCLE_GUARD_SYSTEM;
	if (fstat(fd, &metadata) < 0 || !S_ISREG(metadata.st_mode) ||
	    metadata.st_uid != geteuid() || metadata.st_gid != getegid() ||
	    (metadata.st_mode & 07777) != 0600 || metadata.st_nlink != 1) {
		close(fd);
		return T1_USB_CYCLE_GUARD_INVALID;
	}
	if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
		int status = errno == EWOULDBLOCK ? T1_USB_CYCLE_GUARD_BUSY :
			T1_USB_CYCLE_GUARD_SYSTEM;

		close(fd);
		return status;
	}
	*descriptor = fd;
	return T1_USB_CYCLE_GUARD_OK;
}

static void close_lock(int *descriptor)
{
	if (*descriptor < 0)
		return;
	(void)flock(*descriptor, LOCK_UN);
	(void)close(*descriptor);
	*descriptor = -1;
}

static int install_handlers(void)
{
	struct sigaction action = { 0 };

	action.sa_handler = handle_signal;
	if (sigemptyset(&action.sa_mask) < 0 ||
	    sigaction(SIGHUP, &action, &old_hup) < 0)
		return T1_USB_CYCLE_GUARD_SYSTEM;
	if (sigaction(SIGINT, &action, &old_int) < 0) {
		(void)sigaction(SIGHUP, &old_hup, NULL);
		return T1_USB_CYCLE_GUARD_SYSTEM;
	}
	if (sigaction(SIGTERM, &action, &old_term) < 0) {
		(void)sigaction(SIGINT, &old_int, NULL);
		(void)sigaction(SIGHUP, &old_hup, NULL);
		return T1_USB_CYCLE_GUARD_SYSTEM;
	}
	handlers_installed = true;
	return T1_USB_CYCLE_GUARD_OK;
}

static void restore_handlers(void)
{
	if (!handlers_installed)
		return;
	(void)sigaction(SIGTERM, &old_term, NULL);
	(void)sigaction(SIGINT, &old_int, NULL);
	(void)sigaction(SIGHUP, &old_hup, NULL);
	handlers_installed = false;
}

int t1_usb_cycle_guard_acquire_path(const char *cycle_path)
{
	int status;

	if (!cycle_path || cycle_fd >= 0 || sep_fd >= 0 ||
	    handlers_installed)
		return T1_USB_CYCLE_GUARD_INVALID;
	interrupted = 0;
	status = open_lock(cycle_path, &cycle_fd);
	if (status != T1_USB_CYCLE_GUARD_OK)
		return status;
	status = install_handlers();
	if (status != T1_USB_CYCLE_GUARD_OK)
		close_lock(&cycle_fd);
	return status;
}

int t1_usb_cycle_guard_acquire(void)
{
	if (geteuid() != 0 || getegid() != 0)
		return T1_USB_CYCLE_GUARD_INVALID;
	return t1_usb_cycle_guard_acquire_path(T1_USB_CYCLE_LOCK_PATH);
}

int t1_usb_cycle_guard_acquire_sep_path(const char *sep_path)
{
	if (!sep_path || cycle_fd < 0 || sep_fd >= 0 || !handlers_installed)
		return T1_USB_CYCLE_GUARD_INVALID;
	return open_lock(sep_path, &sep_fd);
}

int t1_usb_cycle_guard_acquire_sep(void)
{
	if (geteuid() != 0 || getegid() != 0)
		return T1_USB_CYCLE_GUARD_INVALID;
	return t1_usb_cycle_guard_acquire_sep_path(T1_SEP_LOCK_PATH);
}

int t1_usb_cycle_guard_interrupted(void)
{
	return interrupted != 0;
}

void t1_usb_cycle_guard_release_sep(void)
{
	close_lock(&sep_fd);
}

void t1_usb_cycle_guard_release(void)
{
	restore_handlers();
	t1_usb_cycle_guard_release_sep();
	close_lock(&cycle_fd);
	interrupted = 0;
}

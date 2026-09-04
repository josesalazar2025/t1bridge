#define _GNU_SOURCE

#include "t1_usb_cycle_guard.h"

#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

static void make_path(char *output, size_t output_size, const char *directory,
		      const char *name)
{
	assert(snprintf(output, output_size, "%s/%s", directory, name) > 0);
}

int main(void)
{
	char temporary[] = "/tmp/t1-usb-cycle-guard-XXXXXX";
	char cycle_path[128];
	char sep_path[128];
	int competing;

	assert(mkdtemp(temporary));
	make_path(cycle_path, sizeof(cycle_path), temporary, "cycle.lock");
	make_path(sep_path, sizeof(sep_path), temporary, "sep.lock");

	assert(t1_usb_cycle_guard_acquire_path(cycle_path) ==
	       T1_USB_CYCLE_GUARD_OK);
	assert(t1_usb_cycle_guard_acquire_sep_path(sep_path) ==
	       T1_USB_CYCLE_GUARD_OK);
	assert(t1_usb_cycle_guard_interrupted() == 0);
	assert(raise(SIGTERM) == 0);
	assert(t1_usb_cycle_guard_interrupted() == 1);
	t1_usb_cycle_guard_release();

	competing = open(sep_path, O_RDWR | O_CLOEXEC);
	assert(competing >= 0);
	assert(flock(competing, LOCK_EX | LOCK_NB) == 0);
	assert(t1_usb_cycle_guard_acquire_path(cycle_path) ==
	       T1_USB_CYCLE_GUARD_OK);
	assert(t1_usb_cycle_guard_acquire_sep_path(sep_path) ==
	       T1_USB_CYCLE_GUARD_BUSY);
	t1_usb_cycle_guard_release();
	assert(flock(competing, LOCK_UN) == 0);
	assert(close(competing) == 0);

	competing = open(cycle_path, O_RDWR | O_CLOEXEC);
	assert(competing >= 0);
	assert(flock(competing, LOCK_EX | LOCK_NB) == 0);
	assert(t1_usb_cycle_guard_acquire_path(cycle_path) ==
	       T1_USB_CYCLE_GUARD_BUSY);
	assert(flock(competing, LOCK_UN) == 0);
	assert(close(competing) == 0);

	assert(chmod(cycle_path, 0644) == 0);
	assert(t1_usb_cycle_guard_acquire_path(cycle_path) ==
	       T1_USB_CYCLE_GUARD_INVALID);
	assert(chmod(cycle_path, 0600) == 0);

	assert(unlink(sep_path) == 0);
	assert(unlink(cycle_path) == 0);
	assert(rmdir(temporary) == 0);
	return 0;
}

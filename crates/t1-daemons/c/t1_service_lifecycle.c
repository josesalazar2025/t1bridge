#define _POSIX_C_SOURCE 200809L

#include "t1_service_lifecycle.h"

#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <systemd/sd-daemon.h>

struct t1_service_lifecycle {
	struct sigaction previous_interrupt;
	struct sigaction previous_terminate;
	bool ready_reported;
};

static struct t1_service_lifecycle *active_lifecycle;
static volatile sig_atomic_t cancellation_requested;

int t1_service_notify_ready_once(void)
{
	return sd_notify(0, "READY=1") > 0 ? 0 : -1;
}

static void request_cancellation(int signal_number)
{
	(void)signal_number;
	cancellation_requested = 1;
}

static int signal_set(sigset_t *signals)
{
	return sigemptyset(signals) == 0 &&
	       sigaddset(signals, SIGINT) == 0 &&
	       sigaddset(signals, SIGTERM) == 0 ?
		       0 :
		       -1;
}

int t1_service_lifecycle_install(struct t1_service_lifecycle **output)
{
	struct t1_service_lifecycle *lifecycle;
	struct sigaction action;
	sigset_t blocked;
	sigset_t previous_mask;
	int interrupt_installed = 0;
	int terminate_installed = 0;

	if (output == NULL)
		return -1;
	*output = NULL;
	if (active_lifecycle != NULL)
		return -1;
	if (signal_set(&blocked) != 0 ||
	    sigprocmask(SIG_BLOCK, &blocked, &previous_mask) != 0)
		return -1;
	lifecycle = calloc(1, sizeof(*lifecycle));
	if (lifecycle == NULL) {
		(void)sigprocmask(SIG_SETMASK, &previous_mask, NULL);
		return -1;
	}
	memset(&action, 0, sizeof(action));
	action.sa_handler = request_cancellation;
	action.sa_flags = SA_RESTART;
	if (signal_set(&action.sa_mask) != 0 ||
	    sigaction(SIGINT, &action, &lifecycle->previous_interrupt) != 0)
		goto fail;
	interrupt_installed = 1;
	if (sigaction(SIGTERM, &action, &lifecycle->previous_terminate) != 0)
		goto fail;
	terminate_installed = 1;
	cancellation_requested = 0;
	active_lifecycle = lifecycle;
	if (sigprocmask(SIG_SETMASK, &previous_mask, NULL) != 0)
		goto fail;
	*output = lifecycle;
	return 0;

fail:
	active_lifecycle = NULL;
	cancellation_requested = 0;
	if (terminate_installed)
		(void)sigaction(
			SIGTERM, &lifecycle->previous_terminate, NULL);
	if (interrupt_installed)
		(void)sigaction(
			SIGINT, &lifecycle->previous_interrupt, NULL);
	(void)sigprocmask(SIG_SETMASK, &previous_mask, NULL);
	free(lifecycle);
	return -1;
}

int t1_service_lifecycle_cancelled(
	const struct t1_service_lifecycle *lifecycle)
{
	return lifecycle != NULL && lifecycle == active_lifecycle &&
	       cancellation_requested != 0;
}

int t1_service_lifecycle_notify_ready(
	struct t1_service_lifecycle *lifecycle)
{
	int result;

	if (lifecycle == NULL || lifecycle != active_lifecycle ||
	    lifecycle->ready_reported || cancellation_requested != 0)
		return -1;
	result = sd_notify(0, "READY=1");
	if (result <= 0)
		return -1;
	lifecycle->ready_reported = true;
	return 0;
}

int t1_service_lifecycle_destroy(struct t1_service_lifecycle *lifecycle)
{
	sigset_t blocked;
	sigset_t previous_mask;
	int signals_blocked = 0;
	int clean = 1;

	if (lifecycle == NULL || lifecycle != active_lifecycle)
		return -1;
	if (signal_set(&blocked) == 0 &&
	    sigprocmask(SIG_BLOCK, &blocked, &previous_mask) == 0)
		signals_blocked = 1;
	else
		clean = 0;
	if (sigaction(SIGTERM, &lifecycle->previous_terminate, NULL) != 0)
		clean = 0;
	if (sigaction(SIGINT, &lifecycle->previous_interrupt, NULL) != 0)
		clean = 0;
	active_lifecycle = NULL;
	cancellation_requested = 0;
	if (signals_blocked &&
	    sigprocmask(SIG_SETMASK, &previous_mask, NULL) != 0)
		clean = 0;
	memset(lifecycle, 0, sizeof(*lifecycle));
	free(lifecycle);
	return clean ? 0 : -1;
}

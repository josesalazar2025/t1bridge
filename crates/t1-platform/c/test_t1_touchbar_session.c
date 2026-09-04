#include "t1_touchbar_session.h"

#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct synthetic_login_state {
	uid_t active_uid;
	uid_t session_uid;
	const char *active_session;
	const char *second_session;
	const char *seat;
	const char *type;
	int active;
	int remote;
	int seat_result;
	int uid_result;
	int session_seat_result;
	int type_result;
	int monitor_new_result;
	int flush_result;
	int monitor_fd;
	int monitor_events;
	int timeout_result;
	uint64_t monitor_timeout;
	unsigned int seat_calls;
	unsigned int flush_calls;
	unsigned int unref_calls;
	unsigned int brightness_calls;
	uint32_t brightness_value;
	uint64_t brightness_timeout_usec;
	int brightness_result;
	const char *expected_brightness_subsystem;
	const char *expected_brightness_name;
	int category_was_seat;
};

static struct synthetic_login_state login_state;
static unsigned int failures;

static void check(int condition, const char *description)
{
	if (condition)
		return;
	fprintf(stderr, "FAIL: %s\n", description);
	++failures;
}

static uid_t synthetic_peer_uid(void)
{
	uid_t uid = (uid_t)getpid();

	/* A userspace test process is never PID zero. */
	return uid;
}

static char *copy_string(const char *source)
{
	size_t length;
	char *copy;

	if (source == NULL)
		return NULL;
	length = strlen(source) + 1;
	copy = malloc(length);
	if (copy != NULL)
		memcpy(copy, source, length);
	return copy;
}

static void reset_login_state(void)
{
	memset(&login_state, 0, sizeof(login_state));
	login_state.active_uid = synthetic_peer_uid();
	login_state.session_uid = synthetic_peer_uid();
	login_state.active_session = "synthetic-current-session";
	login_state.seat = "seat0";
	login_state.type = "wayland";
	login_state.active = 1;
	login_state.remote = 0;
	login_state.monitor_fd = 37;
	login_state.monitor_events = POLLIN;
	login_state.monitor_timeout = UINT64_C(9000000);
	login_state.expected_brightness_subsystem = "backlight";
	login_state.expected_brightness_name = "synthetic-display";
}

static int synthetic_seat_get_active(const char *seat, char **session,
	uid_t *uid)
{
	const char *selected;

	check(strcmp(seat, "seat0") == 0,
	    "query only systemd's canonical primary seat");
	++login_state.seat_calls;
	selected = login_state.active_session;
	if (login_state.second_session != NULL && login_state.seat_calls >= 2)
		selected = login_state.second_session;
	*session = copy_string(selected);
	*uid = login_state.active_uid;
	return login_state.seat_result;
}

static int synthetic_session_is_active(const char *session)
{
	(void)session;
	return login_state.active;
}

static int synthetic_session_is_remote(const char *session)
{
	(void)session;
	return login_state.remote;
}

static int synthetic_session_get_uid(const char *session, uid_t *uid)
{
	(void)session;
	*uid = login_state.session_uid;
	return login_state.uid_result;
}

static int synthetic_session_get_seat(const char *session, char **seat)
{
	(void)session;
	*seat = copy_string(login_state.seat);
	return login_state.session_seat_result;
}

static int synthetic_session_get_type(const char *session, char **type)
{
	(void)session;
	*type = copy_string(login_state.type);
	return login_state.type_result;
}

static int synthetic_monitor_new(const char *category, void **monitor)
{
	login_state.category_was_seat = strcmp(category, "seat") == 0;
	*monitor = login_state.monitor_new_result < 0 ? NULL : &login_state;
	return login_state.monitor_new_result;
}

static void *synthetic_monitor_unref(void *monitor)
{
	check(monitor == &login_state, "unref the created synthetic monitor");
	++login_state.unref_calls;
	return NULL;
}

static int synthetic_monitor_flush(void *monitor)
{
	check(monitor == &login_state, "flush the created synthetic monitor");
	++login_state.flush_calls;
	return login_state.flush_result;
}

static int synthetic_monitor_get_fd(void *monitor)
{
	check(monitor == &login_state, "query the created monitor descriptor");
	return login_state.monitor_fd;
}

static int synthetic_monitor_get_events(void *monitor)
{
	check(monitor == &login_state, "query the created monitor events");
	return login_state.monitor_events;
}

static int synthetic_monitor_get_timeout(void *monitor,
	uint64_t *timeout_usec)
{
	check(monitor == &login_state, "query the created monitor timeout");
	*timeout_usec = login_state.monitor_timeout;
	return login_state.timeout_result;
}

static int synthetic_set_brightness(const char *session,
	const char *subsystem, const char *name, uint32_t value,
	uint64_t timeout_usec)
{
	check(strcmp(session, login_state.active_session) == 0,
	    "set brightness only for the admitted session");
	check(strcmp(subsystem,
	    login_state.expected_brightness_subsystem) == 0,
	    "pass the fixed brightness subsystem");
	check(strcmp(name, login_state.expected_brightness_name) == 0,
	    "pass the dynamically discovered brightness name");
	++login_state.brightness_calls;
	login_state.brightness_value = value;
	login_state.brightness_timeout_usec = timeout_usec;
	return login_state.brightness_result;
}

static const struct t1_touchbar_session_ops synthetic_ops = {
	.seat_get_active = synthetic_seat_get_active,
	.session_is_active = synthetic_session_is_active,
	.session_is_remote = synthetic_session_is_remote,
	.session_get_uid = synthetic_session_get_uid,
	.session_get_seat = synthetic_session_get_seat,
	.session_get_type = synthetic_session_get_type,
	.monitor_new = synthetic_monitor_new,
	.monitor_unref = synthetic_monitor_unref,
	.monitor_flush = synthetic_monitor_flush,
	.monitor_get_fd = synthetic_monitor_get_fd,
	.monitor_get_events = synthetic_monitor_get_events,
	.monitor_get_timeout = synthetic_monitor_get_timeout,
	.set_brightness = synthetic_set_brightness,
};

static struct t1_touchbar_session_watch *create_watch(void)
{
	struct t1_touchbar_session_watch *watch = NULL;

	check(t1_touchbar_session_watch_create_with_ops(&watch,
	    &synthetic_ops) == T1_TOUCHBAR_SESSION_OK,
	    "create a synthetic seat monitor");
	check(watch != NULL, "return the created seat monitor");
	check(login_state.category_was_seat,
	    "subscribe specifically to seat changes");
	check(login_state.flush_calls == 1,
	    "flush preexisting monitor changes during creation");
	return watch;
}

static void test_admits_graphical_local_peer(void)
{
	struct t1_touchbar_session_watch *watch;
	int descriptor = -1;
	int events = 0;
	uint64_t timeout = 0;

	reset_login_state();
	watch = create_watch();
	if (watch == NULL)
		return;
	check(t1_touchbar_session_watch_poll_source(watch, &descriptor, &events,
	    &timeout) == T1_TOUCHBAR_SESSION_OK,
	    "expose the monitor poll source");
	check(descriptor == login_state.monitor_fd &&
	    events == login_state.monitor_events &&
	    timeout == login_state.monitor_timeout,
	    "preserve monitor fd, readiness mask, and timeout");
	check(t1_touchbar_session_watch_admit(watch, synthetic_peer_uid()) ==
	    T1_TOUCHBAR_SESSION_OK, "admit the matching Wayland peer");
	check(login_state.seat_calls == 2,
	    "take two active-session snapshots before admission");
	check(login_state.flush_calls == 2,
	    "flush monitor changes before admission snapshots");
	check(t1_touchbar_session_watch_is_admitted(watch),
	    "retain the admitted UID/session binding");
	check(t1_touchbar_session_watch_admit(watch, synthetic_peer_uid()) ==
	    T1_TOUCHBAR_SESSION_ALREADY_ADMITTED,
	    "do not replace an existing admission");
	t1_touchbar_session_watch_release(watch);
	check(!t1_touchbar_session_watch_is_admitted(watch),
	    "release an admission on normal disconnect");
	login_state.type = "x11";
	login_state.seat_calls = 0;
	check(t1_touchbar_session_watch_admit(watch, synthetic_peer_uid()) ==
	    T1_TOUCHBAR_SESSION_OK, "admit the matching X11 peer");
	t1_touchbar_session_watch_destroy(watch);
	check(login_state.unref_calls == 1, "unref the monitor during cleanup");
}

static void expect_denied(const char *description)
{
	struct t1_touchbar_session_watch *watch = create_watch();

	if (watch == NULL)
		return;
	check(t1_touchbar_session_watch_admit(watch, synthetic_peer_uid()) ==
	    T1_TOUCHBAR_SESSION_PEER_DENIED, description);
	check(!t1_touchbar_session_watch_is_admitted(watch),
	    "leave no binding after denial");
	t1_touchbar_session_watch_destroy(watch);
}

static void test_denies_wrong_session_properties(void)
{
	struct t1_touchbar_session_watch *watch;
	uid_t peer = synthetic_peer_uid();

	reset_login_state();
	watch = create_watch();
	if (watch != NULL) {
		check(t1_touchbar_session_watch_admit(watch, 0) ==
		    T1_TOUCHBAR_SESSION_PEER_DENIED, "deny a root peer");
		check(login_state.seat_calls == 0,
		    "deny root before querying login state");
		t1_touchbar_session_watch_destroy(watch);
	}
	reset_login_state();
	login_state.active_uid = peer + (uid_t)1;
	expect_denied("deny a peer that does not own the active seat session");
	reset_login_state();
	login_state.session_uid = peer + (uid_t)1;
	expect_denied("deny inconsistent seat and session ownership");
	reset_login_state();
	login_state.active = 0;
	expect_denied("deny an inactive session");
	reset_login_state();
	login_state.remote = 1;
	expect_denied("deny a remote session");
	reset_login_state();
	login_state.seat = "synthetic-secondary-seat";
	expect_denied("deny a session outside canonical seat0");
	reset_login_state();
	login_state.type = "tty";
	expect_denied("deny a non-graphical session");
	reset_login_state();
	login_state.type = "mir";
	expect_denied("deny a graphical type outside the v1 allowlist");
}

static void test_denies_inconsistent_admission(void)
{
	struct t1_touchbar_session_watch *watch;

	reset_login_state();
	login_state.second_session = "synthetic-replacement-session";
	watch = create_watch();
	if (watch == NULL)
		return;
	check(t1_touchbar_session_watch_admit(watch, synthetic_peer_uid()) ==
	    T1_TOUCHBAR_SESSION_PEER_DENIED,
	    "deny a transition between admission snapshots");
	check(login_state.seat_calls == 2,
	    "complete the mandatory admission recheck");
	check(!t1_touchbar_session_watch_is_admitted(watch),
	    "retain no stale binding across admission transition");
	t1_touchbar_session_watch_destroy(watch);
}

static void test_lookup_failures_are_closed(void)
{
	struct t1_touchbar_session_watch *watch;

	reset_login_state();
	login_state.type_result = -1;
	watch = create_watch();
	if (watch != NULL) {
		check(t1_touchbar_session_watch_admit(watch,
		    synthetic_peer_uid()) == T1_TOUCHBAR_SESSION_UNAVAILABLE,
		    "fail closed when graphical type lookup fails");
		t1_touchbar_session_watch_destroy(watch);
	}
	reset_login_state();
	login_state.active = -1;
	watch = create_watch();
	if (watch != NULL) {
		check(t1_touchbar_session_watch_admit(watch,
		    synthetic_peer_uid()) == T1_TOUCHBAR_SESSION_UNAVAILABLE,
		    "fail closed when active-state lookup fails");
		t1_touchbar_session_watch_destroy(watch);
	}
	reset_login_state();
	login_state.remote = -1;
	watch = create_watch();
	if (watch != NULL) {
		check(t1_touchbar_session_watch_admit(watch,
		    synthetic_peer_uid()) == T1_TOUCHBAR_SESSION_UNAVAILABLE,
		    "fail closed when remote-state lookup fails");
		t1_touchbar_session_watch_destroy(watch);
	}
}

static void test_refresh_and_revocation(void)
{
	struct t1_touchbar_session_watch *watch;

	reset_login_state();
	watch = create_watch();
	if (watch == NULL)
		return;
	check(t1_touchbar_session_watch_admit(watch, synthetic_peer_uid()) ==
	    T1_TOUCHBAR_SESSION_OK, "establish a binding for revalidation");
	check(t1_touchbar_session_watch_refresh(watch) ==
	    T1_TOUCHBAR_SESSION_OK, "retain an unchanged active session");
	check(t1_touchbar_session_watch_is_admitted(watch),
	    "keep an unchanged binding admitted");
	login_state.active_session = "synthetic-replacement-session";
	check(t1_touchbar_session_watch_refresh(watch) ==
	    T1_TOUCHBAR_SESSION_REVOKED,
	    "revoke when the active session identity changes");
	check(!t1_touchbar_session_watch_is_admitted(watch),
	    "clear the binding on a seat transition");
	check(t1_touchbar_session_watch_refresh(watch) ==
	    T1_TOUCHBAR_SESSION_NOT_ADMITTED,
	    "require a new admission after revocation");
	t1_touchbar_session_watch_destroy(watch);

	reset_login_state();
	watch = create_watch();
	if (watch == NULL)
		return;
	check(t1_touchbar_session_watch_admit(watch, synthetic_peer_uid()) ==
	    T1_TOUCHBAR_SESSION_OK, "establish a binding before session loss");
	login_state.seat_result = -1;
	check(t1_touchbar_session_watch_refresh(watch) ==
	    T1_TOUCHBAR_SESSION_UNAVAILABLE,
	    "revoke when the active session becomes unavailable");
	check(!t1_touchbar_session_watch_is_admitted(watch),
	    "clear the binding when revalidation cannot complete");
	t1_touchbar_session_watch_destroy(watch);

	reset_login_state();
	watch = create_watch();
	if (watch == NULL)
		return;
	check(t1_touchbar_session_watch_admit(watch, synthetic_peer_uid()) ==
	    T1_TOUCHBAR_SESSION_OK, "establish a binding before UID transition");
	login_state.active_uid = synthetic_peer_uid() + (uid_t)1;
	login_state.session_uid = login_state.active_uid;
	check(t1_touchbar_session_watch_refresh(watch) ==
	    T1_TOUCHBAR_SESSION_REVOKED,
	    "revoke when seat0 becomes active for a different UID");
	check(!t1_touchbar_session_watch_is_admitted(watch),
	    "clear the old UID binding after a seat transition");
	t1_touchbar_session_watch_destroy(watch);
}

static void test_monitor_failures_revoke(void)
{
	struct t1_touchbar_session_watch *watch = NULL;
	int descriptor = 12;
	int events = 12;
	uint64_t timeout = 12;

	reset_login_state();
	login_state.monitor_new_result = -1;
	check(t1_touchbar_session_watch_create_with_ops(&watch,
	    &synthetic_ops) == T1_TOUCHBAR_SESSION_MONITOR_FAILED && watch == NULL,
	    "reject monitor creation failure");
	reset_login_state();
	login_state.flush_result = -1;
	check(t1_touchbar_session_watch_create_with_ops(&watch,
	    &synthetic_ops) == T1_TOUCHBAR_SESSION_MONITOR_FAILED && watch == NULL,
	    "reject initial monitor flush failure");
	check(login_state.unref_calls == 1,
	    "unref a monitor after initial flush failure");

	reset_login_state();
	watch = create_watch();
	if (watch == NULL)
		return;
	check(t1_touchbar_session_watch_admit(watch, synthetic_peer_uid()) ==
	    T1_TOUCHBAR_SESSION_OK, "admit before monitor poll failure");
	login_state.monitor_fd = -1;
	check(t1_touchbar_session_watch_poll_source(watch, &descriptor, &events,
	    &timeout) == T1_TOUCHBAR_SESSION_MONITOR_FAILED,
	    "fail closed when monitor poll source fails");
	check(descriptor == -1 && events == 0 && timeout == UINT64_MAX,
	    "clear poll outputs on monitor failure");
	check(!t1_touchbar_session_watch_is_admitted(watch),
	    "revoke after monitor poll source failure");
	t1_touchbar_session_watch_destroy(watch);

	reset_login_state();
	watch = create_watch();
	if (watch == NULL)
		return;
	check(t1_touchbar_session_watch_admit(watch, synthetic_peer_uid()) ==
	    T1_TOUCHBAR_SESSION_OK, "admit before monitor flush failure");
	login_state.flush_result = -1;
	check(t1_touchbar_session_watch_refresh(watch) ==
	    T1_TOUCHBAR_SESSION_MONITOR_FAILED,
	    "fail closed when change flush fails");
	check(!t1_touchbar_session_watch_is_admitted(watch),
	    "revoke after monitor flush failure");
	t1_touchbar_session_watch_destroy(watch);
}

static void test_invalid_poll_outputs_revoke(void)
{
	struct t1_touchbar_session_watch *watch;
	int descriptor = -1;
	int events = 0;
	uint64_t timeout = 0;

	reset_login_state();
	watch = create_watch();
	if (watch == NULL)
		return;
	check(t1_touchbar_session_watch_admit(watch, synthetic_peer_uid()) ==
	    T1_TOUCHBAR_SESSION_OK, "admit before invalid poll arguments");
	check(t1_touchbar_session_watch_poll_source(watch, NULL, &events,
	    &timeout) == T1_TOUCHBAR_SESSION_INVALID_ARGUMENT,
	    "reject a missing poll descriptor output");
	check(!t1_touchbar_session_watch_is_admitted(watch),
	    "revoke after invalid poll outputs");
	check(t1_touchbar_session_watch_admit(watch, synthetic_peer_uid()) ==
	    T1_TOUCHBAR_SESSION_OK, "readmit after invalid poll arguments");
	check(t1_touchbar_session_watch_poll_source(watch, &descriptor, NULL,
	    &timeout) == T1_TOUCHBAR_SESSION_INVALID_ARGUMENT,
	    "reject a missing poll event output");
	check(!t1_touchbar_session_watch_is_admitted(watch),
	    "revoke after a missing poll event output");
	check(t1_touchbar_session_watch_admit(watch, synthetic_peer_uid()) ==
	    T1_TOUCHBAR_SESSION_OK, "readmit before missing timeout output");
	check(t1_touchbar_session_watch_poll_source(watch, &descriptor, &events,
	    NULL) == T1_TOUCHBAR_SESSION_INVALID_ARGUMENT,
	    "reject a missing poll timeout output");
	check(!t1_touchbar_session_watch_is_admitted(watch),
	    "revoke after a missing poll timeout output");
	t1_touchbar_session_watch_destroy(watch);
}

static void test_brightness_is_bound_to_admitted_session(void)
{
	struct t1_touchbar_session_watch *watch;

	reset_login_state();
	watch = create_watch();
	check(t1_touchbar_session_watch_set_brightness(watch, "backlight",
	    "synthetic-display", 79U) == T1_TOUCHBAR_SESSION_NOT_ADMITTED,
	    "reject brightness before session admission");
	check(t1_touchbar_session_watch_admit(watch, synthetic_peer_uid()) ==
	    T1_TOUCHBAR_SESSION_OK, "admit peer before brightness update");
	check(t1_touchbar_session_watch_set_brightness(watch, "backlight",
	    "synthetic-display", 79U) == T1_TOUCHBAR_SESSION_OK,
	    "set brightness through the admitted session");
	check(login_state.brightness_calls == 1 &&
	    login_state.brightness_value == 79U &&
	    login_state.brightness_timeout_usec == UINT64_C(250000),
	    "deliver one exact brightness value with a bounded call timeout");

	login_state.brightness_result = -ETIMEDOUT;
	check(t1_touchbar_session_watch_set_brightness(watch, "backlight",
	    "synthetic-display", 42U) ==
	    T1_TOUCHBAR_SESSION_BRIGHTNESS_FAILED,
	    "map a logind brightness failure without identity detail");
	check(t1_touchbar_session_watch_is_admitted(watch),
	    "brightness timeout does not revoke an unchanged session");
	login_state.brightness_result = 0;
	check(t1_touchbar_session_watch_set_brightness(watch, "backlight",
	    "synthetic-display", 43U) == T1_TOUCHBAR_SESSION_OK,
	    "allow a later brightness update after a timeout");
	check(t1_touchbar_session_watch_set_brightness(watch, "other",
	    "synthetic-display", 1U) == T1_TOUCHBAR_SESSION_INVALID_ARGUMENT,
	    "reject an unassigned brightness subsystem");
	check(t1_touchbar_session_watch_set_brightness(watch, "backlight",
	    "../device", 1U) == T1_TOUCHBAR_SESSION_INVALID_ARGUMENT,
	    "reject a path-like brightness name");
	t1_touchbar_session_watch_destroy(watch);
}

static void test_arguments_and_diagnostics(void)
{
	struct t1_touchbar_session_watch *watch = (void *)(uintptr_t)1;
	struct t1_touchbar_session_ops incomplete = synthetic_ops;

	reset_login_state();
	check(t1_touchbar_session_watch_create_with_ops(NULL, &synthetic_ops) ==
	    T1_TOUCHBAR_SESSION_INVALID_ARGUMENT,
	    "reject a null watch output");
	incomplete.session_get_type = NULL;
	check(t1_touchbar_session_watch_create_with_ops(&watch, &incomplete) ==
	    T1_TOUCHBAR_SESSION_INVALID_ARGUMENT && watch == NULL,
	    "reject incomplete injected operations and clear output");
	check(t1_touchbar_session_watch_admit(NULL, synthetic_peer_uid()) ==
	    T1_TOUCHBAR_SESSION_INVALID_ARGUMENT,
	    "reject admission without a watch");
	check(t1_touchbar_session_watch_refresh(NULL) ==
	    T1_TOUCHBAR_SESSION_INVALID_ARGUMENT,
	    "reject revalidation without a watch");
	check(!t1_touchbar_session_watch_is_admitted(NULL),
	    "report a null watch as not admitted");
	check(t1_touchbar_session_status_string(T1_TOUCHBAR_SESSION_REVOKED) !=
	    NULL && t1_touchbar_session_status_string(
	    (enum t1_touchbar_session_status)999) != NULL,
	    "provide bounded diagnostics for known and unknown statuses");
	t1_touchbar_session_watch_release(NULL);
	t1_touchbar_session_watch_destroy(NULL);
}

int main(void)
{
	test_admits_graphical_local_peer();
	test_denies_wrong_session_properties();
	test_denies_inconsistent_admission();
	test_lookup_failures_are_closed();
	test_refresh_and_revocation();
	test_monitor_failures_revoke();
	test_invalid_poll_outputs_revoke();
	test_brightness_is_bound_to_admitted_session();
	test_arguments_and_diagnostics();
	if (failures != 0) {
		fprintf(stderr, "%u session test(s) failed\n", failures);
		return EXIT_FAILURE;
	}
	puts("all touchbar session tests passed");
	return EXIT_SUCCESS;
}

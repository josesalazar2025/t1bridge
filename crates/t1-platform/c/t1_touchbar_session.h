#ifndef T1BRIDGE_T1_TOUCHBAR_SESSION_H
#define T1BRIDGE_T1_TOUCHBAR_SESSION_H

#include <stdint.h>
#include <sys/types.h>

enum t1_touchbar_session_status {
	T1_TOUCHBAR_SESSION_OK = 0,
	T1_TOUCHBAR_SESSION_INVALID_ARGUMENT,
	T1_TOUCHBAR_SESSION_ALLOCATION_FAILED,
	T1_TOUCHBAR_SESSION_MONITOR_FAILED,
	T1_TOUCHBAR_SESSION_UNAVAILABLE,
	T1_TOUCHBAR_SESSION_PEER_DENIED,
	T1_TOUCHBAR_SESSION_ALREADY_ADMITTED,
	T1_TOUCHBAR_SESSION_NOT_ADMITTED,
	T1_TOUCHBAR_SESSION_REVOKED,
	T1_TOUCHBAR_SESSION_BRIGHTNESS_FAILED,
};

struct t1_touchbar_session_watch;

/*
 * Injection boundary for deterministic native tests. String-returning
 * callbacks transfer malloc-compatible strings to the caller. Monitor
 * callbacks follow the corresponding sd-login return-value contracts.
 */
struct t1_touchbar_session_ops {
	int (*seat_get_active)(const char *seat, char **session, uid_t *uid);
	int (*session_is_active)(const char *session);
	int (*session_is_remote)(const char *session);
	int (*session_get_uid)(const char *session, uid_t *uid);
	int (*session_get_seat)(const char *session, char **seat);
	int (*session_get_type)(const char *session, char **type);
	int (*monitor_new)(const char *category, void **monitor);
	void *(*monitor_unref)(void *monitor);
	int (*monitor_flush)(void *monitor);
	int (*monitor_get_fd)(void *monitor);
	int (*monitor_get_events)(void *monitor);
	int (*monitor_get_timeout)(void *monitor, uint64_t *timeout_usec);
	int (*set_brightness)(const char *session, const char *subsystem,
		const char *name, uint32_t value, uint64_t timeout_usec);
};

/* Create and initially flush an sd-login monitor for seat changes. */
enum t1_touchbar_session_status t1_touchbar_session_watch_create(
	struct t1_touchbar_session_watch **output);
enum t1_touchbar_session_status t1_touchbar_session_watch_create_with_ops(
	struct t1_touchbar_session_watch **output,
	const struct t1_touchbar_session_ops *ops);

/*
 * Return the fd, requested poll events, and absolute CLOCK_MONOTONIC timeout
 * used to wait for the next monitor change. Failure revokes any admission.
 */
enum t1_touchbar_session_status t1_touchbar_session_watch_poll_source(
	struct t1_touchbar_session_watch *watch, int *descriptor, int *events,
	uint64_t *timeout_usec);

/*
 * Admit only a non-root peer matching two consistent snapshots of the active,
 * local, non-remote Wayland/X11 session on seat0. Group membership and peer
 * credential acquisition belong to the service boundary.
 */
enum t1_touchbar_session_status t1_touchbar_session_watch_admit(
	struct t1_touchbar_session_watch *watch, uid_t peer_uid);

/*
 * After monitor readiness or timeout, flush queued changes and revalidate the
 * exact admitted UID/session pair. Every non-OK result clears the admission
 * and therefore requires service-side resource and synthesized-key cleanup.
 */
enum t1_touchbar_session_status t1_touchbar_session_watch_refresh(
	struct t1_touchbar_session_watch *watch);

/* Set one validated brightness class through the admitted logind session. */
enum t1_touchbar_session_status t1_touchbar_session_watch_set_brightness(
	struct t1_touchbar_session_watch *watch, const char *subsystem,
	const char *name, uint32_t value);

int t1_touchbar_session_watch_is_admitted(
	const struct t1_touchbar_session_watch *watch);
void t1_touchbar_session_watch_release(
	struct t1_touchbar_session_watch *watch);
void t1_touchbar_session_watch_destroy(
	struct t1_touchbar_session_watch *watch);

const char *t1_touchbar_session_status_string(
	enum t1_touchbar_session_status status);

#endif

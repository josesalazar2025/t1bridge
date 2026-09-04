#include "t1_touchbar_session.h"

#include <stdlib.h>
#include <string.h>
#include <systemd/sd-bus.h>
#include <systemd/sd-login.h>

#define T1_PRIMARY_SEAT "seat0"
#define T1_MONITOR_CATEGORY "seat"
#define T1_BRIGHTNESS_CALL_TIMEOUT_USEC UINT64_C(250000)

struct t1_touchbar_session_watch {
	struct t1_touchbar_session_ops ops;
	void *monitor;
	char *session;
	uid_t uid;
};

struct t1_session_snapshot {
	char *session;
	uid_t uid;
};

static int systemd_monitor_new(const char *category, void **monitor)
{
	sd_login_monitor *created = NULL;
	int result;

	result = sd_login_monitor_new(category, &created);
	*monitor = created;
	return result;
}

static void *systemd_monitor_unref(void *monitor)
{
	return sd_login_monitor_unref(monitor);
}

static int systemd_monitor_flush(void *monitor)
{
	return sd_login_monitor_flush(monitor);
}

static int systemd_monitor_get_fd(void *monitor)
{
	return sd_login_monitor_get_fd(monitor);
}

static int systemd_monitor_get_events(void *monitor)
{
	return sd_login_monitor_get_events(monitor);
}

static int systemd_monitor_get_timeout(void *monitor,
	uint64_t *timeout_usec)
{
	return sd_login_monitor_get_timeout(monitor, timeout_usec);
}

static int systemd_set_brightness(const char *session,
	const char *subsystem, const char *name, uint32_t value,
	uint64_t timeout_usec)
{
	sd_bus *bus = NULL;
	sd_bus_message *message = NULL;
	char *path = NULL;
	int result;

	result = sd_bus_default_system(&bus);
	if (result < 0)
		goto out;
	result = sd_bus_path_encode("/org/freedesktop/login1/session",
		session, &path);
	if (result < 0)
		goto out;
	result = sd_bus_message_new_method_call(bus, &message,
		"org.freedesktop.login1", path,
		"org.freedesktop.login1.Session", "SetBrightness");
	if (result < 0)
		goto out;
	result = sd_bus_message_append(message, "ssu", subsystem, name, value);
	if (result < 0)
		goto out;
	result = sd_bus_call(bus, message, timeout_usec, NULL, NULL);

out:
	sd_bus_message_unref(message);
	free(path);
	sd_bus_unref(bus);
	return result;
}

static const struct t1_touchbar_session_ops systemd_ops = {
	.seat_get_active = sd_seat_get_active,
	.session_is_active = sd_session_is_active,
	.session_is_remote = sd_session_is_remote,
	.session_get_uid = sd_session_get_uid,
	.session_get_seat = sd_session_get_seat,
	.session_get_type = sd_session_get_type,
	.monitor_new = systemd_monitor_new,
	.monitor_unref = systemd_monitor_unref,
	.monitor_flush = systemd_monitor_flush,
	.monitor_get_fd = systemd_monitor_get_fd,
	.monitor_get_events = systemd_monitor_get_events,
	.monitor_get_timeout = systemd_monitor_get_timeout,
	.set_brightness = systemd_set_brightness,
};

static int ops_valid(const struct t1_touchbar_session_ops *ops)
{
	return ops != NULL && ops->seat_get_active != NULL &&
	    ops->session_is_active != NULL &&
	    ops->session_is_remote != NULL &&
	    ops->session_get_uid != NULL && ops->session_get_seat != NULL &&
	    ops->session_get_type != NULL && ops->monitor_new != NULL &&
	    ops->monitor_unref != NULL && ops->monitor_flush != NULL &&
	    ops->monitor_get_fd != NULL &&
	    ops->monitor_get_events != NULL &&
	    ops->monitor_get_timeout != NULL && ops->set_brightness != NULL;
}

static int graphical_type(const char *type)
{
	return strcmp(type, "wayland") == 0 || strcmp(type, "x11") == 0;
}

static void snapshot_clear(struct t1_session_snapshot *snapshot)
{
	if (snapshot == NULL)
		return;
	free(snapshot->session);
	snapshot->session = NULL;
	snapshot->uid = 0;
}

static enum t1_touchbar_session_status snapshot_load(
	const struct t1_touchbar_session_ops *ops, uid_t expected_uid,
	struct t1_session_snapshot *snapshot)
{
	char *seat = NULL;
	char *session = NULL;
	char *type = NULL;
	uid_t active_uid = 0;
	uid_t session_uid = 0;
	int active;
	int remote;
	enum t1_touchbar_session_status result = T1_TOUCHBAR_SESSION_UNAVAILABLE;

	if (ops->seat_get_active(T1_PRIMARY_SEAT, &session, &active_uid) < 0 ||
	    session == NULL)
		goto out;
	if (active_uid != expected_uid) {
		result = T1_TOUCHBAR_SESSION_PEER_DENIED;
		goto out;
	}
	if (ops->session_get_uid(session, &session_uid) < 0 ||
	    ops->session_get_seat(session, &seat) < 0 || seat == NULL ||
	    ops->session_get_type(session, &type) < 0 || type == NULL) {
		goto out;
	}
	active = ops->session_is_active(session);
	remote = ops->session_is_remote(session);
	if (active < 0 || remote < 0)
		goto out;
	if (session_uid != expected_uid || active == 0 || remote != 0 ||
	    strcmp(seat, T1_PRIMARY_SEAT) != 0 || !graphical_type(type)) {
		result = T1_TOUCHBAR_SESSION_PEER_DENIED;
		goto out;
	}
	snapshot->session = session;
	snapshot->uid = active_uid;
	session = NULL;
	result = T1_TOUCHBAR_SESSION_OK;

out:
	free(type);
	free(seat);
	free(session);
	return result;
}

static void revoke(struct t1_touchbar_session_watch *watch)
{
	free(watch->session);
	watch->session = NULL;
	watch->uid = 0;
}

enum t1_touchbar_session_status t1_touchbar_session_watch_create(
	struct t1_touchbar_session_watch **output)
{
	return t1_touchbar_session_watch_create_with_ops(output, &systemd_ops);
}

enum t1_touchbar_session_status t1_touchbar_session_watch_create_with_ops(
	struct t1_touchbar_session_watch **output,
	const struct t1_touchbar_session_ops *ops)
{
	struct t1_touchbar_session_watch *watch;

	if (output == NULL)
		return T1_TOUCHBAR_SESSION_INVALID_ARGUMENT;
	*output = NULL;
	if (!ops_valid(ops))
		return T1_TOUCHBAR_SESSION_INVALID_ARGUMENT;
	watch = calloc(1, sizeof(*watch));
	if (watch == NULL)
		return T1_TOUCHBAR_SESSION_ALLOCATION_FAILED;
	watch->ops = *ops;
	if (watch->ops.monitor_new(T1_MONITOR_CATEGORY, &watch->monitor) < 0 ||
	    watch->monitor == NULL ||
	    watch->ops.monitor_flush(watch->monitor) < 0) {
		t1_touchbar_session_watch_destroy(watch);
		return T1_TOUCHBAR_SESSION_MONITOR_FAILED;
	}
	*output = watch;
	return T1_TOUCHBAR_SESSION_OK;
}

enum t1_touchbar_session_status t1_touchbar_session_watch_poll_source(
	struct t1_touchbar_session_watch *watch, int *descriptor, int *events,
	uint64_t *timeout_usec)
{
	int monitor_descriptor;
	int monitor_events;
	uint64_t monitor_timeout = UINT64_MAX;

	if (watch == NULL)
		return T1_TOUCHBAR_SESSION_INVALID_ARGUMENT;
	if (descriptor == NULL || events == NULL || timeout_usec == NULL) {
		revoke(watch);
		return T1_TOUCHBAR_SESSION_INVALID_ARGUMENT;
	}
	*descriptor = -1;
	*events = 0;
	*timeout_usec = UINT64_MAX;
	monitor_descriptor = watch->ops.monitor_get_fd(watch->monitor);
	monitor_events = watch->ops.monitor_get_events(watch->monitor);
	if (monitor_descriptor < 0 || monitor_events < 0 ||
	    watch->ops.monitor_get_timeout(watch->monitor, &monitor_timeout) < 0) {
		revoke(watch);
		return T1_TOUCHBAR_SESSION_MONITOR_FAILED;
	}
	*descriptor = monitor_descriptor;
	*events = monitor_events;
	*timeout_usec = monitor_timeout;
	return T1_TOUCHBAR_SESSION_OK;
}

enum t1_touchbar_session_status t1_touchbar_session_watch_admit(
	struct t1_touchbar_session_watch *watch, uid_t peer_uid)
{
	struct t1_session_snapshot first = {0};
	struct t1_session_snapshot second = {0};
	enum t1_touchbar_session_status result;

	if (watch == NULL)
		return T1_TOUCHBAR_SESSION_INVALID_ARGUMENT;
	if (watch->session != NULL)
		return T1_TOUCHBAR_SESSION_ALREADY_ADMITTED;
	if (peer_uid == 0)
		return T1_TOUCHBAR_SESSION_PEER_DENIED;
	if (watch->ops.monitor_flush(watch->monitor) < 0)
		return T1_TOUCHBAR_SESSION_MONITOR_FAILED;
	result = snapshot_load(&watch->ops, peer_uid, &first);
	if (result != T1_TOUCHBAR_SESSION_OK)
		goto out;
	result = snapshot_load(&watch->ops, peer_uid, &second);
	if (result != T1_TOUCHBAR_SESSION_OK)
		goto out;
	if (first.uid != second.uid ||
	    strcmp(first.session, second.session) != 0) {
		result = T1_TOUCHBAR_SESSION_PEER_DENIED;
		goto out;
	}
	watch->session = second.session;
	watch->uid = second.uid;
	second.session = NULL;
	result = T1_TOUCHBAR_SESSION_OK;

out:
	snapshot_clear(&second);
	snapshot_clear(&first);
	return result;
}

enum t1_touchbar_session_status t1_touchbar_session_watch_refresh(
	struct t1_touchbar_session_watch *watch)
{
	struct t1_session_snapshot current = {0};
	enum t1_touchbar_session_status result;

	if (watch == NULL)
		return T1_TOUCHBAR_SESSION_INVALID_ARGUMENT;
	if (watch->session == NULL)
		return T1_TOUCHBAR_SESSION_NOT_ADMITTED;
	if (watch->ops.monitor_flush(watch->monitor) < 0) {
		revoke(watch);
		return T1_TOUCHBAR_SESSION_MONITOR_FAILED;
	}
	result = snapshot_load(&watch->ops, watch->uid, &current);
	if (result != T1_TOUCHBAR_SESSION_OK ||
	    strcmp(watch->session, current.session) != 0) {
		snapshot_clear(&current);
		revoke(watch);
		if (result == T1_TOUCHBAR_SESSION_OK ||
		    result == T1_TOUCHBAR_SESSION_PEER_DENIED)
			return T1_TOUCHBAR_SESSION_REVOKED;
		return result;
	}
	snapshot_clear(&current);
	return T1_TOUCHBAR_SESSION_OK;
}

static int brightness_name_valid(const char *name)
{
	const unsigned char *cursor;
	size_t length;

	if (name == NULL || name[0] == '\0')
		return 0;
	length = strlen(name);
	if (length > 255U || strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
		return 0;
	for (cursor = (const unsigned char *)name; *cursor != '\0'; ++cursor) {
		if (*cursor == '/')
			return 0;
	}
	return 1;
}

enum t1_touchbar_session_status t1_touchbar_session_watch_set_brightness(
	struct t1_touchbar_session_watch *watch, const char *subsystem,
	const char *name, uint32_t value)
{
	if (watch == NULL || subsystem == NULL ||
	    (strcmp(subsystem, "backlight") != 0 &&
	     strcmp(subsystem, "leds") != 0) || !brightness_name_valid(name))
		return T1_TOUCHBAR_SESSION_INVALID_ARGUMENT;
	if (watch->session == NULL)
		return T1_TOUCHBAR_SESSION_NOT_ADMITTED;
	if (watch->ops.set_brightness(watch->session, subsystem, name, value,
	    T1_BRIGHTNESS_CALL_TIMEOUT_USEC) < 0)
		return T1_TOUCHBAR_SESSION_BRIGHTNESS_FAILED;
	return T1_TOUCHBAR_SESSION_OK;
}

int t1_touchbar_session_watch_is_admitted(
	const struct t1_touchbar_session_watch *watch)
{
	return watch != NULL && watch->session != NULL;
}

void t1_touchbar_session_watch_release(
	struct t1_touchbar_session_watch *watch)
{
	if (watch != NULL)
		revoke(watch);
}

void t1_touchbar_session_watch_destroy(
	struct t1_touchbar_session_watch *watch)
{
	if (watch == NULL)
		return;
	revoke(watch);
	if (watch->monitor != NULL)
		watch->monitor = watch->ops.monitor_unref(watch->monitor);
	free(watch);
}

const char *t1_touchbar_session_status_string(
	enum t1_touchbar_session_status status)
{
	switch (status) {
	case T1_TOUCHBAR_SESSION_OK:
		return "session operation succeeded";
	case T1_TOUCHBAR_SESSION_INVALID_ARGUMENT:
		return "invalid session argument";
	case T1_TOUCHBAR_SESSION_ALLOCATION_FAILED:
		return "session allocation failed";
	case T1_TOUCHBAR_SESSION_MONITOR_FAILED:
		return "session monitor failed";
	case T1_TOUCHBAR_SESSION_UNAVAILABLE:
		return "active session unavailable";
	case T1_TOUCHBAR_SESSION_PEER_DENIED:
		return "session peer denied";
	case T1_TOUCHBAR_SESSION_ALREADY_ADMITTED:
		return "session peer already admitted";
	case T1_TOUCHBAR_SESSION_NOT_ADMITTED:
		return "session peer not admitted";
	case T1_TOUCHBAR_SESSION_REVOKED:
		return "session peer revoked";
	case T1_TOUCHBAR_SESSION_BRIGHTNESS_FAILED:
		return "session brightness update failed";
	default:
		return "unknown session failure";
	}
}

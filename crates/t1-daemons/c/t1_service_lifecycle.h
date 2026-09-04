#ifndef T1BRIDGE_SERVICE_LIFECYCLE_H
#define T1BRIDGE_SERVICE_LIFECYCLE_H

struct t1_service_lifecycle;

/* Reports READY=1 once for a service that owns no signal lifecycle. */
int t1_service_notify_ready_once(void);

/* Installs process-wide SIGINT/SIGTERM handlers. Only one owner may exist. */
int t1_service_lifecycle_install(struct t1_service_lifecycle **output);

/* Signal-safe state is observed synchronously between bounded device waits. */
int t1_service_lifecycle_cancelled(
	const struct t1_service_lifecycle *lifecycle);

/* Reports READY=1 through the systemd notification socket exactly once. */
int t1_service_lifecycle_notify_ready(
	struct t1_service_lifecycle *lifecycle);

/* Restores both prior signal dispositions and consumes the owner. */
int t1_service_lifecycle_destroy(struct t1_service_lifecycle *lifecycle);

#endif

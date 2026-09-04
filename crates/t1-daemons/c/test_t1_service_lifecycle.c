#define _POSIX_C_SOURCE 200809L

#include "t1_service_lifecycle.h"

#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static unsigned int failures;
static volatile sig_atomic_t prior_handler_called;

#define EXPECT(condition) expect((condition), #condition, __LINE__)

static void expect(int condition, const char *expression, int line)
{
	if (!condition) {
		fprintf(stderr, "line %d: failed: %s\n", line, expression);
		++failures;
	}
}

static void prior_handler(int signal_number)
{
	(void)signal_number;
	prior_handler_called = 1;
}

static void test_handlers_cancel_and_restore(void)
{
	struct t1_service_lifecycle *lifecycle = NULL;
	struct t1_service_lifecycle *duplicate = NULL;
	struct sigaction previous_interrupt;
	struct sigaction previous_terminate;
	struct sigaction sentinel;

	memset(&sentinel, 0, sizeof(sentinel));
	sentinel.sa_handler = prior_handler;
	EXPECT(sigemptyset(&sentinel.sa_mask) == 0);
	EXPECT(sigaction(SIGINT, &sentinel, &previous_interrupt) == 0);
	EXPECT(sigaction(SIGTERM, &sentinel, &previous_terminate) == 0);
	EXPECT(t1_service_lifecycle_install(&lifecycle) == 0 &&
	       lifecycle != NULL);
	EXPECT(t1_service_lifecycle_install(&duplicate) != 0 &&
	       duplicate == NULL);
	EXPECT(t1_service_lifecycle_cancelled(lifecycle) == 0);
	EXPECT(raise(SIGTERM) == 0);
	EXPECT(t1_service_lifecycle_cancelled(lifecycle) == 1);
	EXPECT(t1_service_lifecycle_destroy(lifecycle) == 0);

	prior_handler_called = 0;
	EXPECT(raise(SIGINT) == 0 && prior_handler_called == 1);
	prior_handler_called = 0;
	EXPECT(raise(SIGTERM) == 0 && prior_handler_called == 1);
	EXPECT(sigaction(SIGINT, &previous_interrupt, NULL) == 0);
	EXPECT(sigaction(SIGTERM, &previous_terminate, NULL) == 0);
}

static void test_readiness_is_exact_and_once(void)
{
	char directory[] = "/tmp/t1bridge-notify-XXXXXX";
	char path[sizeof(directory) + sizeof("/notify.sock")];
	char message[32] = { 0 };
	struct t1_service_lifecycle *lifecycle = NULL;
	struct sockaddr_un address;
	struct pollfd ready;
	ssize_t received;
	int descriptor = -1;

	EXPECT(mkdtemp(directory) != NULL);
	EXPECT(snprintf(path, sizeof(path), "%s/notify.sock", directory) > 0);
	descriptor = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	EXPECT(descriptor >= 0);
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	EXPECT(strlen(path) < sizeof(address.sun_path));
	memcpy(address.sun_path, path, strlen(path) + 1);
	EXPECT(descriptor >= 0 &&
	       bind(descriptor, (const struct sockaddr *)&address,
		    sizeof(address)) == 0);
	EXPECT(setenv("NOTIFY_SOCKET", path, 1) == 0);
	EXPECT(t1_service_lifecycle_install(&lifecycle) == 0);
	EXPECT(t1_service_lifecycle_notify_ready(lifecycle) == 0);
	EXPECT(t1_service_lifecycle_notify_ready(lifecycle) != 0);
	EXPECT(t1_service_notify_ready_once() == 0);
	ready.fd = descriptor;
	ready.events = POLLIN;
	ready.revents = 0;
	EXPECT(poll(&ready, 1, 1000) == 1 && (ready.revents & POLLIN) != 0);
	received = recv(descriptor, message, sizeof(message), 0);
	EXPECT(received == 7 && memcmp(message, "READY=1", 7) == 0);
	memset(message, 0, sizeof(message));
	EXPECT(recv(descriptor, message, sizeof(message), 0) == 7 &&
	       memcmp(message, "READY=1", 7) == 0);
	EXPECT(t1_service_lifecycle_destroy(lifecycle) == 0);
	EXPECT(unsetenv("NOTIFY_SOCKET") == 0);
	EXPECT(t1_service_notify_ready_once() != 0);
	if (descriptor >= 0)
		(void)close(descriptor);
	(void)unlink(path);
	(void)rmdir(directory);
}

static void test_notify_without_systemd_fails_closed(void)
{
	struct t1_service_lifecycle *lifecycle = NULL;

	EXPECT(unsetenv("NOTIFY_SOCKET") == 0);
	EXPECT(t1_service_lifecycle_install(&lifecycle) == 0);
	EXPECT(t1_service_lifecycle_notify_ready(lifecycle) != 0);
	EXPECT(t1_service_lifecycle_destroy(lifecycle) == 0);
}

int main(void)
{
	test_handlers_cancel_and_restore();
	test_readiness_is_exact_and_once();
	test_notify_without_systemd_fails_closed();
	if (failures != 0) {
		fprintf(stderr, "service lifecycle: %u tests failed\n", failures);
		return 1;
	}
	puts("service lifecycle: all tests passed");
	return 0;
}

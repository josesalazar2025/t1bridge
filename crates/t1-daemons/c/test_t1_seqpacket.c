#define _GNU_SOURCE

#include "t1_seqpacket.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned int failures;
static volatile sig_atomic_t sigpipe_count;
static volatile sig_atomic_t alarm_count;

static int mock_connect_enabled;
static int mock_connect_error;
static int mock_client_descriptor = -1;
static int mock_peer_descriptor = -1;
static int mock_socket_domain;
static int mock_socket_type;
static int mock_socket_protocol;
static struct sockaddr_un mock_connect_address;
static socklen_t mock_connect_address_length;

enum peer_groups_mock_mode {
	PEER_GROUPS_REAL,
	PEER_GROUPS_RESIZE_SUCCESS,
	PEER_GROUPS_UNSUPPORTED,
	PEER_GROUPS_MALFORMED,
	PEER_GROUPS_OVERSIZED,
};

static enum peer_groups_mock_mode peer_groups_mode;
static int peer_groups_descriptor = -1;
static unsigned int peer_groups_calls;
static gid_t peer_groups_allowed_gid;

int __real_socket(int domain, int type, int protocol);
int __real_connect(int descriptor, const struct sockaddr *address,
	socklen_t address_length);
int __real_getsockopt(int descriptor, int level, int option, void *value,
	socklen_t *length);

int __wrap_socket(int domain, int type, int protocol)
{
	int descriptors[2] = { -1, -1 };

	if (!mock_connect_enabled)
		return __real_socket(domain, type, protocol);
	mock_socket_domain = domain;
	mock_socket_type = type;
	mock_socket_protocol = protocol;
	if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0,
		       descriptors) != 0)
		return -1;
	mock_client_descriptor = descriptors[0];
	mock_peer_descriptor = descriptors[1];
	return descriptors[0];
}

int __wrap_connect(int descriptor, const struct sockaddr *address,
	socklen_t address_length)
{
	if (!mock_connect_enabled)
		return __real_connect(descriptor, address, address_length);
	if (descriptor != mock_client_descriptor || address == NULL ||
	    address_length > sizeof(mock_connect_address)) {
		errno = EINVAL;
		return -1;
	}
	memset(&mock_connect_address, 0, sizeof(mock_connect_address));
	memcpy(&mock_connect_address, address, address_length);
	mock_connect_address_length = address_length;
	if (mock_connect_error != 0) {
		errno = mock_connect_error;
		return -1;
	}
	return 0;
}

int __wrap_getsockopt(int descriptor, int level, int option, void *value,
	socklen_t *length)
{
	size_t required_count = 65;
	size_t required_length = required_count * sizeof(gid_t);
	gid_t *groups = value;
	size_t index;

	if (peer_groups_mode == PEER_GROUPS_REAL ||
	    descriptor != peer_groups_descriptor || level != SOL_SOCKET ||
	    option != SO_PEERGROUPS)
		return __real_getsockopt(descriptor, level, option, value, length);
	++peer_groups_calls;
	if (value == NULL || length == NULL) {
		errno = EFAULT;
		return -1;
	}
	if (peer_groups_mode == PEER_GROUPS_UNSUPPORTED) {
		errno = ENOPROTOOPT;
		return -1;
	}
	if (peer_groups_mode == PEER_GROUPS_MALFORMED) {
		*length = 1;
		return 0;
	}
	if (peer_groups_mode == PEER_GROUPS_OVERSIZED) {
		*length = (socklen_t)(65537U * sizeof(gid_t));
		errno = ERANGE;
		return -1;
	}
	if (peer_groups_calls == 1) {
		*length = (socklen_t)required_length;
		errno = ERANGE;
		return -1;
	}
	if (*length < required_length) {
		errno = ERANGE;
		return -1;
	}
	for (index = 0; index < required_count; ++index)
		groups[index] = peer_groups_allowed_gid + 1;
	groups[required_count - 1] = peer_groups_allowed_gid;
	*length = (socklen_t)required_length;
	return 0;
}

#define SYSTEMD_LISTENER_DESCRIPTOR 3
#define EXPECTED_TOUCHBAR_SOCKET_PATH "/run/t1bridge/touchbar.sock"
#define EXPECTED_AUTH_SOCKET_PATH "/run/t1-touchid/auth.sock"

struct named_listener {
	char directory[64];
	char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
};

static void alarm_handler(int signal_number);

#define EXPECT_TRUE(expression)                                                \
	do {                                                                    \
		if (!(expression)) {                                              \
			fprintf(stderr, "%s:%d: expectation failed: %s\n",       \
				__FILE__, __LINE__, #expression);                    \
			++failures;                                                 \
		}                                                               \
	} while (0)

#define EXPECT_STATUS(expected, expression)                                   \
	do {                                                                    \
		enum t1_seqpacket_status actual_status = (expression);             \
		if (actual_status != (expected)) {                                \
			fprintf(stderr,                                             \
				"%s:%d: expected status %d, received %d\n",       \
				__FILE__, __LINE__, (int)(expected),                \
				(int)actual_status);                                    \
			++failures;                                                 \
		}                                                               \
	} while (0)

static void close_descriptor(int descriptor)
{
	if (descriptor >= 0)
		EXPECT_TRUE(close(descriptor) == 0);
}

static void begin_mock_connect(int error)
{
	mock_connect_enabled = 1;
	mock_connect_error = error;
	mock_client_descriptor = -1;
	mock_peer_descriptor = -1;
	mock_socket_domain = 0;
	mock_socket_type = 0;
	mock_socket_protocol = -1;
	memset(&mock_connect_address, 0, sizeof(mock_connect_address));
	mock_connect_address_length = 0;
}

static void end_mock_connect(void)
{
	mock_connect_enabled = 0;
	close_descriptor(mock_peer_descriptor);
	mock_peer_descriptor = -1;
}

static void create_pair(int descriptors[2])
{
	EXPECT_TRUE(socketpair(AF_UNIX,
			       SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0,
			       descriptors) == 0);
}

static int first_available_descriptor(int descriptor)
{
	int available = fcntl(descriptor, F_DUPFD_CLOEXEC, 0);

	EXPECT_TRUE(available >= 0);
	close_descriptor(available);
	return available;
}

static ssize_t send_raw_rights(int socket_descriptor, const void *packet,
	size_t packet_length, const int *descriptors, size_t descriptor_count)
{
	union {
		struct cmsghdr alignment;
		uint8_t bytes[CMSG_SPACE(16 * sizeof(int))];
	} control;
	struct iovec vector;
	struct msghdr message;
	struct cmsghdr *header;

	EXPECT_TRUE(descriptor_count > 0 && descriptor_count <= 16);
	vector.iov_base = (void *)packet;
	vector.iov_len = packet_length;
	memset(&message, 0, sizeof(message));
	memset(&control, 0, sizeof(control));
	message.msg_iov = &vector;
	message.msg_iovlen = 1;
	message.msg_control = control.bytes;
	message.msg_controllen = CMSG_SPACE(descriptor_count * sizeof(int));
	header = CMSG_FIRSTHDR(&message);
	EXPECT_TRUE(header != NULL);
	if (header == NULL)
		return -1;
	header->cmsg_level = SOL_SOCKET;
	header->cmsg_type = SCM_RIGHTS;
	header->cmsg_len = CMSG_LEN(descriptor_count * sizeof(int));
	memcpy(CMSG_DATA(header), descriptors,
	       descriptor_count * sizeof(int));
	return sendmsg(socket_descriptor, &message, MSG_NOSIGNAL);
}

static int create_autobound_listener(struct sockaddr_un *address,
				     socklen_t *address_length)
{
	int descriptor = socket(AF_UNIX,
		SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
	struct sockaddr_un unnamed;

	if (descriptor < 0)
		return -1;
	memset(&unnamed, 0, sizeof(unnamed));
	unnamed.sun_family = AF_UNIX;
	if (bind(descriptor, (struct sockaddr *)&unnamed,
		 sizeof(unnamed.sun_family)) != 0 || listen(descriptor, 4) != 0) {
		(void)close(descriptor);
		return -1;
	}
	memset(address, 0, sizeof(*address));
	*address_length = sizeof(*address);
	if (getsockname(descriptor, (struct sockaddr *)address,
			address_length) != 0) {
		(void)close(descriptor);
		return -1;
	}
	return descriptor;
}

static int create_named_listener(struct named_listener *fixture, int type)
{
	struct sockaddr_un address;
	int descriptor;
	int written;

	memset(fixture, 0, sizeof(*fixture));
	memcpy(fixture->directory, "/tmp/t1bridge-seqpacket-XXXXXX",
	       sizeof("/tmp/t1bridge-seqpacket-XXXXXX"));
	if (mkdtemp(fixture->directory) == NULL)
		return -1;
	written = snprintf(fixture->path, sizeof(fixture->path), "%s/listener",
			   fixture->directory);
	if (written <= 0 || (size_t)written >= sizeof(fixture->path)) {
		(void)rmdir(fixture->directory);
		return -1;
	}
	descriptor = socket(AF_UNIX, type | SOCK_CLOEXEC, 0);
	if (descriptor < 0) {
		(void)rmdir(fixture->directory);
		return -1;
	}
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	memcpy(address.sun_path, fixture->path, (size_t)written + 1);
	if (bind(descriptor, (struct sockaddr *)&address,
		 offsetof(struct sockaddr_un, sun_path) + (socklen_t)written + 1) !=
		    0 ||
	    listen(descriptor, 4) != 0) {
		(void)close(descriptor);
		(void)unlink(fixture->path);
		(void)rmdir(fixture->directory);
		return -1;
	}
	return descriptor;
}

static void remove_named_listener(const struct named_listener *fixture)
{
	EXPECT_TRUE(unlink(fixture->path) == 0);
	EXPECT_TRUE(rmdir(fixture->directory) == 0);
}

static void move_to_systemd_descriptor(int descriptor)
{
	EXPECT_TRUE(descriptor >= 0);
	if (descriptor == SYSTEMD_LISTENER_DESCRIPTOR)
		return;
	EXPECT_TRUE(dup2(descriptor, SYSTEMD_LISTENER_DESCRIPTOR) ==
		    SYSTEMD_LISTENER_DESCRIPTOR);
	close_descriptor(descriptor);
}

static void move_to_systemd_descriptor_pair(int first, int second)
{
	int first_copy;
	int second_copy;

	EXPECT_TRUE(first >= 0 && second >= 0 && first != second);
	first_copy = fcntl(first, F_DUPFD_CLOEXEC, 5);
	second_copy = fcntl(second, F_DUPFD_CLOEXEC, 5);
	EXPECT_TRUE(first_copy >= 5 && second_copy >= 5 &&
		    first_copy != second_copy);
	if (first_copy < 0 || second_copy < 0 || first_copy == second_copy) {
		close_descriptor(first_copy);
		close_descriptor(second_copy);
		return;
	}
	close_descriptor(first);
	close_descriptor(second);
	EXPECT_TRUE(dup2(first_copy, SYSTEMD_LISTENER_DESCRIPTOR) ==
		    SYSTEMD_LISTENER_DESCRIPTOR);
	EXPECT_TRUE(dup2(second_copy, SYSTEMD_LISTENER_DESCRIPTOR + 1) ==
		    SYSTEMD_LISTENER_DESCRIPTOR + 1);
	close_descriptor(first_copy);
	close_descriptor(second_copy);
}

static void expect_activation_failure(enum t1_seqpacket_status expected,
	pid_t activation_pid, unsigned int activation_fds,
	const char *expected_path)
{
	int descriptor_flags = fcntl(SYSTEMD_LISTENER_DESCRIPTOR, F_GETFD);
	int status_flags = fcntl(SYSTEMD_LISTENER_DESCRIPTOR, F_GETFL);
	int adopted = 99;

	EXPECT_STATUS(expected,
		      t1_seqpacket_adopt_systemd_listener(activation_pid,
			activation_fds, expected_path, &adopted));
	EXPECT_TRUE(adopted == -1);
	EXPECT_TRUE(fcntl(SYSTEMD_LISTENER_DESCRIPTOR, F_GETFD) ==
		    descriptor_flags);
	EXPECT_TRUE(fcntl(SYSTEMD_LISTENER_DESCRIPTOR, F_GETFL) == status_flags);
}

static void expect_pair_activation_failure(
	enum t1_seqpacket_status expected, pid_t activation_pid,
	unsigned int activation_fds, const char *first_expected_path,
	const char *second_expected_path)
{
	int descriptor_flags[2] = {
		fcntl(SYSTEMD_LISTENER_DESCRIPTOR, F_GETFD),
		fcntl(SYSTEMD_LISTENER_DESCRIPTOR + 1, F_GETFD),
	};
	int status_flags[2] = {
		fcntl(SYSTEMD_LISTENER_DESCRIPTOR, F_GETFL),
		fcntl(SYSTEMD_LISTENER_DESCRIPTOR + 1, F_GETFL),
	};
	int adopted[2] = { 99, 99 };

	EXPECT_STATUS(expected,
		t1_seqpacket_adopt_systemd_listener_pair(activation_pid,
			activation_fds, first_expected_path,
			second_expected_path, &adopted[0], &adopted[1]));
	EXPECT_TRUE(adopted[0] == -1 && adopted[1] == -1);
	EXPECT_TRUE(fcntl(SYSTEMD_LISTENER_DESCRIPTOR, F_GETFD) ==
		    descriptor_flags[0]);
	EXPECT_TRUE(fcntl(SYSTEMD_LISTENER_DESCRIPTOR + 1, F_GETFD) ==
		    descriptor_flags[1]);
	EXPECT_TRUE(fcntl(SYSTEMD_LISTENER_DESCRIPTOR, F_GETFL) ==
		    status_flags[0]);
	EXPECT_TRUE(fcntl(SYSTEMD_LISTENER_DESCRIPTOR + 1, F_GETFL) ==
		    status_flags[1]);
}

typedef void (*child_test_fn)(void);

static void run_fork_isolated(child_test_fn test)
{
	pid_t child = fork();
	int child_status = 0;

	EXPECT_TRUE(child >= 0);
	if (child < 0)
		return;
	if (child == 0) {
		failures = 0;
		test();
		_exit(failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
	}
	EXPECT_TRUE(waitpid(child, &child_status, 0) == child);
	EXPECT_TRUE(WIFEXITED(child_status));
	EXPECT_TRUE(WIFEXITED(child_status) &&
		    WEXITSTATUS(child_status) == EXIT_SUCCESS);
}

static void test_activation_descriptor_failures_child(void)
{
	struct named_listener stream_fixture;
	int descriptors[2] = { -1, -1 };
	int stream;
	int adopted = 99;

	(void)close(SYSTEMD_LISTENER_DESCRIPTOR);
	EXPECT_STATUS(T1_SEQPACKET_ACTIVATION_FAILED,
		      t1_seqpacket_adopt_systemd_listener(getpid(), 1,
			"/synthetic", &adopted));
	EXPECT_TRUE(adopted == -1);

	EXPECT_TRUE(pipe(descriptors) == 0);
	move_to_systemd_descriptor(descriptors[0]);
	descriptors[0] = -1;
	expect_activation_failure(T1_SEQPACKET_DESCRIPTOR_FAILED, getpid(), 1,
				  "/synthetic");
	close_descriptor(SYSTEMD_LISTENER_DESCRIPTOR);
	close_descriptor(descriptors[1]);

	stream = create_named_listener(&stream_fixture, SOCK_STREAM);
	move_to_systemd_descriptor(stream);
	expect_activation_failure(T1_SEQPACKET_WRONG_SOCKET, getpid(), 1,
				  stream_fixture.path);
	close_descriptor(SYSTEMD_LISTENER_DESCRIPTOR);
	remove_named_listener(&stream_fixture);

	create_pair(descriptors);
	move_to_systemd_descriptor(descriptors[0]);
	descriptors[0] = -1;
	expect_activation_failure(T1_SEQPACKET_NOT_LISTENER, getpid(), 1,
				  "/synthetic");
	close_descriptor(SYSTEMD_LISTENER_DESCRIPTOR);
	close_descriptor(descriptors[1]);
}

static void test_activation_wrong_path_child(void)
{
	struct named_listener fixture;
	char wrong_path[sizeof(fixture.path)];
	int listener = create_named_listener(&fixture, SOCK_SEQPACKET);
	int written;

	move_to_systemd_descriptor(listener);
	expect_activation_failure(T1_SEQPACKET_ACTIVATION_FAILED, 0, 1,
				  fixture.path);
	expect_activation_failure(T1_SEQPACKET_ACTIVATION_FAILED, getpid() + 1,
				  1, fixture.path);
	expect_activation_failure(T1_SEQPACKET_ACTIVATION_FAILED, getpid(), 0,
				  fixture.path);
	expect_activation_failure(T1_SEQPACKET_ACTIVATION_FAILED, getpid(), 2,
				  fixture.path);
	written = snprintf(wrong_path, sizeof(wrong_path), "%s/other",
			   fixture.directory);
	EXPECT_TRUE(written > 0 && (size_t)written < sizeof(wrong_path));
	expect_activation_failure(T1_SEQPACKET_WRONG_PATH, getpid(), 1,
				  wrong_path);
	close_descriptor(SYSTEMD_LISTENER_DESCRIPTOR);
	remove_named_listener(&fixture);
}

static void test_activation_success_and_readiness_child(void)
{
	static const uint8_t packet[] = { 0x54, 0x31, 0x52, 0x44 };
	struct named_listener fixture;
	struct sockaddr_un address;
	int listener = create_named_listener(&fixture, SOCK_SEQPACKET);
	int adopted = -1;
	int client = -1;
	int accepted = -1;
	int ready = 99;
	uint8_t received[sizeof(packet)] = { 0 };
	size_t received_length = 0;

	move_to_systemd_descriptor(listener);
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_adopt_systemd_listener(getpid(), 1,
			fixture.path, &adopted));
	EXPECT_TRUE(adopted > SYSTEMD_LISTENER_DESCRIPTOR);
	EXPECT_TRUE(fcntl(SYSTEMD_LISTENER_DESCRIPTOR, F_GETFD) < 0 &&
		    errno == EBADF);
	EXPECT_TRUE((fcntl(adopted, F_GETFD) & FD_CLOEXEC) != 0);
	EXPECT_TRUE((fcntl(adopted, F_GETFL) & O_NONBLOCK) != 0);
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_listener_ready(adopted, &ready));
	EXPECT_TRUE(ready == 0);

	client = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	EXPECT_TRUE(client >= 0);
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	memcpy(address.sun_path, fixture.path, strlen(fixture.path) + 1);
	EXPECT_TRUE(connect(client, (struct sockaddr *)&address,
		    offsetof(struct sockaddr_un, sun_path) +
			    (socklen_t)strlen(fixture.path) + 1) == 0);
	EXPECT_TRUE(send(client, packet, sizeof(packet), MSG_NOSIGNAL) ==
		    (ssize_t)sizeof(packet));
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_listener_ready(adopted, &ready));
	EXPECT_TRUE(ready == 1);
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_listener_ready(adopted, &ready));
	EXPECT_TRUE(ready == 1);
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_accept(adopted, &accepted));
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_receive(accepted, received, sizeof(received),
				       &received_length));
	EXPECT_TRUE(received_length == sizeof(packet));
	EXPECT_TRUE(memcmp(received, packet, sizeof(packet)) == 0);
	close_descriptor(accepted);
	close_descriptor(client);
	close_descriptor(adopted);
	remove_named_listener(&fixture);
}

static void test_pair_activation_validation_is_atomic_child(void)
{
	struct named_listener first_fixture;
	struct named_listener second_fixture;
	struct named_listener stream_fixture;
	int first = create_named_listener(&first_fixture, SOCK_SEQPACKET);
	int second = create_named_listener(&second_fixture, SOCK_SEQPACKET);
	int stream;

	move_to_systemd_descriptor_pair(first, second);
	expect_pair_activation_failure(T1_SEQPACKET_ACTIVATION_FAILED,
		getpid(), 1, first_fixture.path, second_fixture.path);
	expect_pair_activation_failure(T1_SEQPACKET_WRONG_PATH, getpid(), 2,
		second_fixture.path, first_fixture.path);
	expect_pair_activation_failure(T1_SEQPACKET_WRONG_PATH, getpid(), 2,
		first_fixture.path, "/synthetic-wrong-second");
	close_descriptor(SYSTEMD_LISTENER_DESCRIPTOR);
	close_descriptor(SYSTEMD_LISTENER_DESCRIPTOR + 1);
	remove_named_listener(&first_fixture);
	remove_named_listener(&second_fixture);

	first = create_named_listener(&first_fixture, SOCK_SEQPACKET);
	stream = create_named_listener(&stream_fixture, SOCK_STREAM);
	move_to_systemd_descriptor_pair(first, stream);
	expect_pair_activation_failure(T1_SEQPACKET_WRONG_SOCKET, getpid(), 2,
		first_fixture.path, stream_fixture.path);
	close_descriptor(SYSTEMD_LISTENER_DESCRIPTOR);
	close_descriptor(SYSTEMD_LISTENER_DESCRIPTOR + 1);
	remove_named_listener(&first_fixture);
	remove_named_listener(&stream_fixture);
}

static void test_pair_activation_success_child(void)
{
	struct named_listener first_fixture;
	struct named_listener second_fixture;
	int first = create_named_listener(&first_fixture, SOCK_SEQPACKET);
	int second = create_named_listener(&second_fixture, SOCK_SEQPACKET);
	int adopted[2] = { 99, 99 };
	int ready = 99;

	move_to_systemd_descriptor_pair(first, second);
	EXPECT_STATUS(T1_SEQPACKET_OK,
		t1_seqpacket_adopt_systemd_listener_pair(getpid(), 2,
			first_fixture.path, second_fixture.path, &adopted[0],
			&adopted[1]));
	EXPECT_TRUE(adopted[0] >= 5 && adopted[1] >= 5 &&
		    adopted[0] != adopted[1]);
	EXPECT_TRUE(fcntl(SYSTEMD_LISTENER_DESCRIPTOR, F_GETFD) < 0 &&
		    errno == EBADF);
	EXPECT_TRUE(fcntl(SYSTEMD_LISTENER_DESCRIPTOR + 1, F_GETFD) < 0 &&
		    errno == EBADF);
	for (size_t index = 0; index < 2; ++index) {
		EXPECT_TRUE((fcntl(adopted[index], F_GETFD) & FD_CLOEXEC) != 0);
		EXPECT_TRUE((fcntl(adopted[index], F_GETFL) & O_NONBLOCK) != 0);
		EXPECT_STATUS(T1_SEQPACKET_OK,
			t1_seqpacket_listener_ready(adopted[index], &ready));
		EXPECT_TRUE(ready == 0);
		close_descriptor(adopted[index]);
	}
	remove_named_listener(&first_fixture);
	remove_named_listener(&second_fixture);
}

static void test_pair_activation_partial_duplication_fails_closed_child(void)
{
	struct named_listener first_fixture;
	struct named_listener second_fixture;
	struct rlimit descriptor_limit;
	int first = create_named_listener(&first_fixture, SOCK_SEQPACKET);
	int second = create_named_listener(&second_fixture, SOCK_SEQPACKET);

	move_to_systemd_descriptor_pair(first, second);
	EXPECT_TRUE(getrlimit(RLIMIT_NOFILE, &descriptor_limit) == 0);
	descriptor_limit.rlim_cur = 6;
	EXPECT_TRUE(setrlimit(RLIMIT_NOFILE, &descriptor_limit) == 0);
	expect_pair_activation_failure(T1_SEQPACKET_ACTIVATION_FAILED,
		getpid(), 2, first_fixture.path, second_fixture.path);
	EXPECT_TRUE(fcntl(5, F_GETFD) < 0 && errno == EBADF);
	close_descriptor(SYSTEMD_LISTENER_DESCRIPTOR);
	close_descriptor(SYSTEMD_LISTENER_DESCRIPTOR + 1);
	remove_named_listener(&first_fixture);
	remove_named_listener(&second_fixture);
}

static void test_readiness_errors_and_interruption_child(void)
{
	struct sockaddr_un address;
	socklen_t address_length;
	int stream[2] = { -1, -1 };
	int pair[2] = { -1, -1 };
	int listener;
	int ready = 99;
	unsigned int attempts;
	enum t1_seqpacket_status status = T1_SEQPACKET_OK;
	struct sigaction action;
	struct sigaction previous;
	struct itimerval timer;

	EXPECT_TRUE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, stream) ==
		    0);
	EXPECT_STATUS(T1_SEQPACKET_WRONG_SOCKET,
		      t1_seqpacket_listener_ready(stream[0], &ready));
	EXPECT_TRUE(ready == 0);
	create_pair(pair);
	ready = 99;
	EXPECT_STATUS(T1_SEQPACKET_NOT_LISTENER,
		      t1_seqpacket_listener_ready(pair[0], &ready));
	EXPECT_TRUE(ready == 0);
	EXPECT_STATUS(T1_SEQPACKET_INVALID_ARGUMENT,
		      t1_seqpacket_listener_ready(pair[0], NULL));
	close_descriptor(stream[0]);
	close_descriptor(stream[1]);
	close_descriptor(pair[0]);
	close_descriptor(pair[1]);

	listener = create_autobound_listener(&address, &address_length);
	EXPECT_TRUE(listener >= 0);
	memset(&action, 0, sizeof(action));
	action.sa_handler = alarm_handler;
	EXPECT_TRUE(sigemptyset(&action.sa_mask) == 0);
	EXPECT_TRUE(sigaction(SIGALRM, &action, &previous) == 0);
	memset(&timer, 0, sizeof(timer));
	timer.it_value.tv_usec = 10;
	timer.it_interval.tv_usec = 10;
	EXPECT_TRUE(setitimer(ITIMER_REAL, &timer, NULL) == 0);
	for (attempts = 0; attempts < 1000000 &&
			  status != T1_SEQPACKET_INTERRUPTED;
	     ++attempts) {
		ready = 99;
		status = t1_seqpacket_listener_ready(listener, &ready);
		if (status == T1_SEQPACKET_OK)
			EXPECT_TRUE(ready == 0);
		else {
			EXPECT_TRUE(status == T1_SEQPACKET_INTERRUPTED);
			break;
		}
	}
	memset(&timer, 0, sizeof(timer));
	EXPECT_TRUE(setitimer(ITIMER_REAL, &timer, NULL) == 0);
	EXPECT_TRUE(sigaction(SIGALRM, &previous, NULL) == 0);
	EXPECT_TRUE(alarm_count > 0);
	EXPECT_TRUE(status == T1_SEQPACKET_INTERRUPTED);
	close_descriptor(listener);
}

static void test_accept_is_local_nonblocking_and_close_on_exec(void)
{
	struct sockaddr_un address;
	socklen_t address_length;
	int listener = create_autobound_listener(&address, &address_length);
	int peer = -1;
	int accepted = 99;

	EXPECT_TRUE(listener >= 0);
	EXPECT_STATUS(T1_SEQPACKET_WOULD_BLOCK,
		      t1_seqpacket_accept(listener, &accepted));
	EXPECT_TRUE(accepted == -1);
	peer = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	EXPECT_TRUE(peer >= 0);
	EXPECT_TRUE(connect(peer, (struct sockaddr *)&address, address_length) ==
		    0);
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_accept(listener, &accepted));
	EXPECT_TRUE(accepted >= 0);
	EXPECT_TRUE((fcntl(accepted, F_GETFD) & FD_CLOEXEC) != 0);
	EXPECT_TRUE((fcntl(accepted, F_GETFL) & O_NONBLOCK) != 0);
	close_descriptor(accepted);
	close_descriptor(peer);
	close_descriptor(listener);
}

static void test_touchbar_connect_uses_fixed_path_and_safe_flags(void)
{
	struct t1_seqpacket_credentials credentials;
	int connected = 99;

	begin_mock_connect(0);
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_connect_touchbar(&connected));
	EXPECT_TRUE(connected == mock_client_descriptor);
	EXPECT_TRUE(mock_socket_domain == AF_UNIX);
	EXPECT_TRUE(mock_socket_type == (SOCK_SEQPACKET | SOCK_CLOEXEC));
	EXPECT_TRUE(mock_socket_protocol == 0);
	EXPECT_TRUE(mock_connect_address_length ==
		offsetof(struct sockaddr_un, sun_path) +
			(socklen_t)sizeof(EXPECTED_TOUCHBAR_SOCKET_PATH));
	EXPECT_TRUE(mock_connect_address.sun_family == AF_UNIX);
	EXPECT_TRUE(memcmp(mock_connect_address.sun_path,
			   EXPECTED_TOUCHBAR_SOCKET_PATH,
			   sizeof(EXPECTED_TOUCHBAR_SOCKET_PATH)) == 0);
	EXPECT_TRUE((fcntl(connected, F_GETFD) & FD_CLOEXEC) != 0);
	EXPECT_TRUE((fcntl(connected, F_GETFL) & O_NONBLOCK) != 0);
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_peer_credentials(connected, &credentials));
	EXPECT_TRUE(credentials.process_id == getpid());
	EXPECT_TRUE(credentials.user_id == getuid());
	EXPECT_TRUE(credentials.group_id == getgid());
	close_descriptor(connected);
	end_mock_connect();
}

static void test_auth_connect_uses_fixed_path_and_safe_flags(void)
{
	struct t1_seqpacket_credentials credentials;
	int connected = 99;

	begin_mock_connect(0);
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_connect_auth(&connected));
	EXPECT_TRUE(connected == mock_client_descriptor);
	EXPECT_TRUE(mock_socket_domain == AF_UNIX);
	EXPECT_TRUE(mock_socket_type ==
		(SOCK_SEQPACKET | SOCK_CLOEXEC | SOCK_NONBLOCK));
	EXPECT_TRUE(mock_socket_protocol == 0);
	EXPECT_TRUE(mock_connect_address_length ==
		offsetof(struct sockaddr_un, sun_path) +
			(socklen_t)sizeof(EXPECTED_AUTH_SOCKET_PATH));
	EXPECT_TRUE(mock_connect_address.sun_family == AF_UNIX);
	EXPECT_TRUE(memcmp(mock_connect_address.sun_path,
			   EXPECTED_AUTH_SOCKET_PATH,
			   sizeof(EXPECTED_AUTH_SOCKET_PATH)) == 0);
	EXPECT_TRUE((fcntl(connected, F_GETFD) & FD_CLOEXEC) != 0);
	EXPECT_TRUE((fcntl(connected, F_GETFL) & O_NONBLOCK) != 0);
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_peer_credentials(connected, &credentials));
	EXPECT_TRUE(credentials.process_id == getpid());
	EXPECT_TRUE(credentials.user_id == getuid());
	EXPECT_TRUE(credentials.group_id == getgid());
	close_descriptor(connected);
	end_mock_connect();
}

static void test_touchbar_connect_failures_close_the_socket(void)
{
	static const int errors[] = { ECONNREFUSED, EINTR };
	size_t index;

	EXPECT_STATUS(T1_SEQPACKET_INVALID_ARGUMENT,
		      t1_seqpacket_connect_touchbar(NULL));
	for (index = 0; index < sizeof(errors) / sizeof(errors[0]); ++index) {
		int connected = 99;
		enum t1_seqpacket_status expected =
			errors[index] == EINTR ? T1_SEQPACKET_INTERRUPTED :
				T1_SEQPACKET_CONNECT_FAILED;

		begin_mock_connect(errors[index]);
		EXPECT_STATUS(expected,
			      t1_seqpacket_connect_touchbar(&connected));
		EXPECT_TRUE(connected == -1);
		EXPECT_TRUE(mock_client_descriptor >= 0);
		EXPECT_TRUE(fcntl(mock_client_descriptor, F_GETFD) < 0 &&
			    errno == EBADF);
		end_mock_connect();
	}
}

static void test_auth_connect_failures_close_the_socket(void)
{
	static const int errors[] = { ECONNREFUSED, EINTR, EAGAIN, EINPROGRESS };
	size_t index;

	EXPECT_STATUS(T1_SEQPACKET_INVALID_ARGUMENT,
		      t1_seqpacket_connect_auth(NULL));
	for (index = 0; index < sizeof(errors) / sizeof(errors[0]); ++index) {
		int connected = 99;
		enum t1_seqpacket_status expected;

		if (errors[index] == EINTR)
			expected = T1_SEQPACKET_INTERRUPTED;
		else if (errors[index] == EAGAIN || errors[index] == EINPROGRESS)
			expected = T1_SEQPACKET_WOULD_BLOCK;
		else
			expected = T1_SEQPACKET_CONNECT_FAILED;

		begin_mock_connect(errors[index]);
		EXPECT_STATUS(expected, t1_seqpacket_connect_auth(&connected));
		EXPECT_TRUE(connected == -1);
		EXPECT_TRUE(mock_client_descriptor >= 0);
		EXPECT_TRUE(fcntl(mock_client_descriptor, F_GETFD) < 0 &&
			    errno == EBADF);
		end_mock_connect();
	}
}

static void alarm_handler(int signal_number)
{
	(void)signal_number;
	++alarm_count;
}

static void test_interrupted_accept_is_explicit(void)
{
	struct sockaddr_un address;
	socklen_t address_length;
	int listener = create_autobound_listener(&address, &address_length);
	int accepted = 99;
	int flags;
	struct sigaction action;
	struct sigaction previous;
	struct itimerval timer;

	EXPECT_TRUE(listener >= 0);
	flags = fcntl(listener, F_GETFL);
	EXPECT_TRUE(flags >= 0);
	EXPECT_TRUE(fcntl(listener, F_SETFL, flags & ~O_NONBLOCK) == 0);
	memset(&action, 0, sizeof(action));
	action.sa_handler = alarm_handler;
	EXPECT_TRUE(sigemptyset(&action.sa_mask) == 0);
	EXPECT_TRUE(sigaction(SIGALRM, &action, &previous) == 0);
	memset(&timer, 0, sizeof(timer));
	timer.it_value.tv_usec = 10000;
	EXPECT_TRUE(setitimer(ITIMER_REAL, &timer, NULL) == 0);
	EXPECT_STATUS(T1_SEQPACKET_INTERRUPTED,
		      t1_seqpacket_accept(listener, &accepted));
	EXPECT_TRUE(accepted == -1);
	EXPECT_TRUE(alarm_count == 1);
	memset(&timer, 0, sizeof(timer));
	EXPECT_TRUE(setitimer(ITIMER_REAL, &timer, NULL) == 0);
	EXPECT_TRUE(sigaction(SIGALRM, &previous, NULL) == 0);
	close_descriptor(listener);
}

static void test_descriptor_shape_and_connection_are_enforced(void)
{
	int stream[2] = { -1, -1 };
	int descriptors[2] = { -1, -1 };
	int unconnected = -1;
	int accepted = -1;
	uint8_t byte = 0;
	size_t length = 0;

	EXPECT_TRUE(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, stream) ==
		    0);
	EXPECT_STATUS(T1_SEQPACKET_WRONG_SOCKET,
		      t1_seqpacket_receive(stream[0], &byte, sizeof(byte), &length));
	EXPECT_STATUS(T1_SEQPACKET_WRONG_SOCKET,
		      t1_seqpacket_accept(stream[0], &accepted));
	unconnected = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	EXPECT_TRUE(unconnected >= 0);
	EXPECT_STATUS(T1_SEQPACKET_NOT_CONNECTED,
		      t1_seqpacket_receive(unconnected, &byte, sizeof(byte),
				       &length));
	EXPECT_STATUS(T1_SEQPACKET_NOT_LISTENER,
		      t1_seqpacket_accept(unconnected, &accepted));
	EXPECT_TRUE(pipe(descriptors) == 0);
	EXPECT_STATUS(T1_SEQPACKET_DESCRIPTOR_FAILED,
		      t1_seqpacket_send(descriptors[1], &byte, sizeof(byte)));
	close_descriptor(descriptors[0]);
	close_descriptor(descriptors[1]);
	close_descriptor(unconnected);
	close_descriptor(stream[0]);
	close_descriptor(stream[1]);
}

static void test_kernel_peer_credentials(void)
{
	int descriptors[2] = { -1, -1 };
	struct t1_seqpacket_credentials credentials;

	create_pair(descriptors);
	memset(&credentials, 0xff, sizeof(credentials));
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_peer_credentials(descriptors[0], &credentials));
	EXPECT_TRUE(credentials.process_id == getpid());
	EXPECT_TRUE(credentials.user_id == getuid());
	EXPECT_TRUE(credentials.group_id == getgid());
	close_descriptor(descriptors[0]);
	close_descriptor(descriptors[1]);
}

static int group_list_contains(const gid_t *groups, size_t count, gid_t group)
{
	size_t index;

	for (index = 0; index < count; ++index) {
		if (groups[index] == group)
			return 1;
	}
	return 0;
}

static void test_peer_group_admission_uses_kernel_primary_and_supplementary(void)
{
	int descriptors[2] = { -1, -1 };
	int kernel_group_count = getgroups(0, NULL);
	gid_t *kernel_groups = NULL;
	gid_t denied = 0;
	size_t group_count = 0;
	size_t index;

	EXPECT_TRUE(kernel_group_count >= 0);
	if (kernel_group_count > 0) {
		kernel_groups = malloc((size_t)kernel_group_count * sizeof(gid_t));
		EXPECT_TRUE(kernel_groups != NULL);
		if (kernel_groups != NULL) {
			EXPECT_TRUE(getgroups(kernel_group_count, kernel_groups) ==
				    kernel_group_count);
			group_count = (size_t)kernel_group_count;
		}
	}
	create_pair(descriptors);
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_peer_in_group(descriptors[0], getgid()));
	for (index = 0; index < group_count; ++index) {
		if (kernel_groups[index] != getgid()) {
			EXPECT_STATUS(T1_SEQPACKET_OK,
				t1_seqpacket_peer_in_group(descriptors[0],
					kernel_groups[index]));
			break;
		}
	}
	while (denied == getgid() ||
	       group_list_contains(kernel_groups, group_count, denied))
		++denied;
	EXPECT_STATUS(T1_SEQPACKET_PEER_DENIED,
		      t1_seqpacket_peer_in_group(descriptors[0], denied));
	EXPECT_STATUS(T1_SEQPACKET_PEER_DENIED,
		      t1_seqpacket_peer_in_group(-1, denied));
	free(kernel_groups);
	close_descriptor(descriptors[0]);
	close_descriptor(descriptors[1]);
}

static void test_peer_group_admission_bounds_and_validates_kernel_results(void)
{
	static const enum peer_groups_mock_mode modes[] = {
		PEER_GROUPS_UNSUPPORTED,
		PEER_GROUPS_MALFORMED,
		PEER_GROUPS_OVERSIZED,
	};
	int descriptors[2] = { -1, -1 };
	gid_t allowed = getgid() == (gid_t)-1 ? 0 : getgid() + 1;
	size_t index;

	create_pair(descriptors);
	peer_groups_descriptor = descriptors[0];
	peer_groups_allowed_gid = allowed;
	peer_groups_calls = 0;
	peer_groups_mode = PEER_GROUPS_RESIZE_SUCCESS;
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_peer_in_group(descriptors[0], allowed));
	EXPECT_TRUE(peer_groups_calls == 2);
	for (index = 0; index < sizeof(modes) / sizeof(modes[0]); ++index) {
		peer_groups_calls = 0;
		peer_groups_mode = modes[index];
		EXPECT_STATUS(T1_SEQPACKET_PEER_DENIED,
			      t1_seqpacket_peer_in_group(descriptors[0], allowed));
		EXPECT_TRUE(peer_groups_calls == 1);
	}
	peer_groups_mode = PEER_GROUPS_REAL;
	peer_groups_descriptor = -1;
	close_descriptor(descriptors[0]);
	close_descriptor(descriptors[1]);
}

static void test_disconnect_probe_is_non_consuming_and_fail_closed(void)
{
	static const uint8_t packet[] = { 0x54, 0x31, 0x41, 0x55 };
	int descriptors[2] = { -1, -1 };
	int peer_closed = 99;
	uint8_t buffer[sizeof(packet)] = { 0 };
	size_t length = 0;

	create_pair(descriptors);
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_peer_closed(descriptors[0], &peer_closed));
	EXPECT_TRUE(peer_closed == 0);
	EXPECT_TRUE(send(descriptors[1], packet, sizeof(packet), MSG_NOSIGNAL) ==
		    (ssize_t)sizeof(packet));
	peer_closed = 99;
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_peer_closed(descriptors[0], &peer_closed));
	EXPECT_TRUE(peer_closed == 0);
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_receive(descriptors[0], buffer, sizeof(buffer),
				       &length));
	EXPECT_TRUE(length == sizeof(packet));
	EXPECT_TRUE(memcmp(buffer, packet, sizeof(packet)) == 0);
	EXPECT_TRUE(send(descriptors[1], packet, sizeof(packet), MSG_NOSIGNAL) ==
		    (ssize_t)sizeof(packet));
	close_descriptor(descriptors[1]);
	descriptors[1] = -1;
	peer_closed = 0;
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_peer_closed(descriptors[0], &peer_closed));
	EXPECT_TRUE(peer_closed == 1);
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_receive(descriptors[0], buffer, sizeof(buffer),
				       &length));
	EXPECT_TRUE(length == sizeof(packet));
	EXPECT_TRUE(memcmp(buffer, packet, sizeof(packet)) == 0);
	peer_closed = 0;
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_peer_closed(descriptors[0], &peer_closed));
	EXPECT_TRUE(peer_closed == 1);
	EXPECT_STATUS(T1_SEQPACKET_INVALID_ARGUMENT,
		      t1_seqpacket_peer_closed(descriptors[0], NULL));
	close_descriptor(descriptors[0]);
}

static void test_packet_boundaries_and_truncation(void)
{
	static const uint8_t first[] = { 0x54, 0x31, 0x01, 0x0a };
	static const uint8_t second[] = { 0x20, 0x21, 0x22 };
	int descriptors[2] = { -1, -1 };
	uint8_t buffer[sizeof(first)] = { 0 };
	size_t length = 99;

	create_pair(descriptors);
	EXPECT_STATUS(T1_SEQPACKET_WOULD_BLOCK,
		      t1_seqpacket_receive(descriptors[0], buffer, sizeof(buffer),
				       &length));
	EXPECT_TRUE(length == 0);
	EXPECT_TRUE(send(descriptors[1], first, sizeof(first), MSG_NOSIGNAL) ==
		    (ssize_t)sizeof(first));
	EXPECT_TRUE(send(descriptors[1], second, sizeof(second), MSG_NOSIGNAL) ==
		    (ssize_t)sizeof(second));
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_receive(descriptors[0], buffer, sizeof(buffer),
				       &length));
	EXPECT_TRUE(length == sizeof(first));
	EXPECT_TRUE(memcmp(buffer, first, sizeof(first)) == 0);
	memset(buffer, 0, sizeof(buffer));
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_receive(descriptors[0], buffer, sizeof(buffer),
				       &length));
	EXPECT_TRUE(length == sizeof(second));
	EXPECT_TRUE(memcmp(buffer, second, sizeof(second)) == 0);

	EXPECT_TRUE(send(descriptors[1], first, sizeof(first), MSG_NOSIGNAL) ==
		    (ssize_t)sizeof(first));
	EXPECT_STATUS(T1_SEQPACKET_TRUNCATED,
		      t1_seqpacket_receive(descriptors[0], buffer, sizeof(first) - 1,
				       &length));
	EXPECT_TRUE(length == 0);
	close_descriptor(descriptors[1]);
	descriptors[1] = -1;
	EXPECT_STATUS(T1_SEQPACKET_PEER_CLOSED,
		      t1_seqpacket_receive(descriptors[0], buffer, sizeof(buffer),
				       &length));
	EXPECT_TRUE(length == 0);
	close_descriptor(descriptors[0]);
}

static void test_ancillary_rights_are_rejected_without_fd_leak(void)
{
	static const uint8_t payload[] = { 0x54, 0x31, 0x46, 0x44 };
	union {
		struct cmsghdr alignment;
		uint8_t bytes[CMSG_SPACE(sizeof(int))];
	} control;
	int descriptors[2] = { -1, -1 };
	int pipe_descriptors[2] = { -1, -1 };
	int first_free_before;
	int first_free_after_probe;
	int first_free_after;
	int peer_closed = 99;
	uint8_t buffer[sizeof(payload)] = { 0 };
	size_t length = 99;
	struct iovec vector;
	struct msghdr message;
	struct cmsghdr *header;

	create_pair(descriptors);
	EXPECT_TRUE(pipe(pipe_descriptors) == 0);
	vector.iov_base = (void *)payload;
	vector.iov_len = sizeof(payload);
	memset(&message, 0, sizeof(message));
	memset(&control, 0, sizeof(control));
	message.msg_iov = &vector;
	message.msg_iovlen = 1;
	message.msg_control = control.bytes;
	message.msg_controllen = sizeof(control.bytes);
	header = CMSG_FIRSTHDR(&message);
	EXPECT_TRUE(header != NULL);
	header->cmsg_level = SOL_SOCKET;
	header->cmsg_type = SCM_RIGHTS;
	header->cmsg_len = CMSG_LEN(sizeof(int));
	memcpy(CMSG_DATA(header), &pipe_descriptors[0], sizeof(int));
	EXPECT_TRUE(sendmsg(descriptors[1], &message, MSG_NOSIGNAL) ==
		    (ssize_t)sizeof(payload));
	close_descriptor(pipe_descriptors[0]);
	pipe_descriptors[0] = -1;

	first_free_before = fcntl(pipe_descriptors[1], F_DUPFD_CLOEXEC, 0);
	EXPECT_TRUE(first_free_before >= 0);
	close_descriptor(first_free_before);
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_peer_closed(descriptors[0], &peer_closed));
	EXPECT_TRUE(peer_closed == 0);
	first_free_after_probe = fcntl(pipe_descriptors[1], F_DUPFD_CLOEXEC, 0);
	EXPECT_TRUE(first_free_after_probe >= 0);
	EXPECT_TRUE(first_free_after_probe == first_free_before);
	close_descriptor(first_free_after_probe);
	EXPECT_STATUS(T1_SEQPACKET_TRUNCATED,
		      t1_seqpacket_receive(descriptors[0], buffer, sizeof(buffer),
				       &length));
	EXPECT_TRUE(length == 0);
	first_free_after = fcntl(pipe_descriptors[1], F_DUPFD_CLOEXEC, 0);
	EXPECT_TRUE(first_free_after >= 0);
	EXPECT_TRUE(first_free_after == first_free_before);
	close_descriptor(first_free_after);
	close_descriptor(pipe_descriptors[1]);
	close_descriptor(descriptors[0]);
	close_descriptor(descriptors[1]);
}

static void test_fd_packets_preserve_boundaries_and_cloexec(void)
{
	static const uint8_t with_fd[] = { 0x54, 0x31, 0x46, 0x44 };
	static const uint8_t without_fd[] = { 0x54, 0x31, 0x4e, 0x4f };
	int sockets[2] = { -1, -1 };
	int pipe_descriptors[2] = { -1, -1 };
	int sent_descriptor;
	int received_descriptor = 99;
	uint8_t buffer[sizeof(with_fd)] = { 0 };
	uint8_t marker = 0x5a;
	uint8_t read_marker = 0;
	size_t length = 99;

	create_pair(sockets);
	EXPECT_TRUE(pipe2(pipe_descriptors, O_CLOEXEC) == 0);
	sent_descriptor = pipe_descriptors[0];
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_send_with_fds(sockets[0], with_fd,
						 sizeof(with_fd), &sent_descriptor, 1));
	EXPECT_TRUE(fcntl(sent_descriptor, F_GETFD) >= 0);
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_send_with_fds(sockets[0], without_fd,
						 sizeof(without_fd), NULL, 0));
	close_descriptor(pipe_descriptors[0]);
	pipe_descriptors[0] = -1;
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_receive_with_fds(sockets[1], buffer,
						    sizeof(buffer), &length,
						    &received_descriptor, 1));
	EXPECT_TRUE(length == sizeof(with_fd));
	EXPECT_TRUE(memcmp(buffer, with_fd, sizeof(with_fd)) == 0);
	EXPECT_TRUE(received_descriptor >= 0);
	EXPECT_TRUE((fcntl(received_descriptor, F_GETFD) & FD_CLOEXEC) != 0);
	EXPECT_TRUE(write(pipe_descriptors[1], &marker, sizeof(marker)) ==
		    (ssize_t)sizeof(marker));
	EXPECT_TRUE(read(received_descriptor, &read_marker, sizeof(read_marker)) ==
		    (ssize_t)sizeof(read_marker));
	EXPECT_TRUE(read_marker == marker);
	memset(buffer, 0, sizeof(buffer));
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_receive_with_fds(sockets[1], buffer,
						    sizeof(buffer), &length, NULL,
						    0));
	EXPECT_TRUE(length == sizeof(without_fd));
	EXPECT_TRUE(memcmp(buffer, without_fd, sizeof(without_fd)) == 0);
	close_descriptor(received_descriptor);
	close_descriptor(pipe_descriptors[1]);
	close_descriptor(sockets[0]);
	close_descriptor(sockets[1]);
}

static void test_at_most_one_fd_reports_zero_or_one(void)
{
	static const uint8_t without_fd[] = { 0x54, 0x31, 0x5a };
	static const uint8_t with_fd[] = { 0x54, 0x31, 0x4f };
	int sockets[2] = { -1, -1 };
	int pipe_descriptors[2] = { -1, -1 };
	int sent_descriptor;
	int received_descriptor = 99;
	uint8_t buffer[sizeof(without_fd)] = { 0 };
	uint8_t marker = 0x5a;
	uint8_t read_marker = 0;
	size_t descriptor_count = 99;
	size_t length = 99;

	create_pair(sockets);
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_send(sockets[0], without_fd,
				    sizeof(without_fd)));
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_receive_at_most_one_fd(sockets[1], buffer,
				sizeof(buffer), &length,
				&received_descriptor, &descriptor_count));
	EXPECT_TRUE(length == sizeof(without_fd));
	EXPECT_TRUE(memcmp(buffer, without_fd, sizeof(without_fd)) == 0);
	EXPECT_TRUE(received_descriptor == -1);
	EXPECT_TRUE(descriptor_count == 0);

	EXPECT_TRUE(pipe2(pipe_descriptors, O_CLOEXEC) == 0);
	sent_descriptor = pipe_descriptors[0];
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_send_with_fds(sockets[0], with_fd,
					 sizeof(with_fd), &sent_descriptor, 1));
	close_descriptor(pipe_descriptors[0]);
	pipe_descriptors[0] = -1;
	memset(buffer, 0, sizeof(buffer));
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_receive_at_most_one_fd(sockets[1], buffer,
				sizeof(buffer), &length,
				&received_descriptor, &descriptor_count));
	EXPECT_TRUE(length == sizeof(with_fd));
	EXPECT_TRUE(memcmp(buffer, with_fd, sizeof(with_fd)) == 0);
	EXPECT_TRUE(descriptor_count == 1);
	EXPECT_TRUE(received_descriptor >= 0);
	EXPECT_TRUE((fcntl(received_descriptor, F_GETFD) & FD_CLOEXEC) != 0);
	EXPECT_TRUE(write(pipe_descriptors[1], &marker, sizeof(marker)) ==
		    (ssize_t)sizeof(marker));
	EXPECT_TRUE(read(received_descriptor, &read_marker,
			 sizeof(read_marker)) == (ssize_t)sizeof(read_marker));
	EXPECT_TRUE(read_marker == marker);
	close_descriptor(received_descriptor);
	close_descriptor(pipe_descriptors[1]);
	close_descriptor(sockets[0]);
	close_descriptor(sockets[1]);
}

static void test_at_most_one_fd_rejects_and_closes_multiple(void)
{
	static const uint8_t packet[] = { 0x54, 0x31, 0x32 };
	int sockets[2] = { -1, -1 };
	int pipe_descriptors[2] = { -1, -1 };
	int sent_descriptors[2];
	int received_descriptor = 99;
	int available_before;
	int available_after;
	uint8_t buffer[sizeof(packet)] = { 0 };
	size_t descriptor_count = 99;
	size_t length = 99;

	create_pair(sockets);
	EXPECT_TRUE(pipe2(pipe_descriptors, O_CLOEXEC) == 0);
	sent_descriptors[0] = pipe_descriptors[0];
	sent_descriptors[1] = pipe_descriptors[0];
	EXPECT_TRUE(send_raw_rights(sockets[0], packet, sizeof(packet),
				    sent_descriptors, 2) ==
		    (ssize_t)sizeof(packet));
	close_descriptor(pipe_descriptors[0]);
	pipe_descriptors[0] = -1;
	available_before = first_available_descriptor(pipe_descriptors[1]);
	EXPECT_STATUS(T1_SEQPACKET_TRUNCATED,
		      t1_seqpacket_receive_at_most_one_fd(sockets[1], buffer,
				sizeof(buffer), &length,
				&received_descriptor, &descriptor_count));
	EXPECT_TRUE(length == 0);
	EXPECT_TRUE(received_descriptor == -1);
	EXPECT_TRUE(descriptor_count == 0);
	available_after = first_available_descriptor(pipe_descriptors[1]);
	EXPECT_TRUE(available_after == available_before);
	close_descriptor(pipe_descriptors[1]);
	close_descriptor(sockets[0]);
	close_descriptor(sockets[1]);
}

static void test_fd_count_mismatches_close_received_descriptors(void)
{
	static const uint8_t packet[] = { 0x54, 0x31, 0x42, 0x41, 0x44 };
	int sockets[2] = { -1, -1 };
	int pipe_descriptors[2] = { -1, -1 };
	int sent_descriptor;
	int received_descriptor = 99;
	int available_before;
	int available_after;
	uint8_t buffer[sizeof(packet)] = { 0 };
	size_t length = 99;

	create_pair(sockets);
	EXPECT_TRUE(pipe2(pipe_descriptors, O_CLOEXEC) == 0);
	sent_descriptor = pipe_descriptors[0];
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_send_with_fds(sockets[0], packet,
						 sizeof(packet), &sent_descriptor, 1));
	close_descriptor(pipe_descriptors[0]);
	pipe_descriptors[0] = -1;
	available_before = first_available_descriptor(pipe_descriptors[1]);
	EXPECT_STATUS(T1_SEQPACKET_TRUNCATED,
		      t1_seqpacket_receive_with_fds(sockets[1], buffer,
						    sizeof(buffer), &length, NULL,
						    0));
	EXPECT_TRUE(length == 0);
	available_after = first_available_descriptor(pipe_descriptors[1]);
	EXPECT_TRUE(available_after == available_before);

	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_send_with_fds(sockets[0], packet,
						 sizeof(packet), NULL, 0));
	EXPECT_STATUS(T1_SEQPACKET_TRUNCATED,
		      t1_seqpacket_receive_with_fds(sockets[1], buffer,
						    sizeof(buffer), &length,
						    &received_descriptor, 1));
	EXPECT_TRUE(received_descriptor == -1);
	EXPECT_TRUE(length == 0);
	close_descriptor(pipe_descriptors[1]);
	close_descriptor(sockets[0]);
	close_descriptor(sockets[1]);
}

static void test_truncated_fd_control_closes_every_installed_descriptor(void)
{
	static const uint8_t packet[] = { 0x54, 0x31, 0x4d, 0x41, 0x4e, 0x59 };
	int sockets[2] = { -1, -1 };
	int pipe_descriptors[2] = { -1, -1 };
	int sent_descriptors[16];
	int available_before;
	int available_after;
	int index;
	uint8_t buffer[sizeof(packet)] = { 0 };
	size_t length = 99;

	create_pair(sockets);
	EXPECT_TRUE(pipe2(pipe_descriptors, O_CLOEXEC) == 0);
	for (index = 0; index < 16; ++index)
		sent_descriptors[index] = pipe_descriptors[0];
	EXPECT_TRUE(send_raw_rights(sockets[0], packet, sizeof(packet),
				    sent_descriptors, 16) ==
		    (ssize_t)sizeof(packet));
	close_descriptor(pipe_descriptors[0]);
	pipe_descriptors[0] = -1;
	available_before = first_available_descriptor(pipe_descriptors[1]);
	EXPECT_STATUS(T1_SEQPACKET_TRUNCATED,
		      t1_seqpacket_receive_with_fds(sockets[1], buffer,
						    sizeof(buffer), &length, NULL,
						    0));
	EXPECT_TRUE(length == 0);
	available_after = first_available_descriptor(pipe_descriptors[1]);
	EXPECT_TRUE(available_after == available_before);
	close_descriptor(pipe_descriptors[1]);
	close_descriptor(sockets[0]);
	close_descriptor(sockets[1]);
}

static void test_non_rights_ancillary_data_is_rejected(void)
{
	static const uint8_t packet[] = { 0x54, 0x31, 0x43, 0x52, 0x45, 0x44 };
	int sockets[2] = { -1, -1 };
	int enabled = 1;
	uint8_t buffer[sizeof(packet)] = { 0 };
	size_t length = 99;

	create_pair(sockets);
	EXPECT_TRUE(setsockopt(sockets[1], SOL_SOCKET, SO_PASSCRED, &enabled,
			       sizeof(enabled)) == 0);
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_send_with_fds(sockets[0], packet,
						 sizeof(packet), NULL, 0));
	EXPECT_STATUS(T1_SEQPACKET_TRUNCATED,
		      t1_seqpacket_receive_with_fds(sockets[1], buffer,
						    sizeof(buffer), &length, NULL,
						    0));
	EXPECT_TRUE(length == 0);
	close_descriptor(sockets[0]);
	close_descriptor(sockets[1]);
}

static void test_rejected_pidfd_ancillary_is_closed(void)
{
	static const uint8_t packet[] = { 0x54, 0x31, 0x50, 0x49, 0x44 };
	int sockets[2] = { -1, -1 };
	int enabled = 1;
	int available_before;
	int available_after;
	uint8_t buffer[sizeof(packet)] = { 0 };
	size_t length = 99;

	create_pair(sockets);
	EXPECT_TRUE(setsockopt(sockets[1], SOL_SOCKET, SO_PASSPIDFD, &enabled,
			       sizeof(enabled)) == 0);
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_send_with_fds(sockets[0], packet,
						 sizeof(packet), NULL, 0));
	available_before = first_available_descriptor(sockets[0]);
	EXPECT_STATUS(T1_SEQPACKET_TRUNCATED,
		      t1_seqpacket_receive_with_fds(sockets[1], buffer,
						    sizeof(buffer), &length, NULL,
						    0));
	EXPECT_TRUE(length == 0);
	available_after = first_available_descriptor(sockets[0]);
	EXPECT_TRUE(available_after == available_before);
	close_descriptor(sockets[0]);
	close_descriptor(sockets[1]);
}

static void test_payload_truncation_closes_received_descriptor(void)
{
	static const uint8_t packet[] = { 0x54, 0x31, 0x4c, 0x4f, 0x4e, 0x47 };
	int sockets[2] = { -1, -1 };
	int pipe_descriptors[2] = { -1, -1 };
	int sent_descriptor;
	int received_descriptor = 99;
	int available_before;
	int available_after;
	uint8_t buffer[sizeof(packet)] = { 0 };
	size_t length = 99;

	create_pair(sockets);
	EXPECT_TRUE(pipe2(pipe_descriptors, O_CLOEXEC) == 0);
	sent_descriptor = pipe_descriptors[0];
	EXPECT_STATUS(T1_SEQPACKET_OK,
		      t1_seqpacket_send_with_fds(sockets[0], packet,
						 sizeof(packet), &sent_descriptor, 1));
	close_descriptor(pipe_descriptors[0]);
	pipe_descriptors[0] = -1;
	available_before = first_available_descriptor(pipe_descriptors[1]);
	EXPECT_STATUS(T1_SEQPACKET_TRUNCATED,
		      t1_seqpacket_receive_with_fds(sockets[1], buffer,
						    sizeof(packet) - 1, &length,
						    &received_descriptor, 1));
	EXPECT_TRUE(received_descriptor == -1);
	EXPECT_TRUE(length == 0);
	available_after = first_available_descriptor(pipe_descriptors[1]);
	EXPECT_TRUE(available_after == available_before);
	close_descriptor(pipe_descriptors[1]);
	close_descriptor(sockets[0]);
	close_descriptor(sockets[1]);
}

static void sigpipe_handler(int signal_number)
{
	(void)signal_number;
	++sigpipe_count;
}

static void test_exact_send_would_block_and_suppresses_sigpipe(void)
{
	uint8_t packet[1024] = { 0x54, 0x31 };
	int descriptors[2] = { -1, -1 };
	unsigned int attempts;
	enum t1_seqpacket_status status = T1_SEQPACKET_OK;
	struct sigaction action;
	struct sigaction previous;

	create_pair(descriptors);
	for (attempts = 0; attempts < 100000 && status == T1_SEQPACKET_OK;
	     ++attempts)
		status = t1_seqpacket_send(descriptors[0], packet, sizeof(packet));
	EXPECT_TRUE(status == T1_SEQPACKET_WOULD_BLOCK);
	EXPECT_TRUE(attempts < 100000);

	memset(&action, 0, sizeof(action));
	action.sa_handler = sigpipe_handler;
	EXPECT_TRUE(sigemptyset(&action.sa_mask) == 0);
	EXPECT_TRUE(sigaction(SIGPIPE, &action, &previous) == 0);
	close_descriptor(descriptors[1]);
	descriptors[1] = -1;
	EXPECT_STATUS(T1_SEQPACKET_SEND_FAILED,
		      t1_seqpacket_send(descriptors[0], packet, sizeof(packet)));
	EXPECT_TRUE(sigpipe_count == 0);
	EXPECT_TRUE(sigaction(SIGPIPE, &previous, NULL) == 0);
	close_descriptor(descriptors[0]);
}

static void test_arguments_and_static_statuses(void)
{
	static const char private_marker[] = "synthetic-private-marker";
	int descriptors[2] = { -1, -1 };
	struct t1_seqpacket_credentials credentials;
	uint8_t byte = 0;
	size_t length = 0;
	int accepted = -1;
	int adopted = 99;
	int second_adopted = 99;
	int ready = 99;
	int status;

	EXPECT_TRUE(T1_SEQPACKET_ACTIVATION_FAILED == 15);
	EXPECT_TRUE(T1_SEQPACKET_WRONG_PATH == 16);
	EXPECT_TRUE(T1_SEQPACKET_READINESS_FAILED == 17);
	EXPECT_TRUE(T1_SEQPACKET_CONNECT_FAILED == 18);
	EXPECT_TRUE(T1_SEQPACKET_PEER_DENIED == 19);
	create_pair(descriptors);
	EXPECT_STATUS(T1_SEQPACKET_INVALID_ARGUMENT,
		      t1_seqpacket_accept(descriptors[0], NULL));
	EXPECT_STATUS(T1_SEQPACKET_INVALID_ARGUMENT,
		      t1_seqpacket_accept(-1, &accepted));
	EXPECT_STATUS(T1_SEQPACKET_INVALID_ARGUMENT,
		      t1_seqpacket_adopt_systemd_listener(getpid(), 1, NULL,
			&adopted));
	EXPECT_TRUE(adopted == -1);
	adopted = 99;
	EXPECT_STATUS(T1_SEQPACKET_INVALID_ARGUMENT,
		      t1_seqpacket_adopt_systemd_listener(getpid(), 1, "",
			&adopted));
	EXPECT_TRUE(adopted == -1);
	EXPECT_STATUS(T1_SEQPACKET_INVALID_ARGUMENT,
		      t1_seqpacket_adopt_systemd_listener(getpid(), 1,
			"/synthetic", NULL));
	EXPECT_STATUS(T1_SEQPACKET_INVALID_ARGUMENT,
		t1_seqpacket_adopt_systemd_listener_pair(getpid(), 2, NULL,
			"/synthetic-second", &adopted, &second_adopted));
	EXPECT_TRUE(adopted == -1 && second_adopted == -1);
	adopted = 99;
	second_adopted = 99;
	EXPECT_STATUS(T1_SEQPACKET_INVALID_ARGUMENT,
		t1_seqpacket_adopt_systemd_listener_pair(getpid(), 2,
			"/synthetic", "/synthetic", &adopted,
			&second_adopted));
	EXPECT_TRUE(adopted == -1 && second_adopted == -1);
	EXPECT_STATUS(T1_SEQPACKET_INVALID_ARGUMENT,
		      t1_seqpacket_listener_ready(descriptors[0], NULL));
	EXPECT_STATUS(T1_SEQPACKET_NOT_LISTENER,
		      t1_seqpacket_listener_ready(descriptors[0], &ready));
	EXPECT_TRUE(ready == 0);
	EXPECT_STATUS(T1_SEQPACKET_INVALID_ARGUMENT,
		      t1_seqpacket_peer_credentials(descriptors[0], NULL));
	EXPECT_STATUS(T1_SEQPACKET_INVALID_ARGUMENT,
		      t1_seqpacket_receive(descriptors[0], NULL, 1, &length));
	EXPECT_STATUS(T1_SEQPACKET_INVALID_ARGUMENT,
		      t1_seqpacket_receive(descriptors[0], &byte, 0, &length));
	EXPECT_STATUS(T1_SEQPACKET_INVALID_ARGUMENT,
		      t1_seqpacket_receive(descriptors[0], &byte, 1, NULL));
	EXPECT_STATUS(T1_SEQPACKET_INVALID_ARGUMENT,
		      t1_seqpacket_receive_with_fds(descriptors[0], &byte, 1,
						    &length, NULL, 1));
	EXPECT_STATUS(T1_SEQPACKET_INVALID_ARGUMENT,
		      t1_seqpacket_receive_with_fds(descriptors[0], &byte, 1,
					    &length, &accepted, 2));
	EXPECT_STATUS(T1_SEQPACKET_INVALID_ARGUMENT,
		      t1_seqpacket_receive_at_most_one_fd(descriptors[0], &byte,
				1, &length, NULL, &length));
	EXPECT_STATUS(T1_SEQPACKET_INVALID_ARGUMENT,
		      t1_seqpacket_receive_at_most_one_fd(descriptors[0], &byte,
				1, &length, &accepted, NULL));
	EXPECT_STATUS(T1_SEQPACKET_INVALID_ARGUMENT,
		      t1_seqpacket_send(descriptors[0], NULL, 1));
	EXPECT_STATUS(T1_SEQPACKET_INVALID_ARGUMENT,
		      t1_seqpacket_send(descriptors[0], &byte, 0));
	EXPECT_STATUS(T1_SEQPACKET_INVALID_ARGUMENT,
		      t1_seqpacket_send_with_fds(descriptors[0], &byte, 1, NULL, 1));
	EXPECT_STATUS(T1_SEQPACKET_INVALID_ARGUMENT,
		      t1_seqpacket_send_with_fds(descriptors[0], &byte, 1,
						 &accepted, 2));
	accepted = -1;
	EXPECT_STATUS(T1_SEQPACKET_INVALID_ARGUMENT,
		      t1_seqpacket_send_with_fds(descriptors[0], &byte, 1,
						 &accepted, 1));
	memset(&credentials, 0, sizeof(credentials));
	for (status = T1_SEQPACKET_OK; status <= T1_SEQPACKET_PEER_DENIED;
	     ++status) {
		const char *message = t1_seqpacket_status_string(
			(enum t1_seqpacket_status)status);

		EXPECT_TRUE(strstr(message, private_marker) == NULL);
		EXPECT_TRUE(strchr(message, '/') == NULL);
		EXPECT_TRUE(strstr(message, "0x") == NULL);
	}
	close_descriptor(descriptors[0]);
	close_descriptor(descriptors[1]);
}

int main(void)
{
	run_fork_isolated(test_activation_descriptor_failures_child);
	run_fork_isolated(test_activation_wrong_path_child);
	run_fork_isolated(test_activation_success_and_readiness_child);
	run_fork_isolated(test_pair_activation_validation_is_atomic_child);
	run_fork_isolated(test_pair_activation_success_child);
	run_fork_isolated(
		test_pair_activation_partial_duplication_fails_closed_child);
	run_fork_isolated(test_readiness_errors_and_interruption_child);
	test_accept_is_local_nonblocking_and_close_on_exec();
	test_touchbar_connect_uses_fixed_path_and_safe_flags();
	test_touchbar_connect_failures_close_the_socket();
	test_auth_connect_uses_fixed_path_and_safe_flags();
	test_auth_connect_failures_close_the_socket();
	test_interrupted_accept_is_explicit();
	test_descriptor_shape_and_connection_are_enforced();
	test_kernel_peer_credentials();
	test_peer_group_admission_uses_kernel_primary_and_supplementary();
	test_peer_group_admission_bounds_and_validates_kernel_results();
	test_disconnect_probe_is_non_consuming_and_fail_closed();
	test_packet_boundaries_and_truncation();
	test_ancillary_rights_are_rejected_without_fd_leak();
	test_fd_packets_preserve_boundaries_and_cloexec();
	test_at_most_one_fd_reports_zero_or_one();
	test_at_most_one_fd_rejects_and_closes_multiple();
	test_fd_count_mismatches_close_received_descriptors();
	test_truncated_fd_control_closes_every_installed_descriptor();
	test_non_rights_ancillary_data_is_rejected();
	test_rejected_pidfd_ancillary_is_closed();
	test_payload_truncation_closes_received_descriptor();
	test_exact_send_would_block_and_suppresses_sigpipe();
	test_arguments_and_static_statuses();

	if (failures != 0) {
		fprintf(stderr, "%u t1_seqpacket test(s) failed\n", failures);
		return EXIT_FAILURE;
	}
	puts("t1_seqpacket tests passed");
	return EXIT_SUCCESS;
}

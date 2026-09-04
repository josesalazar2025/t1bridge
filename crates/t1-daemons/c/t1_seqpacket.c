#define _GNU_SOURCE

#include "t1_seqpacket.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define T1_SYSTEMD_LISTENER_DESCRIPTOR 3
#define T1_SYSTEMD_SECOND_LISTENER_DESCRIPTOR 4
#define T1_SYSTEMD_PAIR_FIRST_DUPLICATE 5
#define T1_TOUCHBAR_SOCKET_PATH "/run/t1bridge/touchbar.sock"
#define T1_AUTH_SOCKET_PATH "/run/t1-touchid/auth.sock"
#define T1_SEQPACKET_MAX_DESCRIPTOR_COUNT 1
#define T1_SEQPACKET_INITIAL_PEER_GROUPS 64
#define T1_SEQPACKET_MAX_PEER_GROUPS 65536
#define T1_SEQPACKET_PEER_GROUP_RESIZES 2
#define T1_SEQPACKET_CONTROL_CAPACITY                                      \
	(CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(2 * sizeof(int)))

static int get_socket_integer(int descriptor, int option, int *value)
{
	socklen_t length;
	int result;

	do {
		length = sizeof(*value);
		result = getsockopt(descriptor, SOL_SOCKET, option, value,
				    &length);
	} while (result != 0 && errno == EINTR);
	return result == 0 && length == sizeof(*value) ? 0 : -1;
}

static enum t1_seqpacket_status validate_shape(int descriptor, int *accepting)
{
	int domain = 0;
	int type = 0;
	int is_accepting = 0;

	if (descriptor < 0)
		return T1_SEQPACKET_INVALID_ARGUMENT;
	if (get_socket_integer(descriptor, SO_DOMAIN, &domain) != 0)
		return T1_SEQPACKET_DESCRIPTOR_FAILED;
	if (get_socket_integer(descriptor, SO_TYPE, &type) != 0)
		return T1_SEQPACKET_DESCRIPTOR_FAILED;
	if (get_socket_integer(descriptor, SO_ACCEPTCONN, &is_accepting) != 0)
		return T1_SEQPACKET_DESCRIPTOR_FAILED;
	if (domain != AF_UNIX || type != SOCK_SEQPACKET)
		return T1_SEQPACKET_WRONG_SOCKET;
	if (accepting != NULL)
		*accepting = is_accepting != 0;
	return T1_SEQPACKET_OK;
}

static enum t1_seqpacket_status validate_listener(int descriptor)
{
	int accepting = 0;
	enum t1_seqpacket_status status = validate_shape(descriptor, &accepting);

	if (status != T1_SEQPACKET_OK)
		return status;
	return accepting ? T1_SEQPACKET_OK : T1_SEQPACKET_NOT_LISTENER;
}

static enum t1_seqpacket_status validate_client(int descriptor)
{
	struct sockaddr_un address;
	socklen_t address_length = sizeof(address);
	int accepting = 0;
	enum t1_seqpacket_status status = validate_shape(descriptor, &accepting);

	if (status != T1_SEQPACKET_OK)
		return status;
	if (accepting)
		return T1_SEQPACKET_NOT_CONNECTED;
	memset(&address, 0, sizeof(address));
	if (getpeername(descriptor, (struct sockaddr *)&address,
			&address_length) != 0)
		return T1_SEQPACKET_NOT_CONNECTED;
	if (address_length < sizeof(address.sun_family) ||
	    address.sun_family != AF_UNIX)
		return T1_SEQPACKET_WRONG_SOCKET;
	return T1_SEQPACKET_OK;
}

static enum t1_seqpacket_status transient_status(
	int error, enum t1_seqpacket_status permanent_status)
{
	if (error == EINTR)
		return T1_SEQPACKET_INTERRUPTED;
	if (error == EAGAIN || error == EWOULDBLOCK)
		return T1_SEQPACKET_WOULD_BLOCK;
	return permanent_status;
}

static enum t1_seqpacket_status validate_listener_path(
	int descriptor, const char *expected_path)
{
	struct sockaddr_un address;
	socklen_t address_length = sizeof(address);
	size_t expected_length;
	size_t address_path_length;

	if (expected_path == NULL || expected_path[0] == '\0')
		return T1_SEQPACKET_INVALID_ARGUMENT;
	expected_length = strlen(expected_path);
	if (expected_length >= sizeof(address.sun_path))
		return T1_SEQPACKET_INVALID_ARGUMENT;
	do {
		memset(&address, 0, sizeof(address));
		address_length = sizeof(address);
		if (getsockname(descriptor, (struct sockaddr *)&address,
				&address_length) == 0)
			break;

		if (errno == EINTR) {
			continue;
		}
		return T1_SEQPACKET_DESCRIPTOR_FAILED;
	} while (1);
	if (address_length < offsetof(struct sockaddr_un, sun_path) ||
	    address.sun_family != AF_UNIX)
		return T1_SEQPACKET_WRONG_PATH;
	address_path_length = address_length -
		offsetof(struct sockaddr_un, sun_path);
	if (address_path_length != expected_length + 1 ||
	    address.sun_path[0] == '\0' ||
	    memcmp(address.sun_path, expected_path, expected_length) != 0 ||
	    address.sun_path[expected_length] != '\0')
		return T1_SEQPACKET_WRONG_PATH;
	return T1_SEQPACKET_OK;
}

enum t1_seqpacket_status t1_seqpacket_adopt_systemd_listener(
	pid_t activation_pid, unsigned int activation_fds,
	const char *expected_path, int *listener_descriptor)
{
	enum t1_seqpacket_status status;
	int status_flags;
	int duplicate = -1;

	if (listener_descriptor == NULL)
		return T1_SEQPACKET_INVALID_ARGUMENT;
	*listener_descriptor = -1;
	if (expected_path == NULL || expected_path[0] == '\0')
		return T1_SEQPACKET_INVALID_ARGUMENT;
	if (activation_pid != getpid() || activation_fds != 1)
		return T1_SEQPACKET_ACTIVATION_FAILED;
	status_flags = fcntl(T1_SYSTEMD_LISTENER_DESCRIPTOR, F_GETFL);
	if (status_flags < 0)
		return T1_SEQPACKET_ACTIVATION_FAILED;
	status = validate_listener(T1_SYSTEMD_LISTENER_DESCRIPTOR);
	if (status != T1_SEQPACKET_OK)
		return status;
	status = validate_listener_path(T1_SYSTEMD_LISTENER_DESCRIPTOR,
					expected_path);
	if (status != T1_SEQPACKET_OK)
		return status;
	duplicate = fcntl(T1_SYSTEMD_LISTENER_DESCRIPTOR, F_DUPFD_CLOEXEC,
			  T1_SYSTEMD_LISTENER_DESCRIPTOR + 1);
	if (duplicate < 0)
		return T1_SEQPACKET_ACTIVATION_FAILED;
	if (fcntl(duplicate, F_SETFL, status_flags | O_NONBLOCK) != 0) {
		(void)close(duplicate);
		return T1_SEQPACKET_ACTIVATION_FAILED;
	}
	if (close(T1_SYSTEMD_LISTENER_DESCRIPTOR) != 0) {
		(void)close(duplicate);
		return T1_SEQPACKET_ACTIVATION_FAILED;
	}
	*listener_descriptor = duplicate;
	return T1_SEQPACKET_OK;
}

static enum t1_seqpacket_status validate_activation_listener(
	int descriptor, const char *expected_path, int *status_flags)
{
	enum t1_seqpacket_status status;

	*status_flags = fcntl(descriptor, F_GETFL);
	if (*status_flags < 0)
		return T1_SEQPACKET_ACTIVATION_FAILED;
	status = validate_listener(descriptor);
	if (status != T1_SEQPACKET_OK)
		return status;
	return validate_listener_path(descriptor, expected_path);
}

static int duplicate_activation_listener(int descriptor, int minimum)
{
	return fcntl(descriptor, F_DUPFD_CLOEXEC, minimum);
}

enum t1_seqpacket_status t1_seqpacket_adopt_systemd_listener_pair(
	pid_t activation_pid, unsigned int activation_fds,
	const char *first_expected_path, const char *second_expected_path,
	int *first_listener_descriptor, int *second_listener_descriptor)
{
	enum t1_seqpacket_status status;
	int first_flags = 0;
	int second_flags = 0;
	int first_duplicate = -1;
	int second_duplicate = -1;
	int first_close;
	int second_close;

	if (first_listener_descriptor != NULL)
		*first_listener_descriptor = -1;
	if (second_listener_descriptor != NULL)
		*second_listener_descriptor = -1;
	if (first_listener_descriptor == NULL ||
	    second_listener_descriptor == NULL)
		return T1_SEQPACKET_INVALID_ARGUMENT;
	if (first_expected_path == NULL || first_expected_path[0] == '\0' ||
	    second_expected_path == NULL || second_expected_path[0] == '\0' ||
	    strcmp(first_expected_path, second_expected_path) == 0)
		return T1_SEQPACKET_INVALID_ARGUMENT;
	if (activation_pid != getpid() || activation_fds != 2)
		return T1_SEQPACKET_ACTIVATION_FAILED;

	status = validate_activation_listener(T1_SYSTEMD_LISTENER_DESCRIPTOR,
		first_expected_path, &first_flags);
	if (status != T1_SEQPACKET_OK)
		return status;
	status = validate_activation_listener(
		T1_SYSTEMD_SECOND_LISTENER_DESCRIPTOR, second_expected_path,
		&second_flags);
	if (status != T1_SEQPACKET_OK)
		return status;

	first_duplicate = duplicate_activation_listener(
		T1_SYSTEMD_LISTENER_DESCRIPTOR,
		T1_SYSTEMD_PAIR_FIRST_DUPLICATE);
	if (first_duplicate < 0)
		return T1_SEQPACKET_ACTIVATION_FAILED;
	second_duplicate = duplicate_activation_listener(
		T1_SYSTEMD_SECOND_LISTENER_DESCRIPTOR, first_duplicate + 1);
	if (second_duplicate < 0) {
		(void)close(first_duplicate);
		return T1_SEQPACKET_ACTIVATION_FAILED;
	}

	first_close = close(T1_SYSTEMD_LISTENER_DESCRIPTOR);
	second_close = close(T1_SYSTEMD_SECOND_LISTENER_DESCRIPTOR);

	if (first_close != 0 || second_close != 0) {
		(void)close(first_duplicate);
		(void)close(second_duplicate);
		return T1_SEQPACKET_ACTIVATION_FAILED;
	}
	if (fcntl(first_duplicate, F_SETFL, first_flags | O_NONBLOCK) != 0 ||
	    fcntl(second_duplicate, F_SETFL, second_flags | O_NONBLOCK) != 0) {
		(void)close(first_duplicate);
		(void)close(second_duplicate);
		return T1_SEQPACKET_ACTIVATION_FAILED;
	}
	*first_listener_descriptor = first_duplicate;
	*second_listener_descriptor = second_duplicate;
	return T1_SEQPACKET_OK;
}

enum t1_seqpacket_status t1_seqpacket_listener_ready(
	int listener_descriptor, int *ready)
{
	struct pollfd descriptor;
	enum t1_seqpacket_status status;
	int result;

	if (ready == NULL)
		return T1_SEQPACKET_INVALID_ARGUMENT;
	*ready = 0;
	status = validate_listener(listener_descriptor);
	if (status != T1_SEQPACKET_OK)
		return status;
	memset(&descriptor, 0, sizeof(descriptor));
	descriptor.fd = listener_descriptor;
	descriptor.events = POLLIN;
	result = poll(&descriptor, 1, 0);
	if (result < 0)
		return transient_status(errno, T1_SEQPACKET_READINESS_FAILED);
	if ((descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0)
		return T1_SEQPACKET_READINESS_FAILED;
	*ready = (descriptor.revents & POLLIN) != 0;
	return T1_SEQPACKET_OK;
}

enum t1_seqpacket_status t1_seqpacket_accept(int listener_descriptor,
	int *client_descriptor)
{
	enum t1_seqpacket_status status;
	int accepted;

	if (client_descriptor == NULL)
		return T1_SEQPACKET_INVALID_ARGUMENT;
	*client_descriptor = -1;
	status = validate_listener(listener_descriptor);
	if (status != T1_SEQPACKET_OK)
		return status;
	accepted = accept4(listener_descriptor, NULL, NULL,
			   SOCK_CLOEXEC | SOCK_NONBLOCK);
	if (accepted < 0)
		return transient_status(errno, T1_SEQPACKET_ACCEPT_FAILED);
	status = validate_client(accepted);
	if (status != T1_SEQPACKET_OK) {
		(void)close(accepted);
		return status;
	}
	*client_descriptor = accepted;
	return T1_SEQPACKET_OK;
}

static enum t1_seqpacket_status connect_fixed_path(const char *socket_path,
	size_t socket_path_size, int nonblocking_connect,
	int *client_descriptor)
{
	struct sockaddr_un address;
	socklen_t address_length;
	enum t1_seqpacket_status status;
	int descriptor;
	int status_flags;

	if (socket_path == NULL || socket_path_size == 0 ||
	    socket_path_size > sizeof(address.sun_path) ||
	    socket_path[socket_path_size - 1] != '\0' ||
	    client_descriptor == NULL)
		return T1_SEQPACKET_INVALID_ARGUMENT;
	*client_descriptor = -1;
	descriptor = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC |
		(nonblocking_connect ? SOCK_NONBLOCK : 0), 0);
	if (descriptor < 0)
		return T1_SEQPACKET_CONNECT_FAILED;
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	memcpy(address.sun_path, socket_path, socket_path_size);
	address_length = offsetof(struct sockaddr_un, sun_path) +
		(socklen_t)socket_path_size;
	if (connect(descriptor, (struct sockaddr *)&address, address_length) != 0) {
		int connect_error = errno;

		status = nonblocking_connect && connect_error == EINPROGRESS ?
			T1_SEQPACKET_WOULD_BLOCK :
			transient_status(connect_error,
				T1_SEQPACKET_CONNECT_FAILED);
		(void)close(descriptor);
		return status;
	}
	status_flags = fcntl(descriptor, F_GETFL);
	if (status_flags < 0 ||
	    fcntl(descriptor, F_SETFL, status_flags | O_NONBLOCK) != 0) {
		(void)close(descriptor);
		return T1_SEQPACKET_CONNECT_FAILED;
	}
	status = validate_client(descriptor);
	if (status != T1_SEQPACKET_OK) {
		(void)close(descriptor);
		return status;
	}
	*client_descriptor = descriptor;
	return T1_SEQPACKET_OK;
}

enum t1_seqpacket_status t1_seqpacket_connect_touchbar(
	int *client_descriptor)
{
	static const char socket_path[] = T1_TOUCHBAR_SOCKET_PATH;

	return connect_fixed_path(socket_path, sizeof(socket_path), 0,
		client_descriptor);
}

enum t1_seqpacket_status t1_seqpacket_connect_auth(int *client_descriptor)
{
	static const char socket_path[] = T1_AUTH_SOCKET_PATH;

	return connect_fixed_path(socket_path, sizeof(socket_path), 1,
		client_descriptor);
}

enum t1_seqpacket_status t1_seqpacket_peer_credentials(
	int client_descriptor, struct t1_seqpacket_credentials *credentials)
{
	struct ucred kernel_credentials;
	socklen_t length = sizeof(kernel_credentials);
	enum t1_seqpacket_status status;

	if (credentials == NULL)
		return T1_SEQPACKET_INVALID_ARGUMENT;
	memset(credentials, 0, sizeof(*credentials));
	status = validate_client(client_descriptor);
	if (status != T1_SEQPACKET_OK)
		return status;
	memset(&kernel_credentials, 0, sizeof(kernel_credentials));
	if (getsockopt(client_descriptor, SOL_SOCKET, SO_PEERCRED,
		       &kernel_credentials, &length) != 0 ||
	    length != sizeof(kernel_credentials))
		return T1_SEQPACKET_CREDENTIALS_FAILED;
	credentials->process_id = kernel_credentials.pid;
	credentials->user_id = kernel_credentials.uid;
	credentials->group_id = kernel_credentials.gid;
	return T1_SEQPACKET_OK;
}

enum t1_seqpacket_status t1_seqpacket_peer_in_group(
	int client_descriptor, gid_t allowed_gid)
{
	struct t1_seqpacket_credentials credentials;
	gid_t initial_groups[T1_SEQPACKET_INITIAL_PEER_GROUPS];
	gid_t *groups = initial_groups;
	size_t capacity = sizeof(initial_groups);
	size_t resize_count = 0;
	socklen_t length;
	size_t group_count;
	size_t index;
	int result;

	if (t1_seqpacket_peer_credentials(client_descriptor, &credentials) !=
	    T1_SEQPACKET_OK)
		return T1_SEQPACKET_PEER_DENIED;
	if (credentials.group_id == allowed_gid)
		return T1_SEQPACKET_OK;
	for (;;) {
		length = (socklen_t)capacity;
		result = getsockopt(client_descriptor, SOL_SOCKET, SO_PEERGROUPS,
				    groups, &length);
		if (result == 0)
			break;
		if (errno != ERANGE || resize_count ==
					 T1_SEQPACKET_PEER_GROUP_RESIZES ||
		    length <= capacity || length % sizeof(gid_t) != 0 ||
		    length / sizeof(gid_t) > T1_SEQPACKET_MAX_PEER_GROUPS) {
			if (groups != initial_groups)
				free(groups);
			return T1_SEQPACKET_PEER_DENIED;
		}
		if (groups != initial_groups)
			free(groups);
		groups = malloc(length);
		if (groups == NULL)
			return T1_SEQPACKET_PEER_DENIED;
		capacity = length;
		++resize_count;
	}
	if ((size_t)length > capacity || length % sizeof(gid_t) != 0 ||
	    length / sizeof(gid_t) > T1_SEQPACKET_MAX_PEER_GROUPS) {
		if (groups != initial_groups)
			free(groups);
		return T1_SEQPACKET_PEER_DENIED;
	}
	group_count = length / sizeof(gid_t);
	for (index = 0; index < group_count; ++index) {
		if (groups[index] == allowed_gid) {
			if (groups != initial_groups)
				free(groups);
			return T1_SEQPACKET_OK;
		}
	}
	if (groups != initial_groups)
		free(groups);
	return T1_SEQPACKET_PEER_DENIED;
}

enum t1_seqpacket_status t1_seqpacket_peer_closed(int client_descriptor,
	int *peer_closed)
{
	enum t1_seqpacket_status status;
	struct pollfd descriptor;
	int result;

	if (peer_closed == NULL)
		return T1_SEQPACKET_INVALID_ARGUMENT;
	*peer_closed = 0;
	status = validate_client(client_descriptor);
	if (status != T1_SEQPACKET_OK)
		return status;
	memset(&descriptor, 0, sizeof(descriptor));
	descriptor.fd = client_descriptor;
	descriptor.events = POLLIN | POLLRDHUP;
	result = poll(&descriptor, 1, 0);
	if (result < 0)
		return transient_status(errno, T1_SEQPACKET_RECEIVE_FAILED);
	if ((descriptor.revents & (POLLHUP | POLLRDHUP)) != 0) {
		*peer_closed = 1;
		return T1_SEQPACKET_OK;
	}
	if ((descriptor.revents & (POLLERR | POLLNVAL)) != 0)
		return T1_SEQPACKET_RECEIVE_FAILED;
	return T1_SEQPACKET_OK;
}

static void close_descriptors(int *descriptors, size_t descriptor_count)
{
	size_t index;

	for (index = 0; index < descriptor_count; ++index) {
		if (descriptors[index] >= 0)
			(void)close(descriptors[index]);
	}
}

static enum t1_seqpacket_status receive_with_fd_bounds(
	int client_descriptor, void *buffer, size_t capacity,
	size_t *received_length, int *descriptor,
	size_t minimum_descriptor_count, size_t maximum_descriptor_count,
	size_t *actual_descriptor_count)
{
	union {
		struct cmsghdr alignment;
		unsigned char bytes[T1_SEQPACKET_CONTROL_CAPACITY];
	} control;
	int received_descriptors[T1_SEQPACKET_CONTROL_CAPACITY / sizeof(int)];
	struct iovec vector;
	struct msghdr message;
	struct cmsghdr *header;
	enum t1_seqpacket_status status;
	size_t received_descriptor_count = 0;
	int ancillary_valid = 1;
	ssize_t result;

	if (buffer == NULL || received_length == NULL ||
	    actual_descriptor_count == NULL || capacity == 0 ||
	    capacity > (size_t)SSIZE_MAX ||
	    minimum_descriptor_count > maximum_descriptor_count ||
	    maximum_descriptor_count > T1_SEQPACKET_MAX_DESCRIPTOR_COUNT ||
	    (maximum_descriptor_count != 0 && descriptor == NULL))
		return T1_SEQPACKET_INVALID_ARGUMENT;
	*received_length = 0;
	*actual_descriptor_count = 0;
	if (maximum_descriptor_count != 0)
		*descriptor = -1;
	status = validate_client(client_descriptor);
	if (status != T1_SEQPACKET_OK)
		return status;
	memset(received_descriptors, 0xff, sizeof(received_descriptors));
	vector.iov_base = buffer;
	vector.iov_len = capacity;
	memset(&message, 0, sizeof(message));
	memset(&control, 0, sizeof(control));
	message.msg_iov = &vector;
	message.msg_iovlen = 1;
	message.msg_control = control.bytes;
	message.msg_controllen = sizeof(control.bytes);
	result = recvmsg(client_descriptor, &message,
			 MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
	if (result < 0)
		return transient_status(errno, T1_SEQPACKET_RECEIVE_FAILED);
	for (header = CMSG_FIRSTHDR(&message); header != NULL;
	     header = CMSG_NXTHDR(&message, header)) {
		size_t data_length;
		size_t header_descriptor_count;
		size_t index;

		if (header->cmsg_level == SOL_SOCKET &&
		    header->cmsg_type == SCM_PIDFD) {
			int received_descriptor;

			ancillary_valid = 0;
			if (header->cmsg_len != CMSG_LEN(sizeof(int)))
				continue;
			memcpy(&received_descriptor, CMSG_DATA(header),
			       sizeof(received_descriptor));
			if (received_descriptor_count <
			    sizeof(received_descriptors) /
				    sizeof(received_descriptors[0])) {
				received_descriptors[received_descriptor_count++] =
					received_descriptor;
			} else {
				(void)close(received_descriptor);
			}
			continue;
		}
		if (header->cmsg_level != SOL_SOCKET ||
		    header->cmsg_type != SCM_RIGHTS) {
			ancillary_valid = 0;
			continue;
		}
		if (header->cmsg_len < CMSG_LEN(0)) {
			ancillary_valid = 0;
			continue;
		}
		data_length = header->cmsg_len - CMSG_LEN(0);
		if (data_length % sizeof(int) != 0) {
			ancillary_valid = 0;
			continue;
		}
		header_descriptor_count = data_length / sizeof(int);
		for (index = 0; index < header_descriptor_count; ++index) {
			int received_descriptor;

			memcpy(&received_descriptor,
			       (unsigned char *)CMSG_DATA(header) +
				       index * sizeof(int),
			       sizeof(received_descriptor));
			if (received_descriptor_count <
			    sizeof(received_descriptors) /
				    sizeof(received_descriptors[0])) {
				received_descriptors[received_descriptor_count++] =
					received_descriptor;
			} else {
				(void)close(received_descriptor);
				ancillary_valid = 0;
			}
		}
	}
	if ((message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0 ||
	    !ancillary_valid ||
	    received_descriptor_count < minimum_descriptor_count ||
	    received_descriptor_count > maximum_descriptor_count) {
		close_descriptors(received_descriptors,
				  received_descriptor_count);
		return T1_SEQPACKET_TRUNCATED;
	}
	if (result == 0) {
		close_descriptors(received_descriptors,
				  received_descriptor_count);
		return T1_SEQPACKET_PEER_CLOSED;
	}
	if ((size_t)result > capacity) {
		close_descriptors(received_descriptors,
				  received_descriptor_count);
		return T1_SEQPACKET_TRUNCATED;
	}
	if (received_descriptor_count != 0)
		*descriptor = received_descriptors[0];
	*actual_descriptor_count = received_descriptor_count;
	*received_length = (size_t)result;
	return T1_SEQPACKET_OK;
}

enum t1_seqpacket_status t1_seqpacket_receive_with_fds(
	int client_descriptor, void *buffer, size_t capacity,
	size_t *received_length, int *descriptors, size_t descriptor_count)
{
	size_t actual_descriptor_count = 0;

	return receive_with_fd_bounds(client_descriptor, buffer, capacity,
		received_length, descriptors, descriptor_count, descriptor_count,
		&actual_descriptor_count);
}

enum t1_seqpacket_status t1_seqpacket_receive_at_most_one_fd(
	int client_descriptor, void *buffer, size_t capacity,
	size_t *received_length, int *descriptor,
	size_t *received_descriptor_count)
{
	return receive_with_fd_bounds(client_descriptor, buffer, capacity,
		received_length, descriptor, 0, 1, received_descriptor_count);
}

enum t1_seqpacket_status t1_seqpacket_receive(int client_descriptor,
	void *buffer, size_t capacity, size_t *received_length)
{
	return t1_seqpacket_receive_with_fds(client_descriptor, buffer, capacity,
					      received_length, NULL, 0);
}

enum t1_seqpacket_status t1_seqpacket_send_with_fds(int client_descriptor,
	const void *packet, size_t packet_length, const int *descriptors,
	size_t descriptor_count)
{
	union {
		struct cmsghdr alignment;
		unsigned char bytes[CMSG_SPACE(sizeof(int))];
	} control;
	struct iovec vector;
	struct msghdr message;
	struct cmsghdr *header;
	enum t1_seqpacket_status status;
	ssize_t result;

	if (packet == NULL || packet_length == 0 ||
	    packet_length > (size_t)SSIZE_MAX ||
	    descriptor_count > T1_SEQPACKET_MAX_DESCRIPTOR_COUNT ||
	    (descriptor_count != 0 && descriptors == NULL) ||
	    (descriptor_count != 0 && descriptors[0] < 0))
		return T1_SEQPACKET_INVALID_ARGUMENT;
	status = validate_client(client_descriptor);
	if (status != T1_SEQPACKET_OK)
		return status;
	vector.iov_base = (void *)packet;
	vector.iov_len = packet_length;
	memset(&message, 0, sizeof(message));
	message.msg_iov = &vector;
	message.msg_iovlen = 1;
	if (descriptor_count != 0) {
		memset(&control, 0, sizeof(control));
		message.msg_control = control.bytes;
		message.msg_controllen = sizeof(control.bytes);
		header = CMSG_FIRSTHDR(&message);
		if (header == NULL)
			return T1_SEQPACKET_SEND_FAILED;
		header->cmsg_level = SOL_SOCKET;
		header->cmsg_type = SCM_RIGHTS;
		header->cmsg_len = CMSG_LEN(sizeof(int));
		memcpy(CMSG_DATA(header), descriptors, sizeof(int));
	}
	result = sendmsg(client_descriptor, &message,
			 MSG_DONTWAIT | MSG_NOSIGNAL);
	if (result < 0)
		return transient_status(errno, T1_SEQPACKET_SEND_FAILED);
	if ((size_t)result != packet_length)
		return T1_SEQPACKET_SHORT_SEND;
	return T1_SEQPACKET_OK;
}

enum t1_seqpacket_status t1_seqpacket_send(int client_descriptor,
	const void *packet, size_t packet_length)
{
	return t1_seqpacket_send_with_fds(client_descriptor, packet, packet_length,
					   NULL, 0);
}

const char *t1_seqpacket_status_string(enum t1_seqpacket_status status)
{
	switch (status) {
	case T1_SEQPACKET_OK:
		return "success";
	case T1_SEQPACKET_INVALID_ARGUMENT:
		return "invalid local socket argument";
	case T1_SEQPACKET_DESCRIPTOR_FAILED:
		return "local socket descriptor inspection failed";
	case T1_SEQPACKET_WRONG_SOCKET:
		return "descriptor is not a local seqpacket socket";
	case T1_SEQPACKET_NOT_LISTENER:
		return "local seqpacket descriptor is not listening";
	case T1_SEQPACKET_NOT_CONNECTED:
		return "local seqpacket descriptor is not connected";
	case T1_SEQPACKET_WOULD_BLOCK:
		return "local seqpacket operation would block";
	case T1_SEQPACKET_INTERRUPTED:
		return "local seqpacket operation was interrupted";
	case T1_SEQPACKET_ACCEPT_FAILED:
		return "local seqpacket accept failed";
	case T1_SEQPACKET_CREDENTIALS_FAILED:
		return "local peer credential lookup failed";
	case T1_SEQPACKET_RECEIVE_FAILED:
		return "local seqpacket receive failed";
	case T1_SEQPACKET_TRUNCATED:
		return "local seqpacket was truncated";
	case T1_SEQPACKET_PEER_CLOSED:
		return "local seqpacket peer closed";
	case T1_SEQPACKET_SEND_FAILED:
		return "local seqpacket send failed";
	case T1_SEQPACKET_SHORT_SEND:
		return "local seqpacket send was short";
	case T1_SEQPACKET_ACTIVATION_FAILED:
		return "systemd socket activation failed";
	case T1_SEQPACKET_WRONG_PATH:
		return "activated listener has an unexpected path";
	case T1_SEQPACKET_READINESS_FAILED:
		return "local listener readiness check failed";
	case T1_SEQPACKET_CONNECT_FAILED:
		return "Touch Bar service connection failed";
	case T1_SEQPACKET_PEER_DENIED:
		return "local peer is not authorized";
	}
	return "unknown local seqpacket error";
}

#define _GNU_SOURCE

#include "t1_xart_listener.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define T1_XART_SYS_CLASS_NET "/sys/class/net"
#define T1_XART_DRIVER "apple_t1_ncm"
#define T1_XART_BACKLOG 4
#define T1_XART_METADATA_PATH_CAPACITY (IF_NAMESIZE + 64)

static int read_hex_metadata(int root, const char *interface_name,
	const char *suffix, unsigned long maximum, unsigned long *value)
{
	char buffer[16];
	char path[T1_XART_METADATA_PATH_CAPACITY];
	char *end = NULL;
	ssize_t length;
	unsigned long parsed;
	int descriptor;
	int written;

	written = snprintf(path, sizeof(path), "%s/%s", interface_name,
		 suffix);
	if (written < 0 || (size_t)written >= sizeof(path))
		return -1;
	descriptor = openat(root, path, O_RDONLY | O_CLOEXEC | O_NOCTTY);
	if (descriptor < 0)
		return -1;
	do {
		length = read(descriptor, buffer, sizeof(buffer) - 1);
	} while (length < 0 && errno == EINTR);
	(void)close(descriptor);
	if (length <= 0 || (size_t)length >= sizeof(buffer))
		return -1;
	buffer[length] = '\0';
	errno = 0;
	parsed = strtoul(buffer, &end, 16);
	if (errno != 0 || end == buffer || parsed > maximum)
		return -1;
	if (*end == '\n')
		end++;
	if (*end != '\0')
		return -1;
	*value = parsed;
	return 0;
}

static int driver_matches(int root, const char *interface_name, int *matches)
{
	char path[T1_XART_METADATA_PATH_CAPACITY];
	char target[256];
	const char *base;
	ssize_t length;
	int written;

	*matches = 0;
	written = snprintf(path, sizeof(path), "%s/device/driver",
		 interface_name);
	if (written < 0 || (size_t)written >= sizeof(path))
		return -1;
	length = readlinkat(root, path, target, sizeof(target) - 1);
	if (length < 0) {
		if (errno == ENOENT || errno == ENOTDIR)
			return 0;
		return -1;
	}
	if ((size_t)length >= sizeof(target) - 1)
		return -1;
	target[length] = '\0';
	base = strrchr(target, '/');
	base = base == NULL ? target : base + 1;
	*matches = strcmp(base, T1_XART_DRIVER) == 0;
	return 0;
}

static int linux_enumerate(void *context,
	struct t1_xart_interface_candidate *candidates, size_t capacity,
	size_t *count)
{
	struct if_nameindex *interfaces;
	struct if_nameindex *entry;
	size_t inspected = 0;
	size_t found = 0;
	int root;

	(void)context;
	if (candidates == NULL || count == NULL)
		return -1;
	*count = 0;
	root = open(T1_XART_SYS_CLASS_NET,
		O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (root < 0)
		return -1;
	interfaces = if_nameindex();
	if (interfaces == NULL) {
		(void)close(root);
		return -1;
	}
	for (entry = interfaces;
	     entry->if_index != 0 && entry->if_name != NULL; entry++) {
		unsigned long interface_number;
		unsigned long product;
		unsigned long vendor;
		int matches;

		inspected++;
		if (inspected > T1_XART_MAX_INTERFACES) {
			if_freenameindex(interfaces);
			(void)close(root);
			return 1;
		}
		if (driver_matches(root, entry->if_name, &matches) != 0) {
			if_freenameindex(interfaces);
			(void)close(root);
			return -1;
		}
		if (!matches)
			continue;
		if (found == capacity ||
		    read_hex_metadata(root, entry->if_name,
			"device/../idVendor", UINT16_MAX, &vendor) != 0 ||
		    read_hex_metadata(root, entry->if_name,
			"device/../idProduct", UINT16_MAX, &product) != 0 ||
		    read_hex_metadata(root, entry->if_name,
			"device/bInterfaceNumber", UINT8_MAX,
			&interface_number) != 0) {
			if_freenameindex(interfaces);
			(void)close(root);
			return -1;
		}
		candidates[found].interface_index = entry->if_index;
		candidates[found].usb_vendor_id = (uint16_t)vendor;
		candidates[found].usb_product_id = (uint16_t)product;
		candidates[found].usb_interface_number =
			(uint8_t)interface_number;
		candidates[found].driver_matches = 1;
		found++;
	}
	if_freenameindex(interfaces);
	(void)close(root);
	*count = found;
	return 0;
}

static int linux_open_socket(void *context)
{
	int descriptor;
	int enabled = 1;

	(void)context;
	descriptor = socket(AF_INET6,
		SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_TCP);
	if (descriptor < 0)
		return -1;
	if (setsockopt(descriptor, IPPROTO_IPV6, IPV6_V6ONLY, &enabled,
		       sizeof(enabled)) != 0 ||
	    setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, &enabled,
		       sizeof(enabled)) != 0) {
		(void)close(descriptor);
		return -1;
	}
	return descriptor;
}

static int linux_bind_interface(void *context, int descriptor,
	uint32_t interface_index)
{
	char name[IF_NAMESIZE];

	(void)context;
	if (if_indextoname(interface_index, name) == NULL)
		return -1;
	return setsockopt(descriptor, SOL_SOCKET, SO_BINDTODEVICE, name,
		strlen(name) + 1);
}

static int linux_bind_address(void *context, int descriptor, uint16_t port)
{
	struct sockaddr_in6 address;

	(void)context;
	memset(&address, 0, sizeof(address));
	address.sin6_family = AF_INET6;
	address.sin6_port = htons(port);
	address.sin6_addr = in6addr_any;
	return bind(descriptor, (const struct sockaddr *)&address,
		    sizeof(address));
}

static int linux_listen(void *context, int descriptor, int backlog)
{
	(void)context;
	return listen(descriptor, backlog);
}

static int linux_bound_interface(void *context, int descriptor,
	uint32_t *interface_index)
{
	char name[IF_NAMESIZE];
	socklen_t length = sizeof(name);
	unsigned int index;

	(void)context;
	memset(name, 0, sizeof(name));
	if (getsockopt(descriptor, SOL_SOCKET, SO_BINDTODEVICE, name,
		       &length) != 0 || length == 0 || name[0] == '\0')
		return -1;
	name[sizeof(name) - 1] = '\0';
	index = if_nametoindex(name);
	if (index == 0)
		return -1;
	*interface_index = index;
	return 0;
}

static int linux_accept(void *context, int descriptor,
	struct t1_xart_peer_observation *observation)
{
	struct sockaddr_in6 peer;
	socklen_t peer_length = sizeof(peer);
	int accepted;

	(void)context;
	memset(&peer, 0, sizeof(peer));
	accepted = accept4(descriptor, (struct sockaddr *)&peer, &peer_length,
		SOCK_CLOEXEC);
	if (accepted < 0)
		return -errno;
	if (peer_length < sizeof(peer) || peer.sin6_family != AF_INET6) {
		(void)close(accepted);
		return -EAFNOSUPPORT;
	}
	observation->peer_scope_id = peer.sin6_scope_id;
	observation->peer_port = ntohs(peer.sin6_port);
	memcpy(observation->peer_address, &peer.sin6_addr,
	       sizeof(observation->peer_address));
	return accepted;
}

static int linux_close(void *context, int descriptor)
{
	(void)context;
	return close(descriptor);
}

static const struct t1_xart_listener_ops linux_ops = {
	.context = NULL,
	.enumerate = linux_enumerate,
	.open_socket = linux_open_socket,
	.bind_interface = linux_bind_interface,
	.bind_address = linux_bind_address,
	.listen_socket = linux_listen,
	.bound_interface = linux_bound_interface,
	.accept_socket = linux_accept,
	.close_fd = linux_close,
};

static bool valid_ops(const struct t1_xart_listener_ops *ops)
{
	return ops != NULL && ops->enumerate != NULL &&
		ops->open_socket != NULL && ops->bind_interface != NULL &&
		ops->bind_address != NULL && ops->listen_socket != NULL &&
		ops->bound_interface != NULL && ops->accept_socket != NULL &&
		ops->close_fd != NULL;
}

static bool valid_discovery_ops(const struct t1_xart_listener_ops *ops)
{
	return ops != NULL && ops->enumerate != NULL;
}

static bool valid_candidate(const struct t1_xart_interface_candidate *candidate)
{
	return candidate->interface_index != 0 && candidate->driver_matches == 1 &&
		candidate->usb_vendor_id == T1_XART_APPLE_VENDOR_ID &&
		candidate->usb_product_id == T1_XART_APPLE_PRODUCT_ID &&
		candidate->usb_interface_number == T1_XART_NCM_INTERFACE;
}

enum t1_xart_listener_status t1_xart_interface_discover_with_ops(
	const struct t1_xart_listener_ops *ops, uint32_t *interface_index)
{
	struct t1_xart_interface_candidate
		candidates[T1_XART_MAX_INTERFACES];
	size_t count = 0;
	size_t index;
	unsigned int matches = 0;
	int result;

	if (interface_index == NULL)
		return T1_XART_LISTENER_INVALID_ARGUMENT;
	*interface_index = 0;
	if (!valid_discovery_ops(ops))
		return T1_XART_LISTENER_INVALID_ARGUMENT;
	memset(candidates, 0, sizeof(candidates));
	result = ops->enumerate(ops->context, candidates,
		T1_XART_MAX_INTERFACES, &count);
	if (result > 0)
		return T1_XART_LISTENER_CANDIDATE_LIMIT;
	if (result < 0 || count > T1_XART_MAX_INTERFACES)
		return T1_XART_LISTENER_ENUMERATION_FAILED;
	for (index = 0; index < count; index++) {
		if (!valid_candidate(&candidates[index]))
			continue;
		matches++;
		*interface_index = candidates[index].interface_index;
	}
	if (matches == 0)
		return T1_XART_LISTENER_DEVICE_NOT_FOUND;
	if (matches != 1) {
		*interface_index = 0;
		return T1_XART_LISTENER_DEVICE_AMBIGUOUS;
	}
	return T1_XART_LISTENER_OK;
}

enum t1_xart_listener_status t1_xart_interface_discover(
	uint32_t *interface_index)
{
	return t1_xart_interface_discover_with_ops(&linux_ops,
		interface_index);
}

enum t1_xart_listener_status t1_xart_listener_open_with_ops(
	const struct t1_xart_listener_ops *ops, int *listener_descriptor,
	uint32_t *interface_index)
{
	uint32_t bound_index = 0;
	uint32_t revalidated_index = 0;
	uint32_t selected_index = 0;
	enum t1_xart_listener_status status;
	int descriptor = -1;

	if (listener_descriptor == NULL || interface_index == NULL)
		return T1_XART_LISTENER_INVALID_ARGUMENT;
	*listener_descriptor = -1;
	*interface_index = 0;
	if (!valid_ops(ops))
		return T1_XART_LISTENER_INVALID_ARGUMENT;
	status = t1_xart_interface_discover_with_ops(ops, &selected_index);
	if (status != T1_XART_LISTENER_OK)
		return status;
	descriptor = ops->open_socket(ops->context);
	if (descriptor < 0)
		return T1_XART_LISTENER_SOCKET_FAILED;
	if (ops->bind_interface(ops->context, descriptor, selected_index) != 0 ||
	    ops->bind_address(ops->context, descriptor, T1_XART_PORT) != 0) {
		(void)ops->close_fd(ops->context, descriptor);
		return T1_XART_LISTENER_BIND_FAILED;
	}
	if (ops->bound_interface(ops->context, descriptor, &bound_index) != 0) {
		(void)ops->close_fd(ops->context, descriptor);
		return T1_XART_LISTENER_INSPECTION_FAILED;
	}
	if (bound_index != selected_index) {
		(void)ops->close_fd(ops->context, descriptor);
		return T1_XART_LISTENER_WRONG_INTERFACE;
	}
	status = t1_xart_interface_discover_with_ops(ops, &revalidated_index);
	if (status != T1_XART_LISTENER_OK) {
		(void)ops->close_fd(ops->context, descriptor);
		return status;
	}
	if (revalidated_index != selected_index) {
		(void)ops->close_fd(ops->context, descriptor);
		return T1_XART_LISTENER_WRONG_INTERFACE;
	}
	if (ops->listen_socket(ops->context, descriptor,
		T1_XART_BACKLOG) != 0) {
		(void)ops->close_fd(ops->context, descriptor);
		return T1_XART_LISTENER_LISTEN_FAILED;
	}
	*listener_descriptor = descriptor;
	*interface_index = selected_index;
	return T1_XART_LISTENER_OK;
}

enum t1_xart_listener_status t1_xart_listener_open(
	int *listener_descriptor, uint32_t *interface_index)
{
	return t1_xart_listener_open_with_ops(&linux_ops, listener_descriptor,
		interface_index);
}

enum t1_xart_listener_status t1_xart_listener_accept_with_ops(
	const struct t1_xart_listener_ops *ops, int listener_descriptor,
	int *connection_descriptor,
	struct t1_xart_peer_observation *observation)
{
	uint32_t bound_index = 0;
	int accepted;

	if (connection_descriptor == NULL || observation == NULL)
		return T1_XART_LISTENER_INVALID_ARGUMENT;
	*connection_descriptor = -1;
	memset(observation, 0, sizeof(*observation));
	if (!valid_ops(ops) || listener_descriptor < 0)
		return T1_XART_LISTENER_INVALID_ARGUMENT;
	if (ops->bound_interface(ops->context, listener_descriptor,
		&bound_index) != 0)
		return T1_XART_LISTENER_INSPECTION_FAILED;
	accepted = ops->accept_socket(ops->context, listener_descriptor,
		observation);
	if (accepted < 0) {
		if (accepted == -EAGAIN || accepted == -EWOULDBLOCK)
			return T1_XART_LISTENER_WOULD_BLOCK;
		if (accepted == -EINTR)
			return T1_XART_LISTENER_INTERRUPTED;
		if (accepted == -EAFNOSUPPORT)
			return T1_XART_LISTENER_WRONG_PEER_FAMILY;
		return T1_XART_LISTENER_ACCEPT_FAILED;
	}
	observation->listener_interface_index = bound_index;
	*connection_descriptor = accepted;
	return T1_XART_LISTENER_OK;
}

enum t1_xart_listener_status t1_xart_listener_accept(
	int listener_descriptor, int *connection_descriptor,
	struct t1_xart_peer_observation *observation)
{
	return t1_xart_listener_accept_with_ops(&linux_ops,
		listener_descriptor, connection_descriptor, observation);
}

const char *t1_xart_listener_status_string(
	enum t1_xart_listener_status status)
{
	switch (status) {
	case T1_XART_LISTENER_OK:
		return "success";
	case T1_XART_LISTENER_INVALID_ARGUMENT:
		return "invalid argument";
	case T1_XART_LISTENER_ENUMERATION_FAILED:
		return "network interface discovery failed";
	case T1_XART_LISTENER_CANDIDATE_LIMIT:
		return "network interface discovery limit exceeded";
	case T1_XART_LISTENER_DEVICE_NOT_FOUND:
		return "T1 NCM interface not found";
	case T1_XART_LISTENER_DEVICE_AMBIGUOUS:
		return "T1 NCM interface is ambiguous";
	case T1_XART_LISTENER_SOCKET_FAILED:
		return "xART socket creation failed";
	case T1_XART_LISTENER_BIND_FAILED:
		return "xART interface bind failed";
	case T1_XART_LISTENER_LISTEN_FAILED:
		return "xART listen failed";
	case T1_XART_LISTENER_INSPECTION_FAILED:
		return "xART socket inspection failed";
	case T1_XART_LISTENER_WRONG_INTERFACE:
		return "xART socket bound to wrong interface";
	case T1_XART_LISTENER_WOULD_BLOCK:
		return "xART accept would block";
	case T1_XART_LISTENER_INTERRUPTED:
		return "xART accept interrupted";
	case T1_XART_LISTENER_ACCEPT_FAILED:
		return "xART accept failed";
	case T1_XART_LISTENER_WRONG_PEER_FAMILY:
		return "xART peer is not IPv6";
	default:
		return "unknown xART listener error";
	}
}

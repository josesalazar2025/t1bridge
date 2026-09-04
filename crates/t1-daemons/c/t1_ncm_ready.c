#define _GNU_SOURCE

#include "t1_ncm_ready.h"
#include "t1_xart_listener.h"

#include <errno.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <poll.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define T1_NCM_NETLINK_BUFFER_SIZE 8192u
#define T1_NCM_NETLINK_TIMEOUT_MS 1000u
#define T1_NCM_LINK_SEQUENCE 1u
#define T1_NCM_ADDRESS_SEQUENCE 2u
#define T1_NCM_SEND_INTERRUPT_LIMIT 16u

struct t1_ncm_link_request {
	struct nlmsghdr header;
	struct ifinfomsg interface;
};

struct t1_ncm_address_request {
	struct nlmsghdr header;
	struct ifaddrmsg address;
};

static int linux_monotonic_ms(void *context, uint64_t *milliseconds)
{
	struct timespec now;

	(void)context;
	if (milliseconds == NULL || clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
	    now.tv_sec < 0 || (uint64_t)now.tv_sec > UINT64_MAX / 1000u)
		return -1;
	*milliseconds = (uint64_t)now.tv_sec * 1000u +
		(uint64_t)now.tv_nsec / 1000000u;
	return 0;
}

static int linux_wait_ms(void *context, uint32_t milliseconds)
{
	struct timespec remaining;

	(void)context;
	remaining.tv_sec = (time_t)(milliseconds / 1000u);
	remaining.tv_nsec = (long)(milliseconds % 1000u) * 1000000L;
	while (nanosleep(&remaining, &remaining) != 0) {
		if (errno != EINTR)
			return -1;
	}
	return 0;
}

static int linux_discover(void *context, uint32_t *interface_index)
{
	(void)context;
	return t1_xart_interface_discover(interface_index) ==
		T1_XART_LISTENER_OK ? 0 : -1;
}

static int open_route_socket(void)
{
	struct sockaddr_nl local;
	int descriptor;

	descriptor = socket(AF_NETLINK,
		SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);
	if (descriptor < 0)
		return -1;
	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	if (bind(descriptor, (const struct sockaddr *)&local,
		 sizeof(local)) != 0) {
		(void)close(descriptor);
		return -1;
	}
	return descriptor;
}

static int send_kernel_request(int descriptor, const void *request,
	size_t request_size)
{
	struct sockaddr_nl kernel;
	ssize_t sent;
	unsigned int interrupts = 0;

	memset(&kernel, 0, sizeof(kernel));
	kernel.nl_family = AF_NETLINK;
	for (;;) {
		sent = sendto(descriptor, request, request_size, 0,
			(const struct sockaddr *)&kernel, sizeof(kernel));
		if (sent >= 0 || errno != EINTR)
			break;
		interrupts++;
		if (interrupts >= T1_NCM_SEND_INTERRUPT_LIMIT)
			return -1;
	}
	return sent == (ssize_t)request_size ? 0 : -1;
}

static int deadline_after(uint32_t duration_ms, uint64_t *deadline)
{
	uint64_t now;

	if (linux_monotonic_ms(NULL, &now) != 0 ||
	    now > UINT64_MAX - duration_ms)
		return -1;
	*deadline = now + duration_ms;
	return 0;
}

static int wait_readable(int descriptor, uint64_t deadline)
{
	struct pollfd poll_descriptor = {
		.fd = descriptor,
		.events = POLLIN,
	};
	uint64_t now;
	uint64_t remaining;
	int timeout;
	int result;

	for (;;) {
		if (linux_monotonic_ms(NULL, &now) != 0 || now >= deadline)
			return -1;
		remaining = deadline - now;
		timeout = remaining > INT32_MAX ? INT32_MAX : (int)remaining;
		result = poll(&poll_descriptor, 1, timeout);
		if (result > 0 && (poll_descriptor.revents & POLLIN) != 0)
			return 0;
		if (result == 0)
			return -1;
		if (result < 0 && errno == EINTR)
			continue;
		return -1;
	}
}

static int receive_kernel_messages(int descriptor, uint32_t sequence,
	bool inspect_addresses, uint32_t interface_index)
{
	uint8_t buffer[T1_NCM_NETLINK_BUFFER_SIZE];
	uint64_t deadline;
	bool ready = false;

	if (deadline_after(T1_NCM_NETLINK_TIMEOUT_MS, &deadline) != 0)
		return -1;
	for (;;) {
		struct sockaddr_nl source;
		struct iovec vector = {
			.iov_base = buffer,
			.iov_len = sizeof(buffer),
		};
		struct msghdr message = {
			.msg_name = &source,
			.msg_namelen = sizeof(source),
			.msg_iov = &vector,
			.msg_iovlen = 1,
		};
		struct nlmsghdr *header;
		ssize_t length;
		int remaining;

		if (wait_readable(descriptor, deadline) != 0)
			return -1;
		memset(&source, 0, sizeof(source));
		length = recvmsg(descriptor, &message, 0);
		if (length < 0 && errno == EINTR)
			continue;
		if (length <= 0 || (message.msg_flags & MSG_TRUNC) != 0 ||
		    source.nl_family != AF_NETLINK || source.nl_pid != 0 ||
		    length > INT32_MAX)
			return -1;
		remaining = (int)length;
		for (header = (struct nlmsghdr *)buffer;
		     NLMSG_OK(header, remaining); header = NLMSG_NEXT(header, remaining)) {
			if (header->nlmsg_seq != sequence)
				continue;
			if (header->nlmsg_type == NLMSG_ERROR) {
				const struct nlmsgerr *error;

				if (header->nlmsg_len < NLMSG_LENGTH(sizeof(*error)))
					return -1;
				error = (const struct nlmsgerr *)NLMSG_DATA(header);
				return error->error == 0 && !inspect_addresses ? 1 : -1;
			}
			if (header->nlmsg_type == NLMSG_DONE) {
				if ((header->nlmsg_flags & NLM_F_DUMP_INTR) != 0)
					return -1;
				return inspect_addresses ? (ready ? 1 : 0) : -1;
			}
			if (inspect_addresses && header->nlmsg_type == RTM_NEWADDR) {
				const struct ifaddrmsg *address;
				const struct rtattr *attribute;
				const uint8_t *bytes = NULL;
				uint32_t flags;
				int attributes;

				if (header->nlmsg_len < NLMSG_LENGTH(sizeof(*address)))
					return -1;
				address = (const struct ifaddrmsg *)NLMSG_DATA(header);
				if (address->ifa_family != AF_INET6 ||
				    address->ifa_index != interface_index ||
				    address->ifa_scope != RT_SCOPE_LINK)
					continue;
				flags = address->ifa_flags;
				attributes = IFA_PAYLOAD(header);
				for (attribute = IFA_RTA(address);
				     RTA_OK(attribute, attributes);
				     attribute = RTA_NEXT(attribute, attributes)) {
					if (attribute->rta_type == IFA_FLAGS &&
					    RTA_PAYLOAD(attribute) == sizeof(flags))
						memcpy(&flags, RTA_DATA(attribute), sizeof(flags));
					if ((attribute->rta_type == IFA_ADDRESS ||
					     attribute->rta_type == IFA_LOCAL) &&
					    RTA_PAYLOAD(attribute) == 16u)
						bytes = RTA_DATA(attribute);
				}
				if (attributes != 0)
					return -1;
				if (bytes != NULL && bytes[0] == 0xfeu &&
				    (bytes[1] & 0xc0u) == 0x80u &&
				    (flags & (IFA_F_TENTATIVE | IFA_F_DADFAILED)) == 0)
					ready = true;
			}
		}
		if (remaining != 0)
			return -1;
	}
}

static int linux_set_up(void *context, uint32_t interface_index)
{
	struct t1_ncm_link_request request;
	int descriptor;
	int result;

	(void)context;
	if (interface_index == 0)
		return -1;
	descriptor = open_route_socket();
	if (descriptor < 0)
		return -1;
	memset(&request, 0, sizeof(request));
	request.header.nlmsg_len = NLMSG_LENGTH(sizeof(request.interface));
	request.header.nlmsg_type = RTM_NEWLINK;
	request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	request.header.nlmsg_seq = T1_NCM_LINK_SEQUENCE;
	request.interface.ifi_family = AF_UNSPEC;
	request.interface.ifi_index = (int)interface_index;
	request.interface.ifi_flags = IFF_UP;
	request.interface.ifi_change = IFF_UP;
	result = send_kernel_request(descriptor, &request,
		request.header.nlmsg_len);
	if (result == 0)
		result = receive_kernel_messages(descriptor,
			T1_NCM_LINK_SEQUENCE, false, interface_index) == 1 ? 0 : -1;
	(void)close(descriptor);
	return result;
}

static int linux_is_ready(void *context, uint32_t interface_index)
{
	struct t1_ncm_address_request request;
	int descriptor;
	int result;

	(void)context;
	if (interface_index == 0)
		return -1;
	descriptor = open_route_socket();
	if (descriptor < 0)
		return -1;
	memset(&request, 0, sizeof(request));
	request.header.nlmsg_len = NLMSG_LENGTH(sizeof(request.address));
	request.header.nlmsg_type = RTM_GETADDR;
	request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	request.header.nlmsg_seq = T1_NCM_ADDRESS_SEQUENCE;
	request.address.ifa_family = AF_INET6;
	result = send_kernel_request(descriptor, &request,
		request.header.nlmsg_len);
	if (result == 0)
		result = receive_kernel_messages(descriptor,
			T1_NCM_ADDRESS_SEQUENCE, true, interface_index);
	(void)close(descriptor);
	return result;
}

static const struct t1_ncm_ready_ops linux_ops = {
	.context = NULL,
	.discover = linux_discover,
	.set_up = linux_set_up,
	.is_ready = linux_is_ready,
	.monotonic_ms = linux_monotonic_ms,
	.wait_ms = linux_wait_ms,
};

static bool valid_ops(const struct t1_ncm_ready_ops *ops)
{
	return ops != NULL && ops->discover != NULL && ops->set_up != NULL &&
		ops->is_ready != NULL && ops->monotonic_ms != NULL &&
		ops->wait_ms != NULL;
}

enum t1_ncm_ready_status t1_ncm_ready_prepare_for_index_with_ops(
	uint32_t expected_interface_index, const struct t1_ncm_ready_ops *ops)
{
	uint32_t interface_index = 0;
	uint32_t revalidated_index = 0;
	uint64_t deadline;
	uint64_t now;
	uint64_t previous;
	uint32_t wait;
	int ready;

	if (!valid_ops(ops) || expected_interface_index == 0 ||
	    expected_interface_index > INT32_MAX)
		return T1_NCM_READY_INVALID_ARGUMENT;
	if (ops->monotonic_ms(ops->context, &now) != 0 ||
	    now > UINT64_MAX - T1_NCM_READY_TIMEOUT_MS)
		return T1_NCM_READY_CLOCK_FAILED;
	deadline = now + T1_NCM_READY_TIMEOUT_MS;
	previous = now;
	if (ops->discover(ops->context, &interface_index) != 0 ||
	    interface_index == 0 || interface_index > INT32_MAX ||
	    interface_index != expected_interface_index)
		return T1_NCM_READY_DISCOVERY_FAILED;
	if (ops->set_up(ops->context, interface_index) != 0)
		return T1_NCM_READY_LINK_UP_FAILED;
	for (;;) {
		if (ops->monotonic_ms(ops->context, &now) != 0 || now < previous)
			return T1_NCM_READY_CLOCK_FAILED;
		previous = now;
		if (now >= deadline)
			return T1_NCM_READY_TIMEOUT;
		ready = ops->is_ready(ops->context, interface_index);
		if (ready < 0)
			return T1_NCM_READY_INSPECTION_FAILED;
		if (ready > 0)
			break;
		if (ops->monotonic_ms(ops->context, &now) != 0 ||
		    now < previous)
			return T1_NCM_READY_CLOCK_FAILED;
		previous = now;
		if (now >= deadline)
			return T1_NCM_READY_TIMEOUT;
		wait = deadline - now < T1_NCM_READY_RETRY_MS ?
			(uint32_t)(deadline - now) : T1_NCM_READY_RETRY_MS;
		if (wait == 0 || ops->wait_ms(ops->context, wait) != 0)
			return T1_NCM_READY_WAIT_FAILED;
	}
	if (ops->discover(ops->context, &revalidated_index) != 0 ||
	    revalidated_index == 0 || revalidated_index > INT32_MAX ||
	    revalidated_index != interface_index)
		return T1_NCM_READY_DEVICE_CHANGED;
	return T1_NCM_READY_OK;
}

enum t1_ncm_ready_status t1_ncm_ready_prepare_for_interface(
	const char *expected_interface)
{
	uint32_t expected_interface_index;
	enum t1_ncm_ready_status status;
	size_t length;

	if (expected_interface == NULL)
		return T1_NCM_READY_INVALID_ARGUMENT;
	length = strnlen(expected_interface, IFNAMSIZ);
	if (length == 0 || length >= IFNAMSIZ)
		return T1_NCM_READY_INVALID_ARGUMENT;
	expected_interface_index = if_nametoindex(expected_interface);
	if (expected_interface_index == 0 || expected_interface_index > INT32_MAX)
		return T1_NCM_READY_DISCOVERY_FAILED;
	status = t1_ncm_ready_prepare_for_index_with_ops(
		expected_interface_index, &linux_ops);
	if (status != T1_NCM_READY_OK)
		return status;
	return if_nametoindex(expected_interface) == expected_interface_index ?
		T1_NCM_READY_OK : T1_NCM_READY_DEVICE_CHANGED;
}

#ifndef T1BRIDGE_T1_XART_LISTENER_H
#define T1BRIDGE_T1_XART_LISTENER_H

#include <stddef.h>
#include <stdint.h>

#define T1_XART_APPLE_VENDOR_ID 0x05acu
#define T1_XART_APPLE_PRODUCT_ID 0x8600u
#define T1_XART_NCM_INTERFACE 4u
#define T1_XART_PORT 0xf03cu
#define T1_XART_MAX_INTERFACES 256u

enum t1_xart_listener_status {
	T1_XART_LISTENER_OK = 0,
	T1_XART_LISTENER_INVALID_ARGUMENT,
	T1_XART_LISTENER_ENUMERATION_FAILED,
	T1_XART_LISTENER_CANDIDATE_LIMIT,
	T1_XART_LISTENER_DEVICE_NOT_FOUND,
	T1_XART_LISTENER_DEVICE_AMBIGUOUS,
	T1_XART_LISTENER_SOCKET_FAILED,
	T1_XART_LISTENER_BIND_FAILED,
	T1_XART_LISTENER_LISTEN_FAILED,
	T1_XART_LISTENER_INSPECTION_FAILED,
	T1_XART_LISTENER_WRONG_INTERFACE,
	T1_XART_LISTENER_WOULD_BLOCK,
	T1_XART_LISTENER_INTERRUPTED,
	T1_XART_LISTENER_ACCEPT_FAILED,
	T1_XART_LISTENER_WRONG_PEER_FAMILY,
};

/* Path- and name-free kernel metadata for one network interface. */
struct t1_xart_interface_candidate {
	uint32_t interface_index;
	uint16_t usb_vendor_id;
	uint16_t usb_product_id;
	uint8_t usb_interface_number;
	uint8_t driver_matches;
};

/* Kernel endpoint evidence captured before protocol parsing. */
struct t1_xart_peer_observation {
	uint32_t listener_interface_index;
	uint32_t peer_scope_id;
	uint16_t peer_port;
	uint8_t peer_address[16];
};

/* Focused discovery/socket seam for hardware-free native tests. */
struct t1_xart_listener_ops {
	void *context;
	int (*enumerate)(void *context,
		struct t1_xart_interface_candidate *candidates,
		size_t capacity, size_t *count);
	int (*open_socket)(void *context);
	int (*bind_interface)(void *context, int descriptor,
		uint32_t interface_index);
	int (*bind_address)(void *context, int descriptor, uint16_t port);
	int (*listen_socket)(void *context, int descriptor, int backlog);
	int (*bound_interface)(void *context, int descriptor,
		uint32_t *interface_index);
	int (*accept_socket)(void *context, int descriptor,
		struct t1_xart_peer_observation *observation);
	int (*close_fd)(void *context, int descriptor);
};

/*
 * Read and validate exactly one live apple_t1_ncm interface without opening a
 * socket. Success returns only its nonzero kernel index.
 */
enum t1_xart_listener_status t1_xart_interface_discover(
	uint32_t *interface_index);

enum t1_xart_listener_status t1_xart_interface_discover_with_ops(
	const struct t1_xart_listener_ops *ops, uint32_t *interface_index);

/*
 * Discover exactly one descriptor-validated apple_t1_ncm interface, then
 * create an IPv6-only listener bound exclusively to it. Success transfers a
 * close-on-exec, nonblocking listener. No interface name crosses this API.
 */
enum t1_xart_listener_status t1_xart_listener_open(
	int *listener_descriptor, uint32_t *interface_index);

enum t1_xart_listener_status t1_xart_listener_open_with_ops(
	const struct t1_xart_listener_ops *ops, int *listener_descriptor,
	uint32_t *interface_index);

/*
 * Accept one connection and capture its peer plus the listener's current
 * kernel-bound interface before returning it to a protocol parser.
 */
enum t1_xart_listener_status t1_xart_listener_accept(
	int listener_descriptor, int *connection_descriptor,
	struct t1_xart_peer_observation *observation);

enum t1_xart_listener_status t1_xart_listener_accept_with_ops(
	const struct t1_xart_listener_ops *ops, int listener_descriptor,
	int *connection_descriptor,
	struct t1_xart_peer_observation *observation);

const char *t1_xart_listener_status_string(
	enum t1_xart_listener_status status);

#endif

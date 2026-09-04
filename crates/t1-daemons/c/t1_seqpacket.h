#ifndef T1BRIDGE_T1_SEQPACKET_H
#define T1BRIDGE_T1_SEQPACKET_H

#include <stddef.h>
#include <sys/types.h>

enum t1_seqpacket_status {
	T1_SEQPACKET_OK = 0,
	T1_SEQPACKET_INVALID_ARGUMENT,
	T1_SEQPACKET_DESCRIPTOR_FAILED,
	T1_SEQPACKET_WRONG_SOCKET,
	T1_SEQPACKET_NOT_LISTENER,
	T1_SEQPACKET_NOT_CONNECTED,
	T1_SEQPACKET_WOULD_BLOCK,
	T1_SEQPACKET_INTERRUPTED,
	T1_SEQPACKET_ACCEPT_FAILED,
	T1_SEQPACKET_CREDENTIALS_FAILED,
	T1_SEQPACKET_RECEIVE_FAILED,
	T1_SEQPACKET_TRUNCATED,
	T1_SEQPACKET_PEER_CLOSED,
	T1_SEQPACKET_SEND_FAILED,
	T1_SEQPACKET_SHORT_SEND,
	T1_SEQPACKET_ACTIVATION_FAILED,
	T1_SEQPACKET_WRONG_PATH,
	T1_SEQPACKET_READINESS_FAILED,
	T1_SEQPACKET_CONNECT_FAILED,
	T1_SEQPACKET_PEER_DENIED,
};

struct t1_seqpacket_credentials {
	pid_t process_id;
	uid_t user_id;
	gid_t group_id;
};

/*
 * Adopt exactly one systemd-activated listener from descriptor 3. Process
 * entry must parse the activation environment and pass its numeric PID and
 * descriptor count here. The listener must have the exact expected pathname.
 *
 * Success transfers a close-on-exec, nonblocking duplicate and closes
 * descriptor 3. Validation, duplication, and flag-setting failures leave
 * descriptor 3 caller-owned. A close-stage failure is terminal and may have
 * consumed descriptor 3. This function does not read or mutate the process
 * environment.
 */
enum t1_seqpacket_status t1_seqpacket_adopt_systemd_listener(
	pid_t activation_pid, unsigned int activation_fds,
	const char *expected_path, int *listener_descriptor);

/*
 * Atomically validate exactly two systemd-activated listeners from descriptors
 * 3 and 4 in caller-supplied order. Both descriptors must be AF_UNIX
 * SOCK_SEQPACKET listeners at the two distinct exact expected paths before
 * either inherited descriptor is consumed.
 *
 * Success transfers two distinct close-on-exec, nonblocking duplicates and
 * closes descriptors 3 and 4. Every failure leaves -1 in both outputs and
 * closes any duplicates created by the function. Validation and duplication
 * failures leave both inherited descriptors caller-owned. A close-stage
 * failure is terminal and may have consumed one or both inherited descriptors.
 */
enum t1_seqpacket_status t1_seqpacket_adopt_systemd_listener_pair(
	pid_t activation_pid, unsigned int activation_fds,
	const char *first_expected_path, const char *second_expected_path,
	int *first_listener_descriptor, int *second_listener_descriptor);

/*
 * Probe whether an activated listener has a queued connection without
 * blocking, accepting it, or consuming any connection or packet data.
 */
enum t1_seqpacket_status t1_seqpacket_listener_ready(
	int listener_descriptor, int *ready);

/*
 * Accept from a caller-owned AF_UNIX SOCK_SEQPACKET listener. The returned
 * descriptor is close-on-exec and nonblocking. This function never creates,
 * binds, listens on, or assigns a path to a socket.
 */
enum t1_seqpacket_status t1_seqpacket_accept(int listener_descriptor,
	int *client_descriptor);

/*
 * Connect to the fixed Touch Bar hardware service pathname. Success returns a
 * caller-owned AF_UNIX SOCK_SEQPACKET descriptor that is close-on-exec and
 * nonblocking. The connect itself completes before nonblocking mode is set.
 *
 * The caller must use t1_seqpacket_peer_credentials and require root before
 * sending or receiving protocol data. Every failure leaves -1 in the output.
 */
enum t1_seqpacket_status t1_seqpacket_connect_touchbar(
	int *client_descriptor);

/*
 * Connect to the fixed Touch ID authentication broker pathname. The socket is
 * nonblocking from creation, so backlog and in-progress conditions return a
 * prompt transient failure. Success transfers a close-on-exec, nonblocking
 * descriptor. The caller must verify the broker's kernel credential is root
 * before any protocol exchange. No caller-selected pathname crosses here.
 */
enum t1_seqpacket_status t1_seqpacket_connect_auth(
	int *client_descriptor);

/* Read kernel SO_PEERCRED from a connected local seqpacket descriptor. */
enum t1_seqpacket_status t1_seqpacket_peer_credentials(
	int client_descriptor, struct t1_seqpacket_credentials *credentials);

/*
 * Admit only a connected peer whose kernel credential snapshot has allowed_gid
 * as its primary or supplementary group. SO_PEERGROUPS is bounded to 65,536
 * entries. Missing support, malformed results, lookup failure, and no match all
 * return T1_SEQPACKET_PEER_DENIED; no NSS or process-filesystem fallback occurs.
 */
enum t1_seqpacket_status t1_seqpacket_peer_in_group(
	int client_descriptor, gid_t allowed_gid);

/*
 * Probe a connected one-request client for a Linux socket hangup without
 * consuming queued packets.
 */
enum t1_seqpacket_status t1_seqpacket_peer_closed(int client_descriptor,
	int *peer_closed);

/*
 * Receive one complete packet without blocking. A packet larger than capacity
 * is rejected as truncated; its prefix must not be interpreted by the caller.
 */
enum t1_seqpacket_status t1_seqpacket_receive(int client_descriptor,
	void *buffer, size_t capacity, size_t *received_length);

/*
 * Receive one complete packet and exactly descriptor_count SCM_RIGHTS file
 * descriptors. v1 accepts zero or one descriptor. Successful descriptors are
 * close-on-exec and become caller-owned. Any packet/control truncation,
 * unexpected ancillary data, or descriptor-count mismatch closes every
 * received descriptor and returns T1_SEQPACKET_TRUNCATED.
 */
enum t1_seqpacket_status t1_seqpacket_receive_with_fds(
	int client_descriptor, void *buffer, size_t capacity,
	size_t *received_length, int *descriptors, size_t descriptor_count);

/*
 * Receive one complete packet with either zero or one SCM_RIGHTS descriptor.
 * Success reports the actual count and transfers the descriptor when present.
 * Rejection closes every installed descriptor and resets both outputs.
 */
enum t1_seqpacket_status t1_seqpacket_receive_at_most_one_fd(
	int client_descriptor, void *buffer, size_t capacity,
	size_t *received_length, int *descriptor,
	size_t *received_descriptor_count);

/* Send exactly one complete packet without blocking or raising SIGPIPE. */
enum t1_seqpacket_status t1_seqpacket_send(int client_descriptor,
	const void *packet, size_t packet_length);

/*
 * Send one complete packet with descriptor_count SCM_RIGHTS file descriptors.
 * v1 accepts zero or one descriptor and retains caller ownership.
 */
enum t1_seqpacket_status t1_seqpacket_send_with_fds(int client_descriptor,
	const void *packet, size_t packet_length, const int *descriptors,
	size_t descriptor_count);

const char *t1_seqpacket_status_string(enum t1_seqpacket_status status);

#endif

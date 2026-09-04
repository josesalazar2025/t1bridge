#ifndef T1BRIDGE_T1_TOUCHID_CANCEL_H
#define T1BRIDGE_T1_TOUCHID_CANCEL_H

#include <stddef.h>
#include <stdint.h>

enum t1_touchid_cancel_result {
	T1_TOUCHID_CANCEL_OK = 0,
	T1_TOUCHID_CANCEL_DENIED = 1,
	T1_TOUCHID_CANCEL_ERROR_ARGUMENT = -100,
	T1_TOUCHID_CANCEL_ERROR_CLOCK = -101,
	T1_TOUCHID_CANCEL_ERROR_TIMEOUT = -102,
	T1_TOUCHID_CANCEL_ERROR_PATH = -103,
	T1_TOUCHID_CANCEL_ERROR_CONNECT = -104,
	T1_TOUCHID_CANCEL_ERROR_CREDENTIALS = -105,
	T1_TOUCHID_CANCEL_ERROR_SEND = -106,
	T1_TOUCHID_CANCEL_ERROR_RECEIVE = -107,
	T1_TOUCHID_CANCEL_ERROR_PROTOCOL = -108,
	T1_TOUCHID_CANCEL_ERROR_CLOSE = -109,
};

enum t1_touchid_cancel_wait {
	T1_TOUCHID_CANCEL_WAIT_READ = 1,
	T1_TOUCHID_CANCEL_WAIT_WRITE = 2,
};

/* Focused syscall/seqpacket seam for behavior tests without the live broker. */
struct t1_touchid_cancel_ops {
	void *context;
	int (*monotonic_ms)(void *context, uint64_t *value);
	int (*inspect_path)(void *context, const char *path);
	int (*open_socket)(void *context);
	/* Zero connected, one pending, two interrupted, negative failure. */
	int (*connect_socket)(void *context, int descriptor, const char *path);
	int (*peer_user_id)(void *context, int descriptor, uint32_t *user_id);
	/* Zero complete, one would-block, two interrupted, negative failure. */
	int (*send_packet)(void *context, int descriptor,
		const void *packet, size_t packet_length);
	/* Same status convention as send_packet. */
	int (*receive_packet)(void *context, int descriptor,
		void *packet, size_t capacity, size_t *packet_length);
	/* Zero ready, one timed out, two interrupted, negative failure. */
	int (*wait_socket)(void *context, int descriptor,
		enum t1_touchid_cancel_wait interest, unsigned int timeout_ms);
	/* The descriptor is consumed even when close reports failure. */
	int (*close_fd)(void *context, int descriptor);
};

/* Runs only the fixed broker cancellation transaction under one 500ms budget. */
enum t1_touchid_cancel_result t1_touchid_cancel(void);

enum t1_touchid_cancel_result t1_touchid_cancel_with_ops(
	const struct t1_touchid_cancel_ops *ops);

const char *t1_touchid_cancel_result_string(
	enum t1_touchid_cancel_result result);

#ifdef T1_TOUCHID_CANCEL_TESTING
int t1_touchid_cancel_test_poll_events(int revents,
	enum t1_touchid_cancel_wait interest);
#endif

#endif

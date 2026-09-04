#ifndef T1BRIDGE_TOUCHBAR_UINPUT_H
#define T1BRIDGE_TOUCHBAR_UINPUT_H

#include "t1_touchbar_io.h"

enum t1_touchbar_key {
	T1_TOUCHBAR_KEY_ESCAPE = 0,
	T1_TOUCHBAR_KEY_F1,
	T1_TOUCHBAR_KEY_F2,
	T1_TOUCHBAR_KEY_F3,
	T1_TOUCHBAR_KEY_F4,
	T1_TOUCHBAR_KEY_F5,
	T1_TOUCHBAR_KEY_F6,
	T1_TOUCHBAR_KEY_F7,
	T1_TOUCHBAR_KEY_F8,
	T1_TOUCHBAR_KEY_F9,
	T1_TOUCHBAR_KEY_F10,
	T1_TOUCHBAR_KEY_F11,
	T1_TOUCHBAR_KEY_F12,
};

struct t1_touchbar_uinput;

/* Creates a virtual keyboard limited to Escape and F1 through F12. */
enum t1_touchbar_io_status t1_touchbar_uinput_create(
	struct t1_touchbar_uinput **device);

/* Emits one complete press/sync/release/sync sequence. */
enum t1_touchbar_io_status t1_touchbar_uinput_tap(
	struct t1_touchbar_uinput *device, enum t1_touchbar_key key);

/* Retries release for every key whose prior release was not confirmed. */
enum t1_touchbar_io_status t1_touchbar_uinput_release_all(
	struct t1_touchbar_uinput *device);

/* Releases held keys, destroys the virtual device, closes, and consumes it. */
enum t1_touchbar_io_status t1_touchbar_uinput_close(
	struct t1_touchbar_uinput *device);

#ifdef T1_TOUCHBAR_TESTING
/* Test-only constructor. It owns `descriptor` and skips setup ioctls. */
struct t1_touchbar_uinput *t1_touchbar_uinput_test_device(int descriptor);
unsigned int t1_touchbar_uinput_test_held(
	const struct t1_touchbar_uinput *device);
void t1_touchbar_uinput_test_mark_held(
	struct t1_touchbar_uinput *device, enum t1_touchbar_key key);
#endif

#endif

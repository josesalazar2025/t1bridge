#ifndef T1_USB_CYCLE_GUARD_H
#define T1_USB_CYCLE_GUARD_H

enum t1_usb_cycle_guard_status {
	T1_USB_CYCLE_GUARD_OK = 0,
	T1_USB_CYCLE_GUARD_BUSY = 1,
	T1_USB_CYCLE_GUARD_INVALID = 2,
	T1_USB_CYCLE_GUARD_SYSTEM = 3,
};

int t1_usb_cycle_guard_acquire(void);
int t1_usb_cycle_guard_acquire_path(const char *cycle_path);
int t1_usb_cycle_guard_acquire_sep(void);
int t1_usb_cycle_guard_acquire_sep_path(const char *sep_path);
int t1_usb_cycle_guard_interrupted(void);
void t1_usb_cycle_guard_release_sep(void);
void t1_usb_cycle_guard_release(void);

#endif

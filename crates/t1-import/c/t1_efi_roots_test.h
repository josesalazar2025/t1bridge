#ifndef T1BRIDGE_EFI_ROOTS_TEST_H
#define T1BRIDGE_EFI_ROOTS_TEST_H

#include <stddef.h>
#include <stdint.h>

struct t1_efi_test_candidate {
	uint32_t major_number;
	uint32_t minor_number;
};

struct t1_efi_test_ops {
	int (*enumerate)(void *context,
		struct t1_efi_test_candidate *candidates, size_t capacity,
		size_t *count);
	int (*make_private_namespace)(void *context);
	int (*open_root)(void *context,
		const struct t1_efi_test_candidate *candidate,
		unsigned long mount_flags, int *root_descriptor);
	int (*close_descriptor)(void *context, int descriptor);
	void *context;
};

int t1_efi_roots_discover_with_ops(int *root_descriptors,
	size_t descriptor_capacity, size_t *root_count,
	const struct t1_efi_test_ops *ops);
int t1_efi_roots_test_candidate_is_eligible(const char *device_type,
	const char *partition_type, const char *filesystem_type);
int t1_efi_roots_test_device_number_is_valid(uint32_t major_number,
	uint32_t minor_number);
int t1_efi_roots_test_mount_error_status(int error_number);
unsigned long t1_efi_roots_test_mount_flags(void);
const char *t1_efi_roots_test_mountpoint_template(void);

#endif

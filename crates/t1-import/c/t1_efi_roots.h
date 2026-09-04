#ifndef T1BRIDGE_EFI_ROOTS_H
#define T1BRIDGE_EFI_ROOTS_H

#include <stddef.h>

#define T1_EFI_ROOT_LIMIT 64U

enum t1_efi_roots_status {
	T1_EFI_ROOTS_OK = 0,
	T1_EFI_ROOTS_INVALID_ARGUMENT = 1,
	T1_EFI_ROOTS_ENUMERATION_FAILED = 2,
	T1_EFI_ROOTS_CANDIDATE_LIMIT = 3,
	T1_EFI_ROOTS_NAMESPACE_FAILED = 4,
	T1_EFI_ROOTS_INSPECTION_FAILED = 5,
	T1_EFI_ROOTS_CLEANUP_FAILED = 6,
};

/*
 * Discover currently attached FAT EFI System Partitions containing EFI/APPLE.
 * Success transfers root_count read-only directory descriptors in deterministic
 * device-number order. No path or device identifier crosses this interface.
 */
int t1_efi_roots_discover(int *root_descriptors, size_t descriptor_capacity,
	size_t *root_count);

/* Return one only when the effective user is root. */
int t1_efi_roots_is_root(void);

#endif

#ifndef T1BRIDGE_PRESERVED_EFI_H
#define T1BRIDGE_PRESERVED_EFI_H

#include <stdint.h>

enum t1_preserved_efi_status {
	T1_PRESERVED_EFI_OK = 0,
	T1_PRESERVED_EFI_INVALID_ARGUMENT = 1,
	T1_PRESERVED_EFI_INVALID_ROOT = 2,
	T1_PRESERVED_EFI_COMPONENT_UNAVAILABLE = 3,
	T1_PRESERVED_EFI_SOURCE_UNAVAILABLE = 4,
	T1_PRESERVED_EFI_INVALID_SOURCE = 5,
	T1_PRESERVED_EFI_INSPECTION_FAILED = 6,
};

/*
 * Open EFI/APPLE/EMBEDDEDOS/FDRData beneath an already-open ESP root.
 * root_descriptor remains caller-owned. On success, source_descriptor owns
 * one close-on-exec, nonblocking descriptor and source_size is positive.
 */
int t1_preserved_efi_open_fdr(int root_descriptor, int *source_descriptor,
	uint64_t *source_size);

#endif

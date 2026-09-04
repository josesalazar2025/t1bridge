#define _GNU_SOURCE

#include "t1_preserved_efi.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>

static int fstat_retry(int descriptor, struct stat *info)
{
	int result;

	do {
		result = fstat(descriptor, info);
	} while (result < 0 && errno == EINTR);
	return result;
}

static int openat_retry(int directory_descriptor, const char *name,
	int flags)
{
	int descriptor;

	do {
		descriptor = openat(directory_descriptor, name, flags);
	} while (descriptor < 0 && errno == EINTR);
	return descriptor;
}

static int close_internal(int descriptor)
{
	return descriptor < 0 ? 0 : close(descriptor);
}

int t1_preserved_efi_open_fdr(int root_descriptor, int *source_descriptor,
	uint64_t *source_size)
{
	static const char *const components[] = {
		"EFI",
		"APPLE",
		"EMBEDDEDOS",
	};
	struct stat info;
	int owned_directory = -1;
	int source = -1;
	size_t index;

	if (source_descriptor != NULL)
		*source_descriptor = -1;
	if (source_size != NULL)
		*source_size = 0;
	if (source_descriptor == NULL || source_size == NULL)
		return T1_PRESERVED_EFI_INVALID_ARGUMENT;
	if (fstat_retry(root_descriptor, &info) < 0 || !S_ISDIR(info.st_mode))
		return T1_PRESERVED_EFI_INVALID_ROOT;

	for (index = 0; index < sizeof(components) / sizeof(components[0]);
	     ++index) {
		int parent = owned_directory < 0 ? root_descriptor :
			owned_directory;
		int next = openat_retry(parent, components[index],
			O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);

		if (next < 0) {
			(void)close_internal(owned_directory);
			return T1_PRESERVED_EFI_COMPONENT_UNAVAILABLE;
		}
		if (close_internal(owned_directory) < 0) {
			(void)close_internal(next);
			return T1_PRESERVED_EFI_INSPECTION_FAILED;
		}
		owned_directory = next;
	}

	source = openat_retry(owned_directory, "FDRData",
		O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
	if (source < 0) {
		int status = errno == ELOOP ? T1_PRESERVED_EFI_INVALID_SOURCE :
			T1_PRESERVED_EFI_SOURCE_UNAVAILABLE;

		if (close_internal(owned_directory) < 0)
			return T1_PRESERVED_EFI_INSPECTION_FAILED;
		return status;
	}
	if (close_internal(owned_directory) < 0) {
		(void)close_internal(source);
		return T1_PRESERVED_EFI_INSPECTION_FAILED;
	}
	if (fstat_retry(source, &info) < 0) {
		(void)close_internal(source);
		return T1_PRESERVED_EFI_INSPECTION_FAILED;
	}
	if (!S_ISREG(info.st_mode) || info.st_size <= 0 ||
	    (uintmax_t)info.st_size > (uintmax_t)UINT64_MAX) {
		(void)close_internal(source);
		return T1_PRESERVED_EFI_INVALID_SOURCE;
	}

	*source_descriptor = source;
	*source_size = (uint64_t)info.st_size;
	return T1_PRESERVED_EFI_OK;
}

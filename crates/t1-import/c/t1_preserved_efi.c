#define _GNU_SOURCE

#include "t1_preserved_efi.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/syscall.h>
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

static int reopen_regular(int anchor, int *source_descriptor,
	uint64_t *source_size)
{
	struct stat before, after;
	char descriptor_path[64];
	int source;

	if (fstat_retry(anchor, &before) < 0)
		return T1_PRESERVED_EFI_INSPECTION_FAILED;
	if (!S_ISREG(before.st_mode) || before.st_size <= 0)
		return T1_PRESERVED_EFI_INVALID_SOURCE;
	/* Reopen the held regular inode, never the caller's replaceable path.
	 * O_PATH above ensures inspecting a device or FIFO cannot activate it. */
	int length = snprintf(descriptor_path, sizeof(descriptor_path),
		"/proc/self/fd/%d", anchor);
	if (length < 0 || (size_t)length >= sizeof(descriptor_path))
		return T1_PRESERVED_EFI_INSPECTION_FAILED;
	source = openat_retry(AT_FDCWD, descriptor_path,
		O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (source < 0 || fstat_retry(source, &after) < 0 ||
	    !S_ISREG(after.st_mode) || after.st_dev != before.st_dev ||
	    after.st_ino != before.st_ino || after.st_size != before.st_size) {
		(void)close_internal(source);
		return T1_PRESERVED_EFI_INSPECTION_FAILED;
	}
	*source_descriptor = source;
	*source_size = (uint64_t)after.st_size;
	return T1_PRESERVED_EFI_OK;
}

static int finish_open(int anchor, int status, int *source_descriptor,
	uint64_t *source_size)
{
	if (close_internal(anchor) < 0) {
		(void)close_internal(*source_descriptor);
		*source_descriptor = -1;
		*source_size = 0;
		status = T1_PRESERVED_EFI_INSPECTION_FAILED;
	}
	return status;
}

int t1_preserved_efi_open_backup(const char *path, int *source_descriptor,
	uint64_t *source_size)
{
	struct open_how how = {
		.flags = O_PATH | O_CLOEXEC,
		.resolve = RESOLVE_NO_SYMLINKS,
	};
	struct stat info;
	int anchor, status;

	if (source_descriptor != NULL)
		*source_descriptor = -1;
	if (source_size != NULL)
		*source_size = 0;
	if (path == NULL || path[0] != '/' || source_descriptor == NULL ||
	    source_size == NULL)
		return T1_PRESERVED_EFI_INVALID_ARGUMENT;
	do {
		anchor = (int)syscall(SYS_openat2, AT_FDCWD, path, &how,
			sizeof(how));
	} while (anchor < 0 && errno == EINTR);
	if (anchor < 0)
		return T1_PRESERVED_EFI_SOURCE_UNAVAILABLE;
	if (fstat_retry(anchor, &info) < 0)
		status = T1_PRESERVED_EFI_INSPECTION_FAILED;
	else if (S_ISDIR(info.st_mode))
		status = t1_preserved_efi_open_fdr(anchor, source_descriptor,
			source_size);
	else
		status = reopen_regular(anchor, source_descriptor, source_size);
	return finish_open(anchor, status, source_descriptor, source_size);
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
		O_PATH | O_NOFOLLOW | O_CLOEXEC);
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
	int status = reopen_regular(source, source_descriptor, source_size);
	return finish_open(source, status, source_descriptor, source_size);
}

#define _GNU_SOURCE

#include "t1_import_fs.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#define T1_IMPORT_DESTINATION "calibration.fscl"
#define T1_IMPORT_TEMPORARY ".calibration.fscl.tmp"
#define T1_IMPORT_FILE_MODE 0600u
#define T1_IMPORT_MODE_MASK 07777u
#define T1_IMPORT_WRITE_BITS 0022u

#if defined(T1_IMPORT_FS_TEST_EXPECTED_UID) != \
	defined(T1_IMPORT_FS_TEST_EXPECTED_GID)
#error "test owner overrides must define both UID and GID"
#endif

#ifdef T1_IMPORT_FS_TEST_EXPECTED_UID
#define T1_IMPORT_EXPECTED_UID ((uid_t)T1_IMPORT_FS_TEST_EXPECTED_UID)
#define T1_IMPORT_EXPECTED_GID ((gid_t)T1_IMPORT_FS_TEST_EXPECTED_GID)
#else
#define T1_IMPORT_EXPECTED_UID ((uid_t)0)
#define T1_IMPORT_EXPECTED_GID ((gid_t)0)
#endif

enum temporary_state {
	TEMPORARY_NONE = 0,
	TEMPORARY_CREATED,
	TEMPORARY_POISONED,
	TEMPORARY_WRITTEN,
	TEMPORARY_SYNCED,
	TEMPORARY_RENAMED,
};

_Static_assert(T1_IMPORT_FS_OK == 0, "Rust status mapping drifted");
_Static_assert(T1_IMPORT_FS_LOCK_BUSY == 6, "Rust status mapping drifted");
_Static_assert(T1_IMPORT_FS_DESTINATION_ABSENT == 0,
	"Rust destination mapping drifted");
_Static_assert(T1_IMPORT_FS_DESTINATION_VALID == 1,
	"Rust destination mapping drifted");
_Static_assert(T1_IMPORT_FS_DESTINATION_INVALID == 2,
	"Rust destination mapping drifted");
_Static_assert(T1_IMPORT_FS_ORPHAN_ABSENT == 0,
	"Rust orphan mapping drifted");
_Static_assert(T1_IMPORT_FS_ORPHAN_VALIDATED == 1,
	"Rust orphan mapping drifted");
_Static_assert(T1_IMPORT_FS_ORPHAN_UNSAFE == 2,
	"Rust orphan mapping drifted");

struct t1_import_fs {
	int directory_fd;
	int temporary_fd;
	size_t record_size;
	struct stat orphan_stat;
	bool orphan_validated;
	enum temporary_state temporary_state;
};

static bool mode_is_valid(uint32_t mode)
{
	return (mode & ~T1_IMPORT_MODE_MASK) == 0;
}

static bool component_is_valid(const char *name)
{
	return name != NULL && name[0] != '\0' && strcmp(name, ".") != 0 &&
		strcmp(name, "..") != 0 && strchr(name, '/') == NULL;
}

static bool directory_is_safe(const struct stat *info, uint32_t mode)
{
	return S_ISDIR(info->st_mode) &&
		info->st_uid == T1_IMPORT_EXPECTED_UID &&
		info->st_gid == T1_IMPORT_EXPECTED_GID &&
		((uint32_t)info->st_mode & T1_IMPORT_MODE_MASK) == mode;
}

static bool anchor_is_safe(const struct stat *info)
{
	return S_ISDIR(info->st_mode) &&
		info->st_uid == T1_IMPORT_EXPECTED_UID &&
		info->st_gid == T1_IMPORT_EXPECTED_GID &&
		((uint32_t)info->st_mode & T1_IMPORT_WRITE_BITS) == 0;
}

static bool private_file_is_safe(const struct stat *info)
{
	return S_ISREG(info->st_mode) &&
		info->st_uid == T1_IMPORT_EXPECTED_UID &&
		info->st_gid == T1_IMPORT_EXPECTED_GID &&
		((uint32_t)info->st_mode & T1_IMPORT_MODE_MASK) ==
			T1_IMPORT_FILE_MODE &&
		info->st_nlink == 1;
}

static bool same_object(const struct stat *left, const struct stat *right)
{
	return left->st_dev == right->st_dev && left->st_ino == right->st_ino;
}

static enum t1_import_fs_status validate_open_directory(int fd,
	uint32_t mode)
{
	struct stat info;

	if (fstat(fd, &info) < 0)
		return T1_IMPORT_FS_PATH_OPEN_FAILED;
	if (!directory_is_safe(&info, mode))
		return T1_IMPORT_FS_UNSAFE_DIRECTORY;
	return T1_IMPORT_FS_OK;
}

static enum t1_import_fs_status validate_anchor(int fd)
{
	struct stat info;

	if (fstat(fd, &info) < 0)
		return T1_IMPORT_FS_PATH_OPEN_FAILED;
	if (!anchor_is_safe(&info))
		return T1_IMPORT_FS_UNSAFE_DIRECTORY;
	return T1_IMPORT_FS_OK;
}

int t1_import_fs_reserve(
	struct t1_import_fs **out, int anchor_fd,
	const struct t1_import_fs_component *components,
	size_t component_count, size_t record_size, size_t record_limit)
{
	struct t1_import_fs *fs;
	enum t1_import_fs_status status;
	int current_fd;
	size_t index;

	if (out == NULL)
		return T1_IMPORT_FS_INVALID_ARGUMENT;
	*out = NULL;
	if (anchor_fd < 0 || components == NULL ||
	    component_count == 0 || record_size == 0 || record_limit == 0)
		return T1_IMPORT_FS_INVALID_ARGUMENT;
	if (record_size > record_limit)
		return T1_IMPORT_FS_SIZE_LIMIT;

	for (index = 0; index < component_count; ++index) {
		if (!component_is_valid(components[index].name) ||
		    !mode_is_valid(components[index].mode))
			return T1_IMPORT_FS_INVALID_ARGUMENT;
	}

	fs = calloc(1, sizeof(*fs));
	if (fs == NULL)
		return T1_IMPORT_FS_ALLOCATION_FAILED;
	fs->directory_fd = -1;
	fs->temporary_fd = -1;
	fs->record_size = record_size;

	current_fd = fcntl(anchor_fd, F_DUPFD_CLOEXEC, 0);
	if (current_fd < 0) {
		status = T1_IMPORT_FS_PATH_OPEN_FAILED;
		goto fail;
	}
	status = validate_anchor(current_fd);
	if (status != T1_IMPORT_FS_OK)
		goto fail_current;

	for (index = 0; index < component_count; ++index) {
		int next_fd = openat(current_fd, components[index].name,
			O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);

		if (next_fd < 0) {
			status = T1_IMPORT_FS_PATH_OPEN_FAILED;
			goto fail_current;
		}
		status = validate_open_directory(next_fd, components[index].mode);
		if (status != T1_IMPORT_FS_OK) {
			(void)close(next_fd);
			goto fail_current;
		}
		(void)close(current_fd);
		current_fd = next_fd;
	}

	if (flock(current_fd, LOCK_EX | LOCK_NB) < 0) {
		status = errno == EWOULDBLOCK || errno == EAGAIN ?
			T1_IMPORT_FS_LOCK_BUSY : T1_IMPORT_FS_LOCK_FAILED;
		goto fail_current;
	}

	fs->directory_fd = current_fd;
	*out = fs;
	return T1_IMPORT_FS_OK;

fail_current:
	(void)close(current_fd);
fail:
	free(fs);
	return status;
}

static int stat_name(int directory_fd, const char *name, struct stat *info,
	bool *present)
{
	if (fstatat(directory_fd, name, info, AT_SYMLINK_NOFOLLOW) == 0) {
		*present = true;
		return 0;
	}
	if (errno == ENOENT) {
		*present = false;
		return 0;
	}
	return -1;
}

static ssize_t read_retry(int fd, uint8_t *buffer, size_t size)
{
	ssize_t result;

	do {
		result = read(fd, buffer, size);
	} while (result < 0 && errno == EINTR);
	return result;
}

int t1_import_fs_inspect_destination(
	struct t1_import_fs *fs, const uint8_t *expected, size_t expected_size,
	uint32_t *state)
{
	uint8_t buffer[4096];
	struct stat before;
	struct stat opened;
	struct stat after;
	bool present;
	bool matches = true;
	size_t offset = 0;
	int fd;

	if (fs == NULL || expected == NULL || state == NULL ||
	    expected_size != fs->record_size)
		return T1_IMPORT_FS_INVALID_ARGUMENT;
	*state = T1_IMPORT_FS_DESTINATION_INVALID;
	if (stat_name(fs->directory_fd, T1_IMPORT_DESTINATION, &before,
		&present) < 0)
		return T1_IMPORT_FS_INSPECTION_FAILED;
	if (!present) {
		*state = T1_IMPORT_FS_DESTINATION_ABSENT;
		return T1_IMPORT_FS_OK;
	}
	if (!private_file_is_safe(&before) || before.st_size < 0 ||
	    (uintmax_t)before.st_size != (uintmax_t)expected_size)
		return T1_IMPORT_FS_OK;

	fd = openat(fs->directory_fd, T1_IMPORT_DESTINATION,
		O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
	if (fd < 0)
		return T1_IMPORT_FS_INSPECTION_FAILED;
	if (fstat(fd, &opened) < 0 || !same_object(&before, &opened) ||
	    !private_file_is_safe(&opened)) {
		(void)close(fd);
		return T1_IMPORT_FS_INSPECTION_FAILED;
	}

	while (offset < expected_size) {
		size_t remaining = expected_size - offset;
		size_t requested = remaining < sizeof(buffer) ? remaining :
			sizeof(buffer);
		ssize_t count = read_retry(fd, buffer, requested);

		if (count < 0) {
			(void)close(fd);
			return T1_IMPORT_FS_INSPECTION_FAILED;
		}
		if (count == 0) {
			matches = false;
			break;
		}
		if (memcmp(buffer, expected + offset, (size_t)count) != 0)
			matches = false;
		offset += (size_t)count;
	}
	if (matches) {
		ssize_t count = read_retry(fd, buffer, 1);

		if (count < 0) {
			(void)close(fd);
			return T1_IMPORT_FS_INSPECTION_FAILED;
		}
		if (count != 0)
			matches = false;
	}
	if (fstat(fd, &after) < 0 || !same_object(&opened, &after) ||
	    !private_file_is_safe(&after) || after.st_size < 0 ||
	    (uintmax_t)after.st_size != (uintmax_t)expected_size)
		matches = false;
	if (close(fd) < 0)
		return T1_IMPORT_FS_INSPECTION_FAILED;

	*state = matches ? T1_IMPORT_FS_DESTINATION_VALID :
		T1_IMPORT_FS_DESTINATION_INVALID;
	return T1_IMPORT_FS_OK;
}

int t1_import_fs_inspect_orphan(struct t1_import_fs *fs, uint32_t *state)
{
	struct stat info;
	bool present;

	if (fs == NULL || state == NULL)
		return T1_IMPORT_FS_INVALID_ARGUMENT;
	fs->orphan_validated = false;
	*state = T1_IMPORT_FS_ORPHAN_UNSAFE;
	if (stat_name(fs->directory_fd, T1_IMPORT_TEMPORARY, &info,
		&present) < 0)
		return T1_IMPORT_FS_INSPECTION_FAILED;
	if (!present) {
		*state = T1_IMPORT_FS_ORPHAN_ABSENT;
		return T1_IMPORT_FS_OK;
	}
	if (!private_file_is_safe(&info))
		return T1_IMPORT_FS_OK;

	fs->orphan_stat = info;
	fs->orphan_validated = true;
	*state = T1_IMPORT_FS_ORPHAN_VALIDATED;
	return T1_IMPORT_FS_OK;
}

int t1_import_fs_remove_validated_orphan(struct t1_import_fs *fs)
{
	struct stat current;
	bool present;

	if (fs == NULL)
		return T1_IMPORT_FS_INVALID_ARGUMENT;
	if (!fs->orphan_validated)
		return T1_IMPORT_FS_INVALID_STATE;
	fs->orphan_validated = false;
	if (stat_name(fs->directory_fd, T1_IMPORT_TEMPORARY, &current,
		&present) < 0)
		return T1_IMPORT_FS_INSPECTION_FAILED;
	if (!present || !same_object(&fs->orphan_stat, &current) ||
	    !private_file_is_safe(&current))
		return T1_IMPORT_FS_ORPHAN_CHANGED;
	if (unlinkat(fs->directory_fd, T1_IMPORT_TEMPORARY, 0) < 0)
		return T1_IMPORT_FS_REMOVE_FAILED;
	return T1_IMPORT_FS_OK;
}

int t1_import_fs_create_private_temporary(struct t1_import_fs *fs)
{
	struct stat created;
	struct stat info;
	int fd;

	if (fs == NULL)
		return T1_IMPORT_FS_INVALID_ARGUMENT;
	if (fs->temporary_state != TEMPORARY_NONE || fs->temporary_fd >= 0)
		return T1_IMPORT_FS_INVALID_STATE;

	fd = openat(fs->directory_fd, T1_IMPORT_TEMPORARY,
		O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
		T1_IMPORT_FILE_MODE);
	if (fd < 0)
		return errno == EEXIST ? T1_IMPORT_FS_TEMPORARY_EXISTS :
			T1_IMPORT_FS_TEMPORARY_CREATE_FAILED;
	if (fstat(fd, &created) < 0) {
		(void)close(fd);
		return T1_IMPORT_FS_TEMPORARY_CREATE_FAILED;
	}
	if (fchmod(fd, T1_IMPORT_FILE_MODE) < 0 || fstat(fd, &info) < 0 ||
	    !private_file_is_safe(&info)) {
		struct stat current;
		bool present;

		if (stat_name(fs->directory_fd, T1_IMPORT_TEMPORARY, &current,
			&present) == 0 && present && same_object(&created, &current))
			(void)unlinkat(fs->directory_fd, T1_IMPORT_TEMPORARY, 0);
		(void)close(fd);
		return T1_IMPORT_FS_TEMPORARY_CREATE_FAILED;
	}

	fs->temporary_fd = fd;
	fs->temporary_state = TEMPORARY_CREATED;
	return T1_IMPORT_FS_OK;
}

int t1_import_fs_write_temporary(
	struct t1_import_fs *fs, const uint8_t *data, size_t size)
{
	size_t offset = 0;

	if (fs == NULL || data == NULL || size != fs->record_size)
		return T1_IMPORT_FS_INVALID_ARGUMENT;
	if (fs->temporary_fd < 0 ||
	    fs->temporary_state != TEMPORARY_CREATED)
		return T1_IMPORT_FS_INVALID_STATE;
	fs->temporary_state = TEMPORARY_POISONED;

	while (offset < size) {
		size_t remaining = size - offset;
		size_t requested = remaining > (size_t)SSIZE_MAX ?
			(size_t)SSIZE_MAX : remaining;
		ssize_t count = write(fs->temporary_fd, data + offset,
			requested);

		if (count < 0 && errno == EINTR)
			continue;
		if (count <= 0)
			return T1_IMPORT_FS_WRITE_FAILED;
		offset += (size_t)count;
	}

	fs->temporary_state = TEMPORARY_WRITTEN;
	return T1_IMPORT_FS_OK;
}

int t1_import_fs_sync_temporary(struct t1_import_fs *fs)
{
	if (fs == NULL)
		return T1_IMPORT_FS_INVALID_ARGUMENT;
	if (fs->temporary_fd < 0 ||
	    fs->temporary_state != TEMPORARY_WRITTEN)
		return T1_IMPORT_FS_INVALID_STATE;
	if (fsync(fs->temporary_fd) < 0)
		return T1_IMPORT_FS_FILE_SYNC_FAILED;
	fs->temporary_state = TEMPORARY_SYNCED;
	return T1_IMPORT_FS_OK;
}

int t1_import_fs_rename_temporary(struct t1_import_fs *fs)
{
	if (fs == NULL)
		return T1_IMPORT_FS_INVALID_ARGUMENT;
	if (fs->temporary_fd < 0 ||
	    fs->temporary_state != TEMPORARY_SYNCED)
		return T1_IMPORT_FS_INVALID_STATE;
	if (renameat2(fs->directory_fd, T1_IMPORT_TEMPORARY,
		fs->directory_fd, T1_IMPORT_DESTINATION, RENAME_NOREPLACE) < 0)
		return errno == EEXIST ? T1_IMPORT_FS_RENAME_CONFLICT :
			T1_IMPORT_FS_RENAME_FAILED;
	fs->temporary_state = TEMPORARY_RENAMED;
	return T1_IMPORT_FS_OK;
}

int t1_import_fs_sync_destination_directory(struct t1_import_fs *fs)
{
	if (fs == NULL)
		return T1_IMPORT_FS_INVALID_ARGUMENT;
	if (fsync(fs->directory_fd) < 0)
		return T1_IMPORT_FS_DIRECTORY_SYNC_FAILED;
	return T1_IMPORT_FS_OK;
}

void t1_import_fs_close(struct t1_import_fs *fs)
{
	if (fs == NULL)
		return;
	if (fs->temporary_fd >= 0)
		(void)close(fs->temporary_fd);
	if (fs->directory_fd >= 0)
		(void)close(fs->directory_fd);
	free(fs);
}

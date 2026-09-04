#ifndef T1BRIDGE_IMPORT_FS_H
#define T1BRIDGE_IMPORT_FS_H

#include <stddef.h>
#include <stdint.h>

struct t1_import_fs;

struct t1_import_fs_component {
	const char *name;
	uint32_t mode;
};

enum t1_import_fs_status {
	T1_IMPORT_FS_OK = 0,
	T1_IMPORT_FS_INVALID_ARGUMENT = 1,
	T1_IMPORT_FS_SIZE_LIMIT = 2,
	T1_IMPORT_FS_ALLOCATION_FAILED = 3,
	T1_IMPORT_FS_PATH_OPEN_FAILED = 4,
	T1_IMPORT_FS_UNSAFE_DIRECTORY = 5,
	T1_IMPORT_FS_LOCK_BUSY = 6,
	T1_IMPORT_FS_LOCK_FAILED = 7,
	T1_IMPORT_FS_INSPECTION_FAILED = 8,
	T1_IMPORT_FS_ORPHAN_CHANGED = 9,
	T1_IMPORT_FS_REMOVE_FAILED = 10,
	T1_IMPORT_FS_TEMPORARY_EXISTS = 11,
	T1_IMPORT_FS_TEMPORARY_CREATE_FAILED = 12,
	T1_IMPORT_FS_WRITE_FAILED = 13,
	T1_IMPORT_FS_FILE_SYNC_FAILED = 14,
	T1_IMPORT_FS_RENAME_CONFLICT = 15,
	T1_IMPORT_FS_RENAME_FAILED = 16,
	T1_IMPORT_FS_DIRECTORY_SYNC_FAILED = 17,
	T1_IMPORT_FS_INVALID_STATE = 18,
};

enum t1_import_fs_destination_state {
	T1_IMPORT_FS_DESTINATION_ABSENT = 0,
	T1_IMPORT_FS_DESTINATION_VALID = 1,
	T1_IMPORT_FS_DESTINATION_INVALID = 2,
};

enum t1_import_fs_orphan_state {
	T1_IMPORT_FS_ORPHAN_ABSENT = 0,
	T1_IMPORT_FS_ORPHAN_VALIDATED = 1,
	T1_IMPORT_FS_ORPHAN_UNSAFE = 2,
};

/*
 * Reserve one caller-selected machine-data directory. anchor_fd is a trusted
 * open directory (normally `/`); every named component after it is opened
 * separately without following links. The anchor must be a root-owned
 * directory with no group/other write bits; components must be root-owned
 * directories with exactly their declared modes. The returned handle holds a
 * nonblocking exclusive flock until close.
 *
 * record_limit is policy supplied by the Rust caller. No file operation can
 * exceed it, and record_size must be nonzero and no greater than that limit.
 */
int t1_import_fs_reserve(
	struct t1_import_fs **out, int anchor_fd,
	const struct t1_import_fs_component *components,
	size_t component_count, size_t record_size, size_t record_limit);

int t1_import_fs_inspect_destination(
	struct t1_import_fs *fs, const uint8_t *expected, size_t expected_size,
	uint32_t *state);

int t1_import_fs_inspect_orphan(struct t1_import_fs *fs, uint32_t *state);

int t1_import_fs_remove_validated_orphan(struct t1_import_fs *fs);

int t1_import_fs_create_private_temporary(struct t1_import_fs *fs);

int t1_import_fs_write_temporary(
	struct t1_import_fs *fs, const uint8_t *data, size_t size);

int t1_import_fs_sync_temporary(struct t1_import_fs *fs);

int t1_import_fs_rename_temporary(struct t1_import_fs *fs);

int t1_import_fs_sync_destination_directory(struct t1_import_fs *fs);

void t1_import_fs_close(struct t1_import_fs *fs);

#endif

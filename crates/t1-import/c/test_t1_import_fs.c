#define _GNU_SOURCE

#include "t1_import_fs.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define TEST_PATH_CAPACITY 1024u

static const uint8_t record[] = "SYNTHETIC-CALIBRATION-RECORD";
static unsigned int failures;

#define EXPECT_TRUE(expression)                                                \
	do {                                                                    \
		if (!(expression)) {                                              \
			fprintf(stderr, "%s:%d: expectation failed: %s\n",       \
				__FILE__, __LINE__, #expression);                    \
			++failures;                                                 \
		}                                                               \
	} while (0)

#define EXPECT_STATUS(expected, expression)                                   \
	do {                                                                    \
		int actual_status = (expression);                                  \
		if (actual_status != (expected)) {                                \
			fprintf(stderr,                                             \
				"%s:%d: expected status %d, received %d\n",       \
				__FILE__, __LINE__, (int)(expected),                \
				(int)actual_status);                                    \
			++failures;                                                 \
		}                                                               \
	} while (0)

struct fixture {
	char root[TEST_PATH_CAPACITY];
	char first[TEST_PATH_CAPACITY];
	char second[TEST_PATH_CAPACITY];
	char data[TEST_PATH_CAPACITY];
	int anchor_fd;
	int data_fd;
	struct t1_import_fs_component components[3];
};

static bool make_path(char *output, size_t capacity, const char *parent,
	const char *name)
{
	int length = snprintf(output, capacity, "%s/%s", parent, name);

	return length >= 0 && (size_t)length < capacity;
}

static int open_directory(const char *path)
{
	return open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
}

static bool fixture_init(struct fixture *fixture)
{
	char template[] = "/tmp/t1-import-fs.XXXXXX";

	memset(fixture, 0, sizeof(*fixture));
	fixture->anchor_fd = -1;
	fixture->data_fd = -1;
	if (mkdtemp(template) == NULL ||
	    strlen(template) >= sizeof(fixture->root))
		return false;
	memcpy(fixture->root, template, strlen(template) + 1);
	if (chmod(fixture->root, 0700) < 0 ||
	    !make_path(fixture->first, sizeof(fixture->first), fixture->root,
		"var") ||
	    !make_path(fixture->second, sizeof(fixture->second),
		fixture->first, "lib") ||
	    !make_path(fixture->data, sizeof(fixture->data), fixture->second,
		"t1bridge") ||
	    mkdir(fixture->first, 0755) < 0 ||
	    mkdir(fixture->second, 0755) < 0 ||
	    mkdir(fixture->data, 0700) < 0 ||
	    chmod(fixture->first, 0755) < 0 ||
	    chmod(fixture->second, 0755) < 0 ||
	    chmod(fixture->data, 0700) < 0)
		return false;
	fixture->anchor_fd = open_directory(fixture->root);
	fixture->data_fd = open_directory(fixture->data);
	if (fixture->anchor_fd < 0 || fixture->data_fd < 0)
		return false;

	fixture->components[0] = (struct t1_import_fs_component){"var", 0755};
	fixture->components[1] = (struct t1_import_fs_component){"lib", 0755};
	fixture->components[2] = (struct t1_import_fs_component){"t1bridge", 0700};
	return true;
}

static void fixture_destroy(struct fixture *fixture)
{
	if (fixture->data_fd >= 0) {
		(void)unlinkat(fixture->data_fd, "calibration.fscl", 0);
		(void)unlinkat(fixture->data_fd, ".calibration.fscl.tmp", 0);
		(void)unlinkat(fixture->data_fd, "unrelated", 0);
		(void)close(fixture->data_fd);
	}
	if (fixture->anchor_fd >= 0)
		(void)close(fixture->anchor_fd);
	(void)rmdir(fixture->data);
	(void)rmdir(fixture->second);
	(void)rmdir(fixture->first);
	(void)rmdir(fixture->root);
}

static int reserve_fixture(struct fixture *fixture, struct t1_import_fs **fs)
{
	return t1_import_fs_reserve(fs, fixture->anchor_fd,
		fixture->components, 3, sizeof(record), sizeof(record));
}

static bool write_complete(int fd, const uint8_t *data, size_t size)
{
	size_t offset = 0;

	while (offset < size) {
		ssize_t count = write(fd, data + offset, size - offset);

		if (count < 0 && errno == EINTR)
			continue;
		if (count <= 0)
			return false;
		offset += (size_t)count;
	}
	return true;
}

static int create_file_at(int directory_fd, const char *name, uint32_t mode,
	const uint8_t *data, size_t size)
{
	int fd = openat(directory_fd, name,
		O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, mode);

	if (fd < 0)
		return -1;
	if (fchmod(fd, mode) < 0 || !write_complete(fd, data, size)) {
		(void)close(fd);
		return -1;
	}
	return fd;
}

static bool find_alternate_group(gid_t *alternate)
{
	gid_t groups[64];
	int count;
	int index;

	if (geteuid() == 0) {
		*alternate = getegid() == 1 ? 2 : 1;
		return true;
	}
	count = getgroups((int)(sizeof(groups) / sizeof(groups[0])), groups);
	if (count < 0)
		return false;
	for (index = 0; index < count; ++index) {
		if (groups[index] != getegid()) {
			*alternate = groups[index];
			return true;
		}
	}
	return false;
}

static void test_reservation_path_and_lock_contract(void)
{
	struct fixture fixture;
	struct t1_import_fs *first = NULL;
	struct t1_import_fs *second = NULL;
	struct t1_import_fs_component invalid[1] = {{"../escape", 0700}};
	gid_t alternate_group;

	EXPECT_TRUE(fixture_init(&fixture));
	EXPECT_STATUS(T1_IMPORT_FS_SIZE_LIMIT,
		t1_import_fs_reserve(&first, fixture.anchor_fd,
			fixture.components, 3, sizeof(record), sizeof(record) - 1));
	EXPECT_TRUE(first == NULL);
	EXPECT_STATUS(T1_IMPORT_FS_INVALID_ARGUMENT,
		t1_import_fs_reserve(&first, fixture.anchor_fd, invalid, 1,
			sizeof(record), sizeof(record)));
	EXPECT_STATUS(T1_IMPORT_FS_OK, reserve_fixture(&fixture, &first));
	EXPECT_STATUS(T1_IMPORT_FS_LOCK_BUSY,
		reserve_fixture(&fixture, &second));
	EXPECT_TRUE(second == NULL);
	t1_import_fs_close(first);
	first = NULL;
	EXPECT_STATUS(T1_IMPORT_FS_OK, reserve_fixture(&fixture, &second));
	t1_import_fs_close(second);

	EXPECT_TRUE(chmod(fixture.root, 0770) == 0);
	EXPECT_STATUS(T1_IMPORT_FS_UNSAFE_DIRECTORY,
		reserve_fixture(&fixture, &first));
	EXPECT_TRUE(chmod(fixture.root, 0700) == 0);

	EXPECT_TRUE(chmod(fixture.data, 0750) == 0);
	EXPECT_STATUS(T1_IMPORT_FS_UNSAFE_DIRECTORY,
		reserve_fixture(&fixture, &first));
	EXPECT_TRUE(chmod(fixture.data, 0700) == 0);

	if (find_alternate_group(&alternate_group)) {
		EXPECT_TRUE(chown(fixture.data, (uid_t)-1, alternate_group) == 0);
		EXPECT_STATUS(T1_IMPORT_FS_UNSAFE_DIRECTORY,
			reserve_fixture(&fixture, &first));
		EXPECT_TRUE(chown(fixture.data, (uid_t)-1, getegid()) == 0);
	} else {
		fprintf(stderr, "SKIP: no alternate group for wrong-GID check\n");
	}

	fixture_destroy(&fixture);
}

static void test_component_symlink_is_never_followed(void)
{
	struct fixture fixture;
	struct t1_import_fs *fs = NULL;
	struct t1_import_fs_component components[3] = {
		{"redirect", 0755}, {"lib", 0755}, {"t1bridge", 0700},
	};

	EXPECT_TRUE(fixture_init(&fixture));
	EXPECT_TRUE(symlinkat("var", fixture.anchor_fd, "redirect") == 0);
	EXPECT_STATUS(T1_IMPORT_FS_PATH_OPEN_FAILED,
		t1_import_fs_reserve(&fs, fixture.anchor_fd, components, 3,
			sizeof(record), sizeof(record)));
	EXPECT_TRUE(fs == NULL);
	EXPECT_TRUE(unlinkat(fixture.anchor_fd, "redirect", 0) == 0);
	fixture_destroy(&fixture);
}

static void test_destination_inspection_does_not_follow_links(void)
{
	static const uint8_t outside_data[] = "SYNTHETIC-OUTSIDE";
	struct fixture fixture;
	struct t1_import_fs *fs = NULL;
	uint32_t state;
	char outside[TEST_PATH_CAPACITY];
	uint8_t readback[sizeof(outside_data)] = {0};
	int outside_fd;

	EXPECT_TRUE(fixture_init(&fixture));
	EXPECT_STATUS(T1_IMPORT_FS_OK, reserve_fixture(&fixture, &fs));
	EXPECT_STATUS(T1_IMPORT_FS_OK,
		t1_import_fs_inspect_destination(fs, record, sizeof(record),
			&state));
	EXPECT_TRUE(state == T1_IMPORT_FS_DESTINATION_ABSENT);

	EXPECT_TRUE(make_path(outside, sizeof(outside), fixture.root, "outside"));
	outside_fd = create_file_at(fixture.anchor_fd, "outside", 0600,
		outside_data, sizeof(outside_data));
	EXPECT_TRUE(outside_fd >= 0);
	EXPECT_TRUE(close(outside_fd) == 0);
	EXPECT_TRUE(symlinkat(outside, fixture.data_fd, "calibration.fscl") == 0);
	EXPECT_STATUS(T1_IMPORT_FS_OK,
		t1_import_fs_inspect_destination(fs, record, sizeof(record),
			&state));
	EXPECT_TRUE(state == T1_IMPORT_FS_DESTINATION_INVALID);
	EXPECT_TRUE(unlinkat(fixture.data_fd, "calibration.fscl", 0) == 0);

	outside_fd = open(outside, O_RDONLY | O_CLOEXEC);
	EXPECT_TRUE(outside_fd >= 0);
	EXPECT_TRUE(read(outside_fd, readback, sizeof(readback)) ==
		(ssize_t)sizeof(readback));
	EXPECT_TRUE(memcmp(readback, outside_data, sizeof(readback)) == 0);
	EXPECT_TRUE(close(outside_fd) == 0);
	EXPECT_TRUE(unlink(outside) == 0);

	outside_fd = create_file_at(fixture.data_fd, "calibration.fscl", 0640,
		record, sizeof(record));
	EXPECT_TRUE(outside_fd >= 0);
	EXPECT_TRUE(close(outside_fd) == 0);
	EXPECT_STATUS(T1_IMPORT_FS_OK,
		t1_import_fs_inspect_destination(fs, record, sizeof(record),
			&state));
	EXPECT_TRUE(state == T1_IMPORT_FS_DESTINATION_INVALID);
	EXPECT_TRUE(faccessat(fixture.data_fd, "calibration.fscl", F_OK,
		AT_SYMLINK_NOFOLLOW) == 0);
	EXPECT_TRUE(unlinkat(fixture.data_fd, "calibration.fscl", 0) == 0);

	outside_fd = create_file_at(fixture.data_fd, "unrelated", 0600,
		record, sizeof(record));
	EXPECT_TRUE(outside_fd >= 0);
	EXPECT_TRUE(close(outside_fd) == 0);
	EXPECT_TRUE(linkat(fixture.data_fd, "unrelated", fixture.data_fd,
		"calibration.fscl", 0) == 0);
	EXPECT_STATUS(T1_IMPORT_FS_OK,
		t1_import_fs_inspect_destination(fs, record, sizeof(record),
			&state));
	EXPECT_TRUE(state == T1_IMPORT_FS_DESTINATION_INVALID);
	EXPECT_TRUE(faccessat(fixture.data_fd, "calibration.fscl", F_OK,
		AT_SYMLINK_NOFOLLOW) == 0);
	EXPECT_TRUE(faccessat(fixture.data_fd, "unrelated", F_OK,
		AT_SYMLINK_NOFOLLOW) == 0);
	EXPECT_TRUE(unlinkat(fixture.data_fd, "calibration.fscl", 0) == 0);
	EXPECT_TRUE(unlinkat(fixture.data_fd, "unrelated", 0) == 0);
	t1_import_fs_close(fs);
	fixture_destroy(&fixture);
}

static void test_orphan_validation_and_change_detection(void)
{
	static const uint8_t partial[] = "SYNTHETIC-PARTIAL";
	struct fixture fixture;
	struct t1_import_fs *fs = NULL;
	uint32_t state;
	gid_t alternate_group;
	int old_fd;
	int replacement_fd;

	EXPECT_TRUE(fixture_init(&fixture));
	EXPECT_STATUS(T1_IMPORT_FS_OK, reserve_fixture(&fixture, &fs));
	EXPECT_STATUS(T1_IMPORT_FS_OK, t1_import_fs_inspect_orphan(fs, &state));
	EXPECT_TRUE(state == T1_IMPORT_FS_ORPHAN_ABSENT);

	EXPECT_TRUE(symlinkat("unrelated", fixture.data_fd,
		".calibration.fscl.tmp") == 0);
	EXPECT_STATUS(T1_IMPORT_FS_OK, t1_import_fs_inspect_orphan(fs, &state));
	EXPECT_TRUE(state == T1_IMPORT_FS_ORPHAN_UNSAFE);
	EXPECT_STATUS(T1_IMPORT_FS_INVALID_STATE,
		t1_import_fs_remove_validated_orphan(fs));
	EXPECT_STATUS(T1_IMPORT_FS_TEMPORARY_EXISTS,
		t1_import_fs_create_private_temporary(fs));
	EXPECT_TRUE(unlinkat(fixture.data_fd, ".calibration.fscl.tmp", 0) == 0);

	old_fd = create_file_at(fixture.data_fd, ".calibration.fscl.tmp", 0640,
		partial, sizeof(partial));
	EXPECT_TRUE(old_fd >= 0);
	EXPECT_TRUE(close(old_fd) == 0);
	EXPECT_STATUS(T1_IMPORT_FS_OK, t1_import_fs_inspect_orphan(fs, &state));
	EXPECT_TRUE(state == T1_IMPORT_FS_ORPHAN_UNSAFE);
	EXPECT_TRUE(faccessat(fixture.data_fd, ".calibration.fscl.tmp", F_OK,
		AT_SYMLINK_NOFOLLOW) == 0);
	EXPECT_TRUE(unlinkat(fixture.data_fd, ".calibration.fscl.tmp", 0) == 0);

	old_fd = create_file_at(fixture.data_fd, "unrelated", 0600, partial,
		sizeof(partial));
	EXPECT_TRUE(old_fd >= 0);
	EXPECT_TRUE(close(old_fd) == 0);
	EXPECT_TRUE(linkat(fixture.data_fd, "unrelated", fixture.data_fd,
		".calibration.fscl.tmp", 0) == 0);
	EXPECT_STATUS(T1_IMPORT_FS_OK, t1_import_fs_inspect_orphan(fs, &state));
	EXPECT_TRUE(state == T1_IMPORT_FS_ORPHAN_UNSAFE);
	EXPECT_TRUE(faccessat(fixture.data_fd, ".calibration.fscl.tmp", F_OK,
		AT_SYMLINK_NOFOLLOW) == 0);
	EXPECT_TRUE(faccessat(fixture.data_fd, "unrelated", F_OK,
		AT_SYMLINK_NOFOLLOW) == 0);
	EXPECT_TRUE(unlinkat(fixture.data_fd, ".calibration.fscl.tmp", 0) == 0);
	EXPECT_TRUE(unlinkat(fixture.data_fd, "unrelated", 0) == 0);

	old_fd = create_file_at(fixture.data_fd, ".calibration.fscl.tmp", 0600,
		partial, sizeof(partial));
	EXPECT_TRUE(old_fd >= 0);
	if (find_alternate_group(&alternate_group)) {
		EXPECT_TRUE(fchown(old_fd, (uid_t)-1, alternate_group) == 0);
		EXPECT_STATUS(T1_IMPORT_FS_OK,
			t1_import_fs_inspect_orphan(fs, &state));
		EXPECT_TRUE(state == T1_IMPORT_FS_ORPHAN_UNSAFE);
		EXPECT_TRUE(fchown(old_fd, (uid_t)-1, getegid()) == 0);
	}
	EXPECT_STATUS(T1_IMPORT_FS_OK, t1_import_fs_inspect_orphan(fs, &state));
	EXPECT_TRUE(state == T1_IMPORT_FS_ORPHAN_VALIDATED);
	EXPECT_TRUE(unlinkat(fixture.data_fd, ".calibration.fscl.tmp", 0) == 0);
	replacement_fd = create_file_at(fixture.data_fd,
		".calibration.fscl.tmp", 0600, partial, sizeof(partial));
	EXPECT_TRUE(replacement_fd >= 0);
	EXPECT_STATUS(T1_IMPORT_FS_ORPHAN_CHANGED,
		t1_import_fs_remove_validated_orphan(fs));
	EXPECT_TRUE(close(old_fd) == 0);
	EXPECT_TRUE(close(replacement_fd) == 0);

	EXPECT_STATUS(T1_IMPORT_FS_OK, t1_import_fs_inspect_orphan(fs, &state));
	EXPECT_TRUE(state == T1_IMPORT_FS_ORPHAN_VALIDATED);
	EXPECT_STATUS(T1_IMPORT_FS_OK,
		t1_import_fs_remove_validated_orphan(fs));
	EXPECT_TRUE(faccessat(fixture.data_fd, ".calibration.fscl.tmp", F_OK,
		AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT);
	t1_import_fs_close(fs);
	fixture_destroy(&fixture);
}

static void test_complete_durable_commit(void)
{
	static const uint8_t unrelated[] = "SYNTHETIC-UNRELATED";
	struct fixture fixture;
	struct t1_import_fs *fs = NULL;
	uint32_t state;
	struct stat info;
	uint8_t changed[sizeof(record)];
	int unrelated_fd;

	EXPECT_TRUE(fixture_init(&fixture));
	unrelated_fd = create_file_at(fixture.data_fd, "unrelated", 0600,
		unrelated, sizeof(unrelated));
	EXPECT_TRUE(unrelated_fd >= 0);
	EXPECT_TRUE(close(unrelated_fd) == 0);
	EXPECT_STATUS(T1_IMPORT_FS_OK, reserve_fixture(&fixture, &fs));
	EXPECT_STATUS(T1_IMPORT_FS_OK,
		t1_import_fs_create_private_temporary(fs));
	EXPECT_TRUE(fstatat(fixture.data_fd, ".calibration.fscl.tmp", &info,
		AT_SYMLINK_NOFOLLOW) == 0);
	EXPECT_TRUE(S_ISREG(info.st_mode));
	EXPECT_TRUE((info.st_mode & 07777) == 0600);
	EXPECT_TRUE(info.st_uid == geteuid());
	EXPECT_TRUE(info.st_gid == getegid());
	EXPECT_STATUS(T1_IMPORT_FS_INVALID_ARGUMENT,
		t1_import_fs_write_temporary(fs, record, sizeof(record) - 1));
	EXPECT_STATUS(T1_IMPORT_FS_OK,
		t1_import_fs_write_temporary(fs, record, sizeof(record)));
	EXPECT_STATUS(T1_IMPORT_FS_INVALID_STATE,
		t1_import_fs_write_temporary(fs, record, sizeof(record)));
	EXPECT_STATUS(T1_IMPORT_FS_OK, t1_import_fs_sync_temporary(fs));
	EXPECT_STATUS(T1_IMPORT_FS_OK, t1_import_fs_rename_temporary(fs));
	EXPECT_STATUS(T1_IMPORT_FS_OK,
		t1_import_fs_sync_destination_directory(fs));
	EXPECT_TRUE(faccessat(fixture.data_fd, ".calibration.fscl.tmp", F_OK,
		AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT);
	EXPECT_TRUE(faccessat(fixture.data_fd, "unrelated", F_OK, 0) == 0);
	EXPECT_STATUS(T1_IMPORT_FS_OK,
		t1_import_fs_inspect_destination(fs, record, sizeof(record),
			&state));
	EXPECT_TRUE(state == T1_IMPORT_FS_DESTINATION_VALID);
	memcpy(changed, record, sizeof(record));
	changed[0] ^= 0x20u;
	EXPECT_STATUS(T1_IMPORT_FS_OK,
		t1_import_fs_inspect_destination(fs, changed, sizeof(changed),
			&state));
	EXPECT_TRUE(state == T1_IMPORT_FS_DESTINATION_INVALID);
	t1_import_fs_close(fs);
	fixture_destroy(&fixture);
}

static void test_atomic_rename_never_replaces_destination(void)
{
	static const uint8_t existing[sizeof(record)] =
		"SYNTHETIC-EXISTING-RECORD";
	struct fixture fixture;
	struct t1_import_fs *fs = NULL;
	uint8_t readback[sizeof(existing)] = {0};
	int destination_fd;

	EXPECT_TRUE(fixture_init(&fixture));
	EXPECT_STATUS(T1_IMPORT_FS_OK, reserve_fixture(&fixture, &fs));
	EXPECT_STATUS(T1_IMPORT_FS_OK,
		t1_import_fs_create_private_temporary(fs));
	EXPECT_STATUS(T1_IMPORT_FS_OK,
		t1_import_fs_write_temporary(fs, record, sizeof(record)));
	EXPECT_STATUS(T1_IMPORT_FS_OK, t1_import_fs_sync_temporary(fs));
	destination_fd = create_file_at(fixture.data_fd, "calibration.fscl",
		0600, existing, sizeof(existing));
	EXPECT_TRUE(destination_fd >= 0);
	EXPECT_TRUE(close(destination_fd) == 0);
	EXPECT_STATUS(T1_IMPORT_FS_RENAME_CONFLICT,
		t1_import_fs_rename_temporary(fs));
	EXPECT_TRUE(faccessat(fixture.data_fd, ".calibration.fscl.tmp", F_OK,
		AT_SYMLINK_NOFOLLOW) == 0);
	destination_fd = openat(fixture.data_fd, "calibration.fscl",
		O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	EXPECT_TRUE(destination_fd >= 0);
	EXPECT_TRUE(read(destination_fd, readback, sizeof(readback)) ==
		(ssize_t)sizeof(readback));
	EXPECT_TRUE(memcmp(readback, existing, sizeof(existing)) == 0);
	EXPECT_TRUE(close(destination_fd) == 0);
	t1_import_fs_close(fs);
	fixture_destroy(&fixture);
}

int main(void)
{
	test_reservation_path_and_lock_contract();
	test_component_symlink_is_never_followed();
	test_destination_inspection_does_not_follow_links();
	test_orphan_validation_and_change_detection();
	test_complete_durable_commit();
	test_atomic_rename_never_replaces_destination();

	if (failures != 0) {
		fprintf(stderr, "%u filesystem boundary test(s) failed\n",
			failures);
		return 1;
	}
	puts("filesystem boundary tests passed");
	return 0;
}

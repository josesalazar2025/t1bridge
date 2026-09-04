#define _GNU_SOURCE

#include "t1_preserved_efi.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define TEST_PATH_CAPACITY 1024u

static const uint8_t record[] = "SYNTHETIC-PRESERVED-FDR-DATA";
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
	char components[3][TEST_PATH_CAPACITY];
	char source[TEST_PATH_CAPACITY];
	int root_descriptor;
};

struct stable_metadata {
	dev_t device;
	ino_t inode;
	mode_t mode;
	nlink_t links;
	uid_t user;
	gid_t group;
	off_t size;
	struct timespec modified;
	struct timespec changed;
};

static bool make_path(char *output, size_t capacity, const char *parent,
	const char *name)
{
	int length = snprintf(output, capacity, "%s/%s", parent, name);

	return length >= 0 && (size_t)length < capacity;
}

static bool fixture_init(struct fixture *fixture)
{
	char template[] = "/tmp/t1-preserved-efi.XXXXXX";

	memset(fixture, 0, sizeof(*fixture));
	fixture->root_descriptor = -1;
	if (mkdtemp(template) == NULL ||
	    strlen(template) >= sizeof(fixture->root))
		return false;
	memcpy(fixture->root, template, strlen(template) + 1);
	if (!make_path(fixture->components[0],
			sizeof(fixture->components[0]), fixture->root, "EFI") ||
	    !make_path(fixture->components[1],
			sizeof(fixture->components[1]), fixture->components[0],
		"APPLE") ||
	    !make_path(fixture->components[2],
			sizeof(fixture->components[2]), fixture->components[1],
		"EMBEDDEDOS") ||
	    !make_path(fixture->source, sizeof(fixture->source),
		fixture->components[2], "FDRData"))
		return false;
	fixture->root_descriptor = open(fixture->root,
		O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	return fixture->root_descriptor >= 0;
}

static void fixture_destroy(struct fixture *fixture)
{
	(void)unlink(fixture->source);
	(void)rmdir(fixture->source);
	(void)unlink(fixture->components[2]);
	(void)rmdir(fixture->components[2]);
	(void)unlink(fixture->components[1]);
	(void)rmdir(fixture->components[1]);
	(void)unlink(fixture->components[0]);
	(void)rmdir(fixture->components[0]);
	if (fixture->root_descriptor >= 0)
		(void)close(fixture->root_descriptor);
	(void)rmdir(fixture->root);
}

static bool create_parents(struct fixture *fixture, size_t count)
{
	size_t index;

	for (index = 0; index < count; ++index) {
		if (mkdir(fixture->components[index], 0700) < 0)
			return false;
	}
	return true;
}

static bool write_complete(int descriptor, const uint8_t *data, size_t size)
{
	size_t offset = 0;

	while (offset < size) {
		ssize_t count = write(descriptor, data + offset, size - offset);

		if (count < 0 && errno == EINTR)
			continue;
		if (count <= 0)
			return false;
		offset += (size_t)count;
	}
	return true;
}

static bool create_source(struct fixture *fixture, const uint8_t *data,
	size_t size)
{
	int descriptor = open(fixture->source,
		O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
	bool success;

	if (descriptor < 0)
		return false;
	success = write_complete(descriptor, data, size);
	return close(descriptor) == 0 && success;
}

static int open_descriptor_count(void)
{
	DIR *directory = opendir("/proc/self/fd");
	struct dirent *entry;
	int count = 0;

	if (directory == NULL)
		return -1;
	while ((entry = readdir(directory)) != NULL) {
		if (strcmp(entry->d_name, ".") != 0 &&
		    strcmp(entry->d_name, "..") != 0)
			++count;
	}
	if (closedir(directory) < 0)
		return -1;
	return count;
}

static bool capture_metadata(const char *path, struct stable_metadata *result)
{
	struct stat info;

	if (lstat(path, &info) < 0)
		return false;
	*result = (struct stable_metadata){
		.device = info.st_dev,
		.inode = info.st_ino,
		.mode = info.st_mode,
		.links = info.st_nlink,
		.user = info.st_uid,
		.group = info.st_gid,
		.size = info.st_size,
		.modified = info.st_mtim,
		.changed = info.st_ctim,
	};
	return true;
}

static bool metadata_equal(const struct stable_metadata *left,
	const struct stable_metadata *right)
{
	return left->device == right->device && left->inode == right->inode &&
		left->mode == right->mode && left->links == right->links &&
		left->user == right->user && left->group == right->group &&
		left->size == right->size &&
		left->modified.tv_sec == right->modified.tv_sec &&
		left->modified.tv_nsec == right->modified.tv_nsec &&
		left->changed.tv_sec == right->changed.tv_sec &&
		left->changed.tv_nsec == right->changed.tv_nsec;
}

static void expect_failed_open(struct fixture *fixture, int expected_status)
{
	uint64_t size = UINT64_MAX;
	int descriptor = 42;
	int before = open_descriptor_count();

	EXPECT_TRUE(before >= 0);
	EXPECT_STATUS(expected_status, t1_preserved_efi_open_fdr(
		fixture->root_descriptor, &descriptor, &size));
	EXPECT_TRUE(descriptor == -1);
	EXPECT_TRUE(size == 0);
	EXPECT_TRUE(fcntl(fixture->root_descriptor, F_GETFD) >= 0);
	EXPECT_TRUE(open_descriptor_count() == before);
	if (descriptor >= 0)
		(void)close(descriptor);
}

static void test_success_preserves_tree_and_transfers_source(void)
{
	struct fixture fixture;
	struct stable_metadata before[5];
	struct stable_metadata after[5];
	const char *paths[5];
	uint8_t readback[sizeof(record)] = {0};
	uint64_t source_size = 0;
	int source_descriptor = -1;
	int descriptor_count;
	size_t index;
	ssize_t count;

	EXPECT_TRUE(fixture_init(&fixture));
	EXPECT_TRUE(create_parents(&fixture, 3));
	EXPECT_TRUE(create_source(&fixture, record, sizeof(record)));
	paths[0] = fixture.root;
	paths[1] = fixture.components[0];
	paths[2] = fixture.components[1];
	paths[3] = fixture.components[2];
	paths[4] = fixture.source;
	for (index = 0; index < 5; ++index)
		EXPECT_TRUE(capture_metadata(paths[index], &before[index]));
	descriptor_count = open_descriptor_count();
	EXPECT_TRUE(descriptor_count >= 0);

	EXPECT_STATUS(T1_PRESERVED_EFI_OK, t1_preserved_efi_open_fdr(
		fixture.root_descriptor, &source_descriptor, &source_size));
	EXPECT_TRUE(source_descriptor >= 0);
	EXPECT_TRUE(source_size == sizeof(record));
	EXPECT_TRUE((fcntl(source_descriptor, F_GETFD) & FD_CLOEXEC) != 0);
	EXPECT_TRUE((fcntl(source_descriptor, F_GETFL) & O_NONBLOCK) != 0);
	EXPECT_TRUE(fcntl(fixture.root_descriptor, F_GETFD) >= 0);
	EXPECT_TRUE(open_descriptor_count() == descriptor_count + 1);
	for (index = 0; index < 5; ++index) {
		EXPECT_TRUE(capture_metadata(paths[index], &after[index]));
		EXPECT_TRUE(metadata_equal(&before[index], &after[index]));
	}

	count = read(source_descriptor, readback, sizeof(readback));
	EXPECT_TRUE(count == (ssize_t)sizeof(readback));
	EXPECT_TRUE(memcmp(readback, record, sizeof(record)) == 0);
	EXPECT_TRUE(read(source_descriptor, readback, 1) == 0);
	EXPECT_TRUE(close(source_descriptor) == 0);
	EXPECT_TRUE(open_descriptor_count() == descriptor_count);
	fixture_destroy(&fixture);
}

static void test_root_descriptor_survives_path_detachment(void)
{
	struct fixture fixture;
	char detached[TEST_PATH_CAPACITY];
	uint64_t source_size = 0;
	int source_descriptor = -1;
	int length;

	EXPECT_TRUE(fixture_init(&fixture));
	EXPECT_TRUE(create_parents(&fixture, 3));
	EXPECT_TRUE(create_source(&fixture, record, sizeof(record)));
	length = snprintf(detached, sizeof(detached), "%s.detached",
		fixture.root);
	EXPECT_TRUE(length >= 0 && (size_t)length < sizeof(detached));
	EXPECT_TRUE(rename(fixture.root, detached) == 0);
	EXPECT_TRUE(access(fixture.root, F_OK) < 0 && errno == ENOENT);

	EXPECT_STATUS(T1_PRESERVED_EFI_OK, t1_preserved_efi_open_fdr(
		fixture.root_descriptor, &source_descriptor, &source_size));
	EXPECT_TRUE(source_descriptor >= 0);
	EXPECT_TRUE(source_size == sizeof(record));
	if (source_descriptor >= 0)
		EXPECT_TRUE(close(source_descriptor) == 0);

	EXPECT_TRUE(rename(detached, fixture.root) == 0);
	fixture_destroy(&fixture);
}

static void test_invalid_arguments_and_roots(void)
{
	struct fixture fixture;
	uint64_t source_size = UINT64_MAX;
	int source_descriptor = 42;
	int closed_descriptor;
	int regular_descriptor;

	EXPECT_TRUE(fixture_init(&fixture));
	EXPECT_STATUS(T1_PRESERVED_EFI_INVALID_ARGUMENT,
		t1_preserved_efi_open_fdr(fixture.root_descriptor, NULL,
			&source_size));
	EXPECT_TRUE(source_size == 0);
	EXPECT_STATUS(T1_PRESERVED_EFI_INVALID_ARGUMENT,
		t1_preserved_efi_open_fdr(fixture.root_descriptor,
			&source_descriptor, NULL));
	EXPECT_TRUE(source_descriptor == -1);

	source_descriptor = 42;
	source_size = UINT64_MAX;
	EXPECT_STATUS(T1_PRESERVED_EFI_INVALID_ROOT,
		t1_preserved_efi_open_fdr(-1, &source_descriptor, &source_size));
	EXPECT_TRUE(source_descriptor == -1 && source_size == 0);
	closed_descriptor = dup(fixture.root_descriptor);
	EXPECT_TRUE(closed_descriptor >= 0);
	EXPECT_TRUE(close(closed_descriptor) == 0);
	EXPECT_STATUS(T1_PRESERVED_EFI_INVALID_ROOT,
		t1_preserved_efi_open_fdr(closed_descriptor, &source_descriptor,
			&source_size));

	regular_descriptor = openat(fixture.root_descriptor, "regular",
		O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
	EXPECT_TRUE(regular_descriptor >= 0);
	EXPECT_STATUS(T1_PRESERVED_EFI_INVALID_ROOT,
		t1_preserved_efi_open_fdr(regular_descriptor, &source_descriptor,
			&source_size));
	EXPECT_TRUE(fcntl(regular_descriptor, F_GETFD) >= 0);
	EXPECT_TRUE(close(regular_descriptor) == 0);
	EXPECT_TRUE(unlinkat(fixture.root_descriptor, "regular", 0) == 0);
	fixture_destroy(&fixture);
}

enum component_kind {
	COMPONENT_MISSING,
	COMPONENT_SYMLINK,
	COMPONENT_FILE,
};

static void test_component_case(size_t level, enum component_kind kind)
{
	struct fixture fixture;
	int descriptor;

	EXPECT_TRUE(fixture_init(&fixture));
	EXPECT_TRUE(create_parents(&fixture, level));
	if (kind == COMPONENT_SYMLINK)
		EXPECT_TRUE(symlink("synthetic-target",
			fixture.components[level]) == 0);
	if (kind == COMPONENT_FILE) {
		descriptor = open(fixture.components[level],
			O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
			0600);
		EXPECT_TRUE(descriptor >= 0);
		if (descriptor >= 0)
			EXPECT_TRUE(close(descriptor) == 0);
	}
	expect_failed_open(&fixture, T1_PRESERVED_EFI_COMPONENT_UNAVAILABLE);
	fixture_destroy(&fixture);
}

static void test_every_component_rejects_missing_links_and_files(void)
{
	size_t level;

	for (level = 0; level < 3; ++level) {
		test_component_case(level, COMPONENT_MISSING);
		test_component_case(level, COMPONENT_SYMLINK);
		test_component_case(level, COMPONENT_FILE);
	}
}

enum source_kind {
	SOURCE_MISSING,
	SOURCE_SYMLINK,
	SOURCE_DIRECTORY,
	SOURCE_FIFO,
	SOURCE_EMPTY,
};

static void test_source_case(enum source_kind kind, int expected_status)
{
	struct fixture fixture;
	int descriptor;

	EXPECT_TRUE(fixture_init(&fixture));
	EXPECT_TRUE(create_parents(&fixture, 3));
	if (kind == SOURCE_SYMLINK)
		EXPECT_TRUE(symlink("synthetic-target", fixture.source) == 0);
	if (kind == SOURCE_DIRECTORY)
		EXPECT_TRUE(mkdir(fixture.source, 0700) == 0);
	if (kind == SOURCE_FIFO)
		EXPECT_TRUE(mkfifo(fixture.source, 0600) == 0);
	if (kind == SOURCE_EMPTY) {
		descriptor = open(fixture.source,
			O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
			0600);
		EXPECT_TRUE(descriptor >= 0);
		if (descriptor >= 0)
			EXPECT_TRUE(close(descriptor) == 0);
	}
	expect_failed_open(&fixture, expected_status);
	fixture_destroy(&fixture);
}

static void test_source_shape_and_availability(void)
{
	test_source_case(SOURCE_MISSING,
		T1_PRESERVED_EFI_SOURCE_UNAVAILABLE);
	test_source_case(SOURCE_SYMLINK, T1_PRESERVED_EFI_INVALID_SOURCE);
	test_source_case(SOURCE_DIRECTORY, T1_PRESERVED_EFI_INVALID_SOURCE);
	test_source_case(SOURCE_FIFO, T1_PRESERVED_EFI_INVALID_SOURCE);
	test_source_case(SOURCE_EMPTY, T1_PRESERVED_EFI_INVALID_SOURCE);
}

static void test_repeated_failure_does_not_leak_descriptors(void)
{
	struct fixture fixture;
	uint64_t source_size;
	int source_descriptor;
	int before;
	unsigned int iteration;

	EXPECT_TRUE(fixture_init(&fixture));
	EXPECT_TRUE(create_parents(&fixture, 3));
	before = open_descriptor_count();
	EXPECT_TRUE(before >= 0);
	for (iteration = 0; iteration < 64; ++iteration) {
		EXPECT_STATUS(T1_PRESERVED_EFI_SOURCE_UNAVAILABLE,
			t1_preserved_efi_open_fdr(fixture.root_descriptor,
				&source_descriptor, &source_size));
		EXPECT_TRUE(source_descriptor == -1 && source_size == 0);
	}
	EXPECT_TRUE(open_descriptor_count() == before);
	fixture_destroy(&fixture);
}

int main(void)
{
	test_success_preserves_tree_and_transfers_source();
	test_root_descriptor_survives_path_detachment();
	test_invalid_arguments_and_roots();
	test_every_component_rejects_missing_links_and_files();
	test_source_shape_and_availability();
	test_repeated_failure_does_not_leak_descriptors();

	if (failures != 0) {
		fprintf(stderr, "%u preserved EFI test(s) failed\n", failures);
		return 1;
	}
	puts("preserved EFI tests passed");
	return 0;
}

#define _GNU_SOURCE

#include "t1_efi_roots.h"
#include "t1_efi_roots_test.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

struct fixture {
	struct t1_efi_test_candidate candidates[T1_EFI_ROOT_LIMIT + 1U];
	size_t candidate_count;
	int enumerate_status;
	int namespace_status;
	int open_results[T1_EFI_ROOT_LIMIT];
	int open_descriptors[T1_EFI_ROOT_LIMIT];
	size_t open_count;
	struct t1_efi_test_candidate opened[T1_EFI_ROOT_LIMIT];
	unsigned long observed_flags[T1_EFI_ROOT_LIMIT];
	int closed[T1_EFI_ROOT_LIMIT];
	size_t close_count;
	int close_failure;
	int namespace_calls;
};

static int enumerate(void *context,
	struct t1_efi_test_candidate *candidates, size_t capacity,
	size_t *count)
{
	struct fixture *fixture = context;

	if (fixture->enumerate_status != T1_EFI_ROOTS_OK)
		return fixture->enumerate_status;
	if (fixture->candidate_count > capacity)
		return T1_EFI_ROOTS_CANDIDATE_LIMIT;
	memcpy(candidates, fixture->candidates,
		fixture->candidate_count * sizeof(candidates[0]));
	*count = fixture->candidate_count;
	return T1_EFI_ROOTS_OK;
}

static int make_private_namespace(void *context)
{
	struct fixture *fixture = context;

	++fixture->namespace_calls;
	return fixture->namespace_status;
}

static int open_root(void *context,
	const struct t1_efi_test_candidate *candidate,
	unsigned long mount_flags, int *root_descriptor)
{
	struct fixture *fixture = context;
	size_t index = fixture->open_count++;

	assert(index < T1_EFI_ROOT_LIMIT);
	fixture->opened[index] = *candidate;
	fixture->observed_flags[index] = mount_flags;
	*root_descriptor = fixture->open_descriptors[index];
	return fixture->open_results[index];
}

static int close_descriptor(void *context, int descriptor)
{
	struct fixture *fixture = context;

	assert(fixture->close_count < T1_EFI_ROOT_LIMIT);
	fixture->closed[fixture->close_count++] = descriptor;
	if (fixture->close_failure) {
		errno = EIO;
		return -1;
	}
	return 0;
}

static struct t1_efi_test_ops operations(struct fixture *fixture)
{
	const struct t1_efi_test_ops ops = {
		.enumerate = enumerate,
		.make_private_namespace = make_private_namespace,
		.open_root = open_root,
		.close_descriptor = close_descriptor,
		.context = fixture,
	};

	return ops;
}

static struct fixture base_fixture(void)
{
	struct fixture fixture = {
		.enumerate_status = T1_EFI_ROOTS_OK,
		.namespace_status = T1_EFI_ROOTS_OK,
	};
	size_t index;

	for (index = 0; index < T1_EFI_ROOT_LIMIT; ++index) {
		fixture.open_results[index] = 0;
		fixture.open_descriptors[index] = 100 + (int)index;
	}
	return fixture;
}

static void test_candidate_filter(void)
{
	const char *guid = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b";
	const char *upper_guid = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";

	assert(t1_efi_roots_test_candidate_is_eligible("partition", guid,
		"vfat") == 1);
	assert(t1_efi_roots_test_candidate_is_eligible("partition", upper_guid,
		"FAT32") == 1);
	assert(t1_efi_roots_test_candidate_is_eligible("partition", guid,
		NULL) == 1);
	assert(t1_efi_roots_test_candidate_is_eligible("disk", guid,
		"vfat") == 0);
	assert(t1_efi_roots_test_candidate_is_eligible("partition",
		"00000000-0000-0000-0000-000000000000", "vfat") == 0);
	assert(t1_efi_roots_test_candidate_is_eligible("partition", guid,
		"ext4") == 0);
	assert(t1_efi_roots_test_device_number_is_valid(1, 0) == 1);
	assert(t1_efi_roots_test_device_number_is_valid(0, 1) == 0);
	assert(t1_efi_roots_test_mount_error_status(ENOENT) == 1);
	assert(t1_efi_roots_test_mount_error_status(ENODEV) ==
		T1_EFI_ROOTS_INSPECTION_FAILED);
	assert(t1_efi_roots_test_mount_error_status(EIO) ==
		T1_EFI_ROOTS_INSPECTION_FAILED);
	assert(t1_efi_roots_test_mount_error_status(EINVAL) ==
		T1_EFI_ROOTS_INSPECTION_FAILED);
}

static void test_order_deduplication_and_flags(void)
{
	struct fixture fixture = base_fixture();
	struct t1_efi_test_ops ops = operations(&fixture);
	int roots[T1_EFI_ROOT_LIMIT];
	size_t count = 99;
	unsigned long expected_flags = MS_RDONLY | MS_NOSUID | MS_NODEV |
		MS_NOEXEC | MS_NOSYMFOLLOW;

	fixture.candidate_count = 4;
	fixture.candidates[0] = (struct t1_efi_test_candidate){8, 4};
	fixture.candidates[1] = (struct t1_efi_test_candidate){7, 9};
	fixture.candidates[2] = (struct t1_efi_test_candidate){8, 4};
	fixture.candidates[3] = (struct t1_efi_test_candidate){1, 2};

	assert(t1_efi_roots_discover_with_ops(roots, T1_EFI_ROOT_LIMIT,
		&count, &ops) == T1_EFI_ROOTS_OK);
	assert(count == 3);
	assert(fixture.namespace_calls == 1);
	assert(fixture.open_count == 3);
	assert(fixture.opened[0].major_number == 1 &&
		fixture.opened[0].minor_number == 2);
	assert(fixture.opened[1].major_number == 7 &&
		fixture.opened[1].minor_number == 9);
	assert(fixture.opened[2].major_number == 8 &&
		fixture.opened[2].minor_number == 4);
	assert(roots[0] == 100 && roots[1] == 101 && roots[2] == 102);
	assert(fixture.observed_flags[0] == expected_flags);
	assert(fixture.observed_flags[1] == expected_flags);
	assert(fixture.observed_flags[2] == expected_flags);
	assert(t1_efi_roots_test_mount_flags() == expected_flags);
	assert(fixture.close_count == 0);
}

static void test_skips_non_sources_without_reordering_results(void)
{
	struct fixture fixture = base_fixture();
	struct t1_efi_test_ops ops = operations(&fixture);
	int roots[T1_EFI_ROOT_LIMIT];
	size_t count;

	fixture.candidate_count = 3;
	fixture.candidates[0] = (struct t1_efi_test_candidate){3, 1};
	fixture.candidates[1] = (struct t1_efi_test_candidate){1, 1};
	fixture.candidates[2] = (struct t1_efi_test_candidate){2, 1};
	fixture.open_results[0] = 1;
	fixture.open_descriptors[0] = -1;

	assert(t1_efi_roots_discover_with_ops(roots, T1_EFI_ROOT_LIMIT,
		&count, &ops) == T1_EFI_ROOTS_OK);
	assert(count == 2);
	assert(fixture.open_count == 3);
	assert(fixture.opened[0].major_number == 1);
	assert(fixture.opened[1].major_number == 2);
	assert(fixture.opened[2].major_number == 3);
	assert(roots[0] == 101 && roots[1] == 102);
}

static void test_failure_closes_every_transferred_root(void)
{
	struct fixture fixture = base_fixture();
	struct t1_efi_test_ops ops = operations(&fixture);
	int roots[T1_EFI_ROOT_LIMIT];
	size_t count = 99;

	fixture.candidate_count = 3;
	fixture.candidates[0] = (struct t1_efi_test_candidate){1, 1};
	fixture.candidates[1] = (struct t1_efi_test_candidate){2, 1};
	fixture.candidates[2] = (struct t1_efi_test_candidate){3, 1};
	fixture.open_results[2] = T1_EFI_ROOTS_INSPECTION_FAILED;
	fixture.open_descriptors[2] = -1;

	assert(t1_efi_roots_discover_with_ops(roots, T1_EFI_ROOT_LIMIT,
		&count, &ops) == T1_EFI_ROOTS_INSPECTION_FAILED);
	assert(count == 0);
	assert(fixture.close_count == 2);
	assert(fixture.closed[0] == 101);
	assert(fixture.closed[1] == 100);
	assert(roots[0] == -1 && roots[1] == -1);
}

static void test_failure_closes_a_descriptor_returned_with_the_error(void)
{
	struct fixture fixture = base_fixture();
	struct t1_efi_test_ops ops = operations(&fixture);
	int roots[T1_EFI_ROOT_LIMIT];
	size_t count;

	fixture.candidate_count = 2;
	fixture.candidates[0] = (struct t1_efi_test_candidate){1, 1};
	fixture.candidates[1] = (struct t1_efi_test_candidate){2, 1};
	fixture.open_results[1] = T1_EFI_ROOTS_INSPECTION_FAILED;

	assert(t1_efi_roots_discover_with_ops(roots, T1_EFI_ROOT_LIMIT,
		&count, &ops) == T1_EFI_ROOTS_INSPECTION_FAILED);
	assert(count == 0);
	assert(fixture.close_count == 2);
	assert(fixture.closed[0] == 101);
	assert(fixture.closed[1] == 100);
}

static void test_cleanup_failure_has_precedence(void)
{
	struct fixture fixture = base_fixture();
	struct t1_efi_test_ops ops = operations(&fixture);
	int roots[T1_EFI_ROOT_LIMIT];
	size_t count;

	fixture.candidate_count = 2;
	fixture.candidates[0] = (struct t1_efi_test_candidate){1, 1};
	fixture.candidates[1] = (struct t1_efi_test_candidate){2, 1};
	fixture.open_results[1] = T1_EFI_ROOTS_INSPECTION_FAILED;
	fixture.open_descriptors[1] = -1;
	fixture.close_failure = 1;

	assert(t1_efi_roots_discover_with_ops(roots, T1_EFI_ROOT_LIMIT,
		&count, &ops) == T1_EFI_ROOTS_CLEANUP_FAILED);
	assert(count == 0);
	assert(fixture.close_count == 1);
}

static void test_bounds_and_empty_inventory(void)
{
	struct fixture fixture = base_fixture();
	struct t1_efi_test_ops ops = operations(&fixture);
	int roots[T1_EFI_ROOT_LIMIT];
	size_t count = 99;
	size_t index;

	assert(t1_efi_roots_discover_with_ops(NULL, T1_EFI_ROOT_LIMIT,
		&count, &ops) == T1_EFI_ROOTS_INVALID_ARGUMENT);
	assert(t1_efi_roots_discover_with_ops(roots, 0, &count, &ops) ==
		T1_EFI_ROOTS_INVALID_ARGUMENT);
	assert(t1_efi_roots_discover_with_ops(roots, T1_EFI_ROOT_LIMIT + 1U,
		&count, &ops) == T1_EFI_ROOTS_INVALID_ARGUMENT);

	fixture.candidate_count = 0;
	assert(t1_efi_roots_discover_with_ops(roots, T1_EFI_ROOT_LIMIT,
		&count, &ops) == T1_EFI_ROOTS_OK);
	assert(count == 0 && fixture.namespace_calls == 0);
	for (index = 0; index < T1_EFI_ROOT_LIMIT; ++index)
		assert(roots[index] == -1);

	fixture.candidate_count = T1_EFI_ROOT_LIMIT + 1U;
	assert(t1_efi_roots_discover_with_ops(roots, T1_EFI_ROOT_LIMIT,
		&count, &ops) == T1_EFI_ROOTS_CANDIDATE_LIMIT);
	assert(fixture.namespace_calls == 0 && fixture.open_count == 0);
}

static void test_namespace_failure_prevents_source_access(void)
{
	struct fixture fixture = base_fixture();
	struct t1_efi_test_ops ops = operations(&fixture);
	int roots[T1_EFI_ROOT_LIMIT];
	size_t count;

	fixture.candidate_count = 1;
	fixture.candidates[0] = (struct t1_efi_test_candidate){1, 1};
	fixture.namespace_status = T1_EFI_ROOTS_NAMESPACE_FAILED;
	assert(t1_efi_roots_discover_with_ops(roots, T1_EFI_ROOT_LIMIT,
		&count, &ops) == T1_EFI_ROOTS_NAMESPACE_FAILED);
	assert(fixture.namespace_calls == 1 && fixture.open_count == 0);
}

static void test_private_mountpoint_creation_and_cleanup(void)
{
	char *path = strdup(t1_efi_roots_test_mountpoint_template());
	struct stat info;
	mode_t previous;

	assert(path != NULL);
	previous = umask(0077);
	assert(mkdtemp(path) != NULL);
	umask(previous);
	assert(lstat(path, &info) == 0);
	assert(S_ISDIR(info.st_mode));
	assert((info.st_mode & 0777) == 0700);
	assert(info.st_uid == geteuid());
	assert(rmdir(path) == 0);
	assert(lstat(path, &info) == -1 && errno == ENOENT);
	free(path);
}

static void test_existing_mount_selection(void)
{
	const struct t1_efi_test_candidate candidate = {7, 9};
	unsigned long long mount_id = 0;
	char path[PATH_MAX];

	assert(t1_efi_roots_test_parse_mount(
		"42 1 7:9 / /test\\040esp rw - vfat /dev/synthetic rw\n",
		&candidate, &mount_id, path) == 1);
	assert(mount_id == 42 && strcmp(path, "/test esp") == 0);
	assert(t1_efi_roots_test_parse_mount(
		"42 1 7:9 / /test\\134a\\011b\\012c rw - vfat synthetic rw\n",
		&candidate, &mount_id, path) == 1);
	assert(strcmp(path, "/test\\a\tb\nc") == 0);
	assert(t1_efi_roots_test_parse_mount(
		"42 1 7:9 /EFI /test rw - vfat synthetic rw\n",
		&candidate, &mount_id, path) == 0);
	assert(t1_efi_roots_test_parse_mount(
		"42 1 7:8 / /test rw - vfat synthetic rw\n",
		&candidate, &mount_id, path) == 0);
	assert(t1_efi_roots_test_parse_mount(
		"42 1 7:9 / /test rw - ext4 synthetic rw\n",
		&candidate, &mount_id, path) == 0);
	assert(t1_efi_roots_test_parse_mount(
		"42 1 7:9 / /test\\000 rw - vfat synthetic rw\n",
		&candidate, &mount_id, path) == -1);
	assert(t1_efi_roots_test_parse_mount(
		"bad - vfat synthetic rw\n", &candidate, &mount_id, path) == -1);
}

static void test_mount_path_rejects_symlinks_and_parent_traversal(void)
{
	char root[] = "/tmp/t1-efi-path.XXXXXX";
	char child[PATH_MAX], link[PATH_MAX], nested[PATH_MAX], file[PATH_MAX];
	char leaf[PATH_MAX];
	struct stat expected, actual;
	int descriptor;

	assert(mkdtemp(root) != NULL);
	assert(snprintf(child, sizeof(child), "%s/child", root) > 0);
	assert(snprintf(link, sizeof(link), "%s/link", root) > 0);
	assert(snprintf(file, sizeof(file), "%s/file", root) > 0);
	assert(mkdir(child, 0700) == 0);
	assert(snprintf(leaf, sizeof(leaf), "%s/child/leaf", root) > 0);
	assert(mkdir(leaf, 0700) == 0);
	assert(symlink(child, link) == 0);
	descriptor = open(file, O_CREAT | O_EXCL | O_WRONLY, 0600);
	assert(descriptor >= 0 && close(descriptor) == 0);
	descriptor = t1_efi_roots_test_open_mount_path(child);
	assert(descriptor >= 0);
	assert(fstat(descriptor, &actual) == 0 && stat(child, &expected) == 0);
	assert(actual.st_dev == expected.st_dev && actual.st_ino == expected.st_ino);
	assert((fcntl(descriptor, F_GETFD) & FD_CLOEXEC) != 0);
	assert(close(descriptor) == 0);
	assert(t1_efi_roots_test_open_mount_path(link) < 0);
	assert(snprintf(nested, sizeof(nested), "%s/link/leaf", root) > 0);
	assert(t1_efi_roots_test_open_mount_path(nested) < 0);
	assert(snprintf(nested, sizeof(nested), "%s/child/..", root) > 0);
	assert(t1_efi_roots_test_open_mount_path(nested) < 0);
	assert(t1_efi_roots_test_open_mount_path(file) < 0);
	assert(t1_efi_roots_test_open_mount_path("relative") < 0);
	assert(t1_efi_roots_test_open_mount_path(NULL) < 0);
	descriptor = t1_efi_roots_test_open_mount_path("/");
	assert(descriptor >= 0 && close(descriptor) == 0);
	assert(unlink(file) == 0 && unlink(link) == 0);
	assert(rmdir(leaf) == 0 && rmdir(child) == 0 && rmdir(root) == 0);
}

int main(void)
{
	test_mount_path_rejects_symlinks_and_parent_traversal();
	test_existing_mount_selection();
	test_private_mountpoint_creation_and_cleanup();
	test_candidate_filter();
	test_order_deduplication_and_flags();
	test_skips_non_sources_without_reordering_results();
	test_failure_closes_every_transferred_root();
	test_failure_closes_a_descriptor_returned_with_the_error();
	test_cleanup_failure_has_precedence();
	test_bounds_and_empty_inventory();
	test_namespace_failure_prevents_source_access();
	return 0;
}

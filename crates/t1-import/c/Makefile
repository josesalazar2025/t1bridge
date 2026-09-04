.PHONY: all test sanitize sanitize-clean clean

CC ?= cc
CPPFLAGS ?=
CFLAGS ?= -O2 -std=c17 -Wall -Wextra -Wpedantic -Werror
LDLIBS ?= -llzma

BUILD_DIR ?= .
XZ_TEST_BINARY := $(BUILD_DIR)/test_t1_xz
FS_TEST_BINARY := $(BUILD_DIR)/test_t1_import_fs
PRESERVED_EFI_TEST_BINARY := $(BUILD_DIR)/test_t1_preserved_efi
EFI_ROOTS_TEST_BINARY := $(BUILD_DIR)/test_t1_efi_roots
SANITIZER_DIR := .sanitizer
SANITIZER_BINARIES := $(SANITIZER_DIR)/test_t1_xz \
	$(SANITIZER_DIR)/test_t1_import_fs \
	$(SANITIZER_DIR)/test_t1_preserved_efi \
	$(SANITIZER_DIR)/test_t1_efi_roots
SANITIZER_CFLAGS := -O1 -g -std=c17 -Wall -Wextra -Wpedantic -Werror \
	-fno-omit-frame-pointer -fno-sanitize-recover=all \
	-fsanitize=address,undefined
FS_TEST_CPPFLAGS := -DT1_IMPORT_FS_TEST_EXPECTED_UID=$(shell id -u) \
	-DT1_IMPORT_FS_TEST_EXPECTED_GID=$(shell id -g)

all: $(XZ_TEST_BINARY) $(FS_TEST_BINARY) $(PRESERVED_EFI_TEST_BINARY) \
	$(EFI_ROOTS_TEST_BINARY)

$(XZ_TEST_BINARY): t1_xz.c t1_xz.h test_t1_xz.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) t1_xz.c test_t1_xz.c $(LDLIBS) -o $@

$(FS_TEST_BINARY): t1_import_fs.c t1_import_fs.h test_t1_import_fs.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(FS_TEST_CPPFLAGS) $(CFLAGS) \
		t1_import_fs.c test_t1_import_fs.c -o $@

$(PRESERVED_EFI_TEST_BINARY): t1_preserved_efi.c t1_preserved_efi.h \
		test_t1_preserved_efi.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) t1_preserved_efi.c \
		test_t1_preserved_efi.c -o $@

$(EFI_ROOTS_TEST_BINARY): t1_efi_roots.c t1_efi_roots.h \
		t1_efi_roots_test.h test_t1_efi_roots.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) t1_efi_roots.c \
		test_t1_efi_roots.c -ludev -o $@

test: all
	./$(XZ_TEST_BINARY)
	./$(FS_TEST_BINARY)
	./$(PRESERVED_EFI_TEST_BINARY)
	./$(EFI_ROOTS_TEST_BINARY)

sanitize: sanitize-clean
	$(MAKE) CC=gcc BUILD_DIR=$(SANITIZER_DIR) CFLAGS='$(SANITIZER_CFLAGS)' \
		ASAN_OPTIONS='detect_leaks=1:halt_on_error=1' \
		UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1' test

sanitize-clean:
	rm -f $(SANITIZER_BINARIES)
	rmdir $(SANITIZER_DIR) 2>/dev/null || true

$(BUILD_DIR):
	mkdir -p $@

clean:
	rm -f $(XZ_TEST_BINARY) $(FS_TEST_BINARY) \
		$(PRESERVED_EFI_TEST_BINARY) $(EFI_ROOTS_TEST_BINARY) \
		$(SANITIZER_BINARIES)
	rmdir $(SANITIZER_DIR) 2>/dev/null || true

.PHONY: all test sanitize sanitize-clean clean

CC ?= cc
CPPFLAGS ?=
CFLAGS ?= -O2 -std=c17 -Wall -Wextra -Wpedantic -Werror

BUILD_DIR ?= .
TESTS := test_sep_crypto test_sep_relay test_sep_usbfs test_sep_urb \
	test_sep_acm test_sep_keystore test_sep_session test_sep_operation \
	test_sep_keybag_store
TEST_BINARIES := $(addprefix $(BUILD_DIR)/,$(TESTS))
SANITIZER_DIR := .sanitizer
SANITIZER_BINARIES := $(addprefix $(SANITIZER_DIR)/,$(TESTS))
SANITIZER_CFLAGS := -O1 -g -std=c17 -Wall -Wextra -Wpedantic -Werror \
	-fno-omit-frame-pointer -fno-sanitize-recover=all \
	-fsanitize=address,undefined

all: $(TEST_BINARIES)

$(BUILD_DIR)/test_sep_crypto: sep_crypto.c sep_crypto.h test_sep_crypto.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) sep_crypto.c test_sep_crypto.c -o $@

$(BUILD_DIR)/test_sep_relay: sep_relay.c sep_relay.h test_sep_relay.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) sep_relay.c test_sep_relay.c -o $@

$(BUILD_DIR)/test_sep_usbfs: sep_usbfs.c sep_usbfs.h test_sep_usbfs.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) sep_usbfs.c test_sep_usbfs.c -o $@

$(BUILD_DIR)/test_sep_urb: sep_urb.c sep_urb.h sep_usbfs.h test_sep_urb.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) sep_urb.c test_sep_urb.c -o $@

$(BUILD_DIR)/test_sep_acm: sep_acm.c sep_acm.h sep_relay.c sep_relay.h sep_crypto.c \
	sep_crypto.h test_sep_acm.c
	$(CC) $(CPPFLAGS) $(CFLAGS) sep_acm.c sep_relay.c sep_crypto.c \
		test_sep_acm.c -o $@

$(BUILD_DIR)/test_sep_keystore: sep_keystore.c sep_keystore.h sep_relay.c sep_relay.h \
	sep_crypto.c sep_crypto.h test_sep_keystore.c
	$(CC) $(CPPFLAGS) $(CFLAGS) sep_keystore.c sep_relay.c sep_crypto.c \
		test_sep_keystore.c -o $@

$(BUILD_DIR)/test_sep_session: sep_session.c sep_session.h sep_urb.c sep_urb.h \
	sep_usbfs.h sep_acm.c sep_acm.h sep_keystore.c sep_keystore.h sep_relay.c \
	sep_relay.h sep_crypto.c sep_crypto.h test_sep_session.c
	$(CC) $(CPPFLAGS) $(CFLAGS) sep_session.c sep_urb.c sep_acm.c \
		sep_keystore.c sep_relay.c sep_crypto.c test_sep_session.c -o $@

$(BUILD_DIR)/test_sep_operation: sep_operation.c sep_operation.h sep_session.c \
	sep_session.h sep_urb.c sep_urb.h sep_usbfs.c sep_usbfs.h sep_acm.c \
	sep_acm.h sep_keystore.c sep_keystore.h sep_relay.c sep_relay.h \
	sep_crypto.c sep_crypto.h sep_keybag.c sep_keybag_store.c sep_keybag.h \
	test_sep_operation.c
	$(CC) $(CPPFLAGS) $(CFLAGS) sep_operation.c sep_session.c sep_urb.c \
		sep_usbfs.c sep_acm.c sep_keystore.c sep_relay.c sep_crypto.c \
		sep_keybag.c sep_keybag_store.c test_sep_operation.c -o $@

$(BUILD_DIR)/test_sep_keybag_store: sep_keybag_store.c sep_keybag.h \
	sep_crypto.c sep_crypto.h test_sep_keybag_store.c
	$(CC) $(CPPFLAGS) $(CFLAGS) sep_keybag_store.c sep_crypto.c \
		test_sep_keybag_store.c -o $@

test: all
	@set -e; for test_binary in $(TEST_BINARIES); do ./$$test_binary; done

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
	rm -f $(TEST_BINARIES) $(SANITIZER_BINARIES)
	rmdir $(SANITIZER_DIR) 2>/dev/null || true

.PHONY: all test sanitize sanitize-clean clean

CC ?= cc
CPPFLAGS ?=
CFLAGS ?= -O2 -std=c17 -Wall -Wextra -Wpedantic -Werror
LDFLAGS ?=
TEST_WRAP_FLAGS := -Wl,--wrap=socket -Wl,--wrap=connect \
	-Wl,--wrap=getsockopt

BUILD_DIR ?= .
TEST_BINARIES := $(BUILD_DIR)/test_t1_seqpacket \
	$(BUILD_DIR)/test_t1_xart_listener \
	$(BUILD_DIR)/test_t1_ncm_ready \
	$(BUILD_DIR)/test_t1_nss_account \
	$(BUILD_DIR)/test_t1_service_lifecycle
SANITIZER_DIR := .sanitizer
SANITIZER_BINARIES := $(SANITIZER_DIR)/test_t1_seqpacket \
	$(SANITIZER_DIR)/test_t1_xart_listener \
	$(SANITIZER_DIR)/test_t1_ncm_ready \
	$(SANITIZER_DIR)/test_t1_nss_account \
	$(SANITIZER_DIR)/test_t1_service_lifecycle
SANITIZER_CFLAGS := -O1 -g -std=c17 -Wall -Wextra -Wpedantic -Werror \
	-fno-omit-frame-pointer -fno-sanitize-recover=all \
	-fsanitize=address,undefined

all: $(TEST_BINARIES)

$(BUILD_DIR)/test_t1_seqpacket: t1_seqpacket.c t1_seqpacket.h \
	test_t1_seqpacket.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) t1_seqpacket.c test_t1_seqpacket.c \
		$(LDFLAGS) $(TEST_WRAP_FLAGS) -o $@

$(BUILD_DIR)/test_t1_xart_listener: t1_xart_listener.c \
	t1_xart_listener.h test_t1_xart_listener.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) t1_xart_listener.c \
		test_t1_xart_listener.c $(LDFLAGS) -o $@

$(BUILD_DIR)/test_t1_ncm_ready: t1_ncm_ready.c t1_ncm_ready.h \
		t1_xart_listener.c t1_xart_listener.h test_t1_ncm_ready.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) t1_ncm_ready.c t1_xart_listener.c \
		test_t1_ncm_ready.c $(LDFLAGS) -o $@

$(BUILD_DIR)/test_t1_nss_account: t1_nss_account.c t1_nss_account.h \
		test_t1_nss_account.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) -DT1_NSS_ACCOUNT_TEST $(CFLAGS) \
		t1_nss_account.c test_t1_nss_account.c $(LDFLAGS) \
		-Wl,--wrap=getpwnam_r -o $@

$(BUILD_DIR)/test_t1_service_lifecycle: t1_service_lifecycle.c \
		t1_service_lifecycle.h test_t1_service_lifecycle.c | $(BUILD_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) t1_service_lifecycle.c \
		test_t1_service_lifecycle.c $(LDFLAGS) -lsystemd -o $@

$(BUILD_DIR):
	mkdir -p $@

test: all
	./$(BUILD_DIR)/test_t1_seqpacket
	./$(BUILD_DIR)/test_t1_xart_listener
	./$(BUILD_DIR)/test_t1_ncm_ready
	./$(BUILD_DIR)/test_t1_nss_account
	./$(BUILD_DIR)/test_t1_service_lifecycle

sanitize: sanitize-clean
	$(MAKE) CC=gcc BUILD_DIR=$(SANITIZER_DIR) CFLAGS='$(SANITIZER_CFLAGS)' \
		ASAN_OPTIONS='detect_leaks=1:halt_on_error=1' \
		UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1' test

sanitize-clean:
	rm -f $(SANITIZER_BINARIES)
	rmdir $(SANITIZER_DIR) 2>/dev/null || true

clean:
	rm -f $(TEST_BINARIES) $(SANITIZER_BINARIES)
	rmdir $(SANITIZER_DIR) 2>/dev/null || true

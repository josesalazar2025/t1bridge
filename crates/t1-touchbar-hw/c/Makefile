CC ?= cc
CFLAGS ?= -O2 -std=c17 -Wall -Wextra -Wpedantic -Werror
SANITIZER_CFLAGS = -O1 -g -std=c17 -Wall -Wextra -Wpedantic -Werror \
	-fno-omit-frame-pointer -fno-sanitize-recover=all \
	-fsanitize=address,undefined
SOURCES = t1_touchbar_io.c t1_touchbar_digitizer.c t1_touchbar_fn.c \
	t1_touchbar_uinput.c test_t1_touchbar_io.c
SEQPACKET_DIR = ../../t1-daemons/c
BUILD_DIR ?= .
TESTS = test_t1_touchbar_io test_t1_touchid_cancel
TEST_BINARIES = $(addprefix $(BUILD_DIR)/,$(TESTS))
SANITIZER_DIR = .sanitizer
SANITIZER_BINARIES = $(addprefix $(SANITIZER_DIR)/,$(TESTS))

.PHONY: all test sanitize sanitize-clean clean

all: $(TEST_BINARIES)

$(BUILD_DIR)/test_t1_touchbar_io: $(SOURCES) t1_touchbar_io.h t1_touchbar_digitizer.h \
	t1_touchbar_fn.h t1_touchbar_uinput.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DT1_TOUCHBAR_TESTING \
		$(SOURCES) -o $@

$(BUILD_DIR)/test_t1_touchid_cancel: t1_touchid_cancel.c t1_touchid_cancel.h \
	test_t1_touchid_cancel.c $(SEQPACKET_DIR)/t1_seqpacket.c \
	$(SEQPACKET_DIR)/t1_seqpacket.h | $(BUILD_DIR)
	$(CC) $(CFLAGS) -DT1_TOUCHID_CANCEL_TESTING \
		t1_touchid_cancel.c test_t1_touchid_cancel.c \
		$(SEQPACKET_DIR)/t1_seqpacket.c -o $@

test: $(TEST_BINARIES)
	./$(BUILD_DIR)/test_t1_touchbar_io
	./$(BUILD_DIR)/test_t1_touchid_cancel

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

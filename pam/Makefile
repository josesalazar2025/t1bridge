CC ?= cc
CFLAGS ?= -O2 -g
CPPFLAGS += -D_GNU_SOURCE $(shell pkg-config --cflags pam)
CFLAGS += -std=c17 -Wall -Wextra -Werror
LDFLAGS += -Wl,-z,relro,-z,now
LDLIBS += $(shell pkg-config --libs pam)

.PHONY: all clean sanitize test

all: pam_t1_touchid.so

pam_t1_touchid.so: pam_t1_touchid.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -shared $< $(LDFLAGS) $(LDLIBS) -o $@

test_pam_t1_touchid: test_pam_t1_touchid.c pam_t1_touchid.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $< $(LDFLAGS) $(LDLIBS) -o $@

test: test_pam_t1_touchid
	./test_pam_t1_touchid

sanitize: clean
	$(MAKE) CC=gcc \
		CFLAGS='-O1 -g -std=c17 -Wall -Wextra -Werror -fno-omit-frame-pointer -fno-sanitize-recover=all -fsanitize=address,undefined' \
		LDFLAGS='-Wl,-z,relro,-z,now -fsanitize=address,undefined' \
		ASAN_OPTIONS='detect_leaks=1:halt_on_error=1' \
		UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1' test

clean:
	$(RM) pam_t1_touchid.so test_pam_t1_touchid

.PHONY: quality format lint test dependency-policy platform-c \
	platform-c-sanitize touchbar-hw-c touchbar-hw-c-sanitize sep-probe \
	sep-probe-sanitize pam kernel packaging uvc-upstream uvc-parser \
	uvc-parser-sanitize

KDIR ?= /lib/modules/$(shell uname -r)/build

quality: format lint test dependency-policy platform-c platform-c-sanitize \
	touchbar-hw-c touchbar-hw-c-sanitize sep-probe sep-probe-sanitize \
	pam uvc-parser uvc-parser-sanitize kernel packaging

format:
	cargo fmt --all --check

lint:
	cargo clippy --workspace --all-targets --all-features -- -D warnings

test:
	cargo test --workspace --all-targets

dependency-policy:
	cargo deny --all-features check

platform-c:
	$(MAKE) -C crates/t1-platform/c test
	$(MAKE) -C crates/t1-daemons/c test
	$(MAKE) -C crates/t1-import/c test

platform-c-sanitize:
	$(MAKE) -C crates/t1-platform/c sanitize
	$(MAKE) -C crates/t1-daemons/c sanitize
	$(MAKE) -C crates/t1-import/c sanitize

touchbar-hw-c:
	$(MAKE) -C crates/t1-touchbar-hw/c test

touchbar-hw-c-sanitize:
	$(MAKE) -C crates/t1-touchbar-hw/c sanitize

sep-probe:
	$(MAKE) -C sep-probe test

sep-probe-sanitize:
	$(MAKE) -C sep-probe sanitize

pam:
	$(MAKE) -C pam test
	$(MAKE) -C pam sanitize

uvc-upstream:
	@set -eu; \
	work=$$(mktemp -d); \
	trap 'rm -rf "$$work"' EXIT; \
	mkdir -p "$$work/drivers/media/usb/uvc" "$$work/expected"; \
	cp kernel/uvcvideo-t1/uvc_driver.c kernel/uvcvideo-t1/uvc_h264.c \
		kernel/uvcvideo-t1/uvc_h264.h \
		"$$work/drivers/media/usb/uvc/"; \
	awk 'NR == 1 { print; next } /^uvcvideo-objs/ { copy = 1 } \
		copy { print } /^endif/ { copy = 0 } /^obj-m/ { print }' \
		kernel/uvcvideo-t1/Makefile | \
		sed 's/^obj-m += uvcvideo.o$$/obj-$$(CONFIG_USB_VIDEO_CLASS) += uvcvideo.o/' \
		> "$$work/drivers/media/usb/uvc/Makefile"; \
	cp "$$work/drivers/media/usb/uvc/"{Makefile,uvc_driver.c,uvc_h264.c,uvc_h264.h} \
		"$$work/expected/"; \
	patch --silent --batch --reverse --directory="$$work" -p1 \
		< kernel/uvcvideo-t1/upstream/0002-media-uvcvideo-disable-autosuspend-for-t1-ibridge.patch; \
	patch --silent --batch --reverse --directory="$$work" -p1 \
		< kernel/uvcvideo-t1/upstream/0001-media-uvcvideo-parse-h264-descriptors.patch; \
	printf '%s  %s\n%s  %s\n' \
		0f8b5441962a80bcb629c2b7095f98ce9c6c471b42e02c0e2f13b8e19b669cd7 \
		"$$work/drivers/media/usb/uvc/uvc_driver.c" \
		a577b4a0b1bcad08052a7542f8331169ed9d523693ed32ebe99ea6eb53793ef3 \
		"$$work/drivers/media/usb/uvc/Makefile" | sha256sum --check --status; \
	test ! -e "$$work/drivers/media/usb/uvc/uvc_h264.c"; \
	test ! -e "$$work/drivers/media/usb/uvc/uvc_h264.h"; \
	patch --silent --batch --directory="$$work" -p1 \
		< kernel/uvcvideo-t1/upstream/0001-media-uvcvideo-parse-h264-descriptors.patch; \
	patch --silent --batch --directory="$$work" -p1 \
		< kernel/uvcvideo-t1/upstream/0002-media-uvcvideo-disable-autosuspend-for-t1-ibridge.patch; \
	cmp "$$work/drivers/media/usb/uvc/Makefile" "$$work/expected/Makefile"; \
	cmp "$$work/drivers/media/usb/uvc/uvc_driver.c" "$$work/expected/uvc_driver.c"; \
	cmp "$$work/drivers/media/usb/uvc/uvc_h264.c" "$$work/expected/uvc_h264.c"; \
	cmp "$$work/drivers/media/usb/uvc/uvc_h264.h" "$$work/expected/uvc_h264.h"

uvc-parser:
	@set -eu; \
	work=$$(mktemp -d); \
	trap 'rm -rf "$$work"' EXIT; \
	$(CC) -O2 -std=c17 -Wall -Wextra -Wpedantic -Werror \
		kernel/uvcvideo-t1/uvc_h264.c \
		kernel/uvcvideo-t1/test_t1_uvc_h264.c \
		-o "$$work/test_t1_uvc_h264"; \
	"$$work/test_t1_uvc_h264"

uvc-parser-sanitize:
	@set -eu; \
	work=$$(mktemp -d); \
	trap 'rm -rf "$$work"' EXIT; \
	gcc -O1 -g -std=c17 -Wall -Wextra -Wpedantic -Werror \
		-fno-omit-frame-pointer -fno-sanitize-recover=all \
		-fsanitize=address,undefined \
		kernel/uvcvideo-t1/uvc_h264.c \
		kernel/uvcvideo-t1/test_t1_uvc_h264.c \
		-o "$$work/test_t1_uvc_h264"; \
	"$$work/test_t1_uvc_h264"

kernel: uvc-upstream
	$(MAKE) -C kernel/dkms KDIR=$(KDIR)

packaging:
	$(MAKE) -C packaging/arch/t1bridge verify

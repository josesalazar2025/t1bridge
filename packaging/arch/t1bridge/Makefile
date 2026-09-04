.PHONY: verify

SYSTEMD_DIR := ../../../systemd
PKGBUILD := PKGBUILD

verify:
	@set -eu; \
	verify_root="$$(mktemp -d)"; \
	trap 'rm -rf "$${verify_root}"' EXIT; \
	install -d "$${verify_root}/usr/lib/systemd/system" \
		"$${verify_root}/usr/lib/systemd/network" \
		"$${verify_root}/usr/lib/systemd/user" \
		"$${verify_root}/etc/systemd/system" \
		"$${verify_root}/etc/systemd/user" \
		"$${verify_root}/run/systemd/system" \
		"$${verify_root}/run/systemd/user"; \
	cp -a /usr/lib/systemd/system/. \
		"$${verify_root}/usr/lib/systemd/system/"; \
	cp -a /usr/lib/systemd/user/. \
		"$${verify_root}/usr/lib/systemd/user/"; \
	install -Dm755 /usr/bin/true \
		"$${verify_root}/usr/lib/t1bridge/t1-touchbar-hw"; \
	install -Dm755 /usr/bin/true \
		"$${verify_root}/usr/lib/t1bridge/t1-touchbar"; \
	install -Dm755 /usr/bin/true \
		"$${verify_root}/usr/lib/t1bridge/t1-xart-storage"; \
	install -Dm755 /usr/bin/true \
		"$${verify_root}/usr/lib/t1bridge/t1-ncm-ready"; \
	install -Dm755 /usr/bin/true \
		"$${verify_root}/usr/lib/t1bridge/t1-keybag-relay"; \
	install -Dm755 /usr/bin/true \
		"$${verify_root}/usr/bin/systemctl"; \
	install -Dm755 /usr/bin/true \
		"$${verify_root}/usr/lib/t1bridge/t1-touchid-auth"; \
	install -Dm755 /usr/bin/true \
		"$${verify_root}/usr/bin/t1-touchid"; \
	install -Dm755 /usr/bin/true \
		"$${verify_root}/usr/bin/t1bridge"; \
	install -Dm644 "$(SYSTEMD_DIR)/t1-touchbar-hw.service" \
		"$${verify_root}/usr/lib/systemd/system/t1-touchbar-hw.service"; \
	install -Dm644 "$(SYSTEMD_DIR)/t1-touchbar-hw.socket" \
		"$${verify_root}/usr/lib/systemd/system/t1-touchbar-hw.socket"; \
	install -Dm644 "$(SYSTEMD_DIR)/t1-xart-storage@.service" \
		"$${verify_root}/usr/lib/systemd/system/t1-xart-storage@.service"; \
	install -Dm644 "$(SYSTEMD_DIR)/t1-ncm-ready@.service" \
		"$${verify_root}/usr/lib/systemd/system/t1-ncm-ready@.service"; \
	install -Dm644 "$(SYSTEMD_DIR)/t1bridge-keybag.service" \
		"$${verify_root}/usr/lib/systemd/system/t1bridge-keybag.service"; \
	install -Dm644 "$(SYSTEMD_DIR)/t1-touchid-auth.service" \
		"$${verify_root}/usr/lib/systemd/system/t1-touchid-auth.service"; \
	install -Dm644 "$(SYSTEMD_DIR)/t1-touchid-auth.socket" \
		"$${verify_root}/usr/lib/systemd/system/t1-touchid-auth.socket"; \
	install -Dm644 "$(SYSTEMD_DIR)/t1bridge-fingerprint.socket" \
		"$${verify_root}/usr/lib/systemd/system/t1bridge-fingerprint.socket"; \
	install -Dm644 "$(SYSTEMD_DIR)/t1bridge-import.service" \
		"$${verify_root}/usr/lib/systemd/system/t1bridge-import.service"; \
	install -Dm644 "$(SYSTEMD_DIR)/user/t1-touchbar.service" \
		"$${verify_root}/usr/lib/systemd/user/t1-touchbar.service"; \
	install -Dm644 "$(SYSTEMD_DIR)/80-t1bridge.preset" \
		"$${verify_root}/usr/lib/systemd/system-preset/80-t1bridge.preset"; \
	install -Dm644 "$(SYSTEMD_DIR)/user/80-t1bridge.preset" \
		"$${verify_root}/usr/lib/systemd/user-preset/80-t1bridge.preset"; \
	install -Dm644 "$(SYSTEMD_DIR)/50-t1bridge-ncm.link" \
		"$${verify_root}/usr/lib/systemd/network/50-t1bridge-ncm.link"; \
	install -Dm644 verify-user-exec.conf \
		"$${verify_root}/usr/lib/systemd/user/t1-touchbar.service.d/verify-user-exec.conf"; \
	systemd-analyze --root="$${verify_root}" --man=no --generators=no \
		verify t1-touchbar-hw.service t1-touchbar-hw.socket \
		t1-ncm-ready@t1synthetic0.service \
		t1-xart-storage@t1synthetic0.service \
		t1bridge-keybag.service t1-touchid-auth.service \
		t1-touchid-auth.socket t1bridge-fingerprint.socket \
		t1bridge-import.service; \
	systemd-analyze --man=no --generators=no verify \
		"$${verify_root}/usr/lib/systemd/user/t1-touchbar.service"; \
	systemctl --root="$${verify_root}" preset t1-touchbar-hw.service \
		t1-touchid-auth.socket t1bridge-fingerprint.socket \
		t1-touchid-auth.service \
		t1bridge-keybag.service; \
	systemctl --root="$${verify_root}" is-enabled --quiet t1-touchbar-hw.service; \
	systemctl --root="$${verify_root}" is-enabled --quiet t1-touchid-auth.socket; \
	systemctl --root="$${verify_root}" is-enabled --quiet t1bridge-fingerprint.socket; \
	! systemctl --root="$${verify_root}" is-enabled --quiet t1bridge-keybag.service; \
	! systemctl --root="$${verify_root}" is-enabled --quiet t1-touchbar-hw.socket; \
	! systemctl --root="$${verify_root}" is-enabled --quiet t1-touchid-auth.service; \
	! systemctl --root="$${verify_root}" is-enabled --quiet t1-xart-storage@.service; \
	! systemctl --root="$${verify_root}" is-enabled --quiet t1bridge-import.service; \
	systemctl --root="$${verify_root}" --global preset t1-touchbar.service; \
	test -L "$${verify_root}/etc/systemd/user/default.target.wants/t1-touchbar.service"; \
	systemd-sysusers --root="$${verify_root}" \
		"$(abspath $(SYSTEMD_DIR)/t1bridge.sysusers)"; \
	systemd-tmpfiles --root="$${verify_root}" --dry-run --create \
		"$(abspath $(SYSTEMD_DIR)/t1bridge.conf)"; \
	udevadm verify --resolve-names=never \
		"$(abspath $(SYSTEMD_DIR)/99-zz-t1bridge-touchbar.rules)"; \
	udevadm verify --resolve-names=never \
		"$(abspath $(SYSTEMD_DIR)/90-t1bridge-xart.rules)"; \
	bash -n "$(abspath $(PKGBUILD))"

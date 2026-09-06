# T1Bridge

Open-source Linux support for Apple's T1 iBridge: Touch ID, Touch Bar,
FaceTime camera, and the services that keep them working together.

Install the official signed packages from **linux.standardagents.ai**.
No source build, GitHub authentication, or download token is required.

## Supported hardware

| MacBook Pro | Model identifiers |
| --- | --- |
| 2016, 13-inch with Touch Bar | `MacBookPro13,2` |
| 2016, 15-inch with Touch Bar | `MacBookPro13,3` |
| 2017, 13-inch with Touch Bar | `MacBookPro14,2` |
| 2017, 15-inch with Touch Bar | `MacBookPro14,3` |

T2 Macs, Apple Silicon, and models without a Touch Bar are outside this
project's hardware scope. Official packages target **x86_64 Arch Linux and
Arch-based distributions**, with systemd 256 or newer. Other distributions
need their own packaging; the hardware stack does not depend on a particular
desktop environment. See [supported versions](docs/dependencies.md#supported-and-tested-versions).

## T1 function support

| Function | Support | Details |
| --- | --- | --- |
| Touch Bar display and touch input | Supported | Default renderer, Escape, hardware controls, and F1–F12 while Fn is held. |
| Screen and keyboard brightness | Supported | Uses the machine's available backlight controls. |
| Custom Touch Bar renderers | Supported | Unprivileged programs through the [renderer interface](docs/interfaces.md#renderer-selection-v1). |
| Volume, media controls, desktop HUDs | Optional integration | Requires a desktop provider; none is bundled in the core package. |
| Touch ID enrollment, matching and deletion | Supported | Standard fprintd tools; up to three enrolled fingers for one Linux owner. |
| sudo, Polkit and lock-screen authentication | Supported through PAM | Uses `pam_fprintd`; configure each consumer and retain password fallback. |
| Saved fingerprints across reboot | Supported | Protected keybag storage and automatic restore; no routine re-enrollment. |
| FaceTime HD camera | Supported | T1 H.264 support through the packaged UVC driver. Application format support still applies. |
| Private T1 network and xART storage | Supported | Device-driven services; no manually named network profile required. |
| Apple machine-data import | Supported | Matching preserved EFI partition or explicit EFI-tree/FDR backup. |
| Ambient-light sensor | Planned | Linux IIO integration is not shipped. |
| General Secure Enclave key services | Not exposed | No general-purpose signing/key-management API. |

Wi-Fi, Bluetooth, speakers, the internal keyboard/trackpad, GPU switching and
whole-system power management are separate from T1Bridge. This is not a
complete MacBook hardware-enablement bundle.

## Install official packages

Keep a working password login and back up your disk. **Preserve the Apple EFI
partition:** Touch ID needs this Mac's original machine data. A different Mac's
backup or a generic macOS installer is not a substitute.

### 1. Trust the signing key

Run from your normal account:

```bash
key_dir=$(mktemp -d)
curl -fSLo "$key_dir/t1bridge-signing-key.asc" \
  https://linux.standardagents.ai/arch/standardagents/x86_64/t1bridge-signing-key.asc
gpg --show-keys --with-fingerprint "$key_dir/t1bridge-signing-key.asc"
```

Check that the **primary fingerprint** is exactly:

```text
35B166F78B063B04DE1E3D913E6C4216EB03D371
```

Only after it matches:

```bash
sudo pacman-key --add "$key_dir/t1bridge-signing-key.asc"
sudo pacman-key --lsign-key 35B166F78B063B04DE1E3D913E6C4216EB03D371
```

### 2. Add the repository and install

Add this block once to `/etc/pacman.conf`, preserving your existing repositories:

```ini
[standardagents]
SigLevel = Required DatabaseRequired
Server = https://linux.standardagents.ai/arch/$repo/$arch
```

Keep `$repo` and `$arch` literal in that file. For the standard Arch `linux` kernel:

```bash
sudo pacman -Syu --needed linux-headers t1bridge t1bridge-dkms libfprint-t1bridge fprintd-t1bridge
```

Use the header package matching your kernel if it is not `linux`. This performs
a normal system upgrade. Confirm DKMS and initramfs/UKI generation succeed
before rebooting; do not bypass signature or dependency errors.

| Official package | Purpose |
| --- | --- |
| `t1bridge` | Services, importer, Touch ID broker and default Touch Bar |
| `t1bridge-dkms` | T1 configuration, display, network and camera kernel modules |
| `libfprint-t1bridge` | T1Bridge driver for the standard fingerprint API |
| `fprintd-t1bridge` | Matched fingerprint daemon, tools and PAM module |

The fingerprint packages replace distro libfprint/fprintd system-wide and must
stay a matched pair. For Touch Bar/camera-only use, omit those two packages.

### 3. Enable hardware support

Still from your normal account:

```bash
sudo systemd-sysusers /usr/lib/sysusers.d/t1bridge.conf
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/t1bridge.conf
sudo usermod -aG t1bridge "$(id -un)"
sudo systemctl daemon-reload
sudo systemctl enable t1-touchbar-hw.service t1-touchid-auth.socket t1bridge-fingerprint.socket
```

Reboot to load the modules and refresh group membership. Then, in your local
graphical session:

```bash
systemctl --user daemon-reload
systemctl --user enable --now t1-touchbar.service
sudo t1bridge status
```

Check each status row. `keybag: not-enrolled` is normal before first enrollment.
The private network and xART services start with the device; do not enable the
keybag relay as an unconditional boot service or hot-swap competing T1 drivers.

### 4. Set up Touch ID

With this Mac's preserved Apple EFI partition attached and the reader idle:

```bash
sudo systemctl start t1bridge-import.service
sudo systemctl status t1bridge-import.service --no-pager
```

For a copied backup instead, see [backup import](docs/setup.md#import-this-machines-apple-data).
After successful import, enroll and verify from your normal account:

```bash
fprintd-list "$(id -un)"
fprintd-enroll -f right-index-finger
fprintd-verify -f right-index-finger
```

If you already have enrolled fingers, verify an existing one instead of enrolling
it again. Choose the correct finger label and repeatedly lift/touch during
enrollment. Require `enroll-completed` and then `verify-match`.

Enrollment does **not** automatically enable sudo, Polkit or lock-screen login.
Follow [safe PAM setup](docs/setup.md#enable-fingerprint-sign-in-safely) for your
distribution, preserving password access and a root recovery shell. Do not
blindly run a desktop setup wizard that replaces this matched fingerprint pair.

See [manual setup](docs/setup.md) for desktop providers, removal and recovery,
and [How Touch ID works](docs/touch-id.md) for startup and authentication diagrams.

## Package boundaries

T1Bridge owns T1 hardware support, protected machine-data import and recovery,
the fingerprint backend, and the default Touch Bar. Its core does not depend on
desktop integration or the separately packaged libfprint/fprintd integration.

Standard fprintd tools provide fingerprint management. A reusable management
TUI and a baseline desktop-controls provider are planned as separate optional
packages. Distribution integrations own installer preservation, automatic
setup, menus, themes, and HUD integration. Custom Touch Bar renderers remain
user-selected programs, not bundled presets.

Maintained by Andrew Boyd.

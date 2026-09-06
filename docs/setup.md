# Manual setup

Start with the [official package installation instructions](../README.md#install-official-packages)
for the public repository and signing key. This guide covers service activation,
machine-data import, fingerprint management, desktop integration and recovery.

The supplied packages currently target x86_64 Arch Linux with systemd; other
distributions need their own packaging.
See [supported versions](dependencies.md#supported-and-tested-versions).

## Install and start the hardware stack

Keep a working password login and back up the disk before changing boot
configuration. Preserve the Apple EFI partition: it contains machine-specific
data needed by Touch ID. Do not format it as part of installing Linux.

Install these packages together from the official repository:

| Package | Purpose |
| --- | --- |
| `t1bridge` | Hardware services, importer, fingerprint broker, default Touch Bar |
| `t1bridge-dkms` | T1 configuration, display, network, and camera modules |
| `libfprint-t1bridge` | Standard fingerprint driver integration |
| `fprintd-t1bridge` | Matching fprintd integration and command-line tools |

The last two replace the distribution's libfprint/fprintd system-wide and must
stay a matched pair. They are optional for Touch Bar-only use. Use the
[published signing key](../README.md#1-trust-the-signing-key); do not disable
signature checks. Install headers matching the kernel you will
boot, and confirm DKMS and the normal initramfs generation complete successfully.

From your normal user account, after package installation:

```sh
sudo systemd-sysusers /usr/lib/sysusers.d/t1bridge.conf
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/t1bridge.conf
sudo usermod -aG t1bridge "$(id -un)"
sudo systemctl daemon-reload
sudo systemctl enable t1-touchbar-hw.service t1-touchid-auth.socket t1bridge-fingerprint.socket
```

Reboot when convenient to load the packaged early configuration selector and
start a fresh login with the new group membership. Do not hot-swap competing
T1 stacks or reset the USB device to substitute for that boot. In the local
graphical session, start the default Touch Bar:

```sh
systemctl --user daemon-reload
systemctl --user enable --now t1-touchbar.service
sudo t1bridge status
```

Hardware access requires the active local graphical user as well as group
membership; an SSH session alone is not a substitute.

Read the individual status rows; a successful status command does not mean
every component is ready. The private network and xART units are device-driven.
The keybag relay starts when protected state exists; do not enable it as an
unconditional boot service. A new installation can legitimately show no
keybag before its first enrollment. See the [startup diagram](touch-id.md).

## Import this machine's Apple data

With the matching preserved Apple EFI partition attached:

```sh
sudo systemctl start t1bridge-import.service
sudo systemctl status t1bridge-import.service
```

The sandboxed importer discovers EFI partitions, reads them without modifying
them, matches data to the live sensor, and stores the selected record under
root-only `/var/lib/t1bridge/machine-data/`. Missing or conflicting data is an
error, not permission to choose an arbitrary partition.

To use a backup instead, supply its absolute path:

```sh
sudo t1bridge machine-data import --from /path/to/efi-backup
```

The directory must contain `EFI/APPLE/EMBEDDEDOS/FDRData`. You can also pass the
absolute path to that `FDRData` file directly. This works for a copied backup
or a manually mounted preserved EFI filesystem. The source must originate
from the target Mac; a different Mac's data is rejected by live-sensor matching.
No symlink component or special file is accepted. The backup is read-only,
diagnostics do not print its path or identifiers, and a different existing
calibration record is never overwritten.

Run import while no fingerprint operation is in progress. A sensor-unavailable
error does not change calibration; retry when the reader is idle rather than
resetting hardware or deleting state.

Compressed backups and macOS installer/disk-image containers are not accepted
by this command yet. Extract a backup you control first; do not copy guessed
records into protected storage. A generic macOS installer is not guaranteed
to contain your machine's calibration data.

## Enroll and verify

Use your normal user account and a working desktop Polkit authentication agent:

```sh
fprintd-list "$(id -un)"
fprintd-enroll -f right-index-finger
fprintd-verify
```

Choose the intended finger label before enrollment. Authorization may require
your password; the distro's Polkit policy determines that prompt. Keep lifting
and touching the same finger until enrollment completes, then verify it.
T1Bridge currently permits three enrolled identities for one Linux owner.
Use `fprintd-list` again to confirm the recorded label. Do not use the direct
`t1bridge enroll` development path for standard fingerprint management.

To deliberately remove one print, substitute its exact listed label:

```sh
fprintd-delete "$(id -un)" -f right-middle-finger
fprintd-list "$(id -un)"
```

Do not omit `-f`: that requests deletion of all the user's prints. The utility
visits every detected reader, so check the device list first if more than one
is connected. Retain a working password regardless of how many prints remain.

## Enable fingerprint sign-in safely

Enrollment does not configure sudo, Polkit, or your lock screen. Use your
distribution's supported **pam_fprintd** configuration for each consumer, and
consult `man pam_fprintd`. T1Bridge does not replace PAM files or ship a custom
PAM module.

Before editing PAM, verify password authentication and keep a persistent root
recovery shell open. Preserve password fallback and existing account/access
checks; do not paste a replacement PAM stack from another distribution.
Use bounded attempts/timeouts. The default fingerprint timeout is 30 seconds,
and a serial PAM conversation can delay the password prompt until fingerprint
authentication finishes.

Before closing the recovery shell, test both a successful fingerprint and
password fallback with the fingerprint service unavailable, separately for
sudo, Polkit, and the lock screen. Never assume that success in one consumer
proves the others. T1Bridge's Touch Bar prompt is cosmetic, not proof that the
requesting application accepted authentication.

## Desktop controls and customization

The default renderer is included. Hardware controls use T1Bridge's advertised
capabilities; desktop audio/media actions and notifications need an optional
provider. No desktop provider is bundled.

To use a compatible provider, set `T1BRIDGE_DESKTOP_PROVIDER` to its absolute
executable path in a user-service drop-in (`systemctl --user edit
t1-touchbar.service`), then restart that user service. To replace the renderer,
create an executable or symlink at `${XDG_CONFIG_HOME:-$HOME/.config}/t1bridge/renderer`
and restart it. Neither program should run as root. Follow the
[provider and renderer contracts](interfaces.md#renderer-selection-v1), not a
private hardware API. The reusable management TUI and baseline desktop provider
are separate planned packages, not prerequisites for the commands above.

## Firewall, recovery, and removal

xART needs inbound IPv6 TCP port 61500 on the dynamically discovered private
T1 network interface. Keep IPv6 enabled there. If your firewall blocks it,
restrict any exception to that interface and the validated T1 peer; never open
the port on Wi-Fi, Ethernet, or all interfaces. Do not save a machine-specific
interface name as a portable rule. The listener also enforces device and peer
admission. Cross-machine peer validation remains an open release gate.

On failure, inspect `sudo t1bridge status` and the relevant systemd journal.
Do not delete `/var/lib/t1bridge`, reset enrollment, or run USB lifecycle
validation commands as generic repair steps. Protect diagnostic logs before
sharing them. Keep existing protected state through upgrades and reinstalls.

Before uninstalling, restore and test password-only authentication using your
distro's configuration tools, with the root recovery shell still open. Stop
the user renderer and the T1Bridge services, sockets, and device-driven xART
instances. Remove the packages through the package manager, restore the
distribution's matched libfprint/fprintd pair if needed, and rebuild the
initramfs through its normal mechanism before rebooting. Package removal is
not authorization to erase protected state or the preserved Apple EFI partition.

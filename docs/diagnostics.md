# Shareable diagnostics

Requires T1Bridge **0.1.1 or newer**. The original 0.1.0 packages do not support
this switch or format.

Diagnostics are **off by default**. Enable them to investigate import, Touch ID,
boot-service, or Touch Bar failures without removing redaction. Logging observes
existing work; it adds no sensor commands, retries, unlock attempts, or resets.

## Enable

For one CLI command, put `--diagnostics` before the command:

```bash
sudo t1bridge --diagnostics machine-data import
```

This still performs the requested import; the flag is not a dry run. It only
enables the current process, not an already-running broker or renderer.

For services, create `/etc/t1bridge/diagnostics.conf` as root with mode `0644`
(create its parent directory with mode `0755` if absent):

```ini
T1BRIDGE_DIAGNOSTICS=1
```

All packaged T1Bridge services, including the user renderer, read this optional
file on their next start. For a fingerprint reproduction, wait until no
authentication or enrollment is running, then:

```bash
sudo systemctl restart t1-touchid-auth.service
```

For renderer/provider failures, use `systemctl --user restart t1-touchbar.service`.
For boot failures, leave the setting enabled for the next planned reboot.
Do **not** restart NCM, xART, or the keybag relay just to turn on logging: doing so
changes the live state being investigated. Keep password access available.

The broker also accepts `--diagnostics` in its service command. Do not launch a
second broker manually. Direct development commands can use the environment
variable `T1BRIDGE_DIAGNOSTICS=1` instead.

## Reproduce and export

Record the start time in your normal shell, then reproduce once through the
usual UI or command:

```bash
diagnostic_start=$(date --iso-8601=seconds)
```

Do not delete a working print or reset state to make room for a diagnostic.
After the attempt, export **only diagnostic records**, without journal headers:

```bash
sudo journalctl -b --since "$diagnostic_start" --no-pager -o cat \
  --grep '^t1bridge-diagnostic ' > t1bridge-diagnostic.txt
pacman -Q t1bridge t1bridge-dkms libfprint-t1bridge fprintd-t1bridge
```

For boot failures, omit `--since "$diagnostic_start"`. For a CLI import, redirect
stderr to a local file and share only lines starting `t1bridge-diagnostic `.

Inspect the report before posting. Share it, the package versions, and what you
saw (prompt, touch progress, final result). Do not attach full journals, EFI
backups, or state directories. An empty report is not success: check that the
new binaries and setting are active. Locally overridden development binaries
can differ from the package manager's version.

## Coverage and format

| Component | Recorded boundaries |
| --- | --- |
| Importer/EFI | Live hardware association, EFI discovery/open/read/parse, record selection, durable commit, final error category |
| SEP/broker | Relay/service lifecycle, SEP lease return codes, standard list/enroll/verify/identify/delete, existing Mesa commands and native rejection codes |
| NCM/xART | Link preparation, listener bind/accept failures, peer admission, storage-session success/failure |
| Touch Bar hardware | DRM/input/keyboard/session startup, renderer admission and session revocation |
| Renderer/provider | Renderer connection lifetime, provider availability changes and action success/failure |

Example:

```text
t1bridge-diagnostic v=1 component=broker phase=transaction result=error code=1 command=0x03
```

Labels come from fixed enums. `code` is a native command status or adapter error
category; interpret it with its component and phase. `command` is an allowlisted
Mesa command code, never a request header identifier. A stage's `ok` means that
call returned successfully, not that a fingerprint matched or enrollment
completed. Keep the final fprintd result.

No usernames, finger labels, device identifiers, paths, coordinates, keypresses,
credentials, calibration, keybags, or biometric payloads are included. Responses
are not dumped and errors are not formatted with unrestricted `Debug`. Each
process emits at most 4096 records plus a limit marker; each fingerprint
transport trace is capped at 256 commands. Work continues after either limit.

This covers userspace lifecycle/error boundaries and native adapter statuses,
not every internal branch. It does not enable kernel dynamic debug, firmware
tracing, USB capture, or logging in third-party fprintd/PAM/desktop applications.
Those outputs are not part of this public-shareable format.

## Disable

Set `T1BRIDGE_DIAGNOSTICS=0` in the same file. Restart only affected services while
idle, or let the change take effect at the next planned reboot. Remove a broker
`--diagnostics` override separately if you added one; preserve other local
overrides. No diagnostic state or fingerprint data needs deleting.

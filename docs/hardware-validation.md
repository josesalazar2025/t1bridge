# Hardware validation

This is the acceptance runbook for the two supported test machines. Phase 2
runs the Touch ID sections on both. Phase 5 runs the entire document on both
using the exact signed release artifacts.

While the second-machine package handoff is pending, current runs use the
available machine. Those results may unblock private integration,
but every two-machine acceptance row remains deferred until the same required
matrix runs on the second machine; it is not waived.

Record only the model, kernel version, T1Bridge package versions, artifact
checksums, step result, and relevant redacted logs. Never record serials,
network addresses, host or volume identifiers, machine-data contents,
catacombs, keybags, xART records, or biometric data in the repository.

The `t1bridge` commands named below are the required interface for the packaged
Rust CLI. Until a phase implements a command, that acceptance step cannot pass.
`t1bridge enroll` and `t1bridge match` run as the non-root enrollment owner;
the authenticated root broker owns privileged hardware work. Do not run either
direct command through `sudo`. `sudo t1bridge status` is strictly read-only: it
never starts a service, opens an activation socket, or changes a device or
link. It prints these fixed identifier-free rows in order:

```text
usb-configuration: selected|unexpected|unavailable
drm: ready|unavailable
ncm: ready|unavailable
xart: ready|not-ready
keybag: ready|not-ready|not-enrolled
broker: ready|not-ready
touchbar: ready|not-ready
```

An unavailable, not-ready, not-enrolled, or unexpected component is a reported
state and does not itself change the command's success exit. The command exits
nonzero only when a row cannot be inspected safely.

## Readiness handshake

Before any timed or owner-interactive step, the executing agent states the
test, the owner's required action, and the response window, then waits. The
step and its timer begin only after the owner sends a fresh `ready` message.
Readiness applies only to the described step and must be requested again if the
test changes.

## Safety preflight

1. Confirm the machine is one of the supported T1 Touch Bar models and is using
   the packages under test, not development-tree binaries.
   Confirm the graphical user belongs to the package-created `t1bridge` group;
   if membership was just granted, start a fresh login session before testing
   the user Touch Bar process.
2. Confirm no legacy configuration selector or Touch Bar service can compete
   for the hardware. The DKMS package suppresses the known legacy iBridge
   module names through `/usr/lib/modprobe.d/t1bridge.conf`; a deliberate
   rollback to a firmware-mode driver must first remove that package-owned
   suppression file and rebuild the initramfs.
3. Run `sudo t1bridge status`. It must dynamically find the T1, report the
   selected USB configuration, DRM, NCM, xART, keybag, broker, and Touch Bar
   service states, and redact machine-specific values.
4. Verify that the accepted xART connection arrives on the dynamically
   discovered T1 NCM interface and that its peer matches the packaged protocol
   constant. Record only pass or fail, never the observed interface or address.
   This row is pending on the active MacBookPro13,3 and deferred on the
   MacBookPro14,3 under Decision 49.
5. Before any PAM install, removal, or fault injection, open a persistent root
   shell in a separate terminal and verify it is root. Keep it open until
   fingerprint and password paths have both passed after restoration.
6. Confirm the existing password path works before enabling `pam_fprintd`.
7. Confirm enrollment will not overwrite an active catacomb pair. Use a machine
   with no T1Bridge enrollment or preserve the existing state outside the test
   path and explicitly authorize a fresh test enrollment. The CLI must refuse
   an in-place overwrite.

If any preflight check fails, stop. Do not change PAM, USB configuration,
firmware, broad power settings, or preserved biometric state to force a pass.

## Enrollment from scratch

1. Run `t1bridge enroll` from a state with no active T1Bridge enrollment.
2. Repeatedly lift and rest one finger when prompted.
3. Observe the physical Touch Bar during capture and commit.

Expected outcome:

- calibration loads before sensor capture;
- the Touch Bar shows the enrollment instruction beside the sensor without
  hiding Escape or unrelated stock controls;
- enrollment completes only after the user and master catacombs are both
  durably committed in that order;
- both files and any advanced xART record are root-private;
- no opaque contents or identifiers appear in output; and
- the keybag relay is active again after success or cancellation.

## Direct match

1. Run `t1bridge match`.
2. Touch the enrolled finger once.
3. Repeat once with a different finger or allow the operation to time out.

Expected outcome:

- the authorized ACM lease remains live across paired master/user restore,
  policy registration, and matching;
- the enrolled finger returns success and the other finger or timeout returns
  a non-success result;
- retry feedback is cosmetic and does not become authentication success; and
- every exit path clears the overlay, releases exclusive SEP ownership, and
  restores the keybag relay.

## Standard fingerprint hardware go/no-go

From a source checkout, use the development smoke command through the
production broker scheduler and live worker to validate the standard
fingerprint contract independently of the libfprint adapter. It is not shipped
in release packages. The owner's existing unlabeled
enrollment is the recovery anchor:
prove it still matches before starting, reserve its already verified recovery
copy, and use a different physical finger for the disposable labelled
enrollment. Never expose an opaque identity value in command output or the
result record.

Each sensor wait, cancellation, device-removal action, and deletion is a
separate readiness-gated step:

1. Run `cargo run --locked --release -p t1-daemons --bin
   t1-standard-fingerprint-smoke --features standard-fingerprint-smoke --
   list`. It must report zero labelled
   identities without exposing or inventing a label for the legacy enrollment.
2. Enroll the disposable finger under one standard finger label. Record the
   observed number of physical touches and whether progress is monotonic,
   bounded by the advertised fixed stage count, and reaches completion only
   after durable commit.
3. In fresh command processes, list the exact label, verify that label with the
   disposable finger, and identify the same label. A different finger must not
   verify it.
4. Restart the broker without rebooting, then repeat list, verify, and identify
   in fresh command processes. This proves committed metadata and paired
   catacomb restore rather than live process state.
5. Start a verify, cancel while it is waiting for the sensor, and confirm a
   bounded cancelled result. The overlay, exclusive SEP operation, and relay
   must return to their prior healthy states.
6. Exercise device removal and reappearance only through the separately
   owner-approved guarded mechanism. The in-flight request must report device
   loss within the recorded latency bound, the device must reappear once, and
   a fresh verify must succeed. Do not improvise a USB reset, driver unbind, or
   power-policy change for this step.
7. Delete only the disposable labelled identity. List must return to zero,
   verification of that label must no longer succeed, and a fresh direct match
   with the legacy recovery-anchor finger must still succeed.

Stop for an owner decision if the T1 cannot provide honest per-identity list or
delete behavior, if progress cannot be represented by one fixed standard stage
count, or if the legacy enrollment changes at any point. Do not synthesize a
finger label, map exact deletion to clear-all, or proceed to the libfprint
adapter after a failed go/no-go.

Expected outcome: the real T1 proves labelled enrollment, exact listing,
verification and identification, persistence, fresh-process restore,
cancellation, device loss, and exact deletion while the hidden legacy recovery
anchor remains usable.

## Preserved legacy recovery

This is an emergency rollback, not a standard-test preparation step. Run it
only after an owner-ready gate and only when the live T1 has no loaded labelled
generation. A reboot, USB cycle, reset, or driver action remains separately
owner-authorized and is never implied by this procedure.

1. Keep the independently verified private recovery copy unchanged.
2. Confirm the normal password path and root recovery shell remain available.
3. Run `/usr/lib/t1bridge/t1-legacy-recovery` as root with no arguments.
4. Accept only `status recovered` as success. `status quarantined`,
   `status denied`, and `status error` are failures and require inspection
   without retrying enrollment or running catacomb cleanup.
5. In a fresh direct client process, match the preserved legacy finger.

The command internally requires exactly one active labelled generation and one
complete inactive metadata-free generation. It accepts no generation, path, or
identity argument. It reserves the unique legacy generation before live work,
uses the ordinary relay handoff and exclusive SEP lifecycle, forces calibrated
master-first then user restore without trusting live identities, and atomically
promotes only a device-validated pair. Rejection or uncertain validation keeps
the reservation quarantined. Neither generation nor the independent recovery
copy is deleted or rewritten, and this path never invokes store cleanup.

## PAM: sudo and fail-open faults

Keep the verified root recovery shell open for this entire section.

1. Install the distribution integration's fail-open `pam_fprintd` entry without
   replacing its existing password stack. T1Bridge ships no PAM configuration
   or T1-specific PAM module.
2. In a separate unprivileged terminal, invalidate cached sudo credentials and
   request a new sudo authentication. Match the enrolled finger.
3. Repeat and choose password authentication instead.
4. Inject each fault separately, restoring normal state between cases:
   - broker process unavailable;
   - broker socket absent; and
   - T1 unavailable through the guarded, dynamically discovered USB-cycle
     validation operation.
5. Under each fault, request sudo authentication and use the normal password.
6. Restore all units, run `sudo t1bridge status`, then prove fingerprint and
   password authentication once more before closing the root shell.

Expected outcome:

- the enrolled finger can satisfy sudo when the stack is healthy;
- password remains available when the fingerprint attempt is cancelled,
  rejected, times out, or hits any injected fault;
- a missing or unloadable `pam_fprintd` module does not remove the existing
  password path; and
- no helper, overlay, exclusive lock, or stopped relay remains after a request.

Any case in which password authentication is unavailable is a release blocker.

## Hyprlock

1. With the healthy stack restored, lock the active desktop session.
2. Unlock once with the enrolled finger.
3. Lock again, begin a fingerprint attempt, then enter the normal password.
4. Lock once more and cancel from the Touch ID region on the Touch Bar.

Expected outcome:

- the fingerprint conversation unlocks the session only after broker success;
- the independent password conversation remains usable while fingerprint work
  is active;
- password success cancels and cleans up the biometric conversation; and
- Touch Bar cancellation receives an acknowledgement, leaves the lock screen
  locked, removes the overlay, and restores the relay.

## General cancellation

Cancel enrollment during capture, cancel direct matching before a touch, and
disconnect an authentication client while matching.

Expected outcome for every case:

- the active Mesa operation is cancelled or allowed to terminate safely;
- temporary ACM material is destroyed;
- partial catacomb outputs are not promoted;
- the cosmetic state file is removed by its owner;
- SEP and Touch Bar locks are released; and
- the keybag relay returns to its prior healthy state.

## Reboot persistence

Before the reboot, discover the unique live `apple_t1_ncm` interface without
recording its name. Run complete dry-run `udevadm test` evaluations for `add`
and `move` against that interface. The `add` evaluation must select the packaged
`50-t1bridge-ncm.link`, apply the keep policy without assigning another name,
emit both `ID_NET_MANAGED_BY=org.t1bridge` and `NM_UNMANAGED=1`, retain the
`systemd` tag, and request exactly one dynamically named xART service. The
`move` evaluation must select the same link file and regenerate both ownership
properties; it is not expected to request the add-only service. Treat any
different link file, name assignment, missing property, missing tag, missing
add-event service request, or move-event service request as a failed preflight.
Do not use a standalone `net_setup_link` test because it lacks the earlier
driver-property import from the complete rules pass. Do not hard-code or record
the discovered interface or generated unit instance.

During preflight, disable autoconnect for any legacy network-manager profile
for the T1 link but leave the active connection intact. Deactivate it only
immediately before the owner-authorized shutdown, or let shutdown deactivate
it. Confirm any retained prototype udev rule has an inert filename that does
not end in `.rules`, and keep recoverable host-only backups outside the
repository. Otherwise, treat a successful boot as unattributable residue.

1. Record only whether the active catacomb pair and xART record exist with the
   required ownership and permissions. Do not copy their names, contents, or
   hashes into the repository report.
2. Reboot normally.
3. Run `sudo t1bridge status`, then repeat direct match, sudo fingerprint,
   sudo password, and Hyprlock fingerprint checks.

Expected outcome:

- the final real udev database carries both ownership properties and the
  `systemd` tag;
- the interface retains its kernel-assigned ephemeral-style name, with no
  rename or move event and no network-manager claim or activation in the boot
  journal;
- the want-derived NCM and xART services are active and bound to the device
  unit;
- cfgsel, the device-scoped NCM and xART services, the active keybag relay,
  auth socket, and Touch Bar services reach their expected states without
  legacy glue; the relay starts only after the xART listener reports ready;
- the master-then-user restore finds the enrolled identity;
- authentication works without re-enrollment; and
- the T1 device remains runtime-power forced on after the camera probes, while
  the system-wide coldplug trace records no T1 power-policy attribute write;
  and
- no service is in a crash loop and no password path is lost.

## Suspend and resume

Run this section only when the host already supports safe system suspend.
Never enable or override a disabled suspend path for this runbook. Record the
section as not run when suspend is unavailable; it is non-blocking. On a
suspend-capable host, a T1Bridge-specific failure remains a validation failure.

1. Confirm the stack is idle and healthy.
2. Suspend through the normal desktop path, wait for full sleep, then resume.
3. Repeat direct match and the stock Touch Bar smoke test.

Expected outcome:

- the display pipeline resumes without completion timeouts;
- NCM, xART, keybag, and broker state recover without fixed device paths;
- the enrolled finger still matches; and
- the Touch Bar accepts input with no stuck synthesized keys.

## Guarded T1 USB cycle

Run `sudo t1bridge validate usb-cycle`. The command must discover the T1 from
USB identity, validate the expected configuration and drivers, acquire the
hardware lock, preserve prior service/link state, perform only a device-local
runtime suspend or unbind/rebind cycle, and restore that state on signals and
errors. It must not use a fixed interface or sysfs path.

Expected outcome:

- the T1 returns in the validated display configuration;
- DRM and NCM devices reappear and their services recover;
- the Touch Bar renders again;
- direct match succeeds; and
- unrelated USB devices and the camera remain usable.

## Guarded in-flight fingerprint loss

Keep a root recovery shell open. Start an ordinary `fprintd-verify` operation as
the enrolled user and wait until Verify is active, but do not touch the sensor.
In the root shell run `t1bridge validate usb-live-loss`. Do not substitute a
manual sysfs write or USB reset. Measure the client result from the start of the
live-loss command and trace T1 power-policy attributes system-wide.

Expected outcome:

- the client terminates with device loss or cancellation within the recorded
  bound and never reports a match;
- the journal records the redacted device-presence loss before cancellation;
- the command prints only `status live-loss-cycled` and exits successfully;
- no T1 power-policy attribute is written;
- the exact interface map and every steady-state service return; and
- a fresh stock-fprintd Verify succeeds after an owner-ready touch.

## FaceTime camera

1. Confirm the packaged `uvcvideo` override exposes H.264 through V4L2.
2. Capture and decode one frame through an ordinary V4L2 or PipeWire consumer.
3. Keep capture running while exercising Touch Bar rendering and one direct
   Touch ID match.

Expected outcome:

- H.264 capture and decode succeed without a private camera application;
- the camera remains available through PipeWire; and
- camera, Touch Bar, NCM, and SEP operation remain healthy together.

## Stock Touch Bar smoke

Use a clean user account with no selected renderer at
`${XDG_CONFIG_HOME}/t1bridge/renderer`, so the packaged built-in is exercised.
For the distribution-integration pass, configure that distribution's provider
through `T1BRIDGE_DESKTOP_PROVIDER`. Verify:

- Escape is always present and emits exactly one press/release per tap;
- holding Fn exposes F1 through F12 and releasing Fn restores the stock strip;
- display and keyboard-backlight controls change only their intended levels;
- mute and volume controls work;
- media controls appear only when a compatible player is available;
- enrollment, authenticate, retry, cancel, and success overlays appear beside
  the sensor and never authenticate cosmetically; and
- removing or failing the provider hides audio/media controls and uses the
  journal fallback when desktop notification is unavailable, without changing
  Escape, Fn/F-keys, brightness, or Touch ID behavior.

Expected outcome: no crash, stuck key, unexpected service restart, display
completion timeout, or loss of Escape, Fn keys, or Touch ID state.

## Result record

For each machine and phase, record a compact table:

| Field | Value |
| --- | --- |
| Supported model | model name only |
| Kernel | version |
| Packages | exact versions and artifact checksums |
| xART peer protocol constant | pass or fail |
| Enrollment / match | pass or fail |
| PAM healthy / three faults | pass or fail for each |
| Hyprlock / cancellation | pass or fail |
| Reboot / suspend / USB cycle | pass, fail, or suspend not run |
| Stock Touch Bar | pass or fail |
| Redacted evidence | journal time ranges or attached sanitized report |

A failure remains a failure until the same release artifacts pass the affected
step after a fix. Do not edit the expected outcome to match observed behavior.

# v0.1.2

- Distinguish normal xART connection close from truncated frames. A missing HELLO or incomplete frame still fails.
- Add read-only `xart-admission` evidence to `t1bridge status`. Journal collection is bounded and scoped to the broker/xART units. Missing diagnostics never abort the other status rows; recorded admission is not a live firewall test.
- Use the import service's private temporary directory for automatic EFI discovery. A separate multi-ESP discovery failure remains tracked in [#9](https://github.com/standardagents/t1bridge/issues/9); use an explicit same-machine backup when automatic import fails.
- Put the private xART firewall prerequisite before enrollment and record the new 13,2 and 14,3 tester evidence without broadening untested support claims.

Thanks to @josesalazar2025 for [PR #4](https://github.com/standardagents/t1bridge/pull/4), and the testers who helped isolate the firewall prerequisite.

## Upgrade

With the official repository already configured, use `sudo pacman -Syu`. The cohort is `t1bridge`/`t1bridge-dkms` 0.1.2-1, `libfprint-t1bridge` 1.94.100-10 and `fprintd-t1bridge` 1.94.5-7. The fingerprint pair is rebuilt with new package revisions, not new protocol behavior.

Confirm DKMS and initramfs generation succeed, then reboot to use the installed cohort. Do not delete calibration, keybags or enrolled fingers. Desktop audio/media/HUD integration remains optional and is not bundled by this release. System suspend/resume remains unsupported.

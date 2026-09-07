# v0.1.4

- Automatic import: already-mounted EFI partitions are inspected through a
  private read-only view without changing their original mount flags. This
  fixes discovery aborting when a Linux ESP is mounted read-write alongside an
  unmounted Apple ESP (#9).
- Opt-in diagnostics now distinguish Touch ID overlay visibility, eligible
  OLED presses, and cancellation acknowledgments. This helps investigate #10;
  it does not claim the reported cancellation failure is resolved.
- A renderer socket regression test checks cancellation delivery,
  acknowledgment handling, and suppression of repeated cancellation on release.

Update using `sudo pacman -Syu` on Arch or `omarchy update` on Omarchy.
The cohort is `t1bridge`/`t1bridge-dkms` 0.1.4-1,
`libfprint-t1bridge` 1.94.100-12 and `fprintd-t1bridge` 1.94.5-9.
The fingerprint pair has new package revisions but no protocol changes.

No re-enrollment is required. Suspend/resume remains unsupported. The EFI fix
was tested with disposable FAT images through the production discovery code;
this is not a retest of the reporter's machine or a complete calibration import.

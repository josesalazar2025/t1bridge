# v0.1.3

- Touch Bar: press anywhere in the visible Touch ID prompt to cancel. Release
  does not send another cancellation. The separate fingerprint sensor still
  performs verification; Escape remains available.
- Diagnostics: broker attempts without xART logging, or with capped xART logs,
  report incomplete evidence rather than suggesting a firewall problem.
- Installation: README explains Omarchy's package-update guard.

With the official repository configured, update using `sudo pacman -Syu` on
Arch or `omarchy update` on Omarchy. The package cohort is
`t1bridge`/`t1bridge-dkms` 0.1.3-1, `libfprint-t1bridge` 1.94.100-11 and
`fprintd-t1bridge` 1.94.5-8. The fingerprint pair has new package revisions but
no protocol changes.

No re-enrollment is required. Live cancellation and diagnostic confirmation
remain tracked in #10 and #12; this release does not fix suspend/resume or the
remaining multi-ESP automatic-import failure (#9).

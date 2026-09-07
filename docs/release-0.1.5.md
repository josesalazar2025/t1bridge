# v0.1.5

- Fix the mounted-ESP import fallback under the packaged service sandbox.
  `RestrictSUIDSGID` blocks `openat2`; descriptor-relative, no-follow traversal
  now pins the mounted directory without relaxing the sandbox or changing the
  original mount flags (#9).
- Keep status diagnostic queries in the system journal, avoiding unrelated
  user-journal searches that could exhaust the three-second query budget (#12).
- Align the DKMS registration version with the package version. Kernel source
  and fingerprint protocol are unchanged.

Update using `sudo pacman -Syu` on Arch or `omarchy update` on Omarchy.
The cohort is `t1bridge`/`t1bridge-dkms` 0.1.5-1,
`libfprint-t1bridge` 1.94.100-13 and `fprintd-t1bridge` 1.94.5-10.

No re-enrollment is required. Suspend/resume remains unsupported.
Import regression tests, sanitizers and a sandboxed directory-opening probe
passed. Final-package import and the reporter's two-ESP layout remain to be
validated; neither is claimed by those tests.

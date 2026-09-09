# v0.1.7

- Preserve the failing keystore operation and validated remote status in
  opt-in relay diagnostics (#14). Previously a remote rejection appeared only
  as the generic SEP operation result `1`.
- Add `keystore-reply`, `keystore-outer` and `keystore-inner` diagnostic stages
  with an allowlisted `selector`. No keybag handles, identities, payloads or
  request data are logged. Missing or invalid remote fields are not emitted.
- Scope observation to the relay's thread and native call; restore the previous
  observer on return. Diagnostic output retains the shared 4096-record bound
  and cannot change the native operation result.

This release gathers evidence; it does not fix the underlying SEP failure.
The v0.1.6 restart backoff remains in place. See
[relay diagnostics](diagnostics.md#sustained-keybag-relay-restarts). Enable the
existing diagnostic setting for the next normal service start or planned boot;
do not force hardware resets or repeated authentication to produce a failure.

Native success/rejection/malformed-reply tests, sanitizers, observer isolation
and restoration tests, and the full quality suite passed. Affected-hardware
recovery remains unverified.

The cohort is `t1bridge`/`t1bridge-dkms` 0.1.7-1,
`libfprint-t1bridge` 1.94.100-15 and `fprintd-t1bridge` 1.94.5-12.
Kernel code and fingerprint protocol are unchanged. Update with
`omarchy update` or `sudo pacman -Syu`. No re-enrollment is required;
suspend/resume remains unsupported.

# v0.1.6

- Accept binary-plist offset and object-reference widths from 1 through 8
  bytes. This fixes import rejection of valid FDRData with three-byte offsets
  (PR #16, thanks to @niconistal). Existing parser limits remain enforced.
- Back off automatic keybag relay failure restarts from 2 seconds to 60 seconds
  over five steps, retaining the quick first retry. This reduces persistent
  restart storms; the underlying SEP failure and downstream lock-screen retry
  loop remain unresolved (#14).
- Explain enrollment authorization timeouts and distinguish SEP operation
  results from Linux errno values (#15).

The cohort is `t1bridge`/`t1bridge-dkms` 0.1.6-1,
`libfprint-t1bridge` 1.94.100-14 and `fprintd-t1bridge` 1.94.5-11.
The compatibility pair's release revisions advance for this build; its
fingerprint protocol and the kernel code are unchanged.

Update using `sudo pacman -Syu` on Arch or `omarchy update` on Omarchy.
No re-enrollment is required. Suspend/resume remains unsupported.

The parser regression and additional synthetic width/bounds tests passed.
Isolated systemd testing reached the 60-second backoff cap and confirmed that
clean stop/start resets the delay. These tests do not establish recovery from
an affected machine's SEP failure or new hardware coverage.

# T1 UVC compatibility override

This directory is the Linux stable 7.1.9 `drivers/media/usb/uvc` module at
commit `ffc82ed665314ccf141abc4710830f3f424d98ea`, with one bounded parser for
the UVC 1.5 H.264 format and frame descriptors exposed by the T1 camera in USB
configuration 2. The T1 entry also disables UVC's device-wide autosuspend
enablement because that would suspend the shared display, camera, NCM, and SEP
device after its other interfaces are already active.

The complete module is required because the upstream descriptor parser and its
state are private to `uvcvideo`; a companion module cannot extend them. Keep the
unmodified files byte-identical to the pinned stable source. Remove this
override when both patches reach the oldest supported kernel.

The patches live in `upstream/`; `make uvc-upstream` checks them against the
in-tree driver.

Stock `uvcvideo` may autosuspend the composite T1 device, so the DKMS override
is required.

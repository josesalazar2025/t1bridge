# T1 appletbdrm override

This is Linux stable v7.1.8's `appletbdrm` driver adapted for the T1 USB ID,
response flow, and suspend/resume behavior. It deliberately keeps the in-tree
module name and installs under `updates/dkms`, taking precedence over the
in-tree module.

The legacy `apple-ibridge-no-config1-revert.patch` is unnecessary because
T1Bridge does not install the config-1 `apple-ib-drv` stack it modifies.

## Upstream status

The two-patch series in [`upstream/`](upstream/) is a private review draft and
has not been submitted. It is based on kernel.org stable tag `v7.1.8` (tag
object `1af9bbf117b680f903a81485cd74501c334bf538`, commit
`25c76bea853d0db65b51fb4697a47cbfd9e35e76`). Phase 1 hardware acceptance is
complete; suspend/resume was recorded as not run under the host-safety rule.
Owner DCO sign-off and validation against the eventual submission base remain
required before sending the series upstream.

# Unified DKMS package

`t1bridge-dkms` builds the descriptor-validating configuration selector, the
T1-patched `appletbdrm`, the private NCM shim, and the temporary T1 `uvcvideo`
compatibility override as one DKMS unit. All four install under `updates/dkms`;
that precedence is required for the two modules that override in-tree names.

The package adds `t1_cfgsel` to the initramfs so it is registered before the
internal iBridge enumerates. The interface drivers then autoload from their USB
aliases after the selector chooses the display configuration.

Runtime kernel dependencies are limited to mainline Linux USB, USB networking,
CDC-NCM, DRM, media, V4L2, and videobuf2 modules.

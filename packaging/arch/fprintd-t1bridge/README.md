# fprintd-t1bridge

This package replaces Arch's `fprintd` with the same public interfaces plus one narrow compatibility fix: any libfprint driver that advertises native duplicate detection begins enrollment directly instead of requiring a separate identify operation first, and reports only the driver's real enrollment stages. Drivers that do not advertise that capability keep the upstream flow. It deliberately depends on the exact `libfprint-t1bridge` package version and release so the two compatibility packages cannot drift apart on an installed system.

Rebuild the package whenever Arch updates `fprintd`. Remove it once upstream fprintd honors `FP_DEVICE_FEATURE_DUPLICATES_CHECK` before starting enrollment.

The private compatibility watch compares Arch's current package version with `_arch_version` and verifies that the pinned source still accepts the patch.

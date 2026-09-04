# libfprint-t1bridge

This package replaces Arch's `libfprint` with the same public ABI plus the
T1Bridge driver. It intentionally affects the whole system, including plain
Arch installations; the core `t1bridge` package does not depend on it.

Rebuild the package whenever Arch updates `libfprint` or changes the
`libfprint-2.so.2` ABI. Remove this compatibility package once both upstream
libfprint and Arch ship the T1Bridge driver.

The private CI workflow `libfprint-watch.yml` compares Arch's current package
version with `_arch_version` in `PKGBUILD` and verifies that the pinned source
still accepts the complete T1Bridge patch. An Arch update fails that gate until
the source pin, tracked Arch version, patch, and hardware validation are
reviewed together.

`0002-Use-relative-test-helper-path.patch` is packaging-only. Keep it separate
when regenerating the driver patch; otherwise libfprint embeds its checkout
path and the alternate-path release comparison fails.

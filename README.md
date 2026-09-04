# T1Bridge

T1Bridge is a Linux support stack for the Apple T1 iBridge services used by
Touch ID and the Touch Bar.

The repository is in private, pre-release development. Private candidate Arch
packages exist, but no public repository or supported release exists yet and
interfaces may change until the first release.

## Hardware scope

T1Bridge targets the four Touch Bar T1 models: MacBookPro13,2,
MacBookPro13,3, MacBookPro14,2, and MacBookPro14,3. Current private hardware
validation is on MacBookPro13,3. MacBookPro14,3 validation is deferred until
that owned machine has Omarchy installed; neither MacBookPro13,2 nor
MacBookPro14,2 is currently verified.

The architecture, hardware acceptance runbook, and versioned interface
contracts are in [`docs/`](docs/).

## Package boundaries

T1Bridge owns T1 hardware support, protected machine-data import and recovery,
the fingerprint backend, and the default Touch Bar. Its core does not depend on
Omarchy or the separately packaged libfprint/fprintd integration.

Standard fprintd tools provide fingerprint management. A reusable management
TUI and a baseline desktop-controls provider are planned as separate optional
packages. Omarchy owns installer preservation, automatic setup, menus, themes,
and HUD integration. Custom Touch Bar renderers remain user-selected programs,
not bundled presets.

Maintained by Andrew Boyd.

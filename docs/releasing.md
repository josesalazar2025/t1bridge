# Private release candidates

The `Private release candidate` workflow builds only an existing signed
`v<package-version>` tag. It creates one deterministic core source archive,
requires both core PKGBUILDs to pin that archive's SHA-256, and builds the core,
DKMS, libfprint, and fprintd compatibility packages twice. It stops unless all four
unsigned packages are byte-identical. Both jobs use a pinned
Arch container and one dated Arch Linux Archive snapshot so the toolchain and
package inputs do not drift between runs.

Before signing, the build job installs all four candidates into an isolated
Arch root, applies their systemd presets and state declarations, reinstalls the
second byte-identical build, deactivates the preset units, and removes all four
packages. It requires package-owned files to disappear while protected machine
data and user renderer selection remain.

Signing is a separate job behind the `private-release` GitHub Environment. The
environment requires owner approval and contains only a replaceable signing
subkey, its passphrase, and the primary and subkey fingerprints. The job
verifies the unsigned manifest before importing the subkey, verifies the exact
primary and subkey fingerprints, requires the unchanged source tag to carry a
valid signature from that key, signs the packages and pacman database, and then
destroys the temporary keyring before creating a release. It refuses to create
a release if the repository is public or the tag already has a release.
Candidates remain drafts, so making the repository public later cannot expose
one without a separate reviewed promotion after the release gate passes.

The owner-controlled primary package-signing key remains a passphrase-encrypted
document in a private 1Password vault. It is never imported by CI or exposed to
an automated CLI. Keep a separate encrypted recovery copy and revocation
certificate. To rotate CI signing authority, add a new subkey and distribute
the updated public key while releases still use the old subkey. Switch CI only
after clients have imported it, then revoke the old subkey. If a key is
compromised, stop releases and require the documented explicit key-refresh
recovery path before resuming.

Required environment values:

- variable `T1BRIDGE_SIGNING_PRIMARY_FINGERPRINT` — exact uppercase primary
  fingerprint that downstream clients pin and locally trust;
- variable `T1BRIDGE_SIGNING_SUBKEY_FINGERPRINT` — exact uppercase fingerprint
  of the secret signing subkey;
- secret `T1BRIDGE_SIGNING_SUBKEY` — armored export containing the public
  primary stub and only the replaceable secret signing subkey; and
- secret `T1BRIDGE_SIGNING_SUBKEY_PASSPHRASE` — subkey export passphrase.

Private GitHub release assets are not anonymously consumable by pacman. The
hosted clean-install acceptance remains open until an owner-approved private
transport is selected or the Phase 5 gate authorizes public release assets.

# Releasing packages

Documentation changes do not require new packages. Build each package once;
the install checks and signing job consume those same artifacts.

## GitHub signing

The `release` environment permits workflow runs from `main` and requires
approval from the maintainer. Administrator bypass is disabled. Self-approval
is allowed so the maintainer can both start and approve a release.

Only the replaceable signing subkey and its passphrase are environment secrets:
`T1BRIDGE_SIGNING_SUBKEY` and `T1BRIDGE_SIGNING_SUBKEY_PASSPHRASE`.
The primary private key stays outside GitHub. Public fingerprints are stored
as `T1BRIDGE_SIGNING_PRIMARY_FINGERPRINT` and
`T1BRIDGE_SIGNING_SUBKEY_FINGERPRINT` environment variables.

1. Update package versions/releases as needed and re-pin the source archive
   in both core and DKMS recipes before committing. The workflow checks those
   pins against the exact release tree.
2. Create and push an annotated, signed `v<version>` tag matching the core
   package version. Use the approved release key; do not move an existing tag.
3. Run **Release candidate** from the `main` branch, set `ref` to that tag,
   and enable `ci_sign`. The unsigned-only mode instead takes a full commit
   SHA and does not access signing secrets.
4. After the single build and install checks, review the commit, tag and run
   before approving the `release` environment. The signing job verifies the
   exact artifact manifest and tag signature, then signs packages and repository
   databases. It rejects an exported primary private key.
5. Review the resulting **draft** GitHub release before publishing. This job
   does not upload to the package host; publishing to `linux.standardagents.ai`
   remains a separate step using the signed artifacts, without rebuilding.

Environment configuration and secret presence are not proof of a successful
CI signing run. Confirm that first run before treating the path as validated.

## Key custody and rotation

Keep the encrypted primary key, recovery copy and revocation certificate
outside CI. To rotate signing authority, add a replacement subkey and distribute
the updated public key before switching CI. Revoke the old subkey after clients
can verify its replacement. If a key is compromised, stop signing and require
an explicit trusted-key refresh before resuming releases.

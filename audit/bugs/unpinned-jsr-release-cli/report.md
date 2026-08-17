# Release workflow runs an unpinned JSR CLI in the npm publishing workspace

- Project: scure-btc-signer
- Commit/version: 68b2fad4ef8232302c6239c00902def1f511c974
- Category: supply chain
- Severity: Medium — a compromised latest CLI could alter an OIDC-published npm artifact
- Reproduction: static — release workflow and active `jsr.json` path reviewed
- Confirmed: code-review
- Attacker model: compromise of the latest globally installed `jsr` package
- Default config affected: yes for releases
- Reported upstream: no
- Disclosure: no published contact found (see statistics/disclosure-contacts.md entry for `scure-btc-signer`; source https://github.com/paulmillr/scure-btc-signer/blob/master/SECURITY.md, checked 2026-08-12)

## Summary

The reusable release workflow builds, performs an npm dry run, globally installs unpinned `jsr`, publishes to JSR, and then stages the same workspace for npm Trusted Publishing. The latest JSR CLI executes after the dry run with an opportunity to mutate code or metadata later published with valid provenance.

## Suggested fix

Pin the CLI in the lockfile, invoke it with `--no-install`, and publish both registries from separate clean workspaces or one immutable hashed tarball.

## Upstream status (2026-08-10)

The current shared jsbt workflow at `5320e209ca8cc9b1b0b569675e164bdd2a139d71` installs `jsr@0.14.3`. The original unversioned-latest condition is fixed; integrity pinning remains a hardening suggestion.

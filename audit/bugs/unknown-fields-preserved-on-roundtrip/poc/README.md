# PoC: 2026-08-05-unknown-fields-preserved-on-roundtrip

Target: `@scure/btc-signer` @ `68b2fad4ef8232302c6239c00902def1f511c974`.
Finding: `findings/subagent-1/2026-08-05-unknown-fields-preserved-on-roundtrip.md`.

Safety: generated valueless keys and regtest-shaped transactions only; nothing
is broadcast; no network access needed at runtime.

## Run

The PoC imports the library sources (TypeScript) directly, so it needs
node >= 20.19 with type stripping (node 22 works) and the repo's runtime
dependencies present in the worktree (`node_modules`; see finding for how the
flat `package-lock.json` set was fetched).

```sh
# from this directory, with the worktree at /path/to/worktree:
BTC_SIGNER_DIR=/path/to/worktree node --no-warnings poc.ts

# or with Docker (mount worktree at /w):
docker run --rm -v /path/to/worktree:/w -v $PWD:/p -w /p node:22 node --no-warnings poc.ts
```

Expected: every check prints `ok`; exit code 0. A `FAIL` line and exit code 1
mean the bug is fixed (or the library changed).

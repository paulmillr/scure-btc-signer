# PoC: MuSig2 secnonce reuse -> full key extraction

Finding: `2026-08-05-musig2-secnonce-single-use-contract.md` (same identifier, in the
findings directory). Reviewed commit `68b2fad4ef8232302c6239c00902def1f511c974`
(`@scure/btc-signer` 2.2.0).

## Contents

- `poc-secnonce-reuse.ts` — self-contained demonstration:
  1. 2-of-2 session setup (victim + attacker/coordinator), canonical `sortKeys`.
  2. Victim generates one nonce pair; the 97-byte secnonce is "persisted" via
     `structuredClone` (stand-in for DB/JSON storage between MuSig2 rounds).
  3. Attacker runs 3 sessions with distinct messages/nonces; victim signs each
     time with a fresh copy of the persisted secnonce (the in-place zeroization
     at `src/musig2.ts:615` never touches the persisted copy).
  4. Attacker solves the 3x3 linear system mod n and recovers the victim's
     secret key (and `k1, k2`); verifies the extraction against the victim pubkey.
  5. Negative evidence: same-buffer reuse throws (fail-fast), zeroization shape,
     and same-session copy reuse yields an identical psig (no leak).
- `run.log` — captured output of one run.

All keys are generated locally at runtime; nothing touches the network or real funds.

## How to run

Requires a Node with TypeScript type-stripping (>= 22.6; validated on v24.19.0)
and the reviewed worktree with `npm install`ed dependencies
(`@noble/curves`, `@noble/hashes`, `@scure/base`, `micro-packed`).

```
SCURE_WORKTREE=/path/to/scure-btc-signer-worktree \
  node --no-warnings poc-secnonce-reuse.ts
```

`SCURE_WORKTREE` defaults to the review worktree path used during validation.
Expected result: exit code 0, final line
`POC OK: key extraction demonstrated; fail-fast and same-session no-leak confirmed.`,
with `MATCH : true` for the extracted key.

## Validation environment used

- Node v24.19.0 (nodejs.org tarball); dependencies at the exact
  `package-lock.json` versions (integrity-verified tarballs).
- Project BIP327 suite: 25/25 tests pass (`node --no-warnings test/bip327-musig2.test.ts`).
- Vector files byte-identical to bitcoin/bips @ `e7263a4cfe500c89e4269889244606953691ca33`.

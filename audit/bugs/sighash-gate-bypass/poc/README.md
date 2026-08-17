# PoC: post-signing mutation-gate bypass via absent-field append

Target: `@scure/btc-signer` @ `68b2fad4ef8232302c6239c00902def1f511c974`
Finding: `2026-08-05-sighash-gate-bypass.md`

## Contents

- `poc.mts` — four deterministic scenarios on generated keys:
  - S1: sign `SIGHASH_ALL`, then append `sighashType=NONE` to the signed input
    via `updateInput`; the mutation gate reopens, an output is added, and the
    victim's signature no longer verifies; the library still finalizes/extracts
    the consensus-invalid transaction.
  - S2: append `requiredHeightLocktime` to a signed input; `lockTime` shifts
    after signing; the existing signature is invalidated.
  - S3: hostile PSBT carries `sighashType=0x40` beside a partial signature;
    after `fromPSBT`, every mutation method throws
    `Wrong signature hash output type: 0` (permanent gate freeze).
  - S4: same append primitive on a signed taproot input; stored `0x80`
    (`DEFAULT|ANYONECANPAY`, invalid per BIP341) freezes the gate.
- `expected_output.txt` — observed output.
- `state_machine_extended.mts` / `state_machine_extended_output.txt` — the
  extended allowed-vs-blocked gating matrix (SINGLE|ANYONECANPAY index
  stability, NONE semantics, injected-external-signature direction, 0x80
  taproot rejection/freeze) supporting the review-notes coverage table.

## Reproduce

From the worktree root after `npm install` (Node >= 22):

```sh
cp poc/2026-08-05-sighash-gate-bypass/poc.mts poc.mts
node --no-warnings poc.mts
cp poc/2026-08-05-sighash-gate-bypass/state_machine_extended.mts sm.mts
node --no-warnings sm.mts
```

Root cause: `mergeKeyMap` (`src/psbt.ts:875-878`) only enforces the
`PSBTInputUnsignedKeys` change-check when the field was already present before
signing; `inputSighash`/`signStatus` (`src/transaction.ts:860-898`) and
`lockTime` (`src/transaction.ts:819-837`) then trust the newly appended values.

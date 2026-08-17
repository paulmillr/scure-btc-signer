# Post-signing mutation-gate bypass: counterparties can append commitment-relevant PSBT fields to signed inputs

- **Severity:** Low — counterparty can append commitment-relevant fields after signing, invalidating the tx (griefing/DoS); no theft path without a re-sign
- **Confidence:** High (deterministic reproducer)
- **Reviewed revision:** `68b2fad4ef8232302c6239c00902def1f511c974` (`@scure/btc-signer` 2.2.0+)
- **PoC:** `2026-08-05-sighash-gate-bypass/`

## Affected files and lines

- `src/psbt.ts:875-878` — `mergeKeyMap` change-check for non-keyed fields requires `_cur[k] !== undefined`; fields **absent at signing time are freely appendable** on signed inputs.
- `src/psbt.ts:334-342` — `PSBTInputUnsignedKeys` replace/remove allowlist; the comment at `src/psbt.ts:335-336` documents the append behavior ("can still append previously absent metadata ... when they don't conflict").
- `src/transaction.ts:993-1016` — `updateInput` installs `allowedFields = PSBTInputUnsignedKeys` for signed inputs.
- `src/transaction.ts:860-873` — `inputSighash` reads the (newly appended) `sighashType` to drive the gate.
- `src/transaction.ts:876-898` — `signStatus` recomputes add/update permissions from `inputSighash`.
- `src/transaction.ts:819-837` — `lockTime` getter recomputed from appended `requiredHeightLocktime` / `requiredTimeLocktime` (BIP370).
- `src/transaction.ts:1064-1087` — `addOutput`/`updateOutput` rely on the same `signStatus` gate.

## Root cause and violated invariant

The library's only post-approval protection is the `signStatus`/`inputSighash`
mutation gate: once an input is signed, `addInput`/`addOutput` are blocked
unless existing signatures' sighash flags permit it, and `updateInput` /
`updateOutput` are restricted to `PSBTInputUnsignedKeys` /
`PSBTOutputUnsignedKeys`. The gate is computed from **stored PSBT fields**, not
from the signatures themselves.

`mergeKeyMap` enforces the allowlist with:

```ts
} else if (cannotChange && k in _val && _cur && _cur[k] !== undefined) {
  if (!equalBytes(vC.encode(_val[k]), vC.encode(_cur[k])))
    throw new Error(`Cannot change signed field=${k}`);
}
```

The `_cur[k] !== undefined` conjunct means: if a field was **absent** when the
victim signed, a counterparty can append it later, even though the same field
is frozen had it been present. Two appended fields are commitment-relevant:

1. **`sighashType`** — feeds `inputSighash` → `signStatus`. Appending
   `sighashType=NONE` to an input that was signed with the default
   (SIGHASH_ALL, field absent) reopens `addOutput`. The victim's existing
   signature still commits to the original output set, so the mutation silently
   invalidates it; the library then finalizes and `extract()`s a
   consensus-invalid transaction without warning. Appending garbage values
   (e.g., `0x40`, or `0x80` on a taproot input) makes `inputSighash` produce
   `sigOutputs=0`, and `signStatus` throws `Wrong signature hash output type:
   0` on **every** subsequent `addInput`/`addOutput`/`updateInput`/
   `updateOutput` call — a permanent freeze of the transaction object.
2. **`requiredHeightLocktime` / `requiredTimeLocktime`** — feed the `lockTime`
   getter (BIP370), which is committed by all three sighash schemes. Appending
   one after signing changes the transaction's lockTime and invalidates every
   existing signature.

Violated invariant (from the task): *signed state mutable only through the
documented flag-permitted channels* — the documented channel
(`PSBTInputUnsignedKeys` on signed inputs) is bypassed for absent fields.

## Attacker model, prerequisites, attacker-controlled path

Attacker: a PSBT counterparty (coinjoin/swap/multisig participant, or a
coordinator) who can hand the victim's application input-update maps; per the
task model, the attacker controls "PSBT contents and update calls from
counterparties, plus the ordering of API calls a victim application makes".

Prerequisites: the victim signs at least one input through this library
(`signIdx`/`sign`), and the victim's application applies counterparty-supplied
updates via `updateInput` (or imports a counterparty-mutated PSBT that contains
appended fields and then calls any mutation method).

Path: victim signs input 0 (SIGHASH_ALL, `sighashType` absent) → attacker
calls/persuades `updateInput(0, { sighashType: 2 })` → append succeeds →
`signStatus().addOutput` now true → attacker adds an output / shifts lockTime
via `requiredHeightLocktime` → victim's signature no longer matches the final
transaction → `finalize()`/`extract()` succeed anyway → the victim broadcasts
(or holds) a consensus-invalid transaction.

## Concrete impact

- **Availability / integrity (demonstrated):** any signed transaction can be
  turned into a consensus-invalid one after approval by a counterparty. The
  library reports success through `finalize`/`extract`, so the failure surfaces
  only at broadcast. In time-sensitive protocols (fee windows, HTLC timeouts)
  this is a griefing/liveness vector.
- **Gate freeze (demonstrated):** a hostile `sighashType` (e.g., `0x40` — a
  forkid-style bit, or `0x80` on taproot) stored next to a partial signature
  makes every mutation method throw, wedging the transaction object.
- **No direct theft demonstrated:** every bypassed mutation invalidates the
  existing signature rather than redirecting value, because the victim's
  signature was produced with the default ALL commitment. Theft would require
  the victim to *re-sign* after the mutation, which is the application's
  own verification responsibility.

## Reproduction / observed output

See PoC `2026-08-05-sighash-gate-bypass/` (`poc.mts`, `expected_output.txt`).
Key lines:

```
S1) pre-append addOutput: blocked (expected protection)
    updateInput(0,{sighashType:NONE}) on signed input: ACCEPTED
    post-append addOutput: ALLOWED  <-- gate bypassed
    victim signature valid against mutated tx? false
    library finalizes+extracts the now consensus-INVALID tx, bytes: 223
S2) lockTime before=0 after= 700000
    victim signature valid against lockTime-mutated tx? false
S3) stored sighashType after fromPSBT: 64
    addInput/addOutput/updateInput/updateOutput: Wrong signature hash output type: 0
    signIdx: Input with not allowed sigHash=64. Allowed: 1
S4) append sighashType=ALL on taproot-signed input: ACCEPTED
    0x80 addOutput: Wrong signature hash output type: 0
```

Signature validity is checked by recomputing the BIP143 digest over the mutated
transaction with the library's own (differentially validated) `preimageWitnessV0`
and verifying with `@noble/curves` — independent of the library's own gate.

## Remediation guidance

- In `mergeKeyMap`, treat *adding* a commitment-relevant field on a signed
  input the same as changing it: extend the change-check to
  `k in _val && (cannotChange)` regardless of prior presence for
  `sighashType`, `requiredTimeLocktime`, `requiredHeightLocktime`,
  `witnessUtxo`, `nonWitnessUtxo`, `redeemScript`, `witnessScript`,
  `tapInternalKey`, `tapMerkleRoot`, `tapLeafScript` — or maintain an explicit
  allowlist of appendable-after-signing metadata (hash preimages,
  `bip32Derivation`, `porCommitment`, `proprietary`).
- Alternatively/additionally, derive `inputSighash` from the trailing sighash
  byte of the actual stored signatures (and `validateSigHash`-range-check it)
  instead of from the free-standing `sighashType` field, so the gate always
  matches the real commitment; reject stored `sighashType` values outside the
  seven valid combinations at PSBT ingestion.
- Consider rejecting `finalize`/`extract` when a stored `sighashType`
  contradicts the sighash byte embedded in the input's signatures.

## References

- BIP174 (PSBT), BIP370 (PSBTv2; `PSBT_IN_REQUIRED_*_LOCKTIME` and locktime
  derivation), BIP371 (`sighashType` for taproot), BIP341 §"Common signature
  message" (valid `hash_type` values: 0x00–0x03, 0x81–0x83).
- `src/transaction.ts:1466-1472` documents related blunt-API risks for `sign`.

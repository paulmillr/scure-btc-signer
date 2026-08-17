# `mergeKeyMap` allows adding previously-absent fields to signed inputs (sighash/locktime injection invalidates existing signatures)

- **Severity:** Low — post-sign field injection invalidates signatures (DoS/bricking in multisig); needs a coordinator update after the victim signs
- **Confidence:** Confirmed (deterministic PoC)
- **Reviewed revision:** `68b2fad4ef8232302c6239c00902def1f511c974`

## Affected files and lines

- `src/psbt.ts:875-878` — the `cannotChange` guard for non-keyed fields only
  fires when `_cur[k] !== undefined`. A field that is **absent** on the signed
  input can be added freely, even though it is not in `PSBTInputUnsignedKeys`.
- `src/psbt.ts:334-342` — `PSBTInputUnsignedKeys` (the post-sign allowlist:
  `partialSig`, `finalScriptSig`, `finalScriptWitness`, `tapKeySig`,
  `tapScriptSig`).
- `src/transaction.ts:999-1004` — `updateInput` applies that allowlist whenever
  `signStatus()` marks inputs signed.
- `src/transaction.ts:819-837` — `lockTime` getter derives the effective
  locktime from per-input `requiredTimeLocktime`/`requiredHeightLocktime`.

## Root cause and violated invariant

For a signed input, `updateInput(idx, update)` restricts changes to
`PSBTInputUnsignedKeys` — but only for fields that already exist or are being
removed. `mergeKeyMap`'s equality guard
(`else if (cannotChange && k in _val && _cur && _cur[k] !== undefined)`)
silently passes when `_cur[k] === undefined`, so an attacker (or a buggy
coordinator round) can **add** `sighashType`, `requiredTimeLocktime`,
`requiredHeightLocktime`, `witnessUtxo`, `porCommitment`, or any keyed-field
entries (`bip32Derivation`, `tapBip32Derivation`, `tapLeafScript`, …) to an
input that already carries partial signatures. Violated invariant: *"merge/
update … cannot replace committed data, discard security-relevant unknowns
silently, … or treat a partial signature as authorization for changed state"* —
here state the signature semantically depends on (locktime, sighash type)
changes after signing.

Note the same injection is also possible through `fromPSBT` alone (a coordinator
adds `requiredTimeLocktime` to a signed input between rounds); the missing
"signed input must not gain locktime/sighash fields" consistency check is
global, not only in `mergeKeyMap`.

## Attacker-controlled path

Coordinator/cosigner returns an updated PSBT or update object after the victim
(or another cosigner) has signed → victim's app applies `updateInput()` →
`mergeKeyMap()` accepts the new field because it was absent before →
`tx.lockTime` / `inputType.sighash` change.

## Concrete impact

1. **Signature invalidation (DoS / bricking).** PoC: input signed at
   `lockTime = 0`; `updateInput(0, { requiredTimeLocktime: 500000000 })`
   succeeds; `tx.lockTime` flips to 500000000; the previously created
   `partialSig` no longer matches the transaction; `extract()` emits a final
   transaction whose signature is invalid on-chain. In an m-of-n multisig this
   can lock funds until the affected cosigner re-signs.
2. **Contradictory sighash metadata.** `updateInput(0, { sighashType: NONE })`
   on an input already carrying a `SIGHASH_ALL` partialSig is accepted; a later
   signer with permissive `allowedSighash` produces a mixed-sighash input that
   cannot finalize to a valid script.
3. **Contradictory final state.** On a finalized input,
   `updateInput(0, { finalScriptSig })` adds a non-empty `finalScriptSig`
   alongside the existing `finalScriptWitness`; `extract()` serializes both,
   producing an input that is invalid for segwit-v0 (scriptSig must be empty).

Protections that **do** hold (verified): changing an already-present field
(`witnessUtxo`, `sequence`, `sighashType` once set) throws
`Cannot change signed field`; same-key-different-value keyed merges throw
`keyMap(...): same key`; removing fields outside the allowlist throws
`Cannot remove signed field`.

## Reproduction / observed output

PoC: `poc/subagent-1/2026-08-05-mergekeymap-post-sign-field-injection/poc.ts`:

```text
ok  post-sign ADD sighashType (absent before) ACCEPTED
ok  post-sign ADD requiredTimeLocktime ACCEPTED, lockTime changes, sig invalidated
    lockTime changed 0 -> 500000000 after signing; extract produced tx with stale sig
ok  post-sign ADD requiredHeightLocktime ACCEPTED, lockTime changes
ok  finalized input can gain finalScriptSig ALONGSIDE finalScriptWitness
    extract ok, input has BOTH scriptSig=51 and witness
ok  post-sign CHANGE witnessUtxo rejected (Cannot change signed field)
ok  post-sign CHANGE sequence rejected (Cannot change signed field)
ok  keyed same-key different-value rejected (keyMap: same key=...)
```

## Remediation guidance

In `mergeKeyMap`, when `allowedFields` is provided (signed state) and a field is
not in it, reject any `k in _val` whose encoded value differs from `_cur[k]` —
including the `_cur[k] === undefined` case (treat "absent" as a committed value
for locktime/sighash-relevant fields). Independently, `fromPSBT`/`validateInput`
could reject inputs that carry both partial signatures and newly-introduced
`requiredTimeLocktime`/`requiredHeightLocktime`/`sighashType`, matching the
"signer checks" spirit of BIP174.

## References

- BIP174 §"Data Signers Check For"; BIP370 locktime determination.
- `src/psbt.ts:323-342` comments ("Can be modified even on signed input").

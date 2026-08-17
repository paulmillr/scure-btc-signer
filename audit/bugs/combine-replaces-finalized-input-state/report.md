# `Transaction.combine()` silently overwrites this side's committed input state (other-wins), including `finalScriptWitness`, with no equality check

- **Severity:** Low — combine() silently replaces committed input state (DoS / witness choice); attacker must supply a PSBT of the same pinned unsigned tx
- **Confidence:** Confirmed (deterministic PoC)
- **Reviewed revision:** `68b2fad4ef8232302c6239c00902def1f511c974`

## Affected files and lines

- `src/transaction.ts:1675-1676` — `combine()` merges each input/output via
  `updateInput(i, other.inputs[i], /* _ignoreSignStatus */ true)`.
- `src/transaction.ts:999-1004` — with `_ignoreSignStatus = true`,
  `allowedFields` stays `undefined`.
- `src/psbt.ts:829,875-878` — with `allowedFields === undefined`,
  `cannotChange` is always falsy: neither removal protection nor the
  encoded-equality "Cannot change signed field" guard runs. Non-keyed fields
  resolve by plain object spread (`src/psbt.ts:823`: `res = { ..._cur, ..._val }`)
  — **other's value wins with no comparison**.

## Root cause and violated invariant

`combine()` first pins the two sides to the same unsigned transaction
(`src/transaction.ts:1648-1666`: version, lockTime, map counts, and
`equalBytes(this.unsignedTx, other.unsignedTx)`), which makes same-transaction
merging safe for committed *transaction* data. But per-input PSBT state that is
**not** part of `unsignedTx` — `finalScriptWitness`, `finalScriptSig`,
`witnessUtxo`, `nonWitnessUtxo`, `sighashType`, locktimes — is then merged
other-wins with no equality verification. Violated invariant: *"Merge/update/
finalize cannot replace committed data … last-writer-wins behavior"* on
security-relevant fields. Two PSBTs for the same unsigned tx can legitimately
carry different final witnesses (different multisig signature subsets, different
tapleaf paths) — or a malformed-but-well-formed-bytes witness supplied by a
malicious party — and the combiner's own finalized witness is silently replaced.

## Attacker-controlled path

Victim combines their (partially-)finalized PSBT with an attacker-supplied PSBT
of the same unsigned transaction (`tx.combine(other)` or
`PSBTCombine([victim, attacker])`). `other.inputs[i]` replaces conflicting
non-keyed fields of the victim's input.

## Concrete impact

- PoC: victim finalizes input 0 (valid `finalScriptWitness` W_A); attacker's
  PSBT carries the same unsigned tx with a replaced witness W_B (well-formed
  bytes, not necessarily a valid satisfaction). After `combine()`,
  `this.inputs[0].finalScriptWitness === W_B`. Victim's `extract()` emits an
  invalid transaction (DoS); where both witnesses are valid satisfactions, the
  attacker chooses which one is broadcast.
- The same path can create contradictory pairs (`partialSig` from `cur` +
  `finalScriptWitness` from `val`) that `extract()` tolerates but which violate
  the BIP174 finalizer invariant that final fields replace partial ones.
- Not exploitable for txid-binding forgery: `other` must itself survive
  `Transaction.fromPSBT`, which runs `validateInput` (see companion finding
  `2026-08-05-update-path-skips-nonwitnessutxo-txid-binding.md`), and
  `unsignedTx` equality pins outpoints/outputs/amounts.

## Reproduction / observed output

PoC: `poc/subagent-1/2026-08-05-combine-replaces-finalized-input-state/poc.ts`:

```text
ok  combine REPLACES this finalized witness with other (no equality check on committed final state)
    this.finalScriptWitness silently overwritten by other.combine (other-wins)
ok  combine different unsigned tx rejected
ok  combine different lengths rejected
ok  conflicting keyed/global fields (xpub, unknown with allowUnknown) still rejected
```

## Remediation guidance

In `combine()`, when both sides have the same non-keyed field, require encoded
equality (reuse the `mergeKeyMap` `cannotChange` check with a signed-input
allowlist, or explicitly compare `finalScriptWitness`/`finalScriptSig`/
`witnessUtxo`/`nonWitnessUtxo` before overwriting), and fail the combine on
conflict instead of silently preferring `other`. At minimum, document the
other-wins semantics on `combine()`/`PSBTCombine()`.

## References

- BIP174 §Combiner role semantics.
- `src/psbt.ts:809-906` (`mergeKeyMap`), `src/transaction.ts:1643-1678`
  (`combine`), `src/transaction.ts:1698-1704` (`PSBTCombine`).

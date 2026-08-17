# `bip174jsCompat` zero-input transactions cannot be serialized: `toPSBT(0)` throws input-map count mismatch

- **Severity:** Low (functional bug, fail-closed)
- **Confidence:** Confirmed (deterministic PoC)
- **Reviewed revision:** `68b2fad4ef8232302c6239c00902def1f511c974`

## Affected files and lines

- `src/transaction.ts:808-811` — `toPSBT()` with `opts.bip174jsCompat` pushes an
  empty map onto both `inputs` and `outputs` when they are empty.
- `src/psbt.ts:653` — `_RawPSBTV0.inputs` is
  `P.array('global/unsignedTx/inputs/length', PSBTInputCoder)`: on encode it
  requires `inputs.length === unsignedTx.inputs.length` exactly.
- `src/psbt.ts:771-775` — `validatePSBT`'s "one trailing empty input map"
  carve-out, which is unreachable on both decode (input maps are count-framed)
  and encode (the struct length check throws first).

## Root cause

For a transaction with zero inputs, `bip174jsCompat` appends one empty input
map (to mimic bip174js's quirk), but the rebuilt `unsignedTx` has zero inputs,
so the raw v0 writer fails with
`Writer(inputs): Wrong length: 0 len=../global/unsignedTx/inputs/length exp=1`.
The output-side quirk works (outputs are end-of-stream framed, and the
`validatePSBT` outputs carve-out accepts one trailing empty map), so
1-in/0-out works, while 0-in/0-out and 0-in/1-out always throw. The failure is
a thrown `Error` at serialization time — fail-closed, no security impact — but
it makes the opt-in compat mode unusable for input-less PSBTs and shows the
input-side carve-out is dead code.

## Reproduction / observed output

PoC: `poc/subagent-1/2026-08-05-bip174jscompat-zero-input-encode-throws/poc.ts`:

```text
ok  bip174jsCompat 0-in/0-out toPSBT(0) THROWS on encode (input-map count mismatch)
ok  bip174jsCompat 0-in/1-out toPSBT(0) THROWS on encode
ok  bip174jsCompat 1-in/0-out toPSBT(0) roundtrip ok
ok  strict (non-compat) 0-in/1-out toPSBT(0) roundtrip ok
```

## Remediation guidance

Either drop the input-side push for zero-input transactions (keep the compat
quirk outputs-only, matching bip174js behavior for tx without outputs), or
teach `_RawPSBTV0.inputs` to tolerate the single trailing empty map on encode
(mirror the `validatePSBT` outputs carve-out). If the input-side quirk is
intentionally unsupported, remove the dead `inputsLeft` carve-out in
`validatePSBT` and document the limitation.

## References

- BIP174 `<psbt> := <magic> <global-map> <input-map>* <output-map>*`.
- `src/psbt.ts:765-781` (carve-out comment and code), `src/transaction.ts:198-201`
  (`bip174jsCompat` option).

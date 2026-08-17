# Unknown PSBT fields are preserved across `fromPSBT`→`toPSBT` even with `allowUnknown: false` (README claims stripping)

- **Severity:** Low — covert-channel / metadata-smuggling risk to downstream consumers, not direct fund loss; README overclaims stripping
- **Confidence:** Confirmed (deterministic PoC)
- **Reviewed revision:** `68b2fad4ef8232302c6239c00902def1f511c974`

## Affected files and lines

- `src/psbt.ts:502-505` — `PSBTKeyMap` decode collects every unrecognized key
  type into `out.unknown` unconditionally (no option consulted).
- `src/psbt.ts:741-756` — `cleanPSBTFields()` copies `unknown` through
  unconditionally (`if (k !== 'unknown') { …filter… } out[k] = _lst[k]`).
- `src/psbt.ts:880-904` — `mergeKeyMap()` is the **only** place `unknown` is
  stripped, and only when `allowUnknown` is false. It runs on
  `addInput`/`updateInput`/`updateOutput`/`combine`, never on a pure
  parse→serialize round trip.
- `src/transaction.ts:704-741` (`fromPSBT`) and `src/transaction.ts:744-816`
  (`toPSBT`) — neither consults `opts.allowUnknown`.
- `README.md:520` — "We strip 'unknown' keys inside PSBT".

## Root cause and violated invariant

The `allowUnknown` option (default `false`) is documented as *"Preserve unknown
PSBT key/value pairs instead of stripping them"*, and the README claims unknown
keys are stripped. In fact stripping only happens when a map passes through
`mergeKeyMap`. A victim application that parses a PSBT and re-serializes it (a
very common coordinator round trip, including `Transaction.clone()` at
`src/transaction.ts:1679-1682`, implemented as `fromPSBT(toPSBT())`) forwards
every unknown field to the next party regardless of the flag. Violated
invariant: *"Merge/update/finalize cannot … discard security-relevant unknowns
silently"* holds, but the dual — "unknowns are stripped by default" — does not.

## Attacker model and impact

The library's own README warns unknown PSBT fields can smuggle data to
backdoored wallets (and the task brief repeats that warning). An attacker
coordinator embeds arbitrary key/value payloads under unassigned key types; a
victim application using default options and a parse→forward flow relays them
verbatim to cosigners, including into their `unknown` arrays after those parties
parse. Because `combine()` with `allowUnknown: false` **does** strip, behavior
differs between two defensively-configured parties depending on which API shape
each uses — an inconsistency that is invisible at the type level. Impact is a
covert-channel/metadata-smuggling risk to downstream consumers, not direct fund
loss; hence Low.

## Reproduction / observed output

PoC: `poc/subagent-1/2026-08-05-unknown-fields-preserved-on-roundtrip/poc.ts`:

```text
ok  fromPSBT->toPSBT PRESERVES unknown global field with default opts (allowUnknown=false)
ok  unknown input-level field preserved across fromPSBT->toPSBT with default opts
ok  updateInput STRIPS unknown fields when allowUnknown=false
ok  updateInput PRESERVES unknown fields when allowUnknown=true
ok  proprietary fields (0xfc) are KNOWN fields: preserved everywhere (by design)
ok  combine with allowUnknown=false on receiver DROPS sender unknown fields silently
ok  combine conflicting unknown same-key different-value rejected (allowUnknown)
```

## Remediation guidance

Decide and document one policy. If stripping-by-default is intended (per
README.md:520), apply the same `unknown` filtering in `fromPSBT` (drop
`i.unknown`/`o.unknown`/`global.unknown` when `!opts.allowUnknown`) or in
`toPSBT`/`cleanPSBTFields`. If BIP174 pass-through is intended, fix the README
claim and the `allowUnknown` docstring to state that the flag only governs
mutation/combine paths.

## References

- BIP174: unknown/proprietary key pass-through is legal; wallets may ignore.
- `README.md:520` vs. behavior; `src/transaction.ts:210-212` (`allowUnknown`
  option doc).

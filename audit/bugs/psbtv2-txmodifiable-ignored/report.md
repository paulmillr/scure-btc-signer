# PSBTv2 `txModifiable` constraints are represented but not enforced

- Project: scure-btc-signer
- Commit/version: 68b2fad4ef8232302c6239c00902def1f511c974
- Category: collaborative PSBT integrity
- Severity: Low — signature commitments still prevent unauthorized valid mutation
- Reproduction: confirmed — imported PSBTv2 with `txModifiable=0` accepted `addOutput()` and continued advertising zero
- Confirmed: dynamically-reproduced
- Attacker model: collaborative PSBT participant relying on declared mutation restrictions
- Default config affected: yes for PSBTv2
- Reported upstream: no
- Disclosure: no published contact found (see statistics/disclosure-contacts.md entry for `scure-btc-signer`; source https://github.com/paulmillr/scure-btc-signer/blob/master/SECURITY.md, checked 2026-08-12)

## Summary

`txModifiable` exists in the PSBT schema, but input/output modification bits are not enforced by mutation APIs. Imported PSBTs declaring themselves immutable can still change; signing does not clear relevant flags, and `SIGHASH_SINGLE` does not set the corresponding global flag.

## Suggested fix

Enforce the flags in every input/output mutation path and update them atomically when signatures are added, following BIP370 signer requirements.

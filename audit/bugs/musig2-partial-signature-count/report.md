# MuSig2 aggregation accepts fewer partial signatures than participants

- Project: scure-btc-signer
- Commit/version: 68b2fad4ef8232302c6239c00902def1f511c974
- Category: MuSig2 correctness / denial of service
- Severity: Low — returns an invalid signature-shaped value; no forgery was established
- Reproduction: confirmed — supplied two-party model aggregates one partial and observes BIP340 failure
- Confirmed: dynamically-reproduced
- Attacker model: coordinator providing an incomplete partial-signature list
- Default config affected: yes
- Reported upstream: no
- Disclosure: no published contact found (see statistics/disclosure-contacts.md entry for `scure-btc-signer`; source https://github.com/paulmillr/scure-btc-signer/blob/master/SECURITY.md, checked 2026-08-12)

## Summary

`partialSigAgg()` requires a non-empty array of valid scalars but does not require its length to equal the session participant count. In a two-party model, one partial produces a 64-byte signature-shaped result that fails the BIP340 equation.

## Suggested fix

Bind aggregation to the session roster and reject any list whose count or signer identifiers differ from the complete expected participant set.

# Imported redeem, witness, and Taproot commitments are not fully cross-checked

- Project: scure-btc-signer
- Commit/version: 68b2fad4ef8232302c6239c00902def1f511c974
- Category: signing-session denial / metadata integrity
- Severity: Low — substituted metadata produces invalid witnesses rather than transferable signatures
- Reproduction: confirmed — independent model substituted a different Taproot leaf containing the same signer key
- Confirmed: dynamically-reproduced
- Attacker model: untrusted PSBT coordinator supplying wrapper or Taproot metadata
- Default config affected: yes for imported PSBTs
- Reported upstream: no
- Disclosure: no published contact found (see statistics/disclosure-contacts.md entry for `scure-btc-signer`; source https://github.com/paulmillr/scure-btc-signer/blob/master/SECURITY.md, checked 2026-08-12)

## Summary

Directly constructed inputs pass `checkScript()`, but `fromPSBT()` does not subsequently recheck every redeem-script, witness-script, Taproot internal-key, Merkle-root, leaf, and control-block relationship. The signer can sign a supplied leaf without reconstructing its root and verifying the resulting tweaked key against the actual P2TR prevout.

## Impact and fix

The resulting witness is invalid, causing signing-session denial and wasted hardware interaction. Recompute every imported wrapper commitment and Taproot control-block root against the authenticated previous output before exposing the input to signing.

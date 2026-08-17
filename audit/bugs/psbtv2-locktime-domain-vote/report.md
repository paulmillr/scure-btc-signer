# PSBTv2 resolves incompatible height/time locktime requirements by vote count

- Project: scure-btc-signer
- Commit/version: 68b2fad4ef8232302c6239c00902def1f511c974
- Category: PSBT interoperability / transaction integrity
- Severity: Low — produces invalid or policy-incorrect transactions rather than unauthorized spends
- Reproduction: confirmed — supplied audit models incompatible height and time requirements
- Confirmed: dynamically-reproduced
- Attacker model: collaborative PSBT participant supplying per-input locktime requirements
- Default config affected: yes for PSBTv2
- Reported upstream: no
- Disclosure: no published contact found (see statistics/disclosure-contacts.md entry for `scure-btc-signer`; source https://github.com/paulmillr/scure-btc-signer/blob/master/SECURITY.md, checked 2026-08-12)

## Summary

The implementation counts height and time requirements and selects the more common domain, using height on a tie. BIP370 requires the chosen domain to be supported by every input that specifies a locktime. It also defines strict height and time ranges that the implementation does not fully enforce.

## Suggested fix

Reject mixed incompatible domains, enforce height `1..499999999` and time `500000000..0xffffffff`, and test two-input conflicts before any signature commits to the chosen locktime.

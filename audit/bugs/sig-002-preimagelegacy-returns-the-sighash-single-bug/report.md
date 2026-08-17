# preimageLegacy returns the SIGHASH_SINGLE-bug 'hash of one' with reversed byte order vs consensus (0x00..01 instead of 0x01,0x00..)

- Project: scure-btc-signer
- Commit/version: 68b2fad4ef8232302c6239c00902def1f511c974
- Category: other
- Severity: Info — When legacy SIGHASH_SINGLE has no corresponding output (or the input index is out of range), consensus substitutes the well-known 'hash of one'.
- Reproduction: static — source-harness audit finding, no Docker PoC attached
- Confirmed: code-review
- Attacker model: not recorded — see Summary
- Default config affected: unknown
- Reported upstream: no
- Disclosure: no published contact found (see statistics/disclosure-contacts.md entry for `scure-btc-signer`; source https://github.com/paulmillr/scure-btc-signer/blob/master/SECURITY.md, checked 2026-08-12)

## Summary

When legacy SIGHASH_SINGLE has no corresponding output (or the input index is out of range), consensus substitutes the well-known 'hash of one'. The consensus-critical byte string fed to ECDSA is the uint256 internal little-endian form: 0x01 followed by 31 zero bytes. Bitcoin Core returns uint256::ONE and signs hash.begin() (raw internal bytes); Core's own functional test framework pins this exactly: test_framework/script.py LegacySignatureHash defines HASH_ONE = b'\x01' + b'\x00'*31 (the comment calls it 'Consensus-correct SignatureHash'). scure-btc-signer's private preimageLegacy instead returns P.U256BE.encode(_1n), i.e. 0x00*31 || 0x01 — the big-endian encoding of 1 — byte-reversed relative to consensus. Verified empirically in docker (.audit-tmp/check-sighash-edge.ts): scure output 0000...0001 vs consensus 0100...0000. Because ECDSA interprets the 32-byte digest as a big-endian integer, a signature made over scure's digest has z = 1 while Core verifies against z = 2^248, so such a signature would be consensus-invalid. Reachability is currently blocked on two levels: signIdx (transaction.ts:1362-1366) rejects SIGHASH_SINGLE with no matching output for every tx type before any preimage is computed, and preimageLegacy is TypeScript-private. It is only reachable through JS runtime reflection (as the repo's own tests do for other sighash types). Reported as a hardening/correctness note: any future refactor that exposes this helper (or downstream reflection users) would produce invalid signatures, and the stale byte order would be invisible to vector tests that never exercise the SINGLE-bug branch (repo tests only call it with SigHash.ALL).

## Exploit chain

Not exploitable today (private + guarded). Hypothetical: a downstream integration accesses (tx as any).preimageLegacy to coordinate an external signer for a SIGHASH_SINGLE-bug legacy input; the produced signature (over z = 1) is rejected by all Bitcoin Core nodes (which verify over z = 2^248), yielding an unspendable-looking UTXO until re-signed with the correct digest. No key recovery, no theft; temporary fund freeze only.

## Suggested fix

Return the consensus byte order: bytes([0x01, ...31 zero bytes]) (e.g. P.U256LE.encode(_1n)) instead of P.U256BE.encode(_1n); or delete/throw on this branch since signIdx already forbids it. Add a vector test exercising the SINGLE-bug branch to prevent silent regressions if the helper is ever exposed.

## Reproduction

Docker unit test: build a 1-input/0-output legacy (p2pkh witnessUtxo) Transaction, call (tx as any).preimageLegacy(0, script, 0x03); assert returned bytes equal 0x00..01 while consensus HASH_ONE (Bitcoin Core test_framework/script.py) is 0x01,0x00..; sign both digests with the same key via utils.signECDSA and show the scure-digest signature fails noble verification against the consensus digest and vice versa.

## Affected files

- `src/transaction.ts` (1115-1119): private preimageLegacy returns P.U256BE.encode(_1n) = 0x00*31 || 0x01 for SINGLE (or input index) out of range
- `src/transaction.ts` (1361-1366): signIdx throws for SINGLE with no matching output before preimageLegacy can be reached; TS-private method is reachable only via JS runtime reflection (tests use `(tx as any).preimageLegacy`, see test/basic.test.ts:268)

## Affected versions

v2.2.0 (commit 68b2fad4ef8232302c6239c00902def1f511c974, verified); earlier versions unverified

## Confidence

High (as recorded by the source scan).

_Backfilled from btc-sec-research artifact `paulmillr__scure-btc-signer` (finding SIG-002) during the 2026-08-05 gap-close; static entry — treat as a lead pending PoC verification._

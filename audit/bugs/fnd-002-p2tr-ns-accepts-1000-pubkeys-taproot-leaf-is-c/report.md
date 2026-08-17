# p2tr_ns() accepts ≥1000 pubkeys: taproot leaf is constructible/addressable but unspendable (BIP342 1000-element stack limit), while sibling p2tr_ms() is correctly capped at 999

- Project: scure-btc-signer
- Commit/version: 68b2fad4ef8232302c6239c00902def1f511c974
- Category: funds-loss
- Severity: Low — A taproot script-path spend of a tr_ns leaf requires a witness of n signatures followed by the leaf script; execution starts with a stack of n witness elements
- Reproduction: static — source-harness audit finding, no Docker PoC attached
- Confirmed: code-review
- Attacker model: not recorded — see Summary
- Default config affected: unknown
- Reported upstream: no
- Disclosure: no published contact found (see statistics/disclosure-contacts.md entry for `scure-btc-signer`; source https://github.com/paulmillr/scure-btc-signer/blob/master/SECURITY.md, checked 2026-08-12)

## Summary

A taproot script-path spend of a tr_ns leaf requires a witness of n signatures followed by the leaf script; execution starts with a stack of n witness elements and the script's first pubkey push makes it n+1. BIP342 keeps the 1000-element stack limit, so any tr_ns leaf with n ≥ 1000 pubkeys fails at the first push (1001 > 1000) and is consensus-unspendable. The library knows this exact bound — the tr_ms validator caps n at 999 with a comment explaining the same stack math (payment.ts:402-405) — but the analogous tr_ns path has no cap: OutTRNS (payment.ts:211-243) and the OutScript validator (payment.ts:395-399) accept any number of Schnorr-valid keys, and p2tr_ns()/p2tr() happily produce a script, taproot tree and mainnet address for a 1000-of-1000 leaf (reproduced in-container: p2tr_ns(1000, pubs) accepted, 34000-byte script; p2tr(undefined, [leaf]) yields address bc1pcss6...khl3x; p2tr_ms(1000, pubs) throws 'OutScript/tr_ms: invalid params'). With the common pattern p2tr(undefined, [leaf]) (TAPROOT_UNSPENDABLE_KEY internal key = script-only output), funds sent to the resulting address are locked forever: the only spend path is the invalid 1000-key leaf. Note the analogous p2sh (520-byte push) and p2wsh (10000-byte script) limits are enforced by the library, making this omission inconsistent with the library's own unspendable-output defenses.

## Exploit chain

No external attacker required; honest-user footgun with an assist from any coordinator/UI that asks the library to build a very large taproot multisig. 1. User (or a coordinator's wallet software using this library) creates a 1000-of-1000 taproot multisig via p2tr(undefined, [p2tr_ns(1000, pubs)[0]]) — or any tree containing such a leaf. 2. Library returns a normal-looking bech32m address; funds are sent. 3. At spend time, finalizeIdx() produces a witness with 1000 signatures; every node rejects the spend (stack overflow at the first pubkey push) — funds are permanently locked. Only m == n configurations are practically reachable (m < n needs C(n, m) leaves, which blows up combinatorially for n ≈ 1000), hence low severity.

## Suggested fix

Add the same `pubkeys.length > 999` rejection to the tr_ns branch of the OutScript validator (payment.ts:395-399) and/or to p2tr_ns(), mirroring the existing tr_ms guard and its BIP342 stack-limit rationale.

## Reproduction

Container unit test: assert p2tr_ms(1000, pubs) throws but p2tr_ns(1000, pubs) succeeds and p2tr(undefined, [leaf]) returns an address; boundary check that p2tr_ns(999, pubs) is accepted (999 sigs + first push = 1000 = limit). Demonstrated in .audit-tmp/fnd-trns-limit.mjs.

Verification evidence (source harness): In btc-audit-base container: tr_ms(1000 keys) throws 'OutScript/tr_ms: invalid params'; tr_ns(1000 keys) accepted (script 34000 bytes); p2tr(undefined, [1000-key leaf]) accepted, address bc1pcss6xfxxpglp686p8077m5t990exfs37a6e3fe2ynyc9wfsk673q9khl3x; 999-key boundary accepted for both.

## Affected files

- `src/payment.ts` (211-243): OutTRNS coder (encode/decode for `<pk1> CHECKSIGVERIFY ... <pkN> CHECKSIG` leaves) performs no pubkey-count validation.
- `src/payment.ts` (395-406): OutScript validator: tr_ms is explicitly capped (`n > 999` throws, citing the BIP342 1000-element stack limit) but tr_ns keys are only checked for Schnorr validity — no count cap.
- `src/payment.ts` (1232-1245): p2tr_ns(m, pubkeys) → combinations(m, pubkeys); with m == n a single leaf with all n keys is emitted with no upper bound on n.
- `src/payment.ts` (1082-1157): p2tr(internalKey, tree) accepts such a leaf (checkTaprootScript only requires type tr_ns/tr_ms/unknown) and derives a valid bech32m address for it.

## Affected versions

verified on v2.2.0 (commit 68b2fad4ef8232302c6239c00902def1f511c974); earlier versions unverified

## Confidence

High (as recorded by the source scan).

_Backfilled from btc-sec-research artifact `paulmillr__scure-btc-signer` (finding FND-002) during the 2026-08-05 gap-close; static entry — treat as a lead pending PoC verification._

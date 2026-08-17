# micro-packed pinned to ~0.9.0 while upstream 0.10.x ships security hardening of binary decoding primitives (assessed: hardened paths not reachable via current scure-btc-signer usage)

- Project: scure-btc-signer
- Commit/version: unknown (see Affected versions)
- Category: dependency
- Severity: Info — micro-packed is the binary packing/parsing library used for PSBT and transaction decode/encode (attacker-facing input path when parsing externally supplied PSBT
- Reproduction: static — source-harness audit finding, no Docker PoC attached
- Confirmed: code-review
- Attacker model: not recorded — see Summary
- Default config affected: unknown
- Reported upstream: no
- Disclosure: no published contact found (see statistics/disclosure-contacts.md entry for `scure-btc-signer`; source https://github.com/paulmillr/scure-btc-signer/blob/master/SECURITY.md, checked 2026-08-12)

## Summary

micro-packed is the binary packing/parsing library used for PSBT and transaction decode/encode (attacker-facing input path when parsing externally supplied PSBTs). Upstream published 0.10.0 (commits ca4da0f 'Harden binary decoding primitives' and 2e0faf8 'Implement chunked writer, massive speed-up. Harden primitives.', June-July 2026) after 0.9.0. The hardening adds: decode-time validation of padLeft/padRight padding bytes (0.9.0 skips padding unvalidated, allowing alternate encodings with hidden padding data), opt-in minimal-encoding rejection for unsized bigint/int, canonical-NaN enforcement for float coders, immutable (copied) flag/magicBytes/array terminators (0.9.0 retains caller Uint8Arrays by reference), stricter Reader constructor input typing, and rejection of non-number dynamic lengths. scure-btc-signer's ~0.9.0 range excludes 0.10.x, and the git tree's package.json (commit 68b2fad) still specifies ~0.9.0. Reachability analysis of the hardened weaknesses through scure-btc-signer 2.2.0: scure uses only U8/U16LE/U32LE/U32BE/I32LE/U64LE/I64LE/U256BE fixed ints, bytes, string, struct, tuple, array, apply, wrap, validate, magic, prefix, flagged, and one flag call with an inline literal (src/script.ts:434). It does NOT use padLeft/padRight, unsized bigint/int, or float coders (verified by enumerating every P.* reference in src/*.ts), so none of the hardened behaviors are reachable from scure's code today. This is therefore an informational maintenance note: upgrade to ^0.10.2 when convenient to inherit the hardening before any future scure code path starts using the affected primitives.

## Exploit chain

No exploitable chain through scure-btc-signer 2.2.0 was identified. Hypothetically, if a future scure release used P.padLeft/P.padRight in a consensus-critical parse (e.g., script or PSBT field) while staying on micro-packed 0.9.x, an attacker could craft inputs whose padding bytes differ between decoders, producing parse differentials (same bytes decoding differently across implementations) — the classic prelude to funds-loss via inconsistent transaction interpretation. The current finding is a latent exposure only: the fix is a one-line range bump.

## Suggested fix

Bump the micro-packed dependency to ~0.10.2 (or ^0.10.2) after running the existing test suite (483 tests) against it; review the two upstream hardening commits (ca4da0f, 2e0faf8) for any intentional behavior changes affecting scure's coders. No code changes in scure-btc-signer are required by the upgrade itself.

## Reproduction

Demonstration of the underlying 0.9.0 laxity (not of a scure exploit): in Docker, require micro-packed 0.9.0 and show P.padRight(4, P.U8).decode(Uint8Array.of(9, 0xAA, 0xBB, 0xCC)) succeeds (returns 9, padding ignored) whereas micro-packed 0.10.x throws 'padRight: invalid padding byte'. Confirms the version gap; scure reachability confirmed absent by grep enumeration of P.* usage.

Verification evidence (source harness): Version gap verified via npm view (0.9.0 pinned vs 0.10.2 latest); hardening content read from upstream commits ca4da0f/2e0faf8 patches; non-reachability verified by enumerating all P.* identifiers used in src/*.ts and reading micro-packed 0.9.0 index.js (lengthCoder, flag, padLeft/padRight, bigint, Reader).

## Affected files

- `package.json` (17): "micro-packed": "~0.9.0" — for 0.x versions tilde means >=0.9.0 <0.10.0, so the 0.10.x hardening release is excluded
- `package-lock.json` (96-110): Resolved micro-packed 0.9.0; npm view shows latest is 0.10.2 (2026-07-21)
- `src/script.ts` (434): Only micro-packed primitive among the hardened set that scure uses: P.flag(new Uint8Array([0x00, 0x01])) — passed an inline literal not retained elsewhere, so the 0.9.0 by-reference terminator weakness hardened in 0.10.0 is not exploitable here
- `node_modules/micro-packed/index.js` (229-245): 0.9.0 lengthCoder coerces coder-decoded lengths via Number(); 0.10.0 rejects non-number lengths. Not reachable: scure only uses coder lengths that always decode to numbers (CompactSize via U8/U16LE/U32LE/U64LE)

## Affected versions

scure-btc-signer 2.2.0 (dependency specification); micro-packed 0.9.0 as resolved

## Confidence

High (as recorded by the source scan).

_Backfilled from btc-sec-research artifact `paulmillr__scure-btc-signer` (finding DEP-002) during the 2026-08-05 gap-close; static entry — treat as a lead pending PoC verification._

## Upstream and validation status (2026-08-10)

No hardened micro-packed path was reachable from the reviewed signer code, so no signer vulnerability was demonstrated. Current scure-btc-signer 2.3.0 uses micro-packed 0.11, removing the version gap. Do not disclose this as an active security finding.

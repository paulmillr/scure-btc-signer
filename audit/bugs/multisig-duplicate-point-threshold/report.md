# Multisig builders accept the same secp256k1 point in compressed and uncompressed form, silently weakening the m-of-n policy

- **Severity:** Medium — displayed m-of-n silently weakened to theft by one key holder; needs a consumer that funds attacker-influenced key lists without dedup
- **Confidence:** High (deterministic construction-level reproducer; consensus semantics demonstrated cryptographically)
- **Reviewed revision:** `68b2fad4ef8232302c6239c00902def1f511c974` (`@scure/btc-signer` 2.2.0)
- **PoC:** `2026-08-05-multisig-duplicate-point-threshold/` (`poc.mjs`)

## Affected files and lines

- `src/payment.ts:505-514` — `uniqPubkey` rejects only exact-byte duplicates (`hex.encode(pub)` key in a map).
- `src/payment.ts:778-790` — `p2ms(m, pubkeys, allowSamePubkeys=false)` calls `uniqPubkey` and otherwise only relies on `OutScript` ECDSA-key validation.
- `src/payment.ts:1361-1374` — `multisig()` wraps `p2ms` in P2SH/P2WSH, producing the fundable address.
- `src/payment.ts:1396-1405` — `sortedMultisig()` same weakness, plus it admits uncompressed keys although BIP67 sorting is defined for compressed keys only (compat note, see comments at `src/payment.ts:1334-1335`, `src/payment.ts:1402-1403`).
- `src/payment.ts:386-394` — `OutScript` validator for `ms` validates each key with `validatePubkey(p, ecdsa)`, which accepts both 33-byte and 65-byte SEC1 encodings of the *same point*.

## Root cause and violated invariant

`uniqPubkey` deduplicates by exact byte encoding. secp256k1 points have two standard SEC1
serializations (33-byte compressed, 65-byte uncompressed); both pass `validatePubkey(...,
PubT.ecdsa)` (`src/utils.ts:307-320`). Therefore `p2ms(2, [A_compressed, A_uncompressed])`
succeeds and emits `OP_2 <A33> <A65> OP_2 CHECKMULTISIG`.

The violated invariant (task security question): **multisig construction cannot silently
reduce the effective threshold below the displayed m-of-n.** `OutScript.decode` of the
result reports `m=2, n=2` (and any UI would display "2-of-2"), but the consensus policy is
not 2-of-2: `CHECKMULTISIG` matches signatures to pubkeys positionally, and ECDSA
verification is point-based, so *one* private key satisfies both positions. The holder of
key A alone can spend: `scriptSig = OP_0 <sig> <sig>` (with RFC6979-deterministic ECDSA the
two slots even carry byte-identical signatures, since both sign the same sighash with the
same key). In general, k duplicated points in an m-of-n reduce the policy to "m-of-n with
(m−k) independent parties required" — e.g. the PoC shows `p2ms(3, [A, A65, B, C])` accepted,
where A alone covers 2 of the 3 required slots.

## Attacker model, prerequisites, and attacker-controlled path

- Attacker: a cosigner/key-source in a multi-party wallet flow (counterparty-supplied pubkey
  lists, descriptors, PSBT-driven multisig setup), or any application input that feeds
  `pubkeys` into `p2ms`/`multisig`/`sortedMultisig`.
- Prerequisite: the victim application constructs and funds a multisig output from the
  attacker-influenced key list without its own point-level deduplication.
- Path: attacker supplies the same point twice (e.g. their own key in both encodings) →
  library builds a displayed-m-of-n output → victim funds it → attacker spends unilaterally
  with a lower effective threshold than every other cosigner believes is required.

## Concrete impact

Fund theft enabling: the effective signing threshold is lower than the authorized and
displayed policy. All cosigners' policy displays (`OutScript.decode` → `m of n`) show the
authorized values; the consensus script does not enforce them. The PoC demonstrates that the
library's own address wrappers happily emit a fundable address
(`multisig(2, [A33, A65])` → `34UpD1y8SeoocokKZDbV5GEja8guNhJiCR`).

Note: this library's own finalizer cannot spend the weakened script with one key (it matches
`partialSig` entries to pubkeys by exact bytes, so it collects only 1 of 2 signatures), which
means an honest user of this library would also fail to spend such an output cooperatively —
a secondary availability symptom of the same defect.

## Reproduction

```
# in the worktree at 68b2fad4: npm install && cd test && ../node_modules/.bin/tsc
REPO=<worktree> node --experimental-global-webcrypto poc.mjs
```

Observed output (abridged):

```
[0] compA and uncompA are the same secp256k1 point: true
[1] p2ms(2, [compA, compA]) throws: Multisig: non-uniq pubkey ...   (exact-byte dup caught)
[2] p2ms(2, [compA, uncompA]) ACCEPTED. decoded: type=ms m=2 n=2
[3] multisig(...)/sortedMultisig(...) ACCEPTED. address = 34UpD1y8SeoocokKZDbV5GEja8guNhJiCR
[4] one ECDSA sig from privA verifies against compA: true
    same sig verifies against uncompA (same point): true
    deterministic signing => two slots get identical bytes: true
[5] p2ms(3, [A, A(65B), B, C]) ACCEPTED as m=3 of n=4; holder of A alone provides 2 of the 3 required sigs
```

No funds were moved; the demonstration is construction + independent signature-verification
only, using valueless deterministic keys.

## Remediation

- Deduplicate by curve point, not by encoding: in `uniqPubkey`, normalize each ECDSA key
  (e.g. compare the x-coordinate/affine form via `Point.fromBytes(pub)`) and reject on
  point equality, or reject mixed compressed/uncompressed lists outright.
- Enforce compressed-only keys in `sortedMultisig` (BIP67) and in the `witness=true`
  branch of `multisig` (BIP143 compressed-key policy), as the code comments already
  recommend to callers.
- Document that `allowSamePubkeys=true` produces degenerate thresholds.

## References

- BIP67 (canonical multisig ordering; compressed keys only).
- BIP143 (version-0 witness compressed-key policy) and BIP16/BIP11 multisig semantics.
- Bitcoin Core `CHECKMULTISIG` evaluation (positional sig↔pubkey matching; per-pubkey ECDSA verification).
- Related guard already present in-repo: exact-byte dedup (`src/payment.ts:505-514`) and the
  deliberate BIP383 compat comment there.

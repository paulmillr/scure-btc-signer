# OutScript semantic round trip canonicalizes non-minimal pushes; legacy/segwit-v0 signing uses the canonicalized bytes as scriptCode, producing invalid spends

- **Severity:** Low (deterministic DoS of the affected spend; no fund theft — the UTXO stays locked by its original script)
- **Confidence:** High (end-to-end reproducer signs through `Transaction.signIdx` and independently verifies the signature against both candidate scriptCodes)
- **Reviewed revision:** `68b2fad4ef8232302c6239c00902def1f511c974` (`@scure/btc-signer` 2.2.0)
- **PoC:** `2026-08-05-nonminimal-script-canonicalization-sighash/` (`poc.mjs`)

## Affected files and lines

- `src/script.ts:217-287` — `Script` codec: semantic AST codec. Decode maps `OP_1..OP_16`
  to numbers, push opcodes to raw bytes; encode re-canonicalizes (shortest push opcode,
  numbers back to `OP_n`). Byte-exactness is explicitly not guaranteed (comment at
  `src/script.ts:206-208`).
- `src/payment.ts:284-296` — `OutUnknown` re-serializes through the `Script` codec, so
  `OutScript.encode(OutScript.decode(x))` ≠ x for non-minimal spellings. The same holds for
  every *classified* template, because matchers operate on the decoded AST (e.g. a P2PKH
  spelled with `PUSHDATA1 0x14 <hash>` classifies as `pkh` and re-encodes canonically).
- `src/transaction.ts:639` — `getInputType`: `const lastScript = OutScript.encode(last);`
  — the signing scriptCode is produced by *re-encoding the decoded descriptor* instead of
  using the committed raw bytes.
- `src/transaction.ts:1441-1453` — `signIdx` feeds `inputType.lastScript` into
  `preimageLegacy` (legacy) and `preimageWitnessV0` (segwit v0) as scriptCode.
- (Reachability for unknown inputs: `src/transaction.ts:1605`, `src/transaction.ts:1530`
  with `allowUnknownInputs`.)

## Root cause and violated invariant

BIP143 and the legacy sighash commit to the *exact bytes* of the executed script
(witnessScript / redeemScript / prevout scriptPubKey, after CODESEPARATOR stripping).
`getInputType` recomputes that script via `OutScript.decode` → `OutScript.encode`, a
semantic round trip that rewrites any non-minimal push spelling to canonical form. The
violated invariant: **decode/encode round trips preserve the exact committed script bytes.**

Two aliasing consequences:

1. All non-minimal spellings of a script alias to one descriptor; the library signs over
   the canonical bytes, so the produced signature does not verify against the real,
   committed script. The transaction is consensus-invalid: deterministic DoS of that spend.
2. This affects both the `unknown` catch-all (hypothesis as stated) *and* classified
   templates (e.g. non-minimal P2PKH classifies as `pkh`, then re-encodes canonically) —
   the PoC demonstrates the `pkh` case end-to-end and shows the `unknown` case at the
   codec level.

## Attacker model, prerequisites, and attacker-controlled path

- The victim spends an input whose committed script uses a non-minimal push spelling.
  These scripts are relay-non-standard but consensus-valid once mined; more importantly,
  they can arrive through **counterparty-supplied PSBTs** (`nonWitnessUtxo` prevout
  scripts, `witnessScript`, `redeemScript` fields), which this task's attacker model
  explicitly includes.
- The victim calls `Transaction.sign`/`signIdx` (with `allowUnknownInputs` for
  template-less shapes). The resulting transaction is rejected by the network. No value
  moves; the UTXO remains spendable by correctly-built transactions.

## Concrete impact

Availability/robustness: any such input is unsignable-by-this-library (every signature is
invalid), with a confusing failure mode (signature *looks* fine locally; the tx fails at
broadcast or peer validation). Taproot paths are **not** affected: v1 sighashes commit to
raw prevout scripts (`src/transaction.ts:1373`) and to raw leaf-script bytes from the PSBT
(`src/transaction.ts:1403-1406`).

## Reproduction

```
REPO=<worktree> node --experimental-global-webcrypto poc.mjs
```

Observed:

```
[0] raw prevout script     = 76a94c14a3c6...88ac        (PUSHDATA1-spelled P2PKH)
    canonical re-encoding  = 76a914a3c6...88ac
    OutScript.decode type  = pkh (classified, not unknown)
    OutScript round-trip byte-exact: false
    unknown-type round-trip byte-exact: false (type=unknown)
[1] getInputType: type=pkh txType=legacy
    lastScript (used as scriptCode) = 76a914a3c6...88ac   (canonical, not raw)
[2] library produced partialSig, sighash byte = 1
    sig verifies against sighash(scriptCode=CANONICAL): true
    sig verifies against sighash(scriptCode=RAW)      : false
    => the library-signed spend is INVALID on-chain
```

## Remediation

- Preserve raw committed bytes for scriptCode: in `getInputType`, use the raw
  `prevOut.script` / `_input.redeemScript` / `_input.witnessScript` bytes as `lastScript`
  instead of `OutScript.encode(last)` (keeping the decoded descriptor only for *logic*
  decisions such as the wpkh→pkh scriptCode substitution at `src/transaction.ts:1451-1452`,
  which is consensus-correct).
- Alternatively document that `OutScript` round trips canonicalize and reject non-minimal
  scripts at input ingestion with a clear error instead of signing over different bytes.

## References

- BIP143 (scriptCode = exact witnessScript/redeem-derived bytes); legacy sighash (scriptCode
  = exact prevout scriptPubKey with CODESEPARATOR removal only).
- BIP62/BIP66-era minimal-push *policy* (standardness, not consensus) — the affected scripts
  are non-standard but consensus-valid.
- Boundary note: signing/preimage authorization is assigned to a separate review prompt;
  this finding is scoped to the construction/classification root cause.

## Duplicate status (2026-08-10)

This is the canonical record for the same decode/re-encode root cause also described by `2026-08-05-scure-btc-signer-scriptcode-canonicalization`. Disclose once and attach evidence from both directories.

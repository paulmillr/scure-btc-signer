# signIdx signs a canonicalized scriptCode, producing consensus-invalid signatures for non-minimally-encoded redeem/witness scripts

- **Severity:** Low — consensus-invalid signatures brick spending (availability only); needs victim UTXOs with non-minimally encoded scripts
- **Confidence:** High (deterministic reproducer)
- **Reviewed revision:** `68b2fad4ef8232302c6239c00902def1f511c974` (`@scure/btc-signer` 2.2.0+)
- **PoC:** `2026-08-05-scriptcode-canonicalization/`

## Affected files and lines

- `src/transaction.ts:601` — `getInputType` decodes the prevout script with `OutScript.decode`.
- `src/transaction.ts:621` — decodes `redeemScript` with `OutScript.decode`.
- `src/transaction.ts:630` — decodes `witnessScript` with `OutScript.decode`.
- `src/transaction.ts:639` — `lastScript = OutScript.encode(last)` **re-encodes** the matched script template.
- `src/transaction.ts:1446-1447` — legacy signing calls `preimageLegacy(idx, inputType.lastScript, sighash)` with the re-encoded bytes.
- `src/transaction.ts:1449-1453` — SegWit v0 signing passes `inputType.lastScript` (or the pkh template) to `preimageWitnessV0`.
- `src/script.ts:206-208` — `Script` is documented as "a semantic AST codec, not a byte-preserving parser: encode ... chooses the shortest push opcode, so decode(...)+encode(...) rewrites non-minimal push spellings."
- `src/payment.ts:288-290` — `OutUnknown` "preserve[s] semantics but not original non-minimal push spellings" — so the fallback template canonicalizes too.
- `src/transaction.ts:52-54` — the `stripCodeSeparator` comment states the correct invariant ("legacy sighash must ... preserv[e] every other original byte, because semantic decode/re-encode would change the signed digest") but it is undermined upstream by `OutScript.encode`.

## Root cause and violated invariant

Legacy and BIP143 signature hashes commit to the **exact bytes** of the spent
script (redeemScript for P2SH, witnessScript for P2WSH, scriptPubKey for bare
spends) minus only raw `OP_CODESEPARATOR` opcodes. `getInputType` classifies
the scripts by running them through `OutScript.decode` (a semantic AST match)
and then re-serializing with `OutScript.encode`, which rewrites push-op
spellings to the minimal form (`PUSHDATA1 0x21 <33B>` → `<0x21>` direct push,
`4c00` → `00`, `4d0200 51ac` → `0251ac`, etc.).

For any on-chain script that is consensus-valid but **non-minimally encoded**,
the scriptCode the library signs differs byte-for-byte from the scriptCode the
network's consensus rules use. The emitted signature is therefore invalid on
the real network, while the library reports signing success.

Violated invariant: *the digest matches deployed consensus semantics
byte-for-byte for the exact spend type and requested flag.*

## Attacker model, prerequisites, attacker-controlled path

Prerequisites: the victim holds (or receives) a UTXO whose redeem/witness
script uses a non-minimal push spelling. Non-minimal pushes are
consensus-valid (only relay policy discourages them). Delivery paths:

- A counterparty in a contract protocol (swap/HTLC/escrow) proposes the shared
  P2SH/P2WSH contract script in a non-minimal spelling; `checkScript` accepts
  it because the hash commitment matches.
- An attacker simply pays the victim to a bare non-minimal `pk`/`ms`
  scriptPubKey.

Path: victim imports the UTXO (hash checks pass) → `signIdx` → `getInputType`
canonicalizes → signature commits to the wrong scriptCode bytes → transaction
rejected by the network; funds are stuck until recovered with different
tooling. No error is raised at any point.

## Concrete impact

- Funds controlled by such scripts become **unspendable through this library**
  (proven for P2SH-pk and P2WSH-pk; the mechanism covers every legacy/P2WSH
  template, including `unknown` contract scripts such as HTLCs, because
  `OutUnknown` also canonicalizes). In timeout-bearing contracts (HTLC/swap),
  an induced inability to spend before expiry has financial consequences.
- Private keys are not exposed and value cannot be redirected; impact is
  availability, not theft. Hence Low severity.

## Reproduction / observed output

PoC `2026-08-05-scriptcode-canonicalization/` (`poc.mts`,
`expected_output.txt`):

```
A) P2SH(pk) with non-minimally-encoded redeemScript
  on-chain redeemScript : 4c2102..ac
  getInputType lastScript: 2102..ac            <-- canonicalized
  sig verifies vs CONSENSUS digest (original bytes)? false
  sig verifies vs canonical digest? true
B) P2WSH(pk) with non-minimally-encoded witnessScript
  digests differ? true
  sig verifies vs CONSENSUS BIP143 digest (original bytes)? false
  sig verifies vs canonical digest? true
```

The BIP143 digest used for verification is produced by the library's own public
`preimageWitnessV0` fed with the *verbatim* witnessScript, which the included
differential matrix validates byte-for-byte against Bitcoin Core's
`test_framework` semantics (110/110 SegWit v0 cells equal; harness included in
the same PoC directory).

## Remediation guidance

- Stop re-encoding scriptCode: carry the **original** `redeemScript` /
  `witnessScript` / prevout `script` bytes through `getInputType` and pass them
  verbatim to `preimageLegacy`/`preimageWitnessV0` (as
  `stripCodeSeparator`'s own comment requires). Use the `OutScript` match only
  for classification (`type`, `m`, `pubkeys`), not for serialization.
- If canonicalization is retained for other reasons, detect
  `OutScript.encode(OutScript.decode(x)) !== x` at input ingestion and reject
  with an explicit error instead of silently signing a non-consensus digest.

## References

- Legacy sighash scriptCode rules (Bitcoin Core `interpreter.cpp`
  `SignatureHash` + `FindAndDelete(OP_CODESEPARATOR)`), BIP143 §"Specification
  of the new digest algorithm" (scriptCode = "the scriptCode of the input,
  serialized as scripts inside CTxOuts").
- BIP146 (minimal-push rule is policy, not consensus, for P2SH/P2WSH script
  bodies).

## Duplicate status (2026-08-10)

Independent differential testing confirmed this behavior, but it is the same root cause and impact as `2026-08-05-scure-btc-signer-nonminimal-script-canonicalization-sighash`. Disclose and track them as one finding, not two.

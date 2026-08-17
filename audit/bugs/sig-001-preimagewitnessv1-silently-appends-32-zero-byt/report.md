# preimageWitnessV1 silently appends 32 zero bytes for taproot SIGHASH_SINGLE with no matching output, producing digests that can never yield a consensus-valid signature

- Project: scure-btc-signer
- Commit/version: 68b2fad4ef8232302c6239c00902def1f511c974
- Category: funds-loss
- Severity: Low — For taproot (BIP341) sighash computation with hash_type SIGHASH_SINGLE and input index >= number of outputs, Bitcoin Core's SignatureHashSchnorr returns false (
- Reproduction: confirmed — output matches an independent BIP341 SigMsg only when an extra zero32 field is appended
- Confirmed: dynamically-reproduced
- Attacker model: caller directly using the public preimage helper for Taproot SINGLE without a corresponding output
- Default config affected: no for `signIdx`, which rejects first; yes for direct helper users
- Reported upstream: no
- Disclosure: no published contact found (see statistics/disclosure-contacts.md entry for `scure-btc-signer`; source https://github.com/paulmillr/scure-btc-signer/blob/master/SECURITY.md, checked 2026-08-12)

## Summary

For taproot (BIP341) sighash computation with hash_type SIGHASH_SINGLE and input index >= number of outputs, Bitcoin Core's SignatureHashSchnorr returns false (src/script/interpreter.cpp v28: `if (output_type == SIGHASH_SINGLE) { if (in_pos >= tx_to.vout.size()) return false; ... }`), i.e. consensus defines NO sighash in this case and any such signature is invalid (SCRIPT_ERR_SCHNORR_SIG_HASHTYPE). Unlike legacy (the famous 'hash of 1' bug), taproot SIGHASH_SINGLE without a matching output is a hard validation failure. scure-btc-signer's public Transaction.preimageWitnessV1 instead appends a 32-byte zero block (`EMPTY32`) to the SigMsg and returns a TapSighash digest. That digest matches no valid consensus hash: verified empirically (docker, .audit-tmp/check-sighash-edge.ts) that the returned value equals TapSighash(SigMsg || 0x00*32) and differs from the SigMsg without any output commitment. Any caller that signs this digest — e.g. an air-gapped signer, HSM, or a MuSig2 session (musig2.ts takes externally-computed messages) that relies on this library for the sighash — produces a signature that every Bitcoin Core node rejects, so the transaction can never be broadcast. Funds are not stolen and the user can recover by re-signing with a valid sighash type, but the failure is silent and misleading: the API returns a plausible 32-byte digest instead of throwing. The library's own signIdx guard (transaction.ts:1362) already throws for exactly this condition, so the preimage helper is inconsistent with the library's own signing path as well as with consensus. The repo test suite explicitly documents this as a known leniency kept for vector coverage.

## Exploit chain

No attacker profit; honest-user loss-of-liveness scenario. 1) A wallet/coordinator builds a taproot spend with sighashType SINGLE on an input whose index has no corresponding output (or calls preimageWitnessV1 directly in an external-signer/MuSig2 flow). 2) preimageWitnessV1 returns TapSighash(SigMsg || 0x00*32) instead of failing. 3) The (MuSig2/key-path) signature over that digest is finalized and broadcast. 4) Every Bitcoin Core node computes SignatureHashSchnorr -> false -> SCRIPT_ERR_SCHNORR_SIG_HASHTYPE; the tx is invalid and the UTXO appears unspendable with that signature. The user must diagnose the silent mismatch and re-sign with a different sighash; until then funds are frozen.

## Suggested fix

In preimageWitnessV1, replace the EMPTY32 fallback with an explicit throw when `outType === SignatureHash.SINGLE && idx >= outputs.length`, mirroring the signIdx guard at transaction.ts:1362 and Bitcoin Core's hard failure; alternatively append nothing only if you deliberately want Core's legacy-style leniency (but Core defines failure here, so throwing is the correct behavior).

## Reproduction

Docker unit test (already demonstrated in src/.audit-tmp/check-sighash-edge.ts): create Transaction with 1 taproot input (witnessUtxo + tapInternalKey) and 0 outputs; call tx.preimageWitnessV1(0, [script], 0x03, [1000n]); independently compute TapSighash over the BIP341 SigMsg with no sha_single_output field; assert the scure digest equals TapSighash(SigMsg || EMPTY32) and differs from the no-block SigMsg; assert that a schnorr signature over the scure digest does not verify against any digest Bitcoin Core can produce (Core returns false for this case, evidenced by interpreter.cpp source citation).

## Affected files

- `src/transaction.ts` (1244-1245): out.push(idx < outputs.length ? u.sha256(RawOutput.encode(outputs[idx])) : EMPTY32) — the EMPTY32 fallback has no consensus meaning
- `src/transaction.ts` (1189-1198): preimageWitnessV1 is a public method (also exported in transaction.d.ts:341), usable by external signers / MuSig2 coordinators / custom flows
- `src/transaction.ts` (1361-1366): the built-in signIdx path correctly rejects SINGLE with no corresponding output, so the divergence only bites direct preimage API users
- `test/bip341-taproot.test.ts` (255-258): repo test documents the behavior as 'KNOWN ISSUE (leniency, kept for sighash test-vector coverage)'

## Affected versions

v2.2.0 (commit 68b2fad4ef8232302c6239c00902def1f511c974, verified); earlier versions unverified

## Confidence

High (as recorded by the source scan).

_Backfilled from btc-sec-research artifact `paulmillr__scure-btc-signer` (finding SIG-001) during the 2026-08-05 gap-close; static entry — treat as a lead pending PoC verification._

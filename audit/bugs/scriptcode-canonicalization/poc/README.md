# PoC: scriptCode canonicalization produces consensus-invalid signatures

Target: `@scure/btc-signer` @ `68b2fad4ef8232302c6239c00902def1f511c974`
Finding: `2026-08-05-scriptcode-canonicalization.md`

## Contents

- `poc.mts` — demonstrates that `signIdx` signs a canonicalized scriptCode that
  differs byte-for-byte from the on-chain redeem/witness script for valid
  non-minimally-encoded scripts (P2SH and P2WSH variants), yielding signatures
  the real network rejects.
- `expected_output.txt` — observed output of `poc.mts`.
- `differential_matrix.mts` — generates 374 deterministic transaction/flag/script
  shapes and computes digests with `preimageLegacy` / `preimageWitnessV0` /
  `preimageWitnessV1`.
- `ref_sighash.py` — independent sighash oracle transcribed from Bitcoin Core
  `test/functional/test_framework/script.py` @ `5871b5b5ab57a0caf9b7514eb162c491c83281d5`
  (the revision cited in `src/transaction.ts:1112`).
- `compare.py` — per-scheme verdict table.
- `specs.json`, `lib_digests.json`, `ref_digests.json` — captured run artifacts.

## Reproduce

From the worktree root after `npm install` (Node >= 22 for TS type-stripping):

```sh
cp poc/2026-08-05-scriptcode-canonicalization/poc.mts poc.mts
node --no-warnings poc.mts

# differential matrix (harness must run from the worktree root)
cp differential_matrix.mts <worktree>/dm.mts && cd <worktree>
node --no-warnings dm.mts <poc-dir>/specs.json <poc-dir>/lib_digests.json
python3 <poc-dir>/ref_sighash.py <poc-dir>/specs.json <poc-dir>/ref_digests.json
cd <poc-dir> && python3 compare.py
```

Matrix result at this commit: 356/374 byte-equal. All 18 divergences are the
legacy SIGHASH_SINGLE/out-of-range hash-of-one exception byte order
(private `preimageLegacy` returns `00..01`; consensus uses `01 00..00`),
unreachable through public signing (see review notes). SegWit v0 (110/110) and
Taproot/BIP341 (154/154, incl. annex, script-path, codeSeparator, and exotic
hash_type cells) are byte-equal to the Core test-framework oracle.

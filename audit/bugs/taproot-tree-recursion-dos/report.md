# Unbounded recursion in taprootHashTree/taprootAddPath crashes the consumer (RangeError) on adversarially nested trees

- **Severity:** Low (availability; controlled `RangeError`, not memory corruption)
- **Confidence:** High (measured crash threshold; fix boundary conditions verified against an independent BIP341 implementation)
- **Reviewed revision:** `68b2fad4ef8232302c6239c00902def1f511c974` (`@scure/btc-signer` 2.2.0)
- **PoC:** `2026-08-05-taproot-tree-recursion-dos/` (`gen_cases.mjs`, `check_cases.py`, `cases.json`)

## Affected files and lines

- `src/payment.ts:981-1028` — `taprootHashTree` recurses per branch level (`tree[0]`, `tree[1]`).
- `src/payment.ts:957-972` — `taprootAddPath` recurses per branch level.
- `src/payment.ts:973-979` — `taprootWalkTree` recurses per branch level.
- `src/payment.ts:1110-1113` — `p2tr` calls all three on caller-supplied trees with no depth guard.

## Root cause

`p2tr(internalKey, tree)` accepts arbitrarily nested `TaprootScriptTree` arrays. The three
tree walkers are recursive, so a degenerate tree nested d levels deep consumes d stack
frames. Measured under the default Node.js stack: nesting depth ≥ ~4000 throws
`RangeError: Maximum call stack size exceeded` (depths 10⁴, 10⁵, 10⁶ all crash in ~1 ms).
Depths between 129 and ~4000 fail cleanly instead, because the BIP341 control-block depth
guard fires first (`src/psbt.ts:131-132` rejects `merklePath > 128` during the per-leaf
`TaprootControlBlock.encode` at `src/payment.ts:1129`).

## Attacker model and impact

A consumer that builds a taproot tree from counterparty-controlled structure (imported
policy JSON, coordinator-provided tree, PSBT-derived tree rebuilt through these helpers)
can be crashed by a deeply nested tree — one thrown `RangeError` per request is enough to
DoS an unguarded request handler or process. Impact is limited to availability; the
exception is deterministic and catchable.

## Reproduction and positive verification

```
REPO=<worktree> node --experimental-global-webcrypto gen_cases.mjs > cases.json
python3 check_cases.py cases.json
```

- `nested-depth-10000/100000/1000000` cases show `Maximum call stack size exceeded`; depth
  2000 throws the clean `merklePath should be of length 0..128` guard error; the RangeError
  onset was measured between depth 2000 and 4000.
- The same PoC also **verifies the tree machinery against an independent pure-Python
  BIP341 implementation** (tagged hashes, lexicographic TapBranch sorting, control-block
  path application, `Q = lift_x(P) + t·G`, parity): 77/77 cases pass — 40 random explicit
  binary trees, 30 `taprootListToTree` weighted lists, duplicate leaves, single-leaf,
  key-path-only, leaf version 0xc2, and the path-length-128 boundary (constructed fine),
  plus `tapLeafHash(OP_TRUE) = a85b2107f7…d675` matching the known constant. Path length
  129 correctly throws. So the recursion guard is the *only* tree-construction defect found.

## Remediation

- Reject trees deeper than 128 levels up front in `p2tr`/`taprootHashTree` (they can never
  yield a valid control block anyway), which also removes the stack-exhaustion window; or
  convert the walkers to an explicit iterative stack.

## References

- BIP341 (control block `33 + 32m`, m ≤ 128), BIP342.

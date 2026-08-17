# selectUTXO weight lower-bound paths undercut the requested feerate and can emit un-finalizable funding sets

- **Severity:** Low — feerate erosion or stuck/non-relayable txs from weight undercount; needs script-path-only signer or unregistered custom tapscript leaf
- **Confidence:** High (deterministic reproducers, five cases, all confirmed)
- **Reviewed revision:** `68b2fad4ef8232302c6239c00902def1f511c974` (`@scure/btc-signer` 2.2.0 worktree)
- **PoC:** `2026-08-05-utxo-weight-lower-bound-feerate-erosion/` (`poc-weight-lower-bound.ts`, run output below)

## Summary

`selectUTXO`/`_Estimator` computes the fee from `estimateInput`'s satisfaction
weight. Three estimation paths systematically produce a *lower bound* rather
than an upper bound for satisfactions the library's own finalizer will later
build:

1. **Key-path hint** (`src/utxo.ts:131-143`): any present `tapInternalKey`
   (other than the provably-unspendable `TAPROOT_UNSPENDABLE_KEY`) makes the
   estimator assume the minimal key-path witness `[sig]`, even when the signer
   can only use a script path.
2. **Smallest-leaf assumption** (`src/utxo.ts:68-70`): `iterLeafs` sorts
   `tapLeafScript` by control-block size and estimates with the first
   (cheapest) leaf; `Transaction.finalizeIdx` (`src/transaction.ts:1492-1567`)
   picks the cheapest *signable* leaf. If the signer lacks keys for the
   smallest leaf, the finalized witness is larger than estimated.
3. **Custom-script lower bound** (`src/utxo.ts:110-115`): a taproot leaf whose
   script is not `tr_ms`/`tr_ns` and has no matching `finalizeTaproot` hook in
   `opts.customScripts` silently falls back to the witness lower bound
   `[script, controlBlock]` (no signature stack items at all).

Because `result()` fixes output amounts from the *estimated* fee, the
transaction always pays exactly the estimated fee (`tx.fee === result.fee`
holds in every run). An undercount therefore does not burn satoshis directly —
change absorbs the difference — but the **effective feerate of the funded
transaction drops below the caller-requested `feePerByte`**, and with large
tapscript leaves it can fall below the 1 sat/vB relay minimum, producing a
non-relayable transaction. The caller receives no signal: `result()` returns
`{inputs, outputs, fee, weight, change, tx}` with no estimation-accuracy
indicator (`src/utxo.ts:574-589`).

Additionally, path 3 without `allowUnknownInputs` yields a **funding set that
can never be signed**: `selectUTXO` returns a normal result with
`createTx: true`, `tx.sign()` succeeds, and `tx.finalize()` throws
`Finalize: Unknown tapLeafScript` (`src/transaction.ts:1560`).

## Affected files and lines

- `src/utxo.ts:131-143` — taproot branch of `estimateInput`; key-path hint.
- `src/utxo.ts:68-70` — in-place leaf sort and cheapest-leaf estimation in `iterLeafs`.
- `src/utxo.ts:110-115` — silent minimal-witness fallback for custom leaves without a finalizer.
- `src/utxo.ts:546-589` — `result()` computes change/fee from the estimate and reports no uncertainty.
- `src/transaction.ts:1530-1543,1560` — finalizer behavior for the same leaves (larger witness or throw).

## Root cause and violated invariant

Invariant (coin-selection-fund-safety): *satisfaction-weight estimates never
systematically undercount*. For known script families the estimator is a tight
upper bound (verified for 19 families; slack 0–4 weight units from the 72-byte
max-signature assumption). The three paths above invert that guarantee in
caller-reachable configurations, and the fee/change arithmetic in `result()`
has no mechanism to detect or compensate for the shortfall. A second violated
invariant: *every selected input is spendable by the active signer/policy* —
path 3 without `allowUnknownInputs` selects inputs the library itself cannot
finalize.

## Attacker model, prerequisites, attacker-controlled path

- Attacker controls UTXO metadata (taproot leaf sets, presence of
  `tapInternalKey`, custom-script descriptors) — e.g., an untrusted backend
  serving input updates, or a counterparty supplying PSBT input metadata in an
  interactive flow. `src/net.ts` `unspent()` mitigates *amount/script* forgery
  by fetching full prev transactions (`src/net.ts:965-997`), but taproot
  PSBT metadata (`tapInternalKey`, `tapLeafScript`) is application-supplied
  and is exactly what drives these paths.
- Prerequisite: the victim's application funds transactions with
  `selectUTXO`/`_Estimator` and the signer can only script-path spend (no
  internal-key signature), or uses custom taproot scripts without registering
  a matching `finalizeTaproot` hook.
- A malicious metadata source can deliberately include an unspendable-looking
  (but not the standard unspendable) `tapInternalKey` to bias the victim's
  feerates downward — a griefing vector that stalls the victim's transactions.

## Concrete impact (measured on regtest-shaped data)

| Case | Requested | Real outcome |
| --- | --- | --- |
| A: key-path hint, signer has only the leaf key | 200 sat/vB | est weight 520 vs real 589 → effective 175.7 sat/vB |
| B: smallest leaf unsignable (2-leaf tree) | 200 sat/vB | est 621 vs real 757 → effective 164.2 sat/vB |
| C1: custom leaf, no finalizer | 200 sat/vB | selection returned (fee 26 800 sat), `finalize()` throws — un-signable funding set |
| C2: same + `allowUnknownInputs` | 200 sat/vB | est 536 vs real 601 → effective 177.5 sat/vB |
| D: 15-key `tr_ms` leaf + key-path hint | 1 sat/vB | est vsize 130 vs real 287 → effective 0.45 sat/vB → **below relay minimum, non-relayable** |

No direct satoshi loss occurs in any case: the transaction pays exactly the
estimated fee. The damage is liveness (stuck/non-relayable transactions) and,
for C1, a funding set that can never be signed (funds recoverable only by
re-running selection with corrected metadata/hooks).

## Reproduction

```
cd 2026-08-05-utxo-weight-lower-bound-feerate-erosion
REPO=<repo worktree> node poc-weight-lower-bound.ts   # node >= 22.6 (type stripping)
```

Observed output (all five cases):

```
A: requested=200 sat/vB est=520 real=589 effective=175.7 sat/vB
CONFIRMED: A: key-path hint undercounts weight (est 520 < real 589 here)
CONFIRMED: A: effective feerate below requested
CONFIRMED: A: fee paid equals estimate (change absorbs the difference, no direct burn)
B: requested=200 sat/vB est=621 real=757 effective=164.2 sat/vB
CONFIRMED: B: unsignable smallest leaf undercounts weight (est 621 < real 757 here)
CONFIRMED: C1: selectUTXO returned a funding set (fee=26800) for an un-finalizable input
CONFIRMED: C1: finalize() throws -> Error: Finalize: Unknown tapLeafScript
C2: est=536 real=601 effective=177.5 sat/vB (requested 200)
CONFIRMED: C2: lower-bound witness undercounts (est 536 < real 601 here)
D: requested=1 sat/vB est vsize=130 real vsize=287 effective=0.45 sat/vB
CONFIRMED: D: effective feerate below the 1 sat/vB relay minimum (non-relayable tx)
CONFIRMED: E: result fields = [inputs,outputs,fee,weight,change,tx] — no estimation-uncertainty signal
ALL CASES CONFIRMED
```

## Remediation guidance

- When no `finalizeTaproot` hook matches a custom leaf, fail selection loudly
  (restore the pre-fallback `Finalize: Unknown tapLeafScript` throw at
  `src/utxo.ts:86`) instead of emitting a lower-bound estimate — or mark the
  result so callers can reject it.
- Surface estimation uncertainty in `result()`: e.g. a `weightLowerBound:
  boolean` flag, or the per-input estimate basis (`keyPath`/`scriptPath`/
  `customLowerBound`), so applications can re-estimate with signer knowledge.
- For inputs carrying both `tapInternalKey` and `tapLeafScript`, prefer the
  *maximum* of key-path and cheapest-leaf estimates when the caller has not
  asserted key-path spendability (or document that `tapInternalKey` must be
  omitted when only script-path signing is possible; the current comment at
  `src/utxo.ts:133-138` documents the tradeoff but the result carries no
  runtime signal).
- After `createTx` construction, optionally verify the estimated weight
  against a dry-run finalization when all required signer material is locally
  available.

## References

- Bitcoin Core dust/relay policy baseline (1 sat/vB `minrelaytxfee`): the
  sub-1-sat/vB outcome in case D is non-relayable under default policy.
- Project test comments acknowledging the smallest-leaf assumption:
  `test/utxo-select.test.ts:389-392`.
- Code comment acknowledging the key-path hint tradeoff: `src/utxo.ts:133-138`;
  the lower-bound fallback rationale: `src/utxo.ts:110-113`.

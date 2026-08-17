# p2tr_ns/combinations materialize all C(n, m) leaves with no bound, and each leaf re-runs curve-level key validation — counterparty policy parameters exhaust consumer CPU/memory

- **Severity:** Low (availability of the library consumer; requires the victim to build policies from untrusted parameters)
- **Confidence:** High (measured growth curve and per-leaf cost; absence of any guard verified by code and runtime)
- **Reviewed revision:** `68b2fad4ef8232302c6239c00902def1f511c974` (`@scure/btc-signer` 2.2.0)
- **PoC:** `2026-08-05-p2tr-ns-combinations-dos/` (`poc.mjs`)

## Affected files and lines

- `src/payment.ts:1232-1245` — `p2tr_ns(m, pubkeys)` → `combinations(m, pubkeys).map(...)`
  with no bound on n or C(n, m).
- `src/payment.ts:1172-1203` — `combinations()` materializes every combination eagerly into
  an array; no size cap, no lazy iteration.
- `src/payment.ts:1242` — each combination goes through `OutScript.encode({type: 'tr_ns',
  pubkeys})`, which runs the `OutScript` validator → `isValidPubkey(p, schnorr)` →
  `schnorr.utils.lift_x` **for every key of every combination** (`src/payment.ts:395-399`),
  multiplying allocation cost by ~0.8 ms of curve math per leaf.
- `src/payment.ts:1207-1208` — the doc comment admits the blow-up ("99-of-100 is ok,
  5-of-100 is not") but no enforcement exists.

## Root cause and violated invariant

M-of-N taproot multisig via key-quorum leaves requires C(n, m) leaf scripts. The library
materializes them eagerly and revalidates all keys per leaf, so cost is Θ(C(n, m)·m)
elliptic-curve operations plus Θ(C(n, m)) heap. Mid-range thresholds explode combinatorially:
C(30,15) ≈ 1.55·10⁸, C(100,5) ≈ 7.5·10⁷, C(100,50) ≈ 1.0·10²⁹. The violated invariant (task):
**tree and leaf construction stay within resource limits** — there is no limit at all.

## Attacker model, prerequisites, attacker-controlled path

Any consumer that derives the quorum policy (m, n, key list) from counterparty input —
coordinator-suggested wallet policies, descriptor/PSBT-driven setup, hosted policy builders —
can be hung or OOM-killed by a single suggested policy such as 12-of-24 (≈2.7 M leaves,
≈45 min CPU by extrapolation, ≈3 GB) or 5-of-100 (≈75 M leaves, hard OOM). Measured on this
review host:

```
n   m  C(n,m)    time_ms  rss_delta_MB  us_per_leaf
14  7  3432         2241        10.0      653.0
16  8  12870        9937        21.0      772.1   (growth x4.4 per +2 keys)
18  9  48620       38284        31.5      787.4
20 10  184756     167312       135.0      905.6
```

`p2tr(undefined, p2tr_ns(8, keys(16)))` (hash tree + control blocks on top) took 28.7 s for
only 12,870 leaves.

## Reproduction

```
REPO=<worktree> node --experimental-global-webcrypto poc.mjs
```

Also demonstrates `p2tr_ns(1, keys(100))` accepted (no n bound) and prints the exact
binomial counts for attacker-suggested policies without executing them.

## Remediation

- Cap n and C(n, m) in `p2tr_ns`/`combinations` (e.g. refuse C(n, m) above a few thousand
  with a descriptive error), and/or stream combinations lazily.
- Validate keys once per input set, not once per emitted leaf (cache the `isValidPubkey`
  result before the `combinations().map()` loop).

## References

- BIP342 ("using a k-of-k script for every combination" design), BIP341 tree construction.
- The related *consensus* limit for large single leaves is handled separately in finding
  `2026-08-05-tr-ns-stack-limit-unspendable.md`.

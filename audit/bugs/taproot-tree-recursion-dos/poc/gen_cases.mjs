// Generates taproot construction cases with the library under review and dumps
// them to cases.json for verification by the independent Python BIP341
// implementation (check_cases.py).
//
// Reviewed commit: 68b2fad4ef8232302c6239c00902def1f511c974 (@scure/btc-signer 2.2.0)
// Setup: npm install && cd test && ../node_modules/.bin/tsc
// Run:   REPO=<worktree> node --experimental-global-webcrypto gen_cases.mjs > cases.json

import path from 'node:path';
import { pathToFileURL } from 'node:url';

const REPO = process.env.REPO;
if (!REPO) throw new Error('set REPO=<path-to-worktree>');
const src = (f) => pathToFileURL(path.join(REPO, 'test/compiled/src', f)).href;
const nm = (f) => pathToFileURL(path.join(REPO, 'node_modules', f)).href;

const { hex } = await import(nm('@scure/base/index.js'));
const u = await import(src('utils.js'));
const { p2tr, p2tr_pk, p2tr_ns, p2tr_ms, taprootListToTree, tapLeafHash } = await import(src('payment.js'));

// Deterministic PRNG (xorshift32) so the case set is reproducible.
let state = 0x9e3779b9;
const rnd = () => {
  state ^= state << 13; state >>>= 0;
  state ^= state >>> 17;
  state ^= state << 5; state >>>= 0;
  return state / 0xffffffff;
};
const privFrom = (seed) => {
  // valueless deterministic scalar in [1, n)
  const h = u.sha256(hex.decode(seed.toString(16).padStart(8, '0')));
  return h;
};
const xonly = (seed) => u.pubSchnorr(privFrom(seed));

const cases = [];
const internal = xonly(0xabc001);

// Case generator: records internal key, full tree (as nested arrays of leaf
// script hex + version), library merkle root, tweaked output key, and for each
// leaf: control block (version+parity, path) to be re-verified independently.
function record(tag, tree, internalKey) {
  const r = p2tr(internalKey, tree);
  const leaves = r.leaves.map((l) => ({
    script: hex.encode(l.script),
    version: l.version === undefined ? 0xc0 : l.version,
    hash: hex.encode(l.hash),
    path: l.path.map(hex.encode),
    controlBlock: hex.encode(l.controlBlock),
  }));
  const ser = (t) => Array.isArray(t) ? t.map(ser) : ({ script: hex.decode(typeof t.script === 'string' ? t.script : hex.encode(t.script)) && hex.encode(typeof t.script === 'string' ? hex.decode(t.script) : t.script), leafVersion: t.leafVersion });
  cases.push({
    tag,
    internalKey: hex.encode(internalKey),
    tweakedPubkey: hex.encode(r.tweakedPubkey),
    tapMerkleRoot: hex.encode(r.tapMerkleRoot),
    address: r.address,
    leaves,
  });
}

// 1..8 random leaves of mixed tr_ns/tr_ms/pk shapes, some as explicit binary
// trees, some as weighted flat lists through taprootListToTree, incl.
// duplicate leaves and unusual leaf versions (0xc2).
let seed = 1;
function randLeaf() {
  const kind = Math.floor(rnd() * 3);
  const n = 1 + Math.floor(rnd() * 3);
  const keys = Array.from({ length: n + (kind === 2 ? 1 : 0) }, () => xonly(seed++));
  let node;
  if (kind === 0) node = p2tr_pk(keys[0]);
  else if (kind === 1) node = p2tr_ns(keys.length, keys)[0];
  else node = p2tr_ms(Math.max(1, keys.length - 1), keys);
  const out = { script: node.script };
  if (rnd() < 0.2) out.leafVersion = 0xc2; // unknown-but-even future version
  if (rnd() < 0.4) out.weight = 1 + Math.floor(rnd() * 8);
  return out;
}
function randTree(depth) {
  if (depth === 0 || rnd() < 0.45) return randLeaf();
  return [randTree(depth - 1), randTree(depth - 1)];
}

for (let i = 0; i < 40; i++) record('random-explicit-' + i, randTree(3), xonly(0xabc000 + i));

// Weighted flat lists through taprootListToTree (Huffman-like arrangement).
for (let i = 0; i < 30; i++) {
  const count = 2 + Math.floor(rnd() * 7);
  const list = Array.from({ length: count }, () => randLeaf());
  record('weighted-list-' + i, taprootListToTree(list), xonly(0xabd000 + i));
}

// Duplicate leaves: same script object twice at different positions.
const dup = p2tr_pk(xonly(0xf00d));
record('duplicate-leaves', [dup, [p2tr_pk(xonly(0xf00e)), dup]], internal);

// Single leaf (no branch).
record('single-leaf', p2tr_pk(xonly(0xf00f)), internal);

// Key-path only (empty tree) for tweak-only verification.
const r0 = p2tr(internal, undefined);
cases.push({
  tag: 'key-path-only',
  internalKey: hex.encode(internal),
  tweakedPubkey: hex.encode(r0.tweakedPubkey),
  tapMerkleRoot: '',
  address: r0.address,
  leaves: [],
});

// Deep-but-valid tree: leftmost-leaf merkle path exactly 128 (consensus max)
// must still construct.
{
  let deep = p2tr_pk(xonly(0xde128));
  for (let d = 0; d < 127; d++) deep = [deep, p2tr_pk(xonly(0xde000 + d))];
  record('depth-128', deep, internal);
}

// Boundary: path length 128 (max, 128 wraps) must succeed; path length 129
// (129 wraps) is consensus-invalid for script-path and must throw via
// TaprootControlBlock merklePath bound.
{
  let deep = p2tr_pk(xonly(0xde12a));
  for (let d = 0; d < 128; d++) deep = [deep, p2tr_pk(xonly(0xde200 + d))];
  record('path-128-boundary-ok', deep, internal);
}
{
  let deep = p2tr_pk(xonly(0xde129));
  for (let d = 0; d < 129; d++) deep = [deep, p2tr_pk(xonly(0xde100 + d))];
  let err = null;
  try { p2tr(internal, deep); } catch (e) { err = String(e); }
  cases.push({ tag: 'path-129-must-throw', threw: err !== null, error: err });
}

// Adversarial nesting: measure recursion-stack behavior for degenerate trees.
// A small precomputed leaf pool keeps construction cheap; duplicate leaf
// objects are fine for the nesting-depth measurement.
const poolLeafA = p2tr_pk(xonly(0xbad));
const poolLeafB = p2tr_pk(xonly(0xbad001));
for (const depth of [1000, 10000, 100000, 1000000]) {
  let deep = poolLeafA;
  for (let d = 0; d < depth; d++) deep = [deep, poolLeafB];
  let err = null;
  const t0 = Date.now();
  try { p2tr(internal, deep); } catch (e) { err = String(e && e.message || e).slice(0, 120); }
  cases.push({ tag: 'nested-depth-' + depth, ms: Date.now() - t0, error: err });
}

// tapLeafHash vs published BIP341-style sanity: hash of OP_TRUE at 0xc0 is a
// known constant in several implementations; cross-checked in Python instead.
cases.push({
  tag: 'tapleaf-op-true',
  tapLeafHash: hex.encode(tapLeafHash(new Uint8Array([0x51]))),
});

console.log(JSON.stringify(cases, null, 1));

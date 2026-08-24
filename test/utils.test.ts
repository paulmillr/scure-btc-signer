import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { it } from '@paulmillr/jsbt/test.js';
import { hex } from '@scure/base';
import { deepStrictEqual, throws } from 'node:assert';
import * as btc from '../src/index.ts';
import * as btcUtils from '../src/utils.ts';

// Regression tests.
const privA = hex.decode('02'.repeat(32));

it('Packed CompactSize', () => {
  const CASES = [
    [20n, 1, [0x14]],
    [32n, 1, [0x20]],
    [200n, 1, [0xc8]],
    [252n, 1, [0xfc]],
    [253n, 3, [0xfd, 0xfd, 0x00]],
    [40000n, 3, [0xfd, 0x40, 0x9c]],
    [65535n, 3, [0xfd, 0xff, 0xff]],
    [65536n, 5, [0xfe, 0x00, 0x00, 0x01, 0x00]],
    [2000000000n, 5, [0xfe, 0x00, 0x94, 0x35, 0x77]],
    [2000000000n, 5, [0xfe, 0x00, 0x94, 0x35, 0x77]],
    [4294967295n, 5, [0xfe, 0xff, 0xff, 0xff, 0xff]],
    [4294967296n, 9, [0xff, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00]],
    [500000000000000000n, 9, [0xff, 0x00, 0x00, 0xb2, 0xd3, 0x59, 0x5b, 0xf0, 0x06]],
    [18446744073709551615n, 9, [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]],
  ];
  for (const [num, sz, arr] of CASES) {
    const bytes = Uint8Array.from(arr);
    const p = btc.CompactSize.encode(num);
    deepStrictEqual(p.length, sz);
    const unpacked = btc.CompactSize.decode(bytes);
    deepStrictEqual(unpacked, num);
    deepStrictEqual(unpacked, btc.CompactSize.decode(p));
  }
  throws(() => CompactSize.decode([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]));
});

it('cmp', () => {
  // From python
  const CASES = [
    [[0], [0], 0],
    [[0], [1], -1],
    [[1], [0], 1],
    [[0, 1], [0, 1], 0],
    [[0, 1], [0, 2], -1],
    [[0, 2], [0, 1], 1],
    [[0, 1], [0], 1],
    [[0], [0, 1], -1],
    [[1, 2, 3], [4, 5, 6], -1],
  ];
  for (let [l, r, ret] of CASES)
    deepStrictEqual(
      btc.utils.compareBytes(new Uint8Array(l), new Uint8Array(r)),
      ret,
      `l=${l} r=${r} ret=${ret}`
    );
  throws(() => btc.utils.compareBytes('x' as any, new Uint8Array()), TypeError);
});

it('utils validator constructors', () => {
  throws(() => btcUtils.validatePubkey(new Uint8Array(32), btcUtils.PubT.ecdsa), RangeError);
  throws(() => btcUtils.validatePubkey(new Uint8Array(33), btcUtils.PubT.schnorr), RangeError);
  throws(() => btcUtils.validatePubkey(new Uint8Array(33), 99 as any), TypeError);
});

it('reverseObject handles string values that match Object prototype names', () => {
  deepStrictEqual({ ...btcUtils.reverseObject({ a: 'toString' }) }, { toString: 'a' });
  deepStrictEqual({ ...btcUtils.reverseObject({ a: 'hasOwnProperty' }) }, { hasOwnProperty: 'a' });
});

it('signECDSA rejects non-32-byte hashes', () => {
  throws(() => btcUtils.signECDSA(Uint8Array.of(1, 2, 3), btcUtils.randomPrivateKeyBytes()));
});

it('taprootTweakPrivKey rejects non-32-byte secret keys', () => {
  const key = (len: number) => {
    const out = new Uint8Array(len);
    out[len - 1] = 1;
    return out;
  };
  throws(() => btcUtils.taprootTweakPrivKey(key(31), new Uint8Array()));
  throws(() => btcUtils.taprootTweakPrivKey(key(33), new Uint8Array()));
  throws(() => btcUtils.taprootTweakPrivKey(key(1), new Uint8Array()));
});

it('taprootTweakPubkey rejects non-32-byte x-only pubkeys', () => {
  const sk = Uint8Array.from(Array.from({ length: 32 }, (_, i) => i + 1));
  const pub = btcUtils.pubSchnorr(sk);
  throws(() => btcUtils.taprootTweakPubkey(Uint8Array.of(1), new Uint8Array()));
  throws(() => btcUtils.taprootTweakPubkey(pub.slice(1), new Uint8Array()));
  throws(() => btcUtils.taprootTweakPubkey(Uint8Array.from([0, ...pub]), new Uint8Array()));
});

it('cmpBig', () => {
  const CASES = [
    [0n, 0n, 0],
    [0n, 1n, -1],
    [1n, 0n, 1],
  ];
  for (let [l, r, ret] of CASES)
    deepStrictEqual(btc._cmpBig(l, r), ret, `l=${l} r=${r} ret=${ret}`);
});

it('combinations', () => {
  // Looks ok, but still have a feeling like there is off by one bug lying around.
  throws(() => btc.combinations(0, ['A', 'B', 'C']));
  throws(() => btc.combinations(-1, ['A', 'B', 'C']));
  throws(() => btc.combinations(1.5, ['A', 'B', 'C']));
  // 2 elms
  deepStrictEqual(btc.combinations(1, ['A', 'B']), [['A'], ['B']]);
  deepStrictEqual(btc.combinations(2, ['A', 'B']), [['A', 'B']]);
  throws(() => btc.combinations(3, ['A', 'B']));
  // 3 elms
  deepStrictEqual(btc.combinations(1, ['A', 'B', 'C']), [['A'], ['B'], ['C']]);
  deepStrictEqual(btc.combinations(2, ['A', 'B', 'C']), [
    ['A', 'B'],
    ['A', 'C'],
    ['B', 'C'],
  ]);
  deepStrictEqual(btc.combinations(3, ['A', 'B', 'C']), [['A', 'B', 'C']]);
  throws(() => btc.combinations(4, ['A', 'B', 'C']));
  // 4 elms
  deepStrictEqual(btc.combinations(1, ['A', 'B', 'C', 'D']), [['A'], ['B'], ['C'], ['D']]);
  deepStrictEqual(btc.combinations(2, ['A', 'B', 'C', 'D']), [
    ['A', 'B'],
    ['A', 'C'],
    ['A', 'D'],
    ['B', 'C'],
    ['B', 'D'],
    ['C', 'D'],
  ]);
  deepStrictEqual(btc.combinations(3, ['A', 'B', 'C', 'D']), [
    ['A', 'B', 'C'],
    ['A', 'B', 'D'],
    ['A', 'C', 'D'],
    ['B', 'C', 'D'],
  ]);
  deepStrictEqual(btc.combinations(4, ['A', 'B', 'C', 'D']), [['A', 'B', 'C', 'D']]);
  throws(() => btc.combinations(5, ['A', 'B', 'C', 'D']));
  // 5 elms
  deepStrictEqual(btc.combinations(1, ['A', 'B', 'C', 'D', 'E']), [
    ['A'],
    ['B'],
    ['C'],
    ['D'],
    ['E'],
  ]);
  deepStrictEqual(btc.combinations(2, ['A', 'B', 'C', 'D', 'E']), [
    ['A', 'B'],
    ['A', 'C'],
    ['A', 'D'],
    ['A', 'E'],
    ['B', 'C'],
    ['B', 'D'],
    ['B', 'E'],
    ['C', 'D'],
    ['C', 'E'],
    ['D', 'E'],
  ]);
  deepStrictEqual(btc.combinations(3, ['A', 'B', 'C', 'D', 'E']), [
    ['A', 'B', 'C'],
    ['A', 'B', 'D'],
    ['A', 'B', 'E'],
    ['A', 'C', 'D'],
    ['A', 'C', 'E'],
    ['A', 'D', 'E'],
    ['B', 'C', 'D'],
    ['B', 'C', 'E'],
    ['B', 'D', 'E'],
    ['C', 'D', 'E'],
  ]);
  deepStrictEqual(btc.combinations(4, ['A', 'B', 'C', 'D', 'E']), [
    ['A', 'B', 'C', 'D'],
    ['A', 'B', 'C', 'E'],
    ['A', 'B', 'D', 'E'],
    ['A', 'C', 'D', 'E'],
    ['B', 'C', 'D', 'E'],
  ]);
  deepStrictEqual(btc.combinations(5, ['A', 'B', 'C', 'D', 'E']), [['A', 'B', 'C', 'D', 'E']]);
  throws(() => btc.combinations(6, ['A', 'B', 'C', 'D', 'E']));
  // 6 elms
  deepStrictEqual(btc.combinations(1, ['A', 'B', 'C', 'D', 'E', 'F']), [
    ['A'],
    ['B'],
    ['C'],
    ['D'],
    ['E'],
    ['F'],
  ]);
  deepStrictEqual(btc.combinations(2, ['A', 'B', 'C', 'D', 'E', 'F']), [
    ['A', 'B'],
    ['A', 'C'],
    ['A', 'D'],
    ['A', 'E'],
    ['A', 'F'],
    ['B', 'C'],
    ['B', 'D'],
    ['B', 'E'],
    ['B', 'F'],
    ['C', 'D'],
    ['C', 'E'],
    ['C', 'F'],
    ['D', 'E'],
    ['D', 'F'],
    ['E', 'F'],
  ]);
  deepStrictEqual(btc.combinations(3, ['A', 'B', 'C', 'D', 'E', 'F']), [
    ['A', 'B', 'C'],
    ['A', 'B', 'D'],
    ['A', 'B', 'E'],
    ['A', 'B', 'F'],
    ['A', 'C', 'D'],
    ['A', 'C', 'E'],
    ['A', 'C', 'F'],
    ['A', 'D', 'E'],
    ['A', 'D', 'F'],
    ['A', 'E', 'F'],
    ['B', 'C', 'D'],
    ['B', 'C', 'E'],
    ['B', 'C', 'F'],
    ['B', 'D', 'E'],
    ['B', 'D', 'F'],
    ['B', 'E', 'F'],
    ['C', 'D', 'E'],
    ['C', 'D', 'F'],
    ['C', 'E', 'F'],
    ['D', 'E', 'F'],
  ]);
  deepStrictEqual(btc.combinations(4, ['A', 'B', 'C', 'D', 'E', 'F']), [
    ['A', 'B', 'C', 'D'],
    ['A', 'B', 'C', 'E'],
    ['A', 'B', 'C', 'F'],
    ['A', 'B', 'D', 'E'],
    ['A', 'B', 'D', 'F'],
    ['A', 'B', 'E', 'F'],
    ['A', 'C', 'D', 'E'],
    ['A', 'C', 'D', 'F'],
    ['A', 'C', 'E', 'F'],
    ['A', 'D', 'E', 'F'],
    ['B', 'C', 'D', 'E'],
    ['B', 'C', 'D', 'F'],
    ['B', 'C', 'E', 'F'],
    ['B', 'D', 'E', 'F'],
    ['C', 'D', 'E', 'F'],
  ]);
  deepStrictEqual(btc.combinations(5, ['A', 'B', 'C', 'D', 'E', 'F']), [
    ['A', 'B', 'C', 'D', 'E'],
    ['A', 'B', 'C', 'D', 'F'],
    ['A', 'B', 'C', 'E', 'F'],
    ['A', 'B', 'D', 'E', 'F'],
    ['A', 'C', 'D', 'E', 'F'],
    ['B', 'C', 'D', 'E', 'F'],
  ]);
  deepStrictEqual(btc.combinations(6, ['A', 'B', 'C', 'D', 'E', 'F']), [
    ['A', 'B', 'C', 'D', 'E', 'F'],
  ]);
  throws(() => btc.combinations(7, ['A', 'B', 'C', 'D', 'E', 'F']));
  // NOTE: it is exponential
  const cases = [
    [10, 210],
    [20, 38760],
    [30, 593775],
    // [40, 3838380], // too slow
  ];
  for (const [length, combLen] of cases) {
    const list = Array.from({ length }, (_, i) => i);
    if (combLen > btc.MAX_COMBINATIONS)
      throws(
        () => btc.combinations(6, list),
        new RegExp(`materialization limit=${btc.MAX_COMBINATIONS}`)
      );
    deepStrictEqual(
      // Large generic materializations remain available only through an explicit caller limit.
      btc.combinations(6, list, combLen).length,
      combLen
    );
  }
});

it('CompactSize boundaries and minimality', () => {
  // Pins each encoding-width boundary across the hoisted-limits refactor.
  const vectors: [bigint, string][] = [
    [0n, '00'],
    [0xfcn, 'fc'],
    [0xfdn, 'fdfd00'],
    [0xffffn, 'fdffff'],
    [0x10000n, 'fe00000100'],
    [0xffffffffn, 'feffffffff'],
    [0x100000000n, 'ff0000000001000000'],
    [0xffffffffffffffffn, 'ffffffffffffffffff'],
  ];
  for (const [num, exp] of vectors) {
    deepStrictEqual(hex.encode(btc.CompactSize.encode(num)), exp, `encode(${num})`);
    deepStrictEqual(btc.CompactSize.decode(hex.decode(exp)), num, `decode(${exp})`);
  }
  throws(() => btc.CompactSize.encode(-1n));
  throws(() => btc.CompactSize.encode(2n ** 64n));
  // Non-minimal encodings must reject (BIP-174 requirement).
  throws(() => btc.CompactSize.decode(hex.decode('fd0100')));
  throws(() => btc.CompactSize.decode(hex.decode('fe01000000')));
  throws(() => btc.CompactSize.decode(hex.decode('ff0100000000000000')));
});

it('low-R grinding always yields 32-byte DER r', () => {
  // Pins the hoisted LOW_R_BOUND refactor: ground signatures must never need the
  // 33-byte padded DER r form, and must remain valid ECDSA signatures.
  const pub = btcUtils.pubECDSA(privA);
  let unGroundHighRSeen = false;
  for (let i = 0; i < 16; i++) {
    const hash = btcUtils.sha256(new Uint8Array([i]));
    const plain = secp256k1.Signature.fromBytes(btcUtils.signECDSA(hash, privA), 'der');
    if (plain.r >= 2n ** 255n) unGroundHighRSeen = true; // control: grinding has work to do
    const sig = btcUtils.signECDSA(hash, privA, true);
    deepStrictEqual(sig[0], 0x30);
    deepStrictEqual(sig[2], 0x02);
    deepStrictEqual(sig[3] <= 32, true, `DER r length for i=${i}`);
    const parsed = secp256k1.Signature.fromBytes(sig, 'der');
    deepStrictEqual(secp256k1.verify(parsed.toBytes(), hash, pub, { prehash: false }), true);
  }
  deepStrictEqual(unGroundHighRSeen, true);
});

it('taproot tweak priv/pub consistency and BIP341 H constant', () => {
  // pubSchnorr(taprootTweakPrivKey(k)) must equal taprootTweakPubkey(pubSchnorr(k))
  // for both internal-key parities, and key-path signatures must verify under the
  // tweaked output key.
  const parities = new Set<number>();
  for (const c of ['02', '03', '04', '05']) {
    const priv = hex.decode(c.repeat(32));
    const pub = btcUtils.pubSchnorr(priv);
    const [tweakedPub, parity] = btcUtils.taprootTweakPubkey(pub, new Uint8Array(0));
    parities.add(parity);
    const tweakedPriv = btcUtils.taprootTweakPrivKey(priv);
    deepStrictEqual(btcUtils.pubSchnorr(tweakedPriv), tweakedPub);
    const msg = btcUtils.sha256(pub);
    const sig = btcUtils.signSchnorr(msg, tweakedPriv, new Uint8Array(32));
    deepStrictEqual(schnorr.verify(sig, msg, tweakedPub), true);
  }
  deepStrictEqual([...parities].sort(), [0, 1]); // both branches exercised
  // The unspendable internal key is the fixed BIP341 "nothing up my sleeve" H point.
  deepStrictEqual(
    hex.encode(btcUtils.TAPROOT_UNSPENDABLE_KEY),
    '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0'
  );
});

it.runWhen(import.meta.url);

/**
 * BTC P2P layer from BIP324.
 *
 * Experimental ElligatorSwift implementation:
 * Schnorr-like x-only ECDH with public keys indistinguishable from uniformly random bytes.
 *
 * Documented in
 * [BIP324](https://github.com/bitcoin/bips/blob/master/bip-0324.mediawiki),
 * [libsecp](https://github.com/bitcoin/bitcoin/blob/master/src/secp256k1/doc/ellswift.md).
 *
 * SwiftEC: Shallue-van de Woestijne Indifferentiable Function to Elliptic Curves.
 * Documented in https://eprint.iacr.org/2022/759.pdf.
 *
 * Curve25519 & P-521 are incompatible with SwiftEC. Differences from SwiftEC:
 * * undefined inputs are remapped
 * * y-parity is encoded in u/t values
 *
 * @module
 */

import { FpIsSquare } from '@noble/curves/abstract/modular.js';
import type { Hex } from '@noble/curves/abstract/utils.js';
import {
  bytesToNumberBE,
  concatBytes,
  ensureBytes,
  numberToBytesBE,
} from '@noble/curves/abstract/utils.js';
import { type ProjPointType as PointType } from '@noble/curves/abstract/weierstrass.js';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { randomBytes } from '@noble/hashes/utils.js';
import { tagSchnorr } from './utils.ts';

const Fp = secp256k1.CURVE.Fp;
const Point = secp256k1.ProjectivePoint;

const _1n = BigInt(1);
const _2n = BigInt(2);

const MINUS_3_SQRT = Fp.sqrt(Fp.create(BigInt(-3)));
const _3n = BigInt(3);
const _4n = BigInt(4);
const _7n = BigInt(7);
const isValidX = (x: bigint) => FpIsSquare(Fp, Fp.add(Fp.mul(Fp.mul(x, x), x), _7n));
const trySqrt = (x: bigint): bigint | void => {
  try {
    return Fp.sqrt(x);
  } catch (_e) {}
};

/**
 * Experimental ElligatorSwift implementation:
 * Schnorr-like x-only ECDH with public keys indistinguishable from uniformly random bytes.
 * Documented in BIP324.
 */
export const elligatorSwift = {
  // (internal stuff, exported for tests only): decode(u, _inv(x, u)) = x
  _inv: (x: bigint, u: bigint, ellCase: number): bigint | void => {
    if (!Number.isSafeInteger(ellCase) || ellCase < 0 || ellCase > 7)
      throw new Error(`elligatorSwift._inv: wrong case=${ellCase}`);
    let v: bigint, s: bigint;
    // Most rejections happens in 3 condition (in comments, ~33% each)
    const u2 = Fp.mul(u, u); // u**2
    const u3 = Fp.mul(u2, u); // u**3
    if ((ellCase & 2) === 0) {
      if (isValidX(Fp.sub(Fp.neg(x), u))) return; // [1 condition]
      v = x;
      s = Fp.div(Fp.neg(Fp.add(u3, _7n)), Fp.add(Fp.add(u2, Fp.mul(u, v)), Fp.mul(v, v))); // = -(u**3 + 7) / (u**2 + u*v + v**2)
    } else {
      s = Fp.sub(x, u); // x - u
      if (Fp.is0(s)) return;
      const t0 = Fp.add(u3, _7n); // (u**3 + 7)
      const t1 = Fp.mul(Fp.mul(_3n, s), u2); // 3 * s * u**2
      // r = (-s * (4 * (u**3 + 7) + 3 * s * u**2)).sqrt()
      const r = trySqrt(Fp.mul(Fp.neg(s), Fp.add(Fp.mul(_4n, t0), t1)));
      if (r === undefined) return; // [2 condition]
      if (ellCase & 1 && Fp.is0(r)) return;
      v = Fp.div(Fp.add(Fp.neg(u), Fp.div(r, s)), _2n); // v = (-u + r / s) / 2
    }
    const w = trySqrt(s);
    if (w === undefined) return; // [3 condition]
    const last = ellCase & 5; // ellCase = 0..8, last = 0,1,4,5
    const t0 = last & 1 ? Fp.add(_1n, MINUS_3_SQRT) : Fp.sub(_1n, MINUS_3_SQRT);
    const w0 = last === 0 || last === 5 ? Fp.neg(w) : w; // -w | w
    // w0 * (u * t0 / 2 + v)
    return Fp.mul(w0, Fp.add(Fp.div(Fp.mul(u, t0), _2n), v));
  },
  // Encode public key (point or x coordinate bigint) into 64-byte pseudorandom encoding
  encode: (x: bigint | PointType<bigint>): Uint8Array => {
    if (x instanceof secp256k1.ProjectivePoint) x = x.x;
    if (typeof x !== 'bigint') {
      throw new Error(
        'elligatorSwift.encode: wrong public key. Should be Projective point or x coordinate (bigint)'
      );
    }
    // 200k test cycles per keygen: avg=4 max=48
    // seems too much, but same as for reference implementation
    while (true) {
      // random scalar 1..Fp.ORDER
      const u = Fp.create(Fp.fromBytes(secp256k1.utils.randomPrivateKey()));
      const ellCase = randomBytes(1)[0] & 7; // [0..8)
      const t = elligatorSwift._inv(x, u, ellCase);
      if (!t) continue;
      return concatBytes(numberToBytesBE(u, 32), numberToBytesBE(t, 32));
    }
  },
  // Decode elligatorSwift point to xonly
  decode: (data: Hex): Uint8Array => {
    const _data = ensureBytes('data', data, 64);
    let u = Fp.create(Fp.fromBytes(_data.subarray(0, 32)));
    let t = Fp.create(Fp.fromBytes(_data.subarray(32, 64)));
    if (Fp.is0(u)) u = Fp.create(_1n);
    if (Fp.is0(t)) t = Fp.create(_1n);
    const u3 = Fp.mul(Fp.mul(u, u), u); // u**3
    const u3plus7 = Fp.add(u3, _7n);
    // u**3 + t**2 + 7 == 0 -> t = 2 * t
    if (Fp.is0(Fp.add(u3plus7, Fp.mul(t, t)))) t = Fp.add(t, t);
    // X = (u**3 + 7 - t**2) / (2 * t)
    const x = Fp.div(Fp.sub(u3plus7, Fp.mul(t, t)), Fp.add(t, t));
    // Y = (X + t) / (MINUS_3_SQRT * u);
    const y = Fp.div(Fp.add(x, t), Fp.mul(MINUS_3_SQRT, u));
    // try different cases
    let res = Fp.add(u, Fp.mul(Fp.mul(y, y), _4n)); // u + 4 * Y ** 2,
    if (isValidX(res)) return numberToBytesBE(res, 32);
    res = Fp.div(Fp.sub(Fp.div(Fp.neg(x), y), u), _2n); // (-X / Y - u) / 2
    if (isValidX(res)) return numberToBytesBE(res, 32);
    res = Fp.div(Fp.sub(Fp.div(x, y), u), _2n); // (X / Y - u) / 2
    if (isValidX(res)) return numberToBytesBE(res, 32);
    throw new Error('elligatorSwift: cannot decode public key');
  },
  // Generate pair (public key, secret key)
  keygen: () => {
    const privateKey = secp256k1.utils.randomPrivateKey();
    const publicKey = elligatorSwift.encode(Point.fromPrivateKey(privateKey));
    return { privateKey, publicKey };
  },
  // Generates shared secret between a pub key and a priv key
  getSharedSecret: (privateKeyA: Hex, publicKeyB: Hex) => {
    const pub = elligatorSwift.decode(publicKeyB);
    const priv = ensureBytes('privKey', privateKeyA, 32);
    const point = schnorr.utils.lift_x(Fp.fromBytes(pub));
    const d = bytesToNumberBE(priv);
    return numberToBytesBE(point.multiply(d).x, 32);
  },
  // BIP324 shared secret
  getSharedSecretBip324: (
    privateKeyOurs: Hex,
    publicKeyTheirs: Hex,
    publicKeyOurs: Hex,
    initiating: boolean
  ) => {
    const ours = ensureBytes('publicKeyOurs', publicKeyOurs);
    const theirs = ensureBytes('publicKeyTheirs', publicKeyTheirs);
    const ecdhPoint = elligatorSwift.getSharedSecret(privateKeyOurs, theirs);
    const pubs = initiating ? [ours, theirs] : [theirs, ours];
    return tagSchnorr('bip324_ellswift_xonly_ecdh', ...pubs, ecdhPoint);
  },
};

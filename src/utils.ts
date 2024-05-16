import { utils as packedUtils, U32LE } from 'micro-packed';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { sha256 } from '@noble/hashes/sha256';
import { secp256k1 as secp, schnorr } from '@noble/curves/secp256k1';

export type Bytes = Uint8Array;
const Point = secp.ProjectivePoint;
const CURVE_ORDER = secp.CURVE.n;

const { isBytes, concatBytes, equalBytes } = packedUtils;
export { sha256, isBytes, concatBytes, equalBytes };

export const hash160 = (msg: Bytes) => ripemd160(sha256(msg));
export const sha256x2 = (...msgs: Bytes[]) => sha256(sha256(concatBytes(...msgs)));
export const randomPrivateKeyBytes = schnorr.utils.randomPrivateKey;
export const pubSchnorr = schnorr.getPublicKey as (priv: string | Uint8Array) => Uint8Array;
export const pubECDSA = secp.getPublicKey;

// low-r signature grinding. Used to reduce tx size by 1 byte.
// noble/secp256k1 does not support the feature: it is not used outside of BTC.
// We implement it manually, because in BTC it's common.
// Not best way, but closest to bitcoin implementation (easier to check)
const hasLowR = (sig: { r: bigint; s: bigint }) => sig.r < CURVE_ORDER / 2n;
export function signECDSA(hash: Bytes, privateKey: Bytes, lowR = false): Bytes {
  let sig = secp.sign(hash, privateKey);
  if (lowR && !hasLowR(sig)) {
    const extraEntropy = new Uint8Array(32);
    let counter = 0;
    while (!hasLowR(sig)) {
      extraEntropy.set(U32LE.encode(counter++));
      sig = secp.sign(hash, privateKey, { extraEntropy });
      if (counter > 4294967295) throw new Error('lowR counter overflow: report the error');
    }
  }
  return sig.toDERRawBytes();
}

export const signSchnorr = schnorr.sign;
export const tagSchnorr = schnorr.utils.taggedHash;

export enum PubT {
  ecdsa,
  schnorr,
}
export function validatePubkey(pub: Bytes, type: PubT): Bytes {
  const len = pub.length;
  if (type === PubT.ecdsa) {
    if (len === 32) throw new Error('Expected non-Schnorr key');
    Point.fromHex(pub); // does assertValidity
    return pub;
  } else if (type === PubT.schnorr) {
    if (len !== 32) throw new Error('Expected 32-byte Schnorr key');
    schnorr.utils.lift_x(schnorr.utils.bytesToNumberBE(pub));
    return pub;
  } else {
    throw new Error('Unknown key type');
  }
}

export function tapTweak(a: Bytes, b: Bytes): bigint {
  const u = schnorr.utils;
  const t = u.taggedHash('TapTweak', a, b);
  const tn = u.bytesToNumberBE(t);
  if (tn >= CURVE_ORDER) throw new Error('tweak higher than curve order');
  return tn;
}

export function taprootTweakPrivKey(privKey: Uint8Array, merkleRoot = new Uint8Array()) {
  const u = schnorr.utils;
  const seckey0 = u.bytesToNumberBE(privKey); // seckey0 = int_from_bytes(seckey0)
  const P = Point.fromPrivateKey(seckey0); // P = point_mul(G, seckey0)
  // seckey = seckey0 if has_even_y(P) else SECP256K1_ORDER - seckey0
  const seckey = P.hasEvenY() ? seckey0 : u.mod(-seckey0, CURVE_ORDER);
  const xP = u.pointToBytes(P);
  // t = int_from_bytes(tagged_hash("TapTweak", bytes_from_int(x(P)) + h)); >= SECP256K1_ORDER check
  const t = tapTweak(xP, merkleRoot);
  // bytes_from_int((seckey + t) % SECP256K1_ORDER)
  return u.numberToBytesBE(u.mod(seckey + t, CURVE_ORDER), 32);
}

export function taprootTweakPubkey(pubKey: Uint8Array, h: Uint8Array): [Uint8Array, number] {
  const u = schnorr.utils;
  const t = tapTweak(pubKey, h); // t = int_from_bytes(tagged_hash("TapTweak", pubkey + h))
  const P = u.lift_x(u.bytesToNumberBE(pubKey)); // P = lift_x(int_from_bytes(pubkey))
  const Q = P.add(Point.fromPrivateKey(t)); // Q = point_add(P, point_mul(G, t))
  const parity = Q.hasEvenY() ? 0 : 1; // 0 if has_even_y(Q) else 1
  return [u.pointToBytes(Q), parity]; // bytes_from_int(x(Q))
}

// Another stupid decision, where lack of standard affects security.
// Multisig needs to be generated with some key.
// We are using approach from BIP 341/bitcoinjs-lib: SHA256(uncompressedDER(SECP256K1_GENERATOR_POINT))
// It is possible to switch SECP256K1_GENERATOR_POINT with some random point;
// but it's too complex to prove.
// Also used by bitcoin-core and bitcoinjs-lib
export const TAPROOT_UNSPENDABLE_KEY = sha256(Point.BASE.toRawBytes(false));

export const NETWORK = {
  bech32: 'bc',
  pubKeyHash: 0x00,
  scriptHash: 0x05,
  wif: 0x80,
};

export const TEST_NETWORK: typeof NETWORK = {
  bech32: 'tb',
  pubKeyHash: 0x6f,
  scriptHash: 0xc4,
  wif: 0xef,
};

// Exported for tests, internal method
export function compareBytes(a: Bytes, b: Bytes) {
  if (!isBytes(a) || !isBytes(b)) throw new Error(`cmp: wrong type a=${typeof a} b=${typeof b}`);
  // -1 -> a<b, 0 -> a==b, 1 -> a>b
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) if (a[i] != b[i]) return Math.sign(a[i] - b[i]);
  return Math.sign(a.length - b.length);
}

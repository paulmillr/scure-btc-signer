import { schnorr, secp256k1 as secp } from '@noble/curves/secp256k1.js';
import { abytes, bytesToNumberBE, numberToBytesBE } from '@noble/curves/utils.js';
import { ripemd160 } from '@noble/hashes/legacy.js';
import { sha256 as nobleSha256 } from '@noble/hashes/sha2.js';
import { type TArg, type TRet } from '@noble/hashes/utils.js';
import { utils as packedUtils, U32LE } from 'micro-packed';
export { type TArg, type TRet } from '@noble/hashes/utils.js';

/** Hex-like input accepted by helpers in this module. */
export type Hex = string | Uint8Array;
/** Byte array alias used across the library. */
export type Bytes = Uint8Array;

const Point = /* @__PURE__ */ (() => secp.Point)();
const Fn = /* @__PURE__ */ (() => Point.Fn)();
const CURVE_ORDER = /* @__PURE__ */ (() => Point.Fn.ORDER)();
/**
 * Checks whether a curve y-coordinate is even.
 * @param y - y-coordinate to inspect
 * @returns `true` when the coordinate is even.
 * @example
 * Check whether a point coordinate has even parity.
 * ```ts
 * hasEven(2n);
 * ```
 */
export const hasEven = (y: bigint) => y % 2n === 0n;

/**
 * Checks whether a value is a Uint8Array.
 * @param a - value to inspect
 * @returns `true` when the value is a Uint8Array.
 * @example
 * Check whether an unknown value is already bytes.
 * ```ts
 * isBytes(new Uint8Array([1]));
 * ```
 */
export const isBytes: (a: unknown) => a is Uint8Array = /* @__PURE__ */ (() =>
  packedUtils.isBytes)();
/**
 * Concatenates byte arrays into a single Uint8Array.
 * @param arrays - byte arrays to concatenate
 * @returns Concatenated byte array.
 * @example
 * Join several byte chunks before hashing or signing them.
 * ```ts
 * concatBytes(new Uint8Array([1]), new Uint8Array([2]));
 * ```
 */
export const concatBytes: (...arrays: TArg<Uint8Array[]>) => TRet<Uint8Array> =
  /* @__PURE__ */ (() =>
    packedUtils.concatBytes as (...arrays: TArg<Uint8Array[]>) => TRet<Uint8Array>)();
/**
 * Compares two byte arrays for equality.
 * @param a - first byte array
 * @param b - second byte array
 * @returns `true` when both arrays contain the same bytes.
 * @example
 * Compare two serialized values without converting them first.
 * ```ts
 * equalBytes(new Uint8Array([1]), new Uint8Array([1]));
 * ```
 */
export const equalBytes: (a: TArg<Uint8Array>, b: TArg<Uint8Array>) => boolean =
  /* @__PURE__ */ (() =>
    packedUtils.equalBytes as (a: TArg<Uint8Array>, b: TArg<Uint8Array>) => boolean)();
/**
 * SHA-256 hash function.
 * @param msg - bytes to hash
 * @returns SHA-256 digest.
 * @example
 * Hash a byte array with SHA-256.
 * ```ts
 * sha256(new Uint8Array([1, 2, 3]));
 * ```
 */
export const sha256: typeof nobleSha256 = /* @__PURE__ */ (() => nobleSha256)();

/**
 * HASH160 helper used by classic Bitcoin addresses.
 * @param msg - bytes to hash
 * @returns RIPEMD160(SHA256(msg)).
 * @example
 * Derive the HASH160 used by legacy address formats.
 * ```ts
 * hash160(new Uint8Array([1, 2, 3]));
 * ```
 */
export const hash160 = (msg: TArg<Uint8Array>): TRet<Uint8Array> =>
  ripemd160(sha256(msg)) as TRet<Uint8Array>;
/**
 * Double-SHA256 helper used by Bitcoin transaction ids.
 * @param msgs - message parts to concatenate and hash
 * @returns SHA256(SHA256(concat(msgs))).
 * @example
 * Compute the double-SHA256 used by txids and sighashes.
 * ```ts
 * sha256x2(new Uint8Array([1]), new Uint8Array([2]));
 * ```
 */
export const sha256x2 = (...msgs: TArg<Uint8Array[]>): TRet<Uint8Array> =>
  sha256(sha256(concatBytes(...msgs))) as TRet<Uint8Array>;
/**
 * Generates a random secp256k1 private key.
 * @returns Random 32-byte private key.
 * @example
 * Generate a fresh secp256k1 private key for signing.
 * ```ts
 * const privKey = randomPrivateKeyBytes();
 * ```
 */
export const randomPrivateKeyBytes = (): TRet<Uint8Array> =>
  schnorr.utils.randomSecretKey() as TRet<Uint8Array>;
/**
 * Derives a BIP340 Schnorr public key from a private key.
 * @param priv - private key bytes
 * @returns X-only public key bytes.
 * @example
 * Derive the x-only public key used by Schnorr and Taproot.
 * ```ts
 * import { pubSchnorr, randomPrivateKeyBytes } from '@scure/btc-signer/utils.js';
 * pubSchnorr(randomPrivateKeyBytes());
 * ```
 */
export const pubSchnorr = (priv: TArg<Uint8Array>): TRet<Uint8Array> =>
  schnorr.getPublicKey(priv) as TRet<Uint8Array>;
/**
 * Derives a secp256k1 ECDSA public key from a private key.
 * @param privateKey - private key bytes
 * @param isCompressed - whether to return the compressed form
 * @returns Serialized public key bytes.
 * @example
 * Derive the normal secp256k1 public key for legacy or SegWit scripts.
 * ```ts
 * import { pubECDSA, randomPrivateKeyBytes } from '@scure/btc-signer/utils.js';
 * pubECDSA(randomPrivateKeyBytes());
 * ```
 */
export const pubECDSA = (privateKey: TArg<Uint8Array>, isCompressed?: boolean): TRet<Uint8Array> =>
  secp.getPublicKey(privateKey, isCompressed) as TRet<Uint8Array>;

// low-r signature grinding. Used to reduce tx size by 1 byte.
// noble/secp256k1 does not support the feature: it is not used outside of BTC.
// We implement it manually, because in BTC it's common.
// Not best way, but closest to bitcoin implementation (easier to check)
const hasLowR = (sig: { r: bigint; s: bigint }) => sig.r < CURVE_ORDER / 2n;
/**
 * Signs a 32-byte hash with ECDSA and returns DER encoding.
 * @param hash - message hash to sign
 * @param privateKey - signer private key
 * @param lowR - whether to grind for low-R signatures
 * @returns DER-encoded signature bytes.
 * @throws If low-R grinding overflows or ECDSA signing fails validation. {@link Error}
 * @example
 * Hash a message first, then create the DER-encoded ECDSA signature.
 * ```ts
 * import { randomPrivateKeyBytes, sha256, signECDSA } from '@scure/btc-signer/utils.js';
 * signECDSA(sha256(new Uint8Array([1, 2, 3])), randomPrivateKeyBytes());
 * ```
 */
export function signECDSA(hash: TArg<Bytes>, privateKey: TArg<Bytes>, lowR = false): TRet<Bytes> {
  // signECDSA is the 32-byte sighash wrapper for BTC callers, so reject arbitrary-length
  // messages here instead of silently signing them with prehash disabled.
  abytes(hash, 32, 'hash');
  let sig = secp.Signature.fromBytes(secp.sign(hash, privateKey, { prehash: false }));
  if (lowR && !hasLowR(sig)) {
    const extraEntropy = new Uint8Array(32);
    let counter = 0;
    while (!hasLowR(sig)) {
      extraEntropy.set(U32LE.encode(counter++));
      sig = secp.Signature.fromBytes(secp.sign(hash, privateKey, { prehash: false, extraEntropy }));
      if (counter > 4294967295) throw new Error('lowR counter overflow: report the error');
    }
  }
  return sig.toBytes('der') as TRet<Bytes>;
}

/**
 * BIP340 Schnorr signing function.
 * @param message - 32-byte message digest
 * @param secretKey - signer private key
 * @param auxRand - optional auxiliary randomness
 * @returns Schnorr signature bytes.
 * @example
 * Sign a 32-byte digest with the built-in BIP340 helper.
 * ```ts
 * import { randomPrivateKeyBytes, sha256, signSchnorr } from '@scure/btc-signer/utils.js';
 * const msg = sha256(new Uint8Array([1, 2, 3]));
 * signSchnorr(msg, randomPrivateKeyBytes());
 * ```
 */
export const signSchnorr = (
  message: TArg<Uint8Array>,
  secretKey: TArg<Uint8Array>,
  auxRand?: TArg<Uint8Array>
): TRet<Uint8Array> => schnorr.sign(message, secretKey, auxRand) as TRet<Uint8Array>;
/**
 * Tagged-hash helper used by Schnorr and taproot constructions.
 * @param tag - tagged-hash domain separator
 * @param messages - message parts hashed under the tag
 * @returns Tagged SHA-256 digest.
 * @example
 * Build the tagged hash used by Taproot leaves or tweaks.
 * ```ts
 * import { tagSchnorr } from '@scure/btc-signer/utils.js';
 * tagSchnorr('TapLeaf', Uint8Array.of(0xc0), Uint8Array.of(0x51));
 * ```
 */
export const tagSchnorr = (tag: string, ...messages: TArg<Uint8Array[]>): TRet<Uint8Array> =>
  schnorr.utils.taggedHash(tag, ...messages) as TRet<Uint8Array>;

/** Public key format tags used by validation helpers. */
export const PubT = /* @__PURE__ */ (() =>
  Object.freeze({
    ecdsa: 0,
    schnorr: 1,
  }))();
/** Numeric public key format tag from {@link PubT}. */
export type PubT = ValueOf<typeof PubT>;

/**
 * Validates a public key against the expected Bitcoin key encoding.
 * @param pub - public key bytes to validate
 * @param type - expected public key format
 * @returns The validated public key bytes.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Reject keys that do not match the encoding required by the current script path.
 * ```ts
 * import {
 *   PubT,
 *   pubECDSA,
 *   randomPrivateKeyBytes,
 *   validatePubkey,
 * } from '@scure/btc-signer/utils.js';
 * validatePubkey(pubECDSA(randomPrivateKeyBytes()), PubT.ecdsa);
 * ```
 */
export function validatePubkey(pub: TArg<Bytes>, type: PubT): TRet<Bytes> {
  const len = pub.length;
  if (type === PubT.ecdsa) {
    if (len === 32) throw new RangeError('Expected non-Schnorr key');
    Point.fromBytes(pub); // does assertValidity
    return pub as TRet<Bytes>;
  } else if (type === PubT.schnorr) {
    if (len !== 32) throw new RangeError('Expected 32-byte Schnorr key');
    schnorr.utils.lift_x(bytesToNumberBE(pub));
    return pub as TRet<Bytes>;
  } else {
    throw new TypeError('Unknown key type');
  }
}

/**
 * Computes the Taproot tweak scalar from an internal key and merkle root.
 * @param a - internal key bytes
 * @param b - optional merkle root bytes
 * @returns Taproot tweak scalar.
 * @throws If the tweak scalar is outside the curve order. {@link Error}
 * @example
 * Combine the internal key and Merkle root into the Taproot tweak scalar.
 * ```ts
 * import { pubSchnorr, randomPrivateKeyBytes, tapTweak } from '@scure/btc-signer/utils.js';
 * tapTweak(pubSchnorr(randomPrivateKeyBytes()), new Uint8Array());
 * ```
 */
export function tapTweak(a: TArg<Bytes>, b: TArg<Bytes>): bigint {
  const u = schnorr.utils;
  const t = u.taggedHash('TapTweak', a, b);
  const tn = bytesToNumberBE(t);
  if (tn >= CURVE_ORDER) throw new Error('tweak higher than curve order');
  return tn;
}

/**
 * Tweaks a private key for Taproot key-path spending.
 * @param privKey - internal private key bytes
 * @param merkleRoot - optional taproot merkle root
 * @returns Tweaked private key bytes.
 * @throws If the Taproot tweak scalar is outside the curve order. {@link Error}
 * @example
 * Derive the tweaked Taproot key-path secret from the internal private key.
 * ```ts
 * import { randomPrivateKeyBytes, taprootTweakPrivKey } from '@scure/btc-signer/utils.js';
 * taprootTweakPrivKey(randomPrivateKeyBytes());
 * ```
 */
export function taprootTweakPrivKey(
  privKey: TArg<Bytes>,
  merkleRoot: TArg<Bytes> = Uint8Array.of()
): TRet<Bytes> {
  const u = schnorr.utils;
  // BIP341 taproot_tweak_seckey starts with `seckey0 = int_from_bytes(seckey0)`, and
  // BIP340 defines `int(x)` only for `x` as a 32-byte array, so reject other widths here.
  abytes(privKey, 32, 'privKey');
  const seckey0 = bytesToNumberBE(privKey); // seckey0 = int_from_bytes(seckey0)
  const P = Point.BASE.multiply(seckey0); // P = point_mul(G, seckey0)
  // seckey = seckey0 if has_even_y(P) else SECP256K1_ORDER - seckey0
  const seckey = hasEven(P.y) ? seckey0 : Fn.neg(seckey0);
  const xP = u.pointToBytes(P);
  // t = int_from_bytes(tagged_hash("TapTweak", bytes_from_int(x(P)) + h)); >= SECP256K1_ORDER check
  const t = tapTweak(xP, merkleRoot);
  // bytes_from_int((seckey + t) % SECP256K1_ORDER)
  return numberToBytesBE(Fn.add(seckey, t), 32) as TRet<Bytes>;
}

/**
 * Tweaks a Schnorr public key for Taproot key-path spending.
 * @param pubKey - x-only internal public key
 * @param h - taproot merkle root
 * @returns Tweaked public key and output-key parity.
 * @throws If the Taproot tweak scalar is outside the curve order. {@link Error}
 * @example
 * Derive the final Taproot output key from the internal key and Merkle root.
 * ```ts
 * import {
 *   pubSchnorr,
 *   randomPrivateKeyBytes,
 *   taprootTweakPubkey,
 * } from '@scure/btc-signer/utils.js';
 * taprootTweakPubkey(pubSchnorr(randomPrivateKeyBytes()), new Uint8Array());
 * ```
 */
export function taprootTweakPubkey(pubKey: TArg<Bytes>, h: TArg<Bytes>): TRet<[Bytes, number]> {
  const u = schnorr.utils;
  // BIP341 taproot_tweak_pubkey feeds `pubkey` into `int_from_bytes(pubkey)`, and
  // BIP340 defines `int(x)` only for `x` as a 32-byte array, so reject other widths here.
  abytes(pubKey, 32, 'pubKey');
  const t = tapTweak(pubKey, h); // t = int_from_bytes(tagged_hash("TapTweak", pubkey + h))
  const P = u.lift_x(bytesToNumberBE(pubKey)); // P = lift_x(int_from_bytes(pubkey))
  const Q = P.add(Point.BASE.multiply(t)); // Q = point_add(P, point_mul(G, t))
  const parity = hasEven(Q.y) ? 0 : 1; // 0 if has_even_y(Q) else 1
  return [u.pointToBytes(Q), parity] as TRet<[Bytes, number]>; // bytes_from_int(x(Q))
}

// Another stupid decision, where lack of standard affects security.
// Multisig needs to be generated with some key.
// We are using the BIP 341/bitcoinjs-lib approach:
// SHA256(uncompressedDER(SECP256K1_GENERATOR_POINT))
// It is possible to switch SECP256K1_GENERATOR_POINT with some random point;
// but it's too complex to prove.
// Also used by bitcoin-core and bitcoinjs-lib
// This is the fixed BIP 341 H example, not the privacy-preserving H + rG variant.
// Downstream helpers use exact-byte equality with it to recognize
// library-generated script-only outputs.
/** Standard unspendable internal key used for script-only Taproot outputs. */
export const TAPROOT_UNSPENDABLE_KEY: TRet<Bytes> = /* @__PURE__ */ (() =>
  sha256(Point.BASE.toBytes(false)) as TRet<Bytes>)();

/** Bitcoin network parameters. */
export type BTC_NETWORK = {
  /** Human-readable prefix used by Bech32 and Bech32m addresses. */
  bech32: string;
  /** Base58 version byte for pay-to-public-key-hash addresses. */
  pubKeyHash: number;
  /** Base58 version byte for pay-to-script-hash addresses. */
  scriptHash: number;
  /** Base58 version byte for wallet-import-format private keys. */
  wif: number;
};
/** Bitcoin mainnet network parameters. */
export const NETWORK: BTC_NETWORK = /* @__PURE__ */ Object.freeze({
  bech32: 'bc',
  pubKeyHash: 0x00,
  scriptHash: 0x05,
  wif: 0x80,
});

/** Bitcoin testnet network parameters. */
export const TEST_NETWORK: BTC_NETWORK = /* @__PURE__ */ Object.freeze({
  bech32: 'tb',
  pubKeyHash: 0x6f,
  scriptHash: 0xc4,
  wif: 0xef,
});

// Exported for tests, internal method
/**
 * Lexicographically compares two byte arrays.
 * @param a - first byte array
 * @param b - second byte array
 * @returns `-1`, `0`, or `1` depending on the ordering.
 * @throws On wrong argument types. {@link TypeError}
 * @example
 * Compare two serialized keys using Bitcoin's byte ordering.
 * ```ts
 * compareBytes(new Uint8Array([1]), new Uint8Array([2]));
 * ```
 */
export function compareBytes(a: TArg<Bytes>, b: TArg<Bytes>): number {
  if (!isBytes(a) || !isBytes(b))
    throw new TypeError(`cmp: wrong type a=${typeof a} b=${typeof b}`);
  // -1 -> a<b, 0 -> a==b, 1 -> a>b
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) if (a[i] != b[i]) return Math.sign(a[i] - b[i]);
  return Math.sign(a.length - b.length);
}

// Reverses key<->values
/**
 * Reverses an object's keys and values.
 * @param obj - object to reverse
 * @returns Object with original values mapped back to keys.
 * @throws If duplicate values would collide while reversing the object. {@link Error}
 * @example
 * Flip a lookup table so the values become keys.
 * ```ts
 * reverseObject({ a: 1, b: 2 });
 * ```
 */
export function reverseObject<T extends Record<string, string | number>>(
  obj: T
): { [K in T[keyof T]]: Extract<keyof T, string> } {
  // Keep a raw dictionary shape so enum-like tables can reverse values like
  // `toString` without colliding with inherited Object prototype properties.
  const res = Object.create(null) as any;
  for (const k in obj) {
    if (res[obj[k]] !== undefined) throw new Error('duplicate key');
    res[obj[k]] = k;
  }
  return res;
}

/** Union of all value types in an object type. */
export type ValueOf<T> = T[keyof T];

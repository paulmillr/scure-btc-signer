import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { aInRange, concatBytes, equalBytes, numberToBytesBE } from '@noble/curves/utils.js';
import { abytes, anumber, randomBytes } from '@noble/hashes/utils.js';
import * as P from 'micro-packed';
import { compareBytes, hasEven, type TArg, type TRet } from './utils.ts';

/*
MuSig2. This is not the full protocol: only an implementation of primitives from BIP-327.
The implementation can be used to create own protocol,
but you need to implement nonce/partial signatures exchange yourself.
Someday BIP-373 will be more "implementable" and we can use this from PSBT.

Links:
- https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki#user-content-Test_Vectors_and_Reference_Code
- https://github.com/bitcoin/bips/blob/master/bip-0373.mediawiki (PSBT MUSIG2): very raw, no vectors, not implemented for now.
- https://github.com/bitcoin/bips/blob/master/bip-0327/reference.py
*/
// Types
/** Represents a pair of public and secret nonces used in MuSig2 signing. */
export type Nonces = {
  /** Public nonce that gets shared with the other participants. */
  public: Uint8Array;
  /** Secret nonce that stays local until partial signing finishes. */
  secret: Uint8Array;
};
/**
 * Represents a deterministic nonce, including its public part and the
 * resulting partial signature.
 */
export type DetNonce = {
  /** Public nonce that the signer shares for this deterministic signing round. */
  publicNonce: Uint8Array;
  /** Partial signature produced after combining all participant data. */
  partialSig: Uint8Array;
};
/**
 * Represents an error indicating an invalid contribution from a signer.
 * This allows pointing out which participant is malicious and what specifically is wrong.
 * @param idx - signer index with the invalid contribution
 * @param m - error message
 * @example
 * Create an error that points to the participant who sent invalid data.
 * ```ts
 * new InvalidContributionErr(0, 'pubkey');
 * ```
 */
export class InvalidContributionErr extends Error {
  // BIP327 identifiable aborts blame exactly one signer by participant index in the
  // caller's session ordering, so callers interpret idx using the same ordering they signed with.
  readonly idx: number; // Indice of participant
  constructor(idx: number, m: string) {
    super(m);
    this.idx = idx;
  }
}

// Utils
// MuSig2 reuses BIP340 tagged hashing, i.e. SHA256(SHA256(tag) || SHA256(tag) || msg...),
// for all of the domain-separated hashes below (KeyAgg list, noncecoef, challenge, aux, ...).
const taggedHash = /* @__PURE__ */ (() => schnorr.utils.taggedHash)();
// BIP327 uses xbytes(P) = bytes(32, x(P)) for aggregate keys, nonce/challenge hashes,
// and final signatures, so this alias is intentionally x-only instead of 33-byte SEC1.
const pointToBytes = /* @__PURE__ */ (() => schnorr.utils.pointToBytes)();
// MuSig2 keeps aggregate keys/nonces as full secp256k1 points so it can represent infinity
// and inspect parity before exporting compressed or x-only encodings at the API boundaries.
const Point = /* @__PURE__ */ (() => secp256k1.Point)();
type Point = typeof Point.BASE;
// MuSig2 scalars live in Z_n with fixed 32-byte encodings: strict inputs like secret keys
// use Fn.fromBytes(...), tweak bytes allow 0 per ApplyTweak, and hash-derived values are
// intentionally reduced mod n.
const Fn = /* @__PURE__ */ (() => Point.Fn)();
// BIP327 signer keys are plain compressed pubkeys (33 bytes); only aggregate exports switch
// to BIP340's 32-byte x-only format, so the internal input length stays on secp256k1.publicKey.
const PUBKEY_LEN = /* @__PURE__ */ (() => secp256k1.lengths.publicKey!)();
// BIP327 uses bytes(33, 0) both as cbytes_ext(Point.ZERO) for infinity and as GetSecondKey's
// "no second distinct key" sentinel, so this all-zero compressed slot is intentionally out-of-band.
const ZERO = /* @__PURE__ */ new Uint8Array(PUBKEY_LEN); // Compressed zero point

// Encoding
// TODO: re-use in PSBT?
// This is BIP327's cbytes_ext/cpoint_ext adapter: normal points stay in compressed SEC1,
// while Point.ZERO maps to bytes(33, 0) as the out-of-band infinity sentinel for aggnonce.
const compressed = /* @__PURE__ */ (() =>
  P.apply(P.bytes(33), {
    decode: (p: Point) => (isZero(p) ? ZERO : p.toBytes(true)),
    encode: (b: TArg<Uint8Array>) => (equalBytes(b, ZERO) ? Point.ZERO : Point.fromBytes(b)),
  }))();
// This coder is only for stored secnonce limbs k1/k2, which BIP327 requires to be
// nonzero scalars in [1, n); tweak scalars use different validation because 0 is allowed there.
const scalar = /* @__PURE__ */ (() =>
  P.validate(P.U256BE, (n) => {
    aInRange('n', n, 1n, Fn.ORDER);
    return n;
  }))();
// Shared for both per-signer pubnonce bytes and aggregate aggnonce bytes. Because it accepts
// the BIP327 infinity sentinel, so individual pubnonce callers still need
// an explicit zero-point check.
const PubNonce = /* @__PURE__ */ (() => P.struct({ R1: compressed, R2: compressed }))();
// BIP327 stores secnonce as k1 || k2 || pk so Sign can reject reused or
// invalid nonce limbs and detect when the caller pairs the nonce with a
// different individual public key than NonceGen used.
const SecretNonce = /* @__PURE__ */ (() =>
  P.struct({
    k1: scalar,
    k2: scalar,
    publicKey: P.bytes(PUBKEY_LEN),
  }))();

function abytesOptional(b: TArg<Uint8Array | undefined>, ...lengths: number[]) {
  // Optional-byte helper: exact-length checks only happen when callers pass them explicitly.
  if (b !== undefined) abytes(b, ...lengths);
}

function abytesArray(lst: TArg<Uint8Array[]>, ...lengths: number[]) {
  // Element-shape helper only: callers still enforce list-size rules like BIP327's 0 < u < 2^32.
  if (!Array.isArray(lst)) throw new TypeError('expected array');
  lst.forEach((i) => abytes(i, ...lengths));
}

function aXonly(lst: boolean[]) {
  // BIP327 tweak modes are strict booleans; callers should run this before
  // branching on isXonly values because plain JS truthiness would accept invalid inputs.
  if (!Array.isArray(lst)) throw new TypeError('expected array');
  lst.forEach((i, j) => {
    if (typeof i !== 'boolean')
      throw new TypeError('expected boolean in xOnly array, got' + i + '(' + j + ')');
  });
}

// BIP327/BIP340 treat tagged-hash outputs as big-endian integers reduced mod n for
// coefficients, nonce scalars, and challenges; this helper is that int(hash_tag(...)) mod n step.
const taggedInt = (tag: string, ...messages: TArg<Uint8Array[]>) =>
  Fn.create(Fn.fromBytes(taggedHash(tag, ...messages), true));
// BIP327 repeatedly says "use x if the point has even Y, otherwise use n - x"; this
// helper is that parity-conditioned scalar negation for nonce limbs and Q-dependent signs.
const evenScalar = (p: Point, n: bigint) => (hasEven(p.y) ? n : Fn.neg(n));

// Short utility for compat with reference implementation
/**
 * Derives a compressed secp256k1 public key from a private key.
 * @param seckey - signer private key
 * @returns Compressed public key bytes.
 * @example
 * Turn a signer's secret key into the compressed key format MuSig2 expects.
 * ```ts
 * import { schnorr } from '@noble/curves/secp256k1.js';
 * import { IndividualPubkey } from '@scure/btc-signer/musig2.js';
 * IndividualPubkey(schnorr.utils.randomSecretKey());
 * ```
 */
// BIP327 IndividualPubkey is cbytes(d*G): the 33-byte compressed signer key.
// Aggregate exports use separate x-only encoding and should not call this helper.
export function IndividualPubkey(seckey: TArg<Uint8Array>): TRet<Uint8Array> {
  return secp256k1.getPublicKey(seckey, true) as TRet<Uint8Array>;
}
// Same, but returns Point
// Base-point multiply helper for the BIP327 x*G steps below. Point.BASE.multiply rejects 0,
// so call sites that allow zero scalars need to handle that case explicitly instead of using this.
function mulBase(n: bigint): Point {
  return Point.BASE.multiply(n);
}
// Local alias for BIP327's is_infinite(P): used both for rejecting infinity where cpoint(...)
// must never yield it and for the "if R' is infinite, use G" nonce-aggregation fallback.
function isZero(point: Point): boolean {
  return point.equals(Point.ZERO);
}

/**
 * Lexicographically sorts an array of public keys.
 * @param publicKeys - array of public keys
 * @returns A new array containing the sorted public keys.
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Sort participant public keys before building the aggregate MuSig2 key.
 * ```ts
 * import { IndividualPubkey, sortKeys } from '@scure/btc-signer/musig2.js';
 * import { randomPrivateKeyBytes } from '@scure/btc-signer/utils.js';
 * sortKeys([
 *   IndividualPubkey(randomPrivateKeyBytes()),
 *   IndividualPubkey(randomPrivateKeyBytes()),
 * ]);
 * ```
 */
export function sortKeys(publicKeys: TArg<Uint8Array[]>): TRet<Uint8Array[]> {
  // BIP327 KeySort is defined for non-empty signer-key lists, and this helper returns a sorted copy
  // so callers do not lose their original participant ordering as a side effect of key aggregation.
  abytesArray(publicKeys, PUBKEY_LEN);
  if (!publicKeys.length) throw new RangeError('sortKeys: expected non-empty signer key list');
  return Array.from(publicKeys).sort(compareBytes) as TRet<Uint8Array[]>;
}

// Finds second distinct key (to make coefficient 1)
function getSecondKey(publicKeys: TArg<Uint8Array[]>): TRet<Uint8Array> {
  // BIP327 GetSecondKey returns bytes(33, 0) when all signer keys are equal; that sentinel
  // means no key hits the special pk' = pk2 coefficient-1 shortcut in the all-equal case.
  abytesArray(publicKeys, PUBKEY_LEN);
  for (let j = 1; j < publicKeys.length; j++)
    if (!equalBytes(publicKeys[j], publicKeys[0])) return publicKeys[j] as TRet<Uint8Array>;
  return ZERO as TRet<Uint8Array>;
}

function keyAggL(publicKeys: TArg<Uint8Array[]>): TRet<Uint8Array> {
  // BIP327 HashKeys hashes keys in the caller-provided order. Run KeySort first when
  // the surrounding protocol requires the canonical lexicographic participant ordering.
  abytesArray(publicKeys, PUBKEY_LEN);
  return taggedHash('KeyAgg list', ...publicKeys) as TRet<Uint8Array>;
}

function keyAggCoeffInternal(
  publicKey1: TArg<Uint8Array>,
  publicKey2: TArg<Uint8Array>,
  L: TArg<Uint8Array>
): bigint {
  // BIP327 only short-circuits to coefficient 1 for pk' = pk2. When all keys are equal,
  // pk2 is the all-zero sentinel from GetSecondKey, so every real signer key still hashes.
  abytes(publicKey1, PUBKEY_LEN);
  abytes(publicKey2, PUBKEY_LEN);
  if (equalBytes(publicKey1, publicKey2)) return 1n;
  return taggedInt('KeyAgg coefficient', L, publicKey1);
}

/**
 * Aggregates multiple public keys using the MuSig2 key aggregation algorithm.
 * @param publicKeys - individual participant public keys
 * @param tweaks - optional tweaks applied to the aggregate key
 * @param isXonly - whether each tweak uses x-only semantics
 * @returns An object containing the aggregate public key, accumulated sign,
 * and accumulated tweak.
 * @throws If the input is invalid, such as non-array public keys or mismatched
 * tweak metadata. {@link Error}
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @throws If any of the public keys are invalid and cannot be processed.
 * {@link InvalidContributionErr}
 * @example
 * Combine all participant public keys into the shared MuSig2 context.
 * ```ts
 * import { IndividualPubkey, keyAggregate } from '@scure/btc-signer/musig2.js';
 * import { randomPrivateKeyBytes } from '@scure/btc-signer/utils.js';
 * keyAggregate([
 *   IndividualPubkey(randomPrivateKeyBytes()),
 *   IndividualPubkey(randomPrivateKeyBytes()),
 * ]);
 * ```
 */
export function keyAggregate(
  publicKeys: TArg<Uint8Array[]>,
  tweaks: TArg<Uint8Array[]> = [],
  isXonly: boolean[] = []
) {
  // BIP327 KeyAgg inputs require `0 < u < 2^32`, and ApplyTweak consumes a one-for-one
  // list of boolean tweak modes; callers should enforce that public contract here.
  abytesArray(publicKeys, PUBKEY_LEN);
  if (publicKeys.length < 1) throw new RangeError('keyAggregate: expected at least 1 public key');
  abytesArray(tweaks, 32);
  aXonly(isXonly);
  if (tweaks.length !== isXonly.length)
    throw new RangeError('The tweaks and isXonly arrays must have the same length');
  // Aggregate
  const pk2 = getSecondKey(publicKeys);
  const L = keyAggL(publicKeys);
  let aggPublicKey = Point.ZERO;
  for (let i = 0; i < publicKeys.length; i++) {
    let Pi;
    try {
      Pi = Point.fromBytes(publicKeys[i]);
    } catch (error) {
      throw new InvalidContributionErr(i, 'pubkey');
    }
    aggPublicKey = aggPublicKey.add(Pi.multiply(keyAggCoeffInternal(publicKeys[i], pk2, L)));
  }
  let gAcc = Fn.ONE;
  let tweakAcc = Fn.ZERO;
  // Apply tweaks
  for (let i = 0; i < tweaks.length; i++) {
    const g = isXonly[i] && !hasEven(aggPublicKey.y) ? Fn.neg(Fn.ONE) : Fn.ONE;
    // BIP327 ApplyTweak: `Let t = int(tweak); fail if t >= n`, so 32-byte zero tweaks are valid.
    const t = Fn.fromBytes(tweaks[i], true);
    if (!Fn.isValid(t)) throw new RangeError('invalid scalar: out of range');
    aggPublicKey = aggPublicKey.multiply(g).add(Fn.is0(t) ? Point.ZERO : mulBase(t));
    if (isZero(aggPublicKey)) throw new Error('The result of tweaking cannot be infinity');
    gAcc = Fn.mul(g, gAcc);
    tweakAcc = Fn.add(t, Fn.mul(g, tweakAcc));
  }
  return { aggPublicKey, gAcc, tweakAcc };
}
/**
 * Exports the aggregate public key to a byte array.
 * @param ctx - result of {@link keyAggregate}
 * @returns The aggregate public key as a byte array.
 * @example
 * Serialize the aggregate key after building the MuSig2 context.
 * ```ts
 * import { IndividualPubkey, keyAggregate, keyAggExport } from '@scure/btc-signer/musig2.js';
 * import { randomPrivateKeyBytes } from '@scure/btc-signer/utils.js';
 * const ctx = keyAggregate([
 *   IndividualPubkey(randomPrivateKeyBytes()),
 *   IndividualPubkey(randomPrivateKeyBytes()),
 * ]);
 * keyAggExport(ctx);
 * ```
 */
export function keyAggExport(ctx: ReturnType<typeof keyAggregate>): TRet<Uint8Array> {
  // BIP327 GetXonlyPubkey returns xbytes(Q), so this is the 32-byte x-only aggregate key
  // instead of the 33-byte compressed SEC1 form.
  return pointToBytes(ctx.aggPublicKey) as TRet<Uint8Array>;
}

function aux(secret: TArg<Uint8Array>, rand: TArg<Uint8Array>): TRet<Uint8Array> {
  // BIP327 NonceGen and DeterministicSign blind the caller-provided 32-byte randomness with
  // hash_MuSig/aux(rand) before hashing the session inputs into nonce scalars.
  const rand2 = taggedHash('MuSig/aux', rand);
  if (secret.length !== rand2.length) throw new Error('Cannot XOR arrays of different lengths');
  const res = new Uint8Array(secret.length);
  for (let i = 0; i < secret.length; i++) res[i] = secret[i] ^ rand2[i];
  return res as TRet<Uint8Array>;
}

const nonceHash = (
  rand: TArg<Uint8Array>,
  publicKey: TArg<Uint8Array>,
  aggPublicKey: TArg<Uint8Array>,
  i: number,
  msgPrefixed: TArg<Uint8Array>,
  extraIn: TArg<Uint8Array>
): bigint =>
  // BIP327 NonceGen hashes rand || len(pk) || pk || len(aggpk) || aggpk || m_prefixed ||
  // len(extra_in) || extra_in || bytes(1, i - 1), so callers pass i = 0/1 here.
  taggedInt(
    'MuSig/nonce',
    rand,
    new Uint8Array([publicKey.length]),
    publicKey,
    new Uint8Array([aggPublicKey.length]),
    aggPublicKey,
    msgPrefixed,
    numberToBytesBE(extraIn.length, 4),
    extraIn,
    new Uint8Array([i])
  );

/**
 * Generates a nonce pair (public and secret) for MuSig2 signing.
 * @param publicKey - individual public key of the signer
 * @param secretKey - optional secret key, mixed in to blind the randomness source
 * @param aggPublicKey - aggregate public key of all signers
 * @param msg - message to be signed
 * @param extraIn - extra input mixed into nonce generation
 * @param rand - random 32-byte seed for the nonce derivation
 * @returns An object containing the public and secret nonces.
 * @throws If the input is invalid, such as non-array public keys or malformed
 * nonce inputs. {@link Error}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @example
 * Generate the signer-local nonce pair before sharing the public nonce with peers.
 * ```ts
 * import { IndividualPubkey, nonceGen } from '@scure/btc-signer/musig2.js';
 * import { randomPrivateKeyBytes } from '@scure/btc-signer/utils.js';
 * const secretKey = randomPrivateKeyBytes();
 * nonceGen(IndividualPubkey(secretKey), secretKey);
 * ```
 */
export function nonceGen(
  publicKey: TArg<Uint8Array>,
  secretKey?: TArg<Uint8Array>,
  aggPublicKey: TArg<Uint8Array> = new Uint8Array(0),
  msg?: TArg<Uint8Array>,
  extraIn: TArg<Uint8Array> = new Uint8Array(0),
  rand: TArg<Uint8Array> = randomBytes(32)
): TRet<Nonces> {
  abytes(publicKey, PUBKEY_LEN);
  abytesOptional(secretKey, 32);
  abytes(aggPublicKey);
  if (![0, 32].includes(aggPublicKey.length)) throw new RangeError('wrong aggPublicKey');
  abytesOptional(msg);
  abytes(extraIn);
  abytes(rand, 32);

  if (secretKey !== undefined) rand = aux(secretKey, rand);
  // BIP327 distinguishes an omitted message from an explicitly empty one so the two cases
  // derive different nonces even when every other session parameter matches.
  const msgPrefixed =
    msg !== undefined
      ? concatBytes(Uint8Array.of(1), numberToBytesBE(msg.length, 8), msg)
      : Uint8Array.of(0);
  const k1 = nonceHash(rand, publicKey, aggPublicKey, 0, msgPrefixed, extraIn);
  const k2 = nonceHash(rand, publicKey, aggPublicKey, 1, msgPrefixed, extraIn);
  return {
    secret: SecretNonce.encode({ k1, k2, publicKey }),
    public: PubNonce.encode({ R1: mulBase(k1), R2: mulBase(k2) }),
  } as TRet<Nonces>;
}

/**
 * Aggregates public nonces from multiple signers into a single aggregate nonce.
 * @param pubNonces - public nonces from each signer
 * @returns The aggregate nonce (Uint8Array).
 * @throws If the nonce payloads are malformed or contain infinity points. {@link Error}
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @throws If any of the public nonces are invalid and cannot be processed.
 * {@link InvalidContributionErr}
 * @example
 * Combine all participant public nonces before building the session.
 * ```ts
 * import { IndividualPubkey, nonceAggregate, nonceGen } from '@scure/btc-signer/musig2.js';
 * import { randomPrivateKeyBytes } from '@scure/btc-signer/utils.js';
 * const alice = randomPrivateKeyBytes();
 * const bob = randomPrivateKeyBytes();
 * nonceAggregate([
 *   nonceGen(IndividualPubkey(alice), alice).public,
 *   nonceGen(IndividualPubkey(bob), bob).public,
 * ]);
 * ```
 */
export function nonceAggregate(pubNonces: TArg<Uint8Array[]>): TRet<Uint8Array> {
  abytesArray(pubNonces, 66);
  // BIP327 NonceAgg input: "The number u of pubnonces with 0 < u < 2^32".
  // cbytes_ext uses bytes(33, 0) as the infinity sentinel for summed real contributions,
  // not as an "empty aggregate" encoding.
  if (pubNonces.length < 1)
    throw new RangeError('nonceAggregate: expected at least 1 public nonce');
  let R1 = Point.ZERO;
  let R2 = Point.ZERO;
  for (let i = 0; i < pubNonces.length; i++) {
    const pn = pubNonces[i];
    try {
      const { R1: R1n, R2: R2n } = PubNonce.decode(pn);
      if (isZero(R1n) || isZero(R2n)) throw new Error('infinity point');
      R1 = R1.add(R1n);
      R2 = R2.add(R2n);
    } catch (error) {
      throw new InvalidContributionErr(i, 'pubnonce');
    }
  }
  return PubNonce.encode({ R1, R2 }) as TRet<Uint8Array>;
}

// Class allows us re-use pre-computed stuff
// NOTE: it would be nice to aggregate nonce in constructor, but there is a
// test that passes an already aggregated nonce here.
/**
 * MuSig2 session context for partial signing and aggregation.
 * @param aggNonce - aggregate nonce from all participants combined
 * @param publicKeys - all participant public keys
 * @param msg - message to be signed
 * @param tweaks - optional tweaks applied to the aggregate public key
 * @param isXonly - whether each tweak uses x-only semantics
 * @example
 * Build one session object and reuse it for all partial-signature steps.
 * ```ts
 * import {
 *   IndividualPubkey,
 *   Session,
 *   keyAggregate,
 *   keyAggExport,
 *   nonceAggregate,
 *   nonceGen,
 * } from '@scure/btc-signer/musig2.js';
 * import { randomPrivateKeyBytes } from '@scure/btc-signer/utils.js';
 * const alice = randomPrivateKeyBytes();
 * const bob = randomPrivateKeyBytes();
 * const publicKeys = [IndividualPubkey(alice), IndividualPubkey(bob)];
 * const agg = keyAggregate(publicKeys);
 * const aggNonce = nonceAggregate([
 *   nonceGen(publicKeys[0], alice, keyAggExport(agg)).public,
 *   nonceGen(publicKeys[1], bob, keyAggExport(agg)).public,
 * ]);
 * const msg = new TextEncoder().encode('hello musig2');
 * new Session(aggNonce, publicKeys, msg);
 * ```
 */
export class Session {
  private aggNonce: Uint8Array;
  private publicKeys: Uint8Array[];
  private Q: Point;
  private gAcc: bigint;
  private tweakAcc: bigint;
  private b: bigint;
  private R: Point;
  private e: bigint;
  private tweaks: Uint8Array[];
  private isXonly: boolean[];
  private L: Uint8Array;
  private secondKey: Uint8Array;
  /**
   * Constructor for the Session class.
   * It precomputes and stores values derived from the aggregate nonce, public keys,
   * message, and optional tweaks, optimizing the signing process.
   * @param aggNonce - aggregate nonce from all participants combined
   * @param publicKeys - participant public keys
   * @param msg - message to be signed
   * @param tweaks - tweaks applied to the aggregate public key
   * @param isXonly - whether each tweak uses x-only semantics
   * @throws If the input is invalid, such as wrong array sizes or lengths. {@link Error}
   */
  constructor(
    aggNonce: Uint8Array,
    publicKeys: Uint8Array[],
    msg: Uint8Array,
    tweaks: Uint8Array[] = [],
    isXonly: boolean[] = []
  ) {
    abytesArray(publicKeys, 33);
    abytesArray(tweaks, 32);
    aXonly(isXonly);
    abytes(msg);
    if (tweaks.length !== isXonly.length)
      throw new RangeError('The tweaks and isXonly arrays must have the same length');
    const { aggPublicKey, gAcc, tweakAcc } = keyAggregate(publicKeys, tweaks, isXonly);
    const { R1, R2 } = PubNonce.decode(aggNonce);
    // BIP327 requires cached session-context state to be protected from third-party mutation,
    // so Session must own detached copies of the caller-provided arrays and byte entries.
    // Use Uint8Array.from(...) here instead of .slice() because Node Buffer overrides slice()
    // to return a shared-memory view, which would let later caller mutation rewrite session state.
    this.aggNonce = Uint8Array.from(aggNonce);
    this.publicKeys = publicKeys.map((pk) => Uint8Array.from(pk));
    this.Q = aggPublicKey;
    this.gAcc = gAcc;
    this.tweakAcc = tweakAcc;
    this.b = taggedInt('MuSig/noncecoef', aggNonce, pointToBytes(aggPublicKey), msg);
    const R = R1.add(R2.multiply(this.b));
    this.R = isZero(R) ? Point.BASE : R;
    this.e = taggedInt('BIP0340/challenge', pointToBytes(this.R), pointToBytes(aggPublicKey), msg);
    this.tweaks = tweaks.map((t) => Uint8Array.from(t));
    this.isXonly = isXonly.slice();
    this.L = keyAggL(this.publicKeys);
    this.secondKey = getSecondKey(this.publicKeys);
  }
  /**
   * Calculates the key aggregation coefficient for a given point.
   * @private
   * @param P - point to calculate the coefficient for
   * @returns The key aggregation coefficient as a bigint.
   * @throws If the provided public key is not included in the list of pubkeys. {@link Error}
   */
  private getSessionKeyAggCoeff(P: Point): bigint {
    const { publicKeys } = this;
    const pk = P.toBytes(true);
    // BIP327 GetSessionKeyAggCoeff fails if cbytes(P) is not one of the session pubkeys;
    // once membership is confirmed, the cached L/secondKey state is enough to derive KeyAggCoeff.
    const found = publicKeys.some((p) => equalBytes(p, pk));
    if (!found) throw new Error("The signer's pubkey must be included in the list of pubkeys");
    return keyAggCoeffInternal(pk, this.secondKey, this.L);
  }
  private partialSigVerifyInternal(
    partialSig: Uint8Array,
    publicNonce: Uint8Array,
    publicKey: Uint8Array
  ): boolean {
    const { Q, gAcc, b, R, e } = this;
    const s = Fn.fromBytes(partialSig, true);
    if (!Fn.isValid(s)) return false;
    // BIP327 PartialSigVerifyInternal: `Let s = int(psig); fail if s >= n`, so s=0 must stay
    // in the public verification equation and return false on mismatch instead of throwing.
    const { R1, R2 } = PubNonce.decode(publicNonce);
    const Re_s_ = R1.add(R2.multiply(b));
    const Re_s = hasEven(R.y) ? Re_s_ : Re_s_.negate();
    const P = Point.fromBytes(publicKey);
    const a = this.getSessionKeyAggCoeff(P);
    const g = Fn.mul(evenScalar(Q, 1n), gAcc);
    const left = Point.BASE.multiplyUnsafe(s);
    const right = Re_s.add(P.multiply(Fn.mul(e, Fn.mul(a, g))));
    return left.equals(right);
  }

  /**
   * Generates a partial signature for a given message, secret nonce,
   * secret key, and session context.
   * @param secretNonce - secret nonce for this signing session; it is zeroed after use
   * @param secret - secret key of the signer
   * @param fastSign - if `true`, skip the self-verification pass
   * @returns The partial signature (Uint8Array).
   * @throws If the input is invalid, such as wrong array sizes,
   * invalid nonce, or invalid secret key. {@link Error}
   */
  sign(secretNonce: Uint8Array, secret: Uint8Array, fastSign = false): Uint8Array {
    abytes(secret, 32);
    if (typeof fastSign !== 'boolean') throw new TypeError('expected boolean');
    const { Q, gAcc, b, R, e } = this;
    const { k1: k1_, k2: k2_, publicKey: originalPk } = SecretNonce.decode(secretNonce);
    // zero-out the first 64 bytes of secretNonce so it cannot be reused
    // BIP327 permits overwriting the first 64 secnonce bytes after reading k1/k2 so
    // accidental reuse fails fast instead of reusing the same nonce scalars.
    // TODO: this was in the reference implementation, but feels very broken.
    // Modifying input arguments is pretty bad.
    secretNonce.fill(0, 0, 64);
    if (!Fn.isValid(k1_)) throw new Error('wrong k1');
    if (!Fn.isValid(k2_)) throw new Error('wrong k1');
    const k1 = evenScalar(R, k1_);
    const k2 = evenScalar(R, k2_);
    const d_ = Fn.fromBytes(secret);
    if (Fn.is0(d_)) throw new Error('wrong d_');
    const P = mulBase(d_);
    const pk = P.toBytes(true);
    if (!equalBytes(pk, originalPk)) throw new Error('Public key does not match nonceGen argument');
    const a = this.getSessionKeyAggCoeff(P);
    const g = evenScalar(Q, 1n);
    const d = Fn.mul(g, Fn.mul(gAcc, d_));
    /// k1 + (b*k2) + (e*a*d)
    const s = Fn.add(k1, Fn.add(Fn.mul(b, k2), Fn.mul(e, Fn.mul(a, d))));
    const partialSig = Fn.toBytes(s);
    // Skip validation in fast-sign mode
    if (!fastSign) {
      const publicNonce = PubNonce.encode({
        R1: mulBase(k1_),
        R2: mulBase(k2_),
      });
      if (!this.partialSigVerifyInternal(partialSig, publicNonce, pk))
        throw new Error('Partial signature verification failed');
    }
    return partialSig;
  }
  /**
   * Verifies a partial signature against the aggregate public key and other session parameters.
   * @param partialSig - partial signature to verify
   * @param pubNonces - public nonces from each signer
   * @param i - index of the signer whose partial signature is being verified
   * @returns `true` if the partial signature is valid.
   * @throws If the input is invalid, such as non-array partial signatures
   * or mismatched nonce counts. {@link Error}
   */
  partialSigVerify(partialSig: Uint8Array, pubNonces: Uint8Array[], i: number): boolean {
    const { publicKeys, tweaks, isXonly } = this;
    abytes(partialSig, 32);
    abytesArray(pubNonces, 66);
    abytesArray(publicKeys, PUBKEY_LEN);
    abytesArray(tweaks, 32);
    aXonly(isXonly);
    anumber(i);
    if (pubNonces.length !== publicKeys.length)
      throw new RangeError('The pubNonces and publicKeys arrays must have the same length');
    if (tweaks.length !== isXonly.length)
      throw new RangeError('The tweaks and isXonly arrays must have the same length');
    // BIP327 PartialSigVerify rebuilds session_ctx from aggnonce = NonceAgg(pubnonce_1..u),
    // and GetSessionValues derives b and R from that aggnonce. This Session caches b/R/e from
    // the constructor aggNonce, so a stale Session would otherwise accept mismatched pubNonces
    // as long as pubNonces[i] still matched the signer slot.
    if (i >= pubNonces.length) throw new RangeError('index outside of pubKeys/pubNonces');
    if (!equalBytes(this.aggNonce, nonceAggregate(pubNonces))) return false;
    return this.partialSigVerifyInternal(partialSig, pubNonces[i], publicKeys[i]);
  }
  /**
   * Aggregates partial signatures from multiple signers into a single final signature.
   * @param partialSigs - partial signatures from each signer
   * @returns The final aggregate signature (Uint8Array).
   * @throws If the input is invalid, such as wrong array sizes or malformed
   * signatures. {@link Error}
   */
  partialSigAgg(partialSigs: TArg<Uint8Array[]>): TRet<Uint8Array> {
    abytesArray(partialSigs, 32);
    // BIP327 PartialSigAgg is defined for a non-empty psig_1..u list tied to this session_ctx;
    // [] is not a valid aggregate-signature input even though the sum starts from zero.
    if (partialSigs.length < 1) throw new RangeError('partialSigs.length must be >= 1');
    const { Q, tweakAcc, R, e } = this;
    let s = 0n;
    for (let i = 0; i < partialSigs.length; i++) {
      const si = Fn.fromBytes(partialSigs[i], true);
      if (!Fn.isValid(si)) throw new InvalidContributionErr(i, 'psig');
      s = Fn.add(s, si);
    }
    const g = evenScalar(Q, 1n);
    s = Fn.add(s, Fn.mul(e, Fn.mul(g, tweakAcc))); // s + e * g * tweakAcc
    return concatBytes(pointToBytes(R), Fn.toBytes(s)) as TRet<Uint8Array>;
  }
}

const deterministicNonceHash = (
  secret: TArg<Uint8Array>,
  aggOtherNonce: TArg<Uint8Array>,
  aggPublicKey: TArg<Uint8Array>,
  msg: TArg<Uint8Array>,
  i: number
): bigint =>
  taggedInt(
    'MuSig/deterministic/nonce',
    secret,
    aggOtherNonce,
    aggPublicKey,
    numberToBytesBE(msg.length, 8),
    msg,
    // BIP327 hashes bytes(1, i - 1) for i=1,2; callers pass 0/1 directly here.
    new Uint8Array([i])
  );

/**
 * Generates a nonce pair and partial signature deterministically for a single signer.
 * @param secret - secret key of the signer
 * @param aggOtherNonce - aggregate public nonce of the other signers
 * @param publicKeys - public keys of all signers
 * @param msg - message to be signed
 * @param tweaks - tweaks applied to the aggregate public key
 * @param isXonly - whether each tweak uses x-only semantics
 * @param rand - optional extra randomness
 * @param fastSign - whether to skip partial-signature self-verification
 * @returns An object containing the public nonce and partial signature.
 * @throws If MuSig2 session setup or signing fails. {@link Error}
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @throws If one of the aggregated public keys or nonces is invalid. {@link InvalidContributionErr}
 * @example
 * Generate one signer's deterministic nonce and partial signature in one step.
 * ```ts
 * import {
 *   IndividualPubkey,
 *   deterministicSign,
 *   keyAggregate,
 *   keyAggExport,
 *   nonceGen,
 * } from '@scure/btc-signer/musig2.js';
 * import { randomPrivateKeyBytes } from '@scure/btc-signer/utils.js';
 * const alice = randomPrivateKeyBytes();
 * const bob = randomPrivateKeyBytes();
 * const publicKeys = [IndividualPubkey(alice), IndividualPubkey(bob)];
 * const agg = keyAggregate(publicKeys);
 * const otherNonce = nonceGen(publicKeys[1], bob, keyAggExport(agg)).public;
 * deterministicSign(alice, otherNonce, publicKeys, new TextEncoder().encode('hello musig2'));
 * ```
 */
export function deterministicSign(
  secret: TArg<Uint8Array>,
  aggOtherNonce: TArg<Uint8Array>,
  publicKeys: TArg<Uint8Array[]>,
  msg: TArg<Uint8Array>,
  tweaks: TArg<Uint8Array[]> = [],
  isXonly: boolean[] = [],
  rand?: TArg<Uint8Array>,
  fastSign = false
): TRet<DetNonce> {
  abytes(secret, 32);
  abytes(aggOtherNonce, 66);
  abytesArray(publicKeys, PUBKEY_LEN);
  abytesArray(tweaks, 32);
  abytes(msg);
  abytesOptional(rand, 32);
  // BIP327 DeterministicSign input bullet: `The auxiliary randomness rand: a 32-byte array`
  // when present, so this optional argument still needs the exact-length check here.
  const sk = rand !== undefined ? aux(secret, rand) : secret;
  const aggPublicKey = keyAggExport(keyAggregate(publicKeys, tweaks, isXonly));
  const k1 = deterministicNonceHash(sk, aggOtherNonce, aggPublicKey, msg, 0);
  const k2 = deterministicNonceHash(sk, aggOtherNonce, aggPublicKey, msg, 1);
  const R1 = mulBase(k1);
  const R2 = mulBase(k2);
  const publicNonce = PubNonce.encode({ R1, R2 });
  const secretNonce = SecretNonce.encode({ k1, k2, publicKey: IndividualPubkey(secret) });
  const aggNonce = nonceAggregate([publicNonce, aggOtherNonce]);
  const session = new Session(aggNonce, publicKeys, msg, tweaks, isXonly);
  const partialSig = session.sign(secretNonce, secret, fastSign);
  return { publicNonce, partialSig } as TRet<DetNonce>;
}

import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { aInRange, concatBytes, equalBytes, numberToBytesBE } from '@noble/curves/utils.js';
import { abytes, anumber, randomBytes } from '@noble/hashes/utils.js';
import * as P from 'micro-packed';
import { compareBytes, hasEven } from './utils.ts';

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
/** Represents a deterministic nonce, including its public part and the resulting partial signature. */
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
  readonly idx: number; // Indice of participant
  constructor(idx: number, m: string) {
    super(m);
    this.idx = idx;
  }
}

// Utils
const taggedHash = /* @__PURE__ */ (() => schnorr.utils.taggedHash)();
const pointToBytes = /* @__PURE__ */ (() => schnorr.utils.pointToBytes)();
const Point = /* @__PURE__ */ (() => secp256k1.Point)();
type Point = typeof Point.BASE;
const Fn = /* @__PURE__ */ (() => Point.Fn)();
const PUBKEY_LEN = /* @__PURE__ */ (() => secp256k1.lengths.publicKey!)();
const ZERO = /* @__PURE__ */ new Uint8Array(PUBKEY_LEN); // Compressed zero point

// Encoding
// TODO: re-use in PSBT?
const compressed = /* @__PURE__ */ (() =>
  P.apply(P.bytes(33), {
    decode: (p: Point) => (isZero(p) ? ZERO : p.toBytes(true)),
    encode: (b: Uint8Array) => (equalBytes(b, ZERO) ? Point.ZERO : Point.fromBytes(b)),
  }))();
const scalar = /* @__PURE__ */ (() =>
  P.validate(P.U256BE, (n) => {
    aInRange('n', n, 1n, Fn.ORDER);
    return n;
  }))();
const PubNonce = /* @__PURE__ */ (() => P.struct({ R1: compressed, R2: compressed }))();
const SecretNonce = /* @__PURE__ */ (() =>
  P.struct({
    k1: scalar,
    k2: scalar,
    publicKey: P.bytes(PUBKEY_LEN),
  }))();

function abytesOptional(b: Uint8Array | undefined, ...lengths: number[]) {
  if (b !== undefined) abytes(b, ...lengths);
}

function abytesArray(lst: Uint8Array[], ...lengths: number[]) {
  if (!Array.isArray(lst)) throw new TypeError('expected array');
  lst.forEach((i) => abytes(i, ...lengths));
}

function aXonly(lst: boolean[]) {
  if (!Array.isArray(lst)) throw new TypeError('expected array');
  lst.forEach((i, j) => {
    if (typeof i !== 'boolean')
      throw new TypeError('expected boolean in xOnly array, got' + i + '(' + j + ')');
  });
}

const taggedInt = (tag: string, ...messages: Uint8Array[]) =>
  Fn.create(Fn.fromBytes(taggedHash(tag, ...messages), true));
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
export function IndividualPubkey(seckey: Uint8Array): Uint8Array {
  return secp256k1.getPublicKey(seckey, true);
}
// Same, but returns Point
function mulBase(n: bigint): Point {
  return Point.BASE.multiply(n);
}
function isZero(point: Point): boolean {
  return point.equals(Point.ZERO);
}

/**
 * Lexicographically sorts an array of public keys.
 * @param publicKeys - array of public keys
 * @returns A new array containing the sorted public keys.
 * @throws On wrong argument types. {@link TypeError}
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
export function sortKeys(publicKeys: Uint8Array[]): Uint8Array[] {
  abytesArray(publicKeys, PUBKEY_LEN);
  return publicKeys.sort(compareBytes);
}

// Finds second distinct key (to make coefficient 1)
function getSecondKey(publicKeys: Uint8Array[]): Uint8Array {
  abytesArray(publicKeys, PUBKEY_LEN);
  for (let j = 1; j < publicKeys.length; j++)
    if (!equalBytes(publicKeys[j], publicKeys[0])) return publicKeys[j];
  return ZERO;
}

function keyAggL(publicKeys: Uint8Array[]) {
  abytesArray(publicKeys, PUBKEY_LEN);
  return taggedHash('KeyAgg list', ...publicKeys);
}

function keyAggCoeffInternal(
  publicKey1: Uint8Array,
  publicKey2: Uint8Array,
  L: Uint8Array
): bigint {
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
 * @returns An object containing the aggregate public key, accumulated sign, and accumulated tweak.
 * @throws If the input is invalid, such as non-array public keys or mismatched tweak metadata. {@link Error}
 * @throws On wrong argument types. {@link TypeError}
 * @throws On wrong argument ranges or values. {@link RangeError}
 * @throws If any of the public keys are invalid and cannot be processed. {@link InvalidContributionErr}
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
  publicKeys: Uint8Array[],
  tweaks: Uint8Array[] = [],
  isXonly: boolean[] = []
) {
  abytesArray(publicKeys, PUBKEY_LEN);
  abytesArray(tweaks, 32);
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
    const t = Fn.fromBytes(tweaks[i]);
    aggPublicKey = aggPublicKey.multiply(g).add(mulBase(t));
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
export function keyAggExport(ctx: ReturnType<typeof keyAggregate>): Uint8Array {
  return pointToBytes(ctx.aggPublicKey);
}

function aux(secret: Uint8Array, rand: Uint8Array): Uint8Array {
  const rand2 = taggedHash('MuSig/aux', rand);
  if (secret.length !== rand2.length) throw new Error('Cannot XOR arrays of different lengths');
  const res = new Uint8Array(secret.length);
  for (let i = 0; i < secret.length; i++) res[i] = secret[i] ^ rand2[i];
  return res;
}

const nonceHash = (
  rand: Uint8Array,
  publicKey: Uint8Array,
  aggPublicKey: Uint8Array,
  i: number,
  msgPrefixed: Uint8Array,
  extraIn: Uint8Array
): bigint =>
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
 * @throws If the input is invalid, such as non-array public keys or malformed nonce inputs. {@link Error}
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
  publicKey: Uint8Array,
  secretKey?: Uint8Array,
  aggPublicKey: Uint8Array = new Uint8Array(0),
  msg?: Uint8Array,
  extraIn: Uint8Array = new Uint8Array(0),
  rand: Uint8Array = randomBytes(32)
): Nonces {
  abytes(publicKey, PUBKEY_LEN);
  abytesOptional(secretKey, 32);
  abytes(aggPublicKey);
  if (![0, 32].includes(aggPublicKey.length)) throw new RangeError('wrong aggPublicKey');
  abytesOptional(msg);
  abytes(extraIn);
  abytes(rand, 32);

  if (secretKey !== undefined) rand = aux(secretKey, rand);
  const msgPrefixed =
    msg !== undefined
      ? concatBytes(Uint8Array.of(1), numberToBytesBE(msg.length, 8), msg)
      : Uint8Array.of(0);
  const k1 = nonceHash(rand, publicKey, aggPublicKey, 0, msgPrefixed, extraIn);
  const k2 = nonceHash(rand, publicKey, aggPublicKey, 1, msgPrefixed, extraIn);
  return {
    secret: SecretNonce.encode({ k1, k2, publicKey }),
    public: PubNonce.encode({ R1: mulBase(k1), R2: mulBase(k2) }),
  };
}

/**
 * Aggregates public nonces from multiple signers into a single aggregate nonce.
 * @param pubNonces - public nonces from each signer
 * @returns The aggregate nonce (Uint8Array).
 * @throws If the nonce payloads are malformed or contain infinity points. {@link Error}
 * @throws On wrong argument types. {@link TypeError}
 * @throws If any of the public nonces are invalid and cannot be processed. {@link InvalidContributionErr}
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
export function nonceAggregate(pubNonces: Uint8Array[]): Uint8Array {
  abytesArray(pubNonces, 66);
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
  return PubNonce.encode({ R1, R2 });
}

// Class allows us re-use pre-computed stuff
// NOTE: it would be nice to aggregate nonce in construdctor, but there is test that passes already aggregated nonce here.
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
    this.publicKeys = publicKeys;
    this.Q = aggPublicKey;
    this.gAcc = gAcc;
    this.tweakAcc = tweakAcc;
    this.b = taggedInt('MuSig/noncecoef', aggNonce, pointToBytes(aggPublicKey), msg);
    const R = R1.add(R2.multiply(this.b));
    this.R = isZero(R) ? Point.BASE : R;
    this.e = taggedInt('BIP0340/challenge', pointToBytes(this.R), pointToBytes(aggPublicKey), msg);
    this.tweaks = tweaks;
    this.isXonly = isXonly;
    this.L = keyAggL(publicKeys);
    this.secondKey = getSecondKey(publicKeys);
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
    const { R1, R2 } = PubNonce.decode(publicNonce);
    const Re_s_ = R1.add(R2.multiply(b));
    const Re_s = hasEven(R.y) ? Re_s_ : Re_s_.negate();
    const P = Point.fromBytes(publicKey);
    const a = this.getSessionKeyAggCoeff(P);
    const g = Fn.mul(evenScalar(Q, 1n), gAcc);
    const left = mulBase(s);
    const right = Re_s.add(P.multiply(Fn.mul(e, Fn.mul(a, g))));
    return left.equals(right);
  }

  /**
   * Generates a partial signature for a given message, secret nonce, secret key, and session context.
   * @param secretNonce - secret nonce for this signing session; it is zeroed after use
   * @param secret - secret key of the signer
   * @param fastSign - if `true`, skip the self-verification pass
   * @returns The partial signature (Uint8Array).
   * @throws If the input is invalid, such as wrong array sizes, invalid nonce, or invalid secret key. {@link Error}
   */
  sign(secretNonce: Uint8Array, secret: Uint8Array, fastSign = false): Uint8Array {
    abytes(secret, 32);
    if (typeof fastSign !== 'boolean') throw new TypeError('expected boolean');
    const { Q, gAcc, b, R, e } = this;
    const { k1: k1_, k2: k2_, publicKey: originalPk } = SecretNonce.decode(secretNonce);
    // zero-out the first 64 bytes of secretNonce so it cannot be reused
    // TODO: this was in reference implementation, but feels very broken. Modifying input arguments is pretty bad.
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
   * @throws If the input is invalid, such as non-array partial signatures or mismatched nonce counts. {@link Error}
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
    if (i >= pubNonces.length) throw new RangeError('index outside of pubKeys/pubNonces');
    return this.partialSigVerifyInternal(partialSig, pubNonces[i], publicKeys[i]);
  }
  /**
   * Aggregates partial signatures from multiple signers into a single final signature.
   * @param partialSigs - partial signatures from each signer
   * @returns The final aggregate signature (Uint8Array).
   * @throws If the input is invalid, such as wrong array sizes or malformed signatures. {@link Error}
   */
  partialSigAgg(partialSigs: Uint8Array[]): Uint8Array {
    abytesArray(partialSigs, 32);
    const { Q, tweakAcc, R, e } = this;
    let s = 0n;
    for (let i = 0; i < partialSigs.length; i++) {
      const si = Fn.fromBytes(partialSigs[i], true);
      if (!Fn.isValid(si)) throw new InvalidContributionErr(i, 'psig');
      s = Fn.add(s, si);
    }
    const g = evenScalar(Q, 1n);
    s = Fn.add(s, Fn.mul(e, Fn.mul(g, tweakAcc))); // s + e * g * tweakAcc
    return concatBytes(pointToBytes(R), Fn.toBytes(s));
  }
}

const deterministicNonceHash = (
  secret: Uint8Array,
  aggOtherNonce: Uint8Array,
  aggPublicKey: Uint8Array,
  msg: Uint8Array,
  i: number
): bigint =>
  taggedInt(
    'MuSig/deterministic/nonce',
    secret,
    aggOtherNonce,
    aggPublicKey,
    numberToBytesBE(msg.length, 8),
    msg,
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
  secret: Uint8Array,
  aggOtherNonce: Uint8Array,
  publicKeys: Uint8Array[],
  msg: Uint8Array,
  tweaks: Uint8Array[] = [],
  isXonly: boolean[] = [],
  rand?: Uint8Array,
  fastSign = false
): DetNonce {
  abytes(secret, 32);
  abytes(aggOtherNonce, 66);
  abytesArray(publicKeys, PUBKEY_LEN);
  abytesArray(tweaks, 32);
  abytes(msg);
  abytesOptional(rand);
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
  return { publicNonce, partialSig };
}

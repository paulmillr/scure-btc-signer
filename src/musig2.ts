import { mod } from '@noble/curves/abstract/modular.js';
import {
  aInRange,
  bytesToNumberBE,
  concatBytes,
  equalBytes,
  numberToBytesBE,
} from '@noble/curves/abstract/utils.js';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1.js';
import { abytes, anumber, randomBytes } from '@noble/hashes/utils.js';
import * as P from 'micro-packed';
import { compareBytes } from './utils.ts';

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
/**
 * Represents a pair of public and secret nonces used in MuSig2 signing.
 */
export type Nonces = { public: Uint8Array; secret: Uint8Array };
/**
 * Represents a deterministic nonce, including its public part and the resulting partial signature.
 */
export type DetNonce = { publicNonce: Uint8Array; partialSig: Uint8Array };
/**
 * Represents an error indicating an invalid contribution from a signer.
 * This allows pointing out which participant is malicious and what specifically is wrong.
 */
export class InvalidContributionErr extends Error {
  readonly idx: number; // Indice of participant
  constructor(idx: number, m: string) {
    super(m);
    this.idx = idx;
  }
}

// Utils
const { taggedHash, pointToBytes } = schnorr.utils;
const Point = secp256k1.ProjectivePoint;
type Point = typeof Point.BASE;
const PUBKEY_LEN = 33;
const ZERO = new Uint8Array(PUBKEY_LEN); // Compressed zero point
const SECP_N = secp256k1.CURVE.n;

// Encoding
// TODO: re-use in PSBT?
const compressed = P.apply(P.bytes(33), {
  decode: (p: Point) => (isZero(p) ? ZERO : p.toRawBytes(true)),
  encode: (b: Uint8Array) => (equalBytes(b, ZERO) ? Point.ZERO : Point.fromHex(b)),
});
const scalar = P.validate(P.U256BE, (n) => {
  aInRange('n', n, 1n, SECP_N);
  return n;
});
const PubNonce = P.struct({ R1: compressed, R2: compressed });
const SecretNonce = P.struct({ k1: scalar, k2: scalar, publicKey: P.bytes(PUBKEY_LEN) });

function abytesOptional(b: Uint8Array | undefined, ...lengths: number[]) {
  if (b !== undefined) abytes(b, ...lengths);
}

function abytesArray(lst: Uint8Array[], ...lengths: number[]) {
  if (!Array.isArray(lst)) throw new Error('expected array');
  lst.forEach((i) => abytes(i, ...lengths));
}

function aXonly(lst: boolean[]) {
  if (!Array.isArray(lst)) throw new Error('expected array');
  lst.forEach((i, j) => {
    if (typeof i !== 'boolean')
      throw new Error('expected boolean in xOnly array, got' + i + '(' + j + ')');
  });
}

const modN = (x: bigint) => mod(x, SECP_N);
const taggedInt = (tag: string, ...messages: Uint8Array[]) =>
  modN(bytesToNumberBE(taggedHash(tag, ...messages)));
const evenScalar = (p: Point, n: bigint) => (p.hasEvenY() ? n : modN(-n));

// Short utility for compat with reference implementation
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
 * @param publicKeys An array of public keys (Uint8Array).
 * @returns A new array containing the sorted public keys.
 * @throws {Error} If the input is not an array or if any element is not a Uint8Array of the correct length.
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
 * @param publicKeys An array of individual public keys (Uint8Array).
 * @param tweaks An optional array of tweaks (Uint8Array) to apply to the aggregate public key.
 * @param isXonly An optional array of booleans indicating whether each tweak is an X-only tweak.
 * @returns An object containing the aggregate public key, accumulated sign, and accumulated tweak.
 * @throws {Error} If the input is invalid, such as non array publicKeys, tweaks and isXonly array length not matching.
 * @throws {InvalidContributionErr} If any of the public keys are invalid and cannot be processed.
 */
export function keyAggregate(
  publicKeys: Uint8Array[],
  tweaks: Uint8Array[] = [],
  isXonly: boolean[] = []
) {
  abytesArray(publicKeys, PUBKEY_LEN);
  abytesArray(tweaks, 32);
  if (tweaks.length !== isXonly.length)
    throw new Error('The tweaks and isXonly arrays must have the same length');
  // Aggregate
  const pk2 = getSecondKey(publicKeys);
  const L = keyAggL(publicKeys);
  let aggPublicKey = Point.ZERO;
  for (let i = 0; i < publicKeys.length; i++) {
    let Pi;
    try {
      Pi = Point.fromHex(publicKeys[i]);
    } catch (error) {
      throw new InvalidContributionErr(i, 'pubkey');
    }
    aggPublicKey = aggPublicKey.add(Pi.multiply(keyAggCoeffInternal(publicKeys[i], pk2, L)));
  }
  let gAcc = 1n;
  let tweakAcc = 0n;
  // Apply tweaks
  for (let i = 0; i < tweaks.length; i++) {
    const g = isXonly[i] && !aggPublicKey.hasEvenY() ? modN(-1n) : 1n;
    const t = bytesToNumberBE(tweaks[i]);
    aInRange('tweak', t, 0n, SECP_N);
    aggPublicKey = aggPublicKey.multiply(g).add(mulBase(t));
    if (isZero(aggPublicKey)) throw new Error('The result of tweaking cannot be infinity');
    gAcc = modN(g * gAcc);
    tweakAcc = modN(t + g * tweakAcc);
  }
  return { aggPublicKey, gAcc, tweakAcc };
}
/**
 * Exports the aggregate public key to a byte array.
 * @param ctx The result of the keyAggregate function.
 * @returns The aggregate public key as a byte array.
 */
export function keyAggExport(ctx: ReturnType<typeof keyAggregate>) {
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
 * @param publicKey The individual public key of the signer (Uint8Array).
 * @param secretKey The secret key of the signer (Uint8Array). Optional, included to xor randomness
 * @param aggPublicKey The aggregate public key of all signers (Uint8Array).
 * @param msg The message to be signed (Uint8Array).
 * @param extraIn Extra input for nonce generation (Uint8Array).
 * @param rand Random 32-bytes for generating the nonces (Uint8Array).
 * @returns An object containing the public and secret nonces.
 * @throws {Error} If the input is invalid, such as non array publicKey, secretKey, aggPublicKey.
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
  abytes(aggPublicKey, 0, 32);
  abytesOptional(msg);
  abytes(extraIn);
  abytes(rand, 32);

  if (secretKey !== undefined) rand = aux(secretKey, rand);
  const msgPrefixed =
    msg !== undefined
      ? concatBytes(new Uint8Array([1]), numberToBytesBE(msg.length, 8), msg)
      : new Uint8Array([0]);
  const k1 = nonceHash(rand, publicKey, aggPublicKey, 0, msgPrefixed, extraIn);
  const k2 = nonceHash(rand, publicKey, aggPublicKey, 1, msgPrefixed, extraIn);
  return {
    secret: SecretNonce.encode({ k1, k2, publicKey }),
    public: PubNonce.encode({ R1: mulBase(k1), R2: mulBase(k2) }),
  };
}

/**
 * Aggregates public nonces from multiple signers into a single aggregate nonce.
 * @param pubNonces An array of public nonces from each signer (Uint8Array). Each pubnonce is assumed to be 66 bytes (two 33‐byte parts).
 * @returns The aggregate nonce (Uint8Array).
 * @throws {Error} If the input is not an array or if any element is not a Uint8Array of the correct length.
 * @throws {InvalidContributionErr} If any of the public nonces are invalid and cannot be processed.
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
   * @param aggNonce The aggregate nonce (Uint8Array) from all participants combined, must be 66 bytes.
   * @param publicKeys An array of public keys (Uint8Array) from each participant, must be 33 bytes.
   * @param msg The message (Uint8Array) to be signed.
   * @param tweaks Optional array of tweaks (Uint8Array) to be applied to the aggregate public key, each must be 32 bytes. Defaults to [].
   * @param isXonly Optional array of booleans indicating whether each tweak is an X-only tweak. Defaults to [].
   * @throws {Error} If the input is invalid, such as wrong array sizes or lengths.
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
      throw new Error('The tweaks and isXonly arrays must have the same length');
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
   * @param P The point to calculate the coefficient for.
   * @returns The key aggregation coefficient as a bigint.
   * @throws {Error} If the provided public key is not included in the list of pubkeys.
   */
  private getSessionKeyAggCoeff(P: Point): bigint {
    const { publicKeys } = this;
    const pk = P.toRawBytes(true);
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
    const s = bytesToNumberBE(partialSig);
    if (s >= SECP_N) return false;
    const { R1, R2 } = PubNonce.decode(publicNonce);
    const Re_s_ = R1.add(R2.multiply(b));
    const Re_s = R.hasEvenY() ? Re_s_ : Re_s_.negate();
    const P = Point.fromHex(publicKey);
    const a = this.getSessionKeyAggCoeff(P);
    const g = modN(evenScalar(Q, 1n) * gAcc);
    const left = mulBase(s);
    const right = Re_s.add(P.multiply(modN(e * a * g)));
    return left.equals(right);
  }

  /**
   * Generates a partial signature for a given message, secret nonce, secret key, and session context.
   * @param secretNonce The secret nonce for this signing session (Uint8Array). MUST be securely erased after use.
   * @param secret The secret key of the signer (Uint8Array).
   * @param sessionCtx The session context containing all necessary information for signing.
   * @param fastSign if set to true, the signature is created without checking validity.
   * @returns The partial signature (Uint8Array).
   * @throws {Error} If the input is invalid, such as wrong array sizes, invalid nonce or secret key.
   */
  sign(secretNonce: Uint8Array, secret: Uint8Array, fastSign = false): Uint8Array {
    abytes(secret, 32);
    if (typeof fastSign !== 'boolean') throw new Error('expected boolean');
    const { Q, gAcc, b, R, e } = this;
    const { k1: k1_, k2: k2_, publicKey: originalPk } = SecretNonce.decode(secretNonce);
    // zero-out the first 64 bytes of secretNonce so it cannot be reused
    // TODO: this was in reference implementation, but feels very broken. Modifying input arguments is pretty bad.
    secretNonce.fill(0, 0, 64);
    aInRange('k1', k1_, 0n, SECP_N);
    aInRange('k2', k2_, 0n, SECP_N);
    const k1 = evenScalar(R, k1_);
    const k2 = evenScalar(R, k2_);
    const d_ = bytesToNumberBE(secret);
    aInRange('d_', d_, 1n, SECP_N);
    const P = mulBase(d_);
    const pk = P.toRawBytes(true);
    if (!equalBytes(pk, originalPk)) throw new Error('Public key does not match nonceGen argument');
    const a = this.getSessionKeyAggCoeff(P);
    const g = evenScalar(Q, 1n);
    const d = modN(g * gAcc * d_);
    const s = modN(k1 + b * k2 + e * a * d);
    const partialSig = numberToBytesBE(s, 32);
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
   * @param partialSig The partial signature to verify (Uint8Array).
   * @param pubNonces An array of public nonces from each signer (Uint8Array).
   * @param pubKeys An array of public keys from each signer (Uint8Array).
   * @param tweaks An array of tweaks applied to the aggregate public key.
   * @param isXonly An array of booleans indicating whether each tweak is an X-only tweak.
   * @param msg The message that was signed (Uint8Array).
   * @param i The index of the signer whose partial signature is being verified.
   * @returns True if the partial signature is valid, false otherwise.
   * @throws {Error} If the input is invalid, such as non array partialSig, pubNonces, pubKeys, tweaks.
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
      throw new Error('The pubNonces and publicKeys arrays must have the same length');
    if (tweaks.length !== isXonly.length)
      throw new Error('The tweaks and isXonly arrays must have the same length');
    if (i >= pubNonces.length) throw new Error('index outside of pubKeys/pubNonces');
    return this.partialSigVerifyInternal(partialSig, pubNonces[i], publicKeys[i]);
  }
  /**
   * Aggregates partial signatures from multiple signers into a single final signature.
   * @param partialSigs An array of partial signatures from each signer (Uint8Array).
   * @param sessionCtx The session context containing all necessary information for signing.
   * @returns The final aggregate signature (Uint8Array).
   * @throws {Error} If the input is invalid, such as wrong array sizes, invalid signature.
   */
  partialSigAgg(partialSigs: Uint8Array[]): Uint8Array {
    abytesArray(partialSigs, 32);
    const { Q, tweakAcc, R, e } = this;
    let s = 0n;
    for (let i = 0; i < partialSigs.length; i++) {
      const si = bytesToNumberBE(partialSigs[i]);
      if (si >= SECP_N) throw new InvalidContributionErr(i, 'psig');
      s = modN(s + si);
    }
    const g = evenScalar(Q, 1n);
    s = modN(s + e * g * tweakAcc);
    return concatBytes(pointToBytes(R), numberToBytesBE(s, 32));
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
 * @param secret The secret key of the signer (Uint8Array).
 * @param aggOtherNonce The aggregate public nonce of all other signers (Uint8Array).
 * @param publicKeys An array of all signers' public keys (Uint8Array).
 * @param tweaks An array of tweaks to apply to the aggregate public key.
 * @param isXonly An array of booleans indicating whether each tweak is an X-only tweak.
 * @param msg The message to be signed (Uint8Array).
 * @param rand Optional extra randomness (Uint8Array).
 * @returns An object containing the public nonce and partial signature.
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

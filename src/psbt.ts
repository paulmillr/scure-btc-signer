import { hex } from '@scure/base';
import * as P from 'micro-packed';
import {
  CompactSize,
  CompactSizeLen,
  RawOldTx,
  RawOutput,
  RawTx,
  RawWitness,
  VarBytes,
} from './script.ts';
import {
  type Bytes,
  compareBytes,
  equalBytes,
  PubT,
  type TArg,
  type TRet,
  validatePubkey,
} from './utils.ts';

// PSBT BIP174, BIP370, BIP371

// BIP174 keydata only says "public key", so legacy PSBT ECDSA fields still accept both
// compressed (33-byte) and uncompressed (65-byte) SEC1 encodings, but not x-only keys.
const PubKeyECDSA: P.CoderType<Bytes> = /* @__PURE__ */ (() =>
  P.validate(P.bytes(null), (pub) => validatePubkey(pub, PubT.ecdsa)))();
// BIP32 serialized xpub payloads specifically store `ser_P(K)`, which is always the 33-byte
// compressed SEC1 encoding of the public key rather than the looser legacy PSBT "any ECDSA pubkey".
const PubKeyECDSACompressed: P.CoderType<Bytes> = /* @__PURE__ */ (() =>
  P.validate(P.bytes(33), (pub) => validatePubkey(pub, PubT.ecdsa)))();
// BIP371 taproot PSBT key fields use 32-byte x-only pubkeys, so this coder keeps the
// fixed-length check and then reuses the shared Schnorr pubkey validator.
const PubKeySchnorr: P.CoderType<Bytes> = /* @__PURE__ */ (() =>
  P.validate(P.bytes(32), (pub) => validatePubkey(pub, PubT.schnorr)))();
// BIP371 taproot signature fields carry the 64-byte Schnorr signature, plus an optional
// trailing sighash byte when the signer used anything other than the default key-path mode.
const SignatureSchnorr: P.CoderType<Bytes> = /* @__PURE__ */ (() =>
  P.validate(P.bytes(null), (sig) => {
    if (sig.length !== 64 && sig.length !== 65)
      throw new Error('Schnorr signature should be 64 or 65 bytes long');
    return sig;
  }))();
// PSBTInput.finalScriptWitness should keep the historical decoded witness-stack shape even though
// the exported RawWitness coder now uses TRet for declaration stability.
const RawWitnessWire = RawWitness as unknown as P.CoderType<Bytes[]>;

// BIP174 stores the 4-byte master fingerprint as-is, then appends each child index in
// 32-bit little-endian order; cross-field checks like xpub depth matching live above this.
const BIP32Der = /* @__PURE__ */ (() =>
  P.struct({
    fingerprint: P.U32BE,
    path: P.array(null, P.U32LE),
  }))();
// BIP371 prepends the shared BIP32 derivation payload with the tapleaf-hash list; internal keys
// use `hashes.length === 0`, while script-path keys list the leaves that actually use that pubkey.
const TaprootBIP32Der = /* @__PURE__ */ (() =>
  P.struct({
    hashes: P.array(CompactSizeLen, P.bytes(32)),
    der: BIP32Der,
  }))();
// BIP174 `PSBT_GLOBAL_XPUB` says the key is "The 78 byte serialized extended public key as
// defined by BIP 32", so decode it to the actual BIP32 field layout instead of preserving an
// opaque blob. We intentionally do not hardcode version-byte policy here because BIP32 version
// bytes vary by network / deployment; this layer just parses the field and enforces the BIP32
// import rules that are independent of network selection.
const GlobalXPUB = /* @__PURE__ */ (() =>
  P.validate(
    P.struct({
      version: P.U32BE,
      depth: P.U8,
      parentFingerprint: P.U32BE,
      childNumber: P.U32BE,
      chainCode: P.bytes(32),
      // BIP32 serialization stores the public key as the final 33-byte `ser_P(K)` field and says
      // importing an extended public key must verify that point data corresponds to the curve.
      publicKey: PubKeyECDSACompressed,
    }),
    (xpub) => {
      // BIP32 serialization says master nodes use depth 0 with zero parent
      // fingerprint and zero child number. The invalid examples explicitly
      // include zero-depth xpubs with either field non-zero.
      if (xpub.depth === 0 && xpub.parentFingerprint !== 0)
        throw new Error('GlobalXPUB: depth=0 requires parentFingerprint=0');
      if (xpub.depth === 0 && xpub.childNumber !== 0)
        throw new Error('GlobalXPUB: depth=0 requires childNumber=0');
      return xpub;
    }
  ))();
// BIP371 puts the x-only pubkey and leaf hash into the key side of `PSBT_IN_TAP_SCRIPT_SIG`;
// the actual 64/65-byte Schnorr signature stays in the value side under `SignatureSchnorr`.
const tapScriptSigKey = /* @__PURE__ */ (() =>
  P.struct({ pubKey: PubKeySchnorr, leafHash: P.bytes(32) }))();

// Complex structure for PSBT fields
// <control byte with leaf version and parity bit> <internal key p> <C> <E> <AB>
// Raw BIP341 control-block layout only; the exported TaprootControlBlock wrapper adds the
// `0..128` Merkle-depth bound, and later taproot logic checks version/parity semantics.
const _TaprootControlBlock = /* @__PURE__ */ (() =>
  P.struct({
    version: P.U8, // With parity :(
    internalKey: P.bytes(32),
    merklePath: P.array(null, P.bytes(32)),
  }))();
/**
 * Taproot control block coder.
 * @example
 * Encode the Taproot control block attached to a script-path witness.
 * ```ts
 * import { TaprootControlBlock } from '@scure/btc-signer/psbt.js';
 * import { pubSchnorr, randomPrivateKeyBytes } from '@scure/btc-signer/utils.js';
 * TaprootControlBlock.encode({
 *   version: 0xc0,
 *   internalKey: pubSchnorr(randomPrivateKeyBytes()),
 *   merklePath: [],
 * });
 * ```
 */
export const TaprootControlBlock = /* @__PURE__ */ (() =>
  Object.freeze(
    P.validate(_TaprootControlBlock, (cb) => {
      // BIP 341 control blocks are raw 33+32m byte records; this PSBT coder only enforces
      // the length/depth shape here and leaves curve / leaf-version validation to taproot logic.
      if (cb.merklePath.length > 128)
        throw new Error('TaprootControlBlock: merklePath should be of length 0..128 (inclusive)');
      return cb;
    })
  ))();

// BIP371 says PSBT_OUT_TAP_TREE is one or more tuples in DFS order so the Taproot tree can be
// reconstructed. Validate both the non-empty requirement and that the leaf-depth sequence really
// describes a complete left-to-right DFS walk of a binary tree, not just arbitrary tuples.
// {<8-bit uint depth> <8-bit uint leaf version> <compact size uint scriptlen> <bytes script>}*
const tapTree = /* @__PURE__ */ (() =>
  P.validate(
    P.array(
      null,
      P.struct({
        depth: P.U8,
        version: P.U8,
        script: VarBytes,
      })
    ),
    (tree) => {
      if (tree.length < 1) throw new Error('tapTree: expected at least one tuple');
      let path = Array(tree[0].depth).fill(0);
      let maxDepth = tree[0].depth;
      for (let i = 1; i < tree.length; i++) {
        const { depth } = tree[i];
        if (depth > maxDepth) maxDepth = depth;
        let j = path.length - 1;
        while (j >= 0 && path[j] === 1) j--;
        if (j < 0) throw new Error('tapTree: tuples must be in DFS order');
        const next = path.slice(0, j);
        next.push(1);
        if (depth < next.length) throw new Error('tapTree: tuples must be in DFS order');
        while (next.length < depth) next.push(0);
        path = next;
      }
      let leaves = 0n;
      for (let i = 0; i < tree.length; i++) leaves += 1n << BigInt(maxDepth - tree[i].depth);
      if (leaves !== 1n << BigInt(maxDepth))
        throw new Error('tapTree: tuples must describe a complete binary tree');
      return tree;
    }
  ))();

// Shared raw PSBT byte payload coder for fields whose BIP174 value format is just opaque bytes;
// field-specific structure and length checks still live at the individual field definitions.
// Keep a distinct name here so the byte coder does not collide with the Bytes type alias.
const BytesInf: P.CoderType<Bytes> = /* @__PURE__ */ P.bytes(null);
// Shared 20-byte key-data helper for the BIP174 RIPEMD160 and HASH160 preimage maps.
const Bytes20: P.CoderType<Bytes> = /* @__PURE__ */ P.bytes(20);
// Shared 32-byte helper for fixed-size hash / txid / merkle-root byte fields; any stronger
// semantics such as x-only pubkey validity still need to be enforced by the field that uses it.
const Bytes32: P.CoderType<Bytes> = /* @__PURE__ */ P.bytes(32);
type PSBTKeyCoder = P.CoderType<any> | false;
type PSBTKeyMapInfo = Readonly<
  [
    number,
    PSBTKeyCoder,
    any,
    readonly number[], // versionsRequiringInclusion
    readonly number[], // versionsAllowsInclusion
    boolean, // silentIgnore
  ]
>;
// jsbt mutate checks exported PSBT tables recursively, so freeze each field tuple and its
// nested version arrays here while preserving the original coder slot types for local inference.
const PSBTInfo = <
  K extends PSBTKeyCoder,
  V,
  Req extends readonly number[],
  Allow extends readonly number[],
  S extends boolean,
>(
  type: number,
  kc: K,
  vc: V,
  reqInc: Req,
  allowInc: Allow,
  silentIgnore: S
) =>
  /* @__PURE__ */ Object.freeze([
    type,
    kc && typeof kc === 'object' ? (Object.freeze(kc) as K) : kc,
    vc && typeof vc === 'object' ? (Object.freeze(vc as object) as V) : vc,
    Object.freeze([...reqInc]) as Req,
    Object.freeze([...allowInc]) as Allow,
    silentIgnore,
  ] as const) as readonly [number, K, V, Req, Allow, S];
// versionsRequiringExclusing = !versionsAllowsInclusion (as set)
// {name: [tag, keyCoder, valueCoder, versionsRequiringInclusion,
// versionsRequiringExclusing, versionsAllowsInclusion, silentIgnore]}
// SilentIgnore: we use some v2 fields for v1 representation too,
// so we just clean them before serialize.

// Tables from BIP-0174 (https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)
// prettier-ignore
/**
 * PSBT global key definitions.
 * @example
 * Keep only the fields that are valid for the target PSBT version before serializing.
 * ```ts
 * import { PSBTGlobal, cleanPSBTFields } from '@scure/btc-signer/psbt.js';
 * cleanPSBTFields(2, PSBTGlobal, { txVersion: 2, inputCount: 1, outputCount: 1 });
 * ```
 */
export const PSBTGlobal = /* @__PURE__ */ (() => Object.freeze({
  unsignedTx:       PSBTInfo(0x00, false,      RawOldTx,          [0], [0],    false),
  // BIP174 also requires the serialized xpub depth to match the number of path elements in the
  // paired derivation value, so callers still need that cross-field check above this raw table.
  xpub:             PSBTInfo(0x01, GlobalXPUB, BIP32Der,       [],  [0, 2], false),
  txVersion:        PSBTInfo(0x02, false,      P.U32LE,        [2], [2],    false),
  fallbackLocktime: PSBTInfo(0x03, false,      P.U32LE,        [],  [2],    false),
  inputCount:       PSBTInfo(0x04, false,      CompactSizeLen, [2], [2],    false),
  outputCount:      PSBTInfo(0x05, false,      CompactSizeLen, [2], [2],    false),
  // TODO: bitfield
  txModifiable:     PSBTInfo(0x06, false,      P.U8,           [],  [2],    false),
  version:          PSBTInfo(0xfb, false,      P.U32LE,        [],  [0, 2], false),
  proprietary:      PSBTInfo(0xfc, BytesInf,   BytesInf,       [],  [0, 2], false),
} as const))();
// prettier-ignore
/**
 * PSBT input key definitions.
 * @example
 * Strip input fields that do not belong in the requested PSBT version.
 * ```ts
 * import { hex } from '@scure/base';
 * import { PSBTInput, cleanPSBTFields } from '@scure/btc-signer/psbt.js';
 * cleanPSBTFields(2, PSBTInput, {
 *   txid: hex.decode('0000000000000000000000000000000000000000000000000000000000000001'),
 *   index: 0,
 *   witnessUtxo: { amount: 2n, script: new Uint8Array([0x51]) },
 * });
 * ```
 */
export const PSBTInput = /* @__PURE__ */ (() => Object.freeze({
  nonWitnessUtxo:         PSBTInfo(0x00, false,               RawTx,             [],  [0, 2], false),
  witnessUtxo:            PSBTInfo(0x01, false,               RawOutput,         [],  [0, 2], false),
  partialSig:             PSBTInfo(0x02, PubKeyECDSA,         BytesInf,          [],  [0, 2], false),
  sighashType:            PSBTInfo(0x03, false,               P.U32LE,           [],  [0, 2], false),
  redeemScript:           PSBTInfo(0x04, false,               BytesInf,          [],  [0, 2], false),
  witnessScript:          PSBTInfo(0x05, false,               BytesInf,          [],  [0, 2], false),
  bip32Derivation:        PSBTInfo(0x06, PubKeyECDSA,         BIP32Der,          [],  [0, 2], false),
  finalScriptSig:         PSBTInfo(0x07, false,               BytesInf,          [],  [0, 2], false),
  finalScriptWitness:     PSBTInfo(0x08, false,               RawWitnessWire,    [],  [0, 2], false),
  porCommitment:          PSBTInfo(0x09, false,               BytesInf,          [],  [0, 2], false),
  ripemd160:              PSBTInfo(0x0a, Bytes20,             BytesInf,          [],  [0, 2], false),
  sha256:                 PSBTInfo(0x0b, Bytes32,             BytesInf,          [],  [0, 2], false),
  hash160:                PSBTInfo(0x0c, Bytes20,             BytesInf,          [],  [0, 2], false),
  hash256:                PSBTInfo(0x0d, Bytes32,             BytesInf,          [],  [0, 2], false),
  // BIP174/BIP370 serialize PREVIOUS_TXID in standard byte order, while the rest of this repo
  // historically keeps TransactionInput.txid in display-order bytes matching `Transaction.id`.
  // Reverse at this PSBTv2 boundary so internal txid semantics stay aligned with the raw-tx path.
  txid:                   PSBTInfo(0x0e, false,               P.bytes(32, true), [2], [2],    true),
  index:                  PSBTInfo(0x0f, false,               P.U32LE,           [2], [2],    true),
  sequence:               PSBTInfo(0x10, false,               P.U32LE,           [],  [2],    true),
  requiredTimeLocktime:   PSBTInfo(0x11, false,               P.U32LE,           [],  [2],    false),
  requiredHeightLocktime: PSBTInfo(0x12, false,               P.U32LE,           [],  [2],    false),
  tapKeySig:              PSBTInfo(0x13, false,               SignatureSchnorr,  [],  [0, 2], false),
  tapScriptSig:           PSBTInfo(0x14, tapScriptSigKey,     SignatureSchnorr,  [],  [0, 2], false),
  tapLeafScript:          PSBTInfo(0x15, TaprootControlBlock, BytesInf,          [],  [0, 2], false),
  // BIP371 key data here is a 32-byte x-only pubkey, so reuse the shared Schnorr pubkey coder
  // instead of accepting arbitrary 32-byte blobs that only fail much later in taproot flows.
  tapBip32Derivation:     PSBTInfo(0x16, PubKeySchnorr,       TaprootBIP32Der,   [],  [0, 2], false),
  tapInternalKey:         PSBTInfo(0x17, false,               PubKeySchnorr,     [],  [0, 2], false),
  tapMerkleRoot:          PSBTInfo(0x18, false,               Bytes32,           [],  [0, 2], false),
  proprietary:            PSBTInfo(0xfc, BytesInf,            BytesInf,          [],  [0, 2], false),
} as const))();
// All other keys removed when finalizing
/**
 * Input fields preserved after finalization.
 * @example
 * Use the allowlist when stripping transient signing fields after finalization.
 * ```ts
 * import { PSBTInputFinalKeys } from '@scure/btc-signer/psbt.js';
 * const finalKeys = new Set(PSBTInputFinalKeys);
 * finalKeys.has('finalScriptWitness');
 * ```
 */
export const PSBTInputFinalKeys = /* @__PURE__ */ Object.freeze<(keyof TransactionInput)[]>([
  // PSBTv2 extractors rebuild the final transaction from per-input fields, so
  // finalized inputs still need txid/index (and any non-default sequence)
  // even though BIP174's generic cleanup is stricter.
  'txid',
  'sequence',
  'index',
  'witnessUtxo',
  'nonWitnessUtxo',
  'finalScriptSig',
  'finalScriptWitness',
  'unknown',
]);

// Can be modified even on signed input
/**
 * Input fields that may still change after signing starts.
 * @example
 * Signed inputs may still update these fields while new signatures are being added.
 * ```ts
 * import { PSBTInputUnsignedKeys } from '@scure/btc-signer/psbt.js';
 * const mutableKeys = new Set(PSBTInputUnsignedKeys);
 * mutableKeys.has('tapScriptSig');
 * ```
 */
export const PSBTInputUnsignedKeys = /* @__PURE__ */ Object.freeze<(keyof TransactionInput)[]>([
  // This is the replace/remove allowlist for signed inputs; mergeKeyMap() can still append
  // previously absent metadata or new KV entries for other fields when they don't conflict.
  'partialSig',
  'finalScriptSig',
  'finalScriptWitness',
  'tapKeySig',
  'tapScriptSig',
]);

// prettier-ignore
/**
 * PSBT output key definitions.
 * @example
 * Strip output fields that are not valid for the target PSBT version.
 * ```ts
 * import { PSBTOutput, cleanPSBTFields } from '@scure/btc-signer/psbt.js';
 * cleanPSBTFields(2, PSBTOutput, { amount: 2n, script: new Uint8Array([0x51]) });
 * ```
 */
export const PSBTOutput = /* @__PURE__ */ (() => Object.freeze({
  redeemScript:       PSBTInfo(0x00, false,         BytesInf,        [],  [0, 2], false),
  witnessScript:      PSBTInfo(0x01, false,         BytesInf,        [],  [0, 2], false),
  bip32Derivation:    PSBTInfo(0x02, PubKeyECDSA,   BIP32Der,        [],  [0, 2], false),
  // BIP174/BIP370 serialize PSBT_OUT_AMOUNT as a signed int64 on the wire; semantic output
  // validity still rejects negative transaction amounts in `PSBTOutputCoder` below.
  amount:             PSBTInfo(0x03, false,         P.I64LE,         [2], [2],    true),
  script:             PSBTInfo(0x04, false,         BytesInf,        [2], [2],    true),
  tapInternalKey:     PSBTInfo(0x05, false,         PubKeySchnorr,   [],  [0, 2], false),
  // BIP371 expects a non-empty DFS-ordered list of tapleaf tuples here so wallets can
  // reconstruct the same Taproot tree, not just an arbitrary list of serialized leaves.
  tapTree:            PSBTInfo(0x06, false,         tapTree,         [],  [0, 2], false),
  tapBip32Derivation: PSBTInfo(0x07, PubKeySchnorr, TaprootBIP32Der, [],  [0, 2], false),
  proprietary:        PSBTInfo(0xfc, BytesInf,      BytesInf,        [],  [0, 2], false),
} as const))();

// Can be modified even on signed input
/**
 * Output fields that may still change after signing starts.
 * @example
 * PSBTv2 outputs are fully committed once signing starts, so the set stays empty.
 * ```ts
 * import { PSBTOutputUnsignedKeys } from '@scure/btc-signer/psbt.js';
 * const mutableKeys = new Set(PSBTOutputUnsignedKeys);
 * mutableKeys.size; // 0
 * ```
 */
export const PSBTOutputUnsignedKeys = /* @__PURE__ */ Object.freeze<(keyof typeof PSBTOutput)[]>(
  []
);
// Signed outputs have no replace/remove exceptions: once a signature actually commits to a given
// output, every field on that output is frozen. SIGHASH_NONE leaves outputs fully mutable, and
// SIGHASH_SINGLE only freezes the matching output index.

// Raw BIP174 keypair framing only: `<key><value>` records terminated by `0x00`.
// Uniqueness, keyed-vs-unkeyed rules, and per-type decoding live one layer up in `PSBTKeyMap`.
const PSBTKeyPair = /* @__PURE__ */ (() =>
  P.array(
    P.NULL,
    P.struct({
      //  <key> := <keylen> <keytype> <keydata> WHERE keylen = len(keytype)+len(keydata)
      key: P.prefix(CompactSizeLen, P.struct({ type: CompactSizeLen, key: P.bytes(null) })),
      //  <value> := <valuelen> <valuedata>
      value: P.bytes(CompactSizeLen),
    })
  ))();

function PSBTKeyInfo(info: PSBTKeyMapInfo) {
  // Name the tuple slots once so version-filter helpers do not depend on raw positional indexing.
  const [type, kc, vc, reqInc, allowInc, silentIgnore] = info;
  return { type, kc, vc, reqInc, allowInc, silentIgnore };
}

type PSBTKeyMap = Record<string, PSBTKeyMapInfo>;

const PSBTUnknownKey: P.CoderType<
  P.StructInput<{
    type: number;
    key: Bytes;
  }>
> = /* @__PURE__ */ (() =>
  // Raw unknown/proprietary field key: compact-size keytype plus opaque keydata for pass-through.
  P.struct({ type: CompactSizeLen, key: P.bytes(null) }))();
type PSBTUnknownFields = { unknown?: [P.UnwrapCoder<typeof PSBTUnknownKey>, Bytes][] };
/** Maps a PSBT key-definition table to the decoded key-map shape. */
export type PSBTKeyMapKeys<T extends PSBTKeyMap> = {
  -readonly [K in keyof T]?: T[K][1] extends false
    ? P.UnwrapCoder<T[K][2]>
    : [P.UnwrapCoder<T[K][1]>, P.UnwrapCoder<T[K][2]>][];
} & PSBTUnknownFields;
// Key cannot be 'unknown', value coder cannot be array for elements with empty key
function PSBTKeyMap<T extends PSBTKeyMap>(psbtEnum: T): TRet<P.CoderType<PSBTKeyMapKeys<T>>> {
  // -> Record<type, [keyName, ...coders]>
  const byType: Record<number, [string, PSBTKeyCoder, P.CoderType<any>]> = {};
  for (const k in psbtEnum) {
    const [num, kc, vc] = psbtEnum[k];
    byType[num] = [k, kc, vc];
  }
  return P.wrap({
    encodeStream: (w: P.Writer, value: TArg<PSBTKeyMapKeys<T>>) => {
      const _value = value as PSBTKeyMapKeys<T>;
      let out: P.UnwrapCoder<typeof PSBTKeyPair> = [];
      const seen: Record<string, true> = {};
      const add = (key: P.UnwrapCoder<typeof PSBTUnknownKey>, value: TArg<Bytes>) => {
        const _value = value as Bytes;
        // BIP174 defines `<key> := <keylen> <keytype> <keydata>` and says repeated `<keytype>`
        // entries are allowed within one `<map>` as long as the full `<key>` stays unique.
        // `<keylen>` is derived from `<keytype><keydata>`, so `PSBTUnknownKey` is enough here.
        const kStr = hex.encode(PSBTUnknownKey.encode(key));
        if (seen[kStr]) throw new Error(`PSBT: duplicate key=${kStr}`);
        seen[kStr] = true;
        out.push({ key, value: _value });
      };
      // Because we use order of psbtEnum, keymap is sorted here
      for (const name in psbtEnum) {
        const val = _value[name];
        if (val === undefined) continue;
        const [type, kc, vc] = psbtEnum[name];
        if (!kc) {
          add({ type, key: P.EMPTY }, vc.encode(val));
        } else {
          // BIP174 allows repeated `<keytype>` values inside one `<map>`, but the full `<key>`
          // must stay unique, so keyed rows are sorted and then deduped by serialized key bytes.
          const kv: [Bytes, Bytes][] = val!.map(
            ([k, v]: [P.UnwrapCoder<typeof kc>, P.UnwrapCoder<typeof vc>]) => [
              kc.encode(k),
              vc.encode(v),
            ]
          );
          // sort by keys
          kv.sort((a, b) => compareBytes(a[0], b[0]));
          for (const [key, value] of kv) add({ key, type }, value);
        }
      }
      if (_value.unknown) {
        _value.unknown.sort((a, b) => compareBytes(a[0].key, b[0].key));
        for (const [k, v] of _value.unknown) add(k, v);
      }
      PSBTKeyPair.encodeStream(w, out);
    },
    decodeStream: (r: P.Reader): TRet<PSBTKeyMapKeys<T>> => {
      const raw = PSBTKeyPair.decodeStream(r);
      const out: any = {};
      const noKey: Record<string, true> = {};
      const seen: Record<string, true> = {};
      for (const elm of raw) {
        const kStr = hex.encode(PSBTUnknownKey.encode(elm.key));
        if (seen[kStr]) throw new Error(`PSBT: duplicate key=${kStr}`);
        seen[kStr] = true;
        let name = 'unknown';
        let key: any = elm.key.key;
        let value = elm.value;
        if (byType[elm.key.type]) {
          const [_name, kc, vc] = byType[elm.key.type];
          name = _name;
          if (!kc && key.length) {
            throw new Error(
              `PSBT: Non-empty key for ${name} (key=${hex.encode(key)} value=${hex.encode(value)}`
            );
          }
          key = kc ? kc.decode(key) : undefined;
          value = vc.decode(value);
          if (!kc) {
            if (out[name]) throw new Error(`PSBT: Same keys: ${name} (key=${key} value=${value})`);
            out[name] = value;
            noKey[name] = true;
            continue;
          }
        } else {
          // For unknown: add key type inside key
          key = { type: elm.key.type, key: elm.key.key };
        }
        // Only keyed elements at this point.
        // BIP174 uniqueness is over the full serialized `<key>` bytes within one map, not only keytype.
        // Empty-key rows are rejected above; keyed duplicates need an explicit check before this append path.
        if (noKey[name])
          throw new Error(`PSBT: Key type with empty key and no key=${name} val=${value}`);
        if (!out[name]) out[name] = [];
        out[name].push([key, value]);
      }
      return out as TRet<PSBTKeyMapKeys<T>>;
    },
  }) as TRet<P.CoderType<PSBTKeyMapKeys<T>>>;
}

/**
 * Validated PSBT input coder.
 * @example
 * Validate a decoded PSBT input before serializing it back to bytes.
 * ```ts
 * import { hex } from '@scure/base';
 * import { PSBTInputCoder } from '@scure/btc-signer/psbt.js';
 * PSBTInputCoder.encode({
 *   txid: hex.decode('0000000000000000000000000000000000000000000000000000000000000001'),
 *   index: 0,
 *   witnessUtxo: { amount: 1n, script: new Uint8Array([0x51]) },
 * });
 * ```
 */
export const PSBTInputCoder = /* @__PURE__ */ (() =>
  Object.freeze(
    P.validate(PSBTKeyMap(PSBTInput), (i) => {
      // This wrapper adds input-level invariants after raw PSBT key-map decoding.
      // Row-level key validation and duplicate-key rejection still depend on the underlying table/map helpers.
      if (i.finalScriptWitness && !i.finalScriptWitness.length)
        throw new Error('validateInput: empty finalScriptWitness');
      //if (i.finalScriptSig && !i.finalScriptSig.length) throw new Error('validateInput: empty finalScriptSig');
      if (i.partialSig && !i.partialSig.length) throw new Error('Empty partialSig');
      if (i.partialSig) for (const [k] of i.partialSig) validatePubkey(k, PubT.ecdsa);
      if (i.bip32Derivation) for (const [k] of i.bip32Derivation) validatePubkey(k, PubT.ecdsa);
      // Locktime = unsigned little endian integer greater than or equal to 500000000 representing
      if (i.requiredTimeLocktime !== undefined && i.requiredTimeLocktime < 500000000)
        throw new Error(`validateInput: wrong timeLocktime=${i.requiredTimeLocktime}`);
      // unsigned little endian integer greater than 0 and less than 500000000
      if (
        i.requiredHeightLocktime !== undefined &&
        (i.requiredHeightLocktime <= 0 || i.requiredHeightLocktime >= 500000000)
      )
        throw new Error(`validateInput: wrong heighLocktime=${i.requiredHeightLocktime}`);
      if (i.tapLeafScript) {
        // tap leaf version appears here twice: in control block and at the end of script
        for (const [k, v] of i.tapLeafScript) {
          if ((k.version & 0b1111_1110) !== v[v.length - 1])
            throw new Error('validateInput: tapLeafScript version mimatch');
          if (v[v.length - 1] & 1)
            throw new Error('validateInput: tapLeafScript version has parity bit!');
        }
      }
      return i;
    })
  ))();

/** Replaces selected keys in `T` with widened update shapes from `E`. */
export type ExtendType<T, E> = {
  [K in keyof T]: K extends keyof E ? E[K] | T[K] : T[K];
};
/** Marks selected keys in `T` as required. */
export type RequireType<T, K extends keyof T> = T & {
  [P in K]-?: T[P];
};

/** Fully decoded PSBT input. */
export type TransactionInput = PSBTKeyMapKeys<typeof PSBTInput>;
/** PSBT input update shape accepted by mutation helpers. */
export type TransactionInputUpdate = ExtendType<
  PSBTKeyMapKeys<typeof PSBTInput>,
  {
    nonWitnessUtxo?: string | Bytes;
    txid?: string;
  }
>;

/**
 * Validated PSBT output coder.
 * @example
 * Validate a decoded PSBT output before serializing it back to bytes.
 * ```ts
 * import { PSBTOutputCoder } from '@scure/btc-signer/psbt.js';
 * PSBTOutputCoder.encode({ amount: 1n, script: new Uint8Array([0x51]) });
 * ```
 */
export const PSBTOutputCoder = /* @__PURE__ */ (() =>
  Object.freeze(
    P.validate(PSBTKeyMap(PSBTOutput), (o) => {
      // This wrapper only adds output-level invariants after raw key-map decoding.
      // Duplicate-key rejection still depends on the key-map helper; tapTree structure is validated
      // in the field coder itself because BIP371 constrains the tuple value, not just the row shape.
      // BIP174/BIP370 define PSBT_OUT_AMOUNT as a signed int64 transport field, but it still
      // represents the transaction output amount in satoshis, so negative output values are invalid.
      if (o.amount !== undefined && o.amount < 0n)
        throw new Error(`validateOutput: wrong amount=${o.amount}`);
      if (o.bip32Derivation) for (const [k] of o.bip32Derivation) validatePubkey(k, PubT.ecdsa);
      return o;
    })
  ))();

/** Fully decoded PSBT output. */
export type TransactionOutput = PSBTKeyMapKeys<typeof PSBTOutput>;
/** PSBT output update shape accepted by mutation helpers. */
export type TransactionOutputUpdate = ExtendType<
  PSBTKeyMapKeys<typeof PSBTOutput>,
  { script?: string }
>;
/** Transaction output fields required for serialization. */
export type TransactionOutputRequired = {
  /** Serialized scriptPubKey bytes. */
  script: Bytes;
  /** Output value in satoshis. */
  amount: bigint;
};

const PSBTGlobalCoder = /* @__PURE__ */ (() =>
  P.validate(PSBTKeyMap(PSBTGlobal), (g) => {
    // This wrapper adds the BIP174/BIP370 cross-field invariants after raw global key-map decoding.
    // `PSBT_GLOBAL_XPUB` stores the serialized xpub plus a separate derivation value, and BIP174
    // says the number of 32-bit indexes in that derivation path must match the xpub depth.
    const version = g.version || 0;
    if (version === 0) {
      if (!g.unsignedTx) throw new Error('PSBTv0: missing unsignedTx');
      for (const inp of g.unsignedTx.inputs)
        if (inp.finalScriptSig && inp.finalScriptSig.length)
          throw new Error('PSBTv0: input scriptSig found in unsignedTx');
    }
    for (const [xpub, der] of g.xpub || []) {
      if (xpub.depth !== der.path.length)
        throw new Error(
          `PSBT_GLOBAL_XPUB: xpub depth=${xpub.depth} must match derivation path length=${der.path.length}`
        );
    }
    return g;
  }))();

export const _RawPSBTV0 = /* @__PURE__ */ (() =>
  Object.freeze(
    P.struct({
      magic: P.magic(P.string(new Uint8Array([0xff])), 'psbt'),
      global: PSBTGlobalCoder,
      // Raw v0 framing follows the unsigned transaction for input-map count; the stricter
      // one-map-per-input/output reconciliation happens in `RawPSBTV0` / `validatePSBT`.
      inputs: P.array('global/unsignedTx/inputs/length', PSBTInputCoder),
      outputs: P.array(null, PSBTOutputCoder),
    })
  ))();

export const _RawPSBTV2 = /* @__PURE__ */ (() =>
  Object.freeze(
    P.struct({
      magic: P.magic(P.string(new Uint8Array([0xff])), 'psbt'),
      global: PSBTGlobalCoder,
      // Raw v2 framing takes map counts from the global PSBTv2 count fields; deeper version
      // and per-field validation still happens in `RawPSBTV2` / `validatePSBT`.
      inputs: P.array('global/inputCount', PSBTInputCoder),
      outputs: P.array('global/outputCount', PSBTOutputCoder),
    })
  ))();

/** Raw PSBT coder type. */
export type PSBTRaw = typeof _RawPSBTV0 | typeof _RawPSBTV2;

export const _DebugPSBT = /* @__PURE__ */ (() =>
  Object.freeze(
    P.struct({
      magic: P.magic(P.string(new Uint8Array([0xff])), 'psbt'),
      // Debug-only normalized view: maps become plain objects, so key order is intentionally ignored
      // and duplicate keys fail while decoding instead of being preserved for byte-level diagnostics.
      // Each `items[i]` is one raw PSBT map (`global`, then inputs, then outputs), keyed by the
      // full serialized PSBT key bytes as hex rather than decoded field names.
      items: P.array(
        null,
        P.apply(
          P.array(P.NULL, P.tuple([P.hex(CompactSizeLen), P.bytes(CompactSize)])),
          P.coders.dict()
        )
      ),
    })
  ))();

function validatePSBTFields<T extends PSBTKeyMap>(
  version: number,
  info: T,
  lst: TArg<PSBTKeyMapKeys<T>>
) {
  const _lst = lst as PSBTKeyMapKeys<T>;
  // Enforce the BIP174/BIP370 field-table columns directly: reject rows whose
  // "Versions Allowing Inclusion" excludes this version and require rows whose
  // "Versions Requiring Inclusion" includes it.
  for (const k in _lst) {
    if (k === 'unknown') continue;
    if (!info[k]) continue;
    const { allowInc } = PSBTKeyInfo(info[k]);
    if (!allowInc.includes(version)) throw new Error(`PSBTv${version}: field ${k} is not allowed`);
  }
  for (const k in info) {
    const { reqInc } = PSBTKeyInfo(info[k]);
    if (reqInc.includes(version) && _lst[k] === undefined)
      throw new Error(`PSBTv${version}: missing required field ${k}`);
  }
}

/**
 * Removes fields that are not valid for the requested PSBT version.
 * @param version - target PSBT version
 * @param info - PSBT field definition table
 * @param lst - decoded PSBT key map
 * @returns Filtered PSBT key map.
 * @throws If a field cannot be serialized in the requested PSBT version. {@link Error}
 * @example
 * Drop fields that are not allowed in the target PSBT version before encoding.
 * ```ts
 * import { hex } from '@scure/base';
 * import { PSBTInput, cleanPSBTFields } from '@scure/btc-signer/psbt.js';
 * cleanPSBTFields(2, PSBTInput, {
 *   txid: hex.decode('0000000000000000000000000000000000000000000000000000000000000001'),
 *   index: 0,
 * });
 * ```
 */
export function cleanPSBTFields<T extends PSBTKeyMap>(
  version: number,
  info: T,
  lst: TArg<PSBTKeyMapKeys<T>>
): TRet<PSBTKeyMapKeys<T>> {
  const _lst = lst as PSBTKeyMapKeys<T>;
  const out: PSBTKeyMapKeys<T> = {};
  for (const _k in _lst) {
    const k = _k as string & keyof PSBTKeyMapKeys<T>;
    // Serializer-side compatibility filter: preserve unknown pass-through fields, silently drop
    // rows explicitly marked `silentIgnore`, and throw on other rows the target version forbids.
    if (k !== 'unknown') {
      if (!info[k]) continue;
      const { allowInc, silentIgnore } = PSBTKeyInfo(info[k]);
      if (!allowInc.includes(version)) {
        if (silentIgnore) continue;
        throw new Error(
          `Failed to serialize in PSBTv${version}: ${k} but versions allows inclusion=${allowInc}`
        );
      }
    }
    out[k] = _lst[k];
  }
  return out as TRet<PSBTKeyMapKeys<T>>;
}

function validatePSBT(tx: P.UnwrapCoder<PSBTRaw>) {
  const version = (tx && tx.global && tx.global.version) || 0;
  validatePSBTFields(version, PSBTGlobal, tx.global);
  for (const i of tx.inputs) validatePSBTFields(version, PSBTInput, i);
  for (const o of tx.outputs) validatePSBTFields(version, PSBTOutput, o);
  // BIP174 defines `<psbt> := <magic> <global-map> <input-map>* <output-map>*`, so after decode the
  // number of input/output maps should match the unsigned tx. PSBTv2 makes the same shape explicit
  // through `inputCount` / `outputCount`. We intentionally violate that strict reading for one case:
  // keep accepting exactly one trailing empty map because the separate bitcoinjs compatibility PSBT
  // fixture corpus still contains that encoding. Anything non-empty or more than one extra map is
  // still rejected here.
  const inputCount = !version ? tx.global.unsignedTx!.inputs.length : tx.global.inputCount!;
  if (tx.inputs.length < inputCount) throw new Error('Not enough inputs');
  const inputsLeft = tx.inputs.slice(inputCount);
  if (inputsLeft.length > 1 || (inputsLeft.length && Object.keys(inputsLeft[0]).length))
    throw new Error(`Unexpected inputs left in tx=${inputsLeft}`);
  // Same carve-out for outputs.
  const outputCount = !version ? tx.global.unsignedTx!.outputs.length : tx.global.outputCount!;
  if (tx.outputs.length < outputCount) throw new Error('Not outputs inputs');
  const outputsLeft = tx.outputs.slice(outputCount);
  if (outputsLeft.length > 1 || (outputsLeft.length && Object.keys(outputsLeft[0]).length))
    throw new Error(`Unexpected outputs left in tx=${outputsLeft}`);
  return tx;
}

/**
 * Merges two PSBT key maps while preserving keyed-field uniqueness.
 * @param psbtEnum - PSBT field definition table
 * @param val - new values to merge in
 * @param cur - existing decoded PSBT key map
 * @param allowedFields - fields still allowed to change
 * @param allowUnknown - whether to preserve unknown PSBT fields
 * @returns Merged PSBT key map.
 * @throws If keyed PSBT fields conflict or signed fields would be removed. {@link Error}
 * @example
 * Merge an updated `witnessUtxo` into an existing decoded input map.
 * ```ts
 * import { hex } from '@scure/base';
 * import { PSBTInput, mergeKeyMap } from '@scure/btc-signer/psbt.js';
 * mergeKeyMap(
 *   PSBTInput,
 *   { witnessUtxo: { amount: 2n, script: new Uint8Array([0x51]) } },
 *   {
 *     txid: hex.decode('0000000000000000000000000000000000000000000000000000000000000001'),
 *     index: 0,
 *   }
 * );
 * ```
 */
export function mergeKeyMap<T extends PSBTKeyMap>(
  psbtEnum: T,
  val: TArg<PSBTKeyMapKeys<T>>,
  cur?: TArg<PSBTKeyMapKeys<T>>,
  allowedFields?: TArg<readonly (keyof PSBTKeyMapKeys<T>)[]>,
  allowUnknown?: boolean
): TRet<PSBTKeyMapKeys<T>> {
  const _val = val as PSBTKeyMapKeys<T>;
  const _cur = cur as PSBTKeyMapKeys<T> | undefined;
  const _allowedFields = allowedFields as readonly (keyof PSBTKeyMapKeys<T>)[] | undefined;
  const res: PSBTKeyMapKeys<T> = { ..._cur, ..._val };
  // All arguments can be provided as hex
  for (const k in psbtEnum) {
    const key = k as keyof typeof psbtEnum;
    const [_, kC, vC] = psbtEnum[key];
    type _KV = [P.UnwrapCoder<typeof kC>, P.UnwrapCoder<typeof vC>];
    const cannotChange = _allowedFields && !_allowedFields.includes(k);
    if (_val[k] === undefined && k in _val) {
      if (cannotChange) throw new Error(`Cannot remove signed field=${k}`);
      delete res[k];
    } else if (kC) {
      const oldKV = (_cur && _cur[k] ? _cur[k] : []) as _KV[];
      let newKV = _val[key] as _KV[];
      if (newKV) {
        if (!Array.isArray(newKV)) throw new Error(`keyMap(${k}): KV pairs should be [k, v][]`);
        // Decode hex in k-v
        newKV = newKV.map((val: _KV): _KV => {
          if (val.length !== 2) throw new Error(`keyMap(${k}): KV pairs should be [k, v][]`);
          return [
            typeof val[0] === 'string' ? kC.decode(hex.decode(val[0])) : val[0],
            typeof val[1] === 'string' ? vC.decode(hex.decode(val[1])) : val[1],
          ];
        });
        const map: Record<string, _KV> = {};
        const add = (kStr: string, k: _KV[0], v: _KV[1]) => {
          if (map[kStr] === undefined) {
            map[kStr] = [k, v];
            return;
          }
          const oldVal = hex.encode(vC.encode(map[kStr][1]));
          const newVal = hex.encode(vC.encode(v));
          if (oldVal !== newVal)
            throw new Error(
              `keyMap(${key as string}): same key=${kStr} oldVal=${oldVal} newVal=${newVal}`
            );
        };
        for (const [k, v] of oldKV) {
          const kStr = hex.encode(kC.encode(k));
          add(kStr, k, v);
        }
        for (const [k, v] of newKV) {
          const kStr = hex.encode(kC.encode(k));
          // undefined removes previous value
          if (v === undefined) {
            if (cannotChange) throw new Error(`Cannot remove signed field=${key as string}/${k}`);
            delete map[kStr];
          } else add(kStr, k, v);
        }
        (res as any)[key] = Object.values(map) as _KV[];
      }
    } else if (typeof res[k] === 'string') {
      res[k] = vC.decode(hex.decode(res[k] as string));
    } else if (cannotChange && k in _val && _cur && _cur[k] !== undefined) {
      if (!equalBytes(vC.encode(_val[k]), vC.encode(_cur[k])))
        throw new Error(`Cannot change signed field=${k}`);
    }
  }
  if (allowUnknown && _val.unknown) {
    // Unknown PSBT rows are stripped by default here, but explicit allowUnknown mode is pass-through.
    // Merge them by full serialized unknown key so repeated updates do not clobber earlier opaque rows.
    const map: Record<string, [P.UnwrapCoder<typeof PSBTUnknownKey>, Bytes]> = {};
    for (const [k, v] of _cur?.unknown || []) map[hex.encode(PSBTUnknownKey.encode(k))] = [k, v];
    for (const [k, v] of _val.unknown) {
      const kStr = hex.encode(PSBTUnknownKey.encode(k));
      if (map[kStr] === undefined) {
        map[kStr] = [k, v];
        continue;
      }
      const oldVal = hex.encode(BytesInf.encode(map[kStr][1]));
      const newVal = hex.encode(BytesInf.encode(v));
      if (oldVal !== newVal)
        throw new Error(`keyMap(unknown): same key=${kStr} oldVal=${oldVal} newVal=${newVal}`);
    }
    res.unknown = Object.values(map);
  }
  // Remove unknown keys except the "unknown" array if allowUnknown is true
  for (const k in res) {
    if (!psbtEnum[k]) {
      if (allowUnknown && k === 'unknown') continue;
      delete res[k];
    }
  }
  return res as TRet<PSBTKeyMapKeys<T>>;
}

/** Validated PSBTv0 coder. */
// This wrapper only layers `validatePSBT`'s PSBTv0 field/count reconciliation on top of
// `_RawPSBTV0`; field-specific payload invariants still depend on the nested coders/tables.
export const RawPSBTV0 = /* @__PURE__ */ (() =>
  Object.freeze(P.validate(_RawPSBTV0, validatePSBT)))();
/** Validated PSBTv2 coder. */
// This wrapper only layers `validatePSBT`'s PSBTv2 required-field/count reconciliation on top
// of `_RawPSBTV2`; nested input/output/global field invariants still depend on the coders below.
export const RawPSBTV2 = /* @__PURE__ */ (() =>
  Object.freeze(P.validate(_RawPSBTV2, validatePSBT)))();

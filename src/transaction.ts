import { hex } from '@scure/base';
import * as P from 'micro-packed';
import { Address, type CustomScript, OutScript, checkScript, tapLeafHash } from './payment.ts';
import * as psbt from './psbt.ts';
import {
  CompactSizeLen,
  OP,
  RawOldTx,
  RawInput,
  RawOutput,
  RawTx,
  RawWitness,
  Script,
  scriptPushLen,
  VarBytes,
} from './script.ts';
import * as u from './utils.ts';
import {
  type Bytes,
  NETWORK,
  concatBytes,
  equalBytes,
  isBytes,
  type TArg,
  type TRet,
} from './utils.ts';

const EMPTY32: Uint8Array = /* @__PURE__ */ new Uint8Array(32);
const EMPTY_OUTPUT: P.UnwrapCoder<typeof RawOutput> = {
  amount: 0xffffffffffffffffn,
  script: P.EMPTY,
};
/**
 * Converts transaction weight units into virtual bytes.
 * @param weight - transaction weight
 * @returns Rounded-up virtual size.
 * @example
 * Convert transaction weight units into virtual bytes.
 * ```ts
 * toVsize(4);
 * ```
 */
export const toVsize = (weight: number): number => Math.ceil(weight / 4);

const stripCodeSeparator = (script: TArg<Bytes>): TRet<Bytes> => {
  // Reuse Script's raw pushdata-length parser here. Legacy sighash must remove
  // only actual OP_CODESEPARATOR opcodes while preserving every other original
  // byte, because semantic decode/re-encode would change the signed digest.
  let start = 0;
  const out: Uint8Array[] = [];
  for (let i = 0; i < script.length; ) {
    const pos = i;
    const op = script[i++];
    if (op === OP.CODESEPARATOR) {
      if (start < pos) out.push(script.subarray(start, pos));
      start = i;
      continue;
    }
    const len = scriptPushLen(op, (bytes) => {
      if (i + bytes > script.length) throw new Error('Unexpected end of script');
      let len = 0;
      for (let j = 0; j < bytes; j++) len |= script[i + j] << (8 * j);
      i += bytes;
      return len;
    });
    if (len === undefined) continue;
    i += len;
    if (i > script.length) throw new Error('Unexpected end of script');
  }
  if (start === 0) return script as TRet<Bytes>;
  if (start < script.length) out.push(script.subarray(start));
  return (out.length ? concatBytes(...out) : P.EMPTY) as TRet<Bytes>;
};

// @scure/bip32 interface
interface HDKey {
  publicKey: Bytes;
  privateKey: Bytes;
  fingerprint: number;
  derive(path: string): HDKey;
  deriveChild(index: number): HDKey;
  sign(hash: Bytes): Bytes;
}

/** Signing source accepted by transaction signing helpers. */
export type Signer = Bytes | HDKey;

/** Decimal precision used for BTC string formatting. */
export const PRECISION = 8;
/** Default transaction version used for newly created transactions. */
export const DEFAULT_VERSION = 2;
/** Default transaction locktime. */
export const DEFAULT_LOCKTIME = 0;
/** Default input sequence number.
 * Final (`0xffffffff`): matches the PSBT omission default and disables nLockTime/CLTV semantics
 * unless callers choose a lower sequence explicitly (for example `0xfffffffe` with lockTime).
 */
export const DEFAULT_SEQUENCE = 4294967295;
/**
 * Decimal coder for BTC-denominated strings.
 * This is a fixed-precision BTC-string to satoshi-bigint helper, not a validator
 * for transaction/PSBT output amounts. Signed values are intentional here, so
 * callers can reuse the helper for display/history-style deltas as well as
 * unsigned transfer amounts. It keeps the BTC scale at 8 fractional digits and
 * rejects over-precise inputs instead of rounding.
 * @example
 * Convert between satoshi bigint values and BTC-denominated decimal strings.
 * ```ts
 * Decimal.encode(1n);
 * ```
 */
export const Decimal: P.Coder<bigint, string> = /* @__PURE__ */ (() =>
  Object.freeze(P.coders.decimal(PRECISION)))();

// Same as value || def, but doesn't overwrites zero ('0', 0, 0n, etc)
/**
 * Returns a fallback only when the value is `undefined`.
 * @param value - optional value
 * @param def - fallback value
 * @returns `value` when defined, otherwise `def`.
 * @example
 * Keep zero-like values but replace `undefined` with a fallback.
 * ```ts
 * def(undefined, 1);
 * ```
 */
export const def = <T>(value: T | undefined, def: T): T => (value === undefined ? def : value);

/**
 * Deep-clones plain transaction data structures.
 * @param obj - value to clone
 * @returns Deep copy of the input value.
 * @throws If the value contains an unsupported runtime type. {@link Error}
 * @example
 * Clone plain transaction data structures before mutating them.
 * ```ts
 * cloneDeep({ a: [new Uint8Array([1])] });
 * ```
 */
export function cloneDeep<T>(obj: T): T {
  if (Array.isArray(obj)) return obj.map((i) => cloneDeep(i)) as unknown as T;
  // slice of nodejs Buffer doesn't copy
  else if (isBytes(obj)) return Uint8Array.from(obj) as unknown as T;
  // immutable
  else if (['number', 'bigint', 'boolean', 'string', 'undefined'].includes(typeof obj)) return obj;
  // null is object
  else if (obj === null) return obj;
  // should be last, so it won't catch other types
  else if (typeof obj === 'object') {
    return Object.fromEntries(
      Object.entries(obj).map(([k, v]) => [k, cloneDeep(v)])
    ) as unknown as T;
  }
  // Don't interpolate unsupported values here: Symbol string coercion would
  // throw before cloneDeep can surface its own stable helper error.
  throw new Error(`cloneDeep: unknown type=${typeof obj}`);
}

// Mostly security features, hardened defaults;
// but you still can parse other people tx with unspendable outputs and stuff if you want
/** Transaction construction and parsing options. */
export interface TxOpts {
  /** Transaction version to place into new transactions and imported PSBTs. */
  version?: number;
  /** Global locktime for the transaction. */
  lockTime?: number;
  /** PSBT version to emit when serializing. */
  PSBTVersion?: number;
  // Flags
  // Allow non-standard transaction version
  /** Allow transaction versions outside the standard small set. */
  allowUnknownVersion?: boolean;
  // Allow output scripts to be unknown scripts (probably unspendable)
  /**
   * Deprecated alias for {@link allowUnknownOutputs}.
   * @deprecated Use `allowUnknownOutputs`.
   */
  allowUnknowOutput?: boolean;
  /** Allow outputs with scripts this library does not recognize. */
  allowUnknownOutputs?: boolean;
  // Try to sign/finalize unknown input. All bets are off, but there is chance that it will work
  /**
   * Deprecated alias for {@link allowUnknownInputs}.
   * @deprecated Use `allowUnknownInputs`.
   */
  allowUnknowInput?: boolean;
  /** Allow signing and finalizing inputs with unknown script shapes. */
  allowUnknownInputs?: boolean;
  // Check input/output scripts for sanity
  /** Skip redeem-script and witness-script consistency checks. */
  disableScriptCheck?: boolean;
  // There is strange behaviour where tx without outputs encoded with empty output in the end,
  // tx without outputs in BIP174 doesn't have itb
  /** Match the odd empty-output encoding used by `bip174js`. */
  bip174jsCompat?: boolean;
  // If transaction data comes from untrusted source, then it can be modified in such way that will
  // result paying higher mining fee
  /** Permit legacy inputs that only provide witness UTXO data. */
  allowLegacyWitnessUtxo?: boolean;
  /** Grind ECDSA signatures until they use a low-R encoding. */
  lowR?: boolean;
  /** UNSAFE: additional custom payment-script codecs and finalizers. */
  customScripts?: CustomScript[];
  // Allow to add additional unknown keys/values to the "unknown" array member
  /** Preserve unknown PSBT key/value pairs instead of stripping them. */
  allowUnknown?: boolean;
}

/**
 * Internal, exported only for backwards-compat. Use `SigHash` instead.
 * @deprecated Use {@link SigHash} instead.
 * @example
 * Combine the legacy bit flags when interoperating with older code.
 * ```ts
 * SignatureHash.ALL | SignatureHash.ANYONECANPAY;
 * ```
 */
export const SignatureHash = /* @__PURE__ */ (() =>
  Object.freeze({
    DEFAULT: 0,
    ALL: 1,
    NONE: 2,
    SINGLE: 3,
    ANYONECANPAY: 0x80,
  } as const))();

/**
 * Common signature hash flag combinations.
 * @example
 * Use the predefined signature-hash combinations exported by the library.
 * ```ts
 * SigHash.SINGLE_ANYONECANPAY;
 * ```
 */
export const SigHash = /* @__PURE__ */ (() =>
  Object.freeze({
    DEFAULT: SignatureHash.DEFAULT,
    ALL: SignatureHash.ALL,
    NONE: SignatureHash.NONE,
    SINGLE: SignatureHash.SINGLE,
    // BIP341 only permits 0x00, 0x01, 0x02, 0x03, 0x81, 0x82, and 0x83 for taproot, so
    // the mechanical `DEFAULT | ANYONECANPAY` combination (0x80) is invalid and not exported.
    // DEFAULT_ANYONECANPAY: SignatureHash.DEFAULT | SignatureHash.ANYONECANPAY,
    ALL_ANYONECANPAY: SignatureHash.ALL | SignatureHash.ANYONECANPAY,
    NONE_ANYONECANPAY: SignatureHash.NONE | SignatureHash.ANYONECANPAY,
    SINGLE_ANYONECANPAY: SignatureHash.SINGLE | SignatureHash.ANYONECANPAY,
  } as const))();
/** Reverse lookup table for signature hash flag names. */
export const SigHashNames = /* @__PURE__ */ (() => Object.freeze(u.reverseObject(SigHash)))();
/** Signature-hash flag number accepted by signing helpers. */
export type SigHash = u.ValueOf<typeof SigHash>;

function getTaprootKeys(
  privKey: TArg<Bytes>,
  pubKey: TArg<Bytes>,
  internalKey: TArg<Bytes>,
  merkleRoot: TArg<Bytes> = P.EMPTY
) {
  if (equalBytes(internalKey, pubKey)) {
    privKey = u.taprootTweakPrivKey(privKey, merkleRoot);
    pubKey = u.pubSchnorr(privKey);
  }
  return { privKey, pubKey };
}

// User facing API with decoders
/** Minimal transaction input fields required to serialize and sign. */
export type TransactionInputRequired = {
  /** Previous transaction id being spent. */
  txid: Bytes;
  /** Previous output index inside that transaction. */
  index: number;
  /** Final sequence number that will be serialized for the input. */
  sequence: number;
  /** Final scriptSig bytes that will be serialized for the input. */
  finalScriptSig: Bytes;
};

// Force check amount/script
function outputBeforeSign(i: TArg<psbt.TransactionOutput>): TRet<psbt.TransactionOutputRequired> {
  if (i.script === undefined || i.amount === undefined)
    throw new Error('Transaction/output: script and amount required');
  return { script: i.script, amount: i.amount } as TRet<psbt.TransactionOutputRequired>;
}

// Force check index/txid/sequence
/**
 * Normalizes a PSBT input into the fields needed for signing.
 * @param i - PSBT input to validate
 * @returns Input fields required for signing.
 * @throws If the input is missing `txid` or `index`. {@link Error}
 * @example
 * Fill in defaults for the fields the signer expects to see.
 * ```ts
 * import { hex } from '@scure/base';
 * import { inputBeforeSign } from '@scure/btc-signer/transaction.js';
 * inputBeforeSign({
 *   txid: hex.decode('0000000000000000000000000000000000000000000000000000000000000001'),
 *   index: 0,
 * });
 * ```
 */
export function inputBeforeSign(i: TArg<psbt.TransactionInput>): TRet<TransactionInputRequired> {
  if (i.txid === undefined || i.index === undefined)
    throw new Error('Transaction/input: txid and index required');
  const res = {
    txid: i.txid,
    index: i.index,
    sequence: def(i.sequence, DEFAULT_SEQUENCE),
    finalScriptSig: def(i.finalScriptSig, P.EMPTY),
  };
  // This helper is the public "normalize for signing" boundary, so reuse RawInput's existing
  // wire-shape checks here instead of letting malformed runtime field types fail much later.
  RawInput.encode(res);
  return res as TRet<TransactionInputRequired>;
}
function cleanFinalInput(i: TArg<PSBTInputs>) {
  const _i = i as PSBTInputs;
  // BIP174 finalizers clear non-final input metadata after constructing final scripts/witnesses.
  // That intentionally drops sighashType here, so post-finalize mutation becomes conservative
  // until callers explicitly reopen the input by removing finalScriptSig/finalScriptWitness.
  for (const _k in _i) {
    const k = _k as keyof PSBTInputs;
    if (!psbt.PSBTInputFinalKeys.includes(k)) delete _i[k];
  }
}

// (TxHash, Idx)
const TxHashIdx = /* @__PURE__ */ (() => P.struct({ txid: P.bytes(32, true), index: P.U32LE }))();

function validateSigHash(s: SigHash) {
  if (typeof s !== 'number' || typeof SigHashNames[s] !== 'string')
    throw new Error(`Invalid SigHash=${s}`);
  return s;
}

function unpackSighash(hashType: number) {
  const masked = hashType & 0b0011111;
  return {
    isAny: !!(hashType & SignatureHash.ANYONECANPAY),
    isNone: masked === SignatureHash.NONE,
    isSingle: masked === SignatureHash.SINGLE,
  };
}

function validateOpts(opts: TArg<TxOpts>): TRet<Readonly<TxOpts>> {
  if (opts !== undefined && {}.toString.call(opts) !== '[object Object]')
    throw new Error(`Wrong object type for transaction options: ${opts}`);

  const _opts = {
    ...opts,
    // Defaults
    version: def(opts.version, DEFAULT_VERSION),
    lockTime: def(opts.lockTime, 0),
    PSBTVersion: def(opts.PSBTVersion, 0),
  };
  // Normalize deprecated aliases on the owned copy so they still affect tx.opts without rewriting the
  // caller-owned options object passed to the constructor.
  if (typeof _opts.allowUnknowInput !== 'undefined')
    _opts.allowUnknownInputs = _opts.allowUnknowInput;
  if (typeof _opts.allowUnknowOutput !== 'undefined')
    _opts.allowUnknownOutputs = _opts.allowUnknowOutput;
  if (typeof _opts.lockTime !== 'number') throw new Error('Transaction lock time should be number');
  P.U32LE.encode(_opts.lockTime); // Additional range checks that lockTime
  // There is no PSBT v1, and any new version will probably have fields which we don't know how to parse, which
  // can lead to constructing broken transactions
  if (_opts.PSBTVersion !== 0 && _opts.PSBTVersion !== 2)
    throw new Error(`Unknown PSBT version ${_opts.PSBTVersion}`);
  // Flags
  for (const k of [
    'allowUnknownVersion',
    'allowUnknownOutputs',
    'allowUnknownInputs',
    'disableScriptCheck',
    'bip174jsCompat',
    'allowLegacyWitnessUtxo',
    'lowR',
  ] as const) {
    const v = _opts[k];
    if (v === undefined) continue; // optional
    if (typeof v !== 'boolean')
      throw new Error(`Transation options wrong type: ${k}=${v} (${typeof v})`);
  }
  // 0 and -1 happens in tests
  if (
    _opts.allowUnknownVersion
      ? typeof _opts.version === 'number'
      : ![-1, 0, 1, 2, 3].includes(_opts.version)
  )
    throw new Error(`Unknown version: ${_opts.version}`);
  if (_opts.customScripts !== undefined) {
    const cs = _opts.customScripts;
    if (!Array.isArray(cs)) {
      throw new Error(
        `wrong custom scripts type (expected array): customScripts=${cs} (${typeof cs})`
      );
    }
    for (const s of cs) {
      if (typeof s.encode !== 'function' || typeof s.decode !== 'function')
        throw new Error(`wrong script=${s} (${typeof s})`);
      if (s.finalizeTaproot !== undefined && typeof s.finalizeTaproot !== 'function')
        throw new Error(`wrong script=${s} (${typeof s})`);
    }
  }
  return Object.freeze(_opts) as TRet<Readonly<TxOpts>>;
}

// NOTE: we cannot do this inside PSBTInput coder, because there is no index/txid at this point!
function validateInput(i: TArg<psbt.TransactionInput>): TRet<PSBTInputs> {
  const _i = i as PSBTInputs;
  if (_i.nonWitnessUtxo && _i.index !== undefined) {
    const last = _i.nonWitnessUtxo.outputs.length - 1;
    if (_i.index > last) throw new Error(`validateInput: index(${_i.index}) not in nonWitnessUtxo`);
    const prevOut = _i.nonWitnessUtxo.outputs[_i.index];
    if (
      _i.witnessUtxo &&
      (!equalBytes(_i.witnessUtxo.script, prevOut.script) ||
        _i.witnessUtxo.amount !== prevOut.amount)
    )
      throw new Error('validateInput: witnessUtxo different from nonWitnessUtxo');
    if (_i.txid) {
      const outputs = _i.nonWitnessUtxo.outputs;
      if (outputs.length - 1 < _i.index) throw new Error('nonWitnessUtxo: incorect output index');
      // At this point, we are using previous tx output to create new input.
      // Script safety checks are unnecessary:
      // - User has no control over previous tx. If somebody send money in same tx
      //   as unspendable output, we still want user able to spend money
      // - We still want some checks to notify user about possible errors early
      //   in case user wants to use wrong input by mistake
      // - Worst case: tx will be rejected by nodes. Still better than disallowing user
      //   to spend real input, no matter how broken it looks
      const tx = Transaction.fromRaw(RawTx.encode(_i.nonWitnessUtxo), {
        allowUnknownOutputs: true,
        disableScriptCheck: true,
        allowUnknownInputs: true,
      });
      const txid = hex.encode(_i.txid);
      // BIP174 requires the provided nonWitnessUtxo to hash to the prevout txid even when the
      // previous transaction is otherwise non-final; finality does not make its serialized txid optional.
      // Keep the historical TransactionInput.txid convention here: internal txid bytes match
      // `Transaction.id` (display-order hex), while raw-tx / PSBT boundary coders are responsible
      // for any byte-order conversions required by their wire formats.
      if (tx.id !== txid) throw new Error(`nonWitnessUtxo: wrong txid, exp=${txid} got=${tx.id}`);
    }
  }
  return _i as TRet<PSBTInputs>;
}

/** Canonical PSBT input shape used by the coder layer. */
export type PSBTInputs = psbt.PSBTKeyMapKeys<typeof psbt.PSBTInput>;

/** Canonical PSBT output shape used by the coder layer. */
export type PSBTOutputs = psbt.PSBTKeyMapKeys<typeof psbt.PSBTOutput>;

// Normalizes input
/**
 * Extracts the previous output referenced by an input.
 * @param input - PSBT input with previous output data
 * @returns Previous output information.
 * @throws If the input does not contain usable previous-output information. {@link Error}
 * @example
 * Read the previous output from either `witnessUtxo` or `nonWitnessUtxo`.
 * ```ts
 * getPrevOut({ witnessUtxo: { amount: 1n, script: new Uint8Array([0x51]) } });
 * ```
 */
export function getPrevOut(input: TArg<psbt.TransactionInput>): P.UnwrapCoder<typeof RawOutput> {
  const _input = input as PSBTInputs;
  if (_input.nonWitnessUtxo) {
    if (_input.index === undefined) throw new Error('Unknown input index');
    // BIP174 `PSBT_IN_NON_WITNESS_UTXO` is the full spent transaction, so the
    // input outpoint index must name an existing output instead of leaking a
    // synthetic `undefined` prevout into later signing / estimation callers.
    if (
      !Number.isSafeInteger(_input.index) ||
      _input.index < 0 ||
      _input.index >= _input.nonWitnessUtxo.outputs.length
    )
      throw new Error(`Wrong input index=${_input.index}`);
    return _input.nonWitnessUtxo.outputs[_input.index];
  } else if (_input.witnessUtxo) return _input.witnessUtxo;
  else throw new Error('Cannot find previous output info');
}

/**
 * Normalizes a transaction input update into canonical PSBT form.
 * @param i - input update to normalize
 * @param cur - existing input value to merge with
 * @param allowedFields - fields that may still change on signed inputs
 * @param disableScriptCheck - whether to skip redeem/witness script sanity checks
 * @param allowUnknown - whether to keep unknown PSBT fields
 * @returns Normalized PSBT input.
 * @example
 * Accept hex txids from callers in the same display-order form used by `Transaction.id`, then
 * normalize them into the repo's internal `TransactionInput` shape.
 * ```ts
 * import { hex } from '@scure/base';
 * import { normalizeInput } from '@scure/btc-signer/transaction.js';
 * normalizeInput({
 *   txid: '0000000000000000000000000000000000000000000000000000000000000001',
 *   index: 0,
 *   witnessUtxo: { amount: 1n, script: new Uint8Array([0x51]) },
 * });
 * ```
 */
export function normalizeInput(
  i: TArg<psbt.TransactionInputUpdate>,
  cur?: TArg<PSBTInputs>,
  allowedFields?: TArg<readonly (keyof PSBTInputs)[]>,
  disableScriptCheck = false,
  allowUnknown = false
): TRet<PSBTInputs> {
  const _i = i as psbt.TransactionInputUpdate;
  const _cur = cur as PSBTInputs | undefined;
  const _allowedFields = allowedFields as readonly (keyof PSBTInputs)[] | undefined;
  let { nonWitnessUtxo, txid } = _i;
  // String support for common fields. We usually prefer Uint8Array to avoid errors
  // like hex looking string accidentally passed, however, in case of nonWitnessUtxo
  // it is better to expect string, since constructing this complex object will be
  // difficult for user
  if (typeof nonWitnessUtxo === 'string') nonWitnessUtxo = hex.decode(nonWitnessUtxo);
  if (isBytes(nonWitnessUtxo)) nonWitnessUtxo = RawTx.decode(nonWitnessUtxo);
  if (!('nonWitnessUtxo' in _i) && nonWitnessUtxo === undefined)
    nonWitnessUtxo = _cur?.nonWitnessUtxo;
  if (typeof txid === 'string') txid = hex.decode(txid);
  // TODO: if we have nonWitnessUtxo, we can extract txId from here
  if (txid === undefined) txid = _cur?.txid;
  let res: PSBTInputs = { ..._cur, ..._i, nonWitnessUtxo, txid };
  if (!('nonWitnessUtxo' in _i) && res.nonWitnessUtxo === undefined) delete res.nonWitnessUtxo;
  if (res.sequence === undefined) res.sequence = DEFAULT_SEQUENCE;
  if (res.tapMerkleRoot === null) delete res.tapMerkleRoot;
  res = psbt.mergeKeyMap(psbt.PSBTInput, res, _cur, _allowedFields, allowUnknown) as PSBTInputs;
  // Public PSBT coder surface is wrapped with TArg/TRet for TS compatibility; normalizeInput keeps
  // the repo's historical raw internal shape and casts only at the validation boundary here.
  psbt.PSBTInputCoder.encode(res as Parameters<typeof psbt.PSBTInputCoder.encode>[0]); // Validates that everything is correct at this point

  let prevOut;
  if (res.nonWitnessUtxo && res.index !== undefined)
    prevOut = res.nonWitnessUtxo.outputs[res.index];
  else if (res.witnessUtxo) prevOut = res.witnessUtxo;
  if (prevOut && !disableScriptCheck)
    checkScript(prevOut && prevOut.script, res.redeemScript, res.witnessScript);
  return res as TRet<PSBTInputs>;
}

/**
 * Determines how an input should be signed and finalized.
 * Wrapper consistency is expected to be validated earlier by {@link normalizeInput}
 * and {@link checkScript}; this helper classifies already-normalized inputs and is
 * not a standalone redeemScript/witnessScript correctness gate for raw caller input.
 * @param input - PSBT input to inspect
 * @param allowLegacyWitnessUtxo - whether legacy inputs may rely on witness UTXO data only
 * @returns Input classification including transaction type and sighash defaults.
 * @throws If a documented runtime validation or state check fails. {@link Error}
 * @example
 * Detect how the signer should treat a SegWit input from its previous output script.
 * ```ts
 * import { hex } from '@scure/base';
 * import { p2wpkh } from '@scure/btc-signer/payment.js';
 * import { getInputType } from '@scure/btc-signer/transaction.js';
 * import { pubECDSA, randomPrivateKeyBytes } from '@scure/btc-signer/utils.js';
 * getInputType({
 *   witnessUtxo: {
 *     amount: 1n,
 *     script: p2wpkh(pubECDSA(randomPrivateKeyBytes())).script,
 *   },
 * });
 * ```
 */
export function getInputType(input: TArg<psbt.TransactionInput>, allowLegacyWitnessUtxo = false) {
  const _input = input as PSBTInputs;
  let txType = 'legacy';
  let defaultSighash: number = SignatureHash.ALL;
  const prevOut = getPrevOut(_input as TArg<psbt.TransactionInput>);
  const first = OutScript.decode(prevOut.script);
  let type = first.type;
  let cur = first;
  const stack = [first];
  if (first.type === 'tr') {
    // Expected invariant: taproot inputs use PSBT_IN_TAP_* metadata only;
    // legacy redeemScript/witnessScript fields belong to P2SH/P2WSH paths.
    defaultSighash = SignatureHash.DEFAULT;
    return {
      txType: 'taproot',
      type: 'tr',
      last: first,
      lastScript: prevOut.script,
      defaultSighash,
      sighash: _input.sighashType || defaultSighash,
    };
  } else {
    if (first.type === 'wpkh' || first.type === 'wsh') txType = 'segwit';
    if (first.type === 'sh') {
      if (!_input.redeemScript) throw new Error('inputType: sh without redeemScript');
      let child = OutScript.decode(_input.redeemScript);
      if (child.type === 'wpkh' || child.type === 'wsh') txType = 'segwit';
      stack.push(child);
      cur = child;
      type += `-${child.type}`;
    }
    // wsh can be inside sh
    if (cur.type === 'wsh') {
      if (!_input.witnessScript) throw new Error('inputType: wsh without witnessScript');
      let child = OutScript.decode(_input.witnessScript);
      if (child.type === 'wsh') txType = 'segwit';
      stack.push(child);
      cur = child;
      type += `-${child.type}`;
    }
    const last = stack[stack.length - 1];
    if (last.type === 'sh' || last.type === 'wsh')
      throw new Error('inputType: sh/wsh cannot be terminal type');
    const lastScript = OutScript.encode(last);
    const res = {
      type,
      txType,
      last,
      lastScript,
      defaultSighash,
      sighash: _input.sighashType || defaultSighash,
    };
    if (txType === 'legacy' && !allowLegacyWitnessUtxo && !_input.nonWitnessUtxo) {
      throw new Error(
        `Transaction/sign: legacy input without nonWitnessUtxo, can result in attack that forces paying higher fees. Pass allowLegacyWitnessUtxo=true, if you sure`
      );
    }
    return res;
  }
}

/**
 * Mutable Bitcoin transaction and PSBT helper.
 * @param opts - Transaction construction and PSBT serialization options. See {@link TxOpts}.
 * @example
 * Create a transaction, add one spend, and export it as PSBT.
 * ```ts
 * import { hex } from '@scure/base';
 * import { p2wpkh } from '@scure/btc-signer/payment.js';
 * import { Transaction } from '@scure/btc-signer/transaction.js';
 * import { pubECDSA, randomPrivateKeyBytes } from '@scure/btc-signer/utils.js';
 * const spend = p2wpkh(pubECDSA(randomPrivateKeyBytes()));
 * const tx = new Transaction();
 * tx.addInput({
 *   txid: hex.decode('0000000000000000000000000000000000000000000000000000000000000001'),
 *   index: 0,
 *   witnessUtxo: { amount: 2n, script: spend.script },
 * });
 * tx.addOutput({ script: spend.script, amount: 1n });
 * tx.toPSBT();
 * ```
 */
export class Transaction {
  private global: psbt.PSBTKeyMapKeys<typeof psbt.PSBTGlobal> = {};
  private inputs: PSBTInputs[] = []; // use getInput()
  private outputs: PSBTOutputs[] = []; // use getOutput()
  readonly opts: ReturnType<typeof validateOpts>;
  constructor(opts: TxOpts = {}) {
    const _opts = (this.opts = validateOpts(opts));
    // Merge with global structure of PSBTv2
    if (_opts.lockTime !== DEFAULT_LOCKTIME) this.global.fallbackLocktime = _opts.lockTime;
    this.global.txVersion = _opts.version;
  }

  // Import
  static fromRaw(raw: Bytes, opts: TxOpts = {}): Transaction {
    const parsed = RawTx.decode(raw);
    const tx = new Transaction({ ...opts, version: parsed.version, lockTime: parsed.lockTime });
    for (const o of parsed.outputs) tx.addOutput(o);
    tx.outputs = parsed.outputs;
    tx.inputs = parsed.inputs;
    if (parsed.witnesses) {
      for (let i = 0; i < parsed.witnesses.length; i++)
        tx.inputs[i].finalScriptWitness = parsed.witnesses[i];
    }
    return tx;
  }
  // PSBT
  static fromPSBT(psbt_: Bytes, opts: TxOpts = {}): Transaction {
    let parsed: P.UnwrapCoder<typeof psbt.RawPSBTV0>;
    try {
      parsed = psbt.RawPSBTV0.decode(psbt_);
    } catch (e0) {
      try {
        parsed = psbt.RawPSBTV2.decode(psbt_);
      } catch (e2) {
        // Throw error for v0 parsing, since it popular, otherwise it would be shadowed by v2 error
        throw e0;
      }
    }
    const PSBTVersion = parsed.global.version || 0;
    if (PSBTVersion !== 0 && PSBTVersion !== 2)
      throw new Error(`Wrong PSBT version=${PSBTVersion}`);
    const unsigned = parsed.global.unsignedTx;
    const version = PSBTVersion === 0 ? unsigned?.version : parsed.global.txVersion;
    const lockTime = PSBTVersion === 0 ? unsigned?.lockTime : parsed.global.fallbackLocktime;
    const tx = new Transaction({ ...opts, version, lockTime, PSBTVersion });
    // We need slice here, because otherwise
    const inputCount = PSBTVersion === 0 ? unsigned?.inputs.length : parsed.global.inputCount;
    tx.inputs = parsed.inputs.slice(0, inputCount).map(
      (i, j) =>
        validateInput({
          finalScriptSig: P.EMPTY,
          ...parsed.global.unsignedTx?.inputs[j],
          ...i,
        }) as PSBTInputs
    );
    const outputCount = PSBTVersion === 0 ? unsigned?.outputs.length : parsed.global.outputCount;
    tx.outputs = parsed.outputs.slice(0, outputCount).map((i, j) => ({
      ...i,
      ...parsed.global.unsignedTx?.outputs[j],
    }));
    tx.global = { ...parsed.global, txVersion: version }; // just in case proprietary/unknown fields
    if (lockTime !== DEFAULT_LOCKTIME) tx.global.fallbackLocktime = lockTime;
    return tx;
  }
  // Prefer `global.version` when present so cross-version combiners can serialize at the highest
  // required PSBT version without mutating the frozen transaction options object.
  toPSBT(
    PSBTVersion: number | undefined = this.global.version || this.opts.PSBTVersion
  ): Uint8Array {
    if (PSBTVersion !== 0 && PSBTVersion !== 2)
      throw new Error(`Wrong PSBT version=${PSBTVersion}`);
    // if (PSBTVersion === 0 && this.inputs.length === 0) {
    //   throw new Error(
    //     'PSBT version=0 export for transaction without inputs disabled, please use version=2. Please check `toPSBT` method for explanation.'
    //   );
    // }
    const inputs = this.inputs.map((i) =>
      // For PSBTv0 the prevout txid/index live in global.unsignedTx rather than the input map, so
      // validate the full transaction input before version filtering drops those fields.
      psbt.cleanPSBTFields(PSBTVersion, psbt.PSBTInput, validateInput(i) as TArg<PSBTInputs>)
    );
    for (const inp of inputs) {
      // Don't serialize empty fields
      if (inp.partialSig && !inp.partialSig.length) delete inp.partialSig;
      if (inp.finalScriptSig && !inp.finalScriptSig.length) delete inp.finalScriptSig;
      if (inp.finalScriptWitness && !inp.finalScriptWitness.length) delete inp.finalScriptWitness;
    }
    const outputs = this.outputs.map((i) => psbt.cleanPSBTFields(PSBTVersion, psbt.PSBTOutput, i));
    const global = { ...this.global };
    if (PSBTVersion === 0) {
      /*
      - Bitcoin raw transaction expects to have at least 1 input because it uses case with zero inputs as marker for SegWit
      - this means we cannot serialize raw tx with zero inputs since it will be parsed as SegWit tx
      - Parsing of PSBTv0 depends on unsignedTx (it looks for input count here)
      - BIP-174 requires old serialization format (without witnesses) inside global, which solves this
      */
      global.unsignedTx = RawOldTx.decode(
        RawOldTx.encode({
          version: this.version,
          lockTime: this.lockTime,
          inputs: this.inputs
            .map((i) => inputBeforeSign(i as TArg<psbt.TransactionInput>))
            .map((i) => ({
              ...i,
              finalScriptSig: P.EMPTY,
            })),
          outputs: this.outputs.map((o) => outputBeforeSign(o as TArg<psbt.TransactionOutput>)),
        })
      );
      delete global.fallbackLocktime;
      delete global.txVersion;
      // PSBTv0 carries the unsigned transaction as one blob, so the PSBTv2 framing fields must be
      // removed here. Keeping `global.version` would make validation treat this rebuilt v0 map as
      // PSBTv2 and reject the required `unsignedTx` field.
      delete global.inputCount;
      delete global.outputCount;
      delete global.version;
    } else {
      // Cross-version merges and v0->v2 re-exports can still carry the PSBTv0 unsignedTx blob in
      // `this.global`, but PSBTv2 serializes the transaction through split global/input/output
      // fields instead, so drop the stale v0-only field before PSBTv2 validation/encoding.
      delete global.unsignedTx;
      global.version = PSBTVersion;
      global.txVersion = this.version;
      global.inputCount = this.inputs.length;
      global.outputCount = this.outputs.length;
      if (global.fallbackLocktime && global.fallbackLocktime === DEFAULT_LOCKTIME)
        delete global.fallbackLocktime;
    }
    if (this.opts.bip174jsCompat) {
      if (!inputs.length) inputs.push({});
      if (!outputs.length) outputs.push({});
    }
    const raw = { global, inputs, outputs };
    return PSBTVersion === 0
      ? psbt.RawPSBTV0.encode(raw as Parameters<typeof psbt.RawPSBTV0.encode>[0])
      : psbt.RawPSBTV2.encode(raw as Parameters<typeof psbt.RawPSBTV2.encode>[0]);
  }

  // BIP370 lockTime (https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki#determining-lock-time)
  get lockTime(): number {
    let height = DEFAULT_LOCKTIME;
    let heightCnt = 0;
    let time = DEFAULT_LOCKTIME;
    let timeCnt = 0;
    for (const i of this.inputs) {
      if (i.requiredHeightLocktime) {
        height = Math.max(height, i.requiredHeightLocktime);
        heightCnt++;
      }
      if (i.requiredTimeLocktime) {
        time = Math.max(time, i.requiredTimeLocktime);
        timeCnt++;
      }
    }
    if (heightCnt && heightCnt >= timeCnt) return height;
    if (time !== DEFAULT_LOCKTIME) return time;
    return this.global.fallbackLocktime || DEFAULT_LOCKTIME;
  }

  get version(): number {
    // Should be not possible
    if (this.global.txVersion === undefined) throw new Error('No global.txVersion');
    return this.global.txVersion;
  }

  private inputStatus(idx: number) {
    this.checkInputIdx(idx);
    const input = this.inputs[idx];
    // Finalized
    if (input.finalScriptSig && input.finalScriptSig.length) return 'finalized';
    if (input.finalScriptWitness && input.finalScriptWitness.length) return 'finalized';
    // Signed taproot
    if (input.tapKeySig) return 'signed';
    if (input.tapScriptSig && input.tapScriptSig.length) return 'signed';
    // Signed
    if (input.partialSig && input.partialSig.length) return 'signed';
    return 'unsigned';
  }
  // Cannot replace unpackSighash, tests rely on very generic implemenetation with signing inputs outside of range
  // We will lose some vectors -> smaller test coverage of preimages (very important!)
  private inputSighash(idx: number) {
    this.checkInputIdx(idx);
    const inputSighash = this.inputs[idx].sighashType;
    const sighash = inputSighash === undefined ? SignatureHash.DEFAULT : inputSighash;
    // ALL or DEFAULT -- everything signed
    // NONE           -- all inputs + no outputs
    // SINGLE         -- all inputs + output with same index
    // ALL + ANYONE   -- specific input + all outputs
    // NONE + ANYONE  -- specific input + no outputs
    // SINGLE         -- specific inputs + output with same index
    const sigOutputs = sighash === SignatureHash.DEFAULT ? SignatureHash.ALL : sighash & 0b11;
    const sigInputs = sighash & SignatureHash.ANYONECANPAY;
    return { sigInputs, sigOutputs };
  }
  // Very nice for debug purposes, but slow. If there is too much inputs/outputs to add, will be quadratic.
  // Some cache will be nice, but there chance to have bugs with cache invalidation
  private signStatus() {
    // if addInput or addOutput is not possible, then all inputs or outputs are signed
    let addInput = true,
      addOutput = true;
    let inputs = [],
      outputs = [];
    for (let idx = 0; idx < this.inputs.length; idx++) {
      const status = this.inputStatus(idx);
      // Unsigned input doesn't affect anything
      if (status === 'unsigned') continue;
      const { sigInputs, sigOutputs } = this.inputSighash(idx);
      // Input type
      if (sigInputs === SignatureHash.ANYONECANPAY) inputs.push(idx);
      else addInput = false;
      // Output type
      if (sigOutputs === SignatureHash.ALL) addOutput = false;
      else if (sigOutputs === SignatureHash.SINGLE) outputs.push(idx);
      else if (sigOutputs === SignatureHash.NONE) {
        // Doesn't affect any outputs at all
      } else throw new Error(`Wrong signature hash output type: ${sigOutputs}`);
    }
    return { addInput, addOutput, inputs, outputs };
  }

  get isFinal(): boolean {
    for (let idx = 0; idx < this.inputs.length; idx++)
      if (this.inputStatus(idx) !== 'finalized') return false;
    return true;
  }

  // Info utils
  get hasWitnesses(): boolean {
    let out = false;
    for (const i of this.inputs)
      if (i.finalScriptWitness && i.finalScriptWitness.length) out = true;
    return out;
  }
  // https://en.bitcoin.it/wiki/Weight_units
  get weight(): number {
    if (!this.isFinal) throw new Error('Transaction is not finalized');
    let out = 32;
    // Outputs
    const outputs = this.outputs.map(outputBeforeSign);
    out += 4 * CompactSizeLen.encode(this.outputs.length).length;
    for (const o of outputs) out += 32 + 4 * VarBytes.encode(o.script).length;
    // Inputs
    if (this.hasWitnesses) out += 2;
    out += 4 * CompactSizeLen.encode(this.inputs.length).length;
    for (const i of this.inputs) {
      out += 160 + 4 * VarBytes.encode(i.finalScriptSig || P.EMPTY).length;
      // Once segwit serialization is active, every input contributes one witness vector, including
      // legacy inputs whose empty vector still encodes as a single zero-item-count byte.
      if (this.hasWitnesses) out += RawWitness.encode(i.finalScriptWitness || []).length;
    }
    return out;
  }
  get vsize(): number {
    return toVsize(this.weight);
  }
  toBytes(withScriptSig = false, withWitness = false): Uint8Array {
    return RawTx.encode({
      version: this.version,
      lockTime: this.lockTime,
      inputs: this.inputs.map(inputBeforeSign).map((i) => ({
        ...i,
        finalScriptSig: (withScriptSig && i.finalScriptSig) || P.EMPTY,
      })),
      outputs: this.outputs.map(outputBeforeSign),
      witnesses: this.inputs.map((i) => i.finalScriptWitness || []),
      segwitFlag: withWitness && this.hasWitnesses,
    });
  }
  get unsignedTx(): Bytes {
    return this.toBytes(false, false);
  }
  get hex(): string {
    return hex.encode(this.toBytes(true, this.hasWitnesses));
  }

  get hash(): string {
    return hex.encode(u.sha256x2(this.toBytes(true)));
  }
  get id(): string {
    return hex.encode(u.sha256x2(this.toBytes(true)).reverse());
  }
  // Input stuff
  private checkInputIdx(idx: number) {
    if (!Number.isSafeInteger(idx) || 0 > idx || idx >= this.inputs.length)
      throw new Error(`Wrong input index=${idx}`);
  }
  getInput(idx: number): psbt.TransactionInput {
    this.checkInputIdx(idx);
    return cloneDeep(this.inputs[idx]) as psbt.TransactionInput;
  }
  get inputsLength(): number {
    return this.inputs.length;
  }
  // Modification
  addInput(input: TArg<psbt.TransactionInputUpdate>, _ignoreSignStatus = false): number {
    if (!_ignoreSignStatus && !this.signStatus().addInput)
      throw new Error('Tx has signed inputs, cannot add new one');
    // normalizeInput preserves nested caller-owned byte arrays, so detach them here before the
    // new input becomes transaction state and later caller mutation can rewrite it by aliasing.
    this.inputs.push(
      cloneDeep(
        normalizeInput(input, undefined, undefined, this.opts.disableScriptCheck)
      ) as PSBTInputs
    );
    return this.inputs.length - 1;
  }
  updateInput(
    idx: number,
    input: TArg<psbt.TransactionInputUpdate>,
    _ignoreSignStatus = false
  ): void {
    this.checkInputIdx(idx);
    let allowedFields = undefined;
    if (!_ignoreSignStatus) {
      const status = this.signStatus();
      if (!status.addInput || status.inputs.includes(idx))
        allowedFields = psbt.PSBTInputUnsignedKeys;
    }
    // normalizeInput preserves nested caller-owned byte arrays, so detach the merged result here
    // before the updated input becomes transaction state and later caller mutation can rewrite it.
    this.inputs[idx] = cloneDeep(
      normalizeInput(
        input,
        this.inputs[idx],
        allowedFields,
        this.opts.disableScriptCheck,
        this.opts.allowUnknown
      )
    ) as PSBTInputs;
  }
  // Output stuff
  private checkOutputIdx(idx: number) {
    if (!Number.isSafeInteger(idx) || 0 > idx || idx >= this.outputs.length)
      throw new Error(`Wrong output index=${idx}`);
  }
  getOutput(idx: number): psbt.TransactionOutput {
    this.checkOutputIdx(idx);
    return cloneDeep(this.outputs[idx]) as psbt.TransactionOutput;
  }
  getOutputAddress(idx: number, network: u.BTC_NETWORK = NETWORK): string | undefined {
    const out = this.getOutput(idx);
    if (!out.script) return;
    return Address(network).encode(
      OutScript.decode(out.script) as Parameters<ReturnType<typeof Address>['encode']>[0]
    );
  }

  get outputsLength(): number {
    return this.outputs.length;
  }
  private normalizeOutput(
    o: TArg<psbt.TransactionOutputUpdate>,
    cur?: PSBTOutputs,
    allowedFields?: readonly (keyof typeof psbt.PSBTOutput)[]
  ): PSBTOutputs {
    let { amount, script } = o;
    if (amount === undefined) amount = cur?.amount;
    if (typeof amount !== 'bigint')
      throw new Error(
        `Wrong amount type, should be of type bigint in sats, but got ${amount} of type ${typeof amount}`
      );
    if (typeof script === 'string') script = hex.decode(script);
    if (script === undefined) script = cur?.script;
    let res: PSBTOutputs = { ...cur, ...(o as PSBTOutputs & { script?: string }), amount, script };
    if (res.amount === undefined) delete res.amount;
    res = psbt.mergeKeyMap(psbt.PSBTOutput, res, cur, allowedFields, this.opts.allowUnknown);
    psbt.PSBTOutputCoder.encode(res as Parameters<typeof psbt.PSBTOutputCoder.encode>[0]);
    if (
      res.script &&
      !this.opts.allowUnknownOutputs &&
      OutScript.decode(res.script).type === 'unknown'
    ) {
      throw new Error(
        'Transaction/output: unknown output script type, there is a chance that input is unspendable. Pass allowUnknownOutputs=true, if you sure'
      );
    }
    if (!this.opts.disableScriptCheck) checkScript(res.script, res.redeemScript, res.witnessScript);
    return res;
  }
  addOutput(o: TArg<psbt.TransactionOutputUpdate>, _ignoreSignStatus = false): number {
    if (!_ignoreSignStatus && !this.signStatus().addOutput)
      throw new Error('Tx has signed outputs, cannot add new one');
    // normalizeOutput preserves nested caller-owned script bytes, so detach them here before the
    // new output becomes transaction state and later caller mutation can rewrite it by aliasing.
    this.outputs.push(cloneDeep(this.normalizeOutput(o)));
    return this.outputs.length - 1;
  }
  updateOutput(
    idx: number,
    output: TArg<psbt.TransactionOutputUpdate>,
    _ignoreSignStatus = false
  ): void {
    this.checkOutputIdx(idx);
    let allowedFields = undefined;
    if (!_ignoreSignStatus) {
      const status = this.signStatus();
      if (!status.addOutput || status.outputs.includes(idx))
        allowedFields = psbt.PSBTOutputUnsignedKeys;
    }
    // updateOutput replaces stored state with normalizeOutput(...) directly, so detach the result
    // before storing it or later caller mutation of `output.script` will rewrite transaction state.
    this.outputs[idx] = cloneDeep(this.normalizeOutput(output, this.outputs[idx], allowedFields));
  }
  addOutputAddress(address: string, amount: bigint, network: u.BTC_NETWORK = NETWORK): number {
    return this.addOutput({
      // Address.decode() only returns recognized descriptors here, but its wrapped output type
      // still carries `undefined` for coder parity, so narrow before feeding OutScript.encode().
      script: OutScript.encode(
        Address(network).decode(address) as Parameters<typeof OutScript.encode>[0]
      ),
      amount,
    });
  }
  // Utils
  get fee(): bigint {
    let res = 0n;
    for (const i of this.inputs) {
      const prevOut = getPrevOut(i);
      if (!prevOut) throw new Error('Empty input amount');
      res += prevOut.amount;
    }
    const outputs = this.outputs.map(outputBeforeSign);
    for (const o of outputs) res -= o.amount;
    return res;
  }

  // Signing
  // Based on https://github.com/bitcoin/bitcoin/blob/5871b5b5ab57a0caf9b7514eb162c491c83281d5/test/functional/test_framework/script.py#L624
  // There is optimization opportunity to re-use hashes for multiple inputs for witness v0/v1,
  // but we are trying to be less complicated for audit purpose for now.
  private preimageLegacy(idx: number, prevOutScript: Bytes, hashType: number) {
    const { isAny, isNone, isSingle } = unpackSighash(hashType);
    if (idx < 0 || !Number.isSafeInteger(idx)) throw new Error(`Invalid input idx=${idx}`);
    if ((isSingle && idx >= this.outputs.length) || idx >= this.inputs.length)
      return P.U256BE.encode(1n);
    prevOutScript = stripCodeSeparator(prevOutScript);
    let inputs: TransactionInputRequired[] = this.inputs
      .map(inputBeforeSign)
      .map((input, inputIdx) => ({
        ...input,
        finalScriptSig: inputIdx === idx ? prevOutScript : P.EMPTY,
      }));
    if (isAny) inputs = [inputs[idx]];
    else if (isNone || isSingle) {
      inputs = inputs.map((input, inputIdx) => ({
        ...input,
        sequence: inputIdx === idx ? input.sequence : 0,
      }));
    }
    let outputs = this.outputs.map(outputBeforeSign);
    if (isNone) outputs = [];
    else if (isSingle) {
      outputs = outputs
        .slice(0, idx)
        .fill(EMPTY_OUTPUT as (typeof outputs)[number])
        .concat([outputs[idx]]);
    }
    const tmpTx = RawTx.encode({
      lockTime: this.lockTime,
      version: this.version,
      segwitFlag: false,
      inputs,
      outputs,
    });
    return u.sha256x2(tmpTx, P.I32LE.encode(hashType));
  }
  preimageWitnessV0(
    idx: number,
    prevOutScript: Bytes,
    hashType: number,
    amount: bigint
  ): Uint8Array {
    // BIP143 serializes txTo.vin[nIn].prevout and txTo.vin[nIn].nSequence, so reject an invalid
    // nIn explicitly instead of leaking a later undefined-input TypeError from inputs[idx].
    if (idx < 0 || !Number.isSafeInteger(idx) || idx >= this.inputs.length)
      throw new Error(`Invalid input idx=${idx}`);
    const { isAny, isNone, isSingle } = unpackSighash(hashType);
    let inputHash = EMPTY32;
    let sequenceHash = EMPTY32;
    let outputHash = EMPTY32;
    const inputs = this.inputs.map(inputBeforeSign);
    const outputs = this.outputs.map(outputBeforeSign);
    if (!isAny) inputHash = u.sha256x2(...inputs.map(TxHashIdx.encode));
    if (!isAny && !isSingle && !isNone)
      sequenceHash = u.sha256x2(...inputs.map((i) => P.U32LE.encode(i.sequence)));
    if (!isSingle && !isNone) {
      outputHash = u.sha256x2(...outputs.map(RawOutput.encode));
    } else if (isSingle && idx < outputs.length)
      outputHash = u.sha256x2(RawOutput.encode(outputs[idx]));
    const input = inputs[idx];
    return u.sha256x2(
      P.I32LE.encode(this.version),
      inputHash,
      sequenceHash,
      P.bytes(32, true).encode(input.txid),
      P.U32LE.encode(input.index),
      VarBytes.encode(prevOutScript),
      P.U64LE.encode(amount),
      P.U32LE.encode(input.sequence),
      outputHash,
      P.U32LE.encode(this.lockTime),
      P.U32LE.encode(hashType)
    );
  }
  preimageWitnessV1(
    idx: number,
    prevOutScript: Bytes[],
    hashType: number,
    amount: bigint[],
    codeSeparator = -1,
    leafScript?: Bytes,
    leafVer = 0xc0,
    annex?: Bytes
  ): Uint8Array {
    if (!Array.isArray(amount) || this.inputs.length !== amount.length)
      throw new Error(`Invalid amounts array=${amount}`);
    if (!Array.isArray(prevOutScript) || this.inputs.length !== prevOutScript.length)
      throw new Error(`Invalid prevOutScript array=${prevOutScript}`);
    // BIP341 SigMsg commits either to input_index or to the selected input's outpoint/amount/script/
    // sequence under ANYONECANPAY, so reject an invalid index explicitly instead of hashing a
    // nonexistent input or leaking a later integer-encoding RangeError for negative idx.
    if (idx < 0 || !Number.isSafeInteger(idx) || idx >= this.inputs.length)
      throw new Error(`Invalid input idx=${idx}`);
    const out: Bytes[] = [
      P.U8.encode(0),
      P.U8.encode(hashType), // U8 sigHash
      P.I32LE.encode(this.version),
      P.U32LE.encode(this.lockTime),
    ];
    const outType = hashType === SignatureHash.DEFAULT ? SignatureHash.ALL : hashType & 0b11;
    const inType = hashType & SignatureHash.ANYONECANPAY;
    const inputs = this.inputs.map(inputBeforeSign);
    const outputs = this.outputs.map(outputBeforeSign);
    if (inType !== SignatureHash.ANYONECANPAY) {
      out.push(
        ...[
          inputs.map(TxHashIdx.encode),
          amount.map(P.U64LE.encode),
          prevOutScript.map(VarBytes.encode),
          inputs.map((i) => P.U32LE.encode(i.sequence)),
        ].map((i) => u.sha256(concatBytes(...i)))
      );
    }
    if (outType === SignatureHash.ALL) {
      out.push(u.sha256(concatBytes(...outputs.map(RawOutput.encode))));
    }
    const spendType = (annex ? 1 : 0) | (leafScript ? 2 : 0);
    out.push(new Uint8Array([spendType]));
    if (inType === SignatureHash.ANYONECANPAY) {
      const inp = inputs[idx];
      out.push(
        TxHashIdx.encode(inp),
        P.U64LE.encode(amount[idx]),
        VarBytes.encode(prevOutScript[idx]),
        P.U32LE.encode(inp.sequence)
      );
    } else out.push(P.U32LE.encode(idx));
    if (spendType & 1) out.push(u.sha256(VarBytes.encode(annex || P.EMPTY)));
    if (outType === SignatureHash.SINGLE)
      out.push(idx < outputs.length ? u.sha256(RawOutput.encode(outputs[idx])) : EMPTY32);
    if (leafScript)
      out.push(tapLeafHash(leafScript, leafVer), P.U8.encode(0), P.I32LE.encode(codeSeparator));
    return u.tagSchnorr('TapSighash', ...out);
  }
  // Signer can be privateKey OR instance of bip32 HD stuff
  signIdx(privateKey: Signer, idx: number, allowedSighash?: SigHash[], _auxRand?: Bytes): boolean {
    this.checkInputIdx(idx);
    const input = this.inputs[idx];
    const inputType = getInputType(
      input as TArg<psbt.TransactionInput>,
      this.opts.allowLegacyWitnessUtxo
    );
    const canSign = (privateKey: Bytes): boolean => {
      if (inputType.txType === 'taproot') {
        const pubKey = u.pubSchnorr(privateKey);
        if (input.tapInternalKey && equalBytes(pubKey, input.tapInternalKey)) return true;
        if (!input.tapLeafScript) return false;
        for (const [_, leaf] of input.tapLeafScript) {
          for (const op of Script.decode(leaf.subarray(0, -1))) {
            if (isBytes(op) && equalBytes(op, pubKey)) return true;
          }
        }
        return false;
      }
      const pubKey = u.pubECDSA(privateKey);
      const pubKeyHash = u.hash160(pubKey);
      for (const op of Script.decode(inputType.lastScript)) {
        if (isBytes(op) && (equalBytes(op, pubKey) || equalBytes(op, pubKeyHash))) return true;
      }
      return false;
    };
    // Expected invariant: HD signing should use bip32Derivation for legacy/segwit inputs,
    // tapBip32Derivation for taproot inputs, and preserve caller sighash/auxRand constraints.
    if (!isBytes(privateKey)) {
      const root = privateKey as HDKey;
      type DerRow = { pubKey: Bytes; fingerprint: number; path: readonly number[] };
      const deriveSigners = (
        label: string,
        rows: DerRow[] | undefined,
        pubKey: (signer: HDKey) => Bytes
      ): HDKey[] => {
        if (!rows || !rows.length) throw new Error(`${label}: empty`);
        const signers = rows
          .filter((row) => row.fingerprint == root.fingerprint)
          .map((row) => {
            let s = root;
            for (const i of row.path) s = s.deriveChild(i);
            if (!equalBytes(pubKey(s), row.pubKey)) throw new Error(`${label}: wrong pubKey`);
            if (!s.privateKey) throw new Error(`${label}: no privateKey`);
            return s;
          });
        if (!signers.length)
          throw new Error(`${label}: no items with fingerprint=${root.fingerprint}`);
        return signers;
      };
      const signers =
        inputType.txType === 'taproot'
          ? // BIP371 PSBT_IN_TAP_BIP32_DERIVATION stores x-only pubkeys plus `der`, so taproot HD
            // signing must derive against that map instead of legacy bip32Derivation.
            deriveSigners(
              'tapBip32Derivation',
              input.tapBip32Derivation?.map(([pubKey, { der }]) => ({
                pubKey,
                fingerprint: der.fingerprint,
                path: der.path,
              })),
              (s) => s.publicKey.slice(1)
            )
          : deriveSigners(
              'bip32Derivation',
              input.bip32Derivation?.map(([pubKey, der]) => ({
                pubKey,
                fingerprint: der.fingerprint,
                path: der.path,
              })),
              (s) => s.publicKey
            );
      let signed = false;
      for (const s of signers) {
        // PSBT may legitimately carry multiple same-fingerprint derivation entries (multisig or
        // taproot internal/script-path keys). Skip unrelated derived children instead of aborting
        // the whole HD signing attempt on the first non-applicable candidate.
        if (!canSign(s.privateKey)) continue;
        if (this.signIdx(s.privateKey, idx, allowedSighash, _auxRand)) signed = true;
      }
      if (signed) return true;
      if (inputType.txType === 'taproot') throw new Error('No taproot scripts signed');
      throw new Error(`Input script doesn't have pubKey: ${inputType.lastScript}`);
    }
    // Sighash checks
    // Just for compat with bitcoinjs-lib, so users won't face unexpected behaviour.
    if (!allowedSighash) allowedSighash = [inputType.defaultSighash as unknown as SigHash];
    else allowedSighash.forEach(validateSigHash);
    const sighash = inputType.sighash;
    if (!allowedSighash.includes(sighash)) {
      throw new Error(
        `Input with not allowed sigHash=${sighash}. Allowed: ${allowedSighash.join(', ')}`
      );
    }
    // It is possible to sign these inputs for legacy/segwit v0 (but no taproot!),
    // however this was because of bug in bitcoin-core, which remains here because of consensus.
    // If this is absolutely neccessary for your case, please open issue.
    // We disable it to avoid complicated workflow where SINGLE will block adding new outputs
    const { sigOutputs } = this.inputSighash(idx);
    if (sigOutputs === SignatureHash.SINGLE && idx >= this.outputs.length) {
      throw new Error(
        `Input with sighash SINGLE, but there is no output with corresponding index=${idx}`
      );
    }

    // Actual signing
    // Taproot
    const prevOut = getPrevOut(input);
    if (inputType.txType === 'taproot') {
      const prevOuts = this.inputs.map(getPrevOut);
      const prevOutScript = prevOuts.map((i) => i.script);
      const amount = prevOuts.map((i) => i.amount);
      let signed = false;
      let schnorrPub = u.pubSchnorr(privateKey);
      let merkleRoot = input.tapMerkleRoot || P.EMPTY;
      if (input.tapInternalKey) {
        // internal + tweak = tweaked key
        // if internal key == current public key, we need to tweak private key,
        // otherwise sign as is. bitcoinjs implementation always wants tweaked
        // priv key to be provided
        const { pubKey, privKey } = getTaprootKeys(
          privateKey,
          schnorrPub,
          input.tapInternalKey,
          merkleRoot
        );
        const [taprootPubKey, _] = u.taprootTweakPubkey(input.tapInternalKey, merkleRoot);
        if (equalBytes(taprootPubKey, pubKey)) {
          const hash = this.preimageWitnessV1(idx, prevOutScript, sighash, amount);
          const sig = concatBytes(
            u.signSchnorr(hash, privKey, _auxRand),
            sighash !== SignatureHash.DEFAULT ? new Uint8Array([sighash]) : P.EMPTY
          );
          this.updateInput(idx, { tapKeySig: sig }, true);
          signed = true;
        }
      }
      if (input.tapLeafScript) {
        input.tapScriptSig = input.tapScriptSig || [];
        for (const [_, _script] of input.tapLeafScript) {
          const script = _script.subarray(0, -1);
          const scriptDecoded = Script.decode(script);
          const ver = _script[_script.length - 1];
          const hash = tapLeafHash(script, ver);
          // NOTE: no need to tweak internal key here, since we don't support nested p2tr
          const pos = scriptDecoded.findIndex((i) => isBytes(i) && equalBytes(i, schnorrPub));
          // Skip if there is no public key in tapLeafScript
          if (pos === -1) continue;
          const msg = this.preimageWitnessV1(
            idx,
            prevOutScript,
            sighash,
            amount,
            undefined,
            script,
            ver
          );
          const sig = concatBytes(
            u.signSchnorr(msg, privateKey, _auxRand),
            sighash !== SignatureHash.DEFAULT ? new Uint8Array([sighash]) : P.EMPTY
          );
          this.updateInput(
            idx,
            { tapScriptSig: [[{ pubKey: schnorrPub, leafHash: hash }, sig]] },
            true
          );
          signed = true;
        }
      }
      if (!signed) throw new Error('No taproot scripts signed');
      return true;
    } else {
      // only compressed keys are supported for now
      const pubKey = u.pubECDSA(privateKey);
      // TODO: replace with explicit checks
      // Check if script has public key or its has inside
      let hasPubkey = false;
      const pubKeyHash = u.hash160(pubKey);
      for (const i of Script.decode(inputType.lastScript)) {
        if (isBytes(i) && (equalBytes(i, pubKey) || equalBytes(i, pubKeyHash))) hasPubkey = true;
      }
      if (!hasPubkey) throw new Error(`Input script doesn't have pubKey: ${inputType.lastScript}`);
      let hash;
      if (inputType.txType === 'legacy') {
        hash = this.preimageLegacy(idx, inputType.lastScript, sighash);
      } else if (inputType.txType === 'segwit') {
        let script = inputType.lastScript;
        // If wpkh OR sh-wpkh, wsh-wpkh is impossible, so looks ok
        if (inputType.last.type === 'wpkh')
          script = OutScript.encode({ type: 'pkh', hash: inputType.last.hash });
        hash = this.preimageWitnessV0(idx, script, sighash, prevOut.amount);
      } else throw new Error(`Transaction/sign: unknown tx type: ${inputType.txType}`);
      const sig = u.signECDSA(hash, privateKey, this.opts.lowR);
      this.updateInput(
        idx,
        {
          partialSig: [[pubKey, concatBytes(sig, new Uint8Array([sighash]))]],
        },
        true
      );
    }
    return true;
  }
  // This is bad API. Will work if user creates and signs tx, but if
  // there is some complex workflow with exchanging PSBT and signing them,
  // then it is better to validate which output user signs. How could a better API look like?
  // Example: user adds input, sends to another party, then signs received input (mixer etc),
  // another user can add different input for same key and user will sign it.
  // Even worse: another user can add bip32 derivation, and spend money from different address.
  // Better api: signIdx
  sign(privateKey: Signer, allowedSighash?: number[], _auxRand?: Bytes): number {
    let num = 0;
    for (let i = 0; i < this.inputs.length; i++) {
      try {
        if (this.signIdx(privateKey, i, allowedSighash, _auxRand)) num++;
      } catch (e) {}
    }
    if (!num) throw new Error('No inputs signed');
    return num;
  }

  finalizeIdx(idx: number): void {
    this.checkInputIdx(idx);
    if (this.fee < 0n) throw new Error('Outputs spends more than inputs amount');
    const input = this.inputs[idx];
    const inputType = getInputType(input, this.opts.allowLegacyWitnessUtxo);
    // Taproot finalize
    if (inputType.txType === 'taproot') {
      if (input.tapKeySig) input.finalScriptWitness = [input.tapKeySig];
      else if (input.tapLeafScript && input.tapScriptSig) {
        // Sort leafs by control block length.
        const leafs = input.tapLeafScript.sort(
          (a, b) =>
            psbt.TaprootControlBlock.encode(a[0]).length -
            psbt.TaprootControlBlock.encode(b[0]).length
        );
        for (const [cb, _script] of leafs) {
          // Last byte is version
          const script = _script.slice(0, -1);
          const ver = _script[_script.length - 1];
          const outScript = OutScript.decode(script);
          const hash = tapLeafHash(script, ver);
          const scriptSig = input.tapScriptSig.filter((i) => equalBytes(i[0].leafHash, hash));
          let signatures: Bytes[] = [];
          if (outScript.type === 'tr_ms') {
            const m = outScript.m;
            const pubkeys = outScript.pubkeys;
            let added = 0;
            for (const pub of pubkeys) {
              const sigIdx = scriptSig.findIndex((i) => equalBytes(i[0].pubKey, pub));
              // Should have exact amount of signatures (more -- will fail)
              if (added === m || sigIdx === -1) {
                signatures.push(P.EMPTY);
                continue;
              }
              signatures.push(scriptSig[sigIdx][1]);
              added++;
            }
            // Should be exact same as m
            if (added !== m) continue;
          } else if (outScript.type === 'tr_ns') {
            for (const pub of outScript.pubkeys) {
              const sigIdx = scriptSig.findIndex((i) => equalBytes(i[0].pubKey, pub));
              if (sigIdx === -1) continue;
              signatures.push(scriptSig[sigIdx][1]);
            }
            if (signatures.length !== outScript.pubkeys.length) continue;
          } else if (outScript.type === 'unknown' && this.opts.allowUnknownInputs) {
            // Trying our best to sign what we can
            const scriptDecoded = Script.decode(script);
            signatures = scriptSig
              .map(([{ pubKey }, signature]) => {
                const pos = scriptDecoded.findIndex((i) => isBytes(i) && equalBytes(i, pubKey));
                if (pos === -1)
                  throw new Error('finalize/taproot: cannot find position of pubkey in script');
                return { signature, pos };
              })
              // Reverse order (because witness is stack and we take last element first from it)
              .sort((a, b) => a.pos - b.pos)
              .map((i) => i.signature);
            if (!signatures.length) continue;
          } else {
            const custom = this.opts.customScripts;
            if (custom) {
              for (const c of custom) {
                if (!c.finalizeTaproot) continue;
                const scriptDecoded = Script.decode(script);
                const csEncoded = c.encode(scriptDecoded);
                if (csEncoded === undefined) continue;
                const finalized = c.finalizeTaproot(script, csEncoded, scriptSig);
                if (!finalized) continue;
                input.finalScriptWitness = finalized.concat(psbt.TaprootControlBlock.encode(cb));
                delete input.finalScriptSig;
                cleanFinalInput(input as TArg<PSBTInputs>);
                return;
              }
            }
            throw new Error('Finalize: Unknown tapLeafScript');
          }
          // Witness is stack, so last element will be used first
          input.finalScriptWitness = signatures
            .reverse()
            .concat([script, psbt.TaprootControlBlock.encode(cb)]);
          break;
        }
        if (!input.finalScriptWitness) throw new Error('finalize/taproot: empty witness');
      } else throw new Error('finalize/taproot: unknown input');
      // BIP174 Input Finalizer: if scriptSig is empty for an input, 0x07 remains unset.
      delete input.finalScriptSig;
      cleanFinalInput(input as TArg<PSBTInputs>);
      return;
    }
    if (!input.partialSig || !input.partialSig.length) throw new Error('Not enough partial sign');

    let inputScript: Bytes = P.EMPTY;
    let witness: Bytes[] = [];
    // TODO: move input scripts closer to payments/output scripts
    // Multisig
    if (inputType.last.type === 'ms') {
      const m = inputType.last.m;
      const pubkeys = inputType.last.pubkeys;
      let signatures = [];
      // partial: [pubkey, sign]
      for (const pub of pubkeys) {
        const sign = input.partialSig.find((s) => equalBytes(pub, s[0]));
        if (!sign) continue;
        signatures.push(sign[1]);
      }
      signatures = signatures.slice(0, m);
      if (signatures.length !== m) {
        throw new Error(
          `Multisig: wrong signatures count, m=${m} n=${pubkeys.length} signatures=${signatures.length}`
        );
      }
      inputScript = Script.encode([0, ...signatures]);
    } else if (inputType.last.type === 'pk') {
      inputScript = Script.encode([input.partialSig[0][1]]);
    } else if (inputType.last.type === 'pkh') {
      inputScript = Script.encode([input.partialSig[0][1], input.partialSig[0][0]]);
    } else if (inputType.last.type === 'wpkh') {
      inputScript = P.EMPTY;
      witness = [input.partialSig[0][1], input.partialSig[0][0]];
    } else if (inputType.last.type === 'unknown' && !this.opts.allowUnknownInputs)
      throw new Error('Unknown inputs not allowed');

    // Create final scripts (generic part)
    let finalScriptSig: Bytes | undefined, finalScriptWitness: Bytes[] | undefined;
    if (inputType.type.includes('wsh-')) {
      // P2WSH
      if (inputScript.length && inputType.lastScript.length) {
        witness = Script.decode(inputScript).map((i) => {
          if (i === 0) return P.EMPTY;
          if (isBytes(i)) return i;
          throw new Error(`Wrong witness op=${i}`);
        });
      }
      witness = witness.concat(inputType.lastScript);
    }
    if (inputType.txType === 'segwit') finalScriptWitness = witness;
    if (inputType.type.startsWith('sh-wsh-')) {
      finalScriptSig = Script.encode([Script.encode([0, u.sha256(inputType.lastScript)])]);
    } else if (inputType.type.startsWith('sh-')) {
      finalScriptSig = Script.encode([...Script.decode(inputScript), inputType.lastScript]);
    } else if (inputType.type.startsWith('wsh-')) {
    } else if (inputType.txType !== 'segwit') finalScriptSig = inputScript;

    if (!finalScriptSig && !finalScriptWitness) throw new Error('Unknown error finalizing input');
    if (finalScriptSig) input.finalScriptSig = finalScriptSig;
    if (finalScriptWitness) input.finalScriptWitness = finalScriptWitness;
    cleanFinalInput(input as TArg<PSBTInputs>);
  }
  finalize(): void {
    for (let i = 0; i < this.inputs.length; i++) this.finalizeIdx(i);
  }
  extract(): Uint8Array {
    if (!this.isFinal) throw new Error('Transaction has unfinalized inputs');
    if (!this.outputs.length) throw new Error('Transaction has no outputs');
    if (this.fee < 0n) throw new Error('Outputs spends more than inputs amount');
    return this.toBytes(true, true);
  }
  combine(other: Transaction): this {
    // BIP174 combiners merge same-transaction PSBTs across versions and emit the highest required
    // version, so PSBTVersion mismatches are normalized below instead of treated as conflicts.
    const PSBTVersion = Math.max(this.opts.PSBTVersion || 0, other.opts.PSBTVersion || 0);
    for (const k of ['version', 'lockTime'] as const) {
      if (this.opts[k] !== other.opts[k]) {
        throw new Error(
          `Transaction/combine: different ${k} this=${this.opts[k]} other=${other.opts[k]}`
        );
      }
    }
    for (const k of ['inputs', 'outputs'] as const) {
      if (this[k].length !== other[k].length) {
        throw new Error(
          `Transaction/combine: different ${k} length this=${this[k].length} other=${other[k].length}`
        );
      }
    }
    // Same-transaction checks must compare the normalized unsigned tx bytes here: PSBTv0 stores
    // `global.unsignedTx`, while PSBTv2 reconstructs the same transaction from split fields.
    if (!equalBytes(this.unsignedTx, other.unsignedTx))
      throw new Error(`Transaction/combine: different unsigned tx`);
    this.global = psbt.mergeKeyMap(
      psbt.PSBTGlobal,
      this.global,
      other.global,
      undefined,
      this.opts.allowUnknown
    );
    if (PSBTVersion) this.global.version = PSBTVersion;
    for (let i = 0; i < this.inputs.length; i++) this.updateInput(i, other.inputs[i], true);
    for (let i = 0; i < this.outputs.length; i++) this.updateOutput(i, other.outputs[i], true);
    return this;
  }
  clone(): Transaction {
    // deepClone probably faster, but this enforces that encoding is valid
    return Transaction.fromPSBT(this.toPSBT(), this.opts);
  }
}

/**
 * Merges multiple PSBT blobs into one.
 * @param psbts - PSBT byte arrays to combine
 * @returns Combined PSBT bytes.
 * @throws If the PSBT list is empty or the partial transactions cannot be combined. {@link Error}
 * @example
 * Merge separate partially signed PSBTs that share the same unsigned transaction.
 * ```ts
 * import { PSBTCombine, Transaction } from '@scure/btc-signer/transaction.js';
 * const psbt = new Transaction().toPSBT();
 * PSBTCombine([psbt, psbt]);
 * ```
 */
export function PSBTCombine(psbts: TArg<Bytes[]>): TRet<Bytes> {
  if (!psbts || !Array.isArray(psbts) || !psbts.length)
    throw new Error('PSBTCombine: wrong PSBT list');
  const tx = Transaction.fromPSBT(psbts[0]);
  for (let i = 1; i < psbts.length; i++) tx.combine(Transaction.fromPSBT(psbts[i]));
  return tx.toPSBT() as TRet<Bytes>;
}

// Copy-pasted from bip32 derive, maybe do something like 'bip32.parsePath'?
const HARDENED_OFFSET: number = 0x80000000;
/**
 * Parses a BIP32 path string into child indices.
 * @param path - derivation path such as `m/0'/1`
 * @returns Array of encoded child indices.
 * @throws If the derivation path syntax or child indices are invalid. {@link Error}
 * @example
 * Parse a BIP32 derivation path into hardened and unhardened indices.
 * ```ts
 * bip32Path("m/0'/1");
 * ```
 */
export function bip32Path(path: string): number[] {
  const out: number[] = [];
  // PSBT key-origin records only carry raw child indices, so this convenience
  // parser normalizes textual BIP32 roots into the same integer path array and
  // uses apostrophe suffixes for hardening.
  if (!/^[mM]'?/.test(path)) throw new Error('Path must start with "m" or "M"');
  if (/^[mM]'?$/.test(path)) return out;
  const parts = path.replace(/^[mM]'?\//, '').split('/');
  // BIP32 Serialization format `* 1 byte: depth`: extended keys cap depth at
  // 255, so deeper text paths cannot roundtrip.
  if (parts.length > 255) throw new Error('Path depth exceeds 255');
  for (const c of parts) {
    const m = /^(\d+)('?)$/.exec(c);
    if (!m || m.length !== 3) throw new Error(`Invalid child index: ${c}`);
    let idx = +m[1];
    if (!Number.isSafeInteger(idx) || idx >= HARDENED_OFFSET) throw new Error('Invalid index');
    // hardened key
    if (m[2] === "'") idx += HARDENED_OFFSET;
    out.push(idx);
  }
  return out;
}

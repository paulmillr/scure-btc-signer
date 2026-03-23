import * as P from 'micro-packed';
import { isBytes, reverseObject, type ValueOf, type Bytes } from './utils.ts';

/** Maximum byte size allowed for a single pushed script element. */
export const MAX_SCRIPT_BYTE_LENGTH = 520;

// prettier-ignore
/**
 * Bitcoin Script opcode table.
 * @example
 * Use opcode numbers when you need the raw byte form instead of Script mnemonics.
 * ```ts
 * import { OP } from '@scure/btc-signer/script.js';
 * new Uint8Array([OP.OP_1, OP.OP_2, OP.CHECKMULTISIG]);
 * ```
 */
export const OP = {
  OP_0: 0, PUSHDATA1: 76, PUSHDATA2: 77, PUSHDATA4: 78, '1NEGATE': 79,
  RESERVED: 80,
  OP_1: 81, OP_2: 82, OP_3: 83, OP_4: 84, OP_5: 85, OP_6: 86, OP_7: 87, OP_8: 88, OP_9: 89,
  OP_10: 90, OP_11: 91, OP_12: 92, OP_13: 93, OP_14: 94, OP_15: 95, OP_16: 96,
  // Control
  NOP: 97, VER: 98, IF: 99, NOTIF: 100, VERIF: 101, VERNOTIF: 102, ELSE: 103, ENDIF: 104, VERIFY: 105, RETURN: 106,
  // Stack
  TOALTSTACK: 107, FROMALTSTACK: 108, '2DROP': 109, '2DUP': 110, '3DUP': 111, '2OVER': 112, '2ROT': 113, '2SWAP': 114,
  IFDUP: 115, DEPTH: 116, DROP: 117, DUP: 118, NIP: 119, OVER: 120, PICK: 121, ROLL: 122, ROT: 123, SWAP: 124, TUCK: 125,
  // Splice
  CAT: 126, SUBSTR: 127, LEFT: 128, RIGHT: 129, SIZE: 130,
  // Boolean logic
  INVERT: 131, AND: 132, OR: 133, XOR: 134, EQUAL: 135, EQUALVERIFY: 136, RESERVED1: 137, RESERVED2: 138,
    // Numbers
  '1ADD': 139, '1SUB': 140, '2MUL': 141, '2DIV': 142,
  NEGATE: 143, ABS: 144, NOT: 145, '0NOTEQUAL': 146,
  ADD: 147, SUB: 148, MUL: 149, DIV: 150, MOD: 151, LSHIFT: 152, RSHIFT: 153, BOOLAND: 154, BOOLOR: 155,
  NUMEQUAL: 156, NUMEQUALVERIFY: 157, NUMNOTEQUAL: 158, LESSTHAN: 159, GREATERTHAN: 160,
  LESSTHANOREQUAL: 161, GREATERTHANOREQUAL: 162, MIN: 163, MAX: 164, WITHIN: 165,
  // Crypto
  RIPEMD160: 166, SHA1: 167, SHA256: 168, HASH160: 169, HASH256: 170, CODESEPARATOR: 171,
  CHECKSIG: 172, CHECKSIGVERIFY: 173, CHECKMULTISIG: 174, CHECKMULTISIGVERIFY: 175,
  // Expansion
  NOP1: 176, CHECKLOCKTIMEVERIFY: 177, CHECKSEQUENCEVERIFY: 178, NOP4: 179, NOP5: 180, NOP6: 181, NOP7: 182, NOP8: 183, NOP9: 184, NOP10: 185,
  // BIP 342
  CHECKSIGADD: 186,
  // Invalid
  INVALID: 255,
};

/**
 * Reverse lookup map from opcode numbers back to names.
 * @example
 * Turn parsed opcode numbers back into their mnemonic names.
 * ```ts
 * import { OP, OPNames } from '@scure/btc-signer/script.js';
 * OPNames[OP.CHECKSIG];
 * ```
 */
export const OPNames = /* @__PURE__ */ (() => reverseObject(OP))();
/** Numeric opcode value from {@link OP}. */
export type OP = ValueOf<typeof OP>;

/** Single script element accepted by the script encoder. */
export type ScriptOP = keyof typeof OP | Uint8Array | number;
/** Parsed Bitcoin script as a list of script elements. */
export type ScriptType = ScriptOP[];

// We can encode almost any number as ScriptNum, however, parsing will be a problem
// since we can't know if buffer is a number or something else.
/**
 * Coder for Bitcoin Script numbers.
 * @param bytesLimit - maximum encoded length in bytes
 * @param forceMinimal - whether to reject non-minimal encodings
 * @returns Script number coder.
 * @example
 * Encode a small integer using Script number rules.
 * ```ts
 * ScriptNum().encode(1n);
 * ```
 */
export function ScriptNum(bytesLimit = 6, forceMinimal = false): P.CoderType<bigint> {
  return P.wrap({
    encodeStream: (w: P.Writer, value: bigint) => {
      if (value === 0n) return;
      const neg = value < 0;
      const val = BigInt(value);
      const nums = [];
      for (let abs = neg ? -val : val; abs; abs >>= 8n) nums.push(Number(abs & 0xffn));
      if (nums[nums.length - 1] >= 0x80) nums.push(neg ? 0x80 : 0);
      else if (neg) nums[nums.length - 1] |= 0x80;
      w.bytes(new Uint8Array(nums));
    },
    decodeStream: (r: P.Reader): bigint => {
      const len = r.leftBytes;
      if (len > bytesLimit)
        throw new Error(`ScriptNum: number (${len}) bigger than limit=${bytesLimit}`);
      if (len === 0) return 0n;
      if (forceMinimal) {
        const data = r.bytes(len, true);
        // MSB is zero (without sign bit) -> not minimally encoded
        if ((data[data.length - 1] & 0x7f) === 0) {
          // exception
          if (len <= 1 || (data[data.length - 2] & 0x80) === 0)
            throw new Error('Non-minimally encoded ScriptNum');
        }
      }
      let last = 0;
      let res = 0n;
      for (let i = 0; i < len; ++i) {
        last = r.byte();
        res |= BigInt(last) << (8n * BigInt(i));
      }
      if (last >= 0x80) {
        res &= (2n ** BigInt(len * 8) - 1n) >> 1n;
        res = -res;
      }
      return res;
    },
  });
}

/**
 * Attempts to decode a script element into a JavaScript number.
 * @param op - script element to decode
 * @param bytesLimit - maximum encoded length in bytes
 * @param forceMinimal - whether to enforce minimal number encoding
 * @returns Decoded number, or `undefined` when the element is not a valid small number.
 * @example
 * Decode a script element back into a JavaScript number when possible.
 * ```ts
 * OpToNum(1);
 * ```
 */
export function OpToNum(op: ScriptOP, bytesLimit = 4, forceMinimal = true): number | undefined {
  if (typeof op === 'number') return op;
  if (isBytes(op)) {
    try {
      const val = ScriptNum(bytesLimit, forceMinimal).decode(op);
      if (val > Number.MAX_SAFE_INTEGER) return;
      return Number(val);
    } catch (e) {
      return;
    }
  }
  return;
}

// Converts script bytes to parsed script
// 5221030000000000000000000000000000000000000000000000000000000000000001210300000000000000000000000000000000000000000000000000000000000000022103000000000000000000000000000000000000000000000000000000000000000353ae
// =>
// OP_2
//   030000000000000000000000000000000000000000000000000000000000000001
//   030000000000000000000000000000000000000000000000000000000000000002
//   030000000000000000000000000000000000000000000000000000000000000003
//   OP_3
//   CHECKMULTISIG
/**
 * Bitcoin script coder.
 * @example
 * Encode a short script from opcode mnemonics and small integers.
 * ```ts
 * Script.encode(['OP_1', 'OP_2']);
 * ```
 */
export const Script: P.CoderType<ScriptType> = /* @__PURE__ */ (() =>
  P.wrap({
    encodeStream: (w: P.Writer, value: ScriptType) => {
      for (let o of value) {
        if (typeof o === 'string') {
          if (OP[o] === undefined) throw new Error(`Unknown opcode=${o}`);
          w.byte(OP[o]);
          continue;
        } else if (typeof o === 'number') {
          if (o === 0x00) {
            w.byte(0x00);
            continue;
          } else if (1 <= o && o <= 16) {
            w.byte(OP.OP_1 - 1 + o);
            continue;
          }
        }
        // Encode big numbers
        if (typeof o === 'number') o = ScriptNum().encode(BigInt(o));
        if (!isBytes(o)) throw new Error(`Wrong Script OP=${o} (${typeof o})`);
        // Bytes
        const len = o.length;
        if (len < OP.PUSHDATA1) w.byte(len);
        else if (len <= 0xff) {
          w.byte(OP.PUSHDATA1);
          w.byte(len);
        } else if (len <= 0xffff) {
          w.byte(OP.PUSHDATA2);
          w.bytes(P.U16LE.encode(len));
        } else {
          w.byte(OP.PUSHDATA4);
          w.bytes(P.U32LE.encode(len));
        }
        w.bytes(o);
      }
    },
    decodeStream: (r: P.Reader): ScriptType => {
      const out: ScriptType = [];
      while (!r.isEnd()) {
        const cur = r.byte();
        // if 0 < cur < 78
        if (OP.OP_0 < cur && cur <= OP.PUSHDATA4) {
          let len;
          if (cur < OP.PUSHDATA1) len = cur;
          else if (cur === OP.PUSHDATA1) len = P.U8.decodeStream(r);
          else if (cur === OP.PUSHDATA2) len = P.U16LE.decodeStream(r);
          else if (cur === OP.PUSHDATA4) len = P.U32LE.decodeStream(r);
          else throw new Error('Should be not possible');
          out.push(r.bytes(len));
        } else if (cur === 0x00) {
          out.push(0);
        } else if (OP.OP_1 <= cur && cur <= OP.OP_16) {
          out.push(cur - (OP.OP_1 - 1));
        } else {
          const op = OPNames[cur] as keyof typeof OP;
          if (op === undefined) throw new Error(`Unknown opcode=${cur.toString(16)}`);
          out.push(op);
        }
      }
      return out;
    },
  }))();

// BTC specific variable length integer encoding
// https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
const CSLimits: Record<number, [number, number, bigint, bigint]> = {
  0xfd: [0xfd, 2, 253n, 65535n],
  0xfe: [0xfe, 4, 65536n, 4294967295n],
  0xff: [0xff, 8, 4294967296n, 18446744073709551615n],
};
/**
 * Bitcoin CompactSize integer coder.
 * @example
 * Encode a CompactSize integer for wire serialization.
 * ```ts
 * CompactSize.encode(1n);
 * ```
 */
export const CompactSize: P.CoderType<bigint> = /* @__PURE__ */ (() =>
  P.wrap({
    encodeStream: (w: P.Writer, value: bigint) => {
      if (typeof value === 'number') value = BigInt(value);
      if (0n <= value && value <= 252n) return w.byte(Number(value));
      for (const [flag, bytes, start, stop] of Object.values(CSLimits)) {
        if (start > value || value > stop) continue;
        w.byte(flag);
        for (let i = 0; i < bytes; i++) w.byte(Number((value >> (8n * BigInt(i))) & 0xffn));
        return;
      }
      throw w.err(`VarInt too big: ${value}`);
    },
    decodeStream: (r: P.Reader): bigint => {
      const b0 = r.byte();
      if (b0 <= 0xfc) return BigInt(b0);
      const [_, bytes, start] = CSLimits[b0];
      let num = 0n;
      for (let i = 0; i < bytes; i++) num |= BigInt(r.byte()) << (8n * BigInt(i));
      if (num < start) throw r.err(`Wrong CompactSize(${8 * bytes})`);
      return num;
    },
  }))();

// Same thing, but in number instead of bigint. Checks for safe integer inside
/**
 * CompactSize coder that decodes into JavaScript numbers.
 * @example
 * Use the number-based CompactSize helper when the value fits a JS number.
 * ```ts
 * CompactSizeLen.encode(1);
 * ```
 */
export const CompactSizeLen: P.CoderType<number> = /* @__PURE__ */ (() =>
  P.apply(CompactSize, P.coders.numberBigint))();

// ui8a of size <CompactSize>
/**
 * Length-prefixed byte array coder.
 * @example
 * Prefix a byte array with its CompactSize length.
 * ```ts
 * VarBytes.encode(new Uint8Array([1, 2, 3]));
 * ```
 */
export const VarBytes: P.CoderType<Bytes> = /* @__PURE__ */ (() => P.bytes(CompactSize))();

// SegWit v0 stack of witness buffers
/**
 * SegWit witness stack coder.
 * @example
 * Encode one witness stack for a SegWit input.
 * ```ts
 * RawWitness.encode([new Uint8Array([1])]);
 * ```
 */
export const RawWitness: P.CoderType<Bytes[]> = /* @__PURE__ */ (() =>
  P.array(CompactSizeLen, VarBytes))();

// Array of size <CompactSize>
/**
 * Coder for CompactSize-prefixed arrays.
 * @param t - element coder
 * @returns Array coder.
 * @example
 * CompactSize-prefix a small list of fixed-width integers.
 * ```ts
 * import * as P from 'micro-packed';
 * import { BTCArray } from '@scure/btc-signer/script.js';
 * BTCArray(P.U8).encode([1, 2, 3]);
 * ```
 */
export const BTCArray = <T>(t: P.CoderType<T>): P.CoderType<T[]> => P.array(CompactSize, t);

/**
 * Raw Bitcoin transaction input coder.
 * @example
 * Encode one transaction input exactly as it appears on the wire.
 * ```ts
 * import { hex } from '@scure/base';
 * import { RawInput } from '@scure/btc-signer/script.js';
 * RawInput.encode({
 *   txid: hex.decode('0000000000000000000000000000000000000000000000000000000000000001'),
 *   index: 0,
 *   finalScriptSig: new Uint8Array([0x51]),
 *   sequence: 0xffffffff,
 * });
 * ```
 */
export const RawInput = /* @__PURE__ */ (() =>
  P.struct({
    txid: P.bytes(32, true), // hash(prev_tx),
    index: P.U32LE, // output number of previous tx
    finalScriptSig: VarBytes, // btc merges input and output script, executes it. If ok = tx passes
    sequence: P.U32LE, // ?
  }))();

/**
 * Raw Bitcoin transaction output coder.
 * @example
 * Encode one transaction output with amount and scriptPubKey.
 * ```ts
 * import { RawOutput } from '@scure/btc-signer/script.js';
 * RawOutput.encode({ amount: 1n, script: new Uint8Array([0x51]) });
 * ```
 */
export const RawOutput = /* @__PURE__ */ (() => P.struct({ amount: P.U64LE, script: VarBytes }))();

// https://en.bitcoin.it/wiki/Protocol_documentation#tx
const _RawTx = /* @__PURE__ */ (() =>
  P.struct({
    version: P.I32LE,
    segwitFlag: P.flag(new Uint8Array([0x00, 0x01])),
    inputs: BTCArray(RawInput),
    outputs: BTCArray(RawOutput),
    witnesses: P.flagged('segwitFlag', P.array('inputs/length', RawWitness)),
    // < 500000000	Block number at which this transaction is unlocked
    // >= 500000000	UNIX timestamp at which this transaction is unlocked
    // Handled as part of PSBTv2
    lockTime: P.U32LE,
  }))();

function validateRawTx(tx: P.UnwrapCoder<typeof _RawTx>) {
  if (tx.segwitFlag && tx.witnesses && !tx.witnesses.length)
    throw new Error('Segwit flag with empty witnesses array');
  return tx;
}
/**
 * Raw Bitcoin transaction coder.
 * @example
 * Encode a SegWit transaction with one input, one output, and one witness stack.
 * ```ts
 * import { hex } from '@scure/base';
 * import { RawTx } from '@scure/btc-signer/script.js';
 * RawTx.encode({
 *   version: 2,
 *   segwitFlag: true,
 *   inputs: [{
 *     txid: hex.decode('0000000000000000000000000000000000000000000000000000000000000001'),
 *     index: 0,
 *     finalScriptSig: new Uint8Array(),
 *     sequence: 0xffffffff,
 *   }],
 *   outputs: [{ amount: 1n, script: new Uint8Array([0x51]) }],
 *   witnesses: [[new Uint8Array([1])]],
 *   lockTime: 0,
 * });
 * ```
 */
export const RawTx: typeof _RawTx = /* @__PURE__ */ (() => P.validate(_RawTx, validateRawTx))();
// Pre-SegWit serialization format (for PSBTv0)
/**
 * Pre-SegWit transaction coder used by PSBTv0.
 * @example
 * Encode the legacy unsigned transaction format used inside PSBTv0 globals.
 * ```ts
 * import { hex } from '@scure/base';
 * import { RawOldTx } from '@scure/btc-signer/script.js';
 * RawOldTx.encode({
 *   version: 2,
 *   inputs: [{
 *     txid: hex.decode('0000000000000000000000000000000000000000000000000000000000000001'),
 *     index: 0,
 *     finalScriptSig: new Uint8Array(),
 *     sequence: 0xffffffff,
 *   }],
 *   outputs: [{ amount: 1n, script: new Uint8Array([0x51]) }],
 *   lockTime: 0,
 * });
 * ```
 */
export const RawOldTx = /* @__PURE__ */ (() =>
  P.struct({
    version: P.I32LE,
    inputs: BTCArray(RawInput),
    outputs: BTCArray(RawOutput),
    lockTime: P.U32LE,
  }))();

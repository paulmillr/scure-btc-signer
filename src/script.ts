import * as P from 'micro-packed';
import { isBytes, reverseObject, type ValueOf, type Bytes } from './utils.ts';

export const MAX_SCRIPT_BYTE_LENGTH = 520;

// prettier-ignore
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

export const OPNames = reverseObject(OP);
export type OP = ValueOf<typeof OP>;

export type ScriptOP = keyof typeof OP | Uint8Array | number;
export type ScriptType = ScriptOP[];

// We can encode almost any number as ScriptNum, however, parsing will be a problem
// since we can't know if buffer is a number or something else.
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
export const Script: P.CoderType<ScriptType> = P.wrap({
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
});

// BTC specific variable length integer encoding
// https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_integer
const CSLimits: Record<number, [number, number, bigint, bigint]> = {
  0xfd: [0xfd, 2, 253n, 65535n],
  0xfe: [0xfe, 4, 65536n, 4294967295n],
  0xff: [0xff, 8, 4294967296n, 18446744073709551615n],
};
export const CompactSize: P.CoderType<bigint> = P.wrap({
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
});

// Same thing, but in number instead of bigint. Checks for safe integer inside
export const CompactSizeLen: P.CoderType<number> = P.apply(CompactSize, P.coders.numberBigint);

// ui8a of size <CompactSize>
export const VarBytes: P.CoderType<Bytes> = P.bytes(CompactSize);

// SegWit v0 stack of witness buffers
export const RawWitness: P.CoderType<Bytes[]> = P.array(CompactSizeLen, VarBytes);

// Array of size <CompactSize>
export const BTCArray = <T>(t: P.CoderType<T>): P.CoderType<T[]> => P.array(CompactSize, t);

export const RawInput = P.struct({
  txid: P.bytes(32, true), // hash(prev_tx),
  index: P.U32LE, // output number of previous tx
  finalScriptSig: VarBytes, // btc merges input and output script, executes it. If ok = tx passes
  sequence: P.U32LE, // ?
});

export const RawOutput = P.struct({ amount: P.U64LE, script: VarBytes });

// https://en.bitcoin.it/wiki/Protocol_documentation#tx
const _RawTx = P.struct({
  version: P.I32LE,
  segwitFlag: P.flag(new Uint8Array([0x00, 0x01])),
  inputs: BTCArray(RawInput),
  outputs: BTCArray(RawOutput),
  witnesses: P.flagged('segwitFlag', P.array('inputs/length', RawWitness)),
  // < 500000000	Block number at which this transaction is unlocked
  // >= 500000000	UNIX timestamp at which this transaction is unlocked
  // Handled as part of PSBTv2
  lockTime: P.U32LE,
});

function validateRawTx(tx: P.UnwrapCoder<typeof _RawTx>) {
  if (tx.segwitFlag && tx.witnesses && !tx.witnesses.length)
    throw new Error('Segwit flag with empty witnesses array');
  return tx;
}
export const RawTx: typeof _RawTx = P.validate(_RawTx, validateRawTx);
// Pre-SegWit serialization format (for PSBTv0)
export const RawOldTx = P.struct({
  version: P.I32LE,
  inputs: BTCArray(RawInput),
  outputs: BTCArray(RawOutput),
  lockTime: P.U32LE,
});

import * as P from 'micro-packed';
import { isBytes } from './utils.js';

export const MAX_SCRIPT_BYTE_LENGTH = 520;

// prettier-ignore
export enum OP {
  OP_0 = 0x00, PUSHDATA1 = 0x4c, PUSHDATA2, PUSHDATA4, '1NEGATE',
  RESERVED = 0x50,
  OP_1, OP_2, OP_3, OP_4, OP_5, OP_6, OP_7, OP_8,
  OP_9, OP_10, OP_11, OP_12, OP_13, OP_14, OP_15, OP_16,
  // Control
  NOP, VER, IF, NOTIF, VERIF, VERNOTIF, ELSE, ENDIF, VERIFY, RETURN,
  // Stack
  TOALTSTACK, FROMALTSTACK, '2DROP', '2DUP', '3DUP', '2OVER', '2ROT', '2SWAP',
  IFDUP, DEPTH, DROP, DUP, NIP, OVER, PICK, ROLL, ROT, SWAP, TUCK,
  // Splice
  CAT, SUBSTR, LEFT, RIGHT, SIZE,
  // Boolean logic
  INVERT, AND, OR, XOR, EQUAL, EQUALVERIFY, RESERVED1, RESERVED2,
  // Numbers
  '1ADD', '1SUB', '2MUL', '2DIV',
  NEGATE, ABS, NOT, '0NOTEQUAL',
  ADD, SUB, MUL, DIV, MOD, LSHIFT, RSHIFT, BOOLAND, BOOLOR,
  NUMEQUAL, NUMEQUALVERIFY, NUMNOTEQUAL, LESSTHAN, GREATERTHAN,
  LESSTHANOREQUAL, GREATERTHANOREQUAL, MIN, MAX, WITHIN,
  // Crypto
  RIPEMD160, SHA1, SHA256, HASH160, HASH256, CODESEPARATOR,
  CHECKSIG, CHECKSIGVERIFY, CHECKMULTISIG, CHECKMULTISIGVERIFY,
  // Expansion
  NOP1, CHECKLOCKTIMEVERIFY, CHECKSEQUENCEVERIFY, NOP4, NOP5, NOP6, NOP7, NOP8, NOP9, NOP10,
  // BIP 342
  CHECKSIGADD,
  // Invalid
  INVALID = 0xff,
}

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

export function OpToNum(op: ScriptOP, bytesLimit = 4, forceMinimal = true) {
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
        const op = OP[cur] as keyof typeof OP;
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
export const CompactSizeLen = P.apply(CompactSize, P.coders.numberBigint);

// ui8a of size <CompactSize>
export const VarBytes = P.bytes(CompactSize);

// SegWit v0 stack of witness buffers
export const RawWitness = P.array(CompactSizeLen, VarBytes);

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
export const RawTx = P.validate(_RawTx, validateRawTx);
// Pre-SegWit serialization format (for PSBTv0)
export const RawOldTx = P.struct({
  version: P.I32LE,
  inputs: BTCArray(RawInput),
  outputs: BTCArray(RawOutput),
  lockTime: P.U32LE,
});

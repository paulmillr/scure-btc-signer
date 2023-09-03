/*! scure-btc-signer - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import { secp256k1 as _secp, schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { hex, base58check as _b58, bech32, bech32m } from '@scure/base';
import type { Coder } from '@scure/base';
import * as P from 'micro-packed';

const { ProjectivePoint: ProjPoint, sign: _signECDSA, getPublicKey: _pubECDSA } = _secp;
const CURVE_ORDER = _secp.CURVE.n;

// Basic utility types
export type ExtendType<T, E> = {
  [K in keyof T]: K extends keyof E ? E[K] | T[K] : T[K];
};
export type RequireType<T, K extends keyof T> = T & {
  [P in K]-?: T[P];
};
export type Bytes = Uint8Array;
// Same as value || def, but doesn't overwrites zero ('0', 0, 0n, etc)
const def = <T>(value: T | undefined, def: T) => (value === undefined ? def : value);
const isBytes = P.isBytes;
const hash160 = (msg: Bytes) => ripemd160(sha256(msg));
const sha256x2 = (...msgs: Bytes[]) => sha256(sha256(concat(...msgs)));
const concat = P.concatBytes;
// Make base58check work
export const base58check = _b58(sha256);

export function cloneDeep<T>(obj: T): T {
  if (Array.isArray(obj)) return obj.map((i) => cloneDeep(i)) as unknown as T;
  // slice of nodejs Buffer doesn't copy
  else if (obj instanceof Uint8Array) return Uint8Array.from(obj) as unknown as T;
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
  throw new Error(`cloneDeep: unknown type=${obj} (${typeof obj})`);
}

enum PubT {
  ecdsa,
  schnorr,
}
function validatePubkey(pub: Bytes, type: PubT): Bytes {
  const len = pub.length;
  if (type === PubT.ecdsa) {
    if (len === 32) throw new Error('Expected non-Schnorr key');
    ProjPoint.fromHex(pub); // does assertValidity
    return pub;
  } else if (type === PubT.schnorr) {
    if (len !== 32) throw new Error('Expected 32-byte Schnorr key');
    schnorr.utils.lift_x(schnorr.utils.bytesToNumberBE(pub));
    return pub;
  } else {
    throw new Error('Unknown key type');
  }
}

function isValidPubkey(pub: Bytes, type: PubT): boolean {
  try {
    validatePubkey(pub, type);
    return true;
  } catch (e) {
    return false;
  }
}

// low-r signature grinding. Used to reduce tx size by 1 byte.
// noble/secp256k1 does not support the feature: it is not used outside of BTC.
// We implement it manually, because in BTC it's common.
// Not best way, but closest to bitcoin implementation (easier to check)
const hasLowR = (sig: { r: bigint; s: bigint }) => sig.r < CURVE_ORDER / 2n;
function signECDSA(hash: Bytes, privateKey: Bytes, lowR = false): Bytes {
  let sig = _signECDSA(hash, privateKey);
  if (lowR && !hasLowR(sig)) {
    const extraEntropy = new Uint8Array(32);
    for (let cnt = 0; cnt < Number.MAX_SAFE_INTEGER; cnt++) {
      extraEntropy.set(P.U32LE.encode(cnt));
      sig = _signECDSA(hash, privateKey, { extraEntropy });
      if (hasLowR(sig)) break;
    }
  }
  return sig.toDERRawBytes();
}

function tapTweak(a: Bytes, b: Bytes): bigint {
  const u = schnorr.utils;
  const t = u.taggedHash('TapTweak', a, b);
  const tn = u.bytesToNumberBE(t);
  if (tn >= CURVE_ORDER) throw new Error('tweak higher than curve order');
  return tn;
}

export function taprootTweakPrivKey(privKey: Uint8Array, merkleRoot = new Uint8Array()) {
  const u = schnorr.utils;
  const seckey0 = u.bytesToNumberBE(privKey); // seckey0 = int_from_bytes(seckey0)
  const P = ProjPoint.fromPrivateKey(seckey0); // P = point_mul(G, seckey0)
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
  const Q = P.add(ProjPoint.fromPrivateKey(t)); // Q = point_add(P, point_mul(G, t))
  const parity = Q.hasEvenY() ? 0 : 1; // 0 if has_even_y(Q) else 1
  return [u.pointToBytes(Q), parity]; // bytes_from_int(x(Q))
}

// Can be 33 or 64 bytes
const PubKeyECDSA = P.validate(P.bytes(null), (pub) => validatePubkey(pub, PubT.ecdsa));
const PubKeySchnorr = P.validate(P.bytes(32), (pub) => validatePubkey(pub, PubT.schnorr));
const SignatureSchnorr = P.validate(P.bytes(null), (sig) => {
  if (sig.length !== 64 && sig.length !== 65)
    throw new Error('Schnorr signature should be 64 or 65 bytes long');
  return sig;
});

function uniqPubkey(pubkeys: Bytes[]) {
  const map: Record<string, boolean> = {};
  for (const pub of pubkeys) {
    const key = hex.encode(pub);
    if (map[key]) throw new Error(`Multisig: non-uniq pubkey: ${pubkeys.map(hex.encode)}`);
    map[key] = true;
  }
}

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

export const PRECISION = 8;
export const DEFAULT_VERSION = 2;
export const DEFAULT_LOCKTIME = 0;
export const DEFAULT_SEQUENCE = 4294967295;
const EMPTY32 = new Uint8Array(32);
// Utils
export const Decimal = P.coders.decimal(PRECISION);
// Exported for tests, internal method
export function _cmpBytes(a: Bytes, b: Bytes) {
  if (!isBytes(a) || !isBytes(b)) throw new Error(`cmp: wrong type a=${typeof a} b=${typeof b}`);
  // -1 -> a<b, 0 -> a==b, 1 -> a>b
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) if (a[i] != b[i]) return Math.sign(a[i] - b[i]);
  return Math.sign(a.length - b.length);
}

// Coders
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

type ScriptOP = keyof typeof OP | Bytes | number;

type ScriptType = ScriptOP[];
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
        // MSB is zero (without sign bit) -> not minimally encoded
        if ((r.data[len - 1] & 0x7f) === 0) {
          // exception
          if (len <= 1 || (r.data[len - 2] & 0x80) === 0)
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
const CompactSizeLen = P.apply(CompactSize, P.coders.number);

// Array of size <CompactSize>
export const BTCArray = <T>(t: P.CoderType<T>): P.CoderType<T[]> => P.array(CompactSize, t);

// ui8a of size <CompactSize>
export const VarBytes = P.bytes(CompactSize);

export const RawInput = P.struct({
  txid: P.bytes(32, true), // hash(prev_tx),
  index: P.U32LE, // output number of previous tx
  finalScriptSig: VarBytes, // btc merges input and output script, executes it. If ok = tx passes
  sequence: P.U32LE, // ?
});

export const RawOutput = P.struct({ amount: P.U64LE, script: VarBytes });
const EMPTY_OUTPUT: P.UnwrapCoder<typeof RawOutput> = {
  amount: 0xffffffffffffffffn,
  script: P.EMPTY,
};

// SegWit v0 stack of witness buffers
export const RawWitness = P.array(CompactSizeLen, VarBytes);

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

// PSBT BIP174, BIP370, BIP371

type PSBTKeyCoder = P.CoderType<any> | false;

type PSBTKeyMapInfo = Readonly<
  [
    number,
    PSBTKeyCoder,
    any,
    readonly number[], // versionsRequiringInclusion
    readonly number[], // versionsAllowsInclusion
    boolean // silentIgnore
  ]
>;

function PSBTKeyInfo(info: PSBTKeyMapInfo) {
  const [type, kc, vc, reqInc, allowInc, silentIgnore] = info;
  return { type, kc, vc, reqInc, allowInc, silentIgnore };
}

type PSBTKeyMap = Record<string, PSBTKeyMapInfo>;

const BIP32Der = P.struct({
  fingerprint: P.U32BE,
  path: P.array(null, P.U32LE),
});

// Complex structure for PSBT fields
// <control byte with leaf version and parity bit> <internal key p> <C> <E> <AB>
const _TaprootControlBlock = P.struct({
  version: P.U8, // With parity :(
  internalKey: P.bytes(32),
  merklePath: P.array(null, P.bytes(32)),
});
export const TaprootControlBlock = P.validate(_TaprootControlBlock, (cb) => {
  if (cb.merklePath.length > 128)
    throw new Error('TaprootControlBlock: merklePath should be of length 0..128 (inclusive)');
  return cb;
});

const TaprootBIP32Der = P.struct({
  hashes: P.array(CompactSizeLen, P.bytes(32)),
  der: BIP32Der,
});
// The 78 byte serialized extended public key as defined by BIP 32.
const GlobalXPUB = P.bytes(78);
const tapScriptSigKey = P.struct({ pubKey: PubKeySchnorr, leafHash: P.bytes(32) });

// {<8-bit uint depth> <8-bit uint leaf version> <compact size uint scriptlen> <bytes script>}*
const tapTree = P.array(
  null,
  P.struct({
    depth: P.U8,
    version: P.U8,
    script: VarBytes,
  })
);

const BytesInf = P.bytes(null); // Bytes will conflict with Bytes type
const Bytes20 = P.bytes(20);
const Bytes32 = P.bytes(32);
// versionsRequiringExclusing = !versionsAllowsInclusion (as set)
// {name: [tag, keyCoder, valueCoder, versionsRequiringInclusion, versionsRequiringExclusing, versionsAllowsInclusion, silentIgnore]}
// SilentIgnore: we use some v2 fields for v1 representation too, so we just clean them before serialize

// Tables from BIP-0174 (https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki)
// prettier-ignore
const PSBTGlobal = {
  unsignedTx:       [0x00, false,      RawTx,          [0], [0],    false],
  xpub:             [0x01, GlobalXPUB, BIP32Der,       [],  [0, 2], false],
  txVersion:        [0x02, false,      P.U32LE,        [2], [2],    false],
  fallbackLocktime: [0x03, false,      P.U32LE,        [],  [2],    false],
  inputCount:       [0x04, false,      CompactSizeLen, [2], [2],    false],
  outputCount:      [0x05, false,      CompactSizeLen, [2], [2],    false],
  txModifiable:     [0x06, false,      P.U8,           [],  [2],    false],   // TODO: bitfield
  version:          [0xfb, false,      P.U32LE,        [],  [0, 2], false],
  proprietary:      [0xfc, BytesInf,   BytesInf,       [],  [0, 2], false],
} as const;
// prettier-ignore
const PSBTInput = {
  nonWitnessUtxo:         [0x00, false,               RawTx,            [],  [0, 2], false],
  witnessUtxo:            [0x01, false,               RawOutput,        [],  [0, 2], false],
  partialSig:             [0x02, PubKeyECDSA,         BytesInf,         [],  [0, 2], false],
  sighashType:            [0x03, false,               P.U32LE,          [],  [0, 2], false],
  redeemScript:           [0x04, false,               BytesInf,         [],  [0, 2], false],
  witnessScript:          [0x05, false,               BytesInf,         [],  [0, 2], false],
  bip32Derivation:        [0x06, PubKeyECDSA,         BIP32Der,         [],  [0, 2], false],
  finalScriptSig:         [0x07, false,               BytesInf,         [],  [0, 2], false],
  finalScriptWitness:     [0x08, false,               RawWitness,       [],  [0, 2], false],
  porCommitment:          [0x09, false,               BytesInf,         [],  [0, 2], false],
  ripemd160:              [0x0a, Bytes20,             BytesInf,         [],  [0, 2], false],
  sha256:                 [0x0b, Bytes32,             BytesInf,         [],  [0, 2], false],
  hash160:                [0x0c, Bytes20,             BytesInf,         [],  [0, 2], false],
  hash256:                [0x0d, Bytes32,             BytesInf,         [],  [0, 2], false],
  txid:                   [0x0e, false,               Bytes32,          [2], [2],    true],
  index:                  [0x0f, false,               P.U32LE,          [2], [2],    true],
  sequence:               [0x10, false,               P.U32LE,          [],  [2],    true],
  requiredTimeLocktime:   [0x11, false,               P.U32LE,          [],  [2],    false],
  requiredHeightLocktime: [0x12, false,               P.U32LE,          [],  [2],    false],
  tapKeySig:              [0x13, false,               SignatureSchnorr, [],  [0, 2], false],
  tapScriptSig:           [0x14, tapScriptSigKey,     SignatureSchnorr, [],  [0, 2], false],
  tapLeafScript:          [0x15, TaprootControlBlock, BytesInf,         [],  [0, 2], false],
  tapBip32Derivation:     [0x16, Bytes32,             TaprootBIP32Der,  [],  [0, 2], false],
  tapInternalKey:         [0x17, false,               PubKeySchnorr,    [],  [0, 2], false],
  tapMerkleRoot:          [0x18, false,               Bytes32,          [],  [0, 2], false],
  proprietary:            [0xfc, BytesInf,            BytesInf,         [],  [0, 2], false],
} as const;
// All other keys removed when finalizing
const PSBTInputFinalKeys: (keyof TransactionInput)[] = [
  'txid',
  'sequence',
  'index',
  'witnessUtxo',
  'nonWitnessUtxo',
  'finalScriptSig',
  'finalScriptWitness',
  'unknown',
];

// Can be modified even on signed input
const PSBTInputUnsignedKeys: (keyof TransactionInput)[] = [
  'partialSig',
  'finalScriptSig',
  'finalScriptWitness',
  'tapKeySig',
  'tapScriptSig',
];

// prettier-ignore
const PSBTOutput = {
  redeemScript:       [0x00, false,         BytesInf,        [],  [0, 2], false],
  witnessScript:      [0x01, false,         BytesInf,        [],  [0, 2], false],
  bip32Derivation:    [0x02, PubKeyECDSA,   BIP32Der,        [],  [0, 2], false],
  amount:             [0x03, false,         P.I64LE,         [2], [2],    true],
  script:             [0x04, false,         BytesInf,        [2], [2],    true],
  tapInternalKey:     [0x05, false,         PubKeySchnorr,   [],  [0, 2], false],
  tapTree:            [0x06, false,         tapTree,         [],  [0, 2], false],
  tapBip32Derivation: [0x07, PubKeySchnorr, TaprootBIP32Der, [],  [0, 2], false],
  proprietary:        [0xfc, BytesInf,      BytesInf,        [],  [0, 2], false],
} as const;

// Can be modified even on signed input
const PSBTOutputUnsignedKeys: (keyof typeof PSBTOutput)[] = [];

const PSBTKeyPair = P.array(
  P.NULL,
  P.struct({
    //  <key> := <keylen> <keytype> <keydata> WHERE keylen = len(keytype)+len(keydata)
    key: P.prefix(CompactSizeLen, P.struct({ type: CompactSizeLen, key: P.bytes(null) })),
    //  <value> := <valuelen> <valuedata>
    value: P.bytes(CompactSizeLen),
  })
);

const PSBTUnknownKey = P.struct({ type: CompactSizeLen, key: P.bytes(null) });
type PSBTUnknownFields = { unknown?: [P.UnwrapCoder<typeof PSBTUnknownKey>, Bytes][] };
type PSBTKeyMapKeys<T extends PSBTKeyMap> = {
  -readonly [K in keyof T]?: T[K][1] extends false
    ? P.UnwrapCoder<T[K][2]>
    : [P.UnwrapCoder<T[K][1]>, P.UnwrapCoder<T[K][2]>][];
} & PSBTUnknownFields;
// Key cannot be 'unknown', value coder cannot be array for elements with empty key
function PSBTKeyMap<T extends PSBTKeyMap>(psbtEnum: T): P.CoderType<PSBTKeyMapKeys<T>> {
  // -> Record<type, [keyName, ...coders]>
  const byType: Record<number, [string, PSBTKeyCoder, P.CoderType<any>]> = {};
  for (const k in psbtEnum) {
    const [num, kc, vc] = psbtEnum[k];
    byType[num] = [k, kc, vc];
  }
  return P.wrap({
    encodeStream: (w: P.Writer, value: PSBTKeyMapKeys<T>) => {
      let out: P.UnwrapCoder<typeof PSBTKeyPair> = [];
      // Because we use order of psbtEnum, keymap is sorted here
      for (const name in psbtEnum) {
        const val = value[name];
        if (val === undefined) continue;
        const [type, kc, vc] = psbtEnum[name];
        if (!kc) {
          out.push({ key: { type, key: P.EMPTY }, value: vc.encode(val) });
        } else {
          // Low level interface, returns keys as is (with duplicates). Useful for debug
          const kv: [Bytes, Bytes][] = val!.map(
            ([k, v]: [P.UnwrapCoder<typeof kc>, P.UnwrapCoder<typeof vc>]) => [
              kc.encode(k),
              vc.encode(v),
            ]
          );
          // sort by keys
          kv.sort((a, b) => _cmpBytes(a[0], b[0]));
          for (const [key, value] of kv) out.push({ key: { key, type }, value });
        }
      }
      if (value.unknown) {
        value.unknown.sort((a, b) => _cmpBytes(a[0].key, b[0].key));
        for (const [k, v] of value.unknown) out.push({ key: k, value: v });
      }
      PSBTKeyPair.encodeStream(w, out);
    },
    decodeStream: (r: P.Reader): PSBTKeyMapKeys<T> => {
      const raw = PSBTKeyPair.decodeStream(r);
      const out: any = {};
      const noKey: Record<string, true> = {};
      for (const elm of raw) {
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
        // Only keyed elements at this point
        if (noKey[name])
          throw new Error(`PSBT: Key type with empty key and no key=${name} val=${value}`);
        if (!out[name]) out[name] = [];
        out[name].push([key, value]);
      }
      return out;
    },
  });
}

// Basic sanity check for scripts
function checkWSH(s: OutWSHType, witnessScript: Bytes) {
  if (!P.equalBytes(s.hash, sha256(witnessScript)))
    throw new Error('checkScript: wsh wrong witnessScript hash');
  const w = OutScript.decode(witnessScript);
  if (w.type === 'tr' || w.type === 'tr_ns' || w.type === 'tr_ms')
    throw new Error(`checkScript: P2${w.type} cannot be wrapped in P2SH`);
  if (w.type === 'wpkh' || w.type === 'sh')
    throw new Error(`checkScript: P2${w.type} cannot be wrapped in P2WSH`);
}

function checkScript(script?: Bytes, redeemScript?: Bytes, witnessScript?: Bytes) {
  if (script) {
    const s = OutScript.decode(script);
    // ms||pk maybe work, but there will be no address, hard to spend
    if (s.type === 'tr_ns' || s.type === 'tr_ms' || s.type === 'ms' || s.type == 'pk')
      throw new Error(`checkScript: non-wrapped ${s.type}`);
    if (s.type === 'sh' && redeemScript) {
      if (!P.equalBytes(s.hash, hash160(redeemScript)))
        throw new Error('checkScript: sh wrong redeemScript hash');
      const r = OutScript.decode(redeemScript);
      if (r.type === 'tr' || r.type === 'tr_ns' || r.type === 'tr_ms')
        throw new Error(`checkScript: P2${r.type} cannot be wrapped in P2SH`);
      // Not sure if this unspendable, but we cannot represent this via PSBT
      if (r.type === 'sh') throw new Error('checkScript: P2SH cannot be wrapped in P2SH');
    }
    if (s.type === 'wsh' && witnessScript) checkWSH(s, witnessScript);
  }
  if (redeemScript) {
    const r = OutScript.decode(redeemScript);
    if (r.type === 'wsh' && witnessScript) checkWSH(r, witnessScript);
  }
}

const PSBTInputCoder = P.validate(PSBTKeyMap(PSBTInput), (i) => {
  if (i.finalScriptWitness && !i.finalScriptWitness.length)
    throw new Error('validateInput: wmpty finalScriptWitness');
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

  if (i.nonWitnessUtxo && i.index !== undefined) {
    const last = i.nonWitnessUtxo.outputs.length - 1;
    if (i.index > last) throw new Error(`validateInput: index(${i.index}) not in nonWitnessUtxo`);
    const prevOut = i.nonWitnessUtxo.outputs[i.index];
    if (
      i.witnessUtxo &&
      (!P.equalBytes(i.witnessUtxo.script, prevOut.script) ||
        i.witnessUtxo.amount !== prevOut.amount)
    )
      throw new Error('validateInput: witnessUtxo different from nonWitnessUtxo');
  }
  if (i.tapLeafScript) {
    // tap leaf version appears here twice: in control block and at the end of script
    for (const [k, v] of i.tapLeafScript) {
      if ((k.version & 0b1111_1110) !== v[v.length - 1])
        throw new Error('validateInput: tapLeafScript version mimatch');
      if (v[v.length - 1] & 1)
        throw new Error('validateInput: tapLeafScript version has parity bit!');
    }
  }
  // Validate txid for nonWitnessUtxo is correct
  if (i.nonWitnessUtxo && i.index && i.txid) {
    const outputs = i.nonWitnessUtxo.outputs;
    if (outputs.length - 1 < i.index) throw new Error('nonWitnessUtxo: incorect output index');
    const tx = Transaction.fromRaw(RawTx.encode(i.nonWitnessUtxo));
    const txid = hex.encode(i.txid);
    if (tx.id !== txid) throw new Error(`nonWitnessUtxo: wrong txid, exp=${txid} got=${tx.id}`);
  }
  return i;
});

const PSBTOutputCoder = P.validate(PSBTKeyMap(PSBTOutput), (o) => {
  if (o.bip32Derivation) for (const [k] of o.bip32Derivation) validatePubkey(k, PubT.ecdsa);
  return o;
});

const PSBTGlobalCoder = P.validate(PSBTKeyMap(PSBTGlobal), (g) => {
  const version = g.version || 0;
  if (version === 0) {
    if (!g.unsignedTx) throw new Error('PSBTv0: missing unsignedTx');
    if (g.unsignedTx.segwitFlag || g.unsignedTx.witnesses)
      throw new Error('PSBTv0: witness in unsingedTx');
    for (const inp of g.unsignedTx.inputs)
      if (inp.finalScriptSig && inp.finalScriptSig.length)
        throw new Error('PSBTv0: input scriptSig found in unsignedTx');
  }
  return g;
});

export const _RawPSBTV0 = P.struct({
  magic: P.magic(P.string(new Uint8Array([0xff])), 'psbt'),
  global: PSBTGlobalCoder,
  inputs: P.array('global/unsignedTx/inputs/length', PSBTInputCoder),
  outputs: P.array(null, PSBTOutputCoder),
});

export const _RawPSBTV2 = P.struct({
  magic: P.magic(P.string(new Uint8Array([0xff])), 'psbt'),
  global: PSBTGlobalCoder,
  inputs: P.array('global/inputCount', PSBTInputCoder),
  outputs: P.array('global/outputCount', PSBTOutputCoder),
});

export type PSBTRaw = typeof _RawPSBTV0 | typeof _RawPSBTV2;

export const _DebugPSBT = P.struct({
  magic: P.magic(P.string(new Uint8Array([0xff])), 'psbt'),
  items: P.array(
    null,
    P.apply(
      P.array(P.NULL, P.tuple([P.hex(CompactSizeLen), P.bytes(CompactSize)])),
      P.coders.dict()
    )
  ),
});

function validatePSBTFields<T extends PSBTKeyMap>(
  version: number,
  info: T,
  lst: PSBTKeyMapKeys<T>
) {
  for (const k in lst) {
    if (k === 'unknown') continue;
    if (!info[k]) continue;
    const { allowInc } = PSBTKeyInfo(info[k]);
    if (!allowInc.includes(version)) throw new Error(`PSBTv${version}: field ${k} is not allowed`);
  }
  for (const k in info) {
    const { reqInc } = PSBTKeyInfo(info[k]);
    if (reqInc.includes(version) && lst[k] === undefined)
      throw new Error(`PSBTv${version}: missing required field ${k}`);
  }
}

function cleanPSBTFields<T extends PSBTKeyMap>(version: number, info: T, lst: PSBTKeyMapKeys<T>) {
  const out: PSBTKeyMapKeys<T> = {};
  for (const _k in lst) {
    const k = _k as string & keyof PSBTKeyMapKeys<T>;
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
    out[k] = lst[k];
  }
  return out;
}

function validatePSBT(tx: P.UnwrapCoder<PSBTRaw>) {
  const version = (tx && tx.global && tx.global.version) || 0;
  validatePSBTFields(version, PSBTGlobal, tx.global);
  for (const i of tx.inputs) validatePSBTFields(version, PSBTInput, i);
  for (const o of tx.outputs) validatePSBTFields(version, PSBTOutput, o);
  // We allow only one empty element at the end of map (compat with bitcoinjs-lib bug)
  const inputCount = !version ? tx.global.unsignedTx!.inputs.length : tx.global.inputCount!;
  if (tx.inputs.length < inputCount) throw new Error('Not enough inputs');
  const inputsLeft = tx.inputs.slice(inputCount);
  if (inputsLeft.length > 1 || (inputsLeft.length && Object.keys(inputsLeft[0]).length))
    throw new Error(`Unexpected inputs left in tx=${inputsLeft}`);
  // Same for inputs
  const outputCount = !version ? tx.global.unsignedTx!.outputs.length : tx.global.outputCount!;
  if (tx.outputs.length < outputCount) throw new Error('Not outputs inputs');
  const outputsLeft = tx.outputs.slice(outputCount);
  if (outputsLeft.length > 1 || (outputsLeft.length && Object.keys(outputsLeft[0]).length))
    throw new Error(`Unexpected outputs left in tx=${outputsLeft}`);
  return tx;
}

function mergeKeyMap<T extends PSBTKeyMap>(
  psbtEnum: T,
  val: PSBTKeyMapKeys<T>,
  cur?: PSBTKeyMapKeys<T>,
  allowedFields?: (keyof PSBTKeyMapKeys<T>)[]
): PSBTKeyMapKeys<T> {
  const res: PSBTKeyMapKeys<T> = { ...cur, ...val };
  // All arguments can be provided as hex
  for (const k in psbtEnum) {
    const key = k as keyof typeof psbtEnum;
    const [_, kC, vC] = psbtEnum[key];
    type _KV = [P.UnwrapCoder<typeof kC>, P.UnwrapCoder<typeof vC>];
    const cannotChange = allowedFields && !allowedFields.includes(k);
    if (val[k] === undefined && k in val) {
      if (cannotChange) throw new Error(`Cannot remove signed field=${k}`);
      delete res[k];
    } else if (kC) {
      const oldKV = (cur && cur[k] ? cur[k] : []) as _KV[];
      let newKV = val[key] as _KV[];
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
    } else if (cannotChange && k in val && cur && cur[k] !== undefined) {
      if (!P.equalBytes(vC.encode(val[k]), vC.encode(cur[k])))
        throw new Error(`Cannot change signed field=${k}`);
    }
  }
  // Remove unknown keys
  for (const k in res) if (!psbtEnum[k]) delete res[k];
  return res;
}

export const RawPSBTV0 = P.validate(_RawPSBTV0, validatePSBT);
export const RawPSBTV2 = P.validate(_RawPSBTV2, validatePSBT);

// (TxHash, Idx)
const TxHashIdx = P.struct({ txid: P.bytes(32, true), index: P.U32LE });
// /Coders

// Payments
// We need following items:
// - encode/decode output script
// - generate input script
// - generate address/output/redeem from user input
// P2ret represents generic interface for all p2* methods
export type P2Ret = {
  type: string;
  script: Bytes;
  address?: string;
  redeemScript?: Bytes;
  witnessScript?: Bytes;
};
// Public Key (P2PK)
type OutPKType = { type: 'pk'; pubkey: Bytes };
type OptScript = ScriptType | undefined;
const OutPK: Coder<OptScript, OutPKType | undefined> = {
  encode(from: ScriptType): OutPKType | undefined {
    if (
      from.length !== 2 ||
      !isBytes(from[0]) ||
      !isValidPubkey(from[0], PubT.ecdsa) ||
      from[1] !== 'CHECKSIG'
    )
      return;
    return { type: 'pk', pubkey: from[0] };
  },
  decode: (to: OutPKType): OptScript => (to.type === 'pk' ? [to.pubkey, 'CHECKSIG'] : undefined),
};
// @ts-ignore
export const p2pk = (pubkey: Bytes, network = NETWORK): P2Ret => {
  // network is unused
  if (!isValidPubkey(pubkey, PubT.ecdsa)) throw new Error('P2PK: invalid publicKey');
  return {
    type: 'pk',
    script: OutScript.encode({ type: 'pk', pubkey }),
  };
};

// Public Key Hash (P2PKH)
type OutPKHType = { type: 'pkh'; hash: Bytes };
const OutPKH: Coder<OptScript, OutPKHType | undefined> = {
  encode(from: ScriptType): OutPKHType | undefined {
    if (from.length !== 5 || from[0] !== 'DUP' || from[1] !== 'HASH160' || !isBytes(from[2]))
      return;
    if (from[3] !== 'EQUALVERIFY' || from[4] !== 'CHECKSIG') return;
    return { type: 'pkh', hash: from[2] };
  },
  decode: (to: OutPKHType): OptScript =>
    to.type === 'pkh' ? ['DUP', 'HASH160', to.hash, 'EQUALVERIFY', 'CHECKSIG'] : undefined,
};
export const p2pkh = (publicKey: Bytes, network = NETWORK): P2Ret => {
  if (!isValidPubkey(publicKey, PubT.ecdsa)) throw new Error('P2PKH: invalid publicKey');
  const hash = hash160(publicKey);
  return {
    type: 'pkh',
    script: OutScript.encode({ type: 'pkh', hash }),
    address: Address(network).encode({ type: 'pkh', hash }),
  };
};
// Script Hash (P2SH)
type OutSHType = { type: 'sh'; hash: Bytes };
const OutSH: Coder<OptScript, OutSHType | undefined> = {
  encode(from: ScriptType): OutSHType | undefined {
    if (from.length !== 3 || from[0] !== 'HASH160' || !isBytes(from[1]) || from[2] !== 'EQUAL')
      return;
    return { type: 'sh', hash: from[1] };
  },
  decode: (to: OutSHType): OptScript =>
    to.type === 'sh' ? ['HASH160', to.hash, 'EQUAL'] : undefined,
};
export const p2sh = (child: P2Ret, network = NETWORK): P2Ret => {
  // It is already tested inside noble-hashes and checkScript
  const cs = child.script;
  if (!isBytes(cs)) throw new Error(`Wrong script: ${typeof child.script}, expected Uint8Array`);
  const hash = hash160(cs);
  const script = OutScript.encode({ type: 'sh', hash });
  checkScript(script, cs, child.witnessScript);
  const res: P2Ret = {
    type: 'sh',
    redeemScript: cs,
    script: OutScript.encode({ type: 'sh', hash }),
    address: Address(network).encode({ type: 'sh', hash }),
  };
  if (child.witnessScript) res.witnessScript = child.witnessScript;
  return res;
};
// Witness Script Hash (P2WSH)
type OutWSHType = { type: 'wsh'; hash: Bytes };
const OutWSH: Coder<OptScript, OutWSHType | undefined> = {
  encode(from: ScriptType): OutWSHType | undefined {
    if (from.length !== 2 || from[0] !== 0 || !isBytes(from[1])) return;
    if (from[1].length !== 32) return;
    return { type: 'wsh', hash: from[1] };
  },
  decode: (to: OutWSHType): OptScript => (to.type === 'wsh' ? [0, to.hash] : undefined),
};
export const p2wsh = (child: P2Ret, network = NETWORK): P2Ret => {
  const cs = child.script;
  if (!isBytes(cs)) throw new Error(`Wrong script: ${typeof cs}, expected Uint8Array`);
  const hash = sha256(cs);
  const script = OutScript.encode({ type: 'wsh', hash });
  checkScript(script, undefined, cs);
  return {
    type: 'wsh',
    witnessScript: cs,
    script: OutScript.encode({ type: 'wsh', hash }),
    address: Address(network).encode({ type: 'wsh', hash }),
  };
};
// Witness Public Key Hash (P2WPKH)
type OutWPKHType = { type: 'wpkh'; hash: Bytes };
const OutWPKH: Coder<OptScript, OutWPKHType | undefined> = {
  encode(from: ScriptType): OutWPKHType | undefined {
    if (from.length !== 2 || from[0] !== 0 || !isBytes(from[1])) return;
    if (from[1].length !== 20) return;
    return { type: 'wpkh', hash: from[1] };
  },
  decode: (to: OutWPKHType): OptScript => (to.type === 'wpkh' ? [0, to.hash] : undefined),
};
export const p2wpkh = (publicKey: Bytes, network = NETWORK): P2Ret => {
  if (!isValidPubkey(publicKey, PubT.ecdsa)) throw new Error('P2WPKH: invalid publicKey');
  if (publicKey.length === 65) throw new Error('P2WPKH: uncompressed public key');
  const hash = hash160(publicKey);
  return {
    type: 'wpkh',
    script: OutScript.encode({ type: 'wpkh', hash }),
    address: Address(network).encode({ type: 'wpkh', hash }),
  };
};
// Multisig (P2MS)
type OutMSType = { type: 'ms'; pubkeys: Bytes[]; m: number };
const OutMS: Coder<OptScript, OutMSType | undefined> = {
  encode(from: ScriptType): OutMSType | undefined {
    const last = from.length - 1;
    if (from[last] !== 'CHECKMULTISIG') return;
    const m = from[0];
    const n = from[last - 1];
    if (typeof m !== 'number' || typeof n !== 'number') return;
    const pubkeys = from.slice(1, -2);
    if (n !== pubkeys.length) return;
    for (const pub of pubkeys) if (!isBytes(pub)) return;
    return { type: 'ms', m, pubkeys: pubkeys as Bytes[] }; // we don't need n, since it is the same as pubkeys
  },
  // checkmultisig(n, ..pubkeys, m)
  decode: (to: OutMSType): OptScript =>
    to.type === 'ms' ? [to.m, ...to.pubkeys, to.pubkeys.length, 'CHECKMULTISIG'] : undefined,
};
export const p2ms = (m: number, pubkeys: Bytes[], allowSamePubkeys = false): P2Ret => {
  if (!allowSamePubkeys) uniqPubkey(pubkeys);
  return { type: 'ms', script: OutScript.encode({ type: 'ms', pubkeys, m }) };
};
// Taproot (P2TR)
type OutTRType = { type: 'tr'; pubkey: Bytes };
const OutTR: Coder<OptScript, OutTRType | undefined> = {
  encode(from: ScriptType): OutTRType | undefined {
    if (from.length !== 2 || from[0] !== 1 || !isBytes(from[1])) return;
    return { type: 'tr', pubkey: from[1] };
  },
  decode: (to: OutTRType): OptScript => (to.type === 'tr' ? [1, to.pubkey] : undefined),
};
export type TaprootNode = {
  script: Bytes | string;
  leafVersion?: number;
  weight?: number;
} & Partial<P2TROut>;
export type TaprootScriptTree = TaprootNode | TaprootScriptTree[];
export type TaprootScriptList = TaprootNode[];
type _TaprootTreeInternal = {
  weight?: number;
  childs?: [_TaprootTreeInternal[], _TaprootTreeInternal[]];
};

// Helper for generating binary tree from list, with weights
export function taprootListToTree(taprootList: TaprootScriptList): TaprootScriptTree {
  // Clone input in order to not corrupt it
  const lst = Array.from(taprootList) as _TaprootTreeInternal[];
  // We have at least 2 elements => can create branch
  while (lst.length >= 2) {
    // Sort: elements with smallest weight are in the end of queue
    lst.sort((a, b) => (b.weight || 1) - (a.weight || 1));
    const b = lst.pop()!;
    const a = lst.pop()!;
    const weight = (a?.weight || 1) + (b?.weight || 1);
    lst.push({
      weight,
      // Unwrap children array
      // TODO: Very hard to remove any here
      childs: [a?.childs || (a as any[]), b?.childs || (b as any)],
    });
  }
  // At this point there is always 1 element in lst
  const last = lst[0];
  return (last?.childs || last) as TaprootScriptTree;
}
type HashedTree =
  | { type: 'leaf'; version?: number; script: Bytes; hash: Bytes }
  | { type: 'branch'; left: HashedTree; right: HashedTree; hash: Bytes };
function checkTaprootScript(script: Bytes, internalPubKey: Bytes, allowUnknownOutputs = false) {
  const out = OutScript.decode(script);
  if (out.type === 'unknown' && allowUnknownOutputs) return;
  if (!['tr_ns', 'tr_ms'].includes(out.type))
    throw new Error(`P2TR: invalid leaf script=${out.type}`);
  const outms = out as OutTRNSType | OutTRMSType;
  if (!allowUnknownOutputs && outms.pubkeys) {
    for (const p of outms.pubkeys) {
      if (P.equalBytes(p, TAPROOT_UNSPENDABLE_KEY))
        throw new Error('Unspendable taproot key in leaf script');
      // It's likely a mistake at this point:
      // 1. p2tr(A, p2tr_ns(2, [A, B])) == p2tr(A, p2tr_pk(B)) (A or B key)
      // but will take more space and fees.
      // 2. For multi-sig p2tr(A, p2tr_ns(2, [A, B, C])) it's probably a security issue:
      // User creates 2 of 3 multisig of keys [A, B, C],
      // but key A always can spend whole output without signatures from other keys.
      // p2tr(A, p2tr_ns(2, [B, C, D])) is ok: A or (B and C) or (B and D) or (C and D)
      if (P.equalBytes(p, internalPubKey)) {
        throw new Error(
          'Using P2TR with leaf script with same key as internal key is not supported'
        );
      }
    }
  }
}
function taprootHashTree(
  tree: TaprootScriptTree,
  internalPubKey: Bytes,
  allowUnknownOutputs = false
): HashedTree {
  if (!tree) throw new Error('taprootHashTree: empty tree');
  if (Array.isArray(tree) && tree.length === 1) tree = tree[0];
  // Terminal node (leaf)
  if (!Array.isArray(tree)) {
    const { leafVersion: version, script: leafScript } = tree;
    // Earliest tree walk where we can validate tapScripts
    if (tree.tapLeafScript || (tree.tapMerkleRoot && !P.equalBytes(tree.tapMerkleRoot, P.EMPTY)))
      throw new Error('P2TR: tapRoot leafScript cannot have tree');
    const script = typeof leafScript === 'string' ? hex.decode(leafScript) : leafScript;
    if (!isBytes(script)) throw new Error(`checkScript: wrong script type=${script}`);
    checkTaprootScript(script, internalPubKey, allowUnknownOutputs);
    return {
      type: 'leaf',
      version,
      script,
      hash: tapLeafHash(script, version),
    };
  }
  // If tree / branch is not binary tree, convert it
  if (tree.length !== 2) tree = taprootListToTree(tree as TaprootNode[]) as TaprootNode[];
  if (tree.length !== 2) throw new Error('hashTree: non binary tree!');
  // branch
  // Both nodes should exist
  const left = taprootHashTree(tree[0], internalPubKey, allowUnknownOutputs);
  const right = taprootHashTree(tree[1], internalPubKey, allowUnknownOutputs);
  // We cannot swap left/right here, since it will change structure of tree
  let [lH, rH] = [left.hash, right.hash];
  if (_cmpBytes(rH, lH) === -1) [lH, rH] = [rH, lH];
  return { type: 'branch', left, right, hash: schnorr.utils.taggedHash('TapBranch', lH, rH) };
}
type TaprootLeaf = {
  type: 'leaf';
  version?: number;
  script: Bytes;
  hash: Bytes;
  path: Bytes[];
};

type HashedTreeWithPath =
  | TaprootLeaf
  | {
      type: 'branch';
      left: HashedTreeWithPath;
      right: HashedTreeWithPath;
      hash: Bytes;
      path: Bytes[];
    };

function taprootAddPath(tree: HashedTree, path: Bytes[] = []): HashedTreeWithPath {
  if (!tree) throw new Error(`taprootAddPath: empty tree`);
  if (tree.type === 'leaf') return { ...tree, path };
  if (tree.type !== 'branch') throw new Error(`taprootAddPath: wrong type=${tree}`);
  return {
    ...tree,
    path,
    // Left element has right hash in path and otherwise
    left: taprootAddPath(tree.left, [tree.right.hash, ...path]),
    right: taprootAddPath(tree.right, [tree.left.hash, ...path]),
  };
}
function taprootWalkTree(tree: HashedTreeWithPath): TaprootLeaf[] {
  if (!tree) throw new Error(`taprootAddPath: empty tree`);
  if (tree.type === 'leaf') return [tree];
  if (tree.type !== 'branch') throw new Error(`taprootWalkTree: wrong type=${tree}`);
  return [...taprootWalkTree(tree.left), ...taprootWalkTree(tree.right)];
}

// Another stupid decision, where lack of standard affects security.
// Multisig needs to be generated with some key.
// We are using approach from BIP 341/bitcoinjs-lib: SHA256(uncompressedDER(SECP256K1_GENERATOR_POINT))
// It is possible to switch SECP256K1_GENERATOR_POINT with some random point;
// but it's too complex to prove.
// Also used by bitcoin-core and bitcoinjs-lib
export const TAPROOT_UNSPENDABLE_KEY = sha256(ProjPoint.BASE.toRawBytes(false));

export type P2TROut = P2Ret & {
  tweakedPubkey: Uint8Array;
  tapInternalKey: Uint8Array;
  tapMerkleRoot?: Uint8Array;
  tapLeafScript?: TransactionInput['tapLeafScript'];
  leaves?: TaprootLeaf[];
};
// Works as key OR tree.
// If we only have tree, need to add unspendable key, otherwise
// complex multisig wallet can be spent by owner of key only. See TAPROOT_UNSPENDABLE_KEY
export function p2tr(
  internalPubKey?: Bytes | string,
  tree?: TaprootScriptTree,
  network = NETWORK,
  allowUnknownOutputs = false
): P2TROut {
  // Unspendable
  if (!internalPubKey && !tree) throw new Error('p2tr: should have pubKey or scriptTree (or both)');
  const pubKey =
    typeof internalPubKey === 'string'
      ? hex.decode(internalPubKey)
      : internalPubKey || TAPROOT_UNSPENDABLE_KEY;
  if (!isValidPubkey(pubKey, PubT.schnorr)) throw new Error('p2tr: non-schnorr pubkey');
  let hashedTree = tree
    ? taprootAddPath(taprootHashTree(tree, pubKey, allowUnknownOutputs))
    : undefined;
  const tapMerkleRoot = hashedTree ? hashedTree.hash : undefined;
  const [tweakedPubkey, parity] = taprootTweakPubkey(pubKey, tapMerkleRoot || P.EMPTY);
  let leaves;
  if (hashedTree) {
    leaves = taprootWalkTree(hashedTree).map((l) => ({
      ...l,
      controlBlock: TaprootControlBlock.encode({
        version: (l.version || TAP_LEAF_VERSION) + parity,
        internalKey: pubKey,
        merklePath: l.path,
      }),
    }));
  }
  let tapLeafScript: TransactionInput['tapLeafScript'];
  if (leaves) {
    tapLeafScript = leaves.map((l) => [
      TaprootControlBlock.decode(l.controlBlock),
      concat(l.script, new Uint8Array([l.version || TAP_LEAF_VERSION])),
    ]);
  }
  const res: P2TROut = {
    type: 'tr',
    script: OutScript.encode({ type: 'tr', pubkey: tweakedPubkey }),
    address: Address(network).encode({ type: 'tr', pubkey: tweakedPubkey }),
    // For tests
    tweakedPubkey,
    // PSBT stuff
    tapInternalKey: pubKey,
  };
  // Just in case someone would want to select a specific script
  if (leaves) res.leaves = leaves;
  if (tapLeafScript) res.tapLeafScript = tapLeafScript;
  if (tapMerkleRoot) res.tapMerkleRoot = tapMerkleRoot;
  return res;
}

// Taproot N-of-N multisig (P2TR_NS)
type OutTRNSType = { type: 'tr_ns'; pubkeys: Bytes[] };
const OutTRNS: Coder<OptScript, OutTRNSType | undefined> = {
  encode(from: ScriptType): OutTRNSType | undefined {
    const last = from.length - 1;
    if (from[last] !== 'CHECKSIG') return;
    const pubkeys = [];
    // On error return, since it can be different script
    for (let i = 0; i < last; i++) {
      const elm = from[i];
      if (i & 1) {
        if (elm !== 'CHECKSIGVERIFY' || i === last - 1) return;
        continue;
      }
      if (!isBytes(elm)) return;
      pubkeys.push(elm);
    }
    return { type: 'tr_ns', pubkeys };
  },
  decode: (to: OutTRNSType): OptScript => {
    if (to.type !== 'tr_ns') return;
    const out: ScriptType = [];
    for (let i = 0; i < to.pubkeys.length - 1; i++) out.push(to.pubkeys[i], 'CHECKSIGVERIFY');
    out.push(to.pubkeys[to.pubkeys.length - 1], 'CHECKSIG');
    return out;
  },
};
// Returns all combinations of size M from lst
export function combinations<T>(m: number, list: T[]): T[][] {
  const res: T[][] = [];
  if (!Array.isArray(list)) throw new Error('combinations: lst arg should be array');
  const n = list.length;
  if (m > n) throw new Error('combinations: m > lst.length, no combinations possible');
  /*
  Basically works as M nested loops like:
  for (;idx[0]<lst.length;idx[0]++) for (idx[1]=idx[0]+1;idx[1]<lst.length;idx[1]++)
  but since we cannot create nested loops dynamically, we unroll it to a single loop
  */
  const idx = Array.from({ length: m }, (_, i) => i);
  const last = idx.length - 1;
  main: for (;;) {
    res.push(idx.map((i) => list[i]));
    idx[last] += 1;
    let i = last;
    // Propagate increment
    // idx[i] cannot be bigger than n-m+i, otherwise last elements in right part will overflow
    for (; i >= 0 && idx[i] > n - m + i; i--) {
      idx[i] = 0;
      // Overflow in idx[0], break
      if (i === 0) break main;
      idx[i - 1] += 1;
    }
    // Propagate: idx[i+1] = idx[idx]+1
    for (i += 1; i < idx.length; i++) idx[i] = idx[i - 1] + 1;
  }
  return res;
}
/**
 * M-of-N multi-leaf wallet via p2tr_ns. If m == n, single script is emitted.
 * Takes O(n^2) if m != n. 99-of-100 is ok, 5-of-100 is not.
 * `2-of-[A,B,C] => [A,B] | [A,C] | [B,C]`
 */
export const p2tr_ns = (m: number, pubkeys: Bytes[], allowSamePubkeys = false): P2Ret[] => {
  if (!allowSamePubkeys) uniqPubkey(pubkeys);
  return combinations(m, pubkeys).map((i) => ({
    type: 'tr_ns',
    script: OutScript.encode({ type: 'tr_ns', pubkeys: i }),
  }));
};
// Taproot public key (case of p2tr_ns)
export const p2tr_pk = (pubkey: Bytes): P2Ret => p2tr_ns(1, [pubkey], undefined)[0];

// Taproot M-of-N Multisig (P2TR_MS)
type OutTRMSType = { type: 'tr_ms'; pubkeys: Bytes[]; m: number };
const OutTRMS: Coder<OptScript, OutTRMSType | undefined> = {
  encode(from: ScriptType): OutTRMSType | undefined {
    const last = from.length - 1;
    if (from[last] !== 'NUMEQUAL' || from[1] !== 'CHECKSIG') return;
    const pubkeys = [];
    const m = OpToNum(from[last - 1]);
    if (typeof m !== 'number') return;
    for (let i = 0; i < last - 1; i++) {
      const elm = from[i];
      if (i & 1) {
        if (elm !== (i === 1 ? 'CHECKSIG' : 'CHECKSIGADD'))
          throw new Error('OutScript.encode/tr_ms: wrong element');
        continue;
      }
      if (!isBytes(elm)) throw new Error('OutScript.encode/tr_ms: wrong key element');
      pubkeys.push(elm);
    }
    return { type: 'tr_ms', pubkeys, m };
  },
  decode: (to: OutTRMSType): OptScript => {
    if (to.type !== 'tr_ms') return;
    const out: ScriptType = [to.pubkeys[0], 'CHECKSIG'];
    for (let i = 1; i < to.pubkeys.length; i++) out.push(to.pubkeys[i], 'CHECKSIGADD');
    out.push(to.m, 'NUMEQUAL');
    return out;
  },
};
export function p2tr_ms(m: number, pubkeys: Bytes[], allowSamePubkeys = false) {
  if (!allowSamePubkeys) uniqPubkey(pubkeys);
  return {
    type: 'tr_ms',
    script: OutScript.encode({ type: 'tr_ms', pubkeys, m }),
  };
}
// Unknown output type
type OutUnknownType = { type: 'unknown'; script: Bytes };
const OutUnknown: Coder<OptScript, OutUnknownType | undefined> = {
  encode(from: ScriptType): OutUnknownType | undefined {
    return { type: 'unknown', script: Script.encode(from) };
  },
  decode: (to: OutUnknownType): OptScript =>
    to.type === 'unknown' ? Script.decode(to.script) : undefined,
};
// /Payments

const OutScripts = [
  OutPK,
  OutPKH,
  OutSH,
  OutWSH,
  OutWPKH,
  OutMS,
  OutTR,
  OutTRNS,
  OutTRMS,
  OutUnknown,
];
// TODO: we can support user supplied output scripts now
// - addOutScript
// - removeOutScript
// - We can do that as log we modify array in-place
// - Actually is very hard, since there is sign/finalize logic
const _OutScript = P.apply(Script, P.coders.match(OutScripts));

// We can validate this once, because of packed & coders
export const OutScript = P.validate(_OutScript, (i) => {
  if (i.type === 'pk' && !isValidPubkey(i.pubkey, PubT.ecdsa))
    throw new Error('OutScript/pk: wrong key');
  if (
    (i.type === 'pkh' || i.type === 'sh' || i.type === 'wpkh') &&
    (!isBytes(i.hash) || i.hash.length !== 20)
  )
    throw new Error(`OutScript/${i.type}: wrong hash`);
  if (i.type === 'wsh' && (!isBytes(i.hash) || i.hash.length !== 32))
    throw new Error(`OutScript/wsh: wrong hash`);
  if (i.type === 'tr' && (!isBytes(i.pubkey) || !isValidPubkey(i.pubkey, PubT.schnorr)))
    throw new Error('OutScript/tr: wrong taproot public key');
  if (i.type === 'ms' || i.type === 'tr_ns' || i.type === 'tr_ms')
    if (!Array.isArray(i.pubkeys)) throw new Error('OutScript/multisig: wrong pubkeys array');
  if (i.type === 'ms') {
    const n = i.pubkeys.length;
    for (const p of i.pubkeys)
      if (!isValidPubkey(p, PubT.ecdsa)) throw new Error('OutScript/multisig: wrong pubkey');
    if (i.m <= 0 || n > 16 || i.m > n) throw new Error('OutScript/multisig: invalid params');
  }
  if (i.type === 'tr_ns' || i.type === 'tr_ms') {
    for (const p of i.pubkeys)
      if (!isValidPubkey(p, PubT.schnorr)) throw new Error(`OutScript/${i.type}: wrong pubkey`);
  }
  if (i.type === 'tr_ms') {
    const n = i.pubkeys.length;
    if (i.m <= 0 || n > 999 || i.m > n) throw new Error('OutScript/tr_ms: invalid params');
  }
  return i;
});

// Address
function validateWitness(version: number, data: Bytes) {
  if (data.length < 2 || data.length > 40) throw new Error('Witness: invalid length');
  if (version > 16) throw new Error('Witness: invalid version');
  if (version === 0 && !(data.length === 20 || data.length === 32))
    throw new Error('Witness: invalid length for version');
}

export function programToWitness(version: number, data: Bytes, network = NETWORK) {
  validateWitness(version, data);
  const coder = version === 0 ? bech32 : bech32m;
  return coder.encode(network.bech32, [version].concat(coder.toWords(data)));
}

function formatKey(hashed: Bytes, prefix: number[]): string {
  return base58check.encode(concat(Uint8Array.from(prefix), hashed));
}

export function WIF(network = NETWORK): Coder<Bytes, string> {
  return {
    encode(privKey: Bytes) {
      const compressed = concat(privKey, new Uint8Array([0x01]));
      return formatKey(compressed.subarray(0, 33), [network.wif]);
    },
    decode(wif: string) {
      let parsed = base58check.decode(wif);
      if (parsed[0] !== network.wif) throw new Error('Wrong WIF prefix');
      parsed = parsed.subarray(1);
      // Check what it is. Compressed flag?
      if (parsed.length !== 33) throw new Error('Wrong WIF length');
      if (parsed[32] !== 0x01) throw new Error('Wrong WIF postfix');
      return parsed.subarray(0, -1);
    },
  };
}

// Returns OutType, which can be used to create outscript
export function Address(network = NETWORK) {
  return {
    encode(from: P.UnwrapCoder<typeof OutScript>): string {
      const { type } = from;
      if (type === 'wpkh') return programToWitness(0, from.hash, network);
      else if (type === 'wsh') return programToWitness(0, from.hash, network);
      else if (type === 'tr') return programToWitness(1, from.pubkey, network);
      else if (type === 'pkh') return formatKey(from.hash, [network.pubKeyHash]);
      else if (type === 'sh') return formatKey(from.hash, [network.scriptHash]);
      throw new Error(`Unknown address type=${type}`);
    },
    decode(address: string): P.UnwrapCoder<typeof OutScript> {
      if (address.length < 14 || address.length > 74) throw new Error('Invalid address length');
      // Bech32
      if (network.bech32 && address.toLowerCase().startsWith(network.bech32)) {
        let res;
        try {
          res = bech32.decode(address);
          if (res.words[0] !== 0) throw new Error(`bech32: wrong version=${res.words[0]}`);
        } catch (_) {
          // Starting from version 1 it is decoded as bech32m
          res = bech32m.decode(address);
          if (res.words[0] === 0) throw new Error(`bech32m: wrong version=${res.words[0]}`);
        }
        if (res.prefix !== network.bech32) throw new Error(`wrong bech32 prefix=${res.prefix}`);
        const [version, ...program] = res.words;
        const data = bech32.fromWords(program);
        validateWitness(version, data);
        if (version === 0 && data.length === 32) return { type: 'wsh', hash: data };
        else if (version === 0 && data.length === 20) return { type: 'wpkh', hash: data };
        else if (version === 1 && data.length === 32) return { type: 'tr', pubkey: data };
        else throw new Error('Unknown witness program');
      }
      const data = base58check.decode(address);
      if (data.length !== 21) throw new Error('Invalid base58 address');
      // Pay To Public Key Hash
      if (data[0] === network.pubKeyHash) {
        return { type: 'pkh', hash: data.slice(1) };
      } else if (data[0] === network.scriptHash) {
        return {
          type: 'sh',
          hash: data.slice(1),
        };
      }
      throw new Error(`Invalid address prefix=${data[0]}`);
    },
  };
}
// /Address

/**
 * Internal, exported only for backwards-compat. Use `SigHash` instead.
 * @deprecated
 */
export enum SignatureHash {
  DEFAULT,
  ALL,
  NONE,
  SINGLE,
  ANYONECANPAY = 0x80,
}

export enum SigHash {
  DEFAULT = SignatureHash.DEFAULT,
  ALL = SignatureHash.ALL,
  NONE = SignatureHash.NONE,
  SINGLE = SignatureHash.SINGLE,
  DEFAULT_ANYONECANPAY = SignatureHash.DEFAULT | SignatureHash.ANYONECANPAY,
  ALL_ANYONECANPAY = SignatureHash.ALL | SignatureHash.ANYONECANPAY,
  NONE_ANYONECANPAY = SignatureHash.NONE | SignatureHash.ANYONECANPAY,
  SINGLE_ANYONECANPAY = SignatureHash.SINGLE | SignatureHash.ANYONECANPAY,
}

function validateSigHash(s: SigHash) {
  if (typeof s !== 'number' || typeof SigHash[s] !== 'string')
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

export const _sortPubkeys = (pubkeys: Bytes[]) => Array.from(pubkeys).sort(_cmpBytes);

export type TransactionInput = P.UnwrapCoder<typeof PSBTInputCoder>;
// User facing API with decoders
export type TransactionInputUpdate = ExtendType<
  TransactionInput,
  {
    nonWitnessUtxo?: string | Bytes;
    txid?: string;
  }
>;
export type TransactionInputRequired = {
  txid: Bytes;
  index: number;
  sequence: number;
  finalScriptSig: Bytes;
};
// Force check index/txid/sequence
function inputBeforeSign(i: TransactionInput): TransactionInputRequired {
  if (i.txid === undefined || i.index === undefined)
    throw new Error('Transaction/input: txid and index required');
  return {
    txid: i.txid,
    index: i.index,
    sequence: def(i.sequence, DEFAULT_SEQUENCE),
    finalScriptSig: def(i.finalScriptSig, P.EMPTY),
  };
}
function cleanFinalInput(i: TransactionInput) {
  for (const _k in i) {
    const k = _k as keyof TransactionInput;
    if (!PSBTInputFinalKeys.includes(k)) delete i[k];
  }
}

export type TransactionOutput = P.UnwrapCoder<typeof PSBTOutputCoder>;
export type TransactionOutputUpdate = ExtendType<TransactionOutput, { script?: string }>;
export type TransactionOutputRequired = {
  script: Bytes;
  amount: bigint;
};
// Force check amount/script
function outputBeforeSign(i: TransactionOutput): TransactionOutputRequired {
  if (i.script === undefined || i.amount === undefined)
    throw new Error('Transaction/output: script and amount required');
  return { script: i.script, amount: i.amount };
}

export const TAP_LEAF_VERSION = 0xc0;
export const tapLeafHash = (script: Bytes, version = TAP_LEAF_VERSION) =>
  schnorr.utils.taggedHash('TapLeaf', new Uint8Array([version]), VarBytes.encode(script));

function getTaprootKeys(
  privKey: Bytes,
  pubKey: Bytes,
  internalKey: Bytes,
  merkleRoot: Bytes = P.EMPTY
) {
  if (P.equalBytes(internalKey, pubKey)) {
    privKey = taprootTweakPrivKey(privKey, merkleRoot);
    pubKey = schnorr.getPublicKey(privKey);
  }
  return { privKey, pubKey };
}

// @scure/bip32 interface
interface HDKey {
  publicKey: Bytes;
  privateKey: Bytes;
  fingerprint: number;
  derive(path: string): HDKey;
  deriveChild(index: number): HDKey;
  sign(hash: Bytes): Bytes;
}

export type Signer = Bytes | HDKey;

// Mostly security features, hardened defaults;
// but you still can parse other people tx with unspendable outputs and stuff if you want
export type TxOpts = {
  version?: number;
  lockTime?: number;
  PSBTVersion?: number;
  // Flags
  // Allow output scripts to be unknown scripts (probably unspendable)
  /** @deprecated Use `allowUnknownOutputs` */
  allowUnknowOutput?: boolean;
  allowUnknownOutputs?: boolean;
  // Try to sign/finalize unknown input. All bets are off, but there is chance that it will work
  /** @deprecated Use `allowUnknownInputs` */
  allowUnknowInput?: boolean;
  allowUnknownInputs?: boolean;
  // Check input/output scripts for sanity
  disableScriptCheck?: boolean;
  // There is strange behaviour where tx without outputs encoded with empty output in the end,
  // tx without outputs in BIP174 doesn't have itb
  bip174jsCompat?: boolean;
  // If transaction data comes from untrusted source, then it can be modified in such way that will
  // result paying higher mining fee
  allowLegacyWitnessUtxo?: boolean;
  lowR?: boolean; // Use lowR signatures
};

const toStr = {}.toString;
function validateOpts(opts: TxOpts) {
  if (opts !== undefined && toStr.call(opts) !== '[object Object]')
    throw new Error(`Wrong object type for transaction options: ${opts}`);

  const _opts = {
    ...opts,
    // Defaults
    version: def(opts.version, DEFAULT_VERSION),
    lockTime: def(opts.lockTime, 0),
    PSBTVersion: def(opts.PSBTVersion, 0),
  };
  if (typeof _opts.allowUnknowInput !== 'undefined')
    opts.allowUnknownInputs = _opts.allowUnknowInput;
  if (typeof _opts.allowUnknowOutput !== 'undefined')
    opts.allowUnknownOutputs = _opts.allowUnknowOutput;
  // 0 and -1 happens in tests
  if (![-1, 0, 1, 2].includes(_opts.version)) throw new Error(`Unknown version: ${_opts.version}`);
  if (typeof _opts.lockTime !== 'number') throw new Error('Transaction lock time should be number');
  P.U32LE.encode(_opts.lockTime); // Additional range checks that lockTime
  // There is no PSBT v1, and any new version will probably have fields which we don't know how to parse, which
  // can lead to constructing broken transactions
  if (_opts.PSBTVersion !== 0 && _opts.PSBTVersion !== 2)
    throw new Error(`Unknown PSBT version ${_opts.PSBTVersion}`);
  // Flags
  for (const k of [
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
  return Object.freeze(_opts);
}

export class Transaction {
  private global: PSBTKeyMapKeys<typeof PSBTGlobal> = {};
  private inputs: TransactionInput[] = []; // use getInput()
  private outputs: TransactionOutput[] = []; // use getOutput()
  readonly opts: ReturnType<typeof validateOpts>;
  constructor(opts: TxOpts = {}) {
    const _opts = (this.opts = validateOpts(opts));
    // Merge with global structure of PSBTv2
    if (_opts.lockTime !== DEFAULT_LOCKTIME) this.global.fallbackLocktime = _opts.lockTime;
    this.global.txVersion = _opts.version;
  }

  // Import
  static fromRaw(raw: Bytes, opts: TxOpts = {}) {
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
  static fromPSBT(psbt: Bytes, opts: TxOpts = {}) {
    let parsed: P.UnwrapCoder<typeof RawPSBTV0>;
    try {
      parsed = RawPSBTV0.decode(psbt);
    } catch (e0) {
      try {
        parsed = RawPSBTV2.decode(psbt);
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
    tx.inputs = parsed.inputs.slice(0, inputCount).map((i, j) => ({
      finalScriptSig: P.EMPTY,
      ...parsed.global.unsignedTx?.inputs[j],
      ...i,
    }));
    const outputCount = PSBTVersion === 0 ? unsigned?.outputs.length : parsed.global.outputCount;
    tx.outputs = parsed.outputs.slice(0, outputCount).map((i, j) => ({
      ...i,
      ...parsed.global.unsignedTx?.outputs[j],
    }));
    tx.global = { ...parsed.global, txVersion: version }; // just in case proprietary/unknown fields
    if (lockTime !== DEFAULT_LOCKTIME) tx.global.fallbackLocktime = lockTime;
    return tx;
  }
  toPSBT(PSBTVersion = this.opts.PSBTVersion) {
    if (PSBTVersion !== 0 && PSBTVersion !== 2)
      throw new Error(`Wrong PSBT version=${PSBTVersion}`);
    const inputs = this.inputs.map((i) => cleanPSBTFields(PSBTVersion, PSBTInput, i));
    for (const inp of inputs) {
      // Don't serialize empty fields
      if (inp.partialSig && !inp.partialSig.length) delete inp.partialSig;
      if (inp.finalScriptSig && !inp.finalScriptSig.length) delete inp.finalScriptSig;
      if (inp.finalScriptWitness && !inp.finalScriptWitness.length) delete inp.finalScriptWitness;
    }
    const outputs = this.outputs.map((i) => cleanPSBTFields(PSBTVersion, PSBTOutput, i));
    const global = { ...this.global };
    if (PSBTVersion === 0) {
      global.unsignedTx = RawTx.decode(this.unsignedTx);
      delete global.fallbackLocktime;
      delete global.txVersion;
    } else {
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
    return (PSBTVersion === 0 ? RawPSBTV0 : RawPSBTV2).encode({
      global,
      inputs,
      outputs,
    });
  }

  // BIP370 lockTime (https://github.com/bitcoin/bips/blob/master/bip-0370.mediawiki#determining-lock-time)
  get lockTime() {
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

  get version() {
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
    const sighash = this.inputType(this.inputs[idx]).sighash;
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

  get isFinal() {
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
    // TODO: Can we find out how much witnesses/script will be used before signing?
    let out = 32;
    const outputs = this.outputs.map(outputBeforeSign);
    if (this.hasWitnesses) out += 2;
    out += 4 * CompactSizeLen.encode(this.inputs.length).length;
    out += 4 * CompactSizeLen.encode(this.outputs.length).length;
    for (const i of this.inputs)
      out += 160 + 4 * VarBytes.encode(i.finalScriptSig || P.EMPTY).length;
    for (const o of outputs) out += 32 + 4 * VarBytes.encode(o.script).length;
    if (this.hasWitnesses) {
      for (const i of this.inputs)
        if (i.finalScriptWitness) out += RawWitness.encode(i.finalScriptWitness).length;
    }
    return out;
  }
  get vsize(): number {
    return Math.ceil(this.weight / 4);
  }
  toBytes(withScriptSig = false, withWitness = false) {
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
  get hex() {
    return hex.encode(this.toBytes(true, this.hasWitnesses));
  }

  get hash() {
    if (!this.isFinal) throw new Error('Transaction is not finalized');
    return hex.encode(sha256x2(this.toBytes(true)));
  }
  get id() {
    if (!this.isFinal) throw new Error('Transaction is not finalized');
    return hex.encode(sha256x2(this.toBytes(true)).reverse());
  }
  // Input stuff
  private checkInputIdx(idx: number) {
    if (!Number.isSafeInteger(idx) || 0 > idx || idx >= this.inputs.length)
      throw new Error(`Wrong input index=${idx}`);
  }
  getInput(idx: number) {
    this.checkInputIdx(idx);
    return cloneDeep(this.inputs[idx]);
  }
  get inputsLength() {
    return this.inputs.length;
  }
  // Modification
  private normalizeInput(
    i: TransactionInputUpdate,
    cur?: TransactionInput,
    allowedFields?: (keyof TransactionInput)[]
  ): TransactionInput {
    let { nonWitnessUtxo, txid } = i;
    // String support for common fields. We usually prefer Uint8Array to avoid errors (like hex looking string accidentally passed),
    // however in case of nonWitnessUtxo it is better to expect string, since constructing this complex object will be difficult for user
    if (typeof nonWitnessUtxo === 'string') nonWitnessUtxo = hex.decode(nonWitnessUtxo);
    if (isBytes(nonWitnessUtxo)) nonWitnessUtxo = RawTx.decode(nonWitnessUtxo);
    if (nonWitnessUtxo === undefined) nonWitnessUtxo = cur?.nonWitnessUtxo;
    if (typeof txid === 'string') txid = hex.decode(txid);
    if (txid === undefined) txid = cur?.txid;
    let res: PSBTKeyMapKeys<typeof PSBTInput> = { ...cur, ...i, nonWitnessUtxo, txid };
    if (res.nonWitnessUtxo === undefined) delete res.nonWitnessUtxo;
    if (res.sequence === undefined) res.sequence = DEFAULT_SEQUENCE;
    if (res.tapMerkleRoot === null) delete res.tapMerkleRoot;
    res = mergeKeyMap(PSBTInput, res, cur, allowedFields);
    PSBTInputCoder.encode(res); // Validates that everything is correct at this point

    let prevOut;
    if (res.nonWitnessUtxo && res.index !== undefined)
      prevOut = res.nonWitnessUtxo.outputs[res.index];
    else if (res.witnessUtxo) prevOut = res.witnessUtxo;
    if (prevOut && !this.opts.disableScriptCheck)
      checkScript(prevOut && prevOut.script, res.redeemScript, res.witnessScript);

    return res;
  }
  addInput(input: TransactionInputUpdate, _ignoreSignStatus = false): number {
    if (!_ignoreSignStatus && !this.signStatus().addInput)
      throw new Error('Tx has signed inputs, cannot add new one');
    this.inputs.push(this.normalizeInput(input));
    return this.inputs.length - 1;
  }
  updateInput(idx: number, input: TransactionInputUpdate, _ignoreSignStatus = false) {
    this.checkInputIdx(idx);
    let allowedFields = undefined;
    if (!_ignoreSignStatus) {
      const status = this.signStatus();
      if (!status.addInput || status.inputs.includes(idx)) allowedFields = PSBTInputUnsignedKeys;
    }
    this.inputs[idx] = this.normalizeInput(input, this.inputs[idx], allowedFields);
  }
  // Output stuff
  private checkOutputIdx(idx: number) {
    if (!Number.isSafeInteger(idx) || 0 > idx || idx >= this.outputs.length)
      throw new Error(`Wrong output index=${idx}`);
  }
  getOutput(idx: number) {
    this.checkOutputIdx(idx);
    return cloneDeep(this.outputs[idx]);
  }
  get outputsLength() {
    return this.outputs.length;
  }
  private normalizeOutput(
    o: TransactionOutputUpdate,
    cur?: TransactionOutput,
    allowedFields?: (keyof typeof PSBTOutput)[]
  ): TransactionOutput {
    let { amount, script } = o;
    if (amount === undefined) amount = cur?.amount;
    if (typeof amount !== 'bigint') throw new Error('amount must be bigint sats');
    if (typeof script === 'string') script = hex.decode(script);
    if (script === undefined) script = cur?.script;
    let res: PSBTKeyMapKeys<typeof PSBTOutput> = { ...cur, ...o, amount, script };
    if (res.amount === undefined) delete res.amount;
    res = mergeKeyMap(PSBTOutput, res, cur, allowedFields);
    PSBTOutputCoder.encode(res);
    if (
      res.script &&
      !this.opts.allowUnknownOutputs &&
      OutScript.decode(res.script).type === 'unknown'
    ) {
      throw new Error(
        'Transaction/output: unknown output script type, there is a chance that input is unspendable. Pass allowUnknownScript=true, if you sure'
      );
    }
    if (!this.opts.disableScriptCheck) checkScript(res.script, res.redeemScript, res.witnessScript);
    return res;
  }
  addOutput(o: TransactionOutputUpdate, _ignoreSignStatus = false): number {
    if (!_ignoreSignStatus && !this.signStatus().addOutput)
      throw new Error('Tx has signed outputs, cannot add new one');
    this.outputs.push(this.normalizeOutput(o));
    return this.outputs.length - 1;
  }
  updateOutput(idx: number, output: TransactionOutputUpdate, _ignoreSignStatus = false) {
    this.checkOutputIdx(idx);
    let allowedFields = undefined;
    if (!_ignoreSignStatus) {
      const status = this.signStatus();
      if (!status.addOutput || status.outputs.includes(idx)) allowedFields = PSBTOutputUnsignedKeys;
    }
    this.outputs[idx] = this.normalizeOutput(output, this.outputs[idx], allowedFields);
  }
  addOutputAddress(address: string, amount: bigint, network = NETWORK): number {
    return this.addOutput({ script: OutScript.encode(Address(network).decode(address)), amount });
  }
  // Utils
  get fee(): bigint {
    let res = 0n;
    for (const i of this.inputs) {
      const prevOut = this.prevOut(i);
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
    prevOutScript = Script.encode(
      Script.decode(prevOutScript).filter((i) => i !== 'CODESEPARATOR')
    );
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
      outputs = outputs.slice(0, idx).fill(EMPTY_OUTPUT).concat([outputs[idx]]);
    }
    const tmpTx = RawTx.encode({
      lockTime: this.lockTime,
      version: this.version,
      segwitFlag: false,
      inputs,
      outputs,
    });
    return sha256x2(tmpTx, P.I32LE.encode(hashType));
  }
  private preimageWitnessV0(idx: number, prevOutScript: Bytes, hashType: number, amount: bigint) {
    const { isAny, isNone, isSingle } = unpackSighash(hashType);
    let inputHash = EMPTY32;
    let sequenceHash = EMPTY32;
    let outputHash = EMPTY32;
    const inputs = this.inputs.map(inputBeforeSign);
    const outputs = this.outputs.map(outputBeforeSign);
    if (!isAny) inputHash = sha256x2(...inputs.map(TxHashIdx.encode));
    if (!isAny && !isSingle && !isNone)
      sequenceHash = sha256x2(...inputs.map((i) => P.U32LE.encode(i.sequence)));
    if (!isSingle && !isNone) {
      outputHash = sha256x2(...outputs.map(RawOutput.encode));
    } else if (isSingle && idx < outputs.length)
      outputHash = sha256x2(RawOutput.encode(outputs[idx]));
    const input = inputs[idx];
    return sha256x2(
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
  private preimageWitnessV1(
    idx: number,
    prevOutScript: Bytes[],
    hashType: number,
    amount: bigint[],
    codeSeparator = -1,
    leafScript?: Bytes,
    leafVer = 0xc0,
    annex?: Bytes
  ) {
    if (!Array.isArray(amount) || this.inputs.length !== amount.length)
      throw new Error(`Invalid amounts array=${amount}`);
    if (!Array.isArray(prevOutScript) || this.inputs.length !== prevOutScript.length)
      throw new Error(`Invalid prevOutScript array=${prevOutScript}`);
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
        ].map((i) => sha256(concat(...i)))
      );
    }
    if (outType === SignatureHash.ALL) {
      out.push(sha256(concat(...outputs.map(RawOutput.encode))));
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
    if (spendType & 1) out.push(sha256(VarBytes.encode(annex || P.EMPTY)));
    if (outType === SignatureHash.SINGLE)
      out.push(idx < outputs.length ? sha256(RawOutput.encode(outputs[idx])) : EMPTY32);
    if (leafScript)
      out.push(tapLeafHash(leafScript, leafVer), P.U8.encode(0), P.I32LE.encode(codeSeparator));
    return schnorr.utils.taggedHash('TapSighash', ...out);
  }
  // Utils for sign/finalize
  // Used pretty often, should be fast
  private prevOut(input: TransactionInput): P.UnwrapCoder<typeof RawOutput> {
    if (input.nonWitnessUtxo) {
      if (input.index === undefined) throw new Error('Unknown input index');
      return input.nonWitnessUtxo.outputs[input.index];
    } else if (input.witnessUtxo) return input.witnessUtxo;
    else throw new Error('Cannot find previous output info');
  }
  private inputType(input: TransactionInput) {
    let txType = 'legacy';
    let defaultSighash = SignatureHash.ALL;
    const prevOut = this.prevOut(input);
    const first = OutScript.decode(prevOut.script);
    let type = first.type;
    let cur = first;
    const stack = [first];
    if (first.type === 'tr') {
      defaultSighash = SignatureHash.DEFAULT;
      return {
        txType: 'taproot',
        type: 'tr',
        last: first,
        lastScript: prevOut.script,
        defaultSighash,
        sighash: input.sighashType || defaultSighash,
      };
    } else {
      if (first.type === 'wpkh' || first.type === 'wsh') txType = 'segwit';
      if (first.type === 'sh') {
        if (!input.redeemScript) throw new Error('inputType: sh without redeemScript');
        let child = OutScript.decode(input.redeemScript);
        if (child.type === 'wpkh' || child.type === 'wsh') txType = 'segwit';
        stack.push(child);
        cur = child;
        type += `-${child.type}`;
      }
      // wsh can be inside sh
      if (cur.type === 'wsh') {
        if (!input.witnessScript) throw new Error('inputType: wsh without witnessScript');
        let child = OutScript.decode(input.witnessScript);
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
        sighash: input.sighashType || defaultSighash,
      };
      if (txType === 'legacy' && !this.opts.allowLegacyWitnessUtxo && !input.nonWitnessUtxo) {
        throw new Error(
          `Transaction/sign: legacy input without nonWitnessUtxo, can result in attack that forces paying higher fees. Pass allowLegacyWitnessUtxo=true, if you sure`
        );
      }
      return res;
    }
  }

  // Signer can be privateKey OR instance of bip32 HD stuff
  signIdx(privateKey: Signer, idx: number, allowedSighash?: SigHash[], _auxRand?: Bytes): boolean {
    this.checkInputIdx(idx);
    const input = this.inputs[idx];
    const inputType = this.inputType(input);
    // Handle BIP32 HDKey
    if (!isBytes(privateKey)) {
      if (!input.bip32Derivation || !input.bip32Derivation.length)
        throw new Error('bip32Derivation: empty');
      const signers = input.bip32Derivation
        .filter((i) => i[1].fingerprint == (privateKey as HDKey).fingerprint)
        .map(([pubKey, { path }]) => {
          let s = privateKey as HDKey;
          for (const i of path) s = s.deriveChild(i);
          if (!P.equalBytes(s.publicKey, pubKey)) throw new Error('bip32Derivation: wrong pubKey');
          if (!s.privateKey) throw new Error('bip32Derivation: no privateKey');
          return s;
        });
      if (!signers.length)
        throw new Error(`bip32Derivation: no items with fingerprint=${privateKey.fingerprint}`);
      let signed = false;
      for (const s of signers) if (this.signIdx(s.privateKey, idx)) signed = true;
      return signed;
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
    const prevOut = this.prevOut(input);
    if (inputType.txType === 'taproot') {
      if (input.tapBip32Derivation) throw new Error('tapBip32Derivation unsupported');
      const prevOuts = this.inputs.map(this.prevOut);
      const prevOutScript = prevOuts.map((i) => i.script);
      const amount = prevOuts.map((i) => i.amount);
      let signed = false;
      let schnorrPub = schnorr.getPublicKey(privateKey);
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
        const [taprootPubKey, _] = taprootTweakPubkey(input.tapInternalKey, merkleRoot);
        if (P.equalBytes(taprootPubKey, pubKey)) {
          const hash = this.preimageWitnessV1(idx, prevOutScript, sighash, amount);
          const sig = concat(
            schnorr.sign(hash, privKey, _auxRand),
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
          const pos = scriptDecoded.findIndex((i) => isBytes(i) && P.equalBytes(i, schnorrPub));
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
          const sig = concat(
            schnorr.sign(msg, privateKey, _auxRand),
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
      const pubKey = _pubECDSA(privateKey);
      // TODO: replace with explicit checks
      // Check if script has public key or its has inside
      let hasPubkey = false;
      const pubKeyHash = hash160(pubKey);
      for (const i of Script.decode(inputType.lastScript)) {
        if (isBytes(i) && (P.equalBytes(i, pubKey) || P.equalBytes(i, pubKeyHash)))
          hasPubkey = true;
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
      const sig = signECDSA(hash, privateKey, this.opts.lowR);
      this.updateInput(
        idx,
        {
          partialSig: [[pubKey, concat(sig, new Uint8Array([sighash]))]],
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

  finalizeIdx(idx: number) {
    this.checkInputIdx(idx);
    if (this.fee < 0n) throw new Error('Outputs spends more than inputs amount');
    const input = this.inputs[idx];
    const inputType = this.inputType(input);
    // Taproot finalize
    if (inputType.txType === 'taproot') {
      if (input.tapKeySig) input.finalScriptWitness = [input.tapKeySig];
      else if (input.tapLeafScript && input.tapScriptSig) {
        // Sort leafs by control block length.
        const leafs = input.tapLeafScript.sort(
          (a, b) =>
            TaprootControlBlock.encode(a[0]).length - TaprootControlBlock.encode(b[0]).length
        );
        for (const [cb, _script] of leafs) {
          // Last byte is version
          const script = _script.slice(0, -1);
          const ver = _script[_script.length - 1];
          const outScript = OutScript.decode(script);
          const hash = tapLeafHash(script, ver);
          const scriptSig = input.tapScriptSig.filter((i) => P.equalBytes(i[0].leafHash, hash));
          let signatures: Bytes[] = [];
          if (outScript.type === 'tr_ms') {
            const m = outScript.m;
            const pubkeys = outScript.pubkeys;
            let added = 0;
            for (const pub of pubkeys) {
              const sigIdx = scriptSig.findIndex((i) => P.equalBytes(i[0].pubKey, pub));
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
              const sigIdx = scriptSig.findIndex((i) => P.equalBytes(i[0].pubKey, pub));
              if (sigIdx === -1) continue;
              signatures.push(scriptSig[sigIdx][1]);
            }
            if (signatures.length !== outScript.pubkeys.length) continue;
          } else if (outScript.type === 'unknown' && this.opts.allowUnknownInputs) {
            // Trying our best to sign what we can
            const scriptDecoded = Script.decode(script);
            signatures = scriptSig
              .map(([{ pubKey }, signature]) => {
                const pos = scriptDecoded.findIndex((i) => isBytes(i) && P.equalBytes(i, pubKey));
                if (pos === -1)
                  throw new Error('finalize/taproot: cannot find position of pubkey in script');
                return { signature, pos };
              })
              // Reverse order (because witness is stack and we take last element first from it)
              .sort((a, b) => a.pos - b.pos)
              .map((i) => i.signature);
            if (!signatures.length) continue;
          } else throw new Error('Finalize: Unknown tapLeafScript');
          // Witness is stack, so last element will be used first
          input.finalScriptWitness = signatures
            .reverse()
            .concat([script, TaprootControlBlock.encode(cb)]);
          break;
        }
        if (!input.finalScriptWitness) throw new Error('finalize/taproot: empty witness');
      } else throw new Error('finalize/taproot: unknown input');
      input.finalScriptSig = P.EMPTY;
      cleanFinalInput(input);
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
        const sign = input.partialSig.find((s) => P.equalBytes(pub, s[0]));
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
      finalScriptSig = Script.encode([Script.encode([0, sha256(inputType.lastScript)])]);
    } else if (inputType.type.startsWith('sh-')) {
      finalScriptSig = Script.encode([...Script.decode(inputScript), inputType.lastScript]);
    } else if (inputType.type.startsWith('wsh-')) {
    } else if (inputType.txType !== 'segwit') finalScriptSig = inputScript;

    if (!finalScriptSig && !finalScriptWitness) throw new Error('Unknown error finalizing input');
    if (finalScriptSig) input.finalScriptSig = finalScriptSig;
    if (finalScriptWitness) input.finalScriptWitness = finalScriptWitness;
    cleanFinalInput(input);
  }
  finalize() {
    for (let i = 0; i < this.inputs.length; i++) this.finalizeIdx(i);
  }
  extract() {
    if (!this.isFinal) throw new Error('Transaction has unfinalized inputs');
    if (!this.outputs.length) throw new Error('Transaction has no outputs');
    if (this.fee < 0n) throw new Error('Outputs spends more than inputs amount');
    return this.toBytes(true, true);
  }
  combine(other: Transaction): this {
    for (const k of ['PSBTVersion', 'version', 'lockTime'] as const) {
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
    const thisUnsigned = this.global.unsignedTx ? RawTx.encode(this.global.unsignedTx) : P.EMPTY;
    const otherUnsigned = other.global.unsignedTx ? RawTx.encode(other.global.unsignedTx) : P.EMPTY;
    if (!P.equalBytes(thisUnsigned, otherUnsigned))
      throw new Error(`Transaction/combine: different unsigned tx`);
    this.global = mergeKeyMap(PSBTGlobal, this.global, other.global);
    for (let i = 0; i < this.inputs.length; i++) this.updateInput(i, other.inputs[i], true);
    for (let i = 0; i < this.outputs.length; i++) this.updateOutput(i, other.outputs[i], true);
    return this;
  }
  clone() {
    // deepClone probably faster, but this enforces that encoding is valid
    return Transaction.fromPSBT(this.toPSBT(2), this.opts);
  }
}
// User facing API?

// Simple pubkey address, without complex scripts
export function getAddress(type: 'pkh' | 'wpkh' | 'tr', privKey: Bytes, network = NETWORK) {
  if (type === 'tr') {
    return p2tr(schnorr.getPublicKey(privKey), undefined, network).address;
  }
  const pubKey = _pubECDSA(privKey);
  if (type === 'pkh') return p2pkh(pubKey, network).address;
  if (type === 'wpkh') return p2wpkh(pubKey, network).address;
  throw new Error(`getAddress: unknown type=${type}`);
}

export function multisig(m: number, pubkeys: Bytes[], sorted = false, witness = false) {
  const ms = p2ms(m, sorted ? _sortPubkeys(pubkeys) : pubkeys);
  return witness ? p2wsh(ms) : p2sh(ms);
}

export function sortedMultisig(m: number, pubkeys: Bytes[], witness = false) {
  return multisig(m, pubkeys, true, witness);
}
// Copy-pasted from bip32 derive, maybe do something like 'bip32.parsePath'?
const HARDENED_OFFSET: number = 0x80000000;
export function bip32Path(path: string): number[] {
  const out: number[] = [];
  if (!/^[mM]'?/.test(path)) throw new Error('Path must start with "m" or "M"');
  if (/^[mM]'?$/.test(path)) return out;
  const parts = path.replace(/^[mM]'?\//, '').split('/');
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

export function PSBTCombine(psbts: Bytes[]): Bytes {
  if (!psbts || !Array.isArray(psbts) || !psbts.length)
    throw new Error('PSBTCombine: wrong PSBT list');
  const tx = Transaction.fromPSBT(psbts[0]);
  for (let i = 1; i < psbts.length; i++) tx.combine(Transaction.fromPSBT(psbts[i]));
  return tx.toPSBT();
}

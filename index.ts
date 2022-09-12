/*! micro-btc-signer - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import * as secp256k1 from '@noble/secp256k1';
import * as base from '@scure/base';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { ripemd160 } from '@noble/hashes/ripemd160';
import * as P from 'micro-packed';

// as const returns readonly stuff, remove readonly property
// TODO: update in other places
type Writable<T> = T extends {}
  ? T extends Uint8Array
    ? T
    : {
        -readonly [P in keyof T]: Writable<T[P]>;
      }
  : T;
export type Bytes = Uint8Array;

const hash160 = (msg: Bytes) => ripemd160(sha256(msg));
const sha256x2 = (...msgs: Bytes[]) => sha256(sha256(concat(...msgs)));
const concat = P.concatBytes;
// Make base58check work
export const base58check = base.base58check(sha256);
// Enable sync API for noble-secp256k1
secp256k1.utils.hmacSha256Sync = (key, ...msgs) => hmac(sha256, key, concat(...msgs));
secp256k1.utils.sha256Sync = (...msgs) => sha256(concat(...msgs));
const taggedHash = secp256k1.utils.taggedHashSync;

enum PubT {
  ecdsa,
  schnorr,
}
const validatePubkey = (pub: Bytes, type: PubT) => {
  const len = pub.length;
  if (type === PubT.ecdsa) {
    if (len === 32) throw new Error('Expected non-Schnorr key');
  } else if (type === PubT.schnorr) {
    if (len !== 32) throw new Error('Expected 32-byte Schnorr key');
  } else {
    throw new Error('Unknown key type');
  }
  secp256k1.Point.fromHex(pub); // does assertValidity
  return pub;
};
function isValidPubkey(pub: Bytes, type: PubT) {
  try {
    return !!validatePubkey(pub, type);
  } catch (e) {
    return false;
  }
}

// Not best way, but closest to bitcoin implementation (easier to check)
const hasLowR = (sig: Bytes) => secp256k1.Signature.fromHex(sig).toCompactRawBytes()[0] < 0x80;
// TODO: move to @noble/secp256k1?
function signECDSA(hash: Bytes, privateKey: Bytes, lowR = false): Bytes {
  let sig = secp256k1.signSync(hash, privateKey, { canonical: true });
  if (lowR && !hasLowR(sig)) {
    const extraEntropy = new Uint8Array(32);
    for (let cnt = 0; cnt < Number.MAX_SAFE_INTEGER; cnt++) {
      extraEntropy.set(P.U32LE.encode(cnt));
      sig = secp256k1.signSync(hash, privateKey, { canonical: true, extraEntropy });
      if (hasLowR(sig)) break;
    }
  }
  return sig;
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
    const key = base.hex.encode(pub);
    if (map[key]) throw new Error(`Multisig: non-uniq pubkey: ${pubkeys.map(base.hex.encode)}`);
    map[key] = true;
  }
}

export const NETWORK = {
  bech32: 'bc',
  pubKeyHash: 0x00,
  scriptHash: 0x05,
  wif: 0x80,
};

export const PRECISION = 8;
export const DEFAULT_VERSION = 2;
export const DEFAULT_LOCKTIME = 0;
export const DEFAULT_SEQUENCE = 4294967295;
const EMPTY32 = new Uint8Array(32);
// Utils
export const Decimal = P.coders.decimal(PRECISION);
type CmpType = string | number | bigint | boolean | Bytes | undefined;
export function cmp(a: CmpType, b: CmpType): number {
  if (a instanceof Uint8Array && b instanceof Uint8Array) {
    // -1 -> a<b, 0 -> a==b, 1 -> a>b
    const len = Math.min(a.length, b.length);
    for (let i = 0; i < len; i++) if (a[i] != b[i]) return Math.sign(a[i] - b[i]);
    return Math.sign(a.length - b.length);
  } else if (a instanceof Uint8Array || b instanceof Uint8Array)
    throw new Error(`cmp: wrong values a=${a} b=${b}`);
  if (
    (typeof a === 'bigint' && typeof b === 'number') ||
    (typeof a === 'number' && typeof b === 'bigint')
  ) {
    a = BigInt(a);
    b = BigInt(b);
  }
  if (a === undefined || b === undefined) throw new Error(`cmp: wrong values a=${a} b=${b}`);
  // Default js comparasion
  return Number(a > b) - Number(a < b);
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
// OP_\n to numeric value
// TODO: maybe add numbers to script parser for this case?
// prettier-ignore
export enum OPNum {
  OP_0, OP_1, OP_2, OP_3, OP_4, OP_5, OP_6, OP_7, OP_8,
  OP_9, OP_10, OP_11, OP_12, OP_13, OP_14, OP_15, OP_16,
}

function OPtoNumber(op: keyof typeof OP & keyof typeof OPNum): number | undefined {
  if (typeof op === 'string' && OP[op] !== undefined && OPNum[op] !== undefined) return OPNum[op];
}

type ScriptType = (keyof typeof OP | Bytes)[];
// Converts script bytes to parsed script
// 5221030000000000000000000000000000000000000000000000000000000000000001210300000000000000000000000000000000000000000000000000000000000000022103000000000000000000000000000000000000000000000000000000000000000353ae
// =>
// OP_2
//   030000000000000000000000000000000000000000000000000000000000000001
//   030000000000000000000000000000000000000000000000000000000000000002
//   030000000000000000000000000000000000000000000000000000000000000003
//   OP_3
//   CHECKMULTISIG
// TODO: simplify like CompactSize?
export const Script: P.CoderType<ScriptType> = P.wrap({
  encodeStream: (w: P.Writer, value: ScriptType) => {
    for (const o of value) {
      if (typeof o === 'string') {
        if (OP[o] === undefined) throw new Error(`Unknown opcode=${o}`);
        w.byte(OP[o]);
        continue;
      }
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
      } else {
        const op = OP[cur] as any;
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
const CompactSizeLen = P.apply(CompactSize, P.coders.number);

// Array of size <CompactSize>
export const BTCArray = <T>(t: P.CoderType<T>): P.CoderType<T[]> => P.array(CompactSize, t);

// ui8a of size <CompactSize>
export const VarBytes = P.bytes(CompactSize);

export const RawInput = P.struct({
  hash: P.bytes(32, true), // hash(prev_tx)
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
// TODO: more tests. Unsigned tx has version=2 for some reason,
// probably we're exporting broken unsigned tx
// Related: https://github.com/bitcoin/bips/blob/master/bip-0068.mediawiki
const _RawTx = P.struct({
  version: P.I32LE,
  segwitFlag: P.flag(new Uint8Array([0x00, 0x01])),
  inputs: BTCArray(RawInput),
  outputs: BTCArray(RawOutput),
  witnesses: P.flagged('segwitFlag', P.array('inputs/length', RawWitness)),
  // Need to handle that?
  // < 500000000	Block number at which this transaction is unlocked
  // >= 500000000	UNIX timestamp at which this transaction is unlocked
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

type PSBTKeyMap = Record<
  string,
  readonly [number, PSBTKeyCoder, any, readonly number[], readonly number[], readonly number[]]
>;

const BIP32Der = P.struct({
  fingerprint: P.U32BE,
  path: P.array(null, P.U32LE),
});

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

// {name: [tag, keyCoder, valueCoder]}
const PSBTGlobal = {
  // TODO: RAW TX here
  unsignedTx: [0x00, false, RawTx, [0], [2], [0]],
  // The 78 byte serialized extended public key as defined by BIP 32.
  xpub: [0x01, P.bytes(78), BIP32Der, [], [], [0, 2]],
  txVersion: [0x02, false, P.U32LE, [2], [0], [2]],
  fallbackLocktime: [0x03, false, P.U32LE, [], [0], [2]],
  inputCount: [0x04, false, CompactSizeLen, [2], [0], [2]],
  outputCount: [0x05, false, CompactSizeLen, [2], [0], [2]],
  // bitfield
  txModifiable: [0x06, false, P.U8, [], [0], [2]],
  version: [0xfb, false, P.U32LE, [], [], [0, 2]],
  // key = <identifierlen> <identifier> <subtype> <subkeydata>
  propietary: [0xfc, P.bytes(null), P.bytes(null), [], [], [0, 2]],
} as const;

const PSBTInput = {
  nonWitnessUtxo: [0x00, false, RawTx, [], [], [0, 2]],
  witnessUtxo: [0x01, false, RawOutput, [], [], [0, 2]],
  partialSig: [0x02, PubKeyECDSA, P.bytes(null), [], [], [0, 2]],
  sighashType: [0x03, false, P.U32LE, [], [], [0, 2]],
  redeemScript: [0x04, false, P.bytes(null), [], [], [0, 2]],
  witnessScript: [0x05, false, P.bytes(null), [], [], [0, 2]],
  bip32Derivation: [0x06, PubKeyECDSA, BIP32Der, [], [], [0, 2]],
  finalScriptSig: [0x07, false, P.bytes(null), [], [], [0, 2]],
  finalScriptWitness: [0x08, false, RawWitness, [], [], [0, 2]],
  porCommitment: [0x09, false, P.bytes(null), [], [], [0, 2]],
  ripemd160: [0x0a, P.bytes(20), P.bytes(null), [], [], [0, 2]],
  sha256: [0x0b, P.bytes(32), P.bytes(null), [], [], [0, 2]],
  hash160: [0x0c, P.bytes(20), P.bytes(null), [], [], [0, 2]],
  hash256: [0x0d, P.bytes(32), P.bytes(null), [], [], [0, 2]],
  hash: [0x0e, false, P.bytes(32), [2], [0], [2]],
  index: [0x0f, false, P.U32LE, [2], [0], [2]],
  sequence: [0x10, false, P.U32LE, [], [0], [2]],
  requiredTimeLocktime: [0x11, false, P.U32LE, [], [0], [2]],
  requiredHeightLocktime: [0x12, false, P.U32LE, [], [0], [2]],
  tapKeySig: [0x13, false, SignatureSchnorr, [], [], [0, 2]],
  tapScriptSig: [
    0x14,
    P.struct({ pubkey: PubKeySchnorr, leafHash: P.bytes(32) }),
    SignatureSchnorr,
    [],
    [],
    [0, 2],
  ],
  // value = <bytes script> <8-bit uint leaf version>
  tapLeafScript: [0x15, TaprootControlBlock, P.bytes(null), [], [], [0, 2]],
  tapBip32Derivation: [0x16, P.bytes(32), TaprootBIP32Der, [], [], [0, 2]],
  tapInternalKey: [0x17, false, PubKeySchnorr, [], [], [0, 2]],
  tapMerkleRoot: [0x18, false, P.bytes(32), [], [], [0, 2]],
  propietary: [0xfc, P.bytes(null), P.bytes(null), [], [], [0, 2]],
} as const;

const PSBTInputFinalKeys: (keyof typeof PSBTInput)[] = [
  'hash',
  'sequence',
  'index',
  'witnessUtxo',
  'nonWitnessUtxo',
  'finalScriptSig',
  'finalScriptWitness',
  'unknown' as any,
];

const PSBTOutput = {
  redeemScript: [0x00, false, P.bytes(null), [], [], [0, 2]],
  witnessScript: [0x01, false, P.bytes(null), [], [], [0, 2]],
  bip32Derivation: [0x02, PubKeyECDSA, BIP32Der, [], [], [0, 2]],
  amount: [0x03, false, P.I64LE, [2], [0], [2]],
  script: [0x04, false, P.bytes(null), [2], [0], [2]],
  tapInternalKey: [0x05, false, PubKeySchnorr, [], [], [0, 2]],
  /*
  {<8-bit uint depth> <8-bit uint leaf version> <compact size uint scriptlen> <bytes script>}*
  */
  tapTree: [
    0x06,
    false,
    P.array(
      null,
      P.struct({
        depth: P.U8,
        version: P.U8,
        script: VarBytes,
      })
    ),
    [],
    [],
    [0, 2],
  ],
  tapBip32Derivation: [0x07, PubKeySchnorr, TaprootBIP32Der, [], [], [0, 2]],
  propietary: [0xfc, P.bytes(null), P.bytes(null), [], [], [0, 2]],
} as const;

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

type PSBTKeyMapKeys<T extends PSBTKeyMap> = {
  -readonly [K in keyof T]?: T[K][1] extends false
    ? P.UnwrapCoder<T[K][2]>
    : [P.UnwrapCoder<T[K][1]>, P.UnwrapCoder<T[K][2]>][];
};
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
        if (!kc) out.push({ key: { type, key: P.EMPTY }, value: vc.encode(val) });
        else {
          // TODO: check here if there is duplicate keys
          const kv: [Bytes, Bytes][] = val.map(([k, v]: [any, any]) => [
            kc.encode(k),
            vc.encode(v),
          ]);
          // sort by keys
          kv.sort((a, b) => cmp(a[0], b[0]));
          for (const [key, value] of kv) out.push({ key: { key, type }, value });
        }
      }
      if (value.unknown) {
        value.unknown.sort((a: any, b: any) => cmp(a[0], b[0]));
        for (const [k, v] of value.unknown as any)
          out.push({ key: PSBTUnknownKey.decode(k), value: v });
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
              `PSBT: Non-empty key for ${name} (key=${base.hex.encode(key)} value=${base.hex.encode(
                value
              )}`
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
          key = PSBTUnknownKey.encode({ type: elm.key.type, key: elm.key.key });
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
  // TODO: revalidate
  if (script) {
    const s = OutScript.decode(script);
    // TODO: ms||pk maybe work, but there will be no address
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
  if (i.partialSig) for (const [k, v] of i.partialSig) validatePubkey(k, PubT.ecdsa);
  if (i.bip32Derivation) for (const [k, v] of i.bip32Derivation) validatePubkey(k, PubT.ecdsa);
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
  return i;
});

const PSBTOutputCoder = P.validate(PSBTKeyMap(PSBTOutput), (o) => {
  if (o.bip32Derivation) for (const [k, v] of o.bip32Derivation) validatePubkey(k, PubT.ecdsa);
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
    const [reqInc, reqExc, allowInc] = info[k].slice(-3);
    if (reqExc.includes(version) || !allowInc.includes(version))
      throw new Error(`PSBTv${version}: field ${k} is not allowed`);
  }
  for (const k in info) {
    const [reqInc, reqExc, allowInc] = info[k].slice(-3);
    if (reqInc.includes(version) && lst[k] === undefined)
      throw new Error(`PSBTv${version}: missing required field ${k}`);
  }
}

function cleanPSBTFields<T extends PSBTKeyMap>(version: number, info: T, lst: PSBTKeyMapKeys<T>) {
  const out: PSBTKeyMapKeys<T> = {};
  for (const k in lst) {
    if (k !== 'unknown') {
      if (!info[k]) continue;
      const [reqInc, reqExc, allowInc] = info[k].slice(-3);
      if (reqExc.includes(version) || !allowInc.includes(version)) continue;
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

export const RawPSBTV0 = P.validate(_RawPSBTV0, validatePSBT);
export const RawPSBTV2 = P.validate(_RawPSBTV2, validatePSBT);

// (TxHash, Idx)
const TxHashIdx = P.struct({ hash: P.bytes(32, true), index: P.U32LE });
// /Coders

const isBytes = (b: unknown): b is Bytes => b instanceof Uint8Array;

// Payments
// We need following items:
// - encode/decode output script
// - generate input script
// - generate address/output/redeem from user input
// P2ret represents generic interface for all p2* methods
type P2Ret = {
  type: string;
  script: Bytes;
  address?: string;
  redeemScript?: Bytes;
  witnessScript?: Bytes;
};
// Public Key (P2PK)
type OutPKType = { type: 'pk'; pubkey: Bytes };
type OptScript = ScriptType | undefined;
const OutPK: base.Coder<OptScript, OutPKType | undefined> = {
  encode(from: ScriptType): OutPKType | undefined {
    if (
      from.length !== 2 ||
      !P.isBytes(from[0]) ||
      !isValidPubkey(from[0], PubT.ecdsa) ||
      from[1] !== 'CHECKSIG'
    )
      return;
    return { type: 'pk', pubkey: from[0] };
  },
  decode: (to: OutPKType): OptScript => (to.type === 'pk' ? [to.pubkey, 'CHECKSIG'] : undefined),
};
export const p2pk = (pubkey: Bytes, network = NETWORK): P2Ret => {
  if (!isValidPubkey(pubkey, PubT.ecdsa)) throw new Error('P2PK: invalid publicKey');
  return {
    type: 'pk',
    script: OutScript.encode({ type: 'pk', pubkey }),
  };
};

// Publick Key Hash (P2PKH)
type OutPKHType = { type: 'pkh'; hash: Bytes };
const OutPKH: base.Coder<OptScript, OutPKHType | undefined> = {
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
const OutSH: base.Coder<OptScript, OutSHType | undefined> = {
  encode(from: ScriptType): OutSHType | undefined {
    if (from.length !== 3 || from[0] !== 'HASH160' || !isBytes(from[1]) || from[2] !== 'EQUAL')
      return;
    return { type: 'sh', hash: from[1] };
  },
  decode: (to: OutSHType): OptScript =>
    to.type === 'sh' ? ['HASH160', to.hash, 'EQUAL'] : undefined,
};
export const p2sh = (child: P2Ret, network = NETWORK): P2Ret => {
  const hash = hash160(child.script);
  const script = OutScript.encode({ type: 'sh', hash });
  checkScript(script, child.script, child.witnessScript);
  const res: P2Ret = {
    type: 'sh',
    redeemScript: child.script,
    script: OutScript.encode({ type: 'sh', hash }),
    address: Address(network).encode({ type: 'sh', hash }),
  };
  if (child.witnessScript) res.witnessScript = child.witnessScript;
  return res;
};
// Witness Script Hash (P2WSH)
type OutWSHType = { type: 'wsh'; hash: Bytes };
const OutWSH: base.Coder<OptScript, OutWSHType | undefined> = {
  encode(from: ScriptType): OutWSHType | undefined {
    if (from.length !== 2 || from[0] !== 'OP_0' || !isBytes(from[1])) return;
    if (from[1].length !== 32) return;
    return { type: 'wsh', hash: from[1] };
  },
  decode: (to: OutWSHType): OptScript => (to.type === 'wsh' ? ['OP_0', to.hash] : undefined),
};
export const p2wsh = (child: P2Ret, network = NETWORK): P2Ret => {
  const hash = sha256(child.script);
  const script = OutScript.encode({ type: 'wsh', hash });
  checkScript(script, undefined, child.script);
  return {
    type: 'wsh',
    witnessScript: child.script,
    script: OutScript.encode({ type: 'wsh', hash }),
    address: Address(network).encode({ type: 'wsh', hash }),
  };
};
// Witness Public Key Hash (P2WPKH)
type OutWPKHType = { type: 'wpkh'; hash: Bytes };
const OutWPKH: base.Coder<OptScript, OutWPKHType | undefined> = {
  encode(from: ScriptType): OutWPKHType | undefined {
    if (from.length !== 2 || from[0] !== 'OP_0' || !isBytes(from[1])) return;
    if (from[1].length !== 20) return;
    return { type: 'wpkh', hash: from[1] };
  },
  decode: (to: OutWPKHType): OptScript => (to.type === 'wpkh' ? ['OP_0', to.hash] : undefined),
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
const OutMS: base.Coder<OptScript, OutMSType | undefined> = {
  encode(from: ScriptType): OutMSType | undefined {
    const last = from.length - 1;
    if (from[last] !== 'CHECKMULTISIG') return;
    const m = OPtoNumber(from[0] as any);
    const n = OPtoNumber(from[last - 1] as any);
    if (m === undefined || n === undefined)
      throw new Error('OutScript.encode/multisig wrong params');
    const pubkeys: Bytes[] = from.slice(1, -2) as any; // Any is ok, check in for later
    if (n !== pubkeys.length) throw new Error('OutScript.encode/multisig: wrong length');
    return { type: 'ms', m, pubkeys }; // we don't need n, since it is the same as pubkeys
  },
  // checkmultisig(n, ..pubkeys, m)
  decode: (to: OutMSType): OptScript =>
    to.type === 'ms'
      ? [`OP_${to.m}`, ...to.pubkeys, `OP_${to.pubkeys.length}` as any, 'CHECKMULTISIG']
      : undefined,
};
export const p2ms = (m: number, pubkeys: Bytes[], allowSamePubkeys = false): P2Ret => {
  if (!allowSamePubkeys) uniqPubkey(pubkeys);
  return { type: 'ms', script: OutScript.encode({ type: 'ms', pubkeys, m }) };
};
// Taproot (P2TR)
type OutTRType = { type: 'tr'; pubkey: Bytes };
const OutTR: base.Coder<OptScript, OutTRType | undefined> = {
  encode(from: ScriptType): OutTRType | undefined {
    if (from.length !== 2 || from[0] !== 'OP_1' || !isBytes(from[1])) return;
    return { type: 'tr', pubkey: from[1] };
  },
  decode: (to: OutTRType): OptScript => (to.type === 'tr' ? ['OP_1', to.pubkey] : undefined),
};
export type TaprootNode = {
  script: Bytes | string;
  leafVersion?: number;
  weight?: number;
} & Partial<P2TROut>;
export type TaprootScriptTree = TaprootNode | TaprootScriptTree[];
export type TaprootScriptList = TaprootNode[];
type _TaprootListInternal = (
  | TaprootNode
  | { weight?: number; childs: [_TaprootListInternal, _TaprootListInternal] }
)[];
// Helper for generating binary tree from list, with weights
export function taprootListToTree(taprootList: TaprootScriptList): TaprootScriptTree {
  // Clone input in order to not corrupt it
  const lst: _TaprootListInternal = Array.from(taprootList) as _TaprootListInternal;
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
      childs: [(a as any).childs || a, (b as any).childs || b],
    });
  }
  // At this point there is always 1 element in lst
  const last = lst[0];
  return ((last as any).childs || last) as TaprootScriptTree;
}
type HashedTree =
  | { type: 'leaf'; version?: number; script: Bytes; hash: Bytes; tapInternalKey?: Bytes }
  | { type: 'branch'; left: HashedTree; right: HashedTree; hash: Bytes };
function checkTaprootScript(script: Bytes, allowUnknowOutput = false) {
  const out = OutScript.decode(script);
  if (out.type === 'unknown' && allowUnknowOutput) return;
  if (!out.type.startsWith('tr')) throw new Error(`P2TR: invalid leaf script=${out.type}`);
}
function taprootHashTree(tree: TaprootScriptTree, allowUnknowOutput = false): HashedTree {
  if (!tree) throw new Error('taprootHashTree: empty tree');
  if (Array.isArray(tree) && tree.length === 1) tree = tree[0];
  // Terminal node (leaf)
  if (!Array.isArray(tree)) {
    const { leafVersion: version, script: leafScript, tapInternalKey } = tree;
    // Earliest tree walk where we can validate tapScripts
    if (tree.tapLeafScript || (tree.tapMerkleRoot && !P.equalBytes(tree.tapMerkleRoot, P.EMPTY)))
      throw new Error('P2TR: tapRoot leafScript cannot have tree');
    // Just to be sure that it is spendable
    if (tapInternalKey && P.equalBytes(tapInternalKey, TAPROOT_UNSPENDABLE_KEY))
      throw new Error('P2TR: tapRoot leafScript cannot have unspendble key');
    const script = typeof leafScript === 'string' ? base.hex.decode(leafScript) : leafScript;
    checkTaprootScript(script, allowUnknowOutput);
    return {
      type: 'leaf',
      tapInternalKey,
      version,
      script,
      hash: tapLeafHash(script, version),
    };
  }
  // If tree / branch is not binary tree, convert it
  if (tree.length !== 2) tree = taprootListToTree(tree as TaprootNode[]) as TaprootNode[];
  if (tree.length !== 2) throw new Error('hashTree: non binary tree!');
  // branch
  // NOTE: both nodes should exist
  const left = taprootHashTree(tree[0], allowUnknowOutput);
  const right = taprootHashTree(tree[1], allowUnknowOutput);
  // We cannot swap left/right here, since it will change structure of tree
  let [lH, rH] = [left.hash, right.hash];
  if (cmp(rH, lH) === -1) [lH, rH] = [rH, lH];
  return { type: 'branch', left, right, hash: taggedHash('TapBranch', lH, rH) };
}
type TaprootLeaf = {
  type: 'leaf';
  version?: number;
  script: Bytes;
  hash: Bytes;
  path: Bytes[];
  tapInternalKey?: Bytes;
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
export const TAPROOT_UNSPENDABLE_KEY = sha256(secp256k1.Point.BASE.toRawBytes(false));

export type P2TROut = P2Ret & {
  tweakedPubkey: Uint8Array;
  tapInternalKey: Uint8Array;
  tapMerkleRoot: Uint8Array;
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
  allowUnknowOutput = false
): P2TROut {
  // Unspendable
  if (!internalPubKey && !tree) throw new Error('p2tr: should have pubKey or scriptTree (or both)');
  const pubKey =
    typeof internalPubKey === 'string'
      ? base.hex.decode(internalPubKey)
      : internalPubKey || TAPROOT_UNSPENDABLE_KEY;
  if (!isValidPubkey(pubKey, PubT.schnorr)) throw new Error('p2tr: non-schnorr pubkey');
  let hashedTree = tree ? taprootAddPath(taprootHashTree(tree, allowUnknowOutput)) : undefined;
  const tapMerkleRoot = hashedTree ? hashedTree.hash : P.EMPTY;
  const [tweakedPubkey, parity] = taprootTweakPubkey(pubKey, tapMerkleRoot);
  let leaves;
  if (hashedTree) {
    leaves = taprootWalkTree(hashedTree).map((l) => ({
      ...l,
      controlBlock: TaprootControlBlock.encode({
        version: (l.version || TAP_LEAF_VERSION) + +parity,
        internalKey: l.tapInternalKey || pubKey,
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
    tapMerkleRoot,
  };
  // Just in case someone would want to select a specific script
  if (leaves) res.leaves = leaves;
  if (tapLeafScript) res.tapLeafScript = tapLeafScript;
  return res;
}
// TODO: cleanup
export function _taprootTweakPrivKey(privKey: Bytes, merkleRoot: Bytes = P.EMPTY) {
  const pubKey = secp256k1.schnorr.getPublicKey(privKey);
  const pubPoint = secp256k1.Point.fromPrivateKey(privKey);
  const seckey = (pubPoint.y & 1n) === 0n ? privKey : secp256k1.utils.privateNegate(privKey);
  return secp256k1.utils.privateAdd(seckey, taggedHash('TapTweak', pubKey, merkleRoot));
}
export function taprootTweakPubkey(pubKey: Bytes, h: Bytes): [Bytes, boolean] {
  const tweak = taggedHash('TapTweak', pubKey, h);
  // Same as 'utils.pointAddScalar', but returns rawX for now
  const tweakPub = secp256k1.Point.fromPrivateKey(tweak);
  const pubPoint = secp256k1.Point.fromHex(pubKey);
  const tweakPoint = pubPoint.add(tweakPub);
  return [tweakPoint.toRawX(), !!(tweakPoint.y & 1n)];
}

// Taproot N-of-N multisig (P2TR_NS)
type OutTRNSType = { type: 'tr_ns'; pubkeys: Bytes[] };
const OutTRNS: base.Coder<OptScript, OutTRNSType | undefined> = {
  encode(from: ScriptType): OutTRNSType | undefined {
    const last = from.length - 1;
    if (from[last] !== 'CHECKSIG') return;
    const pubkeys = [];
    for (let i = 0; i < last; i++) {
      const elm = from[i];
      if (i & 1) {
        if (elm !== 'CHECKSIGVERIFY') throw new Error('OutScript.encode/tr_ns: wrong element');
        if (i === last - 1) throw new Error('OutScript.encode/tr_ns: wrong element');
        continue;
      }
      if (!isBytes(elm)) throw new Error('OutScript.encode/tr_ns: wrong element');
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
    // NOTE: idx[i] cannot be bigger than n-m+i, otherwise last elements in right part will overflow
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
// Taproot M-of-N Multisig (P2TR_MS)
type OutTRMSType = { type: 'tr_ms'; pubkeys: Bytes[]; m: number };
const OutTRMS: base.Coder<OptScript, OutTRMSType | undefined> = {
  encode(from: ScriptType): OutTRMSType | undefined {
    const last = from.length - 1;
    if (from[last] !== 'NUMEQUAL' || from[1] !== 'CHECKSIG') return;
    const pubkeys = [];
    const m = OPtoNumber(from[last - 1] as any);
    if (m === undefined) return;
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
    out.push(`OP_${to.m}` as any, 'NUMEQUAL');
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
// Uknown output type
type OutUnknownType = { type: 'unknown'; script: Bytes };
const OutUnknown: base.Coder<OptScript, OutUnknownType | undefined> = {
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
  if (i.type === 'ms' || i.type === 'tr_ns')
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
    if (i.m <= 0 || n > 16 || i.m > n) throw new Error('OutScript/tr_ms: invalid params');
  }
  return i;
});

// Address
// TODO: clean-up
function validateWitness(version: number, data: Bytes) {
  if (data.length < 2 || data.length > 40) throw new Error('Witness: invalid length');
  if (version > 16) throw new Error('Witness: invalid version');
  if (version === 0 && !(data.length === 20 || data.length === 32))
    throw new Error('Witness: invalid length for version');
}

export function programToWitness(version: number, data: Bytes, network = NETWORK) {
  validateWitness(version, data);
  const coder = version === 0 ? base.bech32 : base.bech32m;
  return coder.encode(network.bech32, [version].concat(coder.toWords(data)));
}

// TODO: remove?
export function parseWitnessProgram(version: number, data: Bytes) {
  validateWitness(version, data);
  const encodedVersion = version > 0 ? version + 0x50 : version;
  return concat(new Uint8Array([encodedVersion]), VarBytes.encode(Uint8Array.from(data)));
}

function formatKey(hashed: Bytes, prefix: number[]): string {
  return base58check.encode(concat(Uint8Array.from(prefix), hashed));
}

export function WIF(network = NETWORK): base.Coder<Bytes, string> {
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
      return 1 as any;
    },
    decode(address: string): P.UnwrapCoder<typeof OutScript> {
      if (address.length < 14 || address.length > 74) throw new Error('Invalid address length');
      // Bech32
      if (network.bech32 && address.toLowerCase().startsWith(network.bech32)) {
        let res;
        try {
          res = base.bech32.decode(address);
          if (res.words[0] !== 0) throw new Error(`bech32: wrong version=${res.words[0]}`);
        } catch (_) {
          // Starting from version 1 it is decoded as bech32m
          res = base.bech32m.decode(address);
          if (res.words[0] === 0) throw new Error(`bech32m: wrong version=${res.words[0]}`);
        }
        if (res.prefix !== network.bech32) throw new Error(`wrong bech32 prefix=${res.prefix}`);
        const [version, ...program] = res.words;
        const data = base.bech32.fromWords(program);
        validateWitness(version, data);
        if (version === 0 && data.length === 32) return { type: 'wsh', hash: data };
        else if (version === 0 && data.length === 20) return { type: 'wpkh', hash: data };
        else if (version === 1 && data.length === 32) return { type: 'tr', pubkey: data };
        else throw new Error('Unkown witness program');
      }
      const data = base.base58.decode(address);
      if (data.length !== 25) throw new Error('Invalid base58 address');
      // Pay To Public Key Hash
      if (data[0] === network.pubKeyHash) {
        const bytes = base.base58.decode(address);
        return { type: 'pkh', hash: bytes.slice(1, bytes.length - 4) };
      } else if (data[0] === network.scriptHash) {
        const bytes = base.base58.decode(address);
        return {
          type: 'sh',
          hash: base.base58.decode(address).slice(1, bytes.length - 4),
        };
      }
      throw new Error(`Invalid address prefix=${data[0]}`);
    },
  };
}
// /Address

export enum SignatureHash {
  DEFAULT,
  ALL,
  NONE,
  SINGLE,
  ANYONECANPAY = 0x80,
  ALL_SIGHASH_ANYONECANPAY = 0x81,
  NONE_SIGHASH_ANYONECANPAY = 0x82,
  SINGLE_SIGHASH_ANYONECANPAY = 0x83,
}
export const SigHashCoder = P.apply(P.U32LE, P.coders.tsEnum(SignatureHash));

function sum(arr: (number | bigint)[]): bigint {
  return arr.map((n) => BigInt(n)).reduce((a, b) => a + b);
}

// TODO: encoder maybe?
function unpackSighash(hashType: number) {
  const masked = hashType & 0b0011111;
  return {
    isAny: !!(hashType & 128),
    isNone: masked === 2,
    isSingle: masked === 3,
  };
}

export const _sortPubkeys = (pubkeys: Bytes[]) => Array.from(pubkeys).sort(cmp);

export type TransactionInput = P.UnwrapCoder<typeof RawInput> &
  P.UnwrapCoder<typeof PSBTInputCoder>;
export type TransactionOutput = P.UnwrapCoder<typeof RawOutput> &
  P.UnwrapCoder<typeof PSBTOutputCoder>;

const def = {
  sequence: (n: number) => (n === undefined ? DEFAULT_SEQUENCE : n),
  lockTime: (n: number) => (n === undefined ? DEFAULT_LOCKTIME : n),
};

export const TAP_LEAF_VERSION = 0xc0;
export const tapLeafHash = (script: Bytes, version = TAP_LEAF_VERSION) =>
  taggedHash('TapLeaf', new Uint8Array([version]), VarBytes.encode(script));

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
  // Allow output scripts to be unknown scripts (probably unspendable)
  allowUnknowOutput?: boolean;
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

export class Transaction {
  // Import
  static fromRaw(raw: Bytes, opts: TxOpts = {}) {
    const parsed = RawTx.decode(raw);
    const tx = new Transaction(parsed.version, parsed.lockTime, undefined, opts);
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
    const version = parsed.global.version || 0;
    const unsigned = parsed.global.unsignedTx;
    const txVersion = !version ? unsigned?.version : parsed.global.txVersion;
    const lockTime = !version ? unsigned?.lockTime : parsed.global.fallbackLocktime;
    const tx = new Transaction(txVersion, lockTime, version, opts);
    // We need slice here, because otherwise
    const inputCount = !version ? unsigned?.inputs.length : parsed.global.inputCount;
    tx.inputs = parsed.inputs.slice(0, inputCount).map((i, j) => ({
      finalScriptSig: P.EMPTY,
      ...parsed.global.unsignedTx?.inputs[j],
      ...i,
    })) as any;
    const outputCount = !version ? unsigned?.outputs.length : parsed.global.outputCount;
    tx.outputs = parsed.outputs.slice(0, outputCount).map((i, j) => ({
      ...i,
      ...parsed.global.unsignedTx?.outputs[j],
    })) as any;
    tx.global = { ...parsed.global, txVersion }; // just in case propietary/unknown fields
    if (lockTime !== DEFAULT_LOCKTIME) tx.global.fallbackLocktime = lockTime;
    return tx;
  }
  toPSBT(ver = this.PSBTVersion) {
    const inputs = this.inputs.map((i) => cleanPSBTFields(ver, PSBTInput, i));
    for (const inp of inputs) {
      // Don't serialize empty fields
      if (inp.partialSig && !inp.partialSig.length) delete inp.partialSig;
      if (inp.finalScriptSig && !inp.finalScriptSig.length) delete inp.finalScriptSig;
      if (inp.finalScriptWitness && !inp.finalScriptWitness.length) delete inp.finalScriptWitness;
    }
    const outputs = this.outputs.map((i) => cleanPSBTFields(ver, PSBTOutput, i));
    if (ver && ver !== 2) throw new Error(`Wrong PSBT version=${ver}`);
    const global = { ...this.global };
    if (!ver) {
      global.unsignedTx = RawTx.decode(this.unsignedTx);
      delete global.fallbackLocktime;
      delete global.txVersion;
    } else {
      global.version = ver;
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
    return (ver === 2 ? RawPSBTV2 : RawPSBTV0).encode({
      global,
      inputs,
      outputs,
    });
  }
  private global: Writable<PSBTKeyMapKeys<typeof PSBTGlobal>> = {};
  private inputs: TransactionInput[] = [];
  private outputs: TransactionOutput[] = [];
  constructor(
    version = DEFAULT_VERSION,
    lockTime = 0,
    public PSBTVersion = 0,
    readonly opts: TxOpts = {}
  ) {
    if (lockTime !== DEFAULT_LOCKTIME) this.global.fallbackLocktime = lockTime;
    this.global.txVersion = version;
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

  get isFinal() {
    for (const inp of this.inputs) {
      if (
        (!inp.finalScriptSig || !inp.finalScriptSig.length) &&
        (!inp.finalScriptWitness || !inp.finalScriptWitness.length)
      )
        return false;
    }
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
    if (this.hasWitnesses) out += 2;
    out += 4 * CompactSizeLen.encode(this.inputs.length).length;
    out += 4 * CompactSizeLen.encode(this.outputs.length).length;
    for (const i of this.inputs) out += 160 + 4 * VarBytes.encode(i.finalScriptSig).length;
    for (const o of this.outputs) out += 32 + 4 * VarBytes.encode(o.script).length;
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
      inputs: this.inputs.map((i) => ({
        ...i,
        finalScriptSig: (withScriptSig && i.finalScriptSig) || P.EMPTY,
      })),
      outputs: this.outputs,
      witnesses: this.inputs.map((i) => i.finalScriptWitness || []),
      segwitFlag: withWitness && this.hasWitnesses,
    });
  }
  get unsignedTx(): Bytes {
    return this.toBytes(false, false);
  }
  get hex() {
    return base.hex.encode(this.toBytes(true, this.hasWitnesses));
  }

  // TODO: hash requires non-empty script in inputs, why?
  get hash() {
    if (!this.isFinal) throw new Error('Transaction is not finalized');
    return base.hex.encode(sha256x2(this.toBytes(true)));
  }
  get id() {
    if (!this.isFinal) throw new Error('Transaction is not finalized');
    return base.hex.encode(sha256x2(this.toBytes(true)).reverse());
  }
  private keyMap<T extends PSBTKeyMap>(
    psbtEnum: T,
    val: PSBTKeyMapKeys<T>,
    cur?: PSBTKeyMapKeys<T>
  ): PSBTKeyMapKeys<T> {
    const res = { ...cur, ...val };
    // All arguments can be provided as hex
    for (const k in psbtEnum) {
      const key = k as keyof typeof psbtEnum;
      const [_, kC, vC] = psbtEnum[key];
      type _KV = [P.UnwrapCoder<typeof kC>, P.UnwrapCoder<typeof vC>];
      if (val[k] === undefined && k in val) delete res[k];
      else if (kC) {
        const oldKV = (cur && cur[k] ? cur[k] : []) as _KV[];
        let newKV = val[key] as _KV[];
        if (newKV) {
          if (!Array.isArray(newKV)) throw new Error(`keyMap(${k}): KV pairs should be [k, v][]`);
          // Decode hex in k-v
          newKV = newKV.map((val: _KV): _KV => {
            if (val.length !== 2) throw new Error(`keyMap(${k}): KV pairs should be [k, v][]`);
            return [
              typeof val[0] === 'string' ? kC.decode(base.hex.decode(val[0])) : val[0],
              typeof val[1] === 'string' ? vC.decode(base.hex.decode(val[1])) : val[1],
            ];
          });
          const map: Record<string, _KV> = {};
          const add = (kStr: string, k: _KV[0], v: _KV[1]) => {
            if (map[kStr] === undefined) {
              map[kStr] = [k, v];
              return;
            }
            const oldVal = base.hex.encode(vC.encode(map[kStr][1]));
            const newVal = base.hex.encode(vC.encode(v));
            if (oldVal !== newVal)
              throw new Error(
                `keyMap(${key as string}): same key=${kStr} oldVal=${oldVal} newVal=${newVal}`
              );
          };
          for (const [k, v] of oldKV) {
            const kStr = base.hex.encode(kC.encode(k));
            add(kStr, k, v);
          }
          for (const [k, v] of newKV) {
            const kStr = base.hex.encode(kC.encode(k));
            // undefined removes previous value
            if (v === undefined) delete map[kStr];
            else add(kStr, k, v);
          }
          (res as any)[key] = Object.values(map) as _KV[];
        }
      } else if (typeof res[k] === 'string') res[k] = vC.decode(base.hex.decode(res[k] as any));
    }
    // Remove unknown keys
    for (const k in res) if (!psbtEnum[k]) delete res[k];
    return res;
  }
  // Input stuff
  private checkInputIdx(idx: number) {
    if (!Number.isSafeInteger(idx) || 0 > idx || idx >= this.inputs.length)
      throw new Error(`Wrong input index=${idx}`);
  }
  // Modification
  private normalizeInput(
    i: P.UnwrapCoder<typeof PSBTInputCoder>,
    cur?: TransactionInput
  ): TransactionInput {
    let res: PSBTKeyMapKeys<typeof PSBTInput> = { ...cur, ...i };
    if (res.sequence === undefined) res.sequence = DEFAULT_SEQUENCE;
    if (typeof res.hash === 'string') res.hash = base.hex.decode(res.hash).reverse();
    if (res.tapMerkleRoot === null) delete res.tapMerkleRoot;
    res = this.keyMap(PSBTInput, res, cur);
    PSBTInputCoder.encode(res);

    if (res.hash === undefined || res.index === undefined)
      throw new Error('Transaction/input: hash and index required');
    // Cannot move in PSBTInputCoder, since it requires opts for parsing
    if (res.nonWitnessUtxo) {
      const outputs = res.nonWitnessUtxo.outputs;
      if (outputs.length - 1 < res.index) throw new Error('nonWitnessUtxo: incorect output index');
      const tx = Transaction.fromRaw(RawTx.encode(res.nonWitnessUtxo), this.opts);
      const hash = base.hex.encode(res.hash);
      if (tx.id !== hash) throw new Error(`nonWitnessUtxo: wrong hash, exp=${hash} got=${tx.id}`);
    }
    // TODO: use this.prevout?
    let prevOut;
    if (res.nonWitnessUtxo && i.index !== undefined)
      prevOut = res.nonWitnessUtxo.outputs[res.index];
    else if (res.witnessUtxo) prevOut = res.witnessUtxo;
    if (!this.opts.disableScriptCheck)
      checkScript(prevOut && prevOut.script, res.redeemScript, res.witnessScript);

    return res as TransactionInput;
  }
  addInput(input: TransactionInput): number {
    this.inputs.push(this.normalizeInput(input));
    return this.inputs.length - 1;
  }
  updateInput(idx: number, input: P.UnwrapCoder<typeof PSBTInputCoder>) {
    this.checkInputIdx(idx);
    this.inputs[idx] = this.normalizeInput(input, this.inputs[idx]);
  }
  // Output stuff
  private checkOutputIdx(idx: number) {
    if (!Number.isSafeInteger(idx) || 0 > idx || idx >= this.outputs.length)
      throw new Error(`Wrong output index=${idx}`);
  }
  private normalizeOutput(
    o: P.UnwrapCoder<typeof PSBTOutputCoder>,
    cur?: TransactionOutput
  ): TransactionOutput {
    let res: PSBTKeyMapKeys<typeof PSBTOutput> = { ...cur, ...o };
    if (res.amount !== undefined)
      res.amount = typeof res.amount === 'string' ? Decimal.decode(res.amount) : res.amount;
    res = this.keyMap(PSBTOutput, res, cur);
    PSBTOutputCoder.encode(res);
    // TODO: verify here that script
    if (res.script === undefined || res.amount === undefined)
      throw new Error('Transaction/output: script and amount required');
    if (!this.opts.allowUnknowOutput && OutScript.decode(res.script).type === 'unknown') {
      throw new Error(
        'Transaction/output: unknown output script type, there is a chance that input is unspendable. Pass allowUnkownScript=true, if you sure'
      );
    }
    if (!this.opts.disableScriptCheck) checkScript(res.script, res.redeemScript, res.witnessScript);
    return res as TransactionOutput;
  }
  addOutput(o: TransactionOutput): number {
    this.outputs.push(this.normalizeOutput(o));
    return this.outputs.length - 1;
  }
  updateOutput(idx: number, output: P.UnwrapCoder<typeof PSBTOutputCoder>) {
    this.checkOutputIdx(idx);
    this.outputs[idx] = this.normalizeOutput(output, this.outputs[idx]);
  }
  addOutputAddress(address: string, amount: string | bigint, network = NETWORK): number {
    return this.addOutput({
      script: OutScript.encode(Address(network).decode(address)),
      amount: typeof amount === 'string' ? Decimal.decode(amount) : amount,
    });
  }
  // Utils
  get fee(): bigint {
    let res = 0n;
    for (const i of this.inputs) res += this.prevOut(i).amount;
    for (const i of this.outputs) res -= i.amount;
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
    let inputs = this.inputs.map((input, inputIdx) => ({
      ...input,
      finalScriptSig: inputIdx === idx ? prevOutScript : P.EMPTY,
    }));
    if (isAny) inputs = [inputs[idx]];
    else if (isNone || isSingle) {
      inputs = inputs.map((input, inputIdx) => ({
        ...input,
        sequence: inputIdx === idx ? def.sequence(input.sequence) : 0,
      }));
    }
    let outputs = this.outputs;
    if (isNone) outputs = [];
    else if (isSingle) outputs = new Array(idx - 1).fill(EMPTY_OUTPUT).concat([outputs[idx]]);
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
    const { inputs } = this;
    if (!isAny) inputHash = sha256x2(...inputs.map(TxHashIdx.encode));
    if (!isAny && !isSingle && !isNone)
      sequenceHash = sha256x2(...inputs.map((i) => P.U32LE.encode(def.sequence(i.sequence))));
    if (!isSingle && !isNone) outputHash = sha256x2(...this.outputs.map(RawOutput.encode));
    else if (isSingle && idx < this.outputs.length)
      outputHash = sha256x2(RawOutput.encode(this.outputs[idx]));
    const input = inputs[idx];
    return sha256x2(
      P.I32LE.encode(this.version),
      inputHash,
      sequenceHash,
      P.bytes(32, true).encode(input.hash),
      P.U32LE.encode(input.index),
      VarBytes.encode(prevOutScript),
      P.U64LE.encode(amount),
      P.U32LE.encode(def.sequence(input.sequence)),
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
    if (inType !== SignatureHash.ANYONECANPAY) {
      out.push(
        ...[
          this.inputs.map(TxHashIdx.encode),
          amount.map(P.U64LE.encode),
          prevOutScript.map(VarBytes.encode),
          this.inputs.map((i) => P.U32LE.encode(def.sequence(i.sequence))),
        ].map((i) => sha256(concat(...i)))
      );
    }
    if (outType === SignatureHash.ALL) {
      out.push(sha256(concat(...this.outputs.map(RawOutput.encode))));
    }
    const spendType = (annex ? 1 : 0) | (leafScript ? 2 : 0);
    out.push(new Uint8Array([spendType]));
    if (inType === SignatureHash.ANYONECANPAY) {
      const inp = this.inputs[idx];
      out.push(
        TxHashIdx.encode(inp),
        P.U64LE.encode(amount[idx]),
        VarBytes.encode(prevOutScript[idx]),
        P.U32LE.encode(def.sequence(inp.sequence))
      );
    } else out.push(P.U32LE.encode(idx));
    if (spendType & 1) out.push(sha256(VarBytes.encode(annex!)));
    if (outType === SignatureHash.SINGLE)
      out.push(idx < this.outputs.length ? sha256(RawOutput.encode(this.outputs[idx])) : EMPTY32);
    if (leafScript)
      out.push(tapLeafHash(leafScript, leafVer), P.U8.encode(0), P.I32LE.encode(codeSeparator));
    return taggedHash('TapSighash', ...out);
  }
  // Utils for sign/finalize
  // Used pretty often, should be fast
  private prevOut(input: TransactionInput): P.UnwrapCoder<typeof RawOutput> {
    if (input.nonWitnessUtxo) return input.nonWitnessUtxo.outputs[input.index];
    else if (input.witnessUtxo) return input.witnessUtxo;
    else throw new Error('Cannot find previous output info.');
  }
  private inputType(input: TransactionInput) {
    // TODO: check here if non-segwit tx + no nonWitnessUtxo
    let txType = 'legacy';
    const prevOut = this.prevOut(input);
    const first = OutScript.decode(prevOut.script);
    let type = first.type;
    let cur = first;
    const stack = [first];
    if (first.type === 'tr') {
      return {
        txType: 'taproot',
        type: 'tr',
        last: first,
        lastScript: prevOut.script,
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
      // TODO: check for uncompressed public keys in segwit tx
      const last = stack[stack.length - 1];
      if (last.type === 'sh' || last.type === 'wsh')
        throw new Error('inputType: sh/wsh cannot be terminal type');
      const lastScript = OutScript.encode(last);
      const res = { type, txType, last, lastScript };
      return res;
    }
  }

  // TODO: signer can be privateKey OR instance of bip32 HD stuff
  signIdx(
    privateKey: Signer,
    idx: number,
    allowedSighash?: SignatureHash[],
    _auxRand?: Bytes
  ): boolean {
    this.checkInputIdx(idx);
    const input = this.inputs[idx];
    const inputType = this.inputType(input);

    // Handle BIP32 HDKey
    if (!(privateKey instanceof Uint8Array)) {
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

    // Just for compat with bitcoinjs-lib, so users won't face unexpected behaviour.
    const defaultSighash =
      inputType.txType === 'taproot' ? SignatureHash.DEFAULT : SignatureHash.ALL;
    if (!allowedSighash) allowedSighash = [defaultSighash];
    const sighashType = input.sighashType || defaultSighash;
    if (!allowedSighash.includes(sighashType)) {
      throw new Error(
        `Input with not allowed sigHash=${sighashType}. Allowed: ${allowedSighash.join(', ')}`
      );
    }
    // Taproot
    const prevOut = this.prevOut(input);
    if (inputType.txType === 'taproot') {
      if (input.tapBip32Derivation) throw new Error('tapBip32Derivation unsupported');
      const prevOuts = this.inputs.map(this.prevOut);
      const prevOutScript = prevOuts.map((i) => i.script);
      const amount = prevOuts.map((i) => i.amount);

      let schnorrPub = secp256k1.schnorr.getPublicKey(privateKey);
      let merkleRoot = input.tapMerkleRoot || P.EMPTY;
      if (input.tapInternalKey) {
        // internal + tweak = tweaked key
        // if internal key == current public key, we need to tweak private key,
        // otherwise sign as is. bitcoinjs implementation always wants tweaked
        // priv key to be provided
        if (P.equalBytes(input.tapInternalKey, schnorrPub)) {
          privateKey = _taprootTweakPrivKey(privateKey, merkleRoot);
          schnorrPub = secp256k1.schnorr.getPublicKey(privateKey);
        }
        const [taprootPubKey, parity] = taprootTweakPubkey(input.tapInternalKey, merkleRoot);
        if (!P.equalBytes(taprootPubKey, schnorrPub)) throw new Error('Wrong internal key');
        const hash = this.preimageWitnessV1(idx, prevOutScript, sighashType, amount);
        // Tests use null auxRand, which is dumb
        const sig = concat(
          secp256k1.schnorr.signSync(hash, privateKey, _auxRand),
          sighashType !== SignatureHash.DEFAULT ? new Uint8Array([sighashType]) : P.EMPTY
        );
        this.updateInput(idx, { tapKeySig: sig });
        return true;
      } else if (input.tapLeafScript) {
        input.tapScriptSig = input.tapScriptSig || [];
        for (const [cb, _script] of input.tapLeafScript) {
          const script = _script.subarray(0, -1);
          const scriptDecoded = Script.decode(script);
          const ver = _script[_script.length - 1];
          const hash = tapLeafHash(script, ver);
          const pubkeyHash = hash160(schnorrPub);
          const pos = scriptDecoded.findIndex(
            (i) =>
              i instanceof Uint8Array &&
              (P.equalBytes(i, schnorrPub) || P.equalBytes(i, pubkeyHash))
          );
          // Skip if there is no public key in tapLeafScript
          if (pos === -1) continue;
          const msg = this.preimageWitnessV1(
            idx,
            prevOutScript,
            sighashType,
            amount,
            undefined,
            script,
            ver
          );
          const sig = concat(
            secp256k1.schnorr.signSync(msg, privateKey, _auxRand),
            sighashType !== SignatureHash.DEFAULT ? new Uint8Array([sighashType]) : P.EMPTY
          );
          this.updateInput(idx, {
            tapScriptSig: [[{ pubkey: schnorrPub, leafHash: hash }, sig]],
          });
        }
        return true;
      } else throw new Error('sign/taproot: unknown input');
    } else {
      // only compressed keys are supported for now
      const pubKey = secp256k1.getPublicKey(privateKey, true);
      // TODO: replace with explicit checks
      // Check if script has public key or its has inside
      let hasPubkey = false;
      const pubKeyHash = hash160(pubKey);
      for (const i of Script.decode(inputType.lastScript))
        if (i instanceof Uint8Array && (P.equalBytes(i, pubKey) || P.equalBytes(i, pubKeyHash)))
          hasPubkey = true;
      if (!hasPubkey) throw new Error(`Input script doesn't have pubKey: ${inputType.lastScript}`);
      let hash;
      if (inputType.txType === 'legacy') {
        if (!this.opts.allowLegacyWitnessUtxo && !input.nonWitnessUtxo) {
          throw new Error(
            `Transaction/sign: legacy input without nonWitnessUtxo, can result in attack that forces paying higher fees. Pass allowLegacyWitnessUtxo=true, if you sure`
          );
        }
        hash = this.preimageLegacy(idx, inputType.lastScript, sighashType);
      } else if (inputType.txType === 'segwit') {
        let script = inputType.lastScript;
        // If wpkh OR sh-wpkh, wsh-wpkh is impossible, so looks ok
        // TODO: re-check
        if (inputType.last.type === 'wpkh')
          script = OutScript.encode({ type: 'pkh', hash: inputType.last.hash });
        hash = this.preimageWitnessV0(idx, script, sighashType, prevOut.amount);
      } else throw new Error(`Transaction/sign: unknown tx type: ${inputType.txType}`);
      const sig = signECDSA(hash, privateKey, this.opts.lowR);
      this.updateInput(idx, {
        partialSig: [[pubKey, concat(sig, new Uint8Array([sighashType]))]],
      });
    }
    return true;
  }
  // TODO: this is bad API. Will work if user creates and signs tx, but if
  // there is some complex workflow with exchanging PSBT and signing them,
  // then it is better to validate which output user signs. How could a better API look like?
  // Example: user adds input, sends to another party, then signs received input (mixer etc),
  // another user can add different input for same key and user will sign it.
  // Even worse: another user can add bip32 derivation, and spend money from different address.
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
    const input = this.inputs[idx];
    const inputType = this.inputType(input);
    // Taproot finalize
    if (inputType.txType === 'taproot') {
      if (input.tapKeySig) input.finalScriptWitness = [input.tapKeySig];
      else if (input.tapLeafScript && input.tapScriptSig) {
        // TODO: this works the same as bitcoinjs lib fork, however it is not secure,
        // since we add signatures to script which we don't understand.
        // Maybe it is better to disable it?
        // Proper way will be to create check for known scripts, however MuSig, p2tr_ns and other
        // scripts are still not standard; and it will take significant amount of work for them.
        // Sort leafs by control block length. TODO: maybe need to check script length too?
        const leafs = input.tapLeafScript.sort(
          (a, b) =>
            TaprootControlBlock.encode(a[0]).length - TaprootControlBlock.encode(b[0]).length
        );
        for (const [cb, _script] of leafs) {
          // Last byte is version
          const script = _script.slice(0, -1);
          const ver = _script[_script.length - 1];
          const scriptDecoded = Script.decode(script);
          const hash = tapLeafHash(script, ver);
          const sigs = input.tapScriptSig
            .filter((i) => P.equalBytes(i[0].leafHash, hash))
            .map(([{ pubkey }, signature]) => {
              // TODO: it is even possible with taproot?
              const pubkeyHash = hash160(pubkey);
              const pos = scriptDecoded.findIndex(
                (i) =>
                  i instanceof Uint8Array &&
                  (P.equalBytes(i, pubkey) || P.equalBytes(i, pubkeyHash))
              );
              if (pos === -1)
                throw new Error('finalize/taproot: cannot find position of pubkey in script');
              return { signature, pos };
            })
            // Reverse order
            .sort((a, b) => b.pos - a.pos)
            .map((i) => i.signature);
          // Not enough signatures for this leaf
          if (!sigs.length) continue;
          input.finalScriptWitness = sigs.concat([script, TaprootControlBlock.encode(cb)]);
          break;
        }
        if (!input.finalScriptWitness) throw new Error('finalize/taproot: empty witness');
      } else throw new Error('finalize/taproot: unknown input');

      // Clean input
      for (const k in input) if (!PSBTInputFinalKeys.includes(k as any)) delete (input as any)[k];
      return;
    }
    let outScript = inputType.lastScript;
    let isSegwit = inputType.txType === 'segwit';
    if (!input.partialSig || !input.partialSig.length) throw new Error('Not enough partial sign');

    // TODO: this is completely broken, fix.
    let inputScript: any;
    let witness: any[] = [];
    // TODO: move input scripts closer to payments/output scripts
    // Multisig
    if (inputType.last.type === 'ms') {
      const m = inputType.last.m;
      const pubkeys = inputType.last.pubkeys;
      const signatures = [];
      // partial: [pubkey, sign]
      for (const pub of pubkeys) {
        const sign = input.partialSig.find((s) => P.equalBytes(pub, s[0]));
        if (!sign) continue;
        signatures.push(sign[1]);
      }
      if (signatures.length !== m) {
        throw new Error(
          `Multisig: wrong signatures count, m=${m} n=${pubkeys.length} signatures=${signatures.length}`
        );
      }
      inputScript = Script.encode(['OP_0', ...signatures]);
    }
    if (inputType.last.type === 'pk') {
      inputScript = Script.encode([input.partialSig[0][1]]);
    } else if (inputType.last.type === 'pkh') {
      // check if output is correct here
      inputScript = Script.encode([input.partialSig[0][1], input.partialSig[0][0]]);
    } else if (inputType.last.type === 'wpkh') {
      // check if output is correct here
      inputScript = P.EMPTY;
      witness = [input.partialSig[0][1], input.partialSig[0][0]];
    }
    let finalScriptSig, finalScriptWitness;
    if (input.witnessScript) {
      // P2WSH
      if (inputScript && inputScript.length > 0 && outScript && outScript.length > 0) {
        witness = Script.decode(inputScript).map((i) => {
          if (i === 'OP_0') return P.EMPTY;
          if (i instanceof Uint8Array) return i;
          throw new Error(`Wrong witness op=${i}`);
        });
      }
      if (witness && outScript) witness = ([] as Bytes[]).concat(witness, outScript);
      outScript = Script.encode(['OP_0', sha256(outScript)]);
      inputScript = P.EMPTY;
    }
    if (isSegwit) finalScriptWitness = witness;
    if (input.redeemScript) {
      // P2SH
      finalScriptSig = Script.encode([...Script.decode(inputScript), outScript]);
    } else if (!isSegwit) finalScriptSig = inputScript;

    if (!finalScriptSig && !finalScriptWitness) throw new Error('Unknown error finalizing input');
    if (finalScriptSig) input.finalScriptSig = finalScriptSig;
    if (finalScriptWitness) input.finalScriptWitness = finalScriptWitness;
    // Clean input
    for (const k in input) if (!PSBTInputFinalKeys.includes(k as any)) delete (input as any)[k];
  }
  finalize() {
    for (let i = 0; i < this.inputs.length; i++) this.finalizeIdx(i);
  }
  extract() {
    if (!this.isFinal) throw new Error('Transaction has unfinalized inputs');
    return this.toBytes(true, true);
  }
  combine(other: Transaction): this {
    for (const k of ['PSBTVersion', 'version', 'lockTime'] as const) {
      if (this[k] !== other[k])
        throw new Error(`Transaction/combine: different ${k} this=${this[k]} other=${other[k]}`);
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
    this.global = this.keyMap(PSBTGlobal, this.global, other.global);
    for (let i = 0; i < this.inputs.length; i++) this.updateInput(i, other.inputs[i]);
    for (let i = 0; i < this.outputs.length; i++) this.updateOutput(i, other.outputs[i]);
    return this;
  }
}
// User facing API?

// Simple pubkey address, without complex scripts
export function getAddress(type: 'pkh' | 'wpkh' | 'tr', privKey: Bytes, network = NETWORK) {
  if (type === 'tr') {
    return p2tr(secp256k1.schnorr.getPublicKey(privKey), undefined, network).address;
  }
  const pubKey = secp256k1.getPublicKey(privKey, true);
  if (type === 'pkh') return p2pkh(pubKey, network).address;
  if (type === 'wpkh') return p2wpkh(pubKey, network).address;
  throw new Error(`getAddress: unknown type=${type}`);
}

// TODO: rewrite
export function multisig(m: number, pubkeys: Bytes[], sorted = false, witness = false) {
  const ms = p2ms(m, sorted ? _sortPubkeys(pubkeys) : pubkeys);
  return witness ? p2wsh(ms) : p2sh(ms);
}

export function sortedMultisig(m: number, pubkeys: Bytes[], witness = false) {
  return multisig(m, pubkeys, true, witness);
}
// Copy-pase from bip32 derive, maybe do something like 'bip32.parsePath'?
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

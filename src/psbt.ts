import { hex } from '@scure/base';
import * as P from 'micro-packed';
import { CompactSize, CompactSizeLen, VarBytes } from './script.js';
import { RawOutput, RawTx, RawOldTx, RawWitness } from './script.js';
import { Transaction } from './transaction.js'; // circular
import { Bytes, compareBytes, PubT, validatePubkey, equalBytes } from './utils.js';

// PSBT BIP174, BIP370, BIP371

// Can be 33 or 64 bytes
const PubKeyECDSA = P.validate(P.bytes(null), (pub) => validatePubkey(pub, PubT.ecdsa));
const PubKeySchnorr = P.validate(P.bytes(32), (pub) => validatePubkey(pub, PubT.schnorr));
const SignatureSchnorr = P.validate(P.bytes(null), (sig) => {
  if (sig.length !== 64 && sig.length !== 65)
    throw new Error('Schnorr signature should be 64 or 65 bytes long');
  return sig;
});

const BIP32Der = P.struct({
  fingerprint: P.U32BE,
  path: P.array(null, P.U32LE),
});
const TaprootBIP32Der = P.struct({
  hashes: P.array(CompactSizeLen, P.bytes(32)),
  der: BIP32Der,
});
// The 78 byte serialized extended public key as defined by BIP 32.
const GlobalXPUB = P.bytes(78);
const tapScriptSigKey = P.struct({ pubKey: PubKeySchnorr, leafHash: P.bytes(32) });

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
export const PSBTGlobal = {
  unsignedTx:       [0x00, false,      RawOldTx,          [0], [0],    false],
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
export const PSBTInput = {
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
export const PSBTInputFinalKeys: (keyof TransactionInput)[] = [
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
export const PSBTInputUnsignedKeys: (keyof TransactionInput)[] = [
  'partialSig',
  'finalScriptSig',
  'finalScriptWitness',
  'tapKeySig',
  'tapScriptSig',
];

// prettier-ignore
export const PSBTOutput = {
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
export const PSBTOutputUnsignedKeys: (keyof typeof PSBTOutput)[] = [];

const PSBTKeyPair = P.array(
  P.NULL,
  P.struct({
    //  <key> := <keylen> <keytype> <keydata> WHERE keylen = len(keytype)+len(keydata)
    key: P.prefix(CompactSizeLen, P.struct({ type: CompactSizeLen, key: P.bytes(null) })),
    //  <value> := <valuelen> <valuedata>
    value: P.bytes(CompactSizeLen),
  })
);

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

function PSBTKeyInfo(info: PSBTKeyMapInfo) {
  const [type, kc, vc, reqInc, allowInc, silentIgnore] = info;
  return { type, kc, vc, reqInc, allowInc, silentIgnore };
}

type PSBTKeyMap = Record<string, PSBTKeyMapInfo>;

const PSBTUnknownKey = P.struct({ type: CompactSizeLen, key: P.bytes(null) });
type PSBTUnknownFields = { unknown?: [P.UnwrapCoder<typeof PSBTUnknownKey>, Bytes][] };
export type PSBTKeyMapKeys<T extends PSBTKeyMap> = {
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
          kv.sort((a, b) => compareBytes(a[0], b[0]));
          for (const [key, value] of kv) out.push({ key: { key, type }, value });
        }
      }
      if (value.unknown) {
        value.unknown.sort((a, b) => compareBytes(a[0].key, b[0].key));
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

export const PSBTInputCoder = P.validate(PSBTKeyMap(PSBTInput), (i) => {
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

  if (i.nonWitnessUtxo && i.index !== undefined) {
    const last = i.nonWitnessUtxo.outputs.length - 1;
    if (i.index > last) throw new Error(`validateInput: index(${i.index}) not in nonWitnessUtxo`);
    const prevOut = i.nonWitnessUtxo.outputs[i.index];
    if (
      i.witnessUtxo &&
      (!equalBytes(i.witnessUtxo.script, prevOut.script) || i.witnessUtxo.amount !== prevOut.amount)
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
  if (i.nonWitnessUtxo && i.index !== undefined && i.txid) {
    const outputs = i.nonWitnessUtxo.outputs;
    if (outputs.length - 1 < i.index) throw new Error('nonWitnessUtxo: incorect output index');
    // At this point, we are using previous tx output to create new input.
    // Script safety checks are unnecessary:
    // - User has no control over previous tx. If somebody send money in same tx
    //   as unspendable output, we still want user able to spend money
    // - We still want some checks to notify user about possible errors early
    //   in case user wants to use wrong input by mistake
    // - Worst case: tx will be rejected by nodes. Still better than disallowing user
    //   to spend real input, no matter how broken it looks
    const tx = Transaction.fromRaw(RawTx.encode(i.nonWitnessUtxo), {
      allowUnknownOutputs: true,
      disableScriptCheck: true,
      allowUnknownInputs: true,
    });
    const txid = hex.encode(i.txid);
    // PSBTv2 vectors have non-final tx in inputs
    if (tx.isFinal && tx.id !== txid)
      throw new Error(`nonWitnessUtxo: wrong txid, exp=${txid} got=${tx.id}`);
  }
  return i;
});

export type ExtendType<T, E> = {
  [K in keyof T]: K extends keyof E ? E[K] | T[K] : T[K];
};
export type RequireType<T, K extends keyof T> = T & {
  [P in K]-?: T[P];
};

export type TransactionInput = P.UnwrapCoder<typeof PSBTInputCoder>;
export type TransactionInputUpdate = ExtendType<
  TransactionInput,
  {
    nonWitnessUtxo?: string | Bytes;
    txid?: string;
  }
>;

export const PSBTOutputCoder = P.validate(PSBTKeyMap(PSBTOutput), (o) => {
  if (o.bip32Derivation) for (const [k] of o.bip32Derivation) validatePubkey(k, PubT.ecdsa);
  return o;
});

export type TransactionOutput = P.UnwrapCoder<typeof PSBTOutputCoder>;
export type TransactionOutputUpdate = ExtendType<TransactionOutput, { script?: string }>;
export type TransactionOutputRequired = {
  script: Bytes;
  amount: bigint;
};

const PSBTGlobalCoder = P.validate(PSBTKeyMap(PSBTGlobal), (g) => {
  const version = g.version || 0;
  if (version === 0) {
    if (!g.unsignedTx) throw new Error('PSBTv0: missing unsignedTx');
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

export function cleanPSBTFields<T extends PSBTKeyMap>(
  version: number,
  info: T,
  lst: PSBTKeyMapKeys<T>
) {
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

export function mergeKeyMap<T extends PSBTKeyMap>(
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
      if (!equalBytes(vC.encode(val[k]), vC.encode(cur[k])))
        throw new Error(`Cannot change signed field=${k}`);
    }
  }
  // Remove unknown keys
  for (const k in res) if (!psbtEnum[k]) delete res[k];
  return res;
}

export const RawPSBTV0 = P.validate(_RawPSBTV0, validatePSBT);
export const RawPSBTV2 = P.validate(_RawPSBTV2, validatePSBT);

import { bech32, bech32m, type Coder, createBase58check, hex } from '@scure/base';
import * as P from 'micro-packed';
import { TaprootControlBlock, type TransactionInput } from './psbt.ts';
import { OpToNum, Script, type ScriptType, VarBytes } from './script.ts';
import * as u from './utils.ts';
import { type BTC_NETWORK, type Bytes, NETWORK } from './utils.ts';

// We need following items:
// - encode/decode output script
// - generate input script
// - generate address/output/redeem from user input
// P2ret represents generic interface for all p2* methods
/** Common shape returned by payment helper constructors. */
export type P2Ret = {
  /** Payment-script tag such as `pkh`, `wpkh`, or `tr`. */
  type: string;
  /** Serialized output script for the payment descriptor. */
  script: Bytes;
  /** Encoded address when the script has a standard address form. */
  address?: string;
  /** Redeem script for wrapped script-hash descriptors. */
  redeemScript?: Bytes;
  /** Witness script for SegWit script-hash descriptors. */
  witnessScript?: Bytes;
  /** Hash committed by the output script when applicable. */
  hash?: Bytes;
};

// Pay to Anchor (P2A)
type OutP2AType = { type: 'p2a'; script: Bytes };
const OutP2A: Coder<OptScript, OutP2AType | undefined> = {
  encode(from: ScriptType): OutP2AType | undefined {
    if (from.length !== 2 || from[0] !== 1 || !u.isBytes(from[1]) || hex.encode(from[1]) !== '4e73')
      return;
    return { type: 'p2a', script: Script.encode(from) };
  },
  decode: (to: OutP2AType): OptScript => {
    if (to.type !== 'p2a') return;
    return [1, hex.decode('4e73')];
  },
};

// Public Key (P2PK)
type OutPKType = { type: 'pk'; pubkey: Bytes };
/** Optional parsed script result used by output-script coders. */
export type OptScript = ScriptType | undefined;

function isValidPubkey(pub: Bytes, type: u.PubT): boolean {
  try {
    u.validatePubkey(pub, type);
    return true;
  } catch (e) {
    return false;
  }
}

const OutPK: Coder<OptScript, OutPKType | undefined> = {
  encode(from: ScriptType): OutPKType | undefined {
    if (
      from.length !== 2 ||
      !u.isBytes(from[0]) ||
      !isValidPubkey(from[0], u.PubT.ecdsa) ||
      from[1] !== 'CHECKSIG'
    )
      return;
    return { type: 'pk', pubkey: from[0] };
  },
  decode: (to: OutPKType): OptScript => (to.type === 'pk' ? [to.pubkey, 'CHECKSIG'] : undefined),
};

// Public Key Hash (P2PKH)
type OutPKHType = { type: 'pkh'; hash: Bytes };
const OutPKH: Coder<OptScript, OutPKHType | undefined> = {
  encode(from: ScriptType): OutPKHType | undefined {
    if (from.length !== 5 || from[0] !== 'DUP' || from[1] !== 'HASH160' || !u.isBytes(from[2]))
      return;
    if (from[3] !== 'EQUALVERIFY' || from[4] !== 'CHECKSIG') return;
    return { type: 'pkh', hash: from[2] };
  },
  decode: (to: OutPKHType): OptScript =>
    to.type === 'pkh' ? ['DUP', 'HASH160', to.hash, 'EQUALVERIFY', 'CHECKSIG'] : undefined,
};
// Script Hash (P2SH)
type OutSHType = { type: 'sh'; hash: Bytes };
const OutSH: Coder<OptScript, OutSHType | undefined> = {
  encode(from: ScriptType): OutSHType | undefined {
    if (from.length !== 3 || from[0] !== 'HASH160' || !u.isBytes(from[1]) || from[2] !== 'EQUAL')
      return;
    return { type: 'sh', hash: from[1] };
  },
  decode: (to: OutSHType): OptScript =>
    to.type === 'sh' ? ['HASH160', to.hash, 'EQUAL'] : undefined,
};

// Witness Script Hash (P2WSH)
type OutWSHType = { type: 'wsh'; hash: Bytes };
const OutWSH: Coder<OptScript, OutWSHType | undefined> = {
  encode(from: ScriptType): OutWSHType | undefined {
    if (from.length !== 2 || from[0] !== 0 || !u.isBytes(from[1])) return;
    if (from[1].length !== 32) return;
    return { type: 'wsh', hash: from[1] };
  },
  decode: (to: OutWSHType): OptScript => (to.type === 'wsh' ? [0, to.hash] : undefined),
};

// Witness Public Key Hash (P2WPKH)
type OutWPKHType = { type: 'wpkh'; hash: Bytes };
const OutWPKH: Coder<OptScript, OutWPKHType | undefined> = {
  encode(from: ScriptType): OutWPKHType | undefined {
    if (from.length !== 2 || from[0] !== 0 || !u.isBytes(from[1])) return;
    if (from[1].length !== 20) return;
    return { type: 'wpkh', hash: from[1] };
  },
  decode: (to: OutWPKHType): OptScript => (to.type === 'wpkh' ? [0, to.hash] : undefined),
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
    for (const pub of pubkeys) if (!u.isBytes(pub)) return;
    return { type: 'ms', m, pubkeys: pubkeys as Bytes[] }; // we don't need n, since it is the same as pubkeys
  },
  // checkmultisig(n, ..pubkeys, m)
  decode: (to: OutMSType): OptScript =>
    to.type === 'ms' ? [to.m, ...to.pubkeys, to.pubkeys.length, 'CHECKMULTISIG'] : undefined,
};
// Taproot (P2TR)
type OutTRType = { type: 'tr'; pubkey: Bytes };
const OutTR: Coder<OptScript, OutTRType | undefined> = {
  encode(from: ScriptType): OutTRType | undefined {
    if (from.length !== 2 || from[0] !== 1 || !u.isBytes(from[1])) return;
    return { type: 'tr', pubkey: from[1] };
  },
  decode: (to: OutTRType): OptScript => (to.type === 'tr' ? [1, to.pubkey] : undefined),
};

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
      if (!u.isBytes(elm)) return;
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
      if (!u.isBytes(elm)) throw new Error('OutScript.encode/tr_ms: wrong key element');
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

const OutScripts = /* @__PURE__ */ (() => [
  OutP2A,
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
])();
// TODO: we can support user supplied output scripts now
// - addOutScript
// - removeOutScript
// - We can do that as log we modify array in-place
// - Actually is very hard, since there is sign/finalize logic
const _OutScript = /* @__PURE__ */ (() => P.apply(Script, P.coders.match(OutScripts)))();

/*
 * UNSAFE: Custom scripts: mostly ordinals, be very careful when crafting new scripts
 * Only taproot supported for now.
 * NOTE: we can use same to move finalization logic from Transaction, but it will significantly change audited code.
 */

type FinalizeSignature = [{ pubKey: Bytes; leafHash: Bytes }, Bytes];
type CustomScriptOut = { type: string } & Record<string, any>;
/** Custom taproot script coder/finalizer hook. */
export type CustomScript = Coder<OptScript, CustomScriptOut | undefined> & {
  finalizeTaproot?: (
    script: Bytes,
    parsed: CustomScriptOut,
    signatures: FinalizeSignature[]
  ) => Bytes[] | undefined;
};

// We can validate this once, because of packed & coders
/**
 * Coder for recognized Bitcoin output scripts.
 * @example
 * Decode a serialized output script back into the tagged payment descriptor.
 * ```ts
 * import { OutScript, p2wpkh } from '@scure/btc-signer/payment.js';
 * import { pubECDSA, randomPrivateKeyBytes } from '@scure/btc-signer/utils.js';
 * const pay = p2wpkh(pubECDSA(randomPrivateKeyBytes()));
 * OutScript.decode(pay.script);
 * ```
 */
export const OutScript: P.CoderType<
  NonNullable<
    | OutP2AType
    | OutPKType
    | OutPKHType
    | OutSHType
    | OutWSHType
    | OutWPKHType
    | OutMSType
    | OutTRType
    | OutTRNSType
    | OutTRMSType
    | OutUnknownType
    | undefined
  >
> = /* @__PURE__ */ (() =>
  P.validate(_OutScript, (i) => {
    if (i.type === 'pk' && !isValidPubkey(i.pubkey, u.PubT.ecdsa))
      throw new Error('OutScript/pk: wrong key');
    if (
      (i.type === 'pkh' || i.type === 'sh' || i.type === 'wpkh') &&
      (!u.isBytes(i.hash) || i.hash.length !== 20)
    )
      throw new Error(`OutScript/${i.type}: wrong hash`);
    if (i.type === 'wsh' && (!u.isBytes(i.hash) || i.hash.length !== 32))
      throw new Error(`OutScript/wsh: wrong hash`);
    if (i.type === 'tr' && (!u.isBytes(i.pubkey) || !isValidPubkey(i.pubkey, u.PubT.schnorr)))
      throw new Error('OutScript/tr: wrong taproot public key');
    if (i.type === 'ms' || i.type === 'tr_ns' || i.type === 'tr_ms')
      if (!Array.isArray(i.pubkeys)) throw new Error('OutScript/multisig: wrong pubkeys array');
    if (i.type === 'ms') {
      const n = i.pubkeys.length;
      for (const p of i.pubkeys)
        if (!isValidPubkey(p, u.PubT.ecdsa)) throw new Error('OutScript/multisig: wrong pubkey');
      if (i.m <= 0 || n > 16 || i.m > n) throw new Error('OutScript/multisig: invalid params');
    }
    if (i.type === 'tr_ns' || i.type === 'tr_ms') {
      for (const p of i.pubkeys)
        if (!isValidPubkey(p, u.PubT.schnorr)) throw new Error(`OutScript/${i.type}: wrong pubkey`);
    }
    if (i.type === 'tr_ms') {
      const n = i.pubkeys.length;
      if (i.m <= 0 || n > 999 || i.m > n) throw new Error('OutScript/tr_ms: invalid params');
    }
    return i;
  }))();
/** Type of the output-script coder. */
export type OutScriptType = typeof OutScript;

// Basic sanity check for scripts
function checkWSH(s: OutWSHType, witnessScript: Bytes) {
  if (!u.equalBytes(s.hash, u.sha256(witnessScript)))
    throw new Error('checkScript: wsh wrong witnessScript hash');
  const w = OutScript.decode(witnessScript);
  if (w.type === 'tr' || w.type === 'tr_ns' || w.type === 'tr_ms')
    throw new Error(`checkScript: P2${w.type} cannot be wrapped in P2SH`);
  if (w.type === 'wpkh' || w.type === 'sh')
    throw new Error(`checkScript: P2${w.type} cannot be wrapped in P2WSH`);
}

/**
 * Validates that nested redeem and witness scripts match their wrappers.
 * @param script - top-level output script
 * @param redeemScript - optional redeem script for P2SH wrappers
 * @param witnessScript - optional witness script for P2WSH wrappers
 * @throws If the script nesting is invalid or unsupported. {@link Error}
 * @example
 * Verify that wrapped scripts and hashes still match after custom edits.
 * ```ts
 * import { hex } from '@scure/base';
 * import { checkScript, p2pkh, p2sh } from '@scure/btc-signer/payment.js';
 * const wrapped = p2sh(
 *   p2pkh(hex.decode('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'))
 * );
 * checkScript(wrapped.script, wrapped.redeemScript);
 * ```
 */
export function checkScript(script?: Bytes, redeemScript?: Bytes, witnessScript?: Bytes): void {
  if (script) {
    const s = OutScript.decode(script);
    // ms||pk maybe work, but there will be no address, hard to spend
    if (s.type === 'tr_ns' || s.type === 'tr_ms' || s.type === 'ms' || s.type == 'pk')
      throw new Error(`checkScript: non-wrapped ${s.type}`);
    if (s.type === 'sh' && redeemScript) {
      if (!u.equalBytes(s.hash, u.hash160(redeemScript)))
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

function uniqPubkey(pubkeys: Bytes[]) {
  const map: Record<string, boolean> = {};
  for (const pub of pubkeys) {
    const key = hex.encode(pub);
    if (map[key]) throw new Error(`Multisig: non-uniq pubkey: ${pubkeys.map(hex.encode)}`);
    map[key] = true;
  }
}
// We want narrow types inside p2* methods, but always want to type-check if they compatible with P2Ret here!
// Also we use satisfies for additional check (ts 4.9+)
type Extends<T, U> = T extends U ? T : never;

/** Pay-to-public-key output descriptor. */
export type P2PK = {
  /** Payment-script tag for pay-to-public-key outputs. */
  type: 'pk';
  /** Serialized `pubkey CHECKSIG` script. */
  script: Bytes;
};
/**
 * Builds a pay-to-public-key script.
 * @param pubkey - compressed or uncompressed ECDSA public key
 * @param _network - unused network placeholder for API consistency
 * @returns P2PK descriptor.
 * @throws If the public key cannot be encoded as a P2PK output. {@link Error}
 * @example
 * Build a bare pay-to-public-key output.
 * ```ts
 * import { hex } from '@scure/base';
 * import { p2pk } from '@scure/btc-signer/payment.js';
 * p2pk(hex.decode('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'));
 * ```
 */
export const p2pk = (pubkey: Bytes, _network: BTC_NETWORK = NETWORK): Extends<P2PK, P2Ret> => {
  // network is unused
  if (!isValidPubkey(pubkey, u.PubT.ecdsa)) throw new Error('P2PK: invalid publicKey');
  return { type: 'pk', script: OutScript.encode({ type: 'pk', pubkey }) } as const satisfies P2Ret;
};

/** Pay-to-public-key-hash output descriptor. */
export type P2PKH = {
  /** Payment-script tag for pay-to-public-key-hash outputs. */
  type: 'pkh';
  /** Serialized P2PKH script. */
  script: Bytes;
  /** Base58Check address for the descriptor. */
  address: string;
  /** HASH160 committed by the script. */
  hash: Bytes;
};
/**
 * Builds a P2PKH output from a public key.
 * @param publicKey - ECDSA public key bytes
 * @param network - address network parameters
 * @returns P2PKH descriptor.
 * @throws If the public key cannot be encoded as a P2PKH output. {@link Error}
 * @example
 * Build a classic pay-to-public-key-hash output.
 * ```ts
 * import { hex } from '@scure/base';
 * import { p2pkh } from '@scure/btc-signer/payment.js';
 * p2pkh(hex.decode('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'));
 * ```
 */
export const p2pkh = (publicKey: Bytes, network: BTC_NETWORK = NETWORK): Extends<P2PKH, P2Ret> => {
  if (!isValidPubkey(publicKey, u.PubT.ecdsa)) throw new Error('P2PKH: invalid publicKey');
  const hash = u.hash160(publicKey);
  return {
    type: 'pkh',
    script: OutScript.encode({ type: 'pkh', hash }),
    address: Address(network).encode({ type: 'pkh', hash }),
    hash,
  } as const satisfies P2Ret;
};

/** Shared fields for pay-to-script-hash outputs. */
export type P2SHBase = {
  /** Payment-script tag for pay-to-script-hash outputs. */
  type: 'sh';
  /** Child script wrapped by the P2SH output. */
  redeemScript: Bytes;
  /** Serialized P2SH script. */
  script: Bytes;
  /** Base58Check address for the descriptor. */
  address: string;
  /** HASH160 committed by the script. */
  hash: Bytes;
};
/** P2SH descriptor with an embedded witness script. */
export type P2SHWithWitness = P2SHBase & { witnessScript: Bytes };
/** P2SH descriptor without an embedded witness script. */
export type P2SHWithoutWitness = Omit<P2SHBase, 'witnessScript'>;
/** Conditional P2SH return type for wrapped scripts. */
export type P2SHReturn<T extends P2Ret> = T extends { witnessScript: Bytes }
  ? P2SHWithWitness
  : P2SHWithoutWitness;
/**
 * Wraps a child script inside P2SH.
 * @param child - child payment descriptor to wrap
 * @param network - address network parameters
 * @returns P2SH descriptor preserving witness metadata when present.
 * @throws If the wrapped script combination is invalid or unsupported. {@link Error}
 * @example
 * Wrap a child script in P2SH so it gets a base58 address form.
 * ```ts
 * import { hex } from '@scure/base';
 * import { p2pk, p2sh, p2wsh } from '@scure/btc-signer/payment.js';
 * p2sh(p2wsh(p2pk(hex.decode('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'))));
 * ```
 */
export const p2sh = <T extends P2Ret>(
  child: T,
  network: BTC_NETWORK = NETWORK
): Extends<P2SHReturn<T>, P2Ret> => {
  // It is already tested inside noble-hashes and checkScript
  const cs = child.script;
  if (!u.isBytes(cs)) throw new Error(`Wrong script: ${typeof child.script}, expected Uint8Array`);
  const hash = u.hash160(cs);
  const script = OutScript.encode({ type: 'sh', hash });
  checkScript(script, cs, child.witnessScript);
  if (child.witnessScript) {
    return {
      type: 'sh',
      redeemScript: cs,
      script: OutScript.encode({ type: 'sh', hash }),
      address: Address(network).encode({ type: 'sh', hash }),
      hash,
      witnessScript: child.witnessScript,
    } as Extends<P2SHReturn<T>, P2Ret> satisfies P2Ret;
  } else {
    return {
      type: 'sh',
      redeemScript: cs,
      script: OutScript.encode({ type: 'sh', hash }),
      address: Address(network).encode({ type: 'sh', hash }),
      hash,
    } as Extends<P2SHReturn<T>, P2Ret> satisfies P2Ret;
  }
};

/** Pay-to-witness-script-hash descriptor. */
export type P2WSH = {
  /** Payment-script tag for pay-to-witness-script-hash outputs. */
  type: 'wsh';
  /** Child script committed by the witness program. */
  witnessScript: Bytes;
  /** Serialized P2WSH script. */
  script: Bytes;
  /** Bech32 address for the descriptor. */
  address: string;
  /** SHA256 committed by the witness program. */
  hash: Bytes;
};
/**
 * Wraps a child script inside native SegWit P2WSH.
 * @param child - child payment descriptor to wrap
 * @param network - address network parameters
 * @returns P2WSH descriptor.
 * @throws If the wrapped script combination is invalid or unsupported. {@link Error}
 * @example
 * Wrap a child script in native SegWit P2WSH.
 * ```ts
 * import { hex } from '@scure/base';
 * import { p2pk, p2wsh } from '@scure/btc-signer/payment.js';
 * p2wsh(p2pk(hex.decode('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')));
 * ```
 */
export const p2wsh = (child: P2Ret, network: BTC_NETWORK = NETWORK): Extends<P2WSH, P2Ret> => {
  const cs = child.script;
  if (!u.isBytes(cs)) throw new Error(`Wrong script: ${typeof cs}, expected Uint8Array`);
  const hash = u.sha256(cs);
  const script = OutScript.encode({ type: 'wsh', hash });
  checkScript(script, undefined, cs);
  return {
    type: 'wsh',
    witnessScript: cs,
    script: OutScript.encode({ type: 'wsh', hash }),
    address: Address(network).encode({ type: 'wsh', hash }),
    hash,
  } as const satisfies P2Ret;
};

/** Pay-to-witness-public-key-hash descriptor. */
export type P2WPKH = {
  /** Payment-script tag for pay-to-witness-public-key-hash outputs. */
  type: 'wpkh';
  /** Serialized P2WPKH script. */
  script: Bytes;
  /** Bech32 address for the descriptor. */
  address: string;
  /** HASH160 committed by the witness program. */
  hash: Bytes;
};
/**
 * Builds a native SegWit P2WPKH output from a public key.
 * @param publicKey - compressed ECDSA public key
 * @param network - address network parameters
 * @returns P2WPKH descriptor.
 * @throws If the public key cannot be encoded as a P2WPKH output. {@link Error}
 * @example
 * Build a native SegWit pay-to-public-key-hash output.
 * ```ts
 * import { hex } from '@scure/base';
 * import { p2wpkh } from '@scure/btc-signer/payment.js';
 * p2wpkh(hex.decode('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'));
 * ```
 */
export const p2wpkh = (
  publicKey: Bytes,
  network: BTC_NETWORK = NETWORK
): Extends<P2WPKH, P2Ret> => {
  if (!isValidPubkey(publicKey, u.PubT.ecdsa)) throw new Error('P2WPKH: invalid publicKey');
  if (publicKey.length === 65) throw new Error('P2WPKH: uncompressed public key');
  const hash = u.hash160(publicKey);
  return {
    type: 'wpkh',
    script: OutScript.encode({ type: 'wpkh', hash }),
    address: Address(network).encode({ type: 'wpkh', hash }),
    hash,
  } as const satisfies P2Ret;
};

/** Bare multisig output descriptor. */
export type P2MS = {
  /** Payment-script tag for bare multisig outputs. */
  type: 'ms';
  /** Serialized bare multisig script. */
  script: Bytes;
};
/**
 * Builds a bare multisig script.
 * @param m - number of required signatures
 * @param pubkeys - participating public keys
 * @param allowSamePubkeys - whether duplicate keys are allowed
 * @returns P2MS descriptor.
 * @throws If the multisig parameters are invalid. {@link Error}
 * @example
 * Build a bare multisig output script.
 * ```ts
 * import { hex } from '@scure/base';
 * import { p2ms } from '@scure/btc-signer/payment.js';
 * p2ms(1, [hex.decode('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')], true);
 * ```
 */
export const p2ms = (
  m: number,
  pubkeys: Bytes[],
  allowSamePubkeys = false
): Extends<P2MS, P2Ret> => {
  if (!allowSamePubkeys) uniqPubkey(pubkeys);
  return {
    type: 'ms',
    script: OutScript.encode({ type: 'ms', pubkeys, m }),
  } as const satisfies P2Ret;
};

/** Internal taproot hash tree without merkle paths. */
export type HashedTree =
  | { type: 'leaf'; version?: number; script: Bytes; hash: Bytes }
  | { type: 'branch'; left: HashedTree; right: HashedTree; hash: Bytes };
function checkTaprootScript(
  script: Bytes,
  internalPubKey: Bytes,
  allowUnknownOutputs = false,
  customScripts?: CustomScript[]
) {
  const out = OutScript.decode(script);
  if (out.type === 'unknown') {
    // NOTE: this check should be before allowUnknownOutputs, otherwise it will
    // disable custom. All custom scripts for taproot should have prefix 'tr_'
    if (customScripts) {
      const cs = P.apply(Script, P.coders.match(customScripts));
      const c = cs.decode(script);
      if (c !== undefined) {
        if (typeof c.type !== 'string' || !c.type.startsWith('tr_'))
          throw new Error(`P2TR: invalid custom type=${c.type}`);
        return;
      }
    }
    if (allowUnknownOutputs) return;
  }
  if (!['tr_ns', 'tr_ms'].includes(out.type))
    throw new Error(`P2TR: invalid leaf script=${out.type}`);
  const outms = out as OutTRNSType | OutTRMSType;
  if (!allowUnknownOutputs && outms.pubkeys) {
    for (const p of outms.pubkeys) {
      if (u.equalBytes(p, u.TAPROOT_UNSPENDABLE_KEY))
        throw new Error('Unspendable taproot key in leaf script');
      // It's likely a mistake at this point:
      // 1. p2tr(A, p2tr_ns(2, [A, B])) == p2tr(A, p2tr_pk(B)) (A or B key)
      // but will take more space and fees.
      // 2. For multi-sig p2tr(A, p2tr_ns(2, [A, B, C])) it's probably a security issue:
      // User creates 2 of 3 multisig of keys [A, B, C],
      // but key A always can spend whole output without signatures from other keys.
      // p2tr(A, p2tr_ns(2, [B, C, D])) is ok: A or (B and C) or (B and D) or (C and D)
      if (u.equalBytes(p, internalPubKey)) {
        throw new Error(
          'Using P2TR with leaf script with same key as internal key is not supported'
        );
      }
    }
  }
}

/** Taproot key-path descriptor. */
export type P2TR = {
  /** Payment-script tag for taproot outputs. */
  type: 'tr';
  /** Serialized v1 witness-program script. */
  script: Bytes;
  /** Bech32m address for the descriptor. */
  address: string;
  /** Tweaked x-only output key committed by the address and script. */
  tweakedPubkey: Bytes;
  /** Internal x-only taproot key before tweaking. */
  tapInternalKey: Bytes;
};
/** Taproot descriptor with a script tree attached. */
export type P2TR_TREE = P2TR & {
  tapMerkleRoot: Bytes;
  tapLeafScript: TransactionInput['tapLeafScript'];
  leaves: TaprootLeaf[];
};

/** Node accepted when constructing a taproot script tree. */
export type TaprootNode = {
  script: Bytes | string;
  leafVersion?: number;
  weight?: number;
} & Partial<P2TR_TREE>;
/** Recursive taproot tree input. */
export type TaprootScriptTree = TaprootNode | TaprootScriptTree[];
/** Flat list of weighted taproot leaves. */
export type TaprootScriptList = TaprootNode[];
type _TaprootTreeInternal = {
  weight?: number;
  childs?: [_TaprootTreeInternal[], _TaprootTreeInternal[]];
};

// Helper for generating binary tree from list, with weights
/**
 * Converts a flat list of weighted leaves into a binary taproot tree.
 * @param taprootList - weighted leaves to arrange
 * @returns Binary taproot script tree.
 * @example
 * Start from a flat weighted list, then let the helper build the binary tree shape.
 * ```ts
 * import { hex } from '@scure/base';
 * import { p2tr_pk, taprootListToTree } from '@scure/btc-signer/payment.js';
 * taprootListToTree([
 *   p2tr_pk(hex.decode('f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9')),
 *   p2tr_pk(hex.decode('dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659')),
 * ]);
 * ```
 */
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

/** Taproot leaf with its merkle path. */
export type TaprootLeaf = {
  /** Leaf marker inside the annotated taproot tree. */
  type: 'leaf';
  /** Tapleaf version committed by the merkle tree. */
  version?: number;
  /** Serialized leaf script. */
  script: Bytes;
  /** Tagged tapleaf hash for the script and version. */
  hash: Bytes;
  /** Merkle path hashes required for script-path spending. */
  path: Bytes[];
};

/** Internal taproot tree annotated with merkle paths. */
export type HashedTreeWithPath =
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

function taprootHashTree(
  tree: TaprootScriptTree,
  internalPubKey: Bytes,
  allowUnknownOutputs = false,
  customScripts?: CustomScript[]
): HashedTree {
  if (!tree) throw new Error('taprootHashTree: empty tree');
  if (Array.isArray(tree) && tree.length === 1) tree = tree[0];
  // Terminal node (leaf)
  if (!Array.isArray(tree)) {
    const { leafVersion: version, script: leafScript } = tree;
    // Earliest tree walk where we can validate tapScripts
    if (tree.tapLeafScript || (tree.tapMerkleRoot && !u.equalBytes(tree.tapMerkleRoot, P.EMPTY)))
      throw new Error('P2TR: tapRoot leafScript cannot have tree');
    const script = typeof leafScript === 'string' ? hex.decode(leafScript) : leafScript;
    if (!u.isBytes(script)) throw new Error(`checkScript: wrong script type=${script}`);
    checkTaprootScript(script, internalPubKey, allowUnknownOutputs, customScripts);
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
  const left = taprootHashTree(tree[0], internalPubKey, allowUnknownOutputs, customScripts);
  const right = taprootHashTree(tree[1], internalPubKey, allowUnknownOutputs, customScripts);
  // We cannot swap left/right here, since it will change structure of tree
  let [lH, rH] = [left.hash, right.hash];
  if (u.compareBytes(rH, lH) === -1) [lH, rH] = [rH, lH];
  return { type: 'branch', left, right, hash: u.tagSchnorr('TapBranch', lH, rH) };
}

/** Default tapleaf version used by taproot script-path outputs. */
export const TAP_LEAF_VERSION = 0xc0;
/**
 * Computes the tagged hash of a tapleaf script.
 * @param script - tapleaf script bytes
 * @param version - tapleaf version byte
 * @returns Tapleaf hash.
 * @example
 * Hash a finalized tapscript leaf before placing it into a Merkle tree.
 * ```ts
 * tapLeafHash(new Uint8Array([0x51]));
 * ```
 */
export const tapLeafHash = (script: Bytes, version: number = TAP_LEAF_VERSION): Bytes =>
  u.tagSchnorr('TapLeaf', new Uint8Array([version]), VarBytes.encode(script));

// Works as key OR tree.
// If we only have tree, need to add unspendable key, otherwise
// complex multisig wallet can be spent by owner of key only. See TAPROOT_UNSPENDABLE_KEY
/** Conditional taproot return type for key-only or tree-backed outputs. */
export type P2TRRet<T> = T extends TaprootScriptTree ? P2TR_TREE : P2TR;
/**
 * Builds a taproot output from an internal key and optional script tree.
 * @param internalPubKey - x-only internal public key, hex string, or `undefined` for script-only outputs
 * @param tree - optional taproot script tree
 * @param network - address network parameters
 * @param allowUnknownOutputs - whether unknown leaf scripts are allowed
 * @param customScripts - optional custom script codecs for taproot leaves
 * @returns Taproot descriptor with optional script-path metadata.
 * @throws If the internal key or taproot script tree is invalid. {@link Error}
 * @example
 * Combine script leaves into a final taproot output descriptor and address.
 * ```ts
 * import { hex } from '@scure/base';
 * import { p2tr, p2tr_pk } from '@scure/btc-signer/payment.js';
 * p2tr(
 *   undefined,
 *   [p2tr_pk(hex.decode('f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9'))]
 * );
 * ```
 */
export function p2tr(
  internalPubKey: Bytes | string,
  tree?: undefined,
  network?: BTC_NETWORK,
  allowUnknownOutputs?: boolean,
  customScripts?: CustomScript[]
): Extends<P2TR, P2Ret>;
export function p2tr(
  internalPubKey: Bytes | string | undefined,
  tree: TaprootScriptTree,
  network?: BTC_NETWORK,
  allowUnknownOutputs?: boolean,
  customScripts?: CustomScript[]
): Extends<P2TR_TREE, P2Ret>;
export function p2tr(
  internalPubKey?: Bytes | string,
  tree?: TaprootScriptTree,
  network: BTC_NETWORK = NETWORK,
  allowUnknownOutputs = false,
  customScripts?: CustomScript[]
): Extends<P2TR & Partial<P2TR_TREE>, P2Ret> {
  // Unspendable
  if (!internalPubKey && !tree) throw new Error('p2tr: should have pubKey or scriptTree (or both)');
  const pubKey =
    typeof internalPubKey === 'string'
      ? hex.decode(internalPubKey)
      : internalPubKey || u.TAPROOT_UNSPENDABLE_KEY;
  if (!isValidPubkey(pubKey, u.PubT.schnorr)) throw new Error('p2tr: non-schnorr pubkey');
  if (tree) {
    let hashedTree = taprootAddPath(
      taprootHashTree(tree, pubKey, allowUnknownOutputs, customScripts)
    );
    const tapMerkleRoot = hashedTree.hash;
    const [tweakedPubkey, parity] = u.taprootTweakPubkey(pubKey, tapMerkleRoot);
    const leaves = taprootWalkTree(hashedTree).map((l) => ({
      ...l,
      controlBlock: TaprootControlBlock.encode({
        version: (l.version || TAP_LEAF_VERSION) + parity,
        internalKey: pubKey,
        merklePath: l.path,
      }),
    }));
    return {
      type: 'tr',
      script: OutScript.encode({ type: 'tr', pubkey: tweakedPubkey }),
      address: Address(network).encode({ type: 'tr', pubkey: tweakedPubkey }),
      // For tests
      tweakedPubkey,
      // PSBT stuff
      tapInternalKey: pubKey,
      leaves,
      tapLeafScript: leaves.map((l) => [
        TaprootControlBlock.decode(l.controlBlock),
        u.concatBytes(l.script, new Uint8Array([l.version || TAP_LEAF_VERSION])),
      ]),
      tapMerkleRoot,
    } as const satisfies P2TR_TREE;
  } else {
    const tweakedPubkey = u.taprootTweakPubkey(pubKey, P.EMPTY)[0];
    return {
      type: 'tr',
      script: OutScript.encode({ type: 'tr', pubkey: tweakedPubkey }),
      address: Address(network).encode({ type: 'tr', pubkey: tweakedPubkey }),
      // For tests
      tweakedPubkey,
      // PSBT stuff
      tapInternalKey: pubKey,
    } as const satisfies P2TR;
  }
}

// Returns all combinations of size M from lst
/**
 * Returns all size-`m` combinations from a list.
 * @param m - size of each combination
 * @param list - input items to combine
 * @returns Array of combinations.
 * @throws If the combination size or input list is invalid. {@link Error}
 * @example
 * Enumerate all size-two subsets of a short list.
 * ```ts
 * combinations(2, [1, 2, 3]);
 * ```
 */
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
export type P2TR_NS = {
  /** Payment-script tag for taproot `CHECKSIGVERIFY` leaf scripts. */
  type: 'tr_ns';
  /** Serialized tapscript leaf. */
  script: Bytes;
};
/**
 * Builds the leaf set for an M-of-N `CHECKSIGVERIFY` taproot policy.
 * @param m - number of required signatures
 * @param pubkeys - participating Schnorr public keys
 * @param allowSamePubkeys - whether duplicate keys are allowed
 * @returns Array of taproot leaf descriptors.
 * @throws If the taproot multisig parameters are invalid. {@link Error}
 * @example
 * Build the leaf set for an M-of-N taproot `CHECKSIGVERIFY` policy.
 * ```ts
 * import { hex } from '@scure/base';
 * import { p2tr_ns } from '@scure/btc-signer/payment.js';
 * p2tr_ns(1, [hex.decode('f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9')], true);
 * ```
 */
export const p2tr_ns = (
  m: number,
  pubkeys: Bytes[],
  allowSamePubkeys = false
): Extends<P2TR_NS, P2Ret>[] => {
  if (!allowSamePubkeys) uniqPubkey(pubkeys);
  return combinations(m, pubkeys).map(
    (i) =>
      ({
        type: 'tr_ns',
        script: OutScript.encode({ type: 'tr_ns', pubkeys: i }),
      }) as const
  ) satisfies P2Ret[];
};
// Taproot public key (case of p2tr_ns)
/** Single-key taproot leaf descriptor. */
export type P2TR_PK = P2TR_NS;
/**
 * Builds a single-key taproot leaf script.
 * @param pubkey - Schnorr public key
 * @returns Taproot single-key leaf descriptor.
 * @throws If the taproot single-key leaf cannot be encoded. {@link Error}
 * @example
 * Build a single-key tapscript leaf.
 * ```ts
 * import { hex } from '@scure/base';
 * import { p2tr_pk } from '@scure/btc-signer/payment.js';
 * p2tr_pk(hex.decode('f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9'));
 * ```
 */
export const p2tr_pk = (pubkey: Bytes): Extends<P2TR_PK, P2Ret> =>
  p2tr_ns(1, [pubkey], undefined)[0] satisfies P2Ret;

/** Taproot `CHECKSIGADD` multisig leaf descriptor. */
export type P2TR_MS = {
  /** Payment-script tag for taproot `CHECKSIGADD` leaf scripts. */
  type: 'tr_ms';
  /** Serialized tapscript leaf. */
  script: Bytes;
};
/**
 * Builds a `CHECKSIGADD` taproot multisig leaf.
 * @param m - number of required signatures
 * @param pubkeys - participating Schnorr public keys
 * @param allowSamePubkeys - whether duplicate keys are allowed
 * @returns Taproot multisig leaf descriptor.
 * @throws If the taproot multisig parameters are invalid. {@link Error}
 * @example
 * Build a `CHECKSIGADD` taproot multisig leaf.
 * ```ts
 * import { hex } from '@scure/base';
 * import { p2tr_ms } from '@scure/btc-signer/payment.js';
 * p2tr_ms(1, [hex.decode('f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9')], true);
 * ```
 */
export function p2tr_ms(
  m: number,
  pubkeys: Bytes[],
  allowSamePubkeys = false
): Extends<P2TR_MS, P2Ret> {
  if (!allowSamePubkeys) uniqPubkey(pubkeys);
  return {
    type: 'tr_ms',
    script: OutScript.encode({ type: 'tr_ms', pubkeys, m }),
  } as const satisfies P2Ret;
}

// Simple pubkey address, without complex scripts
/**
 * Derives a simple address from a private key.
 * @param type - address type to derive
 * @param privKey - private key bytes
 * @param network - address network parameters
 * @returns Encoded Bitcoin address.
 * @throws If the requested address type is unknown. {@link Error}
 * @example
 * Pick the output type first, then derive the matching address from the private key.
 * ```ts
 * import { getAddress } from '@scure/btc-signer/payment.js';
 * import { randomPrivateKeyBytes } from '@scure/btc-signer/utils.js';
 * getAddress('wpkh', randomPrivateKeyBytes());
 * ```
 */
export function getAddress(
  type: 'pkh' | 'wpkh' | 'tr',
  privKey: Bytes,
  network: BTC_NETWORK = NETWORK
): string {
  if (type === 'tr') {
    return p2tr(u.pubSchnorr(privKey), undefined, network).address;
  }
  const pubKey = u.pubECDSA(privKey);
  if (type === 'pkh') return p2pkh(pubKey, network).address;
  if (type === 'wpkh') return p2wpkh(pubKey, network).address;
  throw new Error(`getAddress: unknown type=${type}`);
}

export const _sortPubkeys = (pubkeys: Bytes[]): Bytes[] => Array.from(pubkeys).sort(u.compareBytes);

/**
 * Builds a classic M-of-N multisig output, wrapped in P2SH or P2WSH.
 * @param m - number of required signatures
 * @param pubkeys - participating public keys
 * @param sorted - whether to sort the public keys first
 * @param witness - whether to wrap the result as native SegWit
 * @param network - address network parameters
 * @returns Multisig payment descriptor.
 * @throws If the multisig parameters or wrapped script are invalid. {@link Error}
 * @example
 * Wrap a classic 2-of-2 script into an addressable multisig output.
 * ```ts
 * import { multisig } from '@scure/btc-signer/payment.js';
 * import { pubECDSA, randomPrivateKeyBytes } from '@scure/btc-signer/utils.js';
 * multisig(
 *   2,
 *   [pubECDSA(randomPrivateKeyBytes()), pubECDSA(randomPrivateKeyBytes())],
 *   true,
 *   true
 * );
 * ```
 */
export function multisig(
  m: number,
  pubkeys: Bytes[],
  sorted = false,
  witness = false,
  network: BTC_NETWORK = NETWORK
): P2Ret {
  const ms = p2ms(m, sorted ? _sortPubkeys(pubkeys) : pubkeys);
  return witness ? p2wsh(ms, network) : p2sh(ms, network);
}

/**
 * Builds a multisig output after lexicographically sorting the keys.
 * @param m - number of required signatures
 * @param pubkeys - participating public keys
 * @param witness - whether to wrap the result as native SegWit
 * @param network - address network parameters
 * @returns Sorted multisig payment descriptor.
 * @throws If the multisig parameters or wrapped script are invalid. {@link Error}
 * @example
 * Sort public keys deterministically before constructing the multisig address.
 * ```ts
 * import { sortedMultisig } from '@scure/btc-signer/payment.js';
 * import { pubECDSA, randomPrivateKeyBytes } from '@scure/btc-signer/utils.js';
 * sortedMultisig(
 *   2,
 *   [pubECDSA(randomPrivateKeyBytes()), pubECDSA(randomPrivateKeyBytes())],
 *   true
 * );
 * ```
 */
export function sortedMultisig(
  m: number,
  pubkeys: Bytes[],
  witness = false,
  network: BTC_NETWORK = NETWORK
): P2Ret {
  return multisig(m, pubkeys, true, witness, network);
}

const base58check = /* @__PURE__ */ createBase58check(u.sha256);

function validateWitness(version: number, data: Bytes) {
  if (data.length < 2 || data.length > 40) throw new Error('Witness: invalid length');
  if (version > 16) throw new Error('Witness: invalid version');
  if (version === 0 && !(data.length === 20 || data.length === 32))
    throw new Error('Witness: invalid length for version');
}

function programToWitness(version: number, data: Bytes, network = NETWORK) {
  validateWitness(version, data);
  const coder = version === 0 ? bech32 : bech32m;
  return coder.encode(network.bech32, [version].concat(coder.toWords(data)));
}

function formatKey(hashed: Bytes, prefix: number[]): string {
  return base58check.encode(u.concatBytes(Uint8Array.from(prefix), hashed));
}

/**
 * Wallet-import-format coder for private keys.
 * @param network - address network parameters
 * @returns WIF coder.
 * @example
 * Encode or decode wallet-import-format private keys.
 * ```ts
 * const coder = WIF();
 * coder.encode(new Uint8Array(32).fill(1));
 * ```
 */
export function WIF(network: BTC_NETWORK = NETWORK): Coder<Bytes, string> {
  return {
    encode(privKey: Bytes) {
      const compressed = u.concatBytes(privKey, new Uint8Array([0x01]));
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
/**
 * Address encoder/decoder for a specific Bitcoin network.
 * @param network - address network parameters
 * @returns Address coder backed by the provided network.
 * @example
 * Create a network-specific address coder and encode a payment descriptor.
 * ```ts
 * import { Address, p2wpkh } from '@scure/btc-signer/payment.js';
 * import { pubECDSA, randomPrivateKeyBytes } from '@scure/btc-signer/utils.js';
 * const coder = Address();
 * coder.encode(p2wpkh(pubECDSA(randomPrivateKeyBytes())));
 * ```
 */
export function Address(network: BTC_NETWORK = NETWORK) {
  return {
    encode(from: P.UnwrapCoder<OutScriptType>): string {
      const { type } = from;
      if (type === 'wpkh') return programToWitness(0, from.hash, network);
      else if (type === 'wsh') return programToWitness(0, from.hash, network);
      else if (type === 'tr') return programToWitness(1, from.pubkey, network);
      else if (type === 'pkh') return formatKey(from.hash, [network.pubKeyHash]);
      else if (type === 'sh') return formatKey(from.hash, [network.scriptHash]);
      throw new Error(`Unknown address type=${type}`);
    },
    decode(address: string): P.UnwrapCoder<OutScriptType> {
      if (address.length < 14 || address.length > 74) throw new Error('Invalid address length');
      // Bech32
      if (network.bech32 && address.toLowerCase().startsWith(`${network.bech32}1`)) {
        let res;
        try {
          res = bech32.decode(address as `${string}1${string}`);
          if (res.words[0] !== 0) throw new Error(`bech32: wrong version=${res.words[0]}`);
        } catch (_) {
          // Starting from version 1 it is decoded as bech32m
          res = bech32m.decode(address as `${string}1${string}`);
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

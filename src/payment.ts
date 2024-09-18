import { Coder, hex, bech32, bech32m, createBase58check } from '@scure/base';
import * as P from 'micro-packed';
import { TaprootControlBlock, TransactionInput } from './psbt.js';
import { OpToNum, ScriptType, Script, VarBytes } from './script.js';
import { Bytes, NETWORK } from './utils.js';
import * as u from './utils.js';

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

/*
 * UNSAFE: Custom scripts: mostly ordinals, be very careful when crafting new scripts
 * Only taproot supported for now.
 * NOTE: we can use same to move finalization logic from Transaction, but it will significantly change audited code.
 */

type FinalizeSignature = [{ pubKey: Bytes; leafHash: Bytes }, Bytes];
type CustomScriptOut = { type: string } & Record<string, any>;
export type CustomScript = Coder<OptScript, CustomScriptOut | undefined> & {
  finalizeTaproot?: (
    script: Bytes,
    parsed: CustomScriptOut,
    signatures: FinalizeSignature[]
  ) => Bytes[] | undefined;
};

// We can validate this once, because of packed & coders
export const OutScript = P.validate(_OutScript, (i) => {
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
});
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

export function checkScript(script?: Bytes, redeemScript?: Bytes, witnessScript?: Bytes) {
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

// @ts-ignore
export const p2pk = (pubkey: Bytes, network = NETWORK): P2Ret => {
  // network is unused
  if (!isValidPubkey(pubkey, u.PubT.ecdsa)) throw new Error('P2PK: invalid publicKey');
  return {
    type: 'pk',
    script: OutScript.encode({ type: 'pk', pubkey }),
  };
};
export const p2pkh = (publicKey: Bytes, network = NETWORK): P2Ret => {
  if (!isValidPubkey(publicKey, u.PubT.ecdsa)) throw new Error('P2PKH: invalid publicKey');
  const hash = u.hash160(publicKey);
  return {
    type: 'pkh',
    script: OutScript.encode({ type: 'pkh', hash }),
    address: Address(network).encode({ type: 'pkh', hash }),
  };
};
export const p2sh = (child: P2Ret, network = NETWORK): P2Ret => {
  // It is already tested inside noble-hashes and checkScript
  const cs = child.script;
  if (!u.isBytes(cs)) throw new Error(`Wrong script: ${typeof child.script}, expected Uint8Array`);
  const hash = u.hash160(cs);
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
export const p2wsh = (child: P2Ret, network = NETWORK): P2Ret => {
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
  };
};
export const p2wpkh = (publicKey: Bytes, network = NETWORK): P2Ret => {
  if (!isValidPubkey(publicKey, u.PubT.ecdsa)) throw new Error('P2WPKH: invalid publicKey');
  if (publicKey.length === 65) throw new Error('P2WPKH: uncompressed public key');
  const hash = u.hash160(publicKey);
  return {
    type: 'wpkh',
    script: OutScript.encode({ type: 'wpkh', hash }),
    address: Address(network).encode({ type: 'wpkh', hash }),
  };
};
export const p2ms = (m: number, pubkeys: Bytes[], allowSamePubkeys = false): P2Ret => {
  if (!allowSamePubkeys) uniqPubkey(pubkeys);
  return { type: 'ms', script: OutScript.encode({ type: 'ms', pubkeys, m }) };
};

type HashedTree =
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

export type P2TROut = P2Ret & {
  tweakedPubkey: Uint8Array;
  tapInternalKey: Uint8Array;
  tapMerkleRoot?: Uint8Array;
  tapLeafScript?: TransactionInput['tapLeafScript'];
  leaves?: TaprootLeaf[];
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

export const TAP_LEAF_VERSION = 0xc0;
export const tapLeafHash = (script: Bytes, version = TAP_LEAF_VERSION) =>
  u.tagSchnorr('TapLeaf', new Uint8Array([version]), VarBytes.encode(script));

// Works as key OR tree.
// If we only have tree, need to add unspendable key, otherwise
// complex multisig wallet can be spent by owner of key only. See TAPROOT_UNSPENDABLE_KEY
export function p2tr(
  internalPubKey?: Bytes | string,
  tree?: TaprootScriptTree,
  network = NETWORK,
  allowUnknownOutputs = false,
  customScripts?: CustomScript[]
): P2TROut {
  // Unspendable
  if (!internalPubKey && !tree) throw new Error('p2tr: should have pubKey or scriptTree (or both)');
  const pubKey =
    typeof internalPubKey === 'string'
      ? hex.decode(internalPubKey)
      : internalPubKey || u.TAPROOT_UNSPENDABLE_KEY;
  if (!isValidPubkey(pubKey, u.PubT.schnorr)) throw new Error('p2tr: non-schnorr pubkey');
  let hashedTree = tree
    ? taprootAddPath(taprootHashTree(tree, pubKey, allowUnknownOutputs, customScripts))
    : undefined;
  const tapMerkleRoot = hashedTree ? hashedTree.hash : undefined;
  const [tweakedPubkey, parity] = u.taprootTweakPubkey(pubKey, tapMerkleRoot || P.EMPTY);
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
      u.concatBytes(l.script, new Uint8Array([l.version || TAP_LEAF_VERSION])),
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

export function p2tr_ms(m: number, pubkeys: Bytes[], allowSamePubkeys = false) {
  if (!allowSamePubkeys) uniqPubkey(pubkeys);
  return {
    type: 'tr_ms',
    script: OutScript.encode({ type: 'tr_ms', pubkeys, m }),
  };
}

// Simple pubkey address, without complex scripts
export function getAddress(type: 'pkh' | 'wpkh' | 'tr', privKey: Bytes, network = NETWORK) {
  if (type === 'tr') {
    return p2tr(u.pubSchnorr(privKey), undefined, network).address;
  }
  const pubKey = u.pubECDSA(privKey);
  if (type === 'pkh') return p2pkh(pubKey, network).address;
  if (type === 'wpkh') return p2wpkh(pubKey, network).address;
  throw new Error(`getAddress: unknown type=${type}`);
}

export const _sortPubkeys = (pubkeys: Bytes[]) => Array.from(pubkeys).sort(u.compareBytes);

export function multisig(
  m: number,
  pubkeys: Bytes[],
  sorted = false,
  witness = false,
  network = NETWORK
) {
  const ms = p2ms(m, sorted ? _sortPubkeys(pubkeys) : pubkeys);
  return witness ? p2wsh(ms, network) : p2sh(ms, network);
}

export function sortedMultisig(m: number, pubkeys: Bytes[], witness = false, network = NETWORK) {
  return multisig(m, pubkeys, true, witness, network);
}

const base58check = createBase58check(u.sha256);

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

export function WIF(network = NETWORK): Coder<Bytes, string> {
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
export function Address(network = NETWORK) {
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

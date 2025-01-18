/*! scure-btc-signer - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import {
  compareBytes,
  concatBytes,
  isBytes,
  pubSchnorr,
  randomPrivateKeyBytes,
  taprootTweakPubkey,
} from './utils.js';
// should multisig be exported as classicMultisig?
// prettier-ignore
export {
  multisig,
  p2ms, p2pk, p2pkh, p2sh, p2tr, p2tr_ms, p2tr_ns, p2tr_pk, p2wpkh, p2wsh
} from './payment.js';
export {
  CompactSize,
  MAX_SCRIPT_BYTE_LENGTH,
  OP,
  RawTx,
  RawWitness,
  Script,
  ScriptNum,
} from './script.js';
export type { ScriptType } from './script.js';
export { Transaction } from './transaction.js';
export { NETWORK, TAPROOT_UNSPENDABLE_KEY, TEST_NETWORK } from './utils.js';
export { getInputType, selectUTXO } from './utxo.js';

export const utils = {
  isBytes,
  concatBytes,
  compareBytes,
  pubSchnorr,
  randomPrivateKeyBytes,
  taprootTweakPubkey,
};

export {
  _sortPubkeys,
  Address,
  combinations,
  getAddress,
  OutScript,
  sortedMultisig,
  taprootListToTree,
  WIF,
} from './payment.js'; // remove
// remove
export type { CustomScript, OptScript } from './payment.js';
export { _DebugPSBT, TaprootControlBlock } from './psbt.js'; // remove
export { bip32Path, Decimal, DEFAULT_SEQUENCE, PSBTCombine, SigHash } from './transaction.js'; // remove
export { _cmpBig, _Estimator } from './utxo.js';

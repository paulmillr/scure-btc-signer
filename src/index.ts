/*! scure-btc-signer - MIT License (c) 2022 Paul Miller (paulmillr.com) */
import {
  compareBytes,
  concatBytes,
  isBytes,
  pubSchnorr,
  randomPrivateKeyBytes,
  taprootTweakPubkey,
} from './utils.ts';
// should multisig be exported as classicMultisig?
// prettier-ignore
export {
  multisig,
  p2ms, p2pk, p2pkh, p2sh, p2tr, p2tr_ms, p2tr_ns, p2tr_pk, p2wpkh, p2wsh
} from './payment.ts';
export {
  CompactSize,
  MAX_SCRIPT_BYTE_LENGTH,
  OP,
  RawTx,
  RawWitness,
  Script,
  ScriptNum,
} from './script.ts';
export type { ScriptType } from './script.ts';
export { getInputType, Transaction } from './transaction.ts';
export { NETWORK, TAPROOT_UNSPENDABLE_KEY, TEST_NETWORK } from './utils.ts';
export { selectUTXO } from './utxo.ts';

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
} from './payment.ts'; // remove
// remove
export type { CustomScript, OptScript } from './payment.ts';
export { _DebugPSBT, TaprootControlBlock } from './psbt.ts'; // remove
export { bip32Path, Decimal, DEFAULT_SEQUENCE, PSBTCombine, SigHash } from './transaction.ts'; // remove
export { _cmpBig, _Estimator } from './utxo.ts';

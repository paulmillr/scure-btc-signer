/*! scure-btc-signer - MIT License (c) 2022 Paul Miller (paulmillr.com) */

// prettier-ignore
export {
  p2pk, p2pkh, p2sh, p2ms, p2wsh, p2wpkh, p2tr, p2tr_ns, p2tr_ms, p2tr_pk,
  multisig // => classicMultisig?
} from './payment.js';
export { OP, RawTx, CompactSize, Script, ScriptNum } from './script.js';
export { Transaction } from './transaction.js';
export { selectUTXO } from './utxo.js';
export { NETWORK, TEST_NETWORK, compareBytes as _cmpBytes, TAPROOT_UNSPENDABLE_KEY } from './utils.js';

// Utils
// prettier-ignore
export {
  Address, getAddress, WIF,
  taprootListToTree, OutScript, _sortPubkeys, sortedMultisig, combinations
} from './payment.js'; // remove
export { _DebugPSBT, TaprootControlBlock } from './psbt.js'; // remove
export { Decimal, bip32Path, SigHash, PSBTCombine, DEFAULT_SEQUENCE } from './transaction.js'; // remove
export { _cmpBig, _Estimator } from './utxo.js';

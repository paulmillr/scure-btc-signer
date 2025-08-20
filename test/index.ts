import { should } from '@paulmillr/jsbt/test.js';

import './basic.test.ts';
import './utils.test.ts';
// Deterministic Pay-to-script-hash multi-signature addresses through public key sorting
import './bip67-multisig.test.ts';
// Partially Signed Bitcoin Transaction Format
import './bip174-psbt.test.ts';
// BIP324: elligatorswift
import './bip324-p2p.test.ts';
// Schnorr Signatures for secp256k1
import './bip340-schnorr.test.ts';
// Taproot: SegWit version 1 spending rules
import './bip174-psbt-extended.test.ts';
import './bip327-musig2.test.ts';
import './bip341-taproot.test.ts';
import './taproot-multisig.test.ts';
import './utxo-select.test.ts';

should.runWhen(import.meta.url);

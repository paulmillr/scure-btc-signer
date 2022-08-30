import { should } from 'micro-should';

import './utils.test.js';
import './basic.test.js';
// Deterministic Pay-to-script-hash multi-signature addresses through public key sorting
import './bip67-multisig.test.js';
// Partially Signed Bitcoin Transaction Format
import './bip174-psbt.test.js';
// Schnorr Signatures for secp256k1
import './bip340-schnorr.test.js';
// Taproot: SegWit version 1 spending rules
import './bip341-taproot.test.js';
import './taproot-multisig.test.js';

should.run();

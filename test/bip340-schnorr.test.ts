import { schnorr } from '@noble/curves/secp256k1.js';
import { hexToBytes } from '@noble/curves/utils.js';
import { should } from '@paulmillr/jsbt/test.js';
import { deepStrictEqual } from 'node:assert';
import { default as v340 } from './vectors/bip340.json' with { type: 'json' };

// BIP340 (same as in secp256k1, just to be sure)
for (const v of v340) {
  should(`BIP340(schnorr): vector=${v.index}`, async () => {
    const pub = hexToBytes(v['public key']);
    const msg = hexToBytes(v['message']);
    const expSig = hexToBytes(v['signature']);
    if (v['secret key']) {
      const sec = hexToBytes(v['secret key']);
      const rnd = hexToBytes(v['aux_rand']);
      deepStrictEqual(schnorr.getPublicKey(sec), pub);
      const sig = await schnorr.sign(msg, sec, rnd);
      const sigS = schnorr.sign(msg, sec, rnd);
      deepStrictEqual(sig, expSig);
      deepStrictEqual(sigS, expSig);
      deepStrictEqual(await schnorr.verify(sigS, msg, pub), true);
      deepStrictEqual(schnorr.verify(sig, msg, pub), true);
    } else {
      const passed = await schnorr.verify(expSig, msg, pub);
      const passedS = schnorr.verify(expSig, msg, pub);
      const res = v['verification result'] === 'TRUE';
      deepStrictEqual(passed, res);
      deepStrictEqual(passedS, res);
    }
  });
}

should.runWhen(import.meta.url);

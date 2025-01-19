import { deepStrictEqual } from 'node:assert';
import { should } from 'micro-should';
import { hex } from '@scure/base';
import { schnorr } from '@noble/curves/secp256k1';
import { default as v340 } from './fixtures/bip340.json' with { type: 'json' };

// BIP340 (same as in secp256k1, just to be sure)
for (const v of v340) {
  should(`BIP340(schnorr): vector=${v.index}`, async () => {
    const pub = v['public key'].toLowerCase();
    const msg = v['message'];
    const expSig = v['signature'];
    if (v['secret key']) {
      const sec = v['secret key'];
      const rnd = v['aux_rand'];
      deepStrictEqual(hex.encode(schnorr.getPublicKey(sec)), pub);
      const sig = await schnorr.sign(msg, sec, rnd);
      const sigS = schnorr.sign(msg, sec, rnd);
      deepStrictEqual(hex.encode(sig), expSig.toLowerCase());
      deepStrictEqual(hex.encode(sigS), expSig.toLowerCase());
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

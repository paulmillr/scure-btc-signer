import { deepStrictEqual, throws } from 'assert';
import { should } from 'micro-should';
import { hex, base64 } from '@scure/base';
import * as btc from '../../index.js';
import { default as rpcPSBT } from './fixtures/rpc_psbt.json' assert { type: 'json' };

for (let i = 0; i < rpcPSBT.invalid.length; i++) {
  should(`rpcPSBT(${i}): invalid`, () => {
    throws(() => btc.Transaction.fromPSBT(base64.decode(rpcPSBT.invalid[i])));
  });
}

for (let i = 0; i < rpcPSBT.valid.length; i++) {
  // Broken unsigned tx (64 inputs count, but after that only 31 byte, bitcoin will parse that, but this is unreasonable)
  // 02000000 0001 40 420f000000000017a9146e91b72d5593e7d4391e2ff44e91e985c31641f087 00000000
  // 02000000 version
  //          0001 segwit flag
  //               40 -- 64 inputs
  //                                                                      lockTime   00000000
  if (i === 0) continue;
  if (i === 5) continue;
  should(`rpcPSBT(${i}): valid`, () => {
    btc.Transaction.fromPSBT(base64.decode(rpcPSBT.valid[i]));
  });
}

for (let i = 0; i < rpcPSBT.creator.length; i++) {
  const t = rpcPSBT.creator[i];
  const regtest = {
    bech32: 'bcrt',
    bip32: {
      public: 0x043587cf,
      private: 0x04358394,
    },
    pubKeyHash: 0x6f,
    scriptHash: 0xc4,
    wif: 0xef,
  };
  should(`rpcPSBT(${i}): creator`, () => {
    const tx = new btc.Transaction();
    // Already reversed
    for (const i of t.inputs) tx.addInput({ hash: hex.decode(i.txid), index: i.vout });
    for (const o of t.outputs) {
      const [k, v] = Object.entries(o)[0];
      tx.addOutputAddress(k, '' + v, regtest);
    }
    deepStrictEqual(base64.encode(tx.toPSBT()), t.result);
  });
}
for (let i = 0; i < rpcPSBT.signer.length; i++) {
  const t = rpcPSBT.signer[i];
  const regtest = {
    bech32: 'bcrt',
    bip32: {
      public: 0x043587cf,
      private: 0x04358394,
    },
    pubKeyHash: 0x6f,
    scriptHash: 0xc4,
    wif: 0xef,
  };
  should(`rpcPSBT(${i}): signer`, () => {
    const tx = btc.Transaction.fromPSBT(base64.decode(t.psbt));
    tx.opts.lowR = true;
    // Some inputs should be unsigned, we throw error when signer didn't sign anything
    try {
      for (const p of t.privkeys) tx.sign(btc.WIF(regtest).decode(p));
    } catch (e) {}
    deepStrictEqual(base64.encode(tx.toPSBT()), t.result);
  });
}

for (let i = 0; i < rpcPSBT.combiner.length; i++) {
  const t = rpcPSBT.combiner[i];
  // Index with key: '0f010203040506070809': [Uint8Array],
  // This should be not possible, but it is in test by some reasons
  if (i === 1) continue;
  should(`rpcPSBT(${i}): combiner`, () => {
    const comb = btc.PSBTCombine(t.combine.map(base64.decode));
    // Test case has non-sorted order of keys which makes it different from our test case
    // NOTE: deepStrictEqual ignores order of keys, so this wont' fail. I'm not insane in the end.
    deepStrictEqual(btc._DebugPSBT.decode(comb), btc._DebugPSBT.decode(base64.decode(t.result)));
    const fromTest = btc.Transaction.fromPSBT(base64.decode(t.result));
    if (i === 0) {
      const ps = fromTest.inputs[1].partialSig;
      deepStrictEqual(ps.length, 2);
      fromTest.inputs[1].partialSig = [ps[1], ps[0]];
    }
    deepStrictEqual(btc.Transaction.fromPSBT(comb), fromTest);
  });
}
for (let i = 0; i < rpcPSBT.finalizer.length; i++) {
  const t = rpcPSBT.finalizer[i];
  should(`rpcPSBT(${i}): finalizer`, () => {
    const tx = btc.Transaction.fromPSBT(base64.decode(t.finalize));
    tx.finalize();
    deepStrictEqual(base64.encode(tx.toPSBT()), t.result);
  });
}

for (let i = 0; i < rpcPSBT.extractor.length; i++) {
  const t = rpcPSBT.extractor[i];
  should(`rpcPSBT(${i}): extractor`, () => {
    const tx = btc.Transaction.fromPSBT(base64.decode(t.extract));
    deepStrictEqual(tx.extract(), hex.decode(t.result));
  });
}

// ESM is broken.
import url from 'url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}

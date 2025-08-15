import { secp256k1, schnorr as secp256k1_schnorr } from '@noble/curves/secp256k1.js';
import * as P from 'micro-packed';
import { should } from 'micro-should';
import { deepStrictEqual } from 'node:assert';
import * as btc from '../src/index.ts';

// Takes 90 sec
should('big multisig (ours)', () => {
  // Slow: sign + preimage. We can cache preimage, but sign is more complex

  // Limits: p2_ms=20, p2tr_ms/p2tr_ns=999 (stacksize)
  // 999 encode as number support? check with bitcoin core
  const regtest = { bech32: 'bcrt', pubKeyHash: 0x6f, scriptHash: 0xc4 };

  const pkeys = [];
  for (let i = 1; i < 1000; i++) pkeys.push(P.U256BE.encode(BigInt(i)));

  const pubs = pkeys.map(secp256k1_schnorr.getPublicKey);
  const spend = btc.p2tr(undefined, btc.p2tr_ms(999, pubs), regtest);
  const outAddr = btc.p2wpkh(secp256k1.getPublicKey(pkeys[0], true), regtest);

  const tx = new btc.Transaction();
  tx.addInput({
    txid: '3d9955e6d03771e276f7b713734bade9c2c5e3c80d90b4b1da35deaa1c0c9bc6',
    index: 0,
    ...spend,
    witnessUtxo: { script: spend.script, amount: btc.Decimal.decode('1.5') },
  });
  tx.addOutputAddress(outAddr.address, btc.Decimal.decode('1'), regtest);
  let ts = Date.now();
  console.log('Creating big multisig of', pkeys.length, 'keys');
  for (let i = 0; i < pkeys.length; i++) {
    if (i % 30 === 0) console.log(Date.now() - ts, 'ms, added', i, 'keys of', pkeys.length);
    const p = pkeys[i];
    tx.sign(p);
  }
  console.log(Date.now() - ts, 'ms, signing done');
  tx.finalize();
  console.log(Date.now() - ts, 'ms, finalized');

  // Verified against regnet
  //console.log(hex.encode(tx.extract()))
  deepStrictEqual(tx.id, '2687c4795c995431d934432def1cda8264c95920ce404229ca5c21328d7c9bcc');
});

should.runWhen(import.meta.url);

import bench from '@paulmillr/jsbt/benchmark.js';
import { deepStrictEqual } from 'node:assert';
import * as btc from '../src/index.ts';
import { pubECDSA, sha256, signECDSA, signSchnorr } from '../src/utils.ts';

const priv = new Uint8Array(32).fill(1);
const aux = new Uint8Array(32).fill(2);
const txid = new Uint8Array(32).fill(3);
const msg = sha256(new Uint8Array(32).fill(4));
const pub = pubECDSA(priv);
const wpkh = btc.p2wpkh(pub);
const tr = btc.p2tr(btc.utils.pubSchnorr(priv));
const address = wpkh.address;

const makeTx = () => {
  const tx = new btc.Transaction();
  tx.addInput({
    txid,
    index: 0,
    witnessUtxo: { script: wpkh.script, amount: 10_000n },
  });
  tx.addOutput({ script: tr.script, amount: 9_000n });
  return tx;
};

const signedTx = makeTx();
signedTx.sign(priv, undefined, aux);
signedTx.finalize();
const rawTx = signedTx.extract();
const psbt = makeTx().toPSBT(2);
deepStrictEqual(btc.Transaction.fromRaw(rawTx).hex, signedTx.hex);

(async () => {
  console.log('# Keys and scripts');
  await bench('pubECDSA', () => pubECDSA(priv));
  await bench('signECDSA', () => signECDSA(msg, priv));
  await bench('signSchnorr', () => signSchnorr(msg, priv, aux));
  await bench('Address.decode', () => btc.Address().decode(address));
  await bench('OutScript.encode p2wpkh', () => btc.OutScript.encode(wpkh));
  await bench('OutScript.decode p2tr', () => btc.OutScript.decode(tr.script));

  console.log('# Transactions');
  await bench('RawTx.decode', () => btc.RawTx.decode(rawTx));
  await bench('Transaction.fromRaw', () => btc.Transaction.fromRaw(rawTx));
  await bench('Transaction.toPSBT v2', () => makeTx().toPSBT(2));
  await bench('Transaction.fromPSBT v2', () => btc.Transaction.fromPSBT(psbt));
  await bench('sign + finalize p2wpkh', () => {
    const tx = makeTx();
    tx.sign(priv, undefined, aux);
    tx.finalize();
    return tx.extract();
  });
})();

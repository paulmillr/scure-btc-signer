import * as btc from './index.js';
import { hex } from '@scure/base';
import { secp256k1 as secp } from '@noble/curves/secp256k1';

const privKey1 = hex.decode('0101010101010101010101010101010101010101010101010101010101010101');
const P1 = secp.getPublicKey(privKey1, true);

const wpkh = btc.p2wpkh(P1);

const tx = new btc.Transaction();

// Basic input test
tx.addInput({
  txid: hex.decode('0af50a00a22f74ece24c12cd667c290d3a35d48124a69f4082700589172a3aa2'),
  index: 0,
  ...wpkh,
  finalScriptSig: new Uint8Array(),
  sequence: 1,
});

// Doesn't force any fields on input addition (only on sign)
tx.addInput({
  sequence: 1,
});

tx.updateInput(0, {
  sequence: 1,
});

const nonWitnessUtxo =
  '0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f618765000000';
const nonWitnessUtxoB = hex.decode(nonWitnessUtxo);

tx.updateInput(0, { nonWitnessUtxo: nonWitnessUtxo });
tx.updateInput(0, { nonWitnessUtxo: nonWitnessUtxoB });
tx.addInput({
  txid: hex.decode('0af50a00a22f74ece24c12cd667c290d3a35d48124a69f4082700589172a3aa2'),
  index: 0,
  nonWitnessUtxo: nonWitnessUtxo,
});

tx.addInput({
  txid: hex.decode('0af50a00a22f74ece24c12cd667c290d3a35d48124a69f4082700589172a3aa2'),
  index: 0,
  nonWitnessUtxo: nonWitnessUtxoB,
});

// Should fail!
// tx.updateInput(0, {
//   nonWitnessUtxo: 1,
// });
// Outputs
tx.addOutput({ amount: 123n });
// should fail
// tx.updateOutput(0, { amount: '1' });
// tx.updateOutput(0, { amount: 1 });
// should fail
// tx.addOutput({ amount: '123' });
// tx.addOutput({ amount: 123 });

for (let i = 0; i < tx.inputsLength; i++) {
  // @ts-ignore
  console.log('I', tx.getInput(i));
}

for (let i = 0; i < tx.outputsLength; i++) {
  // @ts-ignore
  console.log('O', tx.getOutput(i));
}

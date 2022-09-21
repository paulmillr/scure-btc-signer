import { deepStrictEqual } from 'assert';
import { should } from 'micro-should';
import { hex, base64 } from '@scure/base';
import * as btc from '../../index.js';
import * as P from 'micro-packed';
import { default as p2tr } from './fixtures/bitcoinjs-taproot/p2tr.json' assert { type: 'json' };
import { default as tapPsbt } from './fixtures/bitcoinjs-taproot/psbt.json' assert { type: 'json' };

// TODO: move to index.ts as compat layer for bitcoinjs-lib?
function fromASM(asm) {
  const ops = asm.split(' ');
  const out = [];
  for (const op of ops) {
    if (op.startsWith('OP_')) {
      let opName = op.slice(3);
      if (opName === 'FALSE') opName = '0';
      if (opName === 'TRUE') opName = '1';
      // Handle numeric opcodes
      if (String(Number(opName)) === opName) opName = `OP_${opName}`;
      if (btc.OP[opName] === undefined) throw new Error(`Wrong opcode='${op}'`);
      out.push(opName);
    } else {
      out.push(hex.decode(op));
    }
  }
  return out;
}

should(`PSBT P2TR finalizeInput`, () => {
  const t = tapPsbt.finalizeInput.finalizeTapleafByHash;

  const tx = btc.Transaction.fromPSBT(base64.decode(t.psbt));
  // Remove signatures for leaf's we don't want to finalize
  if (tx.inputs[t.index].tapScriptSig) {
    tx.inputs[t.index].tapScriptSig = tx.inputs[t.index].tapScriptSig.filter((i) =>
      P.equalBytes(i[0].leafHash, hex.decode(t.leafHash))
    );
  }
  tx.finalize();
  deepStrictEqual(hex.encode(tx.toPSBT()), hex.encode(base64.decode(t.result)));
});

for (let i = 0; i < tapPsbt.bip174.finalizer.length; i++) {
  const t = tapPsbt.bip174.finalizer[i];
  if (!t.isTaproot) continue;
  should(`PSBT P2TR finalizeInput)(${i}): ${i.description}`, () => {
    const tx = btc.Transaction.fromPSBT(base64.decode(t.psbt));
    tx.finalize();
    deepStrictEqual(hex.encode(tx.toPSBT()), hex.encode(base64.decode(t.result)));
  });
}

for (let i = 0; i < tapPsbt.signInput.checks.length; i++) {
  const v = tapPsbt.signInput.checks[i];
  if (!v.isTaproot) continue;
  // tmp disable for script sig
  should(`PSBT P2TR sign1(${i}): ${v.description}`, () => {
    const t = v.shouldSign;
    const privKey = btc.WIF().decode(t.WIF);
    const tx = btc.Transaction.fromPSBT(base64.decode(t.psbt));
    // bitcoinjs p2tr tests uses old non-BIP340 compliant auxRand
    tx.signIdx(privKey, t.inputToCheck, undefined, null);
    deepStrictEqual(hex.encode(tx.toPSBT()), hex.encode(base64.decode(t.result)));
  });
}

// ESM is broken.
import url from 'url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}

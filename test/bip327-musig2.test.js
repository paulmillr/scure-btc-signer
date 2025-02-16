import { bytesToNumberBE, concatBytes, numberToBytesBE } from '@noble/curves/abstract/utils';
import { schnorr, secp256k1 } from '@noble/curves/secp256k1';
import { hexToBytes, randomBytes } from '@noble/hashes/utils';
import { describe, should } from 'micro-should';
import { deepStrictEqual, throws } from 'node:assert';
import * as musig2 from '../esm/musig2.js';
import { default as detSignVectors } from './fixtures/bip327/det_sign_vectors.json' with { type: 'json' };
import { default as keyAggVectors } from './fixtures/bip327/key_agg_vectors.json' with { type: 'json' };
import { default as keySortVectors } from './fixtures/bip327/key_sort_vectors.json' with { type: 'json' };
import { default as nonceAggVectors } from './fixtures/bip327/nonce_agg_vectors.json' with { type: 'json' };
import { default as nonceGenVectors } from './fixtures/bip327/nonce_gen_vectors.json' with { type: 'json' };
import { default as sigAggVectors } from './fixtures/bip327/sig_agg_vectors.json' with { type: 'json' };
import { default as signVerifyVectors } from './fixtures/bip327/sign_verify_vectors.json' with { type: 'json' };
import { default as tweakVectors } from './fixtures/bip327/tweak_vectors.json' with { type: 'json' };
const Point = secp256k1.ProjectivePoint;

const assertError = (error, cb) => {
  try {
    cb();
  } catch (e) {
    if (error.signer)
      deepStrictEqual(e, new musig2.InvalidContributionErr(error.signer, error.contrib));
    return;
  }
  throw new Error('missing error');
};

describe('BIP327', () => {
  should('Example', () => {
    // MuSig2 Multi-signature for Alice, Bob, and Carol
    // 1. Key Generation (for each signer: Alice, Bob, Carol)
    // - Alice's key generation
    const aliceSecretKey = randomBytes(32); // Alice generates a random 32-byte secret key
    const alicePublicKey = musig2.IndividualPubkey(aliceSecretKey); // Alice derives her individual public key from her secret key
    // - Bob's key generation
    const bobSecretKey = randomBytes(32); // Bob generates a random 32-byte secret key
    const bobPublicKey = musig2.IndividualPubkey(bobSecretKey); // Bob derives his individual public key from his secret key
    // - Carol's key generation
    const carolSecretKey = randomBytes(32); // Carol generates a random 32-byte secret key
    const carolPublicKey = musig2.IndividualPubkey(carolSecretKey); // Carol derives her individual public key from her secret key

    // 2. Key Aggregation (All signers participate by sharing public keys)
    const individualPublicKeys = [alicePublicKey, bobPublicKey, carolPublicKey]; // Collect all individual public keys
    const sortedPublicKeys = musig2.sortKeys(individualPublicKeys); // Sort public keys lexicographically (as required by MuSig2)
    const aggregatePublicKey = musig2.keyAggExport(musig2.keyAggregate(sortedPublicKeys)); // Extract the X-only aggregate public key (32 bytes)
    // At this point, all signers have the 'aggregatePublicKey' and 'keyAggContext'.
    // 3. Nonce Generation - Round 1 (Each signer generates and broadcasts public nonce)
    const msg = new Uint8Array(32).fill(5); // Example message to be signed (32-byte message is recommended for BIP340)
    // Alice generates her nonce
    const aliceNonces = musig2.nonceGen(alicePublicKey, aliceSecretKey, aggregatePublicKey, msg);
    // Secret nonce: must be kept secret and used only once per signing session!
    // Public nonce: to be shared with Bob and Carol
    // Bob generates his nonce
    const bobNonces = musig2.nonceGen(bobPublicKey, bobSecretKey, aggregatePublicKey, msg);
    // Carol generates her nonce
    const carolNonces = musig2.nonceGen(carolPublicKey, carolSecretKey, aggregatePublicKey, msg);
    // Each signer creates own instance
    const session = new musig2.Session(
      // 4. Nonce Aggregation (All signers participate by sharing public nonces)
      musig2.nonceAggregate([aliceNonces.public, bobNonces.public, carolNonces.public]),
      sortedPublicKeys,
      msg
    );
    // At this point, all signers have the 'aggregateNonce'.
    // 5. Partial Signature Generation - Round 2 (Each signer generates partial signature)
    // Alice generates her partial signature
    const alicePartialSignature = session.sign(aliceNonces.secret, aliceSecretKey);
    // Bob generates his partial signature
    const bobPartialSignature = session.sign(bobNonces.secret, bobSecretKey);
    // Carol generates her partial signature
    const carolPartialSignature = session.sign(carolNonces.secret, carolSecretKey);
    // 6. Partial Signature Aggregation (Anyone can aggregate partial signatures)
    const partialSignatures = [alicePartialSignature, bobPartialSignature, carolPartialSignature]; // Collect all partial signatures
    const finalSignature = session.partialSigAgg(partialSignatures); // Aggregate partial signatures to create the final signature
    // 7. Signature Verification (Anyone can verify the final signature)
    // Verify the final signature
    deepStrictEqual(schnorr.verify(finalSignature, msg, aggregatePublicKey), true);
  });
  should('Example (deterministic)', () => {
    // 1. Key Generation (for each signer: Alice, Bob, Carol) - Same as before
    // - Alice's key generation
    const aliceSecretKey = randomBytes(32);
    const alicePublicKey = musig2.IndividualPubkey(aliceSecretKey);
    // - Bob's key generation
    const bobSecretKey = randomBytes(32);
    const bobPublicKey = musig2.IndividualPubkey(bobSecretKey);
    // - Carol's key generation
    const carolSecretKey = randomBytes(32);
    const carolPublicKey = musig2.IndividualPubkey(carolSecretKey);
    // 2. Key Aggregation (All signers participate) - Same as before
    const individualPublicKeys = [alicePublicKey, bobPublicKey, carolPublicKey];
    const sortedPublicKeys = musig2.sortKeys(individualPublicKeys);
    const keyAggContext = musig2.keyAggregate(sortedPublicKeys);
    const aggregatePublicKey = musig2.keyAggExport(keyAggContext);
    // 3. Nonce Generation - Round 1 (Alice and Bob generate normal nonces, Carol will use deterministic)
    const msg = new Uint8Array(32).fill(5);
    // Alice generates her nonce (normal NonceGen)
    const aliceNonces = musig2.nonceGen(alicePublicKey, aliceSecretKey, aggregatePublicKey, msg);
    // Bob generates his nonce (normal NonceGen)
    const bobNonces = musig2.nonceGen(bobPublicKey, bobSecretKey, aggregatePublicKey, msg);
    // Carol will generate her nonce deterministically in Round 2, after receiving Alice and Bob's nonces.
    // Carol *does not* run nonceGen in this round yet for deterministic signing.
    // 4. Nonce Aggregation (Alice and Bob's nonces are aggregated for Carol)
    const otherPublicNoncesForCarol = [aliceNonces.public, bobNonces.public]; // Alice and Bob's public nonces for Carol
    // Aggregate nonces of *other* signers for Carol
    const aggregateOtherNonceForCarol = musig2.nonceAggregate(otherPublicNoncesForCarol);
    // Now Carol has 'aggregateOtherNonceForCarol' which is the aggregate nonce of all *other* signers.
    // 5. Deterministic Signing & Nonce Generation - Round 2 (Carol performs deterministic sign, including nonce gen)
    // Carol uses deterministicSign, providing the aggregate nonce of others
    const { publicNonce: carolPubNonce, partialSig: carolPartialSignature } =
      musig2.deterministicSign(
        carolSecretKey, // Carol's secret key
        aggregateOtherNonceForCarol, // Aggregate nonce of *other* signers (Alice & Bob)
        sortedPublicKeys, // All sorted public keys
        msg, // Message to sign
        [], // Tweaks (none in this example)
        [], // isXonly (none in this example)
        undefined // Optional randomness (can be undefined for fully deterministic, or provide extra randomness)
      );
    // At this point, Carol has generated both her public nonce and partial signature deterministically.
    // Now collect *all* public nonces including Carol's deterministic one
    const allPublicNonces = [aliceNonces.public, bobNonces.public, carolPubNonce];
    // 7. Partial Signature Generation - Round 2 (Alice & Bob generate partial signatures as before)
    const session = new musig2.Session(
      // 6. Complete Nonce Aggregation (Now include Carol's nonce)
      musig2.nonceAggregate(allPublicNonces),
      sortedPublicKeys,
      msg
    );
    // Alice generates her partial signature (using the complete session context)
    const alicePartialSignature = session.sign(aliceNonces.secret, aliceSecretKey);
    // Bob generates his partial signature (using the complete session context)
    const bobPartialSignature = session.sign(bobNonces.secret, bobSecretKey);
    // Carol's partial signature is already generated in step 5 ('carolPartialSignature')
    // 8. Partial Signature Aggregation (Anyone can aggregate partial signatures)
    const partialSignatures = [alicePartialSignature, bobPartialSignature, carolPartialSignature]; // Collect all partial signatures
    const finalSignature = session.partialSigAgg(partialSignatures);
    // 9. Signature Verification (Anyone can verify the final signature)
    deepStrictEqual(schnorr.verify(finalSignature, msg, aggregatePublicKey), true);
  });
  should('key sorting', () => {
    const t = keySortVectors;
    deepStrictEqual(musig2.sortKeys(t.pubkeys.map(hexToBytes)), t.sorted_pubkeys.map(hexToBytes));
  });
  should('key aggregation', () => {
    const pubkeys = keyAggVectors.pubkeys.map(hexToBytes);
    for (const t of keyAggVectors.valid_test_cases) {
      const pub = t.key_indices.map((i) => pubkeys[i]);
      deepStrictEqual(musig2.keyAggExport(musig2.keyAggregate(pub)), hexToBytes(t.expected));
    }
    const tweaks = keyAggVectors.tweaks.map(hexToBytes);
    for (const t of keyAggVectors.error_test_cases) {
      assertError(t.error, () => {
        musig2.keyAggregate(
          t.key_indices.map((i) => pubkeys[i]),
          t.tweak_indices.map((i) => tweaks[i]),
          t.is_xonly
        );
      });
    }
  });
  should('nonce geneneration', () => {
    for (const t of nonceGenVectors.test_cases) {
      const rand = hexToBytes(t.rand_);
      const pk = hexToBytes(t.pk);
      const sk = t.sk !== null ? hexToBytes(t.sk) : undefined;
      const aggpk = t.aggpk !== null ? hexToBytes(t.aggpk) : undefined;
      const msg = t.msg !== null ? hexToBytes(t.msg) : undefined;
      const extraIn = t.extra_in !== null ? hexToBytes(t.extra_in) : undefined;
      deepStrictEqual(musig2.nonceGen(pk, sk, aggpk, msg, extraIn, rand), {
        secret: hexToBytes(t.expected_secnonce),
        public: hexToBytes(t.expected_pubnonce),
      });
    }
  });
  should('nonce aggregate', () => {
    for (const t of nonceAggVectors.valid_test_cases) {
      const pubnonces = t.pnonce_indices.map((i) => hexToBytes(nonceAggVectors.pnonces[i]));
      deepStrictEqual(musig2.nonceAggregate(pubnonces), hexToBytes(t.expected));
    }
    for (const t of nonceAggVectors.error_test_cases) {
      const pubnonces = t.pnonce_indices.map((i) => hexToBytes(nonceAggVectors.pnonces[i]));
      assertError(t.error, () => musig2.nonceAggregate(pubnonces));
    }
  });
  should('sign & verify', () => {
    const sk = hexToBytes(signVerifyVectors.sk);
    const X = signVerifyVectors.pubkeys.map(hexToBytes);
    deepStrictEqual(X[0], musig2.IndividualPubkey(sk));
    const secnonces = signVerifyVectors.secnonces.map(hexToBytes);
    const pnonce = signVerifyVectors.pnonces.map(hexToBytes);
    // Public nonce correct for given secret nonce
    const k1 = bytesToNumberBE(secnonces[0].slice(0, 32));
    const k2 = bytesToNumberBE(secnonces[0].slice(32, 64));
    const R_s1 = Point.BASE.multiply(k1);
    const R_s2 = Point.BASE.multiply(k2);
    deepStrictEqual(pnonce[0], concatBytes(R_s1.toRawBytes(true), R_s2.toRawBytes(true)));

    for (const t of signVerifyVectors.valid_test_cases) {
      const pubkeys = t.key_indices.map((i) => X[i]);
      const pubnonces = t.nonce_indices.map((i) => hexToBytes(signVerifyVectors.pnonces[i]));
      const aggnonce = hexToBytes(signVerifyVectors.aggnonces[t.aggnonce_index]);
      deepStrictEqual(musig2.nonceAggregate(pubnonces), aggnonce); // aggnonce consistency
      const msg = hexToBytes(signVerifyVectors.msgs[t.msg_index]);
      const expected = hexToBytes(t.expected);
      const session = new musig2.Session(musig2.nonceAggregate(pubnonces), pubkeys, msg);
      const secnonceCopy = new Uint8Array(secnonces[0]);
      deepStrictEqual(session.sign(secnonceCopy, sk), expected);
      if (!session.partialSigVerify(expected, pubnonces, t.signer_index)) {
        throw new Error('partialSigVerify failed in valid test case');
      }
    }
    for (const t of signVerifyVectors.sign_error_test_cases) {
      const publicKeys = t.key_indices.map((i) => X[i]);
      const aggNonce = hexToBytes(signVerifyVectors.aggnonces[t.aggnonce_index]);
      const msg = hexToBytes(signVerifyVectors.msgs[t.msg_index]);
      const secnonce = new Uint8Array(secnonces[t.secnonce_index]);
      assertError(t.error, () => {
        // TODO: uses already aggregated nonce here
        const session = new musig2.Session(aggNonce, publicKeys, msg);
        session.sign(secnonce, sk, sessionCtx);
      });
    }
    for (const t of signVerifyVectors.verify_fail_test_cases) {
      const sig = hexToBytes(t.sig);
      const pubkeys = t.key_indices.map((i) => X[i]);
      const pubnonces = t.nonce_indices.map((i) => pnonce[i]);
      const msg = hexToBytes(signVerifyVectors.msgs[t.msg_index]);
      const session = new musig2.Session(musig2.nonceAggregate(pubnonces), pubkeys, msg);
      if (session.partialSigVerify(sig, pubnonces, t.signer_index)) {
        throw new Error('partialSigVerify unexpectedly succeeded on a failing test case');
      }
    }
    for (const t of signVerifyVectors.verify_error_test_cases) {
      const sig = hexToBytes(t.sig);
      const pubkeys = t.key_indices.map((i) => X[i]);
      const pubnonces = t.nonce_indices.map((i) => pnonce[i]);
      const msg = hexToBytes(signVerifyVectors.msgs[t.msg_index]);
      assertError(t.error, () => {
        const session = new musig2.Session(musig2.nonceAggregate(pubnonces), pubkeys, msg);
        return session.partialSigVerify(sig, pubnonces, t.signer_index);
      });
    }
  });

  should('tweak', () => {
    const sk = hexToBytes(tweakVectors.sk);
    const X = tweakVectors.pubkeys.map(hexToBytes);
    deepStrictEqual(X[0], musig2.IndividualPubkey(sk));
    const secnonce = hexToBytes(tweakVectors.secnonce);
    const pnonce = tweakVectors.pnonces.map(hexToBytes);
    const aggnonceVec = musig2.nonceAggregate(pnonce.slice(0, 3));
    deepStrictEqual(aggnonceVec, hexToBytes(tweakVectors.aggnonce));
    const tweaks = tweakVectors.tweaks.map(hexToBytes);
    const msg = hexToBytes(tweakVectors.msg);
    for (const t of tweakVectors.valid_test_cases) {
      const pubkeys = t.key_indices.map((i) => X[i]);
      const pubnonces = t.nonce_indices.map((i) => pnonce[i]);
      const tweaksCase = t.tweak_indices.map((i) => tweaks[i]);
      const isXonly = t.is_xonly;
      const signerIndex = t.signer_index;
      const expected = hexToBytes(t.expected);
      const session = new musig2.Session(
        musig2.nonceAggregate(pnonce),
        pubkeys,
        msg,
        tweaksCase,
        isXonly
      );
      const secnonceCopy = new Uint8Array(secnonce);
      deepStrictEqual(session.sign(secnonceCopy, sk), expected);
      if (!session.partialSigVerify(expected, pubnonces, signerIndex)) {
        throw new Error('partialSigVerify failed for tweak valid test case');
      }
    }

    // Error test cases.
    for (const t of tweakVectors.error_test_cases) {
      assertError(t.error, () => {
        const session = new musig2.Session(
          hexToBytes(tweakVectors.aggnonce),
          t.key_indices.map((i) => X[i]),
          msg,
          t.tweak_indices.map((i) => tweaks[i]),
          t.is_xonly
        );
        return session.sign(new Uint8Array(secnonce), sk);
      });
    }
  });

  should('deterministic sign', () => {
    const sk = hexToBytes(detSignVectors.sk);
    const X = detSignVectors.pubkeys.map(hexToBytes);
    deepStrictEqual(X[0], musig2.IndividualPubkey(sk));
    const msgs = detSignVectors.msgs.map(hexToBytes);
    for (const t of detSignVectors.valid_test_cases) {
      const pubkeys = t.key_indices.map((i) => X[i]);
      const aggothernonce = hexToBytes(t.aggothernonce);
      const tweaks = t.tweaks.map(hexToBytes);
      const isXonly = t.is_xonly;
      const msg = msgs[t.msg_index];
      const signerIndex = t.signer_index;
      const rand = t.rand !== null ? hexToBytes(t.rand) : undefined;
      const expected = t.expected.map(hexToBytes);
      const { publicNonce: pubnonce, partialSig: psig } = musig2.deterministicSign(
        sk,
        aggothernonce,
        pubkeys,
        msg,
        tweaks,
        isXonly,
        rand
      );
      deepStrictEqual(pubnonce, expected[0]);
      deepStrictEqual(psig, expected[1]);
      const pubnonces = [pubnonce, aggothernonce];
      const session = new musig2.Session(
        musig2.nonceAggregate(pubnonces),
        pubkeys,
        msg,
        tweaks,
        isXonly
      );
      if (!session.partialSigVerifyInternal(psig, pubnonce, pubkeys[signerIndex]))
        throw new Error('partialSigVerify failed for deterministic signing');
    }
    for (const t of detSignVectors.error_test_cases) {
      const pubkeys = t.key_indices.map((i) => X[i]);
      const aggothernonce = hexToBytes(t.aggothernonce);
      const tweaks = t.tweaks.map(hexToBytes);
      const isXonly = t.is_xonly;
      const msg = msgs[t.msg_index];
      const rand = t.rand !== null ? hexToBytes(t.rand) : undefined;
      assertError(t.error, () => {
        musig2.deterministicSign(sk, aggothernonce, pubkeys, msg, tweaks, isXonly, rand);
      });
    }
  });
  should('signature aggregation', () => {
    const msg = hexToBytes(sigAggVectors.msg);
    for (const t of sigAggVectors.valid_test_cases) {
      const pubnonces = t.nonce_indices.map((i) => hexToBytes(sigAggVectors.pnonces[i]));
      const aggnonce = hexToBytes(t.aggnonce);
      deepStrictEqual(aggnonce, musig2.nonceAggregate(pubnonces));
      const pubkeys = t.key_indices.map((i) => hexToBytes(sigAggVectors.pubkeys[i]));
      const tweaks = t.tweak_indices.map((i) => hexToBytes(sigAggVectors.tweaks[i]));
      const isXonly = t.is_xonly;
      const psigs = t.psig_indices.map((i) => hexToBytes(sigAggVectors.psigs[i]));
      const expected = hexToBytes(t.expected);
      const session = new musig2.Session(
        musig2.nonceAggregate(pubnonces),
        pubkeys,
        msg,
        tweaks,
        isXonly
      );
      const aggSig = session.partialSigAgg(psigs);
      deepStrictEqual(aggSig, expected);
      const aggpk = musig2.keyAggExport(musig2.keyAggregate(pubkeys, tweaks, isXonly));
      deepStrictEqual(schnorr.verify(aggSig, msg, aggpk), true);
    }
    for (const t of sigAggVectors.error_test_cases) {
      const pubnonces = t.nonce_indices.map((i) => hexToBytes(sigAggVectors.pnonces[i]));
      const aggnonce = musig2.nonceAggregate(pubnonces);
      deepStrictEqual(aggnonce, musig2.nonceAggregate(pubnonces));
      const pubkeys = t.key_indices.map((i) => hexToBytes(sigAggVectors.pubkeys[i]));
      const tweaks = t.tweak_indices.map((i) => hexToBytes(sigAggVectors.tweaks[i]));
      const isXonly = t.is_xonly;
      const psigs = t.psig_indices.map((i) => hexToBytes(sigAggVectors.psigs[i]));
      const session = new musig2.Session(
        musig2.nonceAggregate(pubnonces),
        pubkeys,
        msg,
        tweaks,
        isXonly
      );
      assertError(t.error, () => session.partialSigAgg(psigs));
    }
  });
  should('sign & verify (random)', () => {
    const rand = () => randomBytes(1)[0];
    const rand_1_of_4 = () => rand() % 4 === 0;
    const rand_1_of_2 = () => rand() % 2 === 0;
    for (let i = 0; i < 6; i++) {
      const sk1 = randomBytes(32);
      const sk2 = randomBytes(32);
      const pk1 = musig2.IndividualPubkey(sk1);
      const pk2 = musig2.IndividualPubkey(sk2);
      const pubkeys = [pk1, pk2];
      const msg = randomBytes(32);
      const v = rand_1_of_4(); // random xOnly
      const tweaks = [];
      const isXonly = [];
      for (let j = 0; j < v; j++) {
        tweaks.push(randomBytes(32));
        isXonly.push(rand_1_of_2());
      }
      const aggpk = musig2.keyAggExport(musig2.keyAggregate(pubkeys, tweaks, isXonly));
      const extraIn = numberToBytesBE(i, 4);
      let { public: pubnonce1, secret: secnonce1 } = musig2.nonceGen(pk1, sk1, aggpk, msg, extraIn);
      let pubnonce2, secnonce2, psig2;
      if (i % 2 === 0) {
        ({ secret: secnonce2, public: pubnonce2 } = musig2.nonceGen(
          pk2,
          sk2,
          aggpk,
          msg,
          randomBytes(8)
        ));
      } else {
        // Use deterministicSign for signer 2.
        const aggothernonce = musig2.nonceAggregate([pubnonce1]);
        ({ publicNonce: pubnonce2, partialSig: psig2 } = musig2.deterministicSign(
          sk2,
          aggothernonce,
          pubkeys,
          msg,
          tweaks,
          isXonly
        ));
      }
      const pubnonces = [pubnonce1, pubnonce2];
      const session = new musig2.Session(
        musig2.nonceAggregate(pubnonces),
        pubkeys,
        msg,
        tweaks,
        isXonly
      );
      const psig1 = session.sign(secnonce1, sk1);
      if (!session.partialSigVerify(psig1, pubnonces, 0))
        throw new Error('Random partial signature verification failed for signer 1');
      throws(() => session.sign(secnonce1, sk1)); // Reusing the same secnonce should throw.
      if (i % 2 === 0 && secnonce2 && pubnonce2) {
        const psig2Computed = session.sign(secnonce2, sk2);
        if (!session.partialSigVerify(psig2Computed, pubnonces, 1))
          throw new Error('Random partial signature verification failed for signer 2');
        const fullSig = session.partialSigAgg([psig1, psig2Computed]);
        deepStrictEqual(schnorr.verify(fullSig, msg, aggpk), true);
      }
    }
  });
});
should.runWhen(import.meta.url);

import { concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';
import { describe, it } from '@paulmillr/jsbt/test.js';
import { base64, hex } from '@scure/base';
import * as bip32 from '@scure/bip32';
import { deepStrictEqual, throws } from 'node:assert';
import * as btc from '../src/index.ts';
import {
  _RawPSBTV0,
  mergeKeyMap,
  PSBTInput,
  PSBTInputCoder,
  PSBTOutputCoder,
  RawPSBTV2,
} from '../src/psbt.ts';
import { pubECDSA } from '../src/utils.ts';
import { default as psbtV } from './vectors/psbt_vectors.js';

describe('bip174-psbt', () => {
  for (let i = 0; i < psbtV.length; i++) {
    const v = psbtV[i];
    it(`PSBTv${v.v2 ? '2' : '0'}(${i}), ${v.invalid ? 'invalid' : 'valid'}: ${v.name}`, () => {
      const tx = hex.decode(v.hex);
      if (v.invalid) {
        if (v.signer) return; // we don't test these, because we have no key for signer
        throws(() => btc.Transaction.fromPSBT(tx));
      } else {
        // This suite checks byte-for-byte compatibility with imported vectors, including opaque
        // extension rows. Preservation is opt-in; default stripping is tested separately below.
        const parsed = btc.Transaction.fromPSBT(tx, {
          allowUnknown: true,
          allowMissingTxModifiable: false,
        });
        const encoded = parsed.toPSBT();
        deepStrictEqual(btc._DebugPSBT.decode(encoded), btc._DebugPSBT.decode(tx));
        deepStrictEqual(hex.encode(encoded), v.hex);
        if (v.lockTime) deepStrictEqual(parsed.lockTime, v.lockTime);
      }
    });
  }
});

// it('PSBT combiner', () => {
//   // Currently we skip unknown keys. Need to add support?
//   return;
//   const opts = { allowUnknowOutput: true };
//   const p1 = btc.Transaction.fromPSBT(
//     hex.decode(
//       '70736274ff01003f0200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000ffffffff010000000000000000036a0100000000000af00102030405060708090f0102030405060708090a0b0c0d0e0f000af00102030405060708090f0102030405060708090a0b0c0d0e0f000af00102030405060708090f0102030405060708090a0b0c0d0e0f00'
//     ),
//     opts
//   );
//   const p2 = btc.Transaction.fromPSBT(
//     hex.decode(
//       '70736274ff01003f0200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000ffffffff010000000000000000036a0100000000000af00102030405060708100f0102030405060708090a0b0c0d0e0f000af00102030405060708100f0102030405060708090a0b0c0d0e0f000af00102030405060708100f0102030405060708090a0b0c0d0e0f00'
//     ),
//     opts
//   );
//   deepStrictEqual(
//     p1.combine(p2),
//     btc.Transaction.fromPSBT(
//       hex.decode(
//         '70736274ff01003f0200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000ffffffff010000000000000000036a0100000000000af00102030405060708090f0102030405060708090a0b0c0d0e0f0af00102030405060708100f0102030405060708090a0b0c0d0e0f000af00102030405060708090f0102030405060708090a0b0c0d0e0f0af00102030405060708100f0102030405060708090a0b0c0d0e0f000af00102030405060708090f0102030405060708090a0b0c0d0e0f0af00102030405060708100f0102030405060708090a0b0c0d0e0f00'
//       )
//     )
//   );
//   deepStrictEqual(
//     p1.combine(p2).toPSBT(),
//     hex.decode(
//       '70736274ff01003f0200000001ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000ffffffff010000000000000000036a0100000000000af00102030405060708090f0102030405060708090a0b0c0d0e0f0af00102030405060708100f0102030405060708090a0b0c0d0e0f000af00102030405060708090f0102030405060708090a0b0c0d0e0f0af00102030405060708100f0102030405060708090a0b0c0d0e0f000af00102030405060708090f0102030405060708090a0b0c0d0e0f0af00102030405060708100f0102030405060708090a0b0c0d0e0f00'
//     )
//   );
// });

// TODO!!
it('bip174-psbt: PSBT multisig example', () => {
  const testnet = {
    wif: 0xef,
    bip32: {
      public: 0x043587cf,
      private: 0x04358394,
    },
  };
  // The private keys in the tests below are derived from the following master private key:
  const epriv =
    'tprv8ZgxMBicQKsPd9TeAdPADNnSyH9SSUUbTVeFszDE23Ki6TBB5nCefAdHkK8Fm3qMQR6sHwA56zqRmKmxnHk37JkiFzvncDqoKmPWubu7hDF';

  const hdkey = bip32.HDKey.fromExtendedKey(epriv, testnet.bip32);
  // const seed = 'cUkG8i1RFfWGWy5ziR11zJ5V4U4W3viSFCfyJmZnvQaUsd1xuF3T';
  const tx = new btc.Transaction();
  // A creator creating a PSBT for a transaction which creates the following outputs:
  tx.addOutput({
    script: '0014d85c2b71d0060b09c9886aeb815e50991dda124d',
    amount: btc.Decimal.decode('1.49990000'),
  });
  tx.addOutput({
    script: '001400aea9a2e5f0f876a588df5546e8742d1d87008f',
    amount: btc.Decimal.decode('1.00000000'),
  });
  // and spends the following inputs:
  // NOTE: spec uses txId instead of txHash
  tx.addInput({
    txid: '75ddabb27b8845f5247975c8a5ba7c6f336c4570708ebe230caf6db5217ae858',
    index: 0,
  });
  tx.addInput({
    txid: '1dea7cd05979072a3578cab271c02244ea8a090bbb46aa680a65ecd027048d83',
    index: 1,
  });
  // must create this PSBT:
  const psbt1 = tx.toPSBT();
  deepStrictEqual(
    psbt1,
    hex.decode(
      '70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f000000000000000000'
    )
  );
  // Given the above PSBT, an updater with only the following:
  const tx2 = btc.Transaction.fromPSBT(psbt1);
  tx2.updateInput(0, {
    nonWitnessUtxo:
      '0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f618765000000',
    redeemScript:
      '5221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae',
    bip32Derivation: [
      [
        '029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f',
        { fingerprint: hdkey.fingerprint, path: btc.bip32Path("m/0'/0'/0'") },
      ],
      [
        '02dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d7',
        { fingerprint: hdkey.fingerprint, path: btc.bip32Path("m/0'/0'/1'") },
      ],
    ],
  });
  tx2.updateInput(1, {
    // use witness utxo ({script, amount})
    witnessUtxo: btc.RawTx.decode(
      hex.decode(
        '0200000000010158e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd7501000000171600145f275f436b09a8cc9a2eb2a2f528485c68a56323feffffff02d8231f1b0100000017a914aed962d6654f9a2b36608eb9d64d2b260db4f1118700c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e88702483045022100a22edcc6e5bc511af4cc4ae0de0fcd75c7e04d8c1c3a8aa9d820ed4b967384ec02200642963597b9b1bc22c75e9f3e117284a962188bf5e8a74c895089046a20ad770121035509a48eb623e10aace8bfd0212fdb8a8e5af3c94b0b133b95e114cab89e4f7965000000'
      )
    ).outputs[1],
    redeemScript: '00208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903',
    witnessScript:
      '522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae',
    bip32Derivation: [
      [
        '03089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc',
        { fingerprint: hdkey.fingerprint, path: btc.bip32Path("m/0'/0'/2'") },
      ],
      [
        '023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e73',
        { fingerprint: hdkey.fingerprint, path: btc.bip32Path("m/0'/0'/3'") },
      ],
    ],
  });
  tx2.updateOutput(0, {
    bip32Derivation: [
      [
        '03a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca58771',
        { fingerprint: hdkey.fingerprint, path: btc.bip32Path("m/0'/0'/4'") },
      ],
    ],
  });
  tx2.updateOutput(1, {
    bip32Derivation: [
      [
        '027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b50051096',
        { fingerprint: hdkey.fingerprint, path: btc.bip32Path("m/0'/0'/5'") },
      ],
    ],
  });
  // Must create this PSBT:
  const psbt2 = tx2.toPSBT();
  deepStrictEqual(
    psbt2,
    hex.decode(
      '70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f00000000000100bb0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f6187650000000104475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae2206029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f10d90c6a4f000000800000008000000080220602dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d710d90c6a4f0000008000000080010000800001012000c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e88701042200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903010547522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae2206023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7310d90c6a4f000000800000008003000080220603089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc10d90c6a4f00000080000000800200008000220203a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca5877110d90c6a4f000000800000008004000080002202027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b5005109610d90c6a4f00000080000000800500008000'
    )
  );
  const tx3 = btc.Transaction.fromPSBT(psbt2);
  for (let i = 0; i < tx3.inputs.length; i++) tx3.updateInput(i, { sighashType: btc.SigHash.ALL });
  // An updater which adds SIGHASH_ALL to the above PSBT must create this PSBT:
  const psbt3 = tx3.toPSBT();
  deepStrictEqual(
    psbt3,
    hex.decode(
      '70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f00000000000100bb0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f618765000000010304010000000104475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae2206029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f10d90c6a4f000000800000008000000080220602dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d710d90c6a4f0000008000000080010000800001012000c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e8870103040100000001042200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903010547522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae2206023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7310d90c6a4f000000800000008003000080220603089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc10d90c6a4f00000080000000800200008000220203a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca5877110d90c6a4f000000800000008004000080002202027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b5005109610d90c6a4f00000080000000800500008000'
    )
  );
  /*
  Given the above updated PSBT, a signer that supports SIGHASH_ALL for P2PKH and P2WPKH spends and uses RFC6979 for nonce generation and has the following keys:
  - cP53pDbR5WtAD8dYAW9hhTjuvvTVaEiQBdrz9XPrgLBeRFiyCbQr (m/0'/0'/0')
  - cR6SXDoyfQrcp4piaiHE97Rsgta9mNhGTen9XeonVgwsh4iSgw6d (m/0'/0'/2')
  */
  // NOTE: we don't use HDKey, because it will break everything because of bip32 derivation
  const tx4 = btc.Transaction.fromPSBT(psbt3);
  tx4.sign(btc.WIF(testnet).decode('cP53pDbR5WtAD8dYAW9hhTjuvvTVaEiQBdrz9XPrgLBeRFiyCbQr'));
  tx4.sign(btc.WIF(testnet).decode('cR6SXDoyfQrcp4piaiHE97Rsgta9mNhGTen9XeonVgwsh4iSgw6d'));
  // must create this PSBT:
  const psbt4 = tx4.toPSBT();
  deepStrictEqual(
    psbt4,
    hex.decode(
      '70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f00000000000100bb0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f6187650000002202029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01010304010000000104475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae2206029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f10d90c6a4f000000800000008000000080220602dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d710d90c6a4f0000008000000080010000800001012000c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e887220203089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f010103040100000001042200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903010547522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae2206023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7310d90c6a4f000000800000008003000080220603089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc10d90c6a4f00000080000000800200008000220203a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca5877110d90c6a4f000000800000008004000080002202027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b5005109610d90c6a4f00000080000000800500008000'
    )
  );
  // Given the above updated PSBT, a signer with the following keys:
  // cT7J9YpCwY3AVRFSjN6ukeEeWY6mhpbJPxRaDaP5QTdygQRxP9Au (m/0'/0'/1')
  // cNBc3SWUip9PPm1GjRoLEJT6T41iNzCYtD7qro84FMnM5zEqeJsE (m/0'/0'/3')
  const tx5 = btc.Transaction.fromPSBT(psbt3);
  tx5.sign(btc.WIF(testnet).decode('cT7J9YpCwY3AVRFSjN6ukeEeWY6mhpbJPxRaDaP5QTdygQRxP9Au'));
  tx5.sign(btc.WIF(testnet).decode('cNBc3SWUip9PPm1GjRoLEJT6T41iNzCYtD7qro84FMnM5zEqeJsE'));
  // must create this PSBT:
  const psbt5 = tx5.toPSBT();
  deepStrictEqual(
    psbt5,
    hex.decode(
      '70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f00000000000100bb0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f618765000000220202dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d7483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01010304010000000104475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae2206029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f10d90c6a4f000000800000008000000080220602dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d710d90c6a4f0000008000000080010000800001012000c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e8872202023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e73473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d2010103040100000001042200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903010547522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae2206023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7310d90c6a4f000000800000008003000080220603089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc10d90c6a4f00000080000000800200008000220203a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca5877110d90c6a4f000000800000008004000080002202027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b5005109610d90c6a4f00000080000000800500008000'
    )
  );

  const psbt6 = btc.PSBTCombine([psbt4, psbt5]);
  // Example doesn't sort partial sig lexicographically
  const psbt6Exp = btc.Transaction.fromPSBT(
    hex.decode(
      '70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f00000000000100bb0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f6187650000002202029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01220202dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d7483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01010304010000000104475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae2206029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f10d90c6a4f000000800000008000000080220602dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d710d90c6a4f0000008000000080010000800001012000c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e887220203089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f012202023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e73473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d2010103040100000001042200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903010547522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae2206023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7310d90c6a4f000000800000008003000080220603089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc10d90c6a4f00000080000000800200008000220203a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca5877110d90c6a4f000000800000008004000080002202027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b5005109610d90c6a4f00000080000000800500008000'
    )
  ).toPSBT();
  // Given both of the above PSBTs, a combiner must create this PSBT:
  deepStrictEqual(psbt6, psbt6Exp);
  // Our test that bip32 sign works for these inputs
  const hdTx = btc.Transaction.fromPSBT(psbt3);
  hdTx.sign(hdkey);
  deepStrictEqual(hdTx.toPSBT(), psbt6Exp);
  // Given the above PSBT, an input finalizer must create this PSBT:
  const tx7 = btc.Transaction.fromPSBT(psbt6);
  tx7.finalize();
  const psbt7 = tx7.toPSBT();
  deepStrictEqual(
    psbt7,
    hex.decode(
      '70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f00000000000100bb0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f6187650000000107da00473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae0001012000c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e8870107232200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b20289030108da0400473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d20147522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae00220203a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca5877110d90c6a4f000000800000008004000080002202027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b5005109610d90c6a4f00000080000000800500008000'
    )
  );
  const tx8 = btc.Transaction.fromPSBT(psbt7);
  // Given the above PSBT, a transaction extractor must create this Bitcoin transaction:
  deepStrictEqual(
    tx8.extract(),
    hex.decode(
      '0200000000010258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd7500000000da00473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752aeffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d01000000232200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b2028903ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f000400473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d20147522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae00000000'
    )
  );
});

it('bip174-psbt: PSBT garbage', () => {
  // Parsed by bitcoinjs-lib, however contains garbage inside
  throws(() =>
    btc.Transaction.fromPSBT(
      hex.decode(
        '70736274ff0100750200000001268171371edff285e937adeea4b37b78000c0566cbb3ad64641713ca42171bf60000000000feffffff02d3dff505000000001976a914d0c59903c5bac2868760e90fd521a4665aa7652088ac00e1f5050000000017a9143545e6e33b832c47050f24d3eeb93c9c03948bc787b32e1300000100fda5010100000000010289a3c71eab4d20e0371bbba4cc698fa295c9463afa2e397f8533ccb62f9567e50100000017160014be18d152a9b012039daf3da7de4f53349eecb985ffffffff86f8aa43a71dff1448893a530a7237ef6b4608bbb2dd2d0171e63aec6a4890b40100000017160014fe3e9ef1a745e974d902c4355943abcb34bd5353ffffffff0200c2eb0b000000001976a91485cff1097fd9e008bb34af709c62197b38978a4888ac72fef84e2c00000017a914339725ba21efd62ac753a9bcd067d6c7a6a39d05870247304402202712be22e0270f394f568311dc7ca9a68970b8025fdd3b240229f07f8a5f3a240220018b38d7dcd314e734c9276bd6fb40f673325bc4baa144c800d2f2f02db2765c012103d2e15674941bad4a996372cb87e1856d3652606d98562fe39c5e9e7e413f210502483045022100d12b852d85dcd961d2f5f4ab660654df6eedcc794c0c33ce5cc309ffb5fce58d022067338a8e0e1725c197fb1a88af59f51e44e4255b20167c8684031c05d1f2592a01210223b72beef0965d10be0778efecd61fcac6f79a4ea169393380734464f84f2ab3000000000000000000'
      )
    )
  );
});

it('bip174-psbt: PSBT unknown keys', () => {
  const tx = hex.decode(
    '70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7cbaa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca78352a077959d07cea1d0100000000ffffffff0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2e5f0f876a588df5546e8742d1d87008f00000000000100bb0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f6187650000000107da00473044022074018ad4180097b873323c0015720b3684cc8123891048e7dbcd9b55ad679c99022073d369b740e3eb53dcefa33823c8070514ca55a7dd9544f157c167913261118c01483045022100f61038b308dc1da865a34852746f015772934208c6d24454393cd99bdf2217770220056e675a675a6d0a02b85b14e5e29074d8a25a9b5760bea2816f661910a006ea01475221029583bf39ae0a609747ad199addd634fa6108559d6c5cd39b4c2183f1ab96e07f2102dab61ff49a14db6a7d02b0cd1fbb78fc4b18312b5b4e54dae4dba2fbfef536d752ae0001012000c2eb0b0000000017a914b7f5faf40e3d40a5a459b1db3535f2b72fa921e8870107232200208c2353173743b595dfb4a07b72ba8e42e3797da74e87fe7d9d7497e3b20289030108da0400473044022062eb7a556107a7c73f45ac4ab5a1dddf6f7075fb1275969a7f383efff784bcb202200c05dbb7470dbf2f08557dd356c7325c1ed30913e996cd3840945db12228da5f01473044022065f45ba5998b59a27ffe1a7bed016af1f1f90d54b3aa8f7450aa5f56a25103bd02207f724703ad1edb96680b284b56d4ffcb88f7fb759eabbe08aa30f29b851383d20147522103089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc21023add904f3d6dcf59ddb906b0dee23529b7ffb9ed50e5e86151926860221f0e7352ae00220203a9a4c37f5996d3aa25dbac6b570af0650394492942460b354753ed9eeca5877110d90c6a4f000000800000008004000080002202027f6399757d2eff55a136ad02c684b1838b6556e5f1b6b34282a94b6b5005109610d90c6a4f00000080000000800500008000'
  );

  const psbtWithoutAllowUnknown = btc.Transaction.fromPSBT(tx);
  const psbtWithAllowUnknown = btc.Transaction.fromPSBT(tx, { allowUnknown: true });

  const unknown = [
    [
      { type: 0xff, key: new Uint8Array(utf8ToBytes('unknownKey1')) },
      new Uint8Array(utf8ToBytes('unknownValue1')),
    ],
    [
      { type: 0xff, key: new Uint8Array(utf8ToBytes('unknownKey2')) },
      new Uint8Array(utf8ToBytes('unknownValue2')),
    ],
  ];
  const unknownNext = [
    [
      { type: 0xfd, key: new Uint8Array(utf8ToBytes('unknownKey3')) },
      new Uint8Array(utf8ToBytes('unknownValue3')),
    ],
  ];

  // input unknown key
  throws(
    () => psbtWithoutAllowUnknown.updateInput(0, { unknown }),
    /unknown PSBT field cannot be supplied when policy is strip/
  );
  psbtWithAllowUnknown.updateInput(0, { unknown });
  psbtWithAllowUnknown.updateInput(0, { unknown: unknownNext });

  // output unknown key
  throws(
    () => psbtWithoutAllowUnknown.updateOutput(0, { unknown }),
    /unknown PSBT field cannot be supplied when policy is strip/
  );
  psbtWithAllowUnknown.updateOutput(0, { unknown });
  psbtWithAllowUnknown.updateOutput(0, { unknown: unknownNext });
  // verify the unknown key is preserved only if the flag is set
  deepStrictEqual(psbtWithAllowUnknown.outputs[0].unknown, unknown.concat(unknownNext));
  deepStrictEqual(psbtWithAllowUnknown.inputs[0].unknown, unknown.concat(unknownNext));
  deepStrictEqual(psbtWithoutAllowUnknown.outputs[0].unknown, undefined);
  deepStrictEqual(psbtWithoutAllowUnknown.inputs[0].unknown, undefined);

  // verify the unknown key is preserved with serialization
  const psbt2 = btc.Transaction.fromPSBT(psbtWithAllowUnknown.toPSBT(), { allowUnknown: true });
  deepStrictEqual(psbt2.outputs[0].unknown, unknown.concat(unknownNext));
  deepStrictEqual(psbt2.inputs[0].unknown, unknown.concat(unknownNext));

  const encodedWithUnknown = _RawPSBTV0.decode(psbtWithAllowUnknown.toPSBT());
  encodedWithUnknown.global.unknown = unknownNext;
  const proprietary = [[Uint8Array.of(1, 0x61, 0), Uint8Array.of(2)]];
  encodedWithUnknown.global.proprietary = proprietary;
  encodedWithUnknown.inputs[0].proprietary = proprietary;
  encodedWithUnknown.outputs[0].proprietary = proprietary;
  const injected = _RawPSBTV0.encode(encodedWithUnknown);

  const stripped = _RawPSBTV0.decode(btc.Transaction.fromPSBT(injected).toPSBT());
  deepStrictEqual(stripped.global.unknown, undefined);
  deepStrictEqual(stripped.inputs[0].unknown, undefined);
  deepStrictEqual(stripped.outputs[0].unknown, undefined);
  deepStrictEqual(stripped.global.proprietary, undefined);
  deepStrictEqual(stripped.inputs[0].proprietary, undefined);
  deepStrictEqual(stripped.outputs[0].proprietary, undefined);

  const preserved = _RawPSBTV0.decode(
    btc.Transaction.fromPSBT(injected, {
      allowUnknown: true,
      proprietary: 'ignore',
    }).toPSBT()
  );
  deepStrictEqual(preserved.global.unknown, unknownNext);
  deepStrictEqual(preserved.inputs[0].unknown, unknown.concat(unknownNext));
  deepStrictEqual(preserved.outputs[0].unknown, unknown.concat(unknownNext));
  deepStrictEqual(preserved.global.proprietary, proprietary);
  deepStrictEqual(preserved.inputs[0].proprietary, proprietary);
  deepStrictEqual(preserved.outputs[0].proprietary, proprietary);
});

// Regression / documentation tests. Tests marked KNOWN ISSUE assert current
// (buggy or lenient) behavior on purpose: if one starts failing, the underlying
// issue was fixed — flip the assertion.
const TXID_01 = '00'.repeat(31) + '01';
const privA = hex.decode('02'.repeat(32));

it('mergeKeyMap signed-field guard also covers hex-string updates', () => {
  const spend = btc.p2wpkh(pubECDSA(privA));
  const tx = new btc.Transaction();
  tx.addInput({
    txid: TXID_01,
    index: 0,
    witnessUtxo: { amount: 10000n, script: spend.script },
    sighashType: btc.SigHash.ALL,
  });
  tx.addOutput({ script: spend.script, amount: 9000n });
  tx.signIdx(privA, 0, [btc.SigHash.ALL]);
  // Guard works for normally-typed values on a signed input.
  throws(() => tx.updateInput(0, { sighashType: btc.SigHash.SINGLE }));
  deepStrictEqual(tx.getInput(0).sighashType, btc.SigHash.ALL);
  // Hex-string convenience values must cross the same comparison after decoding.
  throws(() => tx.updateInput(0, { sighashType: '03000000' } as any));
  deepStrictEqual(tx.getInput(0).sighashType, btc.SigHash.ALL);
});

it('mergeKeyMap keyed-field conflicts still throw', () => {
  // Keyed fields are not affected by the hex-string bypass: same key with a
  // different value must conflict no matter how the update is delivered.
  const pub = pubECDSA(privA);
  const der1 = { fingerprint: 0x11223344, path: [1] };
  const der2 = { fingerprint: 0x11223344, path: [2] };
  throws(() =>
    mergeKeyMap(
      PSBTInput,
      { bip32Derivation: [[pub, der2]] } as any,
      { bip32Derivation: [[pub, der1]] } as any
    )
  );
  const merged = mergeKeyMap(
    PSBTInput,
    { bip32Derivation: [[pub, der1]] } as any,
    { bip32Derivation: [[pub, der1]] } as any
  ) as any;
  deepStrictEqual(merged.bip32Derivation.length, 1);
});

it('PSBT encode sorts caller unknown array in place', () => {
  // KNOWN ISSUE: encodeStream sorts value.unknown with Array.prototype.sort,
  // mutating the caller's array (ordering only; the row set is unchanged).
  const row = (key: number) =>
    [{ type: 0xf0, key: new Uint8Array([key]) }, new Uint8Array([0xaa])] as any;
  const unknown = [row(2), row(1)];
  PSBTInputCoder.encode({ unknown } as any);
  deepStrictEqual(
    unknown.map((u) => u[0].key[0]),
    [1, 2]
  );
});

it('schnorr signature length validation in PSBT fields', () => {
  PSBTInputCoder.encode({ tapKeySig: new Uint8Array(64).fill(1) } as any);
  throws(() => PSBTInputCoder.encode({ tapKeySig: new Uint8Array(63).fill(1) } as any));
  throws(() => PSBTInputCoder.encode({ tapKeySig: new Uint8Array(66).fill(1) } as any));
  // KNOWN ISSUE (leniency): 65-byte signature with trailing sighash byte 0x00 is
  // accepted, though BIP341 requires the 64-byte form for the default hash type.
  const sig65 = new Uint8Array(65).fill(1);
  sig65[64] = 0x00;
  PSBTInputCoder.encode({ tapKeySig: sig65 } as any);
});

it('tapTree DFS/completeness validation and leniencies', () => {
  const leaf = (depth: number, version = 0xc0) => ({
    depth,
    version,
    script: new Uint8Array([0x51]),
  });
  // Valid complete trees.
  PSBTOutputCoder.encode({ tapTree: [leaf(0)] } as any);
  PSBTOutputCoder.encode({ tapTree: [leaf(1), leaf(2), leaf(2)] } as any);
  // Incomplete tree: single leaf at depth 1 leaves a missing sibling.
  throws(() => PSBTOutputCoder.encode({ tapTree: [leaf(1)] } as any));
  // Not a DFS walk: three leaves cannot all sit at depth 1.
  throws(() => PSBTOutputCoder.encode({ tapTree: [leaf(1), leaf(1), leaf(1)] } as any));
  // KNOWN ISSUE (leniency): depth beyond BIP341's 128 limit is accepted
  // (caterpillar tree: depths 1..129 plus a second depth-129 leaf).
  const deep = [];
  for (let i = 1; i <= 129; i++) deep.push(leaf(i));
  deep.push(leaf(129));
  PSBTOutputCoder.encode({ tapTree: deep } as any);
  // KNOWN ISSUE (leniency): leaf version with the parity bit set is accepted here,
  // while the tapLeafScript validator rejects it.
  PSBTOutputCoder.encode({ tapTree: [leaf(0, 0xc1)] } as any);
});

const psbtRow = (type: number, key: Uint8Array, value: Uint8Array) =>
  Uint8Array.of(key.length + 1, type, ...key, value.length, ...value);
const psbtMap = (...rows: Uint8Array[]) => concatBytes(...rows, Uint8Array.of(0));

it('decodes every assigned PSBT extension field as known data', () => {
  // Field layouts and version columns:
  // BIP322: https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki#psbt-based-signing
  // BIP353: https://github.com/bitcoin/bips/blob/master/bip-0353.mediawiki#psbt
  // BIP372: https://github.com/bitcoin/bips/blob/master/bip-0372.mediawiki#specification
  // BIP373: https://github.com/bitcoin/bips/blob/master/bip-0373.mediawiki#specification
  // BIP375: https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki#specification
  // BIP376: https://github.com/bitcoin/bips/blob/master/bip-0376.mediawiki#fields
  const aggregate = hex.decode(
    '030b58e337aa4d3852a8c29387c42408d8cfbe3a613a5e397e0a9f01a5fb7107d4'
  );
  const participant = hex.decode(
    '02346b99593357107c9d3459e9deba8d3eaf44e6636c85c7f853eb90ba52e8cd00'
  );
  const scanKey = hex.decode('024fafd65f8169186fc2bfdb2233c77e630d10be280a24c7165c09a27611775c2c');
  const spendKey = hex.decode('02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9');
  const leafHash = new Uint8Array(32).fill(1);
  const pubNonce = new Uint8Array(66).fill(2);
  const partialSig = new Uint8Array(32).fill(3);
  const dleq = new Uint8Array(64).fill(4);
  const tweak = new Uint8Array(32).fill(5);
  const message = utf8ToBytes('registered fields are not unknown');
  const dnssec = { name: utf8ToBytes('alice'), proof: Uint8Array.of(6, 7, 8) };
  const musigKey = { participantPubkey: participant, aggregatePubkey: aggregate };
  const musigLeafKey = { ...musigKey, leafHash };

  const global = RawPSBTV2.decode(
    concatBytes(
      hex.decode('70736274ff'),
      psbtMap(
        psbtRow(0xfb, new Uint8Array(), hex.decode('02000000')),
        psbtRow(0x02, new Uint8Array(), hex.decode('02000000')),
        psbtRow(0x04, new Uint8Array(), Uint8Array.of(0)),
        psbtRow(0x05, new Uint8Array(), Uint8Array.of(0)),
        psbtRow(0x07, scanKey, spendKey),
        psbtRow(0x08, scanKey, dleq),
        psbtRow(0x09, new Uint8Array(), message)
      )
    )
  ).global;
  deepStrictEqual(global, {
    version: 2,
    txVersion: 2,
    inputCount: 0,
    outputCount: 0,
    spEcdhShare: [[scanKey, spendKey]],
    spDleq: [[scanKey, dleq]],
    genericSignedMessage: message,
  });

  const input = PSBTInputCoder.decode(
    psbtMap(
      psbtRow(0x19, participant, tweak),
      psbtRow(0x1a, aggregate, concatBytes(participant, scanKey, spendKey)),
      psbtRow(0x1b, concatBytes(participant, aggregate), pubNonce),
      psbtRow(0x1c, concatBytes(participant, aggregate, leafHash), partialSig),
      psbtRow(0x1d, scanKey, spendKey),
      psbtRow(0x1e, scanKey, dleq),
      psbtRow(0x1f, spendKey, hex.decode('1122334401000000')),
      psbtRow(0x20, new Uint8Array(), tweak)
    )
  );
  deepStrictEqual(input, {
    p2cKeyTweak: [[participant, tweak]],
    musig2ParticipantPubkeys: [[aggregate, [participant, scanKey, spendKey]]],
    musig2PubNonce: [[musigKey, pubNonce]],
    musig2PartialSig: [[musigLeafKey, partialSig]],
    spEcdhShare: [[scanKey, spendKey]],
    spDleq: [[scanKey, dleq]],
    spSpendBip32Derivation: [[spendKey, { fingerprint: 0x11223344, path: [1] }]],
    spTweak: tweak,
  });

  const output = PSBTOutputCoder.decode(
    psbtMap(
      psbtRow(0x08, aggregate, concatBytes(participant, scanKey, spendKey)),
      psbtRow(0x09, new Uint8Array(), concatBytes(scanKey, spendKey)),
      psbtRow(0x0a, new Uint8Array(), hex.decode('78563412')),
      psbtRow(
        0x35,
        new Uint8Array(),
        concatBytes(Uint8Array.of(dnssec.name.length), dnssec.name, dnssec.proof)
      )
    )
  );
  deepStrictEqual(output, {
    musig2ParticipantPubkeys: [[aggregate, [participant, scanKey, spendKey]]],
    spV0Info: { scanKey, spendKey },
    spV0Label: 0x12345678,
    dnssecProof: dnssec,
  });

  // Default stripping is compatible with main's known/unknown boundary after updating the table:
  // every currently assigned field survives, while only genuinely unassigned rows are unknown.
  const tx = new btc.Transaction({ PSBTVersion: 2, allowUnknownOutputs: true });
  tx.addInput({ txid: new Uint8Array(32), index: 0 });
  tx.addOutput({ amount: 1n, script: Uint8Array.of(0x51) });
  const assigned = RawPSBTV2.decode(tx.toPSBT(2));
  Object.assign(assigned.global, {
    spEcdhShare: global.spEcdhShare,
    spDleq: global.spDleq,
    genericSignedMessage: global.genericSignedMessage,
  });
  Object.assign(assigned.inputs[0], input);
  Object.assign(assigned.outputs[0], output);
  const relayed = btc.Transaction.fromPSBT(RawPSBTV2.encode(assigned)).toPSBT(2);
  deepStrictEqual(RawPSBTV2.decode(relayed), assigned);
});

it('validates assigned extension field shapes and version exclusions', () => {
  const pubkey = pubECDSA(privA);
  const short = (length: number) => new Uint8Array(length);
  const inputInvalid = [
    psbtRow(0x19, pubkey, short(31)),
    psbtRow(0x1a, pubkey, short(32)),
    psbtRow(0x1b, concatBytes(pubkey, pubkey), short(65)),
    psbtRow(0x1c, concatBytes(pubkey, pubkey), short(31)),
    psbtRow(0x1d, pubkey, short(32)),
    psbtRow(0x1e, pubkey, short(63)),
    psbtRow(0x1f, short(32), hex.decode('11223344')),
    psbtRow(0x20, new Uint8Array(), short(31)),
  ];
  for (const row of inputInvalid) throws(() => PSBTInputCoder.decode(psbtMap(row)));

  const outputInvalid = [
    psbtRow(0x08, pubkey, short(32)),
    psbtRow(0x09, new Uint8Array(), short(65)),
    psbtRow(0x0a, new Uint8Array(), short(3)),
    psbtRow(0x35, new Uint8Array(), Uint8Array.of(3, 1)),
  ];
  for (const row of outputInvalid) throws(() => PSBTOutputCoder.decode(psbtMap(row)));
  // Register the assigned field without adopting BIP375's draft cross-field semantics: this
  // generic PSBT coder transports metadata but does not implement Silent Payment roles.
  const labelOnly = { spV0Label: 1 };
  deepStrictEqual(PSBTOutputCoder.decode(PSBTOutputCoder.encode(labelOnly)), labelOnly);

  const tx = new btc.Transaction({ allowUnknownOutputs: true });
  tx.addInput({ txid: TXID_01, index: 0 });
  tx.addOutput({ script: Uint8Array.of(0x51), amount: 1n });
  const v0 = _RawPSBTV0.decode(tx.toPSBT(0));
  const invalidV0 = [
    { global: [[{ type: 0x07, key: pubkey }, pubkey]] },
    { inputs: [[[{ type: 0x1d, key: pubkey }, pubkey]]] },
    {
      outputs: [[[{ type: 0x09, key: new Uint8Array() }, concatBytes(pubkey, pubkey)]]],
    },
  ];
  for (const fields of invalidV0) {
    const raw = structuredClone(v0);
    if (fields.global) raw.global.unknown = fields.global as any;
    if (fields.inputs) raw.inputs[0].unknown = fields.inputs[0] as any;
    if (fields.outputs) raw.outputs[0].unknown = fields.outputs[0] as any;
    throws(() => btc.Transaction.fromPSBT(_RawPSBTV0.encode(raw)));
  }

  const scriptless = new btc.Transaction({ PSBTVersion: 2 });
  scriptless.addInput({ txid: new Uint8Array(32), index: 0 });
  // BIP375 remains draft and Core requires PSBT_OUT_SCRIPT. Supporting its assigned metadata does
  // not make the high-level transaction API responsible for its provisional output state.
  scriptless.addOutput({
    amount: 1n,
    spV0Info: { scanKey: pubkey, spendKey: pubkey },
  });
  // Match main's staged builder: incomplete state may exist in memory but cannot become a PSBT.
  throws(() => scriptless.toPSBT(), /required field script/i);
});

it('relays supported BIP373/BIP375 vectors and rejects a scriptless draft vector', () => {
  // BIP373: https://github.com/bitcoin/bips/blob/master/bip-0373.mediawiki#test-vectors
  const bip373 = base64.decode(
    'cHNidP8BAFICAAAAAVaG3/QAFl9OBApYVfZYCTRyybz4EIsnKl0x8YH3tP+xAQAAAAD9////' +
      'ARjd9QUAAAAAFgAUyRI+BujX8JZsXRzQ+TMALU63V80AAAAAAAEBKwDh9QUAAAAAIlEgC1jjN6pN' +
      'OFKowpOHxCQI2M++OmE6Xjl+Cp8BpftxB9QhFgtY4zeqTThSqMKTh8QkCNjPvjphOl45fgqfAaX7' +
      'cQfUBQAmgN1uIRY0a5lZM1cQfJ00Weneuo0+r0TmY2yFx/hT65C6UujNAAUAWAsIhyEWT6/WX4Fp' +
      'GG/Cv9siM8d+Yw0QvigKJMcWXAmidhF3XCwFAMMkmoIhFvkwigGSWMMQSTRPhfidUim1MchFg2+Zs' +
      'IYB8RO84Db5BQB91lWSIhoDC1jjN6pNOFKowpOHxCQI2M++OmE6Xjl+Cp8BpftxB9RjAjRrmVkzV' +
      'xB8nTRZ6d66jT6vROZjbIXH+FPrkLpS6M0AAk+v1l+BaRhvwr/bIjPHfmMNEL4oCiTHFlwJonYRd' +
      '1wsAvkwigGSWMMQSTRPhfidUim1MchFg2+ZsIYB8RO84Db5AAA='
  );
  // BIP375: https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki#test-vectors
  const bip375 = base64.decode(
    'cHNidP8B+wQCAAAAAQIEAgAAAAEEAQEBBQEBAQYBACIHAzNh0/9y805rTnp775bluBUeZql5rc51P' +
      'DnFg8vldm0oIQMKGLm7QZm4kzDrF/juWseG4IU9zS88zfF0S5fOTt4FPiIIAzNh0/9y805rTnp7' +
      '75bluBUeZql5rc51PDnFg8vldm0oQCf7kMXWHHjjEVIA/9GD0o0KtIOAYslUGTTGQW1CZ84xvUK' +
      'H6TWUUsCBevDvTVDP9XhDaw0o+e2PIbeaRHZAgI4AAQ4gGKcXZjsLqxSxKhp3EyP/HkB53VMuXd' +
      'E+KOoQgccAmEoBDwQAAAAAAQEfQA0DAAAAAAAWABQimnLTSmRb00lru/ULu4HJBj9PlCICAsgXu' +
      '3Uhr8NeqW87+ycObrUN3/pVYGJ7lh/sAPKZZQi/RzBEAiA3eo+fWjPY+iVcM7OSJtO88CKd+tlg' +
      'Rw74AWpxQvIzWAIgCBvWlIh63us2Ia9aLeTw05yxNpLQQb99vM00oysFQekBAQMEAQAAACIGAsgX' +
      'u3Uhr8NeqW87+ycObrUN3/pVYGJ7lh/sAPKZZQi/CAAAAIAAAAAAARAE/v///yIdAzNh0/9y805r' +
      'Tnp775bluBUeZql5rc51PDnFg8vldm0oIQMKGLm7QZm4kzDrF/juWseG4IU9zS88zfF0S5fOTt4F' +
      'PiIeAzNh0/9y805rTnp775bluBUeZql5rc51PDnFg8vldm0oQAATg9RmG+hyXvKQSPSMkR+J9fND' +
      'F9fAwKzGDvZfG1K//3qW2DObYl34Orq1eqJz7c2aNceU2suxyGEXG7JnB18AAQMIkF8BAAAAAAAB' +
      'BCJRINxNRNnjYeXnQ2V5x44lklVB4in9wVOtWYmtiuawYkx4AQlCAzNh0/9y805rTnp775bluBUe' +
      'Zql5rc51PDnFg8vldm0oAxJmWB4+hBy7lN5i6nNVg6IyxMiI+m7e8uwvhweJ/B3UAA=='
  );
  // This official draft vector carries PSBT_OUT_SP_V0_INFO but omits PSBT_OUT_SCRIPT.
  const bip375WithoutScript = base64.decode(
    'cHNidP8B+wQCAAAAAQIEAgAAAAEEAQEBBQEBAQYBAAABDiAT8Qa2S1e1sTdvn2xHGQ9AzAazvty4' +
      'qrqXhQqz1/Z9AgEPBAAAAAABASughgEAAAAAACJRIMgXu3Uhr8NeqW87+ycObrUN3/pVYGJ7lh/s' +
      'APKZZQi/ARAE/v///wEXIMgXu3Uhr8NeqW87+ycObrUN3/pVYGJ7lh/sAPKZZQi/AAEDCBhzAQAA' +
      'AAAAAQlCAnpIf8Gft2mHe4dC1uoYEY88TnKx6oxt5gKnrUpB2+BoA2HhseneXkLLIAf3ylS54NV' +
      '+0Tk4+tVtPxnldROo/OA5AA=='
  );
  for (const vector of [bip373, bip375]) {
    const parsed = btc.Transaction.fromPSBT(vector);
    // BIP174 makes map order insignificant, and BIP375's official vector uses a different order
    // from this library's table order. Compare the complete keyed maps, including every value.
    deepStrictEqual(btc._DebugPSBT.decode(parsed.toPSBT()), btc._DebugPSBT.decode(vector));
  }
  // Keep BIP370/Core's required output script: registering BIP375 metadata does not implement its
  // draft constructor role. Callers may put `0x00 || scanKey || spendKey` in the script field.
  // The table validator names missing required fields before printing the field name.
  throws(() => RawPSBTV2.decode(bip375WithoutScript), /required field script/i);
});

it.runWhen(import.meta.url);

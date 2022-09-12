import { deepStrictEqual, throws } from 'assert';
import { should } from 'micro-should';
import { hex } from '@scure/base';
import * as btc from '../index.js';
import * as secp256k1 from '@noble/secp256k1';
import * as P from 'micro-packed';

should('BTC: parseAddress', () => {
  const CASES = [
    // https://github.com/bitcoinjs/bitcoinjs-lib/issues/925
    ['1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP', '76a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac'],
    //
    ['3H3Kc7aSPP4THLX68k4mQMyf1gvL6AtmDm', 'a914a860f76561c85551594c18eecceffaee8c4822d787'],
    // https://bitcointalk.org/index.php?topic=5367891.0
    ['bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq', '0014e8df018c7e326cc253faac7e46cdc51e68542c42'],
    // Valid witness programm, but there is no known output script for it. Unspendable output.
    // [
    //   'bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx',
    //   '5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6',
    // ],
  ];
  for (let [addr, outScript] of CASES) {
    deepStrictEqual(btc.OutScript.encode(btc.Address().decode(addr)), hex.decode(outScript));
  }
});
const ADDR_1 = '1C6Rc3w25VHud3dLDamutaqfKWqhrLRTaD';

should('BTC: Bech32 addresses', () => {
  const priv = hex.decode('0101010101010101010101010101010101010101010101010101010101010101');
  deepStrictEqual(btc.WIF().encode(priv), 'KwFfNUhSDaASSAwtG7ssQM1uVX8RgX5GHWnnLfhfiQDigjioWXHH');
  deepStrictEqual(btc.getAddress('wpkh', priv), 'bc1q0xcqpzrky6eff2g52qdye53xkk9jxkvrh6yhyw');
  const pub = secp256k1.getPublicKey(priv, true);
  deepStrictEqual(btc.p2wpkh(pub).address, 'bc1q0xcqpzrky6eff2g52qdye53xkk9jxkvrh6yhyw');
});

should('BTC: P2PKH addresses', () => {
  const priv = hex.decode('0101010101010101010101010101010101010101010101010101010101010101');
  deepStrictEqual(btc.WIF().encode(priv), 'KwFfNUhSDaASSAwtG7ssQM1uVX8RgX5GHWnnLfhfiQDigjioWXHH');
  deepStrictEqual(btc.getAddress('pkh', priv), ADDR_1);
  const pub = secp256k1.getPublicKey(priv, true);
  deepStrictEqual(btc.p2pkh(pub).address, ADDR_1);
});

// Same as above
const TX_TEST_OUTPUTS = [
  ['1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP', 1000n],
  ['3H3Kc7aSPP4THLX68k4mQMyf1gvL6AtmDm', 5000n],
  ['bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq', 9323n],
];
const TX_TEST_INPUTS = [
  {
    hash: hex.decode('c061c23190ed3370ad5206769651eaf6fac6d87d85b5db34e30a74e0c4a6da3e'),
    index: 0,
    amount: 550n,
    script: hex.decode('76a91411dbe48cc6b617f9c6adaf4d9ed5f625b1c7cb5988ac'),
  },
  {
    hash: hex.decode('a21965903c938af35e7280ae5779b9fea4f7f01ac256b8a2a53b1b19a4e89a0d'),
    index: 0,
    amount: 600n,
    script: hex.decode('76a91411dbe48cc6b617f9c6adaf4d9ed5f625b1c7cb5988ac'),
  },
  {
    hash: hex.decode('fae21e319ca827df32462afc3225c17719338a8e8d3e3b3ddeb0c2387da3a4c7'),
    index: 0,
    amount: 600n,
    script: hex.decode('76a91411dbe48cc6b617f9c6adaf4d9ed5f625b1c7cb5988ac'),
  },
];
const RAW_TX_HEX =
  '01000000033edaa6c4e0740ae334dbb5857dd8c6faf6ea5196760652ad7033ed9031c261c00000000000ffffffff0d9ae8a4191b3ba5a2b856c21af0f7a4feb97957ae80725ef38a933c906519a20000000000ffffffffc7a4a37d38c2b0de3d3b3e8d8e8a331977c12532fc2a4632df27a89c311ee2fa0000000000ffffffff03e8030000000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac881300000000000017a914a860f76561c85551594c18eecceffaee8c4822d7876b24000000000000160014e8df018c7e326cc253faac7e46cdc51e68542c4200000000';

should('BTC: tx (from P2PKH)', async () => {
  const privKey = hex.decode('0101010101010101010101010101010101010101010101010101010101010101');
  const opts = { allowLegacyWitnessUtxo: true };
  const tx = new btc.Transaction(1, undefined, undefined, opts);
  for (const [address, amount] of TX_TEST_OUTPUTS) tx.addOutputAddress(address, amount);
  for (const inp of TX_TEST_INPUTS) tx.addInput(inp);
  deepStrictEqual(tx.hex, RAW_TX_HEX);
  // Replace input scripts with ours, so we can sign
  const tx2 = new btc.Transaction(1, undefined, undefined, opts);
  for (const [address, amount] of TX_TEST_OUTPUTS) tx2.addOutputAddress(address, amount);
  const pub = secp256k1.getPublicKey(privKey, true);
  for (const inp of TX_TEST_INPUTS) {
    tx2.addInput({
      ...inp,
      witnessUtxo: {
        amount: inp.amount,
        script: btc.p2pkh(pub).script,
      },
    });
  }
  // Raw tx didn't change
  deepStrictEqual(hex.encode(tx2.unsignedTx), RAW_TX_HEX);
  tx2.sign(privKey);
  tx2.finalize();
  deepStrictEqual(tx2.id, 'ff4f6059e863b7895c41d281844bd4dc7e4abddeb5355964c8d3289f04d0740e');
  deepStrictEqual(
    tx2.hex,
    '01000000033edaa6c4e0740ae334dbb5857dd8c6faf6ea5196760652ad7033ed9031c261c0000000006b483045022100ebd4914718a90a0a6834045762b7a67d512f73b2a210441385f5ef8edfc5b538022037fd5106983776881a3bcc36310c75e79c12d4aedb43ce11f85ce1d74249e3cb0121031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078fffffffff0d9ae8a4191b3ba5a2b856c21af0f7a4feb97957ae80725ef38a933c906519a2000000006a47304402205a964b10bee52a3c9f79693e14698d31e4db76520d9bc908e80c2083c381727002205455f331c234928cf51db9a32d2a9f1f3f4514a44d17c15429b2f23cedef73140121031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078fffffffffc7a4a37d38c2b0de3d3b3e8d8e8a331977c12532fc2a4632df27a89c311ee2fa000000006a473044022067f886b5b7292aa07b682af0910e48dd4128d336e89751dd93035538d0cde99002203285d5d4a5f5652ddf57275480e5c070241f8d3a1cbe27e1a30934d37ff07ca80121031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078fffffffff03e8030000000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac881300000000000017a914a860f76561c85551594c18eecceffaee8c4822d7876b24000000000000160014e8df018c7e326cc253faac7e46cdc51e68542c4200000000'
  );
});

should('BTC: tx (from bech32)', async () => {
  const privKey = hex.decode('0101010101010101010101010101010101010101010101010101010101010101');
  const tx32 = new btc.Transaction(1);
  for (const inp of TX_TEST_INPUTS) {
    tx32.addInput({
      hash: inp.hash,
      index: inp.index,
      witnessUtxo: {
        amount: inp.amount,
        script: btc.p2wpkh(secp256k1.getPublicKey(privKey, true)).script,
      },
    });
  }
  for (const [address, amount] of TX_TEST_OUTPUTS) tx32.addOutputAddress(address, amount);
  deepStrictEqual(hex.encode(tx32.unsignedTx), RAW_TX_HEX);
  tx32.sign(privKey);
  tx32.finalize();
  deepStrictEqual(tx32.id, 'cbb94443b19861df0824914fa654212facc071854e0df6f7388b482a6394526d');
  deepStrictEqual(
    tx32.hex,
    '010000000001033edaa6c4e0740ae334dbb5857dd8c6faf6ea5196760652ad7033ed9031c261c00000000000ffffffff0d9ae8a4191b3ba5a2b856c21af0f7a4feb97957ae80725ef38a933c906519a20000000000ffffffffc7a4a37d38c2b0de3d3b3e8d8e8a331977c12532fc2a4632df27a89c311ee2fa0000000000ffffffff03e8030000000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac881300000000000017a914a860f76561c85551594c18eecceffaee8c4822d7876b24000000000000160014e8df018c7e326cc253faac7e46cdc51e68542c4202473044022024e7b1a6ae19a95c69c192745db09cc54385a80cc7684570cfbf2da84cbbfa0802205ad55efb2019a1aa6edc03cf243989ea428c4d216699cbae2cfaf3c26ddef5650121031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f0247304402204415ef16f341e888ca2483b767b47fcf22977b6d673c3f7c6cae2f6b4bc2ac08022055be98747345b02a6f40edcc2f80390dcef4efe57b38c1bb7d16bdbca710abfd0121031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f02473044022069769fb5c97a7dd9401dbd3f6d32a38fe82bc8934c49c7c4cd3b39c6d120080c02202c181604203dc45c10e5290ded103195fae117d7fb0db19cdc411e73a76da6cb0121031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f00000000'
  );
});

should('getAddress', () => {
  const privKey = hex.decode('0101010101010101010101010101010101010101010101010101010101010101');
  deepStrictEqual(btc.getAddress('pkh', privKey), ADDR_1); // P2PKH (legacy address)
  deepStrictEqual(btc.getAddress('wpkh', privKey), 'bc1q0xcqpzrky6eff2g52qdye53xkk9jxkvrh6yhyw'); // SegWit V0 address
  deepStrictEqual(
    btc.getAddress('tr', privKey),
    'bc1p33wm0auhr9kkahzd6l0kqj85af4cswn276hsxg6zpz85xe2r0y8syx4e5t'
  ); // TapRoot KeyPathSpend
});

should('WIF', () => {
  const privKey = hex.decode('0101010101010101010101010101010101010101010101010101010101010101');
  deepStrictEqual(
    btc.WIF().encode(privKey),
    'KwFfNUhSDaASSAwtG7ssQM1uVX8RgX5GHWnnLfhfiQDigjioWXHH'
  );
  deepStrictEqual(
    hex.encode(btc.WIF().decode('KwFfNUhSDaASSAwtG7ssQM1uVX8RgX5GHWnnLfhfiQDigjioWXHH')),
    '0101010101010101010101010101010101010101010101010101010101010101'
  );
});

should('Script', () => {
  deepStrictEqual(
    btc.Script.decode(
      hex.decode(
        '5221030000000000000000000000000000000000000000000000000000000000000001210300000000000000000000000000000000000000000000000000000000000000022103000000000000000000000000000000000000000000000000000000000000000353ae'
      )
    ).map((i) => (P.isBytes(i) ? hex.encode(i) : i)),
    [
      'OP_2',
      '030000000000000000000000000000000000000000000000000000000000000001',
      '030000000000000000000000000000000000000000000000000000000000000002',
      '030000000000000000000000000000000000000000000000000000000000000003',
      'OP_3',
      'CHECKMULTISIG',
    ]
  );
  deepStrictEqual(
    hex.encode(
      btc.Script.encode([
        'OP_2',
        hex.decode('030000000000000000000000000000000000000000000000000000000000000001'),
        hex.decode('030000000000000000000000000000000000000000000000000000000000000002'),
        hex.decode('030000000000000000000000000000000000000000000000000000000000000003'),
        'OP_3',
        'CHECKMULTISIG',
      ])
    ),
    '5221030000000000000000000000000000000000000000000000000000000000000001210300000000000000000000000000000000000000000000000000000000000000022103000000000000000000000000000000000000000000000000000000000000000353ae'
  );
});

should('OutScript', () => {
  deepStrictEqual(
    btc.OutScript.decode(
      hex.decode(
        '5221030000000000000000000000000000000000000000000000000000000000000001210300000000000000000000000000000000000000000000000000000000000000022103000000000000000000000000000000000000000000000000000000000000000353ae'
      )
    ),
    {
      type: 'ms',
      m: 2,
      pubkeys: [
        '030000000000000000000000000000000000000000000000000000000000000001',
        '030000000000000000000000000000000000000000000000000000000000000002',
        '030000000000000000000000000000000000000000000000000000000000000003',
      ].map(hex.decode),
    }
  );
  deepStrictEqual(
    hex.encode(
      btc.OutScript.encode({
        type: 'ms',
        m: 2,
        pubkeys: [
          '030000000000000000000000000000000000000000000000000000000000000001',
          '030000000000000000000000000000000000000000000000000000000000000002',
          '030000000000000000000000000000000000000000000000000000000000000003',
        ].map(hex.decode),
      })
    ),
    '5221030000000000000000000000000000000000000000000000000000000000000001210300000000000000000000000000000000000000000000000000000000000000022103000000000000000000000000000000000000000000000000000000000000000353ae'
  );
});

should('payTo API', () => {
  // cross-checked with bitcoinjs-lib manually
  const uncompressed = hex.decode(
    '04ad90e5b6bc86b3ec7fac2c5fbda7423fc8ef0d58df594c773fa05e2c281b2bfe877677c668bd13603944e34f4818ee03cadd81a88542b8b4d5431264180e2c28'
  );
  // No uncompressed keys with segwit!
  throws(() => btc.p2wpkh(uncompressed));
  deepStrictEqual(btc.p2pkh(uncompressed), {
    type: 'pkh',
    address: '1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P',
    script: hex.decode('76a914946cb2e08075bcbaf157e47bcb67eb2b2339d24288ac'),
  });
  deepStrictEqual(btc.p2pk(uncompressed), {
    type: 'pk',
    script: hex.decode(
      '4104ad90e5b6bc86b3ec7fac2c5fbda7423fc8ef0d58df594c773fa05e2c281b2bfe877677c668bd13603944e34f4818ee03cadd81a88542b8b4d5431264180e2c28ac'
    ),
  });
  const compressed = hex.decode(
    '030000000000000000000000000000000000000000000000000000000000000001'
  );
  deepStrictEqual(btc.p2pkh(compressed), {
    type: 'pkh',
    address: '134D6gYy8DsR5m4416BnmgASuMBqKvogQh',
    script: hex.decode('76a914168b992bcfc44050310b3a94bd0771136d0b28d188ac'),
  });
  deepStrictEqual(btc.p2wpkh(compressed), {
    type: 'wpkh',
    address: 'bc1qz69ej270c3q9qvgt822t6pm3zdksk2x35j2jlm',
    script: hex.decode('0014168b992bcfc44050310b3a94bd0771136d0b28d1'),
  });
  deepStrictEqual(btc.p2sh(btc.p2pkh(compressed)), {
    type: 'sh',
    address: '3EPhLJ1FuR2noj6qrTs4YvepCvB6sbShoV',
    script: hex.decode('a9148b530b962725af3bb7c818f197c619db3f71495087'),
    redeemScript: hex.decode('76a914168b992bcfc44050310b3a94bd0771136d0b28d188ac'),
  });
  deepStrictEqual(btc.p2sh(btc.p2wpkh(compressed)), {
    type: 'sh',
    address: '3BCuRViGCTXmQjyJ9zjeRUYrdZTUa38zjC',
    script: hex.decode('a91468602f2db7b7d7cdcd2639ab6bf7f5bfe828e53f87'),
    redeemScript: hex.decode('0014168b992bcfc44050310b3a94bd0771136d0b28d1'),
  });
  deepStrictEqual(btc.p2wsh(btc.p2pkh(compressed)), {
    type: 'wsh',
    address: 'bc1qhxtthndg70cthfasy8y4qlk9h7r3006azn9md0fad5dg9hh76nkqaufnuz',
    script: hex.decode('0020b996bbcda8f3f0bba7b021c9507ec5bf8717bf5d14cbb6bd3d6d1a82defed4ec'),
    witnessScript: hex.decode('76a914168b992bcfc44050310b3a94bd0771136d0b28d188ac'),
  });
  // Cannot be wrapped in p2wsh
  throws(() => btc.p2wsh(btc.p2wpkh(compressed)));
  deepStrictEqual(btc.p2sh(btc.p2wsh(btc.p2pkh(compressed))), {
    type: 'sh',
    address: '3EHxWHyLv5Seu5Cd6D1cH56jLKxSi3ps8C',
    script: hex.decode('a9148a3d36fb710a9c7cae06cfcdf39792ff5773e8f187'),
    redeemScript: hex.decode(
      '0020b996bbcda8f3f0bba7b021c9507ec5bf8717bf5d14cbb6bd3d6d1a82defed4ec'
    ),
    witnessScript: hex.decode('76a914168b992bcfc44050310b3a94bd0771136d0b28d188ac'),
  });
  const compressed2 = hex.decode(
    '030000000000000000000000000000000000000000000000000000000000000002'
  );
  const compressed3 = hex.decode(
    '030000000000000000000000000000000000000000000000000000000000000003'
  );
  // Multisig 2-of-3 wrapped in P2SH
  deepStrictEqual(btc.p2sh(btc.p2ms(2, [compressed, compressed2, compressed3])), {
    type: 'sh',
    address: '3G4AeQtzCLoDAyv2eb3UVTG5atfkyHtuRn',
    script: hex.decode('a9149d91c6de4eacde72a7cc86bff98d1915b3c7818f87'),
    redeemScript: hex.decode(
      '5221030000000000000000000000000000000000000000000000000000000000000001210300000000000000000000000000000000000000000000000000000000000000022103000000000000000000000000000000000000000000000000000000000000000353ae'
    ),
  });
  // Utils
  deepStrictEqual(
    btc.p2sh(btc.p2ms(2, [compressed, compressed2, compressed3])),
    btc.multisig(2, [compressed, compressed2, compressed3])
  );
  deepStrictEqual(
    btc.p2wsh(btc.p2ms(2, [compressed, compressed2, compressed3])),
    btc.multisig(2, [compressed, compressed2, compressed3], undefined, true)
  );
  // sorted multisig (BIP67)
  deepStrictEqual(
    btc.p2sh(btc.p2ms(2, [compressed, compressed2, compressed3])),
    btc.sortedMultisig(2, [compressed, compressed2, compressed3])
  );
  deepStrictEqual(
    btc.p2wsh(btc.p2ms(2, [compressed, compressed2, compressed3])),
    btc.sortedMultisig(2, [compressed, compressed2, compressed3], true)
  );
  // Multisig 2-of-3 wrapped in P2WSH
  deepStrictEqual(btc.p2wsh(btc.p2ms(2, [compressed, compressed2, compressed3])), {
    type: 'wsh',
    address: 'bc1qwnhzkn8wcyyrnfyfcp7555urssu5dq0rmnvg70hg02z3nxgg4f0qljmr2h',
    script: hex.decode('002074ee2b4ceec10839a489c07d4a538384394681e3dcd88f3ee87a85199908aa5e'),
    witnessScript: hex.decode(
      '5221030000000000000000000000000000000000000000000000000000000000000001210300000000000000000000000000000000000000000000000000000000000000022103000000000000000000000000000000000000000000000000000000000000000353ae'
    ),
  });
  // Multisig 2-of-3 wrapped in P2SH-P2WSH
  deepStrictEqual(btc.p2sh(btc.p2wsh(btc.p2ms(2, [compressed, compressed2, compressed3]))), {
    type: 'sh',
    address: '3HKWSo57kmcJZ3h43pXS3m5UESR4wXcWTd',
    script: hex.decode('a914ab70ab84b12b891364b4b2a14ca813cac308b24287'),
    redeemScript: hex.decode(
      '002074ee2b4ceec10839a489c07d4a538384394681e3dcd88f3ee87a85199908aa5e'
    ),
    witnessScript: hex.decode(
      '5221030000000000000000000000000000000000000000000000000000000000000001210300000000000000000000000000000000000000000000000000000000000000022103000000000000000000000000000000000000000000000000000000000000000353ae'
    ),
  });
  throws(() => btc.p2tr(undefined, btc.p2ms(2, [compressed, compressed2, compressed3])));
  // Maybe can be wrapped, but non-representable in PSBT
  throws(() => btc.p2sh(btc.p2sh(btc.p2pkh(compressed))));
  const taproot = hex.decode('0101010101010101010101010101010101010101010101010101010101010101');
  deepStrictEqual(btc.p2tr(taproot), {
    type: 'tr',
    address: 'bc1p7yu5dsly83jg5tkxcljsa30vnpdpl22wr6rty98t6x6p6ekz2gkqzf2t2s',
    script: hex.decode('5120f13946c3e43c648a2ec6c7e50ec5ec985a1fa94e1e86b214ebd1b41d66c2522c'),
    tweakedPubkey: hex.decode('f13946c3e43c648a2ec6c7e50ec5ec985a1fa94e1e86b214ebd1b41d66c2522c'),
    tapInternalKey: hex.decode('0101010101010101010101010101010101010101010101010101010101010101'),
    tapMerkleRoot: hex.decode(''),
  });
  // Taproot script cannot be wrapped in other
  throws(() => btc.p2sh(btc.p2tr(taproot)));
  throws(() => btc.p2wsh(btc.p2tr(taproot)));
  const taproot2 = hex.decode('0202020202020202020202020202020202020202020202020202020202020202');
  const taproot3 = hex.decode('1212121212121212121212121212121212121212121212121212121212121212');
  // TR NS multisig: 3-of-3 (single leaf script)
  deepStrictEqual(btc.p2tr_ns(3, [taproot, taproot2, taproot3]), [
    {
      type: 'tr_ns',
      script: hex.decode(
        '200101010101010101010101010101010101010101010101010101010101010101ad200202020202020202020202020202020202020202020202020202020202020202ad201212121212121212121212121212121212121212121212121212121212121212ac'
      ),
    },
  ]);
  // Cannot be wrapped in P2SH/P2WSH
  throws(() => btc.p2sh(btc.p2tr_ns(3, [taproot, taproot2, taproot3])[0]));
  throws(() => btc.p2wsh(btc.p2tr_ns(3, [taproot, taproot2, taproot3])[0]));

  // If M!==pubkeys.length, then multiple leafs will be created, so third pubkey won't be exposed after
  // signing with first two
  deepStrictEqual(btc.p2tr_ns(2, [taproot, taproot2, taproot3]), [
    {
      type: 'tr_ns',
      script: hex.decode(
        '200101010101010101010101010101010101010101010101010101010101010101ad200202020202020202020202020202020202020202020202020202020202020202ac'
      ),
    },
    {
      type: 'tr_ns',
      script: hex.decode(
        '200101010101010101010101010101010101010101010101010101010101010101ad201212121212121212121212121212121212121212121212121212121212121212ac'
      ),
    },
    {
      type: 'tr_ns',
      script: hex.decode(
        '200202020202020202020202020202020202020202020202020202020202020202ad201212121212121212121212121212121212121212121212121212121212121212ac'
      ),
    },
  ]);
  // NOTE: cannot find implementation, so it is untested for now
  deepStrictEqual(btc.p2tr_ms(2, [taproot, taproot2, taproot3]), {
    type: 'tr_ms',
    script: hex.decode(
      '200101010101010101010101010101010101010101010101010101010101010101ac200202020202020202020202020202020202020202020202020202020202020202ba201212121212121212121212121212121212121212121212121212121212121212ba529c'
    ),
  });
  // Taproot scripts
  // Simple 1-leaf script
  deepStrictEqual(btc.p2tr(undefined, btc.p2tr(taproot)), {
    type: 'tr',
    address: 'bc1pftcdjvdu8mzn9yg7p5xqt2cd46cuc5eg0p7d02cdpkgecrckx7ess7ky4x',
    script: hex.decode('51204af0d931bc3ec532911e0d0c05ab0daeb1cc5328787cd7ab0d0d919c0f1637b3'),
    tweakedPubkey: hex.decode('4af0d931bc3ec532911e0d0c05ab0daeb1cc5328787cd7ab0d0d919c0f1637b3'),
    tapInternalKey: hex.decode('50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0'),
    tapMerkleRoot: hex.decode('e289be80af8fd95dbf86e86838d06b4f9effd622cc3f45797a40e6da9dcece16'),
    leaves: [
      {
        type: 'leaf',
        version: undefined,
        script: hex.decode('5120f13946c3e43c648a2ec6c7e50ec5ec985a1fa94e1e86b214ebd1b41d66c2522c'),
        hash: hex.decode('e289be80af8fd95dbf86e86838d06b4f9effd622cc3f45797a40e6da9dcece16'),
        path: [],
        controlBlock: hex.decode(
          'c00101010101010101010101010101010101010101010101010101010101010101'
        ),
        tapInternalKey: hex.decode(
          '0101010101010101010101010101010101010101010101010101010101010101'
        ),
      },
    ],
    tapLeafScript: [
      [
        {
          version: 192,
          internalKey: hex.decode(
            '0101010101010101010101010101010101010101010101010101010101010101'
          ),
          merklePath: [],
        },
        hex.decode('5120f13946c3e43c648a2ec6c7e50ec5ec985a1fa94e1e86b214ebd1b41d66c2522cc0'),
      ],
    ],
  });
  const tr = (t) => ({ type: t.type, script: t.script, address: t.address });

  deepStrictEqual(tr(btc.p2tr(undefined, [btc.p2tr(taproot)])), {
    type: 'tr',
    address: 'bc1pftcdjvdu8mzn9yg7p5xqt2cd46cuc5eg0p7d02cdpkgecrckx7ess7ky4x',
    script: hex.decode('51204af0d931bc3ec532911e0d0c05ab0daeb1cc5328787cd7ab0d0d919c0f1637b3'),
  });
  // 3 leaf list (p2tr will build binary tree itself)
  deepStrictEqual(
    tr(btc.p2tr(undefined, [btc.p2tr(taproot), btc.p2tr(taproot2), btc.p2tr(taproot3)])),
    {
      type: 'tr',
      // weights for bitcoinjs-lib: [3,2,1]
      address: 'bc1p58hcmfcjaee0jwzlgluzw86paw0h7sqmw2c8yq8t4wleqlqdn3qqv3rxf0',
      script: hex.decode('5120a1ef8da712ee72f9385f47f8271f41eb9f7f401b72b07200ebabbf907c0d9c40'),
    }
  );
  // If scripts is already binary tree provided, it will be used as-is
  deepStrictEqual(
    tr(btc.p2tr(undefined, [btc.p2tr(taproot2), [btc.p2tr(taproot), btc.p2tr(taproot3)]])),
    {
      type: 'tr',
      // default weights for bitcoinjs-lib
      address: 'bc1pepwhs2tvnn6uj9eqy8kqdwjk2n3r8wjkunqcmahvkn4r2uyvzsxqqae82s',
      script: hex.decode('5120c85d78296c9cf5c9172021ec06ba5654e233ba56e4c18df6ecb4ea35708c140c'),
    }
  );
  // p2tr_ns inside p2tr
  deepStrictEqual(tr(btc.p2tr(undefined, btc.p2tr_ns(2, [taproot, taproot2, taproot3]))), {
    type: 'tr',
    address: 'bc1pevfcmnkqqq09a4n0fs8c7mwlc6r4efqpvgyqpjvegllavgw235fq3kz7a0',
    script: hex.decode('5120cb138dcec0001e5ed66f4c0f8f6ddfc6875ca401620800c99947ffd621ca8d12'),
  });
});

should('Transaction input/output', () => {
  const tx = new btc.Transaction();
  // Input
  tx.addInput({ hash: new Uint8Array(32), index: 0 });
  deepStrictEqual(tx.inputs[0], {
    hash: new Uint8Array(32),
    index: 0,
    sequence: btc.DEFAULT_SEQUENCE,
  });
  const i2 = { hash: new Uint8Array(32), index: 0, sequence: 0 };
  tx.addInput(i2);
  // Sequence is 0
  deepStrictEqual(tx.inputs[1], {
    hash: new Uint8Array(32),
    index: 0,
    sequence: 0,
  });
  // Modification of internal input doesn't affect input
  tx.inputs[1].t = 5;
  deepStrictEqual(tx.inputs[1], { hash: new Uint8Array(32), index: 0, sequence: 0, t: 5 });
  deepStrictEqual(i2, { hash: new Uint8Array(32), index: 0, sequence: 0 });
  // Update basic value
  tx.updateInput(0, { index: 10 });
  deepStrictEqual(tx.inputs[0], {
    hash: new Uint8Array(32),
    index: 10,
    sequence: btc.DEFAULT_SEQUENCE,
  });
  // Add hex
  tx.addInput({
    hash: '0000000000000000000000000000000000000000000000000000000000000000',
    index: 0,
  });
  deepStrictEqual(tx.inputs[2], {
    hash: new Uint8Array(32),
    index: 0,
    sequence: btc.DEFAULT_SEQUENCE,
  });
  // Update key map
  const pubKey = hex.decode('030000000000000000000000000000000000000000000000000000000000000001');
  const bip1 = [pubKey, { fingerprint: 5, path: [1, 2, 3] }];
  const pubKey2 = hex.decode('030000000000000000000000000000000000000000000000000000000000000002');
  const bip2 = [pubKey2, { fingerprint: 6, path: [4, 5, 6] }];
  const pubKey3 = hex.decode('030000000000000000000000000000000000000000000000000000000000000003');
  const bip3 = [pubKey3, { fingerprint: 7, path: [7, 8, 9] }];
  // Add K-V
  tx.updateInput(0, { bip32Derivation: [bip1] });
  deepStrictEqual(tx.inputs[0].bip32Derivation, [bip1]);
  // Add another K-V
  tx.updateInput(0, { bip32Derivation: [bip2] });
  deepStrictEqual(tx.inputs[0].bip32Derivation, [bip1, bip2]);
  // Delete K-V
  tx.updateInput(0, { bip32Derivation: [[pubKey, undefined]] });
  deepStrictEqual(tx.inputs[0].bip32Derivation, [bip2]);
  // Second add of same k-v does nothing
  tx.updateInput(0, { bip32Derivation: [bip2] });
  deepStrictEqual(tx.inputs[0].bip32Derivation, [bip2]);
  // Second add of k-v with different value breaks
  throws(() => tx.updateInput(0, { bip32Derivation: [[pubKey2, bip1[1]]] }));
  tx.updateInput(0, { bip32Derivation: [bip1, bip2, bip3] });
  // Preserves order (re-ordered on PSBT encoding)
  deepStrictEqual(tx.inputs[0].bip32Derivation, [bip2, bip1, bip3]);
  // PSBT encoding re-order k-v
  const tx2 = btc.Transaction.fromPSBT(tx.toPSBT());
  deepStrictEqual(tx2.inputs[0].bip32Derivation, [bip1, bip2, bip3]);
  // Point validation
  throws(() => tx.updateInput(0, { tapInternalKey: new Uint8Array(32) }));
  // Remove field
  tx.updateInput(0, { tapInternalKey: new Uint8Array(32).fill(1) });
  deepStrictEqual(tx.inputs[0], {
    hash: new Uint8Array(32),
    index: 10,
    tapInternalKey: new Uint8Array(32).fill(1),
    bip32Derivation: [bip2, bip1, bip3],
    sequence: btc.DEFAULT_SEQUENCE,
  });
  tx.updateInput(0, { tapInternalKey: undefined });
  deepStrictEqual(tx.inputs[0], {
    hash: new Uint8Array(32),
    index: 10,
    bip32Derivation: [bip2, bip1, bip3],
    sequence: btc.DEFAULT_SEQUENCE,
  });
  // Delete KV
  tx.updateInput(0, { bip32Derivation: undefined });
  deepStrictEqual(tx.inputs[0], {
    hash: new Uint8Array(32),
    index: 10,
    sequence: btc.DEFAULT_SEQUENCE,
  });
  // Any other keys ignored
  tx.updateInput(0, { test: '1', b: 2 });
  deepStrictEqual(tx.inputs[0], {
    hash: new Uint8Array(32),
    index: 10,
    sequence: btc.DEFAULT_SEQUENCE,
  });

  // Output
  // Unknown script type
  throws(() => tx.addOutput({ script: new Uint8Array(32), amount: 100n }));
  const compressed = hex.decode(
    '030000000000000000000000000000000000000000000000000000000000000001'
  );
  const script = btc.p2pkh(compressed).script;
  tx.addOutput({ script, amount: 100n });
  deepStrictEqual(tx.outputs[0], {
    script,
    amount: 100n,
  });
  const o2 = { script, amount: 100n };
  tx.addOutput(o2);
  // Modification of internal input doesn't affect input
  tx.outputs[1].t = 5;
  deepStrictEqual(tx.outputs[1], {
    script,
    amount: 100n,
    t: 5,
  });
  deepStrictEqual(o2, {
    script,
    amount: 100n,
  });
  // Update basic value
  tx.updateOutput(0, { amount: 200n });
  deepStrictEqual(tx.outputs[0], {
    script,
    amount: 200n,
  });
  // Add K-V
  tx.updateOutput(0, { bip32Derivation: [bip1] });
  deepStrictEqual(tx.outputs[0].bip32Derivation, [bip1]);
  // Add another K-V
  tx.updateOutput(0, { bip32Derivation: [bip2] });
  deepStrictEqual(tx.outputs[0].bip32Derivation, [bip1, bip2]);
  // Delete K-V
  tx.updateOutput(0, { bip32Derivation: [[pubKey, undefined]] });
  deepStrictEqual(tx.outputs[0].bip32Derivation, [bip2]);
  // Second add of same k-v does nothing
  tx.updateOutput(0, { bip32Derivation: [bip2] });
  deepStrictEqual(tx.outputs[0].bip32Derivation, [bip2]);
  // Second add of k-v with different value breaks
  throws(() => tx.updateOutput(0, { bip32Derivation: [[pubKey2, bip1[1]]] }));
  tx.updateOutput(0, { bip32Derivation: [bip1, bip2, bip3] });
  // Preserves order (re-ordered on PSBT encoding)
  deepStrictEqual(tx.outputs[0].bip32Derivation, [bip2, bip1, bip3]);
  // PSBT encoding re-order k-v
  const tx3 = btc.Transaction.fromPSBT(tx.toPSBT());
  deepStrictEqual(tx3.outputs[0].bip32Derivation, [bip1, bip2, bip3]);
  // Remove field
  tx.updateOutput(0, { bip32Derivation: undefined });
  deepStrictEqual(tx.outputs[0], {
    script,
    amount: 200n,
  });
});

should('TapRoot sanity check', () => {
  const taproot = hex.decode('0101010101010101010101010101010101010101010101010101010101010101');
  const taproot2 = hex.decode('0202020202020202020202020202020202020202020202020202020202020202');
  const compressed = hex.decode(
    '030000000000000000000000000000000000000000000000000000000000000001'
  );
  const compressed2 = hex.decode(
    '030000000000000000000000000000000000000000000000000000000000000001'
  );
  const compressed3 = hex.decode(
    '030000000000000000000000000000000000000000000000000000000000000001'
  );
  throws(() => btc.p2tr(undefined, [btc.p2pkh(compressed)]));
  throws(() => btc.p2tr(undefined, [btc.p2wpkh(compressed)]));
  throws(() => btc.p2tr(undefined, [btc.p2sh(btc.p2pkh(compressed))]));
  throws(() => btc.p2tr(undefined, [btc.p2wsh(btc.p2pkh(compressed))]));
  // Plain tr script is ok
  btc.p2tr(undefined, [btc.p2tr(taproot)]);
  // Nested script tree is not allowed
  throws(() => btc.p2tr(undefined, [btc.p2tr(taproot, btc.p2tr(taproot2))]));
  throws(() => btc.p2tr(undefined, btc.p2tr(undefined, btc.p2tr(taproot2))));
  throws(() => btc.p2tr(undefined, btc.p2ms(2, [compressed, compressed2, compressed3])));
  // No key && no tree
  throws(() => btc.p2tr(undefined, undefined));
  throws(() => btc.p2tr(undefined, btc.p2tr(btc.TAPROOT_UNSPENDABLE_KEY)));
});

should('Multisig sanity check', () => {
  const compressed = hex.decode(
    '030000000000000000000000000000000000000000000000000000000000000001'
  );
  const compressed2 = hex.decode(
    '030000000000000000000000000000000000000000000000000000000000000002'
  );
  const compressed3 = hex.decode(
    '030000000000000000000000000000000000000000000000000000000000000003'
  );
  const taproot = hex.decode('0101010101010101010101010101010101010101010101010101010101010101');
  const taproot2 = hex.decode('0202020202020202020202020202020202020202020202020202020202020202');
  const taproot3 = hex.decode('1212121212121212121212121212121212121212121212121212121212121212');
  // Different keys -> ok
  btc.p2ms(2, [compressed, compressed2, compressed3]);
  // Same key -> error by default
  throws(() => btc.p2ms(2, [compressed, compressed, compressed3]));
  // With opt -> ok
  btc.p2ms(2, [compressed, compressed, compressed3], true);
  // Taproot keys -> fails
  throws(() => btc.p2ms(2, [taproot, taproot2, taproot3]));
  // Same for p2tr_ns
  btc.p2tr_ns(2, [taproot, taproot2, taproot3]);
  throws(() => btc.p2tr_ns(2, [taproot, taproot, taproot3]));
  btc.p2tr_ns(2, [taproot, taproot, taproot3], true);
  throws(() => btc.p2tr_ns(2, [compressed, compressed2, compressed3]));
  // Same for p2tr_ms
  btc.p2tr_ms(2, [taproot, taproot2, taproot3]);
  throws(() => btc.p2tr_ms(2, [taproot, taproot, taproot3]));
  btc.p2tr_ms(2, [taproot, taproot, taproot3], true);
  throws(() => btc.p2tr_ms(2, [compressed, compressed2, compressed3]));
});

should('Big test', () => {
  // Do test with tx to verify against regtest network
  // What we need to test && fix bugs?
  // - Signing taproot inside taproot script tree
  // - taproot multisigs
  // - verify that M-of-N multisig produces only M signatures even if N available
  // - Move input generation for specific output scripts near them
  // - Do every p2* scripts and try to sign with them
  // scripts:
  const privKey1 = hex.decode('0101010101010101010101010101010101010101010101010101010101010101');
  // TODO: btc.getPublic with types or something?
  const pubKey1 = secp256k1.getPublicKey(privKey1, true);
  const spend1_1 = btc.p2sh(btc.p2pk(pubKey1));
  const spend1_2 = btc.p2wsh(btc.p2pk(pubKey1));
  const spend1_3 = btc.p2sh(btc.p2wsh(btc.p2pk(pubKey1)));
  // - p2sh-p2pk
  // - p2wsh-p2pk
  // - p2sh-p2wsh-p2pk
  // ----------------
  const privKey2 = hex.decode('0202020202020202020202020202020202020202020202020202020202020202');
  const pubKey2 = secp256k1.getPublicKey(privKey2, true);
  const spend2_1 = btc.p2sh(btc.p2pkh(pubKey2));
  const spend2_2 = btc.p2wsh(btc.p2pkh(pubKey2));
  const spend2_3 = btc.p2sh(btc.p2wsh(btc.p2pkh(pubKey2)));
  const spend2_4 = btc.p2pkh(pubKey2);
  // - p2sh-p2pkh
  // - p2wsh-p2pkh
  // - p2sh-p2wsh-p2pkh
  // - p2pkh
  // ----------------
  const privKey3 = hex.decode('0303030303030303030303030303030303030303030303030303030303030303');
  const pubKey3 = secp256k1.getPublicKey(privKey3, true);
  const spend3_1 = btc.p2sh(btc.p2wpkh(pubKey3));
  const spend3_2 = btc.p2wpkh(pubKey3);
  // - p2sh-p2wpkh
  // - p2wpkh
  // ----------------
  const privKey4 = hex.decode('0404040404040404040404040404040404040404040404040404040404040404');
  const privKey5 = hex.decode('0505050505050505050505050505050505050505050505050505050505050505');
  const privKey6 = hex.decode('0606060606060606060606060606060606060606060606060606060606060606');
  const pubKey4 = secp256k1.getPublicKey(privKey4, true);
  const pubKey5 = secp256k1.getPublicKey(privKey5, true);
  const pubKey6 = secp256k1.getPublicKey(privKey6, true);
  const spend4_1 = btc.p2sh(btc.p2ms(2, [pubKey4, pubKey5, pubKey6]));
  const spend4_2 = btc.p2wsh(btc.p2ms(2, [pubKey4, pubKey5, pubKey6]));
  const spend4_3 = btc.p2sh(btc.p2wsh(btc.p2ms(2, [pubKey4, pubKey5, pubKey6])));
  // - p2sh-p2ms
  // - p2wsh-p2ms
  // - p2sh-p2wsh-p2ms
  // ----------------
  const privKey7 = hex.decode('0707070707070707070707070707070707070707070707070707070707070707');
  const privKey8 = hex.decode('0808080808080808080808080808080808080808080808080808080808080808');
  const privKey9 = hex.decode('0909090909090909090909090909090909090909090909090909090909090909');
  const pubKey7 = secp256k1.schnorr.getPublicKey(privKey7);
  const pubKey8 = secp256k1.schnorr.getPublicKey(privKey8);
  const pubKey9 = secp256k1.schnorr.getPublicKey(privKey9);
  const spend5_1 = btc.p2tr(pubKey7);
  const spend5_2 = btc.p2tr(undefined, [btc.p2tr(pubKey8)]);
  const spend5_3 = btc.p2tr(pubKey7, [btc.p2tr(pubKey8)]);
  const spend5_4 = btc.p2tr(undefined, btc.p2tr_ns(2, [pubKey7, pubKey8, pubKey9]));
  const spend5_5 = btc.p2tr(undefined, btc.p2tr_ms(2, [pubKey7, pubKey8, pubKey9]));
  // p2tr keysig
  // p2tr-p2tr_ns
  // p2tr-p2tr_ms
  // p2tr-p2tr
  const spends = [
    spend1_1,
    spend1_2,
    spend1_3,
    spend2_1,
    spend2_2,
    spend2_3,
    spend2_4,
    spend3_1,
    spend3_2,
    spend4_1,
    spend4_2,
    spend4_3,
    spend5_1,
    spend5_2,
    spend5_3,
    spend5_4,
    spend5_5,
  ];
  console.log(
    'ADDDR',
    spends.map((i) => i.address)
  );
  /* 
  // Create and send to these at regtest, then try to create & sign tx here and spend
  [
  '32pyvwPt6L2v2xTaDvRYGWm31oefJQ78Ri',
  'bc1q0g8nfnsvxzt8amgutgszrv0fxgwdn9yakprztj29sqzqhpw8gvuqnxyt92',
  '33RtJAwqz79iQrKkAN4s39Ziuo1jzgQEhy',
  '3HAwrTinYuWLj5nj98p4Woxuyw9kvHd51o',
  'bc1q3prrz6e0n55y6d0kkan6uejfyr94x3caq9r4qk8tzxudt6pmg9vqe9zj0z',
  '31oqrpvJ6hakAaqedN9thSXYT5wo5XyBPS',
  '1NVYv5jmr9JRF3usPZJQmJFJhbQhrPESTP',
  '32GDcsUty2rgDyCN6EPeWKmjesu1f4X16d',
  'bc1qg975h6gdx5mryeac72h6lj2nzygugxhyuukqvs',
  '3Ea4B1sCcmhRqPukk4ZkqdajTMjwMiLdUh',
  'bc1q3tq3y634aaf4esr9dzx5n8py0p0tk6jfzt8rd6km4ytnwp84xpxql53xhj',
  '3C6gGbUbd8Rbmso2FYmGHNqAswy5GfjNLy',
  'bc1pw53jtgez0wf69n06fchp0ctk48620zdscnrj8heh86wykp9mv20qya3c8w',
  'bc1p2n3kgpxycaqgs694n52tmad5sew3v8fe2qgl4cu5kk79w6vckuhqf94jfu',
  'bc1p9ck4zvx9x5e9846fy0gahrtre499en8ufdpzvulyr5yd3dr3km0s2e7v06',
  'bc1pyze0lhtk4hmyq8xxxvkt73ae3y53wx2sktupajdp3zkfzlkwtlcsj9hgqa',
  'bc1pvj97rgc5flzt0kpdsly9aqsutsxp7ct2fwgtyzap4mtalh8gxe5suvuj66'
] 
  */
  const tx = new btc.Transaction();
});

// ESM is broken.
import url from 'url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}

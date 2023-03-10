import { deepStrictEqual, throws } from 'assert';
import { should } from 'micro-should';
import { hex } from '@scure/base';
import * as btc from '../index.js';
import { secp256k1, schnorr as secp256k1_schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import * as P from 'micro-packed';

const testClone = (tx) => deepStrictEqual(tx.clone(), tx);

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
  ['1cMh228HTCiwS8ZsaakH8A8wze1JR5ZsP', 10n],
  ['3H3Kc7aSPP4THLX68k4mQMyf1gvL6AtmDm', 50n],
  ['bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq', 93n],
];
const TX_TEST_INPUTS = [
  {
    txid: hex.decode('c061c23190ed3370ad5206769651eaf6fac6d87d85b5db34e30a74e0c4a6da3e'),
    index: 0,
    amount: 550n,
    script: hex.decode('76a91411dbe48cc6b617f9c6adaf4d9ed5f625b1c7cb5988ac'),
  },
  {
    txid: hex.decode('a21965903c938af35e7280ae5779b9fea4f7f01ac256b8a2a53b1b19a4e89a0d'),
    index: 0,
    amount: 600n,
    script: hex.decode('76a91411dbe48cc6b617f9c6adaf4d9ed5f625b1c7cb5988ac'),
  },
  {
    txid: hex.decode('fae21e319ca827df32462afc3225c17719338a8e8d3e3b3ddeb0c2387da3a4c7'),
    index: 0,
    amount: 600n,
    script: hex.decode('76a91411dbe48cc6b617f9c6adaf4d9ed5f625b1c7cb5988ac'),
  },
];
const RAW_TX_HEX =
  '01000000033edaa6c4e0740ae334dbb5857dd8c6faf6ea5196760652ad7033ed9031c261c00000000000ffffffff0d9ae8a4191b3ba5a2b856c21af0f7a4feb97957ae80725ef38a933c906519a20000000000ffffffffc7a4a37d38c2b0de3d3b3e8d8e8a331977c12532fc2a4632df27a89c311ee2fa0000000000ffffffff030a000000000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac320000000000000017a914a860f76561c85551594c18eecceffaee8c4822d7875d00000000000000160014e8df018c7e326cc253faac7e46cdc51e68542c4200000000';

should('BTC: tx (from P2PKH)', async () => {
  const privKey = hex.decode('0101010101010101010101010101010101010101010101010101010101010101');
  const opts = { version: 1, allowLegacyWitnessUtxo: true };
  const tx = new btc.Transaction(opts);
  for (const [address, amount] of TX_TEST_OUTPUTS) tx.addOutputAddress(address, amount);
  for (const inp of TX_TEST_INPUTS) tx.addInput(inp);
  deepStrictEqual(tx.hex, RAW_TX_HEX);
  // Replace input scripts with ours, so we can sign
  const tx2 = new btc.Transaction(opts);
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
  deepStrictEqual(tx2.id, 'e25547b7b2a336b41bfa86f75d727edfd75a7042a6a28c63772c9ccfc0bc46f2');
  deepStrictEqual(
    tx2.hex,
    '01000000033edaa6c4e0740ae334dbb5857dd8c6faf6ea5196760652ad7033ed9031c261c0000000006a47304402206b671e590b4ba4c6577c7ae675e9c1ee60106d70ee76c0c19cb1a3838579c986022072d2a0b6f05b551c58f44202ee2e46516cd80f8b8722bb7b6011114e5f0c7b8f0121031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078fffffffff0d9ae8a4191b3ba5a2b856c21af0f7a4feb97957ae80725ef38a933c906519a2000000006b483045022100b2f14a2fc37f9f543bb41abbfb0fe9c1a64b749741697d41a9835a8fd1da5c6102201f885ff5b9cb91da9b47490d7c4b035c157098f35bd31eb174b4d1740729027e0121031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078fffffffffc7a4a37d38c2b0de3d3b3e8d8e8a331977c12532fc2a4632df27a89c311ee2fa000000006a47304402202bffd6721d35e06fd36f99e709f16c5007c99a09051098109366df50542bec4d0220427a7604b77749de9afe876951f19fcba1d7f7d743805466403b7331100fc8170121031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078fffffffff030a000000000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac320000000000000017a914a860f76561c85551594c18eecceffaee8c4822d7875d00000000000000160014e8df018c7e326cc253faac7e46cdc51e68542c4200000000'
  );
});

should('BTC: tx (from bech32)', async () => {
  const privKey = hex.decode('0101010101010101010101010101010101010101010101010101010101010101');
  const tx32 = new btc.Transaction({ version: 1 });
  for (const [address, amount] of TX_TEST_OUTPUTS) tx32.addOutputAddress(address, amount);
  for (const inp of TX_TEST_INPUTS) {
    tx32.addInput({
      txid: inp.txid,
      index: inp.index,
      witnessUtxo: {
        amount: inp.amount,
        script: btc.p2wpkh(secp256k1.getPublicKey(privKey, true)).script,
      },
    });
  }
  deepStrictEqual(hex.encode(tx32.unsignedTx), RAW_TX_HEX);
  tx32.sign(privKey);
  tx32.finalize();
  deepStrictEqual(tx32.id, 'e4db0a196f378a6648deb221a2771fde577892479a2d52abbe8cf3d31d2f140f');
  deepStrictEqual(
    tx32.hex,
    '010000000001033edaa6c4e0740ae334dbb5857dd8c6faf6ea5196760652ad7033ed9031c261c00000000000ffffffff0d9ae8a4191b3ba5a2b856c21af0f7a4feb97957ae80725ef38a933c906519a20000000000ffffffffc7a4a37d38c2b0de3d3b3e8d8e8a331977c12532fc2a4632df27a89c311ee2fa0000000000ffffffff030a000000000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac320000000000000017a914a860f76561c85551594c18eecceffaee8c4822d7875d00000000000000160014e8df018c7e326cc253faac7e46cdc51e68542c4202483045022100d04801283249fc9a80f71d8fe8d9f6dc0e84afc0e59df2733f04ff659e095a8802206ce71c598d8f75b7cb2102b252b7bd04c6228c0826da0ed27104f8cca829869d0121031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f02473044022026ef492099b86572a965b28d11a40bf9b1e9fe5a2aeab22cbca1b354988910e30220416508f564e67932cb1c38bef7a3c3f0a95470fc81c6cb359a9268a49f6449850121031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f0247304402202cf37bbcf2c098e48ffc204d0ab688465b43642546d2e0414f5b8e4bdfae9420022006ccfb2415c7a941b6d5c07651fd80b9656bdea5fe793530cf2c604920c72d100121031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f00000000'
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
      2,
      '030000000000000000000000000000000000000000000000000000000000000001',
      '030000000000000000000000000000000000000000000000000000000000000002',
      '030000000000000000000000000000000000000000000000000000000000000003',
      3,
      'CHECKMULTISIG',
    ]
  );
  deepStrictEqual(
    hex.encode(
      btc.Script.encode([
        2,
        hex.decode('030000000000000000000000000000000000000000000000000000000000000001'),
        hex.decode('030000000000000000000000000000000000000000000000000000000000000002'),
        hex.decode('030000000000000000000000000000000000000000000000000000000000000003'),
        3,
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

  // OpNum
  const OpNumVectors = [
    [0, ''],
    [1, '01'],
    [-1, '81'],
    [-2, '82'],
    [127, '7f'],
    [128, '8000'],
    [-255, 'ff80'],
    [256, '0001'],
    [998, 'e603'],
    [32767, 'ff7f'],
    [-65536, '000081'],
    [16777215, 'ffffff00'],
    [2147483648, '0000008000'],
    [-4294967295, 'ffffffff80'],
    [1099511627776, '000000000001'],
    [1500, 'dc05'],
    [-1500, 'dc85'],
  ];
  for (const [num, exp] of OpNumVectors) {
    deepStrictEqual(hex.encode(btc.ScriptNum().encode(num)), exp, 'encode');
    deepStrictEqual(Number(btc.ScriptNum().decode(hex.decode(exp))), num, 'decode');
  }
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
  deepStrictEqual(btc.p2tr(undefined, btc.p2tr_pk(taproot)), {
    type: 'tr',
    address: 'bc1pfj6w68w3v2f4pkzesc9tsqfvy5znw5qgydwa832v3v83vjn76kdsmr4360',
    script: hex.decode('51204cb4ed1dd1629350d859860ab8012c2505375008235dd3c54c8b0f164a7ed59b'),
    tweakedPubkey: hex.decode('4cb4ed1dd1629350d859860ab8012c2505375008235dd3c54c8b0f164a7ed59b'),
    tapInternalKey: hex.decode('50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0'),
    tapMerkleRoot: hex.decode('96e43f98ce59a7302b2a0d4e50234d5645e59f0329f74d6a02aa8fab066b0fc4'),
    leaves: [
      {
        type: 'leaf',
        version: undefined,
        script: hex.decode('200101010101010101010101010101010101010101010101010101010101010101ac'),
        hash: hex.decode('96e43f98ce59a7302b2a0d4e50234d5645e59f0329f74d6a02aa8fab066b0fc4'),
        path: [],
        controlBlock: hex.decode(
          'c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0'
        ),
        tapInternalKey: undefined,
      },
    ],
    tapLeafScript: [
      [
        {
          version: 193,
          internalKey: hex.decode(
            '50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0'
          ),
          merklePath: [],
        },
        hex.decode('200101010101010101010101010101010101010101010101010101010101010101acc0'),
      ],
    ],
  });

  const tr = (t) => ({ type: t.type, script: t.script, address: t.address });
  deepStrictEqual(tr(btc.p2tr(undefined, [btc.p2tr_pk(taproot)])), {
    type: 'tr',
    address: 'bc1pfj6w68w3v2f4pkzesc9tsqfvy5znw5qgydwa832v3v83vjn76kdsmr4360',
    script: hex.decode('51204cb4ed1dd1629350d859860ab8012c2505375008235dd3c54c8b0f164a7ed59b'),
  });
  // 3 leaf list (p2tr will build binary tree itself)
  deepStrictEqual(
    tr(btc.p2tr(undefined, [btc.p2tr_pk(taproot), btc.p2tr_pk(taproot2), btc.p2tr_pk(taproot3)])),
    {
      type: 'tr',
      // weights for bitcoinjs-lib: [3,2,1]
      address: 'bc1pj2uvajyygyu2zw0rg0d6yxdsc920kzc5pamfgtlqepe30za922cqjjmkta',
      script: hex.decode('512092b8cec8844138a139e343dba219b0c154fb0b140f76942fe0c873178ba552b0'),
    }
  );
  // If scripts is already binary tree provided, it will be used as-is
  deepStrictEqual(
    tr(btc.p2tr(undefined, [btc.p2tr_pk(taproot2), [btc.p2tr_pk(taproot), btc.p2tr_pk(taproot3)]])),
    {
      type: 'tr',
      // default weights for bitcoinjs-lib
      address: 'bc1pvue6sk9efyvcvpzzqkg8at4qy2u67zj7rj5sfsy573m7alxavqjqucc26a',
      script: hex.decode('51206733a858b9491986044205907eaea022b9af0a5e1ca904c094f477eefcdd6024'),
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
  tx.addInput({ txid: new Uint8Array(32), index: 0 });
  deepStrictEqual(tx.inputs[0], {
    txid: new Uint8Array(32),
    index: 0,
    sequence: btc.DEFAULT_SEQUENCE,
  });
  const i2 = { txid: new Uint8Array(32), index: 0, sequence: 0 };
  tx.addInput(i2);
  // Sequence is 0
  deepStrictEqual(tx.inputs[1], {
    txid: new Uint8Array(32),
    index: 0,
    sequence: 0,
  });
  // Modification of internal input doesn't affect input
  tx.inputs[1].t = 5;
  deepStrictEqual(tx.inputs[1], { txid: new Uint8Array(32), index: 0, sequence: 0, t: 5 });
  deepStrictEqual(i2, { txid: new Uint8Array(32), index: 0, sequence: 0 });
  // Update basic value
  tx.updateInput(0, { index: 10 });
  deepStrictEqual(tx.inputs[0], {
    txid: new Uint8Array(32),
    index: 10,
    sequence: btc.DEFAULT_SEQUENCE,
  });
  // Add hex
  tx.addInput({
    txid: '0000000000000000000000000000000000000000000000000000000000000000',
    index: 0,
  });
  deepStrictEqual(tx.inputs[2], {
    txid: new Uint8Array(32),
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
    txid: new Uint8Array(32),
    index: 10,
    tapInternalKey: new Uint8Array(32).fill(1),
    bip32Derivation: [bip2, bip1, bip3],
    sequence: btc.DEFAULT_SEQUENCE,
  });
  tx.updateInput(0, { tapInternalKey: undefined });
  deepStrictEqual(tx.inputs[0], {
    txid: new Uint8Array(32),
    index: 10,
    bip32Derivation: [bip2, bip1, bip3],
    sequence: btc.DEFAULT_SEQUENCE,
  });
  // Delete KV
  tx.updateInput(0, { bip32Derivation: undefined });
  deepStrictEqual(tx.inputs[0], {
    txid: new Uint8Array(32),
    index: 10,
    sequence: btc.DEFAULT_SEQUENCE,
  });
  // Any other keys ignored
  tx.updateInput(0, { test: '1', b: 2 });
  deepStrictEqual(tx.inputs[0], {
    txid: new Uint8Array(32),
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
  throws(() => btc.p2tr(undefined, [btc.p2tr(taproot)]));
  // tr-tr_pk -> OK
  btc.p2tr(undefined, [btc.p2tr_pk(taproot)]);
  // Plain tr inside tr -> error
  throws(() => btc.p2tr(undefined, [btc.p2tr(taproot)]));
  // Nested script tree is not allowed
  throws(() => btc.p2tr(undefined, [btc.p2tr(taproot, btc.p2tr(taproot2))]));
  throws(() => btc.p2tr(undefined, btc.p2tr(undefined, btc.p2tr(taproot2))));
  throws(() => btc.p2tr(undefined, btc.p2ms(2, [compressed, compressed2, compressed3])));
  // No key && no tree
  throws(() => btc.p2tr(undefined, undefined));
  throws(() => btc.p2tr(undefined, btc.p2tr(btc.TAPROOT_UNSPENDABLE_KEY)));
  // Check taproot address generation against bitcoin-core
  const regtest = { bech32: 'bcrt', pubKeyHash: 0x6f, scriptHash: 0xc4 };
  const pubKey1 = hex.decode('989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f');
  const pubKey2 = hex.decode('f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661b');
  const pubKey3 = hex.decode('56b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967');
  // DESC tr(989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f)
  // ADDR ['bcrt1pw53jtgez0wf69n06fchp0ctk48620zdscnrj8heh86wykp9mv20q7vd3gm']
  deepStrictEqual(
    btc.p2tr(pubKey1, undefined, regtest).address,
    'bcrt1pw53jtgez0wf69n06fchp0ctk48620zdscnrj8heh86wykp9mv20q7vd3gm'
  );
  // DESC tr($H,pk(f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661b))
  // ADDR ['bcrt1pjepsmz8uq3y0e3levr2g2wpnw9f7rgrft223akntzp3c8e30e82qm397fa']
  deepStrictEqual(
    btc.p2tr(undefined, btc.p2tr_pk(pubKey2), regtest).address,
    'bcrt1pjepsmz8uq3y0e3levr2g2wpnw9f7rgrft223akntzp3c8e30e82qm397fa'
  );
  deepStrictEqual(
    btc.p2tr(undefined, [btc.p2tr_pk(pubKey2)], regtest).address,
    'bcrt1pjepsmz8uq3y0e3levr2g2wpnw9f7rgrft223akntzp3c8e30e82qm397fa'
  );
  // DESC tr(989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f,pk(f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661b))
  // ADDR ['bcrt1pqufcrewfzysl4xepy03508fl9hznt3t9j7q925zwwpf7qz9kr55sh9mdn4']
  deepStrictEqual(
    btc.p2tr(pubKey1, btc.p2tr_pk(pubKey2), regtest).address,
    'bcrt1pqufcrewfzysl4xepy03508fl9hznt3t9j7q925zwwpf7qz9kr55sh9mdn4'
  );
  deepStrictEqual(
    btc.p2tr(pubKey1, [btc.p2tr_pk(pubKey2)], regtest).address,
    'bcrt1pqufcrewfzysl4xepy03508fl9hznt3t9j7q925zwwpf7qz9kr55sh9mdn4'
  );
  // DESC tr($H,multi_a(2,989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f,f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661b,56b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967))
  // ADDR ['bcrt1pvj97rgc5flzt0kpdsly9aqsutsxp7ct2fwgtyzap4mtalh8gxe5sxaqm40']
  deepStrictEqual(
    btc.p2tr(undefined, btc.p2tr_ms(2, [pubKey1, pubKey2, pubKey3]), regtest).address,
    'bcrt1pvj97rgc5flzt0kpdsly9aqsutsxp7ct2fwgtyzap4mtalh8gxe5sxaqm40'
  );
  deepStrictEqual(
    btc.p2tr(undefined, [btc.p2tr_ms(2, [pubKey1, pubKey2, pubKey3])], regtest).address,
    'bcrt1pvj97rgc5flzt0kpdsly9aqsutsxp7ct2fwgtyzap4mtalh8gxe5sxaqm40'
  );
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

should('Big transaction regtest validation', () => {
  const regtest = { bech32: 'bcrt', pubKeyHash: 0x6f, scriptHash: 0xc4 };
  // - p2sh_p2pk
  // - p2wsh-p2pk
  // - p2sh-p2wsh-p2pk
  const privKey1 = hex.decode('0101010101010101010101010101010101010101010101010101010101010101');
  const privKey2 = hex.decode('0202020202020202020202020202020202020202020202020202020202020202');
  const privKey3 = hex.decode('0303030303030303030303030303030303030303030303030303030303030303');
  const privKey4 = hex.decode('0404040404040404040404040404040404040404040404040404040404040404');
  const privKey5 = hex.decode('0505050505050505050505050505050505050505050505050505050505050505');
  const privKey6 = hex.decode('0606060606060606060606060606060606060606060606060606060606060606');
  const privKey7 = hex.decode('0707070707070707070707070707070707070707070707070707070707070707');
  const privKey8 = hex.decode('0808080808080808080808080808080808080808080808080808080808080808');
  const privKey9 = hex.decode('0909090909090909090909090909090909090909090909090909090909090909');
  const privKey10 = hex.decode('0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a');

  const P1 = secp256k1.getPublicKey(privKey1, true);
  const P2 = secp256k1.getPublicKey(privKey2, true);
  const P3 = secp256k1.getPublicKey(privKey3, true);
  const P4 = secp256k1.getPublicKey(privKey4, true);
  const P5 = secp256k1.getPublicKey(privKey5, true);
  const P6 = secp256k1.getPublicKey(privKey6, true);
  const P7 = secp256k1.getPublicKey(privKey7, true);
  const P7S = secp256k1_schnorr.getPublicKey(privKey7);
  const P8S = secp256k1_schnorr.getPublicKey(privKey8);
  const P9S = secp256k1_schnorr.getPublicKey(privKey9);
  const P10S = secp256k1_schnorr.getPublicKey(privKey10);

  // TODO: btc.getPublic with types or something?
  const spend1_1 = btc.p2sh(btc.p2pk(P1), regtest);
  const spend1_2 = btc.p2wsh(btc.p2pk(P1), regtest);
  const spend1_3 = btc.p2sh(btc.p2wsh(btc.p2pk(P1)), regtest);
  // - p2sh-p2pkh
  // - p2wsh-p2pkh
  // - p2sh-p2wsh-p2pkh
  // - p2pkh
  const spend2_1 = btc.p2sh(btc.p2pkh(P2), regtest);
  const spend2_2 = btc.p2wsh(btc.p2pkh(P2), regtest);
  const spend2_3 = btc.p2sh(btc.p2wsh(btc.p2pkh(P2)), regtest);
  const spend2_4 = btc.p2pkh(P2, regtest);
  // - p2sh-p2wpkh
  // - p2wpkh
  const spend3_1 = btc.p2sh(btc.p2wpkh(P3), regtest);
  const spend3_2 = btc.p2wpkh(P3, regtest);
  // - p2sh-p2ms
  // - p2wsh-p2ms
  // - p2sh-p2wsh-p2ms

  const spend4_1 = btc.p2sh(btc.p2ms(2, [P4, P5, P6]), regtest);
  const spend4_2 = btc.p2wsh(btc.p2ms(2, [P4, P5, P6]), regtest);
  const spend4_3 = btc.p2sh(btc.p2wsh(btc.p2ms(2, [P4, P5, P6])), regtest);
  // Pattern
  const spend4_4 = btc.p2sh(btc.p2ms(1, [P4, P5, P6]), regtest);
  const spend4_5 = btc.p2sh(btc.p2ms(2, [P4, P5, P6]), regtest);
  const spend4_6 = btc.p2sh(btc.p2ms(2, [P4, P5, P6, P7]), regtest);

  // p2tr keysig
  // p2tr-p2tr_ns
  // p2tr-p2tr_ms
  // p2tr-p2tr
  const spend5_1 = btc.p2tr(P7S, undefined, regtest);
  const spend5_2 = btc.p2tr(undefined, [btc.p2tr_pk(P8S)], regtest);
  const spend5_3 = btc.p2tr(P7S, [btc.p2tr_pk(P8S)], regtest);
  const spend5_4 = btc.p2tr(undefined, btc.p2tr_ns(2, [P7S, P8S, P9S]), regtest);
  const spend5_5 = btc.p2tr(undefined, btc.p2tr_ms(2, [P7S, P8S, P9S]), regtest);
  const spend5_6 = btc.p2tr(undefined, btc.p2tr_ns(3, [P7S, P8S, P9S]), regtest);
  const spend5_7 = btc.p2tr(undefined, btc.p2tr_ms(3, [P7S, P8S, P9S]), regtest);
  // Pattern (ns)
  const spend5_8 = btc.p2tr(undefined, btc.p2tr_ns(1, [P7S, P8S, P9S]), regtest);
  const spend5_9 = btc.p2tr(undefined, btc.p2tr_ns(2, [P7S, P8S, P9S]), regtest);
  const spend5_10 = btc.p2tr(undefined, btc.p2tr_ns(2, [P7S, P8S, P9S, P10S]), regtest);
  // Pattern (ms)
  const spend5_11 = btc.p2tr(undefined, btc.p2tr_ms(1, [P7S, P8S, P9S]), regtest);
  const spend5_12 = btc.p2tr(undefined, btc.p2tr_ms(2, [P7S, P8S, P9S]), regtest);
  const spend5_13 = btc.p2tr(undefined, btc.p2tr_ms(2, [P7S, P8S, P9S, P10S]), regtest);

  const spends = [
    { spend: spend1_1, name: 'spend1_1', privKeys: [privKey1] },
    { spend: spend1_2, name: 'spend1_2', privKeys: [privKey1] },
    { spend: spend1_3, name: 'spend1_3', privKeys: [privKey1] },
    { spend: spend2_1, name: 'spend2_1', privKeys: [privKey2] },
    { spend: spend2_2, name: 'spend2_2', privKeys: [privKey2] },
    { spend: spend2_3, name: 'spend2_3', privKeys: [privKey2] },
    { spend: spend2_4, name: 'spend2_4', privKeys: [privKey2] }, // pkh
    { spend: spend3_1, name: 'spend3_1', privKeys: [privKey3] },
    { spend: spend3_2, name: 'spend3_2', privKeys: [privKey3] },
    { spend: spend4_1, name: 'spend4_1', privKeys: [privKey4, privKey5, privKey6] },
    { spend: spend4_2, name: 'spend4_2', privKeys: [privKey4, privKey5, privKey6] },
    { spend: spend4_3, name: 'spend4_3', privKeys: [privKey4, privKey5, privKey6] },
    // Pattern 1-3
    { spend: spend4_4, name: 'spend4_4', privKeys: [privKey4, privKey5, privKey6] },
    // 2 of 1-3
    { spend: spend4_4, name: 'spend4_4', privKeys: [privKey4, privKey5, privKey6] },
    { spend: spend4_4, name: 'spend4_4', privKeys: [privKey4, privKey6] },
    { spend: spend4_4, name: 'spend4_4', privKeys: [privKey5, privKey6] },
    // 1 of 1-3
    { spend: spend4_4, name: 'spend4_4', privKeys: [privKey4] },
    { spend: spend4_4, name: 'spend4_4', privKeys: [privKey5] },
    { spend: spend4_4, name: 'spend4_4', privKeys: [privKey6] },

    // Pattern 2-3
    { spend: spend4_5, name: 'spend4_5', privKeys: [privKey4, privKey5, privKey6] },
    // 2 of 2-3
    { spend: spend4_5, name: 'spend4_5', privKeys: [privKey4, privKey5] },
    { spend: spend4_5, name: 'spend4_5', privKeys: [privKey4, privKey6] },
    { spend: spend4_5, name: 'spend4_5', privKeys: [privKey5, privKey6] },
    // Pattern 2-4
    { spend: spend4_6, name: 'spend4_6', privKeys: [privKey4, privKey5, privKey6, privKey7] },
    // 3 of 2-4
    { spend: spend4_6, name: 'spend4_6', privKeys: [privKey4, privKey5, privKey6] },
    { spend: spend4_6, name: 'spend4_6', privKeys: [privKey4, privKey5, privKey7] },
    { spend: spend4_6, name: 'spend4_6', privKeys: [privKey4, privKey6, privKey7] },
    { spend: spend4_6, name: 'spend4_6', privKeys: [privKey5, privKey6, privKey7] },
    // 2 of 2-4
    { spend: spend4_6, name: 'spend4_6', privKeys: [privKey4, privKey5] },
    { spend: spend4_6, name: 'spend4_6', privKeys: [privKey4, privKey6] },
    { spend: spend4_6, name: 'spend4_6', privKeys: [privKey4, privKey7] },
    { spend: spend4_6, name: 'spend4_6', privKeys: [privKey5, privKey6] },
    { spend: spend4_6, name: 'spend4_6', privKeys: [privKey5, privKey7] },
    { spend: spend4_6, name: 'spend4_6', privKeys: [privKey6, privKey7] },
    // tr
    { spend: spend5_1, name: 'spend5_1', privKeys: [privKey7] },
    { spend: spend5_2, name: 'spend5_2', privKeys: [privKey8] },
    { spend: spend5_3, name: 'spend5_3', privKeys: [privKey7, privKey8] },
    { spend: spend5_4, name: 'spend5_4', privKeys: [privKey7, privKey8, privKey9] },
    { spend: spend5_5, name: 'spend5_5', privKeys: [privKey7, privKey8, privKey9] },
    { spend: spend5_6, name: 'spend5_6', privKeys: [privKey7, privKey8, privKey9] },
    { spend: spend5_7, name: 'spend5_7', privKeys: [privKey7, privKey8, privKey9] },
    // ns 1-3
    { spend: spend5_8, name: 'spend5_8', privKeys: [privKey7, privKey8, privKey9] },
    // 2-3 of 1-3
    { spend: spend5_8, name: 'spend5_8', privKeys: [privKey7, privKey8] },
    { spend: spend5_8, name: 'spend5_8', privKeys: [privKey7, privKey9] },
    { spend: spend5_8, name: 'spend5_8', privKeys: [privKey8, privKey9] },
    // 1-3 of 1-3
    { spend: spend5_8, name: 'spend5_8', privKeys: [privKey7] },
    { spend: spend5_8, name: 'spend5_8', privKeys: [privKey8] },
    { spend: spend5_8, name: 'spend5_8', privKeys: [privKey9] },
    // ns 2-3
    { spend: spend5_9, name: 'spend5_9', privKeys: [privKey7, privKey8, privKey9] },
    // 2-3 of 2-3
    { spend: spend5_9, name: 'spend5_9', privKeys: [privKey7, privKey8] },
    { spend: spend5_9, name: 'spend5_9', privKeys: [privKey7, privKey9] },
    { spend: spend5_9, name: 'spend5_9', privKeys: [privKey8, privKey9] },
    // ns 2-4
    { spend: spend5_10, name: 'spend5_10', privKeys: [privKey7, privKey8, privKey9, privKey10] },
    // 3 of 2-4
    { spend: spend5_10, name: 'spend5_10', privKeys: [privKey7, privKey8, privKey9] },
    { spend: spend5_10, name: 'spend5_10', privKeys: [privKey7, privKey8, privKey10] },
    { spend: spend5_10, name: 'spend5_10', privKeys: [privKey7, privKey9, privKey10] },
    { spend: spend5_10, name: 'spend5_10', privKeys: [privKey8, privKey9, privKey10] },
    // 2 of 2-4
    { spend: spend5_10, name: 'spend5_10', privKeys: [privKey7, privKey8] },
    { spend: spend5_10, name: 'spend5_10', privKeys: [privKey7, privKey9] },
    { spend: spend5_10, name: 'spend5_10', privKeys: [privKey7, privKey10] },
    { spend: spend5_10, name: 'spend5_10', privKeys: [privKey8, privKey9] },
    { spend: spend5_10, name: 'spend5_10', privKeys: [privKey8, privKey10] },
    { spend: spend5_10, name: 'spend5_10', privKeys: [privKey9, privKey10] },
    // ms 1-3
    { spend: spend5_11, name: 'spend5_11', privKeys: [privKey7, privKey8, privKey9] },
    // 2 of 1-3
    { spend: spend5_11, name: 'spend5_11', privKeys: [privKey7, privKey8] },
    { spend: spend5_11, name: 'spend5_11', privKeys: [privKey7, privKey9] },
    { spend: spend5_11, name: 'spend5_11', privKeys: [privKey8, privKey9] },
    // 1 of 1-3
    { spend: spend5_11, name: 'spend5_11', privKeys: [privKey7] },
    { spend: spend5_11, name: 'spend5_11', privKeys: [privKey8] },
    { spend: spend5_11, name: 'spend5_11', privKeys: [privKey9] },
    // ms 2-3
    { spend: spend5_12, name: 'spend5_12', privKeys: [privKey7, privKey8, privKey9] },
    // 2 of 2-3
    { spend: spend5_12, name: 'spend5_12', privKeys: [privKey7, privKey8] },
    { spend: spend5_12, name: 'spend5_12', privKeys: [privKey7, privKey9] },
    { spend: spend5_12, name: 'spend5_12', privKeys: [privKey8, privKey9] },
    // ms 2-4
    { spend: spend5_13, name: 'spend5_13', privKeys: [privKey7, privKey8, privKey9, privKey10] },
    // 3 of 2-4
    { spend: spend5_13, name: 'spend5_13', privKeys: [privKey7, privKey8, privKey9] },
    { spend: spend5_13, name: 'spend5_13', privKeys: [privKey7, privKey8, privKey10] },
    { spend: spend5_13, name: 'spend5_13', privKeys: [privKey7, privKey9, privKey10] },
    { spend: spend5_13, name: 'spend5_13', privKeys: [privKey8, privKey9, privKey10] },
    // 2 of 2-4
    { spend: spend5_13, name: 'spend5_13', privKeys: [privKey7, privKey8] },
    { spend: spend5_13, name: 'spend5_13', privKeys: [privKey7, privKey9] },
    { spend: spend5_13, name: 'spend5_13', privKeys: [privKey7, privKey10] },
    { spend: spend5_13, name: 'spend5_13', privKeys: [privKey8, privKey9] },
    { spend: spend5_13, name: 'spend5_13', privKeys: [privKey8, privKey10] },
    { spend: spend5_13, name: 'spend5_13', privKeys: [privKey9, privKey10] },
  ];
  deepStrictEqual(
    spends.map((i) => i.spend.address),
    [
      '2MtPBzgKuhnYGEk67u43QtTkJE9rq2xpLnV',
      'bcrt1q0g8nfnsvxzt8amgutgszrv0fxgwdn9yakprztj29sqzqhpw8gvuqfhcz2l',
      '2Mtz6MussbZf4cdxHqVgjf6Yz89Dun7iu8y',
      '2N8j9vCepAN1gvsRGpGRw8kxBCHMvkR4GYE',
      'bcrt1q3prrz6e0n55y6d0kkan6uejfyr94x3caq9r4qk8tzxudt6pmg9vqr57mqh',
      '2MsN3vZrKiA66NNUCJVmmKPWofS9xtBspZc',
      'n31WD8pkfAjg2APV78GnbDTdZb1QonBi5D',
      '2MspRgcQvaVN2RkpumN1X8GkzsE7BVTTb6y',
      'bcrt1qg975h6gdx5mryeac72h6lj2nzygugxhy5n57q2',
      '2N68GEkoEEECn3BYJRCBdTaZzfhx76eLSjb',
      'bcrt1q3tq3y634aaf4esr9dzx5n8py0p0tk6jfzt8rd6km4ytnwp84xpxq99d0c8',
      '2N3etLLQdEavwyfRZvgP8uKpS6JBF3MmV9W',
      '2MshuFeVGhXVdRv77UcJYvRBi2JyTNwgSR2',
      '2MshuFeVGhXVdRv77UcJYvRBi2JyTNwgSR2',
      '2MshuFeVGhXVdRv77UcJYvRBi2JyTNwgSR2',
      '2MshuFeVGhXVdRv77UcJYvRBi2JyTNwgSR2',
      '2MshuFeVGhXVdRv77UcJYvRBi2JyTNwgSR2',
      '2MshuFeVGhXVdRv77UcJYvRBi2JyTNwgSR2',
      '2MshuFeVGhXVdRv77UcJYvRBi2JyTNwgSR2',
      '2N68GEkoEEECn3BYJRCBdTaZzfhx76eLSjb',
      '2N68GEkoEEECn3BYJRCBdTaZzfhx76eLSjb',
      '2N68GEkoEEECn3BYJRCBdTaZzfhx76eLSjb',
      '2N68GEkoEEECn3BYJRCBdTaZzfhx76eLSjb',
      '2MvpbAgedBzJUBZWesDwdM7p3FEkBEwq3n3',
      '2MvpbAgedBzJUBZWesDwdM7p3FEkBEwq3n3',
      '2MvpbAgedBzJUBZWesDwdM7p3FEkBEwq3n3',
      '2MvpbAgedBzJUBZWesDwdM7p3FEkBEwq3n3',
      '2MvpbAgedBzJUBZWesDwdM7p3FEkBEwq3n3',
      '2MvpbAgedBzJUBZWesDwdM7p3FEkBEwq3n3',
      '2MvpbAgedBzJUBZWesDwdM7p3FEkBEwq3n3',
      '2MvpbAgedBzJUBZWesDwdM7p3FEkBEwq3n3',
      '2MvpbAgedBzJUBZWesDwdM7p3FEkBEwq3n3',
      '2MvpbAgedBzJUBZWesDwdM7p3FEkBEwq3n3',
      '2MvpbAgedBzJUBZWesDwdM7p3FEkBEwq3n3',
      'bcrt1pw53jtgez0wf69n06fchp0ctk48620zdscnrj8heh86wykp9mv20q7vd3gm',
      'bcrt1pjepsmz8uq3y0e3levr2g2wpnw9f7rgrft223akntzp3c8e30e82qm397fa',
      'bcrt1pqufcrewfzysl4xepy03508fl9hznt3t9j7q925zwwpf7qz9kr55sh9mdn4',
      'bcrt1pyze0lhtk4hmyq8xxxvkt73ae3y53wx2sktupajdp3zkfzlkwtlcsg5tp0g',
      'bcrt1pvj97rgc5flzt0kpdsly9aqsutsxp7ct2fwgtyzap4mtalh8gxe5sxaqm40',
      'bcrt1py0w7ln5kul2ac5cmtvs4534557y7qwf0nk04pytmnj34wk5u24eqdy2afr',
      'bcrt1pyyhymhfw6sg9xr0hl5ut4pj0cjgwwa8yqvvrve94t6m4ph6snaxqaphglf',
      'bcrt1pa2n64dga8jce6u5kp60f23jfrf85580pl7nv4d23qhuphjgvsc0szamdtn',
      'bcrt1pa2n64dga8jce6u5kp60f23jfrf85580pl7nv4d23qhuphjgvsc0szamdtn',
      'bcrt1pa2n64dga8jce6u5kp60f23jfrf85580pl7nv4d23qhuphjgvsc0szamdtn',
      'bcrt1pa2n64dga8jce6u5kp60f23jfrf85580pl7nv4d23qhuphjgvsc0szamdtn',
      'bcrt1pa2n64dga8jce6u5kp60f23jfrf85580pl7nv4d23qhuphjgvsc0szamdtn',
      'bcrt1pa2n64dga8jce6u5kp60f23jfrf85580pl7nv4d23qhuphjgvsc0szamdtn',
      'bcrt1pa2n64dga8jce6u5kp60f23jfrf85580pl7nv4d23qhuphjgvsc0szamdtn',
      'bcrt1pyze0lhtk4hmyq8xxxvkt73ae3y53wx2sktupajdp3zkfzlkwtlcsg5tp0g',
      'bcrt1pyze0lhtk4hmyq8xxxvkt73ae3y53wx2sktupajdp3zkfzlkwtlcsg5tp0g',
      'bcrt1pyze0lhtk4hmyq8xxxvkt73ae3y53wx2sktupajdp3zkfzlkwtlcsg5tp0g',
      'bcrt1pyze0lhtk4hmyq8xxxvkt73ae3y53wx2sktupajdp3zkfzlkwtlcsg5tp0g',
      'bcrt1pe3su7y00eqm4wg8lk70pxflwg860342tu9en33m7asxwmkxt6pcsa6h3xt',
      'bcrt1pe3su7y00eqm4wg8lk70pxflwg860342tu9en33m7asxwmkxt6pcsa6h3xt',
      'bcrt1pe3su7y00eqm4wg8lk70pxflwg860342tu9en33m7asxwmkxt6pcsa6h3xt',
      'bcrt1pe3su7y00eqm4wg8lk70pxflwg860342tu9en33m7asxwmkxt6pcsa6h3xt',
      'bcrt1pe3su7y00eqm4wg8lk70pxflwg860342tu9en33m7asxwmkxt6pcsa6h3xt',
      'bcrt1pe3su7y00eqm4wg8lk70pxflwg860342tu9en33m7asxwmkxt6pcsa6h3xt',
      'bcrt1pe3su7y00eqm4wg8lk70pxflwg860342tu9en33m7asxwmkxt6pcsa6h3xt',
      'bcrt1pe3su7y00eqm4wg8lk70pxflwg860342tu9en33m7asxwmkxt6pcsa6h3xt',
      'bcrt1pe3su7y00eqm4wg8lk70pxflwg860342tu9en33m7asxwmkxt6pcsa6h3xt',
      'bcrt1pe3su7y00eqm4wg8lk70pxflwg860342tu9en33m7asxwmkxt6pcsa6h3xt',
      'bcrt1pe3su7y00eqm4wg8lk70pxflwg860342tu9en33m7asxwmkxt6pcsa6h3xt',
      'bcrt1plxdxgx03v2cy0skec086qrnt0qrxxjszjgc2rfzs5t7hc40gtlwqp88ffs',
      'bcrt1plxdxgx03v2cy0skec086qrnt0qrxxjszjgc2rfzs5t7hc40gtlwqp88ffs',
      'bcrt1plxdxgx03v2cy0skec086qrnt0qrxxjszjgc2rfzs5t7hc40gtlwqp88ffs',
      'bcrt1plxdxgx03v2cy0skec086qrnt0qrxxjszjgc2rfzs5t7hc40gtlwqp88ffs',
      'bcrt1plxdxgx03v2cy0skec086qrnt0qrxxjszjgc2rfzs5t7hc40gtlwqp88ffs',
      'bcrt1plxdxgx03v2cy0skec086qrnt0qrxxjszjgc2rfzs5t7hc40gtlwqp88ffs',
      'bcrt1plxdxgx03v2cy0skec086qrnt0qrxxjszjgc2rfzs5t7hc40gtlwqp88ffs',
      'bcrt1pvj97rgc5flzt0kpdsly9aqsutsxp7ct2fwgtyzap4mtalh8gxe5sxaqm40',
      'bcrt1pvj97rgc5flzt0kpdsly9aqsutsxp7ct2fwgtyzap4mtalh8gxe5sxaqm40',
      'bcrt1pvj97rgc5flzt0kpdsly9aqsutsxp7ct2fwgtyzap4mtalh8gxe5sxaqm40',
      'bcrt1pvj97rgc5flzt0kpdsly9aqsutsxp7ct2fwgtyzap4mtalh8gxe5sxaqm40',
      'bcrt1pea3850rzre54e53eh7suwmrwc66un6nmu9npd7eqrhd6g4lh8uqsxcxln8',
      'bcrt1pea3850rzre54e53eh7suwmrwc66un6nmu9npd7eqrhd6g4lh8uqsxcxln8',
      'bcrt1pea3850rzre54e53eh7suwmrwc66un6nmu9npd7eqrhd6g4lh8uqsxcxln8',
      'bcrt1pea3850rzre54e53eh7suwmrwc66un6nmu9npd7eqrhd6g4lh8uqsxcxln8',
      'bcrt1pea3850rzre54e53eh7suwmrwc66un6nmu9npd7eqrhd6g4lh8uqsxcxln8',
      'bcrt1pea3850rzre54e53eh7suwmrwc66un6nmu9npd7eqrhd6g4lh8uqsxcxln8',
      'bcrt1pea3850rzre54e53eh7suwmrwc66un6nmu9npd7eqrhd6g4lh8uqsxcxln8',
      'bcrt1pea3850rzre54e53eh7suwmrwc66un6nmu9npd7eqrhd6g4lh8uqsxcxln8',
      'bcrt1pea3850rzre54e53eh7suwmrwc66un6nmu9npd7eqrhd6g4lh8uqsxcxln8',
      'bcrt1pea3850rzre54e53eh7suwmrwc66un6nmu9npd7eqrhd6g4lh8uqsxcxln8',
      'bcrt1pea3850rzre54e53eh7suwmrwc66un6nmu9npd7eqrhd6g4lh8uqsxcxln8',
    ]
  );
  const tx = new btc.Transaction({
    allowLegacyWitnessUtxo: true,
  });
  const enabled = [
    'spend1_1', // - p2sh-p2pk
    'spend1_2', // - p2wsh-p2pk
    'spend1_3', // - p2sh-p2wsh-p2pk
    'spend2_1', // - p2sh-p2pkh
    'spend2_2', // - p2wsh-p2pkh
    'spend2_3', // - p2sh-p2wsh-p2pkh
    'spend2_4', // - p2pkh
    'spend3_1', // - p2sh-p2wpkh
    'spend3_2', // - p2wpkh
    'spend4_1', // - p2sh-p2ms
    'spend4_2', // - p2wsh-p2ms
    'spend4_3', // - p2sh-p2wsh-p2ms
    'spend4_4', // ms(1-3)
    'spend4_5', // ms(2-3)
    'spend4_6', // ms(2-4)
    'spend5_1', // p2tr keysig
    'spend5_2', // tr(undefined, tr)
    'spend5_3', // tr(keysig, tr)
    'spend5_4', // p2tr-p2tr_ns(2)
    'spend5_5', // p2tr-p2tr_ms(2)
    'spend5_6', // p2tr-p2tr_ns(3)
    'spend5_7', // p2tr-p2tr_ms(3)
    'spend5_8', // tr-ns(1-3)
    'spend5_9', // tr-ns(2-3)
    'spend5_10', // tr-ns(2-4)
    'spend5_11', // tr-ms(1-3)
    'spend5_12', // tr-ms(2-3)
    'spend5_13', // tr-ms(2-4)
  ];

  const BTCamount = 10n ** 8n; // 1btc
  // Input
  const txid = hex.decode('0af50a00a22f74ece24c12cd667c290d3a35d48124a69f4082700589172a3aa2');

  let ts = Date.now();

  for (let index = 0; index < spends.length; index++) {
    const { spend, name } = spends[index];
    if (!enabled.includes(name)) continue;
    tx.addInput({
      ...spend,
      txid,
      index,
      witnessUtxo: { script: spend.script, amount: btc.Decimal.decode('1.5') },
    });
    //console.log('SPENDING', index, spend.address, btc.Decimal.encode(amount));
  }
  // console.log('ADD INPUTS', Date.now() - ts);
  ts = Date.now();
  // Output
  const privOut = hex.decode('0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e');
  // TODO: btc.getPublic with types or something?
  const pubOut = secp256k1.getPublicKey(privOut, true);
  const out = btc.p2wpkh(pubOut, regtest);
  deepStrictEqual(out.address, 'bcrt1q37eawpk6wtn39jxnnmat0ggf85f0h6mtuhxxu3');
  tx.addOutputAddress(out.address, BigInt(enabled.length) * BTCamount, regtest);
  // Sign inputs
  for (let index = 0, idx = 0; index < spends.length; index++) {
    const { name, privKeys } = spends[index];
    if (!enabled.includes(name)) continue;
    for (const p of privKeys) tx.signIdx(p, idx, undefined, new Uint8Array(32));
    idx++;
  }
  // console.log('SIGN', Date.now() - ts);
  ts = Date.now();
  tx.finalize();
  // console.log('FINALIZE', Date.now() - ts);
  ts = Date.now();

  const txHex = hex.encode(tx.extract());
  // console.log('EXTRACT', Date.now() - ts);
  /*
  This is verified against bitcoin regtest via functional tests:
  - test/_create_tx_for_regnet.js <- creates funding tx
    (bitcoin cannot create tx with multiple outputs to same address)
  - test/test_noble.py <- verifies this tx to be working
  NOTE: this assert should not fail OR at least be re-tested on any changes
  */
  deepStrictEqual(
    txHex,
    '02000000000155a23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a000000006c47304402207bf1d5cd0c25dfd71b14b24e330e2bf007e2dfcf7e6860135285e3f00f3a2deb0220628e226cfe48591670e30bee27fd87157f97348c00a6d45cb65080e33c00c895012321031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078facffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a0100000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a02000000232200207a0f34ce0c30967eed1c5a2021b1e9321cd9949db04625c94580040b85c74338ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a0300000085483045022100c5e2eb6bdc4660b0129db78e3c8081e6a8c80ae432e75cbca57f4bc070473740022072825c24ea0f1837491d81db65f69a8d3c2773d36944628aa149875ae6b7342c0121024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d07661976a914ebc0ee0b2ab9e8277a600c251475e22a3241a1c188acffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a0400000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a05000000232200208846316b2f9d284d35f6b767ae664920cb53471d01475058eb11b8d5e83b4158ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a060000006a4730440220234e36aa681a2f67364e3c3ed1adab26dc503e076067ae5d13589305064a25a1022064efeb6d084b4d5e752755cf845028490741ccf368d4968c73f35841531d3e250121024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a0700000017160014417d4be90d35363267b8f2afafc9531111c41ae4ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a0800000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a09000000fdfe0000483045022100dee3c8afbb22595ce2c764731012760f980e988db84b1e7751484f70984f105b02204ab91c11db2e564959406b51bd0d04316e49f647451444608466d652bbec76d201483045022100ff52b59f7adc811f1b0d31ca58aa6840326f99dec74e8f4b261c266b6c45aae9022000d1bc7fc707f4d7c8d5a19963d4ad9395b076cbd8dc246c5ad4fc4b6d449f88014c69522103462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b210362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f72103f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a53aeffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a0a00000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a0b000000232200208ac1126a35ef535cc065688d499c24785ebb6a4912ce36eadba9173704f5304cffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a0c000000b400473044022053a51f15699d9c620e92a7f26c24bbaa7d43696172450e8277eea453edc10bd802202b92ee8a6581f3b3727d42a11ea31eab2a48eb1810949d9565d740842e8644ed014c69512103462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b210362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f72103f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a53aeffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a0d000000b400473044022049f9859a6cc67b0cce6c68fec859819781172127b8e662c2ff17ee68d869e90302204c233a36fe72cc710ffcbf1659ef845d6b68f6921e6cd512cd72120f88800e0c014c69512103462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b210362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f72103f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a53aeffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a0e000000b40047304402204e24d5b602ad8e7f6660bf82dc880fe6a8a7992c8ae061d2a9744f31fdcdef9c022053f2aff717379fd5ba5f54338b8dc13e16449ade5353d7573191b817213c0487014c69512103462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b210362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f72103f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a53aeffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a0f000000b500483045022100dc795e28662a13909cd773a73b18343feb84b3a6991c5d06f3553aaff7010efe02200a7ec500cabc81168633d41c56d8052936c98dcd2c84b0e1b88614a3e441a708014c69512103462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b210362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f72103f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a53aeffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a10000000b500483045022100e784deb29889fb1f1417ac7361aa5943613b7818fea67180fad9a017e09b976002201b271e5cce6abe9e92eb166ea2b118d129f038f00333d00c0044ace82582e365014c69512103462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b210362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f72103f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a53aeffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a11000000b5004830450221009aefead0c111b2737564c2a368e143a94b6551a7a31ad309b5b85d11655f33b302203ec12c31aa4cd09e57272876e1a2e0f21f47565b72e8bc806431607264823e89014c69512103462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b210362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f72103f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a53aeffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a12000000b40047304402201ee006ac402dbb9b0b117b97fc68b57acb1ffadcc7461f43bddfc0f3f43df35c022062e864519570a55b6ce8e3b0f8e24a9d0ebf6b3c308b1770ffec6b40a8dc8c4b014c69512103462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b210362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f72103f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a53aeffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a13000000fdfe0000483045022100886461373580f5c68b7c0114d078d72fba3cb59ae8f017dfba95b7921882bfd102207f24b024fe6ffbee977144d1419ebbcf1aabc558f071d8b5e37f7823cc82fa1d014830450221008ae86343ab1312069e5baa6e272df39141f391d78dc348596d688374d79960c4022075ed7bee6c46510388f07656fd42f12ba020a19d97bd1e46b6580bfc7aca2e10014c69522103462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b210362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f72103f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a53aeffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a14000000fdfd0000483045022100aefbe15294c42e1f07450b7608b4f9d791edb44267f7b1be52d14bc1d657270502206214ba8ae283e1d2080e7e324f246c20a8ca170c8766ae5add882993dfc4f0610147304402203d068b2f59cd280a257a2128c083cb3fa346027ec9004fb1274d68ee2eedf397022066ffdf0db2eef3a008ed881bc4690d08cdafaa9a537d51822c7d289f9797b8c0014c69522103462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b210362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f72103f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a53aeffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a15000000fc004730440220249c1b01235113fff90a7844a427cd2a7003fc6095f9c4b50c2d84eefaf742f902204b42e24d4a2538434c3696d3ff4798b5c6a3804e1439afeb1a09a3772d06e5c001473044022076b542eef85d5f6d8f522de5c49dd82b1af644624da0b580cc5faa91e812ef5b02207d7d3cf4323cebbf0a2b1259bfc286502d54d8ee98c79099b481713c132bf258014c69522103462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b210362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f72103f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a53aeffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a16000000fdfd000047304402201b1d91a3eb65478f5a2344208d71676ed81491e4c033be7332d2c8975ccabe7502204719d7788e82054c5f26f9f351118c84a077365fa0aeeb5b786811223e083e5701483045022100cee5aeda1c98131e098da8bf8b277316024ae91ffe2d45bcfd25125fdb6741a202203c084db9e429bbe2cf4b87e1d85e69d194b0c52c46f53e05a6938c813aea22d2014c69522103462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b210362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f72103f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a53aeffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a17000000fd1e010047304402200c4e80234fa76d24d682fa8e924322b11c90138512945326e996d11ea427c29f02205f3dad2bd5e233a2e762f6b7b5cce0257789fc0cb75846f5df0abe53f6f901700147304402205247a6843b95ce42438535e939c1ff59ec9adebc95c4a9458a15f89a78bd392b022074aebc07d7b80e500879a359185347e09820b3692407c243762b1aa827a00760014c8b522103462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b210362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f72103f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a2102989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f54aeffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a18000000fd1f01004730440220650195cff7779c75b5e089c4d4f5c8b107b90d4c3eb60bf121a514b8d828cf4d022061cd504caf41c5f389b0e850881788363bffd333a8cc72a8bba47f10cb071ce001483045022100c0d29c7fdb0a9baecb0a016d909e2053f7f05ced4ecfea97ac4807d938b8d441022079fc0d3a143cebe2a9a553042b7c2f1bce1b8b0724b825e4d0c17360fbd16b91014c8b522103462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b210362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f72103f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a2102989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f54aeffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a19000000fd1f0100483045022100c2cfe82eb36f0cf9185ba4dd61351f53d084cb6b7dd8128ede1c39398b9998bd0220306603c57eeb4ff40f7d27a749d64548ecdc0c6eb881e29eafd5d08ba08c4e850147304402203353f4559937d9e039dc5f28b91e64ad0d74d9b3b64c7cf957f927b5cfd7e4d802203528372471bc35c5124eff5d6643ca677a0ffa54ab9b75f66853da3acccf1973014c8b522103462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b210362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f72103f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a2102989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f54aeffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a1a000000fd1e010047304402202195e261e4299e7c9864869b4289aaa818445e0c523f6cf94ef97dd680c4e327022067c24fd58ada9d9b271d56f5db34107096d0e83984ffe9a3f0c798e96a8ebea90147304402205f9c7c92e6faf332915c1a643fea6a87e3940d5d43259060684e382ca7de843a0220665a94c6520f1b10a5bd3fea24fe929f80d18367ab4b9317386c331b31d61ee5014c8b522103462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b210362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f72103f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a2102989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f54aeffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a1b000000fd1f0100483045022100f39c05aa5e3edf119a6bb74cad8635a6044121e84cc861b786a4b8d85218fa0802206e06b5767a7f3f58010ae6d630a1e834ffa50bd06cb2a18350c8bc010010fb200147304402201df5fafd6256e170ab24f4f87b6b0babc9614c646180a1041f1f836ba528c7e0022023fc59c1b0f9626b7d4284345bdd25574708bcb8b3074e8f2bc5068bae5cb324014c8b522103462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b210362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f72103f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a2102989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f54aeffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a1c000000fd1f0100483045022100d46fbf64d8bb597d91a009e18a5b96d746c7ed3df3d75069dc0b258bd37fc331022063f7734c374d32cab9c27a9d221dbdfee0e8f00dda772e5b167ae907ac03fae50147304402205fb119a6d4bed2387ecca5031abfb4bdb8a06e7a47bf37996b705f7a17d187d3022075d395750531ab2e7d64b4eed7b46cfcbe605bfbc774372bf3763de8ce42df48014c8b522103462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b210362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f72103f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a2102989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f54aeffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a1d000000fd1f0100483045022100b28c5c30b6e0762890c33107c3841dc3a242f79928ffd58570dc0eebc105a63702200541285a4f1e28a5cc544ba0ab371527248db101c7124da0f7439dcdb705c33d01473044022034e7ff15859a18f0bc407022fa57d4e3c606d63098fd3c62455b3dc432958e680220338ef0cad1e37fe9c1b63deb2326d7799910d2419f8fa7beca3a7e137a85227b014c8b522103462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b210362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f72103f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a2102989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f54aeffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a1e000000fd1f0100483045022100fdcaa3cf754ef150178410f84952c32d63150ac8d6fe8409920dfd7897e8ea4a02207155ccd124efb33fe25822c01261b8c6347e954e8605c0f2e034004c20f01d8d0147304402205672303e5e3eeffadd15948057ec0ef13f97247e88d0fc7d4062f444115359c202205870d7bc9b94dc3ae088baf5cabd2401a037f335750312651baf3768befd01eb014c8b522103462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b210362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f72103f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a2102989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f54aeffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a1f000000fd1f0100473044022036089817bd12cccd7bffd5d9433f735f838c37090d9b23f97507af2da9eb00b502202ed3d3261269f1ec1d84e6d68f4f9263b84b33596dfbe6b5e7acdc1b228b45cd014830450221008e1ad77c310d8a742209831fe8fb9f3edf2b8b8dcefdd35d3f8276f8e5e282f40220144f6083047387f115ab97b25ec2500ead41c172a5b2857e4d1e0ba20624f47d014c8b522103462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b210362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f72103f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a2102989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f54aeffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a20000000fd1e010047304402200df98b7b46241db092763f1db3e938f603b8950cc6688b14cdbdaa60c0c09c60022064f948998d6a6ad1485bb969c423ddfd3fa672011939adcbf94472ae8c3da0280147304402205df2362180200174d40a9fd544f82450e9423ef1dd507dab566a6dc59764baf402207724d41d7fcd0b75ba03bd8b9d8b75d0d3119c3cdf184d3a90ab804637735f6b014c8b522103462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b210362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f72103f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a2102989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f54aeffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a21000000fd1f0100483045022100f64a083d08ce200bb6fe51edd037165f1ae4faad8cf235b7e9fdd86bfb8ae3f502205811e5aa40377b629e3289c921c497478dde6479ab9b82503643173460177c730147304402205dca1eb3356930a7c3fef149687e9731ec2ef67786b3683cc1834dfaef7eb07c02201be3c6cde941f5d8a81ed8012c7d84bf5d769896d7fefdaa1e4c46b3cf49a78d014c8b522103462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b210362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f72103f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a2102989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f54aeffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a2200000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a2300000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a2400000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a2500000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a2600000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a2700000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a2800000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a2900000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a2a00000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a2b00000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a2c00000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a2d00000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a2e00000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a2f00000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a3000000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a3100000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a3200000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a3300000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a3400000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a3500000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a3600000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a3700000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a3800000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a3900000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a3a00000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a3b00000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a3c00000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a3d00000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a3e00000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a3f00000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a4000000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a4100000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a4200000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a4300000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a4400000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a4500000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a4600000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a4700000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a4800000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a4900000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a4a00000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a4b00000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a4c00000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a4d00000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a4e00000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a4f00000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a5000000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a5100000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a5200000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a5300000000ffffffffa23a2a1789057082409fa62481d4353a0d297c66cd124ce2ec742fa2000af50a5400000000ffffffff01009ce4a6000000001600148fb3d706da72e712c8d39efab7a1093d12fbeb6b0002473044022022fa3757b31481bfe77e676e8bc12b56b47ed21d5915380b4a542e70043fef8a0220299273cf866bf6be7abbfddfac13c44d90eb99ef8129d711b01e115d6e80a35f012321031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078fac02483045022100af82740d89b6f64c9308f7bc4173c373945d1a897966b48c2760b8fc79f31dd8022034167afeb9a692c3afb2106b07fcb2e79af2c9812fc31ef67d175cf9b0fe716f012321031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078fac0003483045022100934c14cc283e457e7737a7d47589e2deb300ed318fb9c49af6051e9e6546ed9302206e14bbd890b6e0b7b56166531e42f3e2cf6cc3172c2b07d7f1296b98738add390121024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d07661976a914ebc0ee0b2ab9e8277a600c251475e22a3241a1c188ac0348304502210092acd529b0289329f16000091e2c9097ae484fa774f723fa7641a2d4ca416e3202207bbf1676ce2d632fcf930d0be354f28b2fb3cf42343dde64d4007ac057f105ad0121024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d07661976a914ebc0ee0b2ab9e8277a600c251475e22a3241a1c188ac000247304402205bcd041e07cd41398203878b5c215fbcaba024ce45bd6c4236eb1901d06fe37502204f160980c137f991da2d14bd5ccb71ff3a528098bc23f93fab0388386bc0ef42012102531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe33702483045022100b0837aca16038de9c200a3bdc4895fe59adc6b9624c2e473828a88f71a4f480c02202669857e383918571c35944b1af63aeb8269eed1c6f1b901a83cd488bcaee39e012102531fe6068134503d2723133227c867ac8fa6c83c537e9a44c3c5bdbdcb1fe337000400483045022100a81de59f4023846fbb38b958d29f259a9885c31c6db44052d913e1997ad182dc022037a2f8700c7cdf514b782dd8f4499cf1f3415913f6f027996696cd02336e768f01483045022100f4d8050bfc9eac98647a46ed7b019305708d2ccc734c74ad589ce37d07fe9b270220684fef4b465fbdfadb73b2b15662ca4f98a40e26d5eb84dd4383ec1fa0bfc14d0169522103462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b210362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f72103f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a53ae0400473044022014b6f8b1bec7c5a11f15237930e2a6e95219692161565f6b16e7abdcb22dfa20022025fd5df0287bfbb85c564449dc79345b44c1063070bd04a708a9f9ab528b85470147304402205669e2488035e0ea37eb62e4e3ea4999237025aa3d8c478ed42a7b296a78ce4e02207b7b62aee4b17bae531988089da49b75f3678a73705393d38e96684369c79f000169522103462779ad4aad39514614751a71085f2f10e1c7a593e4e030efb5b8721ce55b0b210362c0a046dacce86ddd0343c6d3c7c79c2208ba0d9c9cf24a6d046d21d21f90f72103f006a18d5653c4edf5391ff23a61f03ff83d237e880ee61187fa9f379a028e0a53ae000000000000000000000000000000000000000000000140aa19278f25d1e6a774c49cbb04421691f0833d124dd6a0ebd1172f432925d6292d2f90073f0309205aa2cab09cbb17d32bd3a093fad92d46c3534ced20dbbc06034006d5bf03e0d6d6a3e0a731e51ba3d6b8cfd8ec264545e438e89d423157417cb18ddea2dad0e5cfaea2a5305ce5998ef84cb3d0244a37ded8f12f69eb192c97632220f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bac21c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac00140d5e5f69f7466d0e0fb1a02e9efa0fe80480389dfe150f04a2f0ddfaac25c61c2bb7ae016b7c2b41be86e23abd7c32d7de5c55996fcedd3819fa0cd99b46a37e9044087e7a5df78e6d68011163fa200bf7d12865874d25af5b96cb6ad1d16a7774cb91598b92aee288c882176b08e55b7497c0ce656dc4cfc515552dcfa84af2adf3a40c6baf65f292148181ab4f9c772553d7782434aa52cc8c3eeb8055c4311b382bf98f1629296b90ecd3155df0c7b9d196fc7b5468196ddc45383ba78311e94222d4420989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fad20f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bac41c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0735906e20bf1d1c2b7235833f3183185349b57f52db72096b9ad4404a82fa5520500405e5d38d6b93f2595ad256ce1d502e0ad96bb3e9cc341ff4cf67960d324281036dfd5cec76fc16fb510d2de1436dc12f4a289ebe52250779aba343860d8165220400933addf3373f56ed909a29ac17898d9d62676c98e8539eeaef66c61535c9e8416b2e7fcc6312bd20b1512ea63019c1559b1b4164d3a4d4502c067cf836828786820989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fac20f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bba2056b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967ba529c21c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0054045ddb54a4067143f2e81d85a1fbd5cafabae3189c0b52a3a1889ede6b9097784426ddef3fea397fce4ed6982031f4275649c62c13f5a9eaba31d1b6cee730f6a40f26fb1ae4a92f2d99d5143a424f49146ef52f9a0ad09c2336070cf20afddeb526283b320b2c3b8aeff6ccf841a3f3243790dacc116d3e1d66ffb5b2567a52c384098c791750618378a80ada6d3359ac5a094887aab4c0306fdba010c47708f30b179dec67ed7aec6434f856265e1e23a1b07432fa734c486f1f24afa3f79bd08e66620989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fad20f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bad2056b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967ac21c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0054023c1439f22313fe366ae0bf7d08c2e90ea5491f71b06e109af4a774c271bf4fca0fdf8c4c56eb66e691310e790d01d87eccea45bed947685d46725735edfd76040201e34c8615de725f8dbacb91cb6cd5529857b26736c1fcce429d66729e0a79d611c16fd718e69abe0c47c0c4d01e72939c4634961d698f6862d744d74c5b32b401b1a08175e5b77bb2dfdc183535cb3b514b701bdea719e48f943f4c4b3a73444fd45d3e9d466f9ee6eaa7d01b87612a3a3a48cf659e826e286a01eb84f50659a6820989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fac20f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bba2056b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967ba539c21c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0034069dfc34e423df254d6d3bcd55ada4864cda1e91216c0470e3c16436e69227773fa6e8ba26f32e1a8295af86f975d8ad5bdd33d3be3e498115a2790dc845ef8c22220989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fac41c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac093ed8ee7f6f9417fa098ddffbe0e40d1327660e99d259e210918a078af20f694034031e500485bd0a707bf6b7506e8930bbb231276bf7edea9a9b379adaf9172413b3883ef8b721d302f8561b4ea8785a5a4a269328e52b7e9036e27333051af285d2220989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fac41c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac093ed8ee7f6f9417fa098ddffbe0e40d1327660e99d259e210918a078af20f6940340a42a550372a3f2ba4fcb19c0bf2c8c8791e9782464e7d7731e87c87984f7347b3a331cb2ec07b14693d360019067fca85878123fcab6c6011890774d6604c1452220989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fac41c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac093ed8ee7f6f9417fa098ddffbe0e40d1327660e99d259e210918a078af20f69403402a3887b1a8535270c201fd0be937809faab85c48d2d5c334f8b8108e7fafd1150770337f08f2f18014976be732c73b1f246a6b1c0759536ec5c8043b1a63b2652220f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bac61c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac09c22b2ecad94f8f461494b644c31e2f77d4895f7dbdab249249f51e3d7834db4fa7263102846c4ab1cc894d24d162f871cce774ab1a44537bdb8790225c5d852034002e526f98c68924ee089d7b8de8cd8dad4e0a07b447ae440a01f70a32639163daddcddbb23182d47793e88d4416eb214c9d633095ba6fc8365018d36bcbb18342220989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fac41c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac093ed8ee7f6f9417fa098ddffbe0e40d1327660e99d259e210918a078af20f6940340d402dc7eeaf78feb4e8eaef9eb72b1a3500f98feb56a9254fab90c53f04bd3ab3d51ff7b62d5646a2af68a8b256ef754487e3d4dfcb86a187e8be44c4681f83f2220f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bac61c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac09c22b2ecad94f8f461494b644c31e2f77d4895f7dbdab249249f51e3d7834db4fa7263102846c4ab1cc894d24d162f871cce774ab1a44537bdb8790225c5d8520340a176b3236628ec0440182336ebf67eea1d09dcdb73acf87aac5e83a8091a22a88e80fd68922898ccd21fe8c70caa760d9624165597227970e8cb19db22cce3e2222056b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967ac61c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0b08c3ecb40b880e1634037e1673fc81a3a572706a409eb2a328bfb9e74fe2526fa7263102846c4ab1cc894d24d162f871cce774ab1a44537bdb8790225c5d8520440c86767ad2878e670b1e669313ea14eababe7ff64dd4dd7866885ae14053b276910d69e600480e94c477dad3bf0cc13f93967c4541b85a3b737795561f6017096401f3c44e4682a4abdcc1bb091ce93d2f9e5d375cf2995ebf1e5fafbd6dfea37f4c8ea504c6433e189743befe13f71b4b401b1ab1a38e9ed3f1757ce4def9827c44420989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fad20f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bac41c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0735906e20bf1d1c2b7235833f3183185349b57f52db72096b9ad4404a82fa55204403c6dc78dc42226c8417cddeaebb480d46d4484cead945a0f14d83fe36caddc3b45c47fc08e35f37c64976ea24ab06e60bcd0abaa811cf4f3b29ef692f208b46d401832ba037fadb830432a55e8e5a1bc9eecb8d5d477eeae66fb446eee3926d266af5385bfa02b531c51fc3fc6fed9aaba176ec8317571e3f9f9108c037247d15a4420989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fad20f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bac41c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0735906e20bf1d1c2b7235833f3183185349b57f52db72096b9ad4404a82fa5520440b08646b5b6fd0f2a023048e2c5fc768ecba8c1092daca39394ae08fac57936e80113fac027a9a976ce5847e72d7bb235508386716b27a7c243b125976615fb4f400f895411f8275e5151d1f3645ac49e26e537caa34a80f7632d13e7ff69ed7c6e8135e8f6c3e282639a754ba800ec418ba77f14b22027dc53fae919e5486b6fdb4420989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fad2056b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967ac61c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac021bc3c0aa46aae0e9645cda5bd2ce2bb2439834b28630081f614e9889c643ce277edc213f6636c9b05d7ee61f9e2479bb65fe6324e4168268e3857b616da7346044050bb15a40bfa60d3a9f66982bbc1705d6ff8997b54c65e73c7087c46877356e5277a5cf055ba7a9b62feb85eb58629e3c837ead6db83d8590dbacde6e124e69240bb5338064f0b68c280be396910a197b5f458a8e9026d034b9e0a9c7b12fa412e6defb954e6a0c567870778ab892c3425481b082b2240c5e70c2ab93f403340984420f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bad2056b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967ac61c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0e9cb200c28fbdb784258fe8e791c232bd363c6389d9c49dbb51bea776c02c68b77edc213f6636c9b05d7ee61f9e2479bb65fe6324e4168268e3857b616da73460440a92ccd6213e651dc08d5b1c53b62cdab7bef13e32c133c403217ae7b020c9719c2ed78bee806ae8de176f39f123ce70416f2eea98393fde423b590f9c4f4c34a400fe392079a3cf4864651d4d3f37930a7634acf037c3a0edddad845e3bf68b0359fb736947a1249867b46c54d0f61bca69ec538b365104d3850f66362384833a54420f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bad20f76a39d05686e34a4420897e359371836145dd3973e3982568b60f8433adde6eac61c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0710b2a8bcf8e0d73c68a452f1c3b5df186ee6e5f4a3b8ceb38d97a0a03f81d9e525a492d39d483bda14091454f2da78aecd76c6b8b8d5af821c231c0bc2cc96b044001741bbc19fade7e67038b250e8b1f2a0ac888a7007a999dcc495d00411336495eb4406877ddf33ae883d78c04a22347053aac74ee1962897b3d67bbf92bebf040da85dec1b3bff660bb3640baf21094ac43c4909940104e76c08456874a3360af683da91edf17f8a29763dd6e2ad0463a4bece3453d3f2559cc132868113638564420f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bad2056b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967ac81c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0fab6872a6472f720348abd5ee60dfe41980da33e7968f6d3ccddedc589e2c29b853a2daa2bac0f787716aca1fafb177298c909c23c64944399d108f9546269f2d2272618f71062f94e7afa4ccc8073dc4dca3d878f6582af5e52ecab01a118880440ab21a7cd5e2721b227c53d323ef57b831bd679c0ba016d1e34bf0d7f1e35fed1ddba86a6c426e2af4dda6107469d8f23e95266c81928786e40d5155dddfe385d40be006ee09127ff9dfc745d1bec701c599a00d1841a7d3a3d5f37cb84e72de229066c1f48c52c74e4c380c0aaaac240ae9b28c845e5a7e79bcb3cb0ee5843b4eb4420f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bad20f76a39d05686e34a4420897e359371836145dd3973e3982568b60f8433adde6eac61c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0710b2a8bcf8e0d73c68a452f1c3b5df186ee6e5f4a3b8ceb38d97a0a03f81d9e525a492d39d483bda14091454f2da78aecd76c6b8b8d5af821c231c0bc2cc96b0440d4524b8bc2b164e064fc93485e4ab6b0605f1eab06c3339e669541f857a40f91a8103e5cd3c381834f8fa31d5833f6458862858593da62a7987bbd1e6161c13d40fd2058b7ef892f1e9d0ff02cc5ce7971003ebb6813b7008b0071f5148285363fcd6d0f7150d9b3af9234ca2f371f9ad5dc240b75058b86acbfdba504175f1bee442056b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967ad20f76a39d05686e34a4420897e359371836145dd3973e3982568b60f8433adde6eac61c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0234ca28869178771c3fbe3e24b88ae2b39a3d732a09c37753fe34009502bc624525a492d39d483bda14091454f2da78aecd76c6b8b8d5af821c231c0bc2cc96b0440ca86972ae29e8c979279625ff5471846a8b9aa22a413015129113d12e92b4bcf93adde442dc6ceb13f9087b9b61e7dd551ec91eb3c93bd4cf6709f5f925019bf404cab704dec9aec7c72c1ce6542c7734c777d95928bbc67cbb6f702d35265d1ccc491739d60ee173812c34d1de5602a708d6b5b3e75626fa0521f51b6a1308a634420f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bad20f76a39d05686e34a4420897e359371836145dd3973e3982568b60f8433adde6eac61c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0710b2a8bcf8e0d73c68a452f1c3b5df186ee6e5f4a3b8ceb38d97a0a03f81d9e525a492d39d483bda14091454f2da78aecd76c6b8b8d5af821c231c0bc2cc96b04404d02f3369c3e0e707638e3327df318050a7fa5a7f74144650cb33921bc10e69ba4957c7967ef6af9aed39930b126f5e44f245a480b4f319fa37a47878cbc0c0140b88445ce06bc9622abefa92cd74abf86df6b1e5e13c7d63865b869555708a65d1405b8f82853c55505e3a488c9f3bcc6c79f00bf6fba5d8c136b03d31545a5d04420989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fad20f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bac81c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0e9cb200c28fbdb784258fe8e791c232bd363c6389d9c49dbb51bea776c02c68bb695e809f89ca1e63e5874dccc718f7a7e6969495cc3b200e2029a7dfb5a2a44d2272618f71062f94e7afa4ccc8073dc4dca3d878f6582af5e52ecab01a118880440c4d8ca54e387f4bcacfab5483941baaa566676c356e2cb490c1160feab2f659127fe22b48811e9eabcc6b8c3c3435c5b321d8d56fca5da7c3eacf38ebfd0ee1b400a045d96f0a3154ac142eccf0537976d5def6a56f4e3de79f5e03a889fa3a280e55e84dac9eb2673ae3c070c78156efc9c8a1fb481124f85c8734170a5febb8e4420989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fad2056b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967ac81c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac077edc213f6636c9b05d7ee61f9e2479bb65fe6324e4168268e3857b616da7346b695e809f89ca1e63e5874dccc718f7a7e6969495cc3b200e2029a7dfb5a2a44d2272618f71062f94e7afa4ccc8073dc4dca3d878f6582af5e52ecab01a118880440d127fd24d9152da8cce54bddc365a420a9ab9ab9b68ee4d7f3022e2d6d9c230273403c0ef4b0f6f693f45037462bec8490fa746e232d4220dd08149e22d2d85a408280fdf565123e517219399804e25aef8912769d58633731241295c0cf7215766c0355bd8dbce702ff80a0b8b6f702ae94f760e2fe0ebdd16837ee8884446b734420989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fad20f76a39d05686e34a4420897e359371836145dd3973e3982568b60f8433adde6eac81c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac021bc3c0aa46aae0e9645cda5bd2ce2bb2439834b28630081f614e9889c643ce2853a2daa2bac0f787716aca1fafb177298c909c23c64944399d108f9546269f2d2272618f71062f94e7afa4ccc8073dc4dca3d878f6582af5e52ecab01a118880440f457823a6d3134a50f22ae1c600328a3f69598be0bdccb15536b08bd8d7625ea083c47a964156ca6778c245788aba2c41af6010a98790a3e19cd31a5cd01c624403882d2100eb79b7e0f755c5397e1e495a266b9ee7c74321a4162c0b34d36de236624f4578e94a3f5fdcad1aac3b8410cfbf6ea69f309382950e7570c3b6343034420f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bad2056b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967ac81c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0fab6872a6472f720348abd5ee60dfe41980da33e7968f6d3ccddedc589e2c29b853a2daa2bac0f787716aca1fafb177298c909c23c64944399d108f9546269f2d2272618f71062f94e7afa4ccc8073dc4dca3d878f6582af5e52ecab01a1188804404c59f16105692cb720cc330f397bee5d7e49d4d197b7b0bf9ddba9161c59610fe58f3c690663f796e9117497c3bef0969cdad432445a1308057c8202e65d3dac4004896f67005aab65c02a768d91b71628a56a48c7d974b16e543e8189c35f37fab0b038e5ff406be8594769366a5158134149672c528c3a8b99de80f8bc6e60064420f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bad20f76a39d05686e34a4420897e359371836145dd3973e3982568b60f8433adde6eac61c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0710b2a8bcf8e0d73c68a452f1c3b5df186ee6e5f4a3b8ceb38d97a0a03f81d9e525a492d39d483bda14091454f2da78aecd76c6b8b8d5af821c231c0bc2cc96b04403ff3df852d735d203aca8955b7cc833443f5c8e69731dd44abfd4ecef54318c6867c18ec9b443f27bf7753c935a6af43889e7a0f6b5d59471450d3987d049e37405a0c27fb96cd2c02a4ab51d16a3cfa0d8e2805dc37993cf8a38f6ebeb8147e64dccba89f6832e91894e5ac274cfd4065839b5b41c7be884e385e20ea553d1b8d442056b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967ad20f76a39d05686e34a4420897e359371836145dd3973e3982568b60f8433adde6eac61c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0234ca28869178771c3fbe3e24b88ae2b39a3d732a09c37753fe34009502bc624525a492d39d483bda14091454f2da78aecd76c6b8b8d5af821c231c0bc2cc96b05000040c046304b24b321c6cf30a164de1aa4ac89e52353fc064f889cc66161d7be7982c29748c8603d9f369b8f421c6926e4b5d84842927abb448545457c0bc62ec61c6820989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fac20f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bba2056b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967ba519c21c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac005000040503a6535f80c0472cb4defc1a1d72c2e04b8a08d4b7a68f1ed665f824adb2f41bf6a1bffeaed09fd28222e543611f78e8780e26fdf54732bcd1da5817e21f04b6820989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fac20f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bba2056b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967ba519c21c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac005000040fd63cc16f6b85a9feb42d8fc6090a517df7840a1d804f9d597b30a1b5a2a302224adca95a936c762288066a574fe8ac56b428c2442c9287f642c2e931f3c950c6820989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fac20f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bba2056b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967ba519c21c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0050040685bf0f619636e18d5d54701fabcbb0faeaa591ce59b6094aa73816c852db0c9fd733f6368a3d8895279209d6524ce880bec7c0e4fe6e4f8cd949fa16b83f300006820989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fac20f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bba2056b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967ba519c21c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0050000403e84ea6c2efac3c335002a00774ffe06dad237093418f6745337f35f28ae401b6ceac2255c435294ecee8d0ca240414e54b04d393ebe331380145ffb02cb23176820989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fac20f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bba2056b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967ba519c21c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0050040538c72507cef87d38341b1eab66f4f5fb8095af72b454090ac85a4df5985517468112249c374c2a31e4b312e39b8ab3a3a0b1fa10437b01b48a81efa463d5c61006820989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fac20f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bba2056b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967ba519c21c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac005405a9c5b9eb304bc1c2345ae2a23a021942dd7dd1acf8d179b9193156c4c6b7558d4f28006b90f582405e98e435ae0742b17b705ef676205259f0ba79c3bd4ddc100006820989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fac20f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bba2056b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967ba519c21c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac00500404a04f75dd8a795bc9416fddf44ad14b1cec87634944b1ae257830c4fb68a9cad25b2d9df3ccad2280de6586fbde94e4833bf649bca4b5af836c506ab6c10605140ba2979e2572ce83da5b51092e9aa00b348c6d5a9c747b3c6d5639a2e414fec48243b4917870bf2611420e7f131c0829aea202e3c1a738ab1fed5cd8471bddc3a6820989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fac20f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bba2056b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967ba529c21c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac00500405db2fd50527ba1d5657e991f9cbf18289920297b713c540fe2b5042467c727415121816ddd1e624ff3e0278364a0c71e65b9ed9eadfb945337d3e7988261dcf940ee0f2462a812e4f36bb107c16ec7191dcbc4747e8f2a47c80053e4c35eace4c7998e5a3a18d1f51f345c3a8a8195117a009ce82b518dbf1c044abe6bb078219a6820989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fac20f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bba2056b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967ba529c21c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac00540c5f267e842c52a0f1ece7aeac7f61fed5bf60e9fc1e4914b5035c3cf82503f8eebd796f66abf12e77688bb8f42b7eee2c69aa41d62ec5caa57c7c6d8363ebca40040ac8238564a86212595c575b15290cd22f75c85395b0313515197addff691bf1b4733546139aaf1a35631cc65b19dba981c8f2c6922553295081a36a496d1a5d66820989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fac20f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bba2056b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967ba529c21c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac00540ffef800a0f13e72baf62764184251fada9879bdf9584529c4ea3e4cb45a8ed5fc411abfbb45be7d7f156fb9d2c2a07a0ecc798baa4265738cd9f018f30b03c414027e2c00afcae5a6e3ee7a5d55a086ac6b8e73474ffeaaa77569aca817c1a126b5033d94807b9409114610b97f33b97b0e5d1c0b2091e9af990caf3af6a74b8d9006820989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fac20f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bba2056b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967ba529c21c050929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac006000040a48015ee77cbea36e10ee5b53657c4503b30dc27cd524e7e1632eb156c3b654ab31a65eb3e1da59a0de2156d5c60219116789cead15fc29967f19f32365be9934067746697fb2506182be21c89c904db40c50ed45802783a349775a5f1c0006277a8981925c6e61d9398302af84b88ed2c54d006f66093fb0ac233aa4bc83b6e738a20989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fac20f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bba2056b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967ba20f76a39d05686e34a4420897e359371836145dd3973e3982568b60f8433adde6eba529c21c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac006000040de8688c83891b60362eab0dd87785af271cf53566c89973d158877ccc99efb7618e70566339afa66fbc9bde5c1b733d2b75d6a964b2aa25d74046391bb42ebb5400530209914f68fea7cf4f6bf3b80e8fd696a791bde0f76d7d2fc6e3b383bdfdcad6cc436dc179142b768bb22503bb14130724eeda9bf3464e165d8020311b6768a20989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fac20f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bba2056b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967ba20f76a39d05686e34a4420897e359371836145dd3973e3982568b60f8433adde6eba529c21c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac006000040bc719ff59faac25693253c713f17445ca4deb71b693e0c84dd3ea6bd22ac8985ae106b68288df945f641f2c15d7d9075d30c23830d064f7bab4b16cc6fb1004d40b16dfc01131fe3bcb3c69084a4d8f574bcb796a11761fff942fb1f1e826cf13b2c909201a71100d08173e5b81808a16cda2fdc42aca02fb67ae513f92dc7af598a20989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fac20f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bba2056b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967ba20f76a39d05686e34a4420897e359371836145dd3973e3982568b60f8433adde6eba529c21c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac006004061ff762c9f28166c76c41e881fd7ef50d422fed330f4bc65cd1539a92a3e3e296277dd9551bc62150f7431fdc7cbb4c1ada02d883ba3a753402114a1ac6f87e100406240671d54789dac33166389c7deb66120d164f7ff345033aae93278835bc51c4e32cad5564d69e1309bf4fc60f7f6ed4d2d9631371f2db2070a7b45978147688a20989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fac20f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bba2056b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967ba20f76a39d05686e34a4420897e359371836145dd3973e3982568b60f8433adde6eba529c21c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac00600400daa771d34fc6c3e53dd09e60c5363569b9cc6085cd40c40f7b569c3c09bb210723842bce1fe92237e63553e9e3ccb44b14a59ce94563f33e5cfcc992e4e7b69403870c2b5992f37b2bd98dd48c7efc4474dec9209353203edbba21f454341d091ddddba126d59bb9e646567338c64271458ea684dea90b3363ca9acc389ad05c8008a20989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fac20f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bba2056b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967ba20f76a39d05686e34a4420897e359371836145dd3973e3982568b60f8433adde6eba529c21c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac006000040762a5e751c2b613f2c8e0367ed8e805148bffeac34029eae25e52baac464f5fa1febfdb3c66df80e2143967db68ded288282bfbc0590e51f5e83b667cd3572b140b89df614986a195f6bc0ad32f6ec392ee68f02f5a99a0061ce70ef8638908f72af571f055406c5c9529687ce0301e82c75bb2c5870c682d96e221ba744357ced8a20989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fac20f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bba2056b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967ba20f76a39d05686e34a4420897e359371836145dd3973e3982568b60f8433adde6eba529c21c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0060040158f7d96e6028ef2e7487ee306b1c7392c86cc65494ebe56e0a15211232d15e2ec8570778258aacb644f9d887edbbe89e3f6a1cd23bd47b3ec4b86834d93ad56004074a325101ff66ae80da85f10fea5c7d05850b28dcd2a4945e694a156fa738c29e6003afdc7ae9f7889b6c4cbf7f99115b77c8d17117dba10bfd0a9fdf6fef3f68a20989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fac20f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bba2056b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967ba20f76a39d05686e34a4420897e359371836145dd3973e3982568b60f8433adde6eba529c21c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0064056e8de23b6a84c682f59d7c88dd076322a1bcee71c84435945a2829ef1f770625b1d91cafd65973df7a2a4a749d1bba54ffdd6fd87b32832dff2d7d501105310000040f4629e2ea28431303c274f1be1edead02f8f593fa0d2ad6a7e58d75fbed231c1105eb2bccf9d5e60cb86ddb691ada502416c5a7af99e1d2b5e0c2c66a76b06a28a20989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fac20f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bba2056b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967ba20f76a39d05686e34a4420897e359371836145dd3973e3982568b60f8433adde6eba529c21c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac00600407d6da03b21e9a2fb60704107eeb825d5260c977ef951e89e126ff7d0eccc34238e6784b3b0ad91b2c310dbeda42940004c566e9480136cb8bd9f493e09be6a9040fff31ef8a232dd77985a7c9fc643a0692c1c317afbd41123535181199a89a2f1becc004a4c3da753273555cf1a2ab8ee9508b75fe8df9c736bb487242a46fa10008a20989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fac20f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bba2056b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967ba20f76a39d05686e34a4420897e359371836145dd3973e3982568b60f8433adde6eba529c21c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac006407fbaf4f2742a120d59483a3c2d265663736044c7744eba188aa422b31a5d25350a5a835a2ebb56740d7372d2e1adcc31c1ab50d03b5a993ae8f987145848c1360040da01c492a2d5a2cc1705ddb61539316d037175d4caf406cb77b94e1d77fef92d4863d5595acf2c35b551b85f236a8619348531c6cd0d4660d49b835509bda2ee008a20989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fac20f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bba2056b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967ba20f76a39d05686e34a4420897e359371836145dd3973e3982568b60f8433adde6eba529c21c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac006408d6516a725506a2419c383a3622c8bf2db3ae1e481e7a9b4747c5ae36cc028e5e36b2e79004c999dcffb8889596b3c656394b6d550e19c0221ec0a0b7587c1ec40cf89cba4410fdd7811117544dcbe04230db773edc628cab20fb6fa6f72dfe3172a7f582f4e680845a79823c84879f66e90ba52d9f97bc06dcd3b1a9dd0e852c600008a20989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6fac20f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661bba2056b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967ba20f76a39d05686e34a4420897e359371836145dd3973e3982568b60f8433adde6eba529c21c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac000000000'
  );
});

should('SignatureHash tests', () => {
  const regtest = { bech32: 'bcrt', pubKeyHash: 0x6f, scriptHash: 0xc4 };
  const tx = new btc.Transaction({
    allowLegacyWitnessUtxo: true,
  });
  const BTCamount = 10n ** 8n; // 1btc
  const txid = hex.decode('5d315414e5772696366f21e383d8306b668d0bfc4d2bbc66bcf8f13403f501f4');

  // Out addr
  const privOut = hex.decode('0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e');
  // TODO: btc.getPublic with types or something?
  const pubOut = secp256k1.getPublicKey(privOut, true);
  const out = btc.p2wpkh(pubOut, regtest);
  deepStrictEqual(out.address, 'bcrt1q37eawpk6wtn39jxnnmat0ggf85f0h6mtuhxxu3');

  const privKey = hex.decode('0101010101010101010101010101010101010101010101010101010101010101');
  const P1 = secp256k1.getPublicKey(privKey, true);
  const P1S = secp256k1_schnorr.getPublicKey(privKey);
  const S1 = btc.p2pkh(P1, regtest);
  const S2 = btc.p2wpkh(P1, regtest);
  const S3 = btc.p2tr(P1S, undefined, regtest);
  const spends = [S1, S2, S3];
  // console.log(
  //   'SPENDS',
  //   spends.map((i) => i.address)
  // );
  const auxRand = new Uint8Array(32);
  let index = 0;
  const addInput = (spend, sighash) => {
    tx.addInput({
      ...spend,
      txid,
      index: index++,
      witnessUtxo: { script: spend.script, amount: btc.Decimal.decode('1.5') },
      sighashType: sighash,
    });
  };
  const signIdx = (idx) => {
    tx.signIdx(privKey, idx, [tx.inputs[idx].sighashType], auxRand);
  };

  // Inputs
  // NONE + ANYONE  -- specific input + no outputs
  for (const s of spends) {
    addInput(s, btc.SignatureHash.NONE | btc.SignatureHash.ANYONECANPAY);
    // Should sign, since we don't care about outputs
    signIdx(index - 1);
  }
  // Add ouputs, since they are not signed.
  // NOTE: very problematic tx, because miner/pool can replce outputs with whatever it wants and re-send tx.
  for (const s of spends) tx.addOutputAddress(out.address, 1n * BTCamount, regtest);
  // Change last output 1 -> 1.5. This is fine, since output is unsigned
  tx.updateOutput(2, { amount: btc.Decimal.decode('1.5') });
  let curIndex = index;
  for (const s of spends) addInput(s, btc.SignatureHash.SINGLE | btc.SignatureHash.ANYONECANPAY);
  // Throw because not corresponding outputs
  for (let i = curIndex; i < curIndex + 3; i++) throws(() => signIdx(i));
  // Let's add corresponding outputs
  for (const s of spends) tx.addOutputAddress(out.address, 1n * BTCamount, regtest);
  // Now sign is fine!
  for (let i = curIndex; i < curIndex + 3; i++) signIdx(i);
  // Cannot do that (output is signed)
  //throws(() => tx.updateOutput(5, { amount: btc.Decimal.decode('1.5') }));

  deepStrictEqual(tx.signStatus(), {
    addInput: true,
    addOutput: true,
    inputs: [0, 1, 2, 3, 4, 5],
    outputs: [3, 4, 5], // 0,1,2 is not signed, we can modify them
  });
  // Add outputs since we cannot add them after sign
  for (const s of spends) tx.addOutputAddress(out.address, 1n * BTCamount, regtest);
  for (const s of spends) {
    addInput(s, btc.SignatureHash.ALL | btc.SignatureHash.ANYONECANPAY);
    // Still can add inputs after sign, because of ANYONE
    signIdx(index - 1);
  }
  // Cannot add output, since they signed
  throws(() => tx.addOutputAddress(out.address, 1n * BTCamount, regtest));
  curIndex = index;
  // Default sighash all
  for (const s of spends) addInput(s, btc.SignatureHash.ALL);
  for (let i = curIndex; i < curIndex + 3; i++) signIdx(i);
  throws(() => tx.addOutputAddress(out.address, 1n * BTCamount, regtest));
  // Throws too, because no ANYONE in previous output
  throws(() => addInput(S1, btc.SignatureHash.ALL));
  tx.finalize();
  const txHex = hex.encode(tx.extract());
  // Verified against bitcoin core regnet (see test_noble3.py).
  // If breaks test, please re-test before changing
  deepStrictEqual(
    txHex,
    '0200000000010cf401f50334f1f8bc66bc2b4dfc0b8d666b30d883e3216f36962677e51454315d000000006b483045022100b740ffd61cd149d4cc16df56418813531db907ec78bbb5a7a092bd54590ec0ec022020217910b904bf8d1e7a7ac6dda61481aaac220ad6d95db7baafc6fd2b2cc2988221031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078ffffffffff401f50334f1f8bc66bc2b4dfc0b8d666b30d883e3216f36962677e51454315d0100000000fffffffff401f50334f1f8bc66bc2b4dfc0b8d666b30d883e3216f36962677e51454315d0200000000fffffffff401f50334f1f8bc66bc2b4dfc0b8d666b30d883e3216f36962677e51454315d030000006b483045022100f5eb8ff874eb0a56ea15f6032807c40aae44fa7ca8506d10a0b04b584f64d2b9022036674720c93cb331fbf2296b0c25476949cd53dedea86b8ac1c02f714e3803e98321031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078ffffffffff401f50334f1f8bc66bc2b4dfc0b8d666b30d883e3216f36962677e51454315d0400000000fffffffff401f50334f1f8bc66bc2b4dfc0b8d666b30d883e3216f36962677e51454315d0500000000fffffffff401f50334f1f8bc66bc2b4dfc0b8d666b30d883e3216f36962677e51454315d060000006a4730440220643eadb5498abf506542994b91edb80ae4b5642416a01b4b230789f2d450ea72022043004aea51367e89afab915e687880d50a4734cd62036e87fff1f3d37819f9598121031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078ffffffffff401f50334f1f8bc66bc2b4dfc0b8d666b30d883e3216f36962677e51454315d0700000000fffffffff401f50334f1f8bc66bc2b4dfc0b8d666b30d883e3216f36962677e51454315d0800000000fffffffff401f50334f1f8bc66bc2b4dfc0b8d666b30d883e3216f36962677e51454315d090000006b483045022100940d419d66b904b17e1b80bc347c397b44a93b797d45abc14b6c50d20485bad4022012314f3a430b32ff45d52c5875f210a2a4610d81f5c9f05f2024a9a18f8860110121031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078ffffffffff401f50334f1f8bc66bc2b4dfc0b8d666b30d883e3216f36962677e51454315d0a00000000fffffffff401f50334f1f8bc66bc2b4dfc0b8d666b30d883e3216f36962677e51454315d0b00000000ffffffff0900e1f505000000001600148fb3d706da72e712c8d39efab7a1093d12fbeb6b00e1f505000000001600148fb3d706da72e712c8d39efab7a1093d12fbeb6b80d1f008000000001600148fb3d706da72e712c8d39efab7a1093d12fbeb6b00e1f505000000001600148fb3d706da72e712c8d39efab7a1093d12fbeb6b00e1f505000000001600148fb3d706da72e712c8d39efab7a1093d12fbeb6b00e1f505000000001600148fb3d706da72e712c8d39efab7a1093d12fbeb6b00e1f505000000001600148fb3d706da72e712c8d39efab7a1093d12fbeb6b00e1f505000000001600148fb3d706da72e712c8d39efab7a1093d12fbeb6b00e1f505000000001600148fb3d706da72e712c8d39efab7a1093d12fbeb6b00024730440220415127cbbe534a8ffbf4e314ee0a9d2abffb7f64fdbd5135dd263b5ce3f67d5802203189fb2db5569dc850671085b3c25c24f278aa5cc0453d24b0c4a3fc1454afbe8221031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f0141507f628d3ef46e70b9243434b8ca539274731c87a14ec88fa65dfd7b2037e60b3e416babe7ef276cb273833ed8042291914c26334feeb9a55cc8f9efa35be41d8200024730440220539211d3ad931874083b2bc952a49eb9aa8fea75502527f29fd5ae48c46b8c9202200f7579cf758ea7e1e899418164d632d8107dd1ba9f4a90bcbfa1bb98ae64cb3f8321031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f01411b437539d56e59b0dbde2cfab5564d51d39891ed8519def0d59cbd2789125eb12aa1530d087802cd3dd0078e4c0b18c9fbdf2a2f6fdf2d76c4df31ca4aaa79c78300024830450221008afa156f9d47d122c30232e258ffebf0a8e266343981277ff9d0790ef2a3329002204b066ee4271098e4b016aa129de3de2bcab8c68f0fa29e7fb796abcf588686ea8121031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f0141a8b9f0b486db7ceab2599b4bb3f010a2869ebeae1710952f2abd48ff7addf8cfb275e1f224a264ab1874b31c210d7cba6a64eb32ca0c99c0e6eb1f667a219696810002483045022100f6d3c2e18b703d7947bc4f6dee0dd263bd08dbbeb035da3cfbb7dbbeea3d1805022011ff20cb91194d7bcb4da5a0b73f466abe26b63ea0fbaf496cac2fdefe6e9cbc0121031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f014114298569294ef1a933df44e1cb24657c31fc2806689e3aad5b47e527d6cf058fdffdb4b79227e663a448e4dc16615cedb1cfce1c79ebb76474bbb12d908d548c0100000000'
  );
});

should('taproot single array as script', () => {
  const A = hex.decode('0101010101010101010101010101010101010101010101010101010101010101');
  const B = hex.decode('0202020202020202020202020202020202020202020202020202020202020202');
  const C = hex.decode('1212121212121212121212121212121212121212121212121212121212121212');
  const D = hex.decode('989c0b76cb563971fdc9bef31ec06c3560f3249d6ee9e5d83c57625596e05f6f');
  const E = hex.decode('f991f944d1e1954a7fc8b9bf62e0d78f015f4c07762d505e20e6c45260a3661b');
  const F = hex.decode('56b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967');
  const ns1 = btc.p2tr_ns(2, [A, B]);
  const ns2 = btc.p2tr_ns(2, [A, C]);
  const ns3 = btc.p2tr_ns(2, [B, C]);
  const ns4 = btc.p2tr_ns(2, [D, E]);
  const ns5 = btc.p2tr_ns(2, [E, F]);
  const ns6 = btc.p2tr_ns(2, [C, D]);
  for (const ns of [ns1, ns2, ns3, ns4, ns5, ns6]) deepStrictEqual(ns.length, 1);
  // Test for 4 elements
  deepStrictEqual(
    btc.p2tr(undefined, [ns1, ns2, ns3, ns4]),
    btc.p2tr(undefined, [ns1[0], ns2[0], ns3[0], ns4[0]])
  );
  deepStrictEqual(
    btc.p2tr(undefined, [ns1, ns2, ns3, ns4]),
    btc.p2tr(undefined, [...ns1, ...ns2, ...ns3, ...ns4])
  );
  // Test for 5 elements (just to be sure)
  deepStrictEqual(
    btc.p2tr(undefined, [ns1, ns2, ns3, ns4, ns5]),
    btc.p2tr(undefined, [ns1[0], ns2[0], ns3[0], ns4[0], ns5[0]])
  );
  deepStrictEqual(
    btc.p2tr(undefined, [ns1, ns2, ns3, ns4, ns5]),
    btc.p2tr(undefined, [...ns1, ...ns2, ...ns3, ...ns4, ...ns5])
  );
  // Mixed input (single script + multiple arrays of single element)
  const pk1 = btc.p2tr_pk(A);
  // A or (B and C) or (C and D) or (D and E)
  // => pk1 or ns3 or ns6 or ns4
  deepStrictEqual(
    btc.p2tr(undefined, [pk1, ns3, ns6, ns4]),
    btc.p2tr(undefined, [pk1, ns3[0], ns6[0], ns4[0]])
  );
  deepStrictEqual(
    btc.p2tr(undefined, [pk1, ns3, ns6, ns4]),
    btc.p2tr(undefined, [pk1, ...ns3, ...ns6, ...ns4])
  );
  // Mixed, but with single script at the end
  deepStrictEqual(
    btc.p2tr(undefined, [ns3, ns6, ns4, pk1]),
    btc.p2tr(undefined, [ns3[0], ns6[0], ns4[0], pk1])
  );
  deepStrictEqual(
    btc.p2tr(undefined, [ns3, ns6, ns4, pk1]),
    btc.p2tr(undefined, [...ns3, ...ns6, ...ns4, pk1])
  );
});

should('Finalize negative fee', () => {
  const opts = { version: 1, allowLegacyWitnessUtxo: true };
  const privKey = hex.decode('0101010101010101010101010101010101010101010101010101010101010101');
  const pub = secp256k1.getPublicKey(privKey, true);

  // Fails
  {
    const tx = new btc.Transaction(opts);
    for (const inp of TX_TEST_INPUTS) {
      tx.addInput({
        ...inp,
        witnessUtxo: {
          script: btc.p2pkh(pub).script,
          amount: inp.amount,
        },
      });
    }
    tx.addOutputAddress(TX_TEST_OUTPUTS[0][0], tx.fee + 1n);
    tx.sign(privKey);
    //testClone(tx);
    throws(() => tx.finalize());
  }
  // OK
  {
    const tx = new btc.Transaction(opts);
    for (const inp of TX_TEST_INPUTS) {
      tx.addInput({
        ...inp,
        witnessUtxo: {
          script: btc.p2pkh(pub).script,
          amount: inp.amount,
        },
      });
    }
    tx.addOutputAddress(TX_TEST_OUTPUTS[0][0], tx.fee);
    tx.sign(privKey);
    tx.finalize();
  }
});

should('Issue #13', () => {
  const keypairFromSecret = (hexSecretKey) => {
    const secretKey = hex.decode(hexSecretKey);
    const schnorrPublicKey = secp256k1_schnorr.getPublicKey(secretKey);
    return {
      schnorrPublicKey,
      secretKey,
    };
  };

  const aliceKeyPair = keypairFromSecret(
    '2bd806c97f0e00af1a1fc3328fa763a9269723c8db8fac4f93af71db186d6e90'
  );
  const bobKeyPair = keypairFromSecret(
    '81b637d8fcd2c6da6359e6963113a1170de795e4b725b84d1e0b4cfd9ec58ce9'
  );
  const internalKeyPair = keypairFromSecret(
    '1229101a0fcf2104e8808dab35661134aa5903867d44deb73ce1c7e4eb925be8'
  );
  const preimage = sha256(
    hex.decode('107661134f21fc7c02223d50ab9eb3600bc3ffc3712423a1e47bb1f9a9dbf55f')
  );

  const scriptAlice = new Uint8Array([
    0x02,
    144,
    0x00,
    btc.OP.CHECKSEQUENCEVERIFY,
    btc.OP.DROP,
    0x20,
    ...aliceKeyPair.schnorrPublicKey,
    0xac,
  ]);

  const scriptBob = new Uint8Array([
    btc.OP.SHA256,
    0x20,
    ...preimage,
    btc.OP.EQUALVERIFY,
    0x20,
    ...bobKeyPair.schnorrPublicKey,
    0xac,
  ]);

  const taprootTree = btc.taprootListToTree([
    {
      script: scriptAlice,
      leafVersion: 0xc0,
    },
    {
      script: scriptBob,
      leafVersion: 0xc0,
    },
  ]);

  const taprootCommitment = btc.p2tr(
    internalKeyPair.schnorrPublicKey,
    taprootTree,
    undefined,
    true
  );
  deepStrictEqual(
    { ...taprootCommitment, leaves: undefined, tapLeafScript: undefined },
    {
      type: 'tr',
      script: hex.decode('5120a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951'),
      address: 'bc1p5kaqsuted66fldx256lh3en4h9z4uttxuagkwepqlqup6hw639gspmmz4d',
      tweakedPubkey: hex.decode('a5ba0871796eb49fb4caa6bf78e675b9455e2d66e751676420f8381d5dda8951'),
      tapInternalKey: hex.decode(
        'f30544d6009c8d8d94f5d030b2e844b1a3ca036255161c479db1cca5b374dd1c'
      ),
      tapMerkleRoot: hex.decode('41646f8c1fe2a96ddad7f5471bc4fee7da98794ef8c45a4f4fc6a559d60c9f6b'),
      leaves: undefined,
      tapLeafScript: undefined,
    }
  );
});

should('TapRoot export version', () => {
  const opts = {};
  const privKey = hex.decode('0101010101010101010101010101010101010101010101010101010101010101');
  // without taproot
  {
    const pub = secp256k1.getPublicKey(privKey, true);
    const tx = new btc.Transaction(opts);
    for (const inp of TX_TEST_INPUTS) {
      tx.addInput({
        ...inp,
        witnessUtxo: {
          script: btc.p2wpkh(pub).script,
          amount: inp.amount,
        },
      });
    }
    tx.toPSBT(0);
    throws(() => tx.toPSBT(1));
    tx.toPSBT(2);
  }
  // with taproot
  {
    const pubS = secp256k1_schnorr.getPublicKey(privKey);
    const tx = new btc.Transaction(opts);
    for (const inp of TX_TEST_INPUTS) {
      const tr = btc.p2tr(pubS);
      tx.addInput({
        ...inp,
        ...tr,
        witnessUtxo: {
          script: tr.script,
          amount: inp.amount,
        },
      });
    }
    // As per BIP-371, version 0 can have taproot fields!
    tx.toPSBT(0);
    throws(() => tx.toPSBT(1));
    tx.toPSBT(2);
  }
  // requiredHeightLocktime (PSBTv2 only field)
  {
    const pubS = secp256k1_schnorr.getPublicKey(privKey);
    const tx = new btc.Transaction(opts);
    for (const inp of TX_TEST_INPUTS) {
      const tr = btc.p2tr(pubS);
      tx.addInput({
        ...inp,
        ...tr,
        witnessUtxo: {
          script: tr.script,
          amount: inp.amount,
        },
        requiredHeightLocktime: 1,
      });
    }
    // As per BIP-371, version 0 can have taproot fields!
    throws(() => tx.toPSBT(0));
    throws(() => tx.toPSBT(1));
    tx.toPSBT(2);
  }
});

should('big multisig (real)', () => {
  // https://gist.github.com/AdamISZ/9b2395ddcb43890d9611df99287cfe6b
  // -> https://www.blockchain.com/explorer/transactions/btc/7393096d97bfee8660f4100ffd61874d62f9a65de9fb6acf740c4c386990ef73

  // ScriptNum in last part
  deepStrictEqual(hex.encode(btc.Script.encode([998, 'GREATERTHANOREQUAL'])), '02e603a2');

  const pub = hex.decode('1ea539fd851574f6802e6cc0cda3b2bd60afcfca9cd72d9279c5dc8c2054f6b6');

  // Uses different multisig
  const script = [pub, 'CHECKSIG'];
  for (let i = 0; i < 998; i++) script.push(pub, 'CHECKSIGADD');
  script.push(998, 'GREATERTHANOREQUAL');

  const script2 = script.slice(0, -1);
  script2.push('NUMEQUAL');
  btc.OutScript.decode(btc.Script.encode(script2));

  const tx = new btc.Transaction({ allowUnknowInput: true });
  tx.addOutputAddress('bc1q34yl3qzqv4qlxf0gj9tguv23tzh99syawhmekm', 750n);

  const controlBlock = hex.decode(
    'c11dae61a4a8f841952be3a511502d4f56e889ffa0685aa0098773ea2d4309f624'
  );
  const sig = hex.decode(
    '809edb01f5931cc992763731cda9e983d7e2030a0863352530907490ef2a289721358c386d0b23d82fe78aab1e2f7f3bcf9ae7409bb771c98e7222dc136209f9'
  );

  const payment = btc.p2tr(pub, { script: btc.Script.encode(script) }, undefined, true);
  const cb = btc.TaprootControlBlock.decode(controlBlock);
  tx.addInput({
    txid: '6c0d4d4c715945b2e495f8878d42db16675f080f53fb84c521261774a0636148',
    index: 0,
    witnessUtxo: {
      script: hex.decode('512056e1005938333d0095cd0b7225e47216417619867bc12ae91c5b61cbc95a315e'),
      amount: 26000n,
    },
    ...payment,
    tapScriptSig: [[{ pubKey: pub, leafHash: payment.leaves[0].hash }, sig]],
    sequence: 0,
  });
  tx.finalize();
  deepStrictEqual(tx.id, '7393096d97bfee8660f4100ffd61874d62f9a65de9fb6acf740c4c386990ef73');
});

should('big multisig (ours)', () => {
  return; // too slow, but works
  // Slow: sign + preimage. We can cache preimage, but sign is more complex

  // Limits: p2_ms=20, p2tr_ms/p2tr_ns=999 (stacksize)
  // 999 encode as number support? check with bitcoin core
  const regtest = { bech32: 'bcrt', pubKeyHash: 0x6f, scriptHash: 0xc4 };

  const pkeys = [];
  for (let i = 1; i < 1000; i++) pkeys.push(P.U256BE.encode(i));

  const pubs = pkeys.map(secp256k1_schnorr.getPublicKey);
  const spend = btc.p2tr(undefined, btc.p2tr_ms(999, pubs), regtest);
  const outAddr = btc.p2wpkh(secp256k1.getPublicKey(pkeys[0], true), regtest);

  const tx = new btc.Transaction();
  tx.addInput({
    txid: '3d9955e6d03771e276f7b713734bade9c2c5e3c80d90b4b1da35deaa1c0c9bc6',
    index: 0,
    ...spend,
    witnessUtxo: { script: spend.script, amount: btc.Decimal.decode('1.5') },
  });
  tx.addOutputAddress(outAddr.address, '1', regtest);
  let ts = Date.now();
  for (const p of pkeys) tx.sign(p);
  // console.log('SIGN', Date.now() - ts);
  ts = Date.now();
  tx.finalize();
  // console.log('FINALIZE', Date.now() - ts);

  // Verified against regnet
  //console.log(hex.encode(tx.extract()))
  deepStrictEqual(tx.id, '2687c4795c995431d934432def1cda8264c95920ce404229ca5c21328d7c9bcc');
});

should('Signed fields', () => {
  const opts = {};
  const privKey = hex.decode('0101010101010101010101010101010101010101010101010101010101010101');

  const pub = secp256k1.getPublicKey(privKey, true);

  const out = btc.p2pkh(pub);
  const tx = new btc.Transaction(opts);
  const inp = TX_TEST_INPUTS[0];
  tx.addInput(inp);
  tx.updateInput(0, {
    witnessUtxo: {
      script: btc.p2wpkh(pub).script,
      amount: inp.amount,
    },
  });
  const fingerprint = 12345;
  tx.updateInput(0, {
    bip32Derivation: [
      [
        '03089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc',
        { fingerprint: fingerprint, path: [0, 1, 2] },
      ],
    ],
  });
  tx.addOutputAddress(out.address, 123n);
  tx.updateOutput(0, { amount: 122n });
  tx.sign(privKey);
  // At this point tx is signed

  // Same input -> no issues
  tx.updateInput(0, {
    witnessUtxo: {
      script: btc.p2wpkh(pub).script,
      amount: inp.amount,
    },
  });

  throws(
    () =>
      tx.updateInput(0, {
        witnessUtxo: {
          script: btc.p2wpkh(pub).script,
          amount: inp.amount + 1n,
        },
      }),
    'modify signed input'
  );
  // Same works
  tx.updateInput(0, {
    bip32Derivation: [
      [
        '03089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc',
        { fingerprint: fingerprint, path: [0, 1, 2] },
      ],
    ],
  });

  throws(() =>
    tx.updateInput(0, {
      bip32Derivation: [
        ['03089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc', undefined],
      ],
    })
  );

  // Addition of new values is still works
  tx.updateInput(0, {
    bip32Derivation: [
      [
        '03089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02db',
        { fingerprint: fingerprint, path: [0, 1, 2] },
      ],
    ],
  });

  tx.updateOutput(0, { amount: 122n }); // Same
  throws(() => tx.updateOutput(0, { amount: 121n }), 'modify signed output');

  // Remove signatures
  tx.updateInput(0, {
    partialSig: undefined,
  });

  tx.updateInput(0, {
    witnessUtxo: {
      script: btc.p2wpkh(pub).script,
      amount: inp.amount + 1n,
    },
  });
  tx.updateInput(0, {
    bip32Derivation: [
      ['03089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02dc', undefined],
    ],
  });
  tx.updateInput(0, {
    bip32Derivation: [
      [
        '03089dc10c7ac6db54f91329af617333db388cead0c231f723379d1b99030b02db',
        { fingerprint: fingerprint, path: [0, 1, 2] },
      ],
    ],
  });
  tx.updateOutput(0, { amount: 121n });
});

should('have proper vsize for cloned transactions (gh-18)', () => {
  const opts = {};
  const privKey = hex.decode('0101010101010101010101010101010101010101010101010101010101010101');
  // setup taproot tx
  const pubS = secp256k1_schnorr.getPublicKey(privKey);
  const tx = new btc.Transaction(opts);
  for (const inp of TX_TEST_INPUTS) {
    const tr = btc.p2tr(pubS);
    tx.addInput({
      ...inp,
      ...tr,
      witnessUtxo: {
        script: tr.script,
        amount: inp.amount,
      },
    });
  }
  const clone = tx.clone();
  tx.sign(privKey, undefined, new Uint8Array(32));
  tx.finalize();
  //console.log(tx.vsize); // A
  clone.sign(privKey, undefined, new Uint8Array(32));
  clone.finalize();
  //console.log(clone.vsize); // B
  deepStrictEqual(tx.vsize, clone.vsize);
  deepStrictEqual(tx.vsize, 183);
});

should('return immutable outputs/inputs', () => {
  const privKey1 = hex.decode('0101010101010101010101010101010101010101010101010101010101010101');
  const P1 = secp256k1.getPublicKey(privKey1, true);
  const wpkh = btc.p2wpkh(P1);
  const tx = new btc.Transaction();
  // Basic input test
  tx.addInput({
    txid: hex.decode('0af50a00a22f74ece24c12cd667c290d3a35d48124a69f4082700589172a3aa2'),
    index: 0,
    ...wpkh,
    finalScriptSig: new Uint8Array(),
    sequence: 1,
  });
  tx.addInput({ sequence: 1 });
  tx.updateInput(0, { sequence: 1 });
  const nonWitnessUtxo =
    '0200000001aad73931018bd25f84ae400b68848be09db706eac2ac18298babee71ab656f8b0000000048473044022058f6fc7c6a33e1b31548d481c826c015bd30135aad42cd67790dab66d2ad243b02204a1ced2604c6735b6393e5b41691dd78b00f0c5942fb9f751856faa938157dba01feffffff0280f0fa020000000017a9140fb9463421696b82c833af241c78c17ddbde493487d0f20a270100000017a91429ca74f8a08f81999428185c97b5d852e4063f618765000000';
  const nonWitnessUtxoB = hex.decode(nonWitnessUtxo);
  tx.updateInput(0, { nonWitnessUtxo: nonWitnessUtxo });
  tx.updateInput(0, { nonWitnessUtxo: nonWitnessUtxoB });
  tx.addInput({
    txid: hex.decode('0af50a00a22f74ece24c12cd667c290d3a35d48124a69f4082700589172a3aa2'),
    index: 0,
    nonWitnessUtxo: nonWitnessUtxo,
  });
  tx.addInput({
    txid: hex.decode('0af50a00a22f74ece24c12cd667c290d3a35d48124a69f4082700589172a3aa2'),
    index: 0,
    nonWitnessUtxo: nonWitnessUtxoB,
  });
  tx.addOutput({ amount: 123n });
  tx.addOutput({ amount: 456n, script: wpkh.script });
  deepStrictEqual(tx.inputsLength, tx.inputs.length);
  for (let i = 0; i < tx.inputsLength; i++) deepStrictEqual(tx.getInput(i), tx.inputs[i]);
  deepStrictEqual(tx.outputsLength, tx.outputs.length);
  for (let i = 0; i < tx.outputsLength; i++) deepStrictEqual(tx.getOutput(i), tx.outputs[i]);
  // Doesn't modify internal representation
  const i2 = tx.getInput(2);
  deepStrictEqual(tx.inputs[2].txid[0], 10);
  deepStrictEqual(i2.txid[0], 10);
  i2.txid[0] = 255;
  deepStrictEqual(tx.inputs[2].txid[0], 10);
  deepStrictEqual(tx.inputs[2].nonWitnessUtxo.lockTime, 101);
  deepStrictEqual(i2.nonWitnessUtxo.lockTime, 101);
  i2.nonWitnessUtxo.lockTime = 12345;
  deepStrictEqual(tx.inputs[2].nonWitnessUtxo.lockTime, 101);
  // Same for outputs
  const o1 = tx.getOutput(1);
  deepStrictEqual(tx.outputs[1].amount, 456n);
  deepStrictEqual(o1.amount, 456n);
  o1.amount = 786n;
  deepStrictEqual(tx.outputs[1].amount, 456n);
  deepStrictEqual(tx.outputs[1].script[0], 0);
  deepStrictEqual(o1.script[0], 0);
  o1.script[0] = 128;
  deepStrictEqual(tx.outputs[1].script[0], 0);
  console.log('O', tx.outputs[1], o1);
});

// ESM is broken.
import url from 'url';
if (import.meta.url === url.pathToFileURL(process.argv[1]).href) {
  should.run();
}
